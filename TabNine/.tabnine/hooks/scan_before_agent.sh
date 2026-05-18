#!/bin/bash
# Tabnine CLI BeforeAgent hook — Prisma AIRS prompt scanner
#
# Fires after the user submits a prompt, before the agent begins planning.
# Scans for prompt injection, jailbreaks, and malicious instructions.
#
# Tabnine contract:
#   stdin  → JSON { hook_event_name, prompt, session_id, stop_hook_active, timestamp, ... }
#   stdout → JSON { decision: "allow" }
#            or  { decision: "deny", reason: "..." }   ← discards msg from history
#            or  { continue: false, reason: "..." }    ← blocks but saves msg to history
#   exit 0 for JSON-based decisions (preferred)
#   exit 2 blocks with stderr as reason (fallback)

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prisma-airs.sh
source "$HOOKS_DIR/prisma-airs.sh"

# === FD HARDENING: redirect stdout to log, keep FD3 for JSON output ===
exec 3>&1
exec 1>>"$LOG_FILE"

print_allow() {
    printf '%s\n' '{"decision":"allow"}' >&3
}

print_deny() {
    local reason="$1"
    jq -cn --arg reason "$reason" '{"decision":"deny","reason":$reason}' >&3
}

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Skip scanning during retry sequences to avoid infinite loops
STOP_HOOK_ACTIVE=$(printf '%s' "$INPUT_JSON" | jq -r '.stop_hook_active // false' 2>/dev/null)
if [[ "$STOP_HOOK_ACTIVE" == "true" ]]; then
    log "BEFORE-AGENT: Retry sequence detected — skipping scan"
    print_allow
    exit 0
fi

# Extract prompt
PROMPT=$(printf '%s' "$INPUT_JSON" | jq -r '.prompt // empty' 2>/dev/null)

if [[ -z "$PROMPT" ]]; then
    print_allow
    exit 0
fi

# Truncate to 20000 chars
TRUNCATED=$(printf '%s' "$PROMPT" | head -c 20000)

log "BEFORE-AGENT: Scanning user prompt (${#TRUNCATED} chars)"

# Fail-closed: block if credentials missing
if [[ -z "$PRISMA_AIRS_API_KEY" ]] || ! has_profile; then
    log "ERROR: PRISMA_AIRS_API_KEY or profile not set — blocking prompt (fail-closed)"
    print_deny "Prisma AIRS: API key or profile not configured — blocking prompt (fail-closed)"
    exit 0
fi

# Use Tabnine's session_id to group all scans in one session
TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-tabnine-agent-$(date +%s)-$$}"

# Call AIRS
SCAN_RESULT=$(airs_scan "$TRUNCATED" "prompt" "$TR_ID")

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED USER PROMPT: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
        REASON="Blocked by Prisma AIRS: Prompt contained $CATEGORY content (detected: $DETECTIONS)"
    else
        log "BLOCKED USER PROMPT: $CATEGORY (scan_id: $SCAN_ID)"
        REASON="Blocked by Prisma AIRS: Prompt contained $CATEGORY content"
    fi
    print_deny "$REASON"
    exit 0
fi

if [[ -n "$DETECTIONS" ]]; then
    log "ALLOWED USER PROMPT: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
else
    log "ALLOWED USER PROMPT: $CATEGORY (scan_id: $SCAN_ID)"
fi

print_allow
exit 0
