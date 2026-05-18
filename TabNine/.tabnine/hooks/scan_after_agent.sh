#!/bin/bash
# Tabnine CLI AfterAgent hook — Prisma AIRS response scanner
#
# Fires after the model generates its final response. Scans for sensitive data,
# malicious code, DLP violations, and policy violations in AI output.
#
# Tabnine contract:
#   stdin  → JSON { hook_event_name, prompt_response, session_id, stop_hook_active, timestamp, ... }
#   stdout → JSON { decision: "allow" }
#            or  { decision: "retry", prompt: "..." }  ← rejects response and triggers retry
#   NEVER exit 2 for blocking (not supported for AfterAgent)
#
# Note: "retry" is used rather than a hard block because AfterAgent has no direct
# block decision. stop_hook_active prevents infinite retry loops.

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prisma-airs.sh
source "$HOOKS_DIR/prisma-airs.sh"

# === FD HARDENING ===
exec 3>&1
exec 1>>"$LOG_FILE"

print_allow() {
    printf '%s\n' '{"decision":"allow"}' >&3
}

print_retry() {
    local prompt="$1"
    jq -cn --arg prompt "$prompt" '{"decision":"retry","prompt":$prompt}' >&3
}

# Read input
INPUT_JSON=$(cat)

# Guard: if this is already a retry triggered by us, allow to avoid infinite loop
STOP_HOOK_ACTIVE=$(printf '%s' "$INPUT_JSON" | jq -r '.stop_hook_active // false' 2>/dev/null)
if [[ "$STOP_HOOK_ACTIVE" == "true" ]]; then
    log "AFTER-AGENT: Retry sequence active — skipping scan to avoid loop"
    print_allow
    exit 0
fi

# Extract response text
RESPONSE_TEXT=$(printf '%s' "$INPUT_JSON" | jq -r '.prompt_response // empty' 2>/dev/null)

if [[ -z "$RESPONSE_TEXT" ]]; then
    exit 0
fi

# Truncate to 20000 chars
TRUNCATED=$(printf '%s' "$RESPONSE_TEXT" | head -c 20000)

log "AFTER-AGENT: Scanning assistant response (${#TRUNCATED} chars)"

# Fail-closed: block if credentials missing
if [[ -z "$PRISMA_AIRS_API_KEY" ]] || ! has_profile; then
    log "ERROR: PRISMA_AIRS_API_KEY or profile not set — blocking response (fail-closed)"
    print_retry "Your previous response could not be security-scanned (Prisma AIRS not configured). Please provide a brief, safe response."
    exit 0
fi

TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-tabnine-agent-$(date +%s)-$$}"

SCAN_RESULT=$(airs_scan "$TRUNCATED" "response" "$TR_ID")

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED AGENT RESPONSE: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
        RETRY_PROMPT="Your previous response was blocked by Prisma AIRS security scanning (category: $CATEGORY, detected: $DETECTIONS, scan_id: $SCAN_ID). Please regenerate a response that does not contain $CATEGORY content."
    else
        log "BLOCKED AGENT RESPONSE: $CATEGORY (scan_id: $SCAN_ID)"
        RETRY_PROMPT="Your previous response was blocked by Prisma AIRS security scanning (category: $CATEGORY, scan_id: $SCAN_ID). Please regenerate a safe response."
    fi
    print_retry "$RETRY_PROMPT"
    exit 0
fi

if [[ -n "$DETECTIONS" ]]; then
    log "ALLOWED AGENT RESPONSE: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
else
    log "ALLOWED AGENT RESPONSE: $CATEGORY (scan_id: $SCAN_ID)"
fi

print_allow
exit 0
