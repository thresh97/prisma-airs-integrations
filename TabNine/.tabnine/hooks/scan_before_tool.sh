#!/bin/bash
# Tabnine CLI BeforeTool hook — Prisma AIRS tool input scanner
#
# Fires before any tool executes. Scans tool arguments for prompt injection,
# malicious parameters, and policy violations.
#
# Tabnine contract:
#   stdin  → JSON { hook_event_name, tool_name, tool_input, mcp_context, session_id, timestamp, ... }
#   stdout → JSON { decision: "allow" }
#            or  { decision: "deny", reason: "..." }  ← prevents execution; reason sent to agent
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

# Read input
INPUT_JSON=$(cat)

TOOL_NAME=$(printf '%s' "$INPUT_JSON" | jq -r '.tool_name // empty' 2>/dev/null)

if [[ -z "$TOOL_NAME" ]]; then
    log "BEFORE-TOOL: No tool_name in input; allowing through"
    print_allow
    exit 0
fi

# Normalize tool_input to string
TOOL_INPUT_RAW=$(printf '%s' "$INPUT_JSON" | jq -c '.tool_input // empty' 2>/dev/null)

if [[ -z "$TOOL_INPUT_RAW" || "$TOOL_INPUT_RAW" == "null" ]]; then
    log "BEFORE-TOOL: tool_name=$TOOL_NAME — empty tool_input; allowing through"
    print_allow
    exit 0
fi

TOOL_INPUT_TYPE=$(printf '%s' "$TOOL_INPUT_RAW" | jq -r 'type' 2>/dev/null)
if [[ "$TOOL_INPUT_TYPE" == "string" ]]; then
    TOOL_INPUT_STR=$(printf '%s' "$TOOL_INPUT_RAW" | jq -r '.' 2>/dev/null)
else
    TOOL_INPUT_STR=$(printf '%s' "$TOOL_INPUT_RAW" | jq -c '.' 2>/dev/null)
fi

if [[ -z "$TOOL_INPUT_STR" ]]; then
    log "BEFORE-TOOL: tool_name=$TOOL_NAME — could not normalize tool_input; allowing through"
    print_allow
    exit 0
fi

# Validate credentials (fail-closed)
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "BEFORE-TOOL: ERROR — PRISMA_AIRS_API_KEY not set; blocking tool=$TOOL_NAME (fail-closed)"
    print_deny "Prisma AIRS: API key not configured — blocking tool execution (fail-closed)"
    exit 0
fi

if ! has_profile; then
    log "BEFORE-TOOL: ERROR — no profile configured; blocking tool=$TOOL_NAME (fail-closed)"
    print_deny "Prisma AIRS: profile not configured — blocking tool execution (fail-closed)"
    exit 0
fi

# Extract MCP server from mcp_context if available, else fall back to tool_name
MCP_SERVER=$(printf '%s' "$INPUT_JSON" | jq -r '.mcp_context.server_name // empty' 2>/dev/null)
if [[ -z "$MCP_SERVER" ]]; then
    MCP_SERVER="tabnine"
fi
MCP_TOOL="$TOOL_NAME"

TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-tabnine-tool-$(date +%s)-$$}"

log "BEFORE-TOOL: Scanning tool=$TOOL_NAME server=$MCP_SERVER tr_id=$TR_ID"

SCAN_RESULT=$(airs_scan_tool_event "$MCP_SERVER" "$MCP_TOOL" "$TOOL_INPUT_STR" "" "$TR_ID")
CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    log "BEFORE-TOOL: curl error (exit $CURL_EXIT) for tool=$TOOL_NAME; failing open"
    print_allow
    exit 0
fi

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)

if [[ -z "$ACTION" || "$ACTION" == "null" ]]; then
    log "BEFORE-TOOL: Empty AIRS response for tool=$TOOL_NAME; failing open"
    print_allow
    exit 0
fi

DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BEFORE-TOOL: BLOCKED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
    else
        log "BEFORE-TOOL: BLOCKED tool=$TOOL_NAME category=$CATEGORY scan_id=$SCAN_ID"
    fi

    REASON="Prisma AIRS blocked tool: $TOOL_NAME. Category: $CATEGORY. Scan ID: $SCAN_ID${DETECTIONS:+ (detected: $DETECTIONS)}. Do not retry this tool call."
    print_deny "$REASON"
    exit 0
fi

if [[ -n "$DETECTIONS" ]]; then
    log "BEFORE-TOOL: ALLOWED tool=$TOOL_NAME action=$ACTION category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
else
    log "BEFORE-TOOL: ALLOWED tool=$TOOL_NAME action=$ACTION scan_id=$SCAN_ID"
fi

print_allow
exit 0
