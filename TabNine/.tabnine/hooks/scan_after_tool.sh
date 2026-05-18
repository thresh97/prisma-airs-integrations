#!/bin/bash
# Tabnine CLI AfterTool hook — Prisma AIRS tool output scanner
#
# Fires after a tool executes. Scans tool results for sensitive data,
# malicious content, and DLP violations before the agent sees them.
#
# Tabnine contract:
#   stdin  → JSON { hook_event_name, tool_name, tool_input, tool_response, session_id, timestamp, ... }
#   stdout → JSON { decision: "allow" }
#            or  { hookSpecificOutput: { tool_response: { llmContent, returnDisplay } } }  ← replace output
#   NEVER exit 2 (AfterTool cannot kill the loop via exit code)

set -o pipefail

HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HOOKS_DIR}/prisma-airs.sh"

# === READ STDIN FIRST (before any redirects) ===
INPUT_JSON=$(cat)

# === FD3 HARDENING ===
exec 3>&1
exec 1>>"$LOG_FILE"
exec 2>>"$LOG_FILE"

allow() {
    printf '%s\n' '{"decision":"allow"}' >&3
}

# Replace tool output with a block message visible to both LLM and user
block_output() {
    local message="$1"
    jq -cn --arg msg "$message" '{
      "hookSpecificOutput": {
        "tool_response": {
          "llmContent": $msg,
          "returnDisplay": $msg
        }
      }
    }' >&3
}

# Validate JSON input
if ! echo "$INPUT_JSON" | jq -e . > /dev/null 2>&1; then
    log "AFTER-TOOL: Failed to parse stdin JSON, passing through"
    allow
    exit 0
fi

TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')

# Normalize tool_response to string for scanning
TOOL_RESPONSE_RAW=$(echo "$INPUT_JSON" | jq -c '.tool_response // ""')
if echo "$TOOL_RESPONSE_RAW" | jq -e 'type == "string"' > /dev/null 2>&1; then
    TOOL_OUTPUT=$(echo "$TOOL_RESPONSE_RAW" | jq -r '.')
elif echo "$TOOL_RESPONSE_RAW" | jq -e 'type == "object"' > /dev/null 2>&1; then
    # tool_response is an object — extract llmContent or serialize it
    TOOL_OUTPUT=$(echo "$TOOL_RESPONSE_RAW" | jq -r '.llmContent // .' 2>/dev/null | jq -Rs '.' | jq -r '.')
else
    TOOL_OUTPUT=$(echo "$TOOL_RESPONSE_RAW" | jq -c '.' 2>/dev/null)
fi

# Normalize tool_input for tool_event scan
TOOL_INPUT_RAW=$(echo "$INPUT_JSON" | jq -c '.tool_input // ""')
if echo "$TOOL_INPUT_RAW" | jq -e 'type == "string"' > /dev/null 2>&1; then
    TOOL_INPUT=$(echo "$TOOL_INPUT_RAW" | jq -r '.')
else
    TOOL_INPUT=$(echo "$TOOL_INPUT_RAW" | jq -c '.' 2>/dev/null)
fi

log "AFTER-TOOL: tool=$TOOL_NAME output_size=${#TOOL_OUTPUT}"

# === GUARDRAILS ===
if [[ -z "${TOOL_OUTPUT// /}" ]]; then
    log "AFTER-TOOL: Empty tool_response, skipping scan"
    allow
    exit 0
fi

if [[ ${#TOOL_OUTPUT} -gt 51200 ]]; then
    log "AFTER-TOOL: tool_response too large (${#TOOL_OUTPUT} bytes), skipping scan"
    allow
    exit 0
fi

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "AFTER-TOOL: ERROR: PRISMA_AIRS_API_KEY not set — blocking output (fail-closed)"
    block_output "Prisma AIRS: API key not configured — tool output blocked (fail-closed)"
    exit 0
fi

if ! has_profile; then
    log "AFTER-TOOL: ERROR: no profile configured — blocking output (fail-closed)"
    block_output "Prisma AIRS: profile not configured — tool output blocked (fail-closed)"
    exit 0
fi

# Truncate content before scanning
TRUNCATED_OUTPUT=$(printf '%s' "$TOOL_OUTPUT" | head -c 20000)
TRUNCATED_INPUT=$(printf '%s' "$TOOL_INPUT" | head -c 20000)

TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-tabnine-aftertool-$(date +%s)-$$}"

# Extract MCP server from mcp_context if available
MCP_SERVER=$(printf '%s' "$INPUT_JSON" | jq -r '.mcp_context.server_name // empty' 2>/dev/null)
if [[ -n "$MCP_SERVER" ]]; then
    log "AFTER-TOOL: Scanning MCP tool=$TOOL_NAME server=$MCP_SERVER as tool_event"
    SCAN_RESULT=$(airs_scan_tool_event \
        "$MCP_SERVER" \
        "$TOOL_NAME" \
        "$TRUNCATED_INPUT" \
        "$TRUNCATED_OUTPUT" \
        "$TR_ID")
else
    log "AFTER-TOOL: Scanning tool=$TOOL_NAME as response"
    SCAN_RESULT=$(airs_scan "$TRUNCATED_OUTPUT" "response" "$TR_ID")
fi

CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    log "AFTER-TOOL: WARNING: curl failed (exit: $CURL_EXIT), allowing by default"
    allow
    exit 0
fi

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)

if [[ -z "$ACTION" || "$ACTION" == "unknown" || "$ACTION" == "null" ]]; then
    log "AFTER-TOOL: WARNING: Invalid AIRS response, allowing by default (raw: ${SCAN_RESULT:0:200})"
    allow
    exit 0
fi

DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "AFTER-TOOL: BLOCKED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
        BLOCK_MSG="BLOCKED by Prisma AIRS: ${CATEGORY} (detected: ${DETECTIONS}) [scan:${SCAN_ID}]"
    else
        log "AFTER-TOOL: BLOCKED tool=$TOOL_NAME category=$CATEGORY scan_id=$SCAN_ID"
        BLOCK_MSG="BLOCKED by Prisma AIRS: ${CATEGORY} [scan:${SCAN_ID}]"
    fi
    block_output "$BLOCK_MSG"
    exit 0
fi

if [[ -n "$DETECTIONS" ]]; then
    log "AFTER-TOOL: ALLOWED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
else
    log "AFTER-TOOL: ALLOWED tool=$TOOL_NAME scan_id=$SCAN_ID"
fi

allow
exit 0
