#!/usr/bin/env bats
# Tests for TabNine AfterTool hook (scan_after_tool.sh)
# Fires after a tool executes; replaces output if content is flagged.

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.tabnine/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/scan_after_tool.sh"

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

@test "allows clean tool output" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{"command":"ls"},"tool_response":"file1.py\nfile2.py\n","session_id":"sess-1"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

@test "output is valid JSON" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"write_file","tool_input":{},"tool_response":"success","session_id":"sess-2"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
}

@test "allows when tool_response is empty string" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"write_file","tool_input":{},"tool_response":"","session_id":"sess-3"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

@test "allows when tool_response is whitespace only" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"   ","session_id":"sess-4"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

@test "skips scan and allows when tool_response exceeds 50KB" {
    BIG=$(python3 -c "print('x' * 52000)")
    INPUT=$(jq -cn --arg resp "$BIG" '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":$resp,"session_id":"sess-5"}')
    run bash "$SCRIPT" <<< "$INPUT"
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

@test "handles tool_response as JSON object" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"mcp_tool","tool_input":{},"tool_response":{"llmContent":"some content","returnDisplay":"some content"},"session_id":"sess-6"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
}

# --- Block cases ---

@test "replaces output when AIRS returns block" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"sensitive data: password=abc123","session_id":"sess-7"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.hookSpecificOutput.tool_response.llmContent | test("BLOCKED")'
    echo "$output" | jq -e '.hookSpecificOutput.tool_response.returnDisplay | test("BLOCKED")'
}

@test "block message contains scan_id" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"bad content","session_id":"sess-8"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.hookSpecificOutput.tool_response.llmContent | test("mock-scan-block")'
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"some output","session_id":"sess-9"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.hookSpecificOutput.tool_response.llmContent | test("fail-closed")'
}

@test "fail-closed when profile is missing" {
    unset PRISMA_AIRS_PROFILE_NAME
    unset PRISMA_AIRS_PROFILE_ID
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"some output","session_id":"sess-10"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.hookSpecificOutput.tool_response'
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{},"tool_response":"some output","session_id":"sess-11"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}
