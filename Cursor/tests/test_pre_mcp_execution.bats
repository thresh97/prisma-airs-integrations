#!/usr/bin/env bats
# Tests for Cursor beforeMCPExecution hook (pre_mcp_execution.sh)

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.cursor/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/pre_mcp_execution.sh"

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

@test "allows clean MCP tool input" {
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:search_repos","tool_input":{"query":"prisma-airs"},"conversation_id":"conv-1"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}

@test "output is valid JSON" {
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:filesystem:read_file","tool_input":{"path":"/tmp/test.txt"},"conversation_id":"conv-2"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
}

@test "allows when tool_name is missing" {
    run bash "$SCRIPT" <<< '{"conversation_id":"conv-3"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}

@test "allows when tool_input is null" {
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:list_repos","tool_input":null,"conversation_id":"conv-4"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}

@test "allows when tool_input is empty" {
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:list_repos","tool_input":{},"conversation_id":"conv-5"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}

@test "handles non-MCP tool name" {
    run bash "$SCRIPT" <<< '{"tool_name":"Bash","tool_input":{"command":"ls"},"conversation_id":"conv-6"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}

# --- Block cases ---

@test "blocks MCP tool when AIRS returns block" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:create_file","tool_input":{"content":"malicious payload"},"conversation_id":"conv-7"}'
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.permission == "deny"'
    echo "$output" | jq -e '.user_message | length > 0'
    echo "$output" | jq -e '.agent_message | length > 0'
}

@test "deny user_message references tool name" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:create_file","tool_input":{"content":"bad"},"conversation_id":"conv-8"}'
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.user_message | test("MCP:github:create_file")'
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:search","tool_input":{"query":"x"},"conversation_id":"conv-9"}'
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.permission == "deny"'
}

@test "fail-closed when profile is missing" {
    unset PRISMA_AIRS_PROFILE_NAME
    unset PRISMA_AIRS_PROFILE_ID
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:search","tool_input":{"query":"x"},"conversation_id":"conv-10"}'
    [ "$status" -eq 2 ]
    echo "$output" | jq -e '.permission == "deny"'
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"tool_name":"MCP:github:search","tool_input":{"query":"x"},"conversation_id":"conv-11"}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.permission == "allow"'
}
