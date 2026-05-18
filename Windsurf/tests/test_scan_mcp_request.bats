#!/usr/bin/env bats
# Tests for Windsurf pre_mcp_tool_use hook (scan-mcp-request.sh)
# Blocks MCP tool calls via exit 2 before execution.

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.windsurf/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/scan-mcp-request.sh"

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

@test "allows clean MCP request (exit 0)" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"search_repos","mcp_tool_arguments":{"query":"prisma-airs"}},"trajectory_id":"traj-1"}'
    [ "$status" -eq 0 ]
}

@test "allows when mcp_tool_arguments is empty (exit 0)" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"list_repos","mcp_tool_arguments":{}},"trajectory_id":"traj-2"}'
    [ "$status" -eq 0 ]
}

@test "extracts query from web_search tool" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"brave","mcp_tool_name":"web_search","mcp_tool_arguments":{"query":"safe search term"}},"trajectory_id":"traj-3"}'
    [ "$status" -eq 0 ]
}

@test "extracts url from web_fetch tool" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"fetch","mcp_tool_name":"web_fetch","mcp_tool_arguments":{"url":"https://example.com"}},"trajectory_id":"traj-4"}'
    [ "$status" -eq 0 ]
}

# --- Block cases ---

@test "blocks MCP request when AIRS returns block (exit 2)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"create_file","mcp_tool_arguments":{"content":"malicious payload"}},"trajectory_id":"traj-5"}'
    [ "$status" -eq 2 ]
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing (exit 2)" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"search","mcp_tool_arguments":{"query":"x"}},"trajectory_id":"traj-6"}'
    [ "$status" -eq 2 ]
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500 (exit 0)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"search","mcp_tool_arguments":{"query":"x"}},"trajectory_id":"traj-7"}'
    [ "$status" -eq 0 ]
}
