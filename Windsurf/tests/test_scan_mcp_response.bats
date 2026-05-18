#!/usr/bin/env bats
# Tests for Windsurf post_mcp_tool_use hook (scan-mcp-response.sh)
# Audit-only — cannot block. Always exits 0 (except exit 1 on missing API key).

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.windsurf/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/scan-mcp-response.sh"

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

@test "exits 0 for clean MCP response (audit only)" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"search_repos","mcp_tool_arguments":{},"mcp_result":"[{\"name\":\"repo1\"}]"},"trajectory_id":"traj-1"}'
    [ "$status" -eq 0 ]
}

@test "exits 0 even when AIRS would block (post-hooks cannot block)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"get_file","mcp_tool_arguments":{},"mcp_result":"secret_key=abc123"},"trajectory_id":"traj-2"}'
    [ "$status" -eq 0 ]
}

@test "exits 0 when mcp_result is empty" {
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"ping","mcp_tool_arguments":{},"mcp_result":""},"trajectory_id":"traj-3"}'
    [ "$status" -eq 0 ]
}

@test "exits 1 when API key is missing (cannot scan)" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"tool_info":{"mcp_server_name":"github","mcp_tool_name":"search","mcp_tool_arguments":{},"mcp_result":"results"},"trajectory_id":"traj-4"}'
    [ "$status" -eq 1 ]
}
