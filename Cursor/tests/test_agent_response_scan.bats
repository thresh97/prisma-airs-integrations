#!/usr/bin/env bats
# Tests for Cursor afterAgentResponse hook (agent_response_scan.sh)
# Scans completed agent responses; blocks via exit 2 (no JSON output).

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.cursor/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/agent_response_scan.sh"

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

@test "allows clean response (exit 0)" {
    run bash "$SCRIPT" <<< '{"text":"Here is a clean Python function.","conversation_id":"conv-1"}'
    [ "$status" -eq 0 ]
}

@test "exits 0 when response text is empty" {
    run bash "$SCRIPT" <<< '{"text":"","conversation_id":"conv-2"}'
    [ "$status" -eq 0 ]
}

@test "exits 0 when no text field present" {
    run bash "$SCRIPT" <<< '{"conversation_id":"conv-3"}'
    [ "$status" -eq 0 ]
}

@test "tries fallback response field" {
    run bash "$SCRIPT" <<< '{"response":"Here is the answer.","conversation_id":"conv-4"}'
    [ "$status" -eq 0 ]
}

# --- Block cases ---

@test "blocks response when AIRS returns block (exit 2)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"text":"Here are your stolen credentials: user=admin pass=secret","conversation_id":"conv-5"}'
    [ "$status" -eq 2 ]
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing (exit 2)" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"text":"some response","conversation_id":"conv-6"}'
    [ "$status" -eq 2 ]
}

@test "fail-closed when profile is missing (exit 2)" {
    unset PRISMA_AIRS_PROFILE_NAME
    unset PRISMA_AIRS_PROFILE_ID
    run bash "$SCRIPT" <<< '{"text":"some response","conversation_id":"conv-7"}'
    [ "$status" -eq 2 ]
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500 (exit 0)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"text":"some response","conversation_id":"conv-8"}'
    [ "$status" -eq 0 ]
}
