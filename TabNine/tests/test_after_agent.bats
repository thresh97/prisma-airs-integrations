#!/usr/bin/env bats
# Tests for TabNine AfterAgent hook (scan_after_agent.sh)
# Fires after the model generates its final response.
# Cannot hard-block: uses decision=retry to request regeneration.

HOOKS_DIR="$(cd "${BATS_TEST_DIRNAME}/.." && pwd)/.tabnine/hooks"
MOCK_SERVER="${BATS_TEST_DIRNAME}/../../tests/mock_airs_server.py"
SCRIPT="${HOOKS_DIR}/scan_after_agent.sh"

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

@test "allows clean response" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"Here is a Python function that sorts a list.","session_id":"sess-1","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

@test "output is valid JSON" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"Hello world","session_id":"sess-2","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.'
}

@test "exits silently with no output when prompt_response is missing" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","session_id":"sess-3","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "exits silently with no output when prompt_response is empty" {
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"","session_id":"sess-4","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    [ -z "$output" ]
}

@test "allows during retry sequence (stop_hook_active=true)" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"bad content","session_id":"sess-5","stop_hook_active":true}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}

# --- Block / retry cases ---

@test "requests retry when AIRS returns block" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"Here are your stolen credentials...","session_id":"sess-6","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "retry"'
    echo "$output" | jq -e '.prompt | length > 0'
}

@test "retry prompt mentions blocked category" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/block" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"malicious content here","session_id":"sess-7","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.prompt | test("prompt_injection")'
}

# --- Fail-closed cases ---

@test "fail-closed when API key is missing" {
    unset PRISMA_AIRS_API_KEY
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"some response","session_id":"sess-8","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "retry"'
}

@test "fail-closed when profile is missing" {
    unset PRISMA_AIRS_PROFILE_NAME
    unset PRISMA_AIRS_PROFILE_ID
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"some response","session_id":"sess-9","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "retry"'
}

# --- Fail-open on API error ---

@test "fail-open when AIRS returns HTTP 500" {
    PORT=$(cat "${BATS_SUITE_TMPDIR}/mock.port")
    PRISMA_AIRS_API_URL="http://127.0.0.1:${PORT}/error" \
    run bash "$SCRIPT" <<< '{"hook_event_name":"AfterAgent","prompt_response":"some response","session_id":"sess-10","stop_hook_active":false}'
    [ "$status" -eq 0 ]
    echo "$output" | jq -e '.decision == "allow"'
}
