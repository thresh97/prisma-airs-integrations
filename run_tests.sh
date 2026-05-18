#!/usr/bin/env bash
# Run all Prisma AIRS hook integration tests across TabNine, Cursor, and Windsurf.
# Requires: bats (brew install bats-core), jq, python3

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"

if ! command -v bats &>/dev/null; then
    echo "ERROR: bats not found. Install with: brew install bats-core"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq not found. Install with: brew install jq"
    exit 1
fi

PASS=0
FAIL=0

run_suite() {
    local label="$1"
    local dir="$2"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  $label"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if bats "$dir"/*.bats; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
}

run_suite "TabNine"   "${REPO_ROOT}/TabNine/tests"
run_suite "Cursor"    "${REPO_ROOT}/Cursor/tests"
run_suite "Windsurf"  "${REPO_ROOT}/Windsurf/tests"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Suites passed: ${PASS}  |  failed: ${FAIL}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ "$FAIL" -eq 0 ]
