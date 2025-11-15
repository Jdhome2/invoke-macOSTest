#!/usr/bin/env bash
# Security Test Suite for Atomic Red Team Workflow

set -euo pipefail

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test utilities
test_pass() {
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
    echo -e "${GREEN}✓${NC} $1"
}

test_fail() {
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
    echo -e "${RED}✗${NC} $1"
    echo -e "  ${RED}Error:${NC} $2"
}

test_suite() {
    echo -e "\n${YELLOW}=== $1 ===${NC}\n"
}

# Change to repository root
cd "$(dirname "$0")/.."

# Test Suite 1: Input Validation
test_suite "Input Validation Tests"

# Test valid TTP formats
if scripts/validate-ttp.sh "T1234" &>/dev/null; then
    test_pass "Valid TTP: T1234"
else
    test_fail "Valid TTP: T1234" "Should accept basic format"
fi

if scripts/validate-ttp.sh "T1234.001" &>/dev/null; then
    test_pass "Valid TTP: T1234.001"
else
    test_fail "Valid TTP: T1234.001" "Should accept sub-technique"
fi

if scripts/validate-ttp.sh "T1234.001-2" &>/dev/null; then
    test_pass "Valid TTP: T1234.001-2"
else
    test_fail "Valid TTP: T1234.001-2" "Should accept test variation"
fi

# Test invalid TTP formats
if ! scripts/validate-ttp.sh "INVALID" &>/dev/null; then
    test_pass "Invalid TTP rejected: INVALID"
else
    test_fail "Invalid TTP rejected: INVALID" "Should reject non-T format"
fi

if ! scripts/validate-ttp.sh "T123" &>/dev/null; then
    test_pass "Invalid TTP rejected: T123 (too short)"
else
    test_fail "Invalid TTP rejected: T123" "Should reject short format"
fi

if ! scripts/validate-ttp.sh "T12345" &>/dev/null; then
    test_pass "Invalid TTP rejected: T12345 (too long)"
else
    test_fail "Invalid TTP rejected: T12345" "Should reject long format"
fi

# Test command injection attempts
if ! scripts/validate-ttp.sh "T1234; rm -rf /" &>/dev/null; then
    test_pass "Command injection blocked: semicolon"
else
    test_fail "Command injection blocked: semicolon" "Should block shell metacharacters"
fi

if ! scripts/validate-ttp.sh "T1234\$(whoami)" &>/dev/null; then
    test_pass "Command injection blocked: command substitution"
else
    test_fail "Command injection blocked" "Should block command substitution"
fi

if ! scripts/validate-ttp.sh "T1234|cat /etc/passwd" &>/dev/null; then
    test_pass "Command injection blocked: pipe"
else
    test_fail "Command injection blocked: pipe" "Should block pipe character"
fi

if ! scripts/validate-ttp.sh "T1234&whoami" &>/dev/null; then
    test_pass "Command injection blocked: ampersand"
else
    test_fail "Command injection blocked: ampersand" "Should block ampersand"
fi

# Test range validation
if ! scripts/validate-ttp.sh "T0001" &>/dev/null; then
    test_pass "Out of range TTP rejected: T0001"
else
    test_fail "Out of range TTP rejected" "Should reject T0001 (out of range)"
fi

if ! scripts/validate-ttp.sh "T9999" &>/dev/null; then
    test_pass "Out of range TTP rejected: T9999"
else
    test_fail "Out of range TTP rejected" "Should reject T9999 (out of range)"
fi

# Test Suite 2: Log Sanitization
test_suite "Log Sanitization Tests"

# Create test log file
TEST_LOG=$(mktemp)
trap "rm -f $TEST_LOG $TEST_LOG.original" EXIT

# Test password sanitization
echo "password=SecretPass123" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "SecretPass123" "$TEST_LOG"; then
    test_pass "Password sanitized"
else
    test_fail "Password sanitization" "Password still visible in log"
fi

# Test API key sanitization
echo "api_key=abcdef123456" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "abcdef123456" "$TEST_LOG"; then
    test_pass "API key sanitized"
else
    test_fail "API key sanitization" "API key still visible"
fi

# Test token sanitization
echo "token=ghp_1234567890abcdefghijklmnopqrstuvwxyz" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "ghp_1234567890" "$TEST_LOG"; then
    test_pass "Token sanitized"
else
    test_fail "Token sanitization" "Token still visible"
fi

# Test email sanitization
echo "User: test@example.com logged in" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "test@example.com" "$TEST_LOG"; then
    test_pass "Email sanitized"
else
    test_fail "Email sanitization" "Email still visible"
fi

# Test IP sanitization
echo "Connected to 192.168.1.100" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "192.168.1.100" "$TEST_LOG"; then
    test_pass "IP address sanitized"
else
    test_fail "IP sanitization" "Full IP still visible"
fi

# Test AWS key sanitization
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > "$TEST_LOG"
scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if ! grep -q "AKIAIOSFODNN7EXAMPLE" "$TEST_LOG"; then
    test_pass "AWS key sanitized"
else
    test_fail "AWS key sanitization" "AWS key still visible"
fi

# Test JSON validity preservation
cat > "$TEST_LOG" <<'EOF'
{
  "test": "value",
  "password": "secret123",
  "data": {"nested": "value"}
}
EOF

scripts/sanitize-logs.sh "$TEST_LOG" &>/dev/null

if command -v jq &>/dev/null; then
    if jq empty "$TEST_LOG" 2>/dev/null; then
        test_pass "JSON validity preserved after sanitization"
    else
        test_fail "JSON validity" "JSON invalid after sanitization"
    fi
fi

# Test Suite 3: Workflow Security
test_suite "Workflow Security Tests"

# Check for unpinned actions in hardened workflow
if ! grep -q 'uses:.*@v[0-9]' .github/workflows/actions-hardened.yml; then
    test_pass "No unpinned actions in hardened workflow"
else
    test_fail "Unpinned actions check" "Found unpinned actions in hardened workflow"
fi

# Check for proper permissions in hardened workflow
if grep -q "permissions:" .github/workflows/actions-hardened.yml; then
    test_pass "Workflow permissions defined"
else
    test_fail "Workflow permissions" "No permissions block found"
fi

# Check for timeout in hardened workflow
if grep -q "timeout-minutes:" .github/workflows/actions-hardened.yml; then
    test_pass "Job timeout configured"
else
    test_fail "Job timeout" "No timeout configured"
fi

# Check for concurrency control
if grep -q "concurrency:" .github/workflows/actions-hardened.yml; then
    test_pass "Concurrency control configured"
else
    test_fail "Concurrency control" "No concurrency configuration found"
fi

# Check for validation job
if grep -q "validate-inputs:" .github/workflows/actions-hardened.yml; then
    test_pass "Input validation job exists"
else
    test_fail "Input validation job" "No validation job found"
fi

# Test Suite 4: Security Files
test_suite "Security Configuration Files"

REQUIRED_FILES=(
    "SECURITY.md"
    "SECURITY_REVIEW.md"
    ".github/workflows/security-checks.yml"
    ".gitleaks.toml"
    "CODEOWNERS"
    ".github/dependabot.yml"
    "scripts/validate-ttp.sh"
    "scripts/sanitize-logs.sh"
    "scripts/install-atomic-redteam.sh"
    "scripts/security-monitor.sh"
    "docs/INCIDENT_RESPONSE.md"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        test_pass "Required file exists: $file"
    else
        test_fail "Required file" "$file not found"
    fi
done

# Test Suite 5: Script Executability
test_suite "Script Permissions"

SCRIPTS=(
    "scripts/validate-ttp.sh"
    "scripts/sanitize-logs.sh"
    "scripts/install-atomic-redteam.sh"
    "scripts/security-monitor.sh"
)

for script in "${SCRIPTS[@]}"; do
    if [[ -x "$script" ]]; then
        test_pass "Script executable: $script"
    else
        # Try to make executable
        chmod +x "$script" 2>/dev/null && test_pass "Script made executable: $script" || test_fail "Script permissions" "$script not executable"
    fi
done

# Test Suite 6: Gitleaks Configuration
test_suite "Secret Scanning Configuration"

if [[ -f ".gitleaks.toml" ]]; then
    # Check for key rules
    if grep -q "github-pat" .gitleaks.toml; then
        test_pass "GitHub PAT detection configured"
    else
        test_fail "GitHub PAT detection" "Rule not found in .gitleaks.toml"
    fi

    if grep -q "aws-access-key" .gitleaks.toml; then
        test_pass "AWS key detection configured"
    else
        test_fail "AWS key detection" "Rule not found"
    fi

    if grep -q "allowlist" .gitleaks.toml; then
        test_pass "Allowlist configured for false positives"
    else
        test_fail "Allowlist configuration" "No allowlist found"
    fi
fi

# Final Report
echo -e "\n${YELLOW}=== Test Summary ===${NC}\n"
echo "Total Tests: $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [[ $TESTS_FAILED -eq 0 ]]; then
    echo -e "\n${GREEN}All tests passed!${NC}\n"
    exit 0
else
    echo -e "\n${RED}Some tests failed!${NC}\n"
    exit 1
fi
