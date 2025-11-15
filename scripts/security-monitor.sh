#!/usr/bin/env bash
# Security Monitoring Script
# Monitors Atomic Red Team workflow execution for security anomalies

set -euo pipefail

# Configuration
MONITORING_INTERVAL="${MONITORING_INTERVAL:-60}"  # seconds
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"
LOG_FILE="${LOG_FILE:-/var/log/atomic-security-monitor.log}"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

alert() {
    local severity="$1"
    local message="$2"

    log "${severity}: ${message}"

    # Send to webhook if configured
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        curl -X POST "$ALERT_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"severity\":\"${severity}\",\"message\":\"${message}\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            || log "WARNING: Failed to send alert to webhook"
    fi
}

check_workflow_integrity() {
    log "Checking workflow integrity..."

    # Check for unpinned actions
    if grep -r "uses:.*@v[0-9]" .github/workflows/ 2>/dev/null; then
        alert "HIGH" "Unpinned GitHub Actions detected in workflows"
        return 1
    fi

    # Check for hardcoded secrets
    if grep -ri "password\|secret\|api.key" .github/workflows/ 2>/dev/null | grep -v "secrets\." | grep -v "#"; then
        alert "CRITICAL" "Potential hardcoded secrets detected in workflows"
        return 1
    fi

    log "Workflow integrity check: PASSED"
    return 0
}

check_recent_commits() {
    log "Checking recent commits..."

    # Get commits from last hour
    RECENT_COMMITS=$(git log --since="1 hour ago" --oneline --no-merges)

    if [[ -n "$RECENT_COMMITS" ]]; then
        log "Recent commits detected:"
        echo "$RECENT_COMMITS" | tee -a "$LOG_FILE"

        # Check commit signatures
        while IFS= read -r commit; do
            COMMIT_SHA=$(echo "$commit" | awk '{print $1}')
            if ! git verify-commit "$COMMIT_SHA" 2>/dev/null; then
                alert "MEDIUM" "Unsigned commit detected: $COMMIT_SHA"
            fi
        done <<< "$RECENT_COMMITS"
    fi
}

check_workflow_runs() {
    log "Checking recent workflow runs..."

    # Requires gh CLI
    if ! command -v gh &> /dev/null; then
        log "WARNING: gh CLI not found, skipping workflow run checks"
        return 0
    fi

    # Get recent runs
    RECENT_RUNS=$(gh run list --limit 10 --json status,conclusion,createdAt,headBranch 2>/dev/null || echo "[]")

    # Check for suspicious patterns
    FAILED_COUNT=$(echo "$RECENT_RUNS" | jq '[.[] | select(.conclusion=="failure")] | length')
    CANCELLED_COUNT=$(echo "$RECENT_RUNS" | jq '[.[] | select(.conclusion=="cancelled")] | length')

    if [[ $FAILED_COUNT -gt 3 ]]; then
        alert "MEDIUM" "High failure rate detected: $FAILED_COUNT failures in last 10 runs"
    fi

    if [[ $CANCELLED_COUNT -gt 5 ]]; then
        alert "LOW" "High cancellation rate: $CANCELLED_COUNT cancellations in last 10 runs"
    fi

    # Check for runs from unexpected branches
    UNEXPECTED_BRANCHES=$(echo "$RECENT_RUNS" | jq -r '.[] | select(.headBranch | test("^(main|master|claude/)") | not) | .headBranch' | sort -u)
    if [[ -n "$UNEXPECTED_BRANCHES" ]]; then
        alert "MEDIUM" "Workflow runs from unexpected branches: $UNEXPECTED_BRANCHES"
    fi
}

check_runner_status() {
    log "Checking runner status..."

    if ! command -v gh &> /dev/null; then
        log "WARNING: gh CLI not found, skipping runner checks"
        return 0
    fi

    # Check for self-hosted runners
    RUNNERS=$(gh api repos/:owner/:repo/actions/runners --jq '.runners[] | select(.name=="tartelet")' 2>/dev/null || echo "")

    if [[ -n "$RUNNERS" ]]; then
        RUNNER_STATUS=$(echo "$RUNNERS" | jq -r '.status')
        if [[ "$RUNNER_STATUS" != "online" ]]; then
            alert "HIGH" "Self-hosted runner 'tartelet' is not online (status: $RUNNER_STATUS)"
        fi

        # Check for multiple runners (potential compromise)
        RUNNER_COUNT=$(echo "$RUNNERS" | jq -s 'length')
        if [[ $RUNNER_COUNT -gt 1 ]]; then
            alert "HIGH" "Multiple runners detected with same name: $RUNNER_COUNT"
        fi
    fi
}

check_artifacts() {
    log "Checking recent artifacts..."

    if ! command -v gh &> /dev/null; then
        return 0
    fi

    # Get recent runs with artifacts
    RUNS_WITH_ARTIFACTS=$(gh run list --limit 5 --json databaseId,conclusion 2>/dev/null | jq -r '.[] | select(.conclusion=="success") | .databaseId')

    for RUN_ID in $RUNS_WITH_ARTIFACTS; do
        # Check artifact sizes
        ARTIFACTS=$(gh api "repos/:owner/:repo/actions/runs/$RUN_ID/artifacts" --jq '.artifacts[]' 2>/dev/null || echo "")

        if [[ -n "$ARTIFACTS" ]]; then
            TOTAL_SIZE=$(echo "$ARTIFACTS" | jq -s 'map(.size_in_bytes) | add')

            # Alert if artifacts are suspiciously large (>100MB)
            if [[ $TOTAL_SIZE -gt 104857600 ]]; then
                alert "MEDIUM" "Large artifacts detected in run $RUN_ID: $(($TOTAL_SIZE / 1048576))MB"
            fi
        fi
    done
}

check_security_files() {
    log "Checking security configuration files..."

    REQUIRED_FILES=(
        "SECURITY.md"
        ".github/workflows/security-checks.yml"
        ".gitleaks.toml"
        "CODEOWNERS"
        "scripts/validate-ttp.sh"
        "scripts/sanitize-logs.sh"
    )

    MISSING_FILES=()
    for file in "${REQUIRED_FILES[@]}"; do
        if [[ ! -f "$file" ]]; then
            MISSING_FILES+=("$file")
        fi
    done

    if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
        alert "HIGH" "Missing security files: ${MISSING_FILES[*]}"
    fi
}

generate_security_report() {
    log "Generating security report..."

    cat <<EOF

=== Security Monitoring Report ===
Generated: $(date)

Workflow Integrity: $(check_workflow_integrity && echo "✅ PASS" || echo "❌ FAIL")
Recent Commits: $(git log --since="1 hour ago" --oneline --no-merges | wc -l) in last hour
Workflow Runs: $(gh run list --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || echo "Unknown")
Runner Status: $(gh api repos/:owner/:repo/actions/runners --jq '.runners[] | select(.name=="tartelet") | .status' 2>/dev/null || echo "Unknown")

Last 5 Workflow Runs:
$(gh run list --limit 5 --json conclusion,createdAt,headBranch 2>/dev/null | jq -r '.[] | "\(.createdAt) - \(.headBranch) - \(.conclusion)"' || echo "Unable to fetch")

Security Files Status:
$(for f in SECURITY.md CODEOWNERS .gitleaks.toml; do [[ -f "$f" ]] && echo "✅ $f" || echo "❌ $f"; done)

===================================

EOF
}

# Main monitoring loop
main() {
    log "Starting security monitoring..."
    log "Monitoring interval: ${MONITORING_INTERVAL}s"

    # Change to repository directory if REPO_PATH is set
    if [[ -n "${REPO_PATH:-}" ]]; then
        cd "$REPO_PATH"
    fi

    while true; do
        check_workflow_integrity || true
        check_recent_commits || true
        check_workflow_runs || true
        check_runner_status || true
        check_artifacts || true
        check_security_files || true

        log "Monitoring cycle complete. Next check in ${MONITORING_INTERVAL}s"
        sleep "$MONITORING_INTERVAL"
    done
}

# Run once if --once flag provided
if [[ "${1:-}" == "--once" ]]; then
    check_workflow_integrity
    check_recent_commits
    check_workflow_runs
    check_runner_status
    check_artifacts
    check_security_files
    generate_security_report
else
    main
fi
