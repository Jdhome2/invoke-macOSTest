#!/usr/bin/env bash
# Log Sanitization Script
# Removes sensitive data from execution logs before artifact upload

set -euo pipefail

LOG_FILE="${1:-}"

if [[ -z "$LOG_FILE" || ! -f "$LOG_FILE" ]]; then
    echo "ERROR: Valid log file path required"
    exit 1
fi

# Create backup
cp "$LOG_FILE" "${LOG_FILE}.original"

# Sanitization patterns
sanitize() {
    local file="$1"

    # Remove common secret patterns
    sed -i.bak -E \
        -e 's/(password|passwd|pwd)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=REDACTED/gi' \
        -e 's/(api[_-]?key|apikey)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=REDACTED/gi' \
        -e 's/(secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=REDACTED/gi' \
        -e 's/(bearer|authorization)[[:space:]]*[:=][[:space:]]*[^[:space:]]+/\1=REDACTED/gi' \
        "$file"

    # Remove email addresses (potential PII)
    sed -i.bak -E 's/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/EMAIL_REDACTED/g' "$file"

    # Remove IPv4 addresses (partial - keep first two octets for debugging)
    sed -i.bak -E 's/([0-9]{1,3}\.[0-9]{1,3}\.)[0-9]{1,3}\.[0-9]{1,3}/\1XXX.XXX/g' "$file"

    # Remove potential AWS keys
    sed -i.bak -E 's/AKIA[0-9A-Z]{16}/AWS_KEY_REDACTED/g' "$file"

    # Remove potential private keys
    sed -i.bak -E 's/-----BEGIN [A-Z ]+ PRIVATE KEY-----.*-----END [A-Z ]+ PRIVATE KEY-----/PRIVATE_KEY_REDACTED/gs' "$file"

    # Remove file paths containing 'secret', 'password', 'credential'
    sed -i.bak -E 's|/[^[:space:]]*/(secret|password|credential)[^[:space:]]*|/REDACTED_PATH|gi' "$file"

    # Remove cleanup files
    rm -f "${file}.bak"
}

echo "Sanitizing log file: $LOG_FILE"
sanitize "$LOG_FILE"
echo "Sanitization complete. Original saved as: ${LOG_FILE}.original"

# Verify file is valid JSON if it's a JSON file
if [[ "$LOG_FILE" == *.json ]]; then
    if command -v jq &> /dev/null; then
        if ! jq empty "$LOG_FILE" 2>/dev/null; then
            echo "WARNING: Sanitized file is not valid JSON. Restoring original."
            mv "${LOG_FILE}.original" "$LOG_FILE"
            exit 1
        fi
    fi
fi

exit 0
