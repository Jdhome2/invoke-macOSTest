#!/usr/bin/env bash
# TTP Validation Script
# Validates MITRE ATT&CK Technique IDs to prevent injection attacks

set -euo pipefail

TTP="${1:-}"

# Input validation
if [[ -z "$TTP" ]]; then
    echo "ERROR: TTP identifier required"
    exit 1
fi

# Validate format: T<digits>[.<digits>][-<digits>]
# Examples: T1234, T1234.001, T1234.001-2
if ! [[ "$TTP" =~ ^T[0-9]{4}(\.[0-9]{3})?(-[0-9]+)?$ ]]; then
    echo "ERROR: Invalid TTP format: $TTP"
    echo "Expected format: T<4-digits>[.<3-digits>][-<number>]"
    echo "Examples: T1569, T1569.001, T1569.001-1"
    exit 1
fi

# Additional validation: Check if TTP is in allowed range
# MITRE ATT&CK uses T1000-T1999 range (as of 2025)
TTP_NUM=$(echo "$TTP" | grep -oP 'T\K[0-9]{4}')
if [[ $TTP_NUM -lt 1000 || $TTP_NUM -gt 1999 ]]; then
    echo "ERROR: TTP number out of valid range: T$TTP_NUM"
    echo "Valid range: T1000-T1999"
    exit 1
fi

# Check for shell metacharacters (defense in depth)
if [[ "$TTP" =~ [\$\`\;\|\&\<\>\(\)\{\}] ]]; then
    echo "ERROR: TTP contains invalid characters"
    exit 1
fi

echo "TTP validation passed: $TTP"
exit 0
