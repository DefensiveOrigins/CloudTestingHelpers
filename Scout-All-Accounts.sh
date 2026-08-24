
#!/usr/bin/env bash
#
# run_scoutsuite_all_accounts.sh
#
# For every credential set (profile) in ~/.aws/credentials, run ScoutSuite
# and write its report into a folder named for that profile/account.
#
# Usage:
#   ./run_scoutsuite_all_accounts.sh [output_root_dir]
#
# Requires: ScoutSuite installed and on PATH (pip install scoutsuite)

set -uo pipefail

CREDS_FILE="${AWS_SHARED_CREDENTIALS_FILE:-$HOME/.aws/credentials}"
OUTPUT_ROOT="${1:-./scoutsuite-reports}"

if [[ ! -f "$CREDS_FILE" ]]; then
    echo "Credentials file not found: $CREDS_FILE" >&2
    exit 1
fi

if ! command -v scout &>/dev/null; then
    echo "ScoutSuite ('scout' command) not found on PATH." >&2
    echo "Install it with: pip install scoutsuite" >&2
    exit 1
fi

# Pull out each [profile-name] section header from the credentials file
mapfile -t PROFILES < <(grep -oP '^\[\K[^]]+(?=\]\s*$)' "$CREDS_FILE")

if [[ ${#PROFILES[@]} -eq 0 ]]; then
    echo "No profiles found in $CREDS_FILE" >&2
    exit 1
fi

echo "Found ${#PROFILES[@]} profile(s): ${PROFILES[*]}"
mkdir -p "$OUTPUT_ROOT"

for profile in "${PROFILES[@]}"; do
    echo
    echo "=== ScoutSuite: $profile ==="
    report_dir="$OUTPUT_ROOT/$profile"
    mkdir -p "$report_dir"

    scout aws --profile "$profile" --report-dir "$report_dir" --no-browser

    if [[ $? -ne 0 ]]; then
        echo "!! ScoutSuite failed for profile '$profile' - continuing to next" >&2
    fi
done

echo
echo "Done. Reports are under: $OUTPUT_ROOT/<profile-name>/"