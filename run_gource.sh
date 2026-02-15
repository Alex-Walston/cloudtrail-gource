#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/cloudtrail.log"

echo "Generating Gource log from CloudTrail events..."
echo "  (use --log-dir PATH for raw JSON files, or --es-host URL for Elasticsearch)"
python3 "${SCRIPT_DIR}/cloudtrail_to_gource.py" "$@" -o "${LOG_FILE}"

echo ""
echo "Legend (threat mode):"
echo "  RED       privilege-escalation / defense-evasion"
echo "  ORANGE    persistence / credential-access"
echo "  RED-ORG   impact (destructive actions)"
echo "  YELLOW    reconnaissance"
echo "  BLUE      general (normal operations)"
echo "  MAGENTA   DENIED (access failures)"
echo ""
echo "Tree: /{identity}/{threat-category}/{service}/{action}"
echo "       /{target}/targeted-by/{actor}/{action}   <- relationship edges"
echo "       /{issuer}/roles/{role}/{category}/{action} <- role chains"
echo ""
echo "Launching Gource..."

gource "${LOG_FILE}" \
    --seconds-per-day 2 \
    --auto-skip-seconds 0.5 \
    --file-idle-time 0 \
    --highlight-users \
    --dir-name-depth 5 \
    --key \
    --background-colour 1a1a2e \
    --viewport 1280x720 \
    --title "CloudTrail Identity Threat View"
