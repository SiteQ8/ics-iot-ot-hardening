#!/usr/bin/env bash
#
# Secure ICS/IoT/OT Exposure Monitor
#
# Collects exposure information for ICS/OT/IoT devices using Shodan
# and generates structured reports. Optionally sends alert notifications
# securely via email or other configured channels.
#
# Author: Ali AlEnezi
# License: MIT
# Version: 1.0.0
#
# Requirements:
#   - Shodan CLI (https://cli.shodan.io/)
#   - jq (JSON processor)
#   - Optional: mailutils or another mail client for email alerts
#
# Usage:
#   chmod +x shodan-monitor.sh
#   ./shodan-monitor.sh
#
# Notes:
#   - Targets are read from 'targets.txt', one per line
#   - Outputs stored in 'shodan-monitor-reports' directory
#   - Designed to be safe: avoids unsafe CSV parsing, sanitizes filenames

set -euo pipefail
IFS=$'\n\t'

TARGETS_FILE="targets.txt"
OUTPUT_DIR="shodan-monitor-reports"
ALERT_EMAIL="security-team@example.com"
SHODAN_BIN="$(command -v shodan || true)"
JQ_BIN="$(command -v jq || true)"
MAIL_BIN="$(command -v mail || true)"  # optional
RETRY_MAX=3
RETRY_DELAY=5
SEPARATOR="|"

mkdir -p "$OUTPUT_DIR"

timestamp() { date +"%Y-%m-%d_%H%M%S"; }

# Dependency checks
if [[ -z "$SHODAN_BIN" ]]; then
  echo "Error: shodan CLI not found. Install from https://cli.shodan.io/" >&2
  exit 2
fi
if [[ -z "$JQ_BIN" ]]; then
  echo "Error: jq not found. Please install jq." >&2
  exit 2
fi

# Ensure target file exists
if [[ ! -f "$TARGETS_FILE" ]]; then
  echo "Error: targets file '$TARGETS_FILE' not found." >&2
  exit 2
fi

# Read file safely (skip blank lines and comments)
while IFS= read -r raw_target || [[ -n "$raw_target" ]]; do
  # strip leading/trailing spaces
  target="$(echo "$raw_target" | awk '{$1=$1;print}')"
  [[ -z "$target" || "${target:0:1}" == "#" ]] && continue

  ts="$(timestamp)"
  sanitized="$(echo "$target" | sed 's/[^A-Za-z0-9._-]/_/g')"
  report="$OUTPUT_DIR/report_${sanitized}_${ts}.json"

  echo "[$ts] Querying Shodan for $target ..."

  attempt=0
  success=0
  while (( attempt < RETRY_MAX )); do
    attempt=$((attempt + 1))
    # Use a safe separator (pipe) to limit CSV breaking; check your shodan version for --separator support
    if shodan search --fields ip_str,port,org,hostnames,product,title --separator "$SEPARATOR" "net:$target" > "$OUTPUT_DIR/tmp_${sanitized}.out" 2> "$OUTPUT_DIR/tmp_${sanitized}.err"; then
      # Convert CSV lines into JSON objects using the safe separator
      awk -v sep="$SEPARATOR" '
      BEGIN { OFS=""; print "[" }
      {
        # split to 6 fields (the hostnames field may contain the sep; so join last columns if too many)
        n = split($0, parts, sep);
        ip = parts[1]; port = parts[2]; org = parts[3];
        # hostnames may be a json-like array or a joined string; join parts[4..n-2] if necessary
        product = parts[n-1]; title = parts[n];
        # reconstruct hostnames if there are extra fields
        hostnames = "";
        for(i=4;i<=n-2;i++){
          hostnames = hostnames (i>4?sep:"") parts[i];
        }
        gsub(/^[ \t]+|[ \t]+$/, "", ip);
        if (NR>1) print ",";
        # For safety escape quotes in title/product
        gsub(/"/, "\\\"", product);
        gsub(/"/, "\\\"", title);
        gsub(/"/, "\\\"", hostnames);
        printf("{\"ip\":\"%s\",\"port\":\"%s\",\"org\":\"%s\",\"hostnames\":\"%s\",\"product\":\"%s\",\"title\":\"%s\"}", ip, port, org, hostnames, product, title);
      }
      END { print "]" }' "$OUTPUT_DIR/tmp_${sanitized}.out" > "$report" || true

      rm -f "$OUTPUT_DIR/tmp_${sanitized}.out" "$OUTPUT_DIR/tmp_${sanitized}.err"
      success=1
      break
    else
      echo "[$(timestamp)] shodan query failed (attempt $attempt). Retrying in $RETRY_DELAY s..."
      sleep $RETRY_DELAY
    fi
  done

  if (( success == 0 )); then
    echo "[$(timestamp)] ERROR: All attempts failed for $target. Check Shodan CLI and API key/rate limits." >&2
    continue
  fi

  # Validate JSON output with jq
  if ! jq empty "$report" 2>/dev/null; then
    echo "[$(timestamp)] WARNING: Report for $target is not valid JSON, saving raw output at $report" >&2
    continue
  fi

  count=$(jq 'length' "$report" || echo 0)
  if (( count > 0 )); then
    echo "[$(timestamp)] ALERT: Found $count exposed hosts for $target. Report: $report"
    # Recommended: send only a short alert; avoid attaching raw JSON with sensitive data.
    if [[ -n "$MAIL_BIN" ]]; then
      subject="Shodan Monitor ALERT: $count exposures for $target"
      body="Shodan monitor detected $count exposures in $target. Report stored at $report on the monitoring host."
      echo "$body" | mail -s "$subject" "$ALERT_EMAIL"
    else
      echo "Mail client not found; not sending email. Please check $report"
    fi
  else
    echo "[$(timestamp)] No exposures found for $target."
    # optionally remove empty reports after x days
  fi

  # small pause to avoid hitting rate limits
  sleep 2
done < "$TARGETS_FILE"

echo "Monitor run complete."
