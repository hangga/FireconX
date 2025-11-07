#!/bin/bash
set -euo pipefail

# ==================================================
#   FIRECONX v2.5 - Mobile Pentest (Google body-check)
# ==================================================

# Colors (ANSI)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Helpers
ts() { date "+%Y-%m-%d %H:%M:%S"; }

# Global logfile (set later)
LOG_FILE=""

# Colored log: prints colored text to terminal and appends same text to logfile.
log() {
  local level="$1"
  local msg="$2"
  local color="$NC"
  case "$level" in
    INFO) color="$BLUE" ;;
    SUCCESS) color="$GREEN" ;;
    WARNING) color="$YELLOW" ;;
    ERROR) color="$RED" ;;
    VULN) color="$RED" ;;
    *) color="$NC" ;;
  esac

  local line="[$(ts)][$level] $msg"
  # print colored to terminal
  echo -e "${color}${line}${NC}"
  # append colored to logfile (if set). If you want logfile without colors, pipe through sed to strip ANSI.
  if [ -n "${LOG_FILE:-}" ]; then
    echo -e "${color}${line}${NC}" >> "$LOG_FILE"
  fi
}

# Normalize URL: remove scheme then return https://host/path (no duplicate slashes)
normalize_url() {
  local url="$1"
  # trim spaces
  url="$(echo "$url" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  # strip leading http(s)://
  url="${url#http://}"
  url="${url#https://}"
  # strip leading slashes
  url="${url#/}"
  # remove trailing slash
  url="${url%/}"
  printf "https://%s" "$url"
}

# Do a curl request; returns "HTTP|--|BODY"
# params: url method data timeout
do_curl() {
  local url="$1"
  local method="${2:-GET}"
  local data="${3:-}"
  local timeout="${4:-8}"

  local curl_args=(--silent --show-error --max-time "$timeout" --write-out "HTTP_STATUS:%{http_code}")

  if [ "$method" != "GET" ]; then
    curl_args+=(-X "$method" -H "Content-Type: application/json" -d "$data")
  fi

  # Attempt once
  local resp
  resp="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
  local code
  code="$(echo "$resp" | tr -d '\r' | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\)$/\1/p' || true)"
  local body
  body="$(echo "$resp" | sed -e 's/HTTP_STATUS:[0-9]\{3\}$//' || true)"

  # retry once on empty code
  if [ -z "$code" ]; then
    sleep 1
    resp="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
    code="$(echo "$resp" | tr -d '\r' | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\)$/\1/p' || true)"
    body="$(echo "$resp" | sed -e 's/HTTP_STATUS:[0-9]\{3\}$//' || true)"
  fi

  if [ -z "$code" ]; then
    code="000"
    body=""
  fi

  printf "%s|--|%s" "$code" "$body"
}

# Generic test that handles firebase-like endpoints and stores sample for vuln
test_http() {
  local raw_url="$1"
  local desc="$2"
  local method="${3:-GET}"
  local data="${4:-}"

  # Normalize if needed
  local url
  if [[ "$raw_url" =~ ^https?:// ]]; then
    # fix duplicate scheme segments like https:////host
    url="$(echo "$raw_url" | sed -E 's#(https?://)+#https://#')"
  else
    url="$(normalize_url "$raw_url")"
  fi

  log INFO "Testing $desc -> $url"

  local result
  result="$(do_curl "$url" "$method" "$data")"
  local http_code="${result%%|--|*}"
  local body="${result#*|--|}"

  if [ "$http_code" = "000" ]; then
    log WARNING "No HTTP response from $url"
    return 0
  fi

  local body_lc
  body_lc="$(echo "$body" | tr '[:upper:]' '[:lower:]')"

  if [[ "$http_code" =~ ^2 ]]; then
    # if google-like error messages inside body, treat accordingly (secure/error)
    if echo "$body_lc" | grep -qiE '"error_message"|"request_denied"|"error"|"permission"|"denied"|"unauthorized"'; then
      log SUCCESS "SECURE: $desc (HTTP $http_code with error in body)"
      # save body for inspection
      if [ -n "${LOG_FILE:-}" ]; then
        local fname
        fname="$(printf "%s/%s_error.json" "$OUTPUT_DIR" "$(echo "$desc" | sed 's/[^a-zA-Z0-9]/_/g')")"
        echo "$body" > "$fname"
        log INFO "Saved error body to $fname"
      fi
      return 0
    fi

    if [ "$method" = "GET" ]; then
      if [ -n "$body" ] && ! echo "$body" | grep -qE '^(null|\{\}|\[\])$'; then
        log VULN "VULNERABLE: Publicly readable (HTTP $http_code) - $desc"
        # store sample to logfile
        if [ -n "${LOG_FILE:-}" ]; then
          echo "---- Sample: $desc ----" >> "$LOG_FILE"
          echo "$body" | head -c 800 >> "$LOG_FILE"
          echo "" >> "$LOG_FILE"
        fi
      else
        log INFO "No data found ($http_code) - $desc"
      fi
    else
      log VULN "VULNERABLE: Write allowed (HTTP $http_code) - $desc"
    fi

  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    log SUCCESS "SECURE: $desc (Access denied, HTTP $http_code)"
  elif [ "$http_code" = "404" ]; then
    log INFO "Not Found ($http_code) - $desc"
  else
    log WARNING "Unexpected status $http_code - $desc"
  fi
}

# Specialized test for Google Maps-style endpoints which often return 200 + error payload
test_google_api() {
  local endpoint="$1"   # full URL already containing key param or not
  local desc="$2"

  # ensure https and no duplicate slashes
  local url
  if [[ "$endpoint" =~ ^https?:// ]]; then
    url="$(echo "$endpoint" | sed -E 's#(https?://)+#https://#')"
  else
    url="$(normalize_url "$endpoint")"
  fi

  log INFO "Testing $desc -> $url"

  local result
  # Use slightly longer timeout for maps
  result="$(do_curl "$url" "GET" "" 12)"
  local http_code="${result%%|--|*}"
  local body="${result#*|--|}"

  if [ "$http_code" = "000" ]; then
    log WARNING "No HTTP response from $url"
    return 0
  fi

  # Check body for Google error info even when HTTP 200
  if [ "$http_code" = "200" ]; then
    local body_lc
    body_lc="$(echo "$body" | tr '[:upper:]' '[:lower:]')"
    if echo "$body_lc" | grep -qiE '"error_message"|"request_denied"|"status"\s*:\s*"request_denied"'; then
      log WARNING "SECURE (API error in 200): $desc (HTTP 200 but API error)"
      # save payload
      if [ -n "${LOG_FILE:-}" ]; then
        local fname="$OUTPUT_DIR/$(echo "$desc" | sed 's/[^a-zA-Z0-9]/_/g')_google_error.json"
        echo "$body" > "$fname"
        log INFO "Saved Google error body to $fname"
      fi
      return 0
    else
      log SUCCESS "OPEN: $desc (HTTP 200, no API error found)"
      # optionally save successful response
      if [ -n "${LOG_FILE:-}" ]; then
        local fname="$OUTPUT_DIR/$(echo "$desc" | sed 's/[^a-zA-Z0-9]/_/g')_google_ok.json"
        echo "$body" > "$fname"
      fi
      return 0
    fi
  fi

  # If non-200, rely on generic logic
  if [[ "$http_code" =~ ^(401|403)$ ]]; then
    log SUCCESS "SECURE: $desc (Access denied, $http_code)"
  else
    log WARNING "Unexpected status $http_code - $desc"
  fi
}

# Runners
run_firebase_tests() {
  local base="$1"
  test_http "${base}/.json" "Root"
  test_http "${base}/users.json" "Users"
  test_http "${base}/messages.json" "Messages"
  test_http "${base}/orders.json" "Orders"
  # write tests (PUT/POST)
  test_http "${base}/pentest_$(date +%s).json" "Write test (PUT)" "PUT" '{"test":"unauthorized_write"}'
  test_http "${base}/test_collection.json" "POST test" "POST" '{"pentest":true}'
}

run_storage_tests() {
  local base="$1"
  # extract host and project id
  local host
  host="$(echo "$base" | sed -E 's#https?://([^/]+).*#\1#')"
  local proj="${host%.firebaseio.com}"
  if [ -z "$proj" ]; then
    log WARNING "Cannot extract project id from $base"
    return
  fi
  local storage_url="https://firebasestorage.googleapis.com/v0/b/${proj}.appspot.com/o"
  test_http "$storage_url" "Storage Bucket List"
  test_http "${storage_url}/images%2Ftest.jpg" "Sample Image"
}

run_maps_tests() {
  local key="$1"
  # build endpoints with key param (if key already present in argument endpoint pass full)
  test_google_api "https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key=${key}" "Geocode API"
  test_google_api "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant&key=${key}" "Places API"
  test_google_api "https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key=${key}" "Directions API"
}

check_key_restrictions() {
  local key="$1"
  for svc in maps.googleapis.com places.googleapis.com vision.googleapis.com translation.googleapis.com identitytoolkit.googleapis.com; do
    local u="https://${svc}/test?key=${key}"
    local code
    code="$(curl -s -o /dev/null -w "%{http_code}" "$u" || echo "000")"
    if [ "$code" = "403" ]; then
      log SUCCESS "Restricted: ${svc} ($code)"
    else
      log VULN "API Key usable with ${svc} ($code)"
    fi
  done
}

# ---------------------------
# Parse args
FIREBASE_URL=""
API_KEY=""
OUTPUT_DIR="pentest_$(date +%Y%m%d_%H%M%S)"

usage() {
  echo "Usage: $0 --url <firebase_url> [--key <api_key>] [--output <dir>]"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) FIREBASE_URL="$(normalize_url "$2")"; shift 2 ;;
    --key) API_KEY="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [ -z "${FIREBASE_URL:-}" ]; then
  usage
fi

mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/pentest.log"

log INFO "Initialized. Output dir: $OUTPUT_DIR"
log INFO "Firebase URL: $FIREBASE_URL"
if [ -n "${API_KEY:-}" ]; then
  log INFO "API Key: ${API_KEY:0:10}..."
else
  log WARNING "No API key provided; skipping Google API tests."
fi

# Run tests
run_firebase_tests "$FIREBASE_URL"
run_storage_tests "$FIREBASE_URL"

if [ -n "${API_KEY:-}" ]; then
  run_maps_tests "$API_KEY"
  check_key_restrictions "$API_KEY"
fi

# summary
log INFO "Generating summary..."
{
  echo "MOBILE PENTEST SUMMARY ($(date))"
  echo "Target: $FIREBASE_URL"
  echo "----------------------------------"
  echo "Vulnerable: $(grep -c 'VULNERABLE' "$LOG_FILE" || true)"
  echo "Secure: $(grep -c 'SECURE' "$LOG_FILE" || true)"
  echo "Warnings: $(grep -c 'WARNING' "$LOG_FILE" || true)"
  echo "----------------------------------"
  echo "Details:"
  grep -E 'VULNERABLE|SECURE|WARNING' "$LOG_FILE" || true
} > "$OUTPUT_DIR/summary.txt"

log SUCCESS "Pentest completed. Summary at $OUTPUT_DIR/summary.txt"
exit 0
