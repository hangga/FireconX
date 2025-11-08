#!/bin/bash
set -euo pipefail

# ==================================================
#   FIRECONX v2.8 - Mobile Pentest (Remote Config + Google API Key checks improved)
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

# ---------------------------
# Improved Google API Key checks
# ---------------------------
# This function uses valid endpoints (GET/POST where needed) to determine if API key is usable,
# restricted, invalid, or API not enabled.
check_google_api_key() {
  local key="$1"
  log INFO "Checking Google API Key across several services..."

  # Define array of tests: each entry has name|method|url|data(optional)
  # Use safe, minimal requests. For services that require POST we send the smallest valid payload.
  local tests=(
    "MapsGeocode|GET|https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key=${key}|"
    "PlacesText|GET|https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant&key=${key}|"
    "Directions|GET|https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key=${key}|"
    "Translate|GET|https://translation.googleapis.com/language/translate/v2?key=${key}&q=hello&target=id|"
    "YouTube|GET|https://www.googleapis.com/youtube/v3/search?part=snippet&q=cybersecurity&key=${key}|"
    "Books|GET|https://www.googleapis.com/books/v1/volumes?q=python&key=${key}|"
    "SafeBrowsing|GET|https://safebrowsing.googleapis.com/v4/threatLists?key=${key}|"
    # Identity Toolkit signUp expects POST with JSON body containing returnSecureToken maybe; we'll send minimal payload
    "IdentityToolkit|POST|https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${key}|{\"returnSecureToken\":true}"
  )

  for t in "${tests[@]}"; do
    IFS='|' read -r name method url data <<< "$t"
    log INFO "Testing API key on $name -> $url (method=$method)"
    local result
    if [[ "$method" == "GET" ]]; then
      result="$(do_curl "$url" "GET" "" 8)"
    else
      # POST with small payload
      result="$(do_curl "$url" "POST" "$data" 10)"
    fi

    local code="${result%%|--|*}"
    local body="${result#*|--|}"
    local body_lc
    body_lc="$(echo "$body" | tr '[:upper:]' '[:lower:]')"

    # Save response for triage if interesting
    local safe_name
    safe_name="$(echo "$name" | sed 's/[^a-zA-Z0-9]/_/g')"
    if [ -n "${LOG_FILE:-}" ]; then
      echo "---- $name Response ($code) ----" >> "$OUTPUT_DIR/google_key_${safe_name}.resp"
      echo "$body" >> "$OUTPUT_DIR/google_key_${safe_name}.resp"
    fi

    # Interpret
    if [ "$code" = "200" ]; then
      # Some APIs return 200 but include error field (e.g., maps may return status: REQUEST_DENIED)
      if echo "$body_lc" | grep -qiE 'request_denied|permission_denied|error_message|accessnotconfigured|access_not_configured'; then
        # likely secure or API not enabled
        if echo "$body_lc" | grep -qi 'accessnotconfigured\|access_not_configured'; then
          log WARNING "SECURE (API not enabled): $name (HTTP 200 with accessNotConfigured)"
        else
          log WARNING "SECURE (API error in 200): $name (HTTP 200 with error payload)"
        fi
      else
        log VULN "API Key usable with $name (HTTP 200) — usable/unrestricted"
      fi
    elif [ "$code" = "400" ]; then
      if echo "$body_lc" | grep -qiE 'keyinvalid|invalid api key|api key not valid'; then
        log ERROR "Invalid API Key (400) - $name"
      else
        log WARNING "Bad Request (400) - $name"
      fi
    elif [ "$code" = "401" ]; then
      log WARNING "Unauthorized (401) - $name (possibly OAuth expected)"
    elif [ "$code" = "403" ]; then
      # Distinguish common messages
      if echo "$body_lc" | grep -qiE 'request_denied|forbidden|permission_denied|permission-denied|accessdenied'; then
        log SUCCESS "Restricted/Denied (403) - $name (API key present but restricted or not allowed)"
      elif echo "$body_lc" | grep -qi 'accessnotconfigured\|access_not_configured'; then
        log WARNING "API not enabled (403) - $name"
      else
        log SUCCESS "Restricted/Denied (403) - $name"
      fi
    elif [ "$code" = "404" ]; then
      # should be rare because we chose valid endpoints; treat as warning
      log WARNING "Endpoint not found (404) - $name"
    elif [ "$code" = "429" ]; then
      log WARNING "Rate limited (429) - $name"
    else
      log WARNING "Unexpected status $code - $name"
    fi

    # small delay to avoid aggressive rate hitting
    sleep 0.2
  done
}

# ---------------------------
# Remote Config specialized test
# (unchanged, full implementation included)
# ---------------------------
test_remote_config() {
  local endpoint="$1"
  local desc="$2"
  local ns_suffix="$3"

  local url
  if [[ "$endpoint" =~ ^https?:// ]]; then
    url="$(echo "$endpoint" | sed -E 's#(https?://)+#https://#')"
  else
    url="$(normalize_url "$endpoint")"
  fi

  log INFO "Testing Remote Config -> $url"

  local headers_file="$OUTPUT_DIR/rc_${ns_suffix}_headers.txt"
  local body_file="$OUTPUT_DIR/rc_${ns_suffix}_body.json"
  local http_code

  http_code="$(curl -sS -D "$headers_file" -o "$body_file" -m 12 -w "%{http_code}" "$url" 2>/dev/null || echo "000")"
  if [ -z "$http_code" ]; then http_code="000"; fi

  if [ "$http_code" = "000" ]; then
    log WARNING "No HTTP response from $url"
    return 0
  fi

  local body
  body="$(cat "$body_file" 2>/dev/null || true)"
  local headers
  headers="$(cat "$headers_file" 2>/dev/null || true)"
  local body_lc
  body_lc="$(echo "$body" | tr '[:upper:]' '[:lower:]')"

  local etag=""
  etag="$(echo "$headers" | grep -i '^etag:' || true | sed -E 's/^[eE][tT][aA][gG]:[[:space:]]*//')"
  local last_mod=""
  last_mod="$(echo "$headers" | grep -i '^last-modified:' || true | sed -E 's/^[lL][aA][sS][tT]-[mM][oO][dD][iI][fF][iI][eE][dD]:[[:space:]]*//')"

  if [ "$http_code" = "200" ]; then
    if echo "$body_lc" | grep -qiE '"entries"|"parameters"|"conditions"|"etag"|"state"|"template"'; then
      log VULN "VULNERABLE: Remote Config publicly readable (HTTP 200) - $desc"
      if [ -n "${LOG_FILE:-}" ]; then
        local full_payload_file="$OUTPUT_DIR/remoteconfig_${ns_suffix}_full.json"
        local saved_headers_file="$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt"
        mv "$body_file" "$full_payload_file" 2>/dev/null || echo "$body" > "$full_payload_file"
        mv "$headers_file" "$saved_headers_file" 2>/dev/null || echo "$headers" > "$saved_headers_file"
        log INFO "Saved Remote Config payload to $full_payload_file"
        log INFO "Saved Remote Config headers to $saved_headers_file"
      fi
      if [ -n "$etag" ]; then log INFO "ETag: $etag"; fi
      if [ -n "$last_mod" ]; then log INFO "Last-Modified: $last_mod"; fi
      return 0
    fi

    if echo "$body_lc" | grep -qiE 'permission_denied|request_denied|error|unauthorized|not_allowed'; then
      log SUCCESS "SECURE: Remote Config fetch returned API error (HTTP 200 with error payload) - $desc"
      if [ -n "${LOG_FILE:-}" ]; then
        local errfile="$OUTPUT_DIR/remoteconfig_${ns_suffix}_error.json"
        mv "$body_file" "$errfile" 2>/dev/null || echo "$body" > "$errfile"
        mv "$headers_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt" 2>/dev/null || true
        log INFO "Saved error payload to $errfile"
      fi
      return 0
    fi

    log WARNING "Unexpected 200 response (no clear remote config payload) - $desc"
    if [ -n "${LOG_FILE:-}" ]; then
      mv "$body_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_unknown.json" 2>/dev/null || echo "$body" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_unknown.json"
      mv "$headers_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt" 2>/dev/null || echo "$headers" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt"
      log INFO "Saved response to $OUTPUT_DIR/remoteconfig_${ns_suffix}_unknown.json"
    fi
    return 0
  fi

  if [[ "$http_code" =~ ^(401|403)$ ]]; then
    log SUCCESS "SECURE: Remote Config access denied (HTTP $http_code) - $desc"
    if [ -n "${LOG_FILE:-}" ]; then
      mv "$headers_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt" 2>/dev/null || echo "$headers" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt"
    fi
  elif [ "$http_code" = "404" ]; then
    log INFO "Not Found (404) - $desc"
  else
    if echo "$body_lc" | grep -qiE 'permission_denied|request_denied|error|unauthorized|not_allowed'; then
      log SUCCESS "SECURE: Remote Config returned error payload (HTTP $http_code) - $desc"
      if [ -n "${LOG_FILE:-}" ]; then
        mv "$body_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_error.json" 2>/dev/null || echo "$body" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_error.json"
        mv "$headers_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt" 2>/dev/null || echo "$headers" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt"
      fi
    else
      log WARNING "Unexpected status $http_code - $desc"
      if [ -n "${LOG_FILE:-}" ]; then
        mv "$body_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_other_${http_code}.json" 2>/dev/null || echo "$body" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_other_${http_code}.json"
        mv "$headers_file" "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt" 2>/dev/null || echo "$headers" > "$OUTPUT_DIR/remoteconfig_${ns_suffix}_headers.txt"
      fi
    fi
  fi
}

run_remote_config_tests() {
  local rc_url_arg="${1:-}"
  local project_arg="${2:-}"
  local ns_list="${NAMESPACES:-firebase}"
  local project_id=""

  if [ -n "$rc_url_arg" ]; then
    test_remote_config "$rc_url_arg" "Remote Config (custom endpoint)" "custom"
    return
  fi

  if [ -n "${project_arg:-}" ]; then
    project_id="$project_arg"
  else
    if [ -n "${FIREBASE_URL:-}" ]; then
      local host
      host="$(echo "$FIREBASE_URL" | sed -E 's#https?://([^/]+).*#\1#' || true)"
      project_id="${host%.firebaseio.com}"
      if [ -z "$project_id" ]; then
        project_id="$host"
      fi
    fi
  fi

  if [ -z "${project_id:-}" ]; then
    log WARNING "Cannot determine project id for Remote Config tests. Provide --project-id or --remote-config-url."
    return
  fi

  IFS=',' read -r -a ns_array <<< "$ns_list"
  for ns in "${ns_array[@]}"; do
    ns_trimmed="$(echo "$ns" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -z "$ns_trimmed" ]; then
      continue
    fi
    local base="https://firebaseremoteconfig.googleapis.com/v1/projects/${project_id}/namespaces/${ns_trimmed}:fetch"
    if [ -n "${API_KEY:-}" ]; then
      test_remote_config "${base}?key=${API_KEY}" "Remote Config (fetch with API key, ns=${ns_trimmed})" "${ns_trimmed}_withkey"
      sleep 0.3
    fi
    test_remote_config "${base}" "Remote Config (fetch without key, ns=${ns_trimmed})" "${ns_trimmed}_nokey"
    sleep 0.3
  done
}

# Runners (unchanged)
run_firebase_tests() {
  local base="$1"
  test_http "${base}/.json" "Root"
  test_http "${base}/users.json" "Users"
  test_http "${base}/messages.json" "Messages"
  test_http "${base}/orders.json" "Orders"
  test_http "${base}/pentest_$(date +%s).json" "Write test (PUT)" "PUT" '{"test":"unauthorized_write"}'
  test_http "${base}/test_collection.json" "POST test" "POST" '{"pentest":true}'
}

run_storage_tests() {
  local base="$1"
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
  test_google_api "https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key=${key}" "Geocode API"
  test_google_api "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant&key=${key}" "Places API"
  test_google_api "https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key=${key}" "Directions API"
}

# ---------------------------
# Parse args
FIREBASE_URL=""
API_KEY=""
OUTPUT_DIR="output_$(date +%Y%m%d_%H%M%S)"
REMOTE_CONFIG_URL=""
PROJECT_ID=""
NAMESPACES="firebase"   # comma-separated list, default single namespace 'firebase'

usage() {
  echo "Usage: $0 --url <firebase_url> [--key <api_key>] [--output <dir>] [--remote-config-url <url>] [--project-id <project>] [--namespaces <csv>]"
  echo ""
  echo "Examples:"
  echo "  $0 --url myproject.firebaseio.com --key AIza... "
  echo "  $0 --url https://myproject.firebaseio.com --project-id myproject --namespaces firebase,default"
  echo "  $0 --remote-config-url 'https://firebaseremoteconfig.googleapis.com/v1/projects/508767403424/namespaces/firebase:fetch?key=...' "
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) FIREBASE_URL="$(normalize_url "$2")"; shift 2 ;;
    --key) API_KEY="$2"; shift 2 ;;
    --output) OUTPUT_DIR="$2"; shift 2 ;;
    --remote-config-url) REMOTE_CONFIG_URL="$2"; shift 2 ;;
    --project-id) PROJECT_ID="$2"; shift 2 ;;
    --namespaces) NAMESPACES="$2"; shift 2 ;;
    --help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

if [ -z "${FIREBASE_URL:-}" ] && [ -z "${REMOTE_CONFIG_URL:-}" ] && [ -z "${PROJECT_ID:-}" ]; then
  usage
fi

mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/pentest.log"

log INFO "Initialized. Output dir: $OUTPUT_DIR"
log INFO "Firebase URL: ${FIREBASE_URL:-(none)}"
log INFO "Namespaces to test: ${NAMESPACES}"
if [ -n "${API_KEY:-}" ]; then
  log INFO "API Key: ${API_KEY:0:10}..."
else
  log WARNING "No API key provided; skipping some Google API tests."
fi

# Run tests
if [ -n "${FIREBASE_URL:-}" ]; then
  run_firebase_tests "$FIREBASE_URL"
  run_storage_tests "$FIREBASE_URL"
fi

if [ -n "${API_KEY:-}" ]; then
  run_maps_tests "$API_KEY"
  check_google_api_key "$API_KEY"
fi

# Run Remote Config tests (custom URL preferred, else try project/project-id)
run_remote_config_tests "$REMOTE_CONFIG_URL" "$PROJECT_ID"

# summary
log INFO "Generating summary..."
{
  echo "MOBILE PENTEST SUMMARY ($(date))"
  echo "Target: ${FIREBASE_URL:-(none)}"
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
