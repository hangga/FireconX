#!/bin/bash

# =============================================
# MOBILE PENTEST SUPER SCRIPT - ALL IN ONE
# Firebase + API Key Comprehensive Security Test
# Complete version with improved vuln detection logic
# =============================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
FIREBASE_URL=""
API_KEY=""
OUTPUT_DIR=""
LOG_FILE=""
USER_AGENT="Mozilla/5.0 (Linux; Android 10; Mobile Pentest) AppleWebKit/537.36"

# Banner
show_banner() {
    echo -e "${CYAN}"
    echo "=================================================="
    echo "    MOBILE PENTEST SUPER SCRIPT - ALL IN ONE"
    echo "    Firebase + API Key Comprehensive Security Test"
    echo "=================================================="
    echo -e "${NC}"
}

# Usage information
show_usage() {
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 <firebase_url> <api_key>"
    echo "  $0 --url <firebase_url> --key <api_key> [options]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --url     Firebase database URL"
    echo "  --key     Google API key"
    echo "  --output  Output directory (default: auto-generated)"
    echo "  --fast    Fast mode (skip some tests)"
    echo "  --quiet   Quiet mode (minimal output)"
    echo "  --help    Show this help"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 https://myapp.firebaseio.com AIzaSyABC123def456"
    echo "  $0 --url https://myapp.firebaseio.com --key AIzaSyABC123def456 --fast"
    echo "  $0 --url https://myapp.firebaseio.com --key AIzaSyABC123def456 --output my_pentest"
}

# Initialize setup
initialize() {
    # Create output directory
    if [ -z "$OUTPUT_DIR" ]; then
        OUTPUT_DIR="firereconx_log_$(date +%Y%m%d_%H%M%S)"
    fi
    mkdir -p "$OUTPUT_DIR"
    
    LOG_FILE="$OUTPUT_DIR/pentest.log"
    
    echo "[+] Initializing Mobile Pentest..." | tee -a "$LOG_FILE"
    echo "Start Time: $(date)" | tee -a "$LOG_FILE"
    echo "Firebase URL: $FIREBASE_URL" | tee -a "$LOG_FILE"
    if [ -n "$API_KEY" ]; then
        echo "API Key: ${API_KEY:0:10}..." | tee -a "$LOG_FILE"
    fi
    echo "Output Directory: $OUTPUT_DIR" | tee -a "$LOG_FILE"
}

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    local color="$NC"
    case $level in
        "INFO") color=$BLUE ;;
        "SUCCESS") color=$GREEN ;;
        "WARNING") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "VULN") color=$RED ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}" | tee -a "$LOG_FILE"
}

# Test URL function (improved decision logic, no eval)
test_endpoint() {
    local url="$1"
    local method="$2"
    local data="$3"
    local description="$4"
    local headers_str="$5"

    log "INFO" "Testing: $description"
    log "INFO" "URL: $url"
    log "INFO" "Method: $method"

    # Build curl command as array to avoid word-splitting and quoting issues
    local -a curl_cmd=(curl -s -w "HTTP_STATUS:%{http_code}" -H "User-Agent: $USER_AGENT")

    # Add custom headers (headers_str should be a string with header flags, e.g. -H 'Authorization: key=...')
    if [ -n "$headers_str" ]; then
        read -r -a hdrs <<< "$headers_str"
        for h in "${hdrs[@]}"; do
            curl_cmd+=("$h")
        done
    fi

    local response
    if [[ "$method" == "GET" ]]; then
        response=$("${curl_cmd[@]}" "$url" 2>/dev/null)
    else
        # For write methods, ensure Content-Type header and method
        curl_cmd+=( -H "Content-Type: application/json" )
        curl_cmd+=( -X "$method" )
        if [ -n "$data" ]; then
            curl_cmd+=( -d "$data" )
        fi
        response=$("${curl_cmd[@]}" "$url" 2>/dev/null)
    fi

    # Extract HTTP status and body reliably
    local http_status
    http_status=$(echo "$response" | tr -d '\r' | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\)$/\1/p')
    local body
    body=$(echo "$response" | sed -e 's/HTTP_STATUS:[0-9]\{3\}$//')

    if [ -z "$http_status" ]; then
        log "WARNING" "No HTTP status returned from $url"
        return 4
    fi

    log "INFO" "HTTP Status: $http_status"

    # --- Improved vulnerability decision logic ---
    # Any 2xx is considered a successful response. Distinguish GET (read) vs write methods.
    if [[ "$http_status" =~ ^2 ]]; then
        # normalize body (trim whitespace and newlines)
        local body_trimmed
        body_trimmed=$(echo "$body" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

        # If body looks like an error message (common in some APIs), don't mark as vuln
        if echo "$body_trimmed" | grep -qiE '"error"|"errorMessage"|"error_description"|"message"|"status"'; then
            log "INFO" "Received 2xx but body indicates an error-like payload -> not flagged as vulnerable"
            return 1
        fi

        if [ "$method" = "GET" ]; then
            # GET: vulnerable only if body contains meaningful content (not null/{} or [])
            if [ -n "$body_trimmed" ] && ! echo "$body_trimmed" | grep -qE '^null$|^\{\s*\}$|^\[\s*\]$'; then
                log "VULN" "VULNERABLE: $description - Publicly readable (HTTP $http_status)"
                echo "Data: $(echo "$body" | head -c 500)" | tee -a "$LOG_FILE"
                return 0
            else
                log "INFO" "HTTP $http_status but response body empty/null -> likely not exposed"
                return 2
            fi
        else
            # For write methods (PUT/POST/PATCH/DELETE) any 2xx typically means write succeeded -> vuln
            log "VULN" "VULNERABLE: $description - Write allowed (HTTP $http_status)"
            if [ -n "$body_trimmed" ] && ! echo "$body_trimmed" | grep -qE '^null$|^\{\s*\}$|^\[\s*\]$'; then
                echo "Response: $(echo "$body" | head -c 500)" | tee -a "$LOG_FILE"
            fi
            return 0
        fi
    fi

    # Handle common non-2xx statuses
    if [ "$http_status" = "401" ] || [ "$http_status" = "403" ]; then
        log "SUCCESS" "SECURE: $description - Access denied (HTTP $http_status)"
        return 1
    elif [ "$http_status" = "404" ]; then
        log "INFO" "NOT FOUND: $description"
        return 2
    elif [ "$http_status" = "429" ]; then
        log "WARNING" "RATE LIMITED: $description"
        return 3
    else
        log "WARNING" "UNKNOWN: $description - Status $http_status"
        return 4
    fi
}

# =============================================
# FIREBASE DATABASE SECURITY TEST
# =============================================

test_firebase_security() {
    log "INFO" "Starting Firebase Database Security Tests"

    local firebase_tests=(
        # method::url::data::description (data empty if not applicable)
        "GET::${FIREBASE_URL}/.json::::Root database access"
        "GET::${FIREBASE_URL}/users.json::::Users collection access"
        "GET::${FIREBASE_URL}/user.json::::User data access"
        "GET::${FIREBASE_URL}/profiles.json::::Profiles data access"
        
        # Mobile app specific collections
        "GET::${FIREBASE_URL}/tokens.json::::FCM Tokens"
        "GET::${FIREBASE_URL}/devices.json::::Device information"
        "GET::${FIREBASE_URL}/sessions.json::::User sessions"
        "GET::${FIREBASE_URL}/app.json::::App configuration"
        "GET::${FIREBASE_URL}/config.json::::General configuration"
        "GET::${FIREBASE_URL}/settings.json::::App settings"
        
        # Common mobile app data structures
        "GET::${FIREBASE_URL}/posts.json::::Posts/Content data"
        "GET::${FIREBASE_URL}/messages.json::::Chat messages"
        "GET::${FIREBASE_URL}/conversations.json::::Conversations"
        "GET::${FIREBASE_URL}/notifications.json::::Notifications"
        "GET::${FIREBASE_URL}/orders.json::::E-commerce orders"
        "GET::${FIREBASE_URL}/products.json::::Products data"
        "GET::${FIREBASE_URL}/payments.json::::Payment information"
        "GET::${FIREBASE_URL}/transactions.json::::Transactions"
        
        # Write operations (provide JSON payloads)
        "PUT::${FIREBASE_URL}/pentest_$(date +%s).json::{\"test\":\"unauthorized_write\",\"timestamp\":\"$(date)\",\"source\":\"mobile_pentest\"}::Write permission test"
        "POST::${FIREBASE_URL}/test_collection.json::{\"pentest\":true,\"mobile_app\":\"security_test\",\"timestamp\":\"$(date)\"}::POST data creation"
    )

    for t in "${firebase_tests[@]}"; do
        IFS='::' read -r method url data description <<< "$t"
        test_endpoint "$url" "$method" "$data" "$description"
        sleep 0.5
    done
}

# =============================================
# GOOGLE MAPS APIS TEST
# =============================================

test_google_maps_apis() {
    log "INFO" "Starting Google Maps APIs Tests"
    
    local maps_tests=(
        "https://maps.googleapis.com/maps/api/geocode/json?address=Jakarta&key=$API_KEY::Geocoding API"
        "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-6.2,106.8&radius=1000&key=$API_KEY::Places Nearby Search"
        "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurant&key=$API_KEY::Places Text Search"
        "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=pizza&key=$API_KEY::Places Autocomplete"
        "https://maps.googleapis.com/maps/api/directions/json?origin=Jakarta&destination=Bandung&key=$API_KEY::Directions API"
        "https://maps.googleapis.com/maps/api/geolocation/v1/geolocate?key=$API_KEY::Geolocation API"
    )

    for test in "${maps_tests[@]}"; do
        IFS='::' read -r url description <<< "$test"
        test_endpoint "$url" "GET" "" "$description"
        sleep 0.3
    done
}

# =============================================
# FIREBASE SERVICES TEST
# =============================================

test_firebase_services() {
    log "INFO" "Starting Firebase Services Tests"
    
    local firebase_api_tests=(
        "https://firestore.googleapis.com/v1/projects/test/databases/(default)/documents::Firestore API"
        "https://fcm.googleapis.com/fcm/send::FCM Send Endpoint"
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY::Firebase Auth"
        "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY::Firebase Auth SignUp"
    )

    for test in "${firebase_api_tests[@]}"; do
        IFS='::' read -r url description <<< "$test"
        test_endpoint "$url" "GET" "" "$description"
    done
    
    # FCM Test with POST (will attempt to send to /topics/all)
    local fcm_data='{
      "to": "/topics/all",
      "notification": {
        "title": "Pentest Notification",
        "body": "Security test message",
        "click_action": "OPEN_APP"
      }
    }'
    test_endpoint "https://fcm.googleapis.com/fcm/send" "POST" "$fcm_data" "FCM Push Notification" "-H Authorization:key=$API_KEY"
}

# =============================================
# GOOGLE ML APIS TEST
# =============================================

test_google_ml_apis() {
    log "INFO" "Starting Google Machine Learning APIs Tests"
    
    local ml_tests=(
        "https://vision.googleapis.com/v1/images:annotate?key=$API_KEY::Vision API"
        "https://language.googleapis.com/v1/documents/analyzeEntities?key=$API_KEY::Natural Language Entities"
        "https://translation.googleapis.com/language/translate/v2?q=hello&target=id&key=$API_KEY::Translate API"
        "https://speech.googleapis.com/v1/speech:recognize?key=$API_KEY::Speech-to-Text::Speech-to-Text"
    )

    for test in "${ml_tests[@]}"; do
        IFS='::' read -r url description <<< "$test"
        test_endpoint "$url" "GET" "" "$description"
    done
}

# =============================================
# FIREBASE STORAGE TEST
# =============================================

test_firebase_storage() {
    log "INFO" "Starting Firebase Storage Tests"
    
    # Extract project ID from Firebase URL
    local project_id
    project_id=$(echo "$FIREBASE_URL" | sed -E 's|https?://([^/]+).*|\1|' | sed 's|.firebaseio.com||')
    
    if [ -n "$project_id" ]; then
        local storage_tests=(
            "GET::https://firebasestorage.googleapis.com/v0/b/${project_id}.appspot.com/o::Storage bucket list"
            "GET::https://firebasestorage.googleapis.com/v0/b/${project_id}.appspot.com/o/users%2Ftest.jpg::User file access"
            "GET::https://firebasestorage.googleapis.com/v0/b/${project_id}.appspot.com/o/images%2Fprofile.jpg::Profile images access"
        )

        for test in "${storage_tests[@]}"; do
            IFS='::' read -r method url description <<< "$test"
            test_endpoint "$url" "$method" "" "$description"
        done
    else
        log "WARNING" "Could not extract project ID from FIREBASE_URL"
    fi
}

# =============================================
# API KEY RESTRICTIONS CHECK
# =============================================

check_api_restrictions() {
    log "INFO" "Checking API Key Restrictions"
    
    local services=(
        "maps.googleapis.com"
        "places.googleapis.com"
        "geolocation.googleapis.com"
        "vision.googleapis.com"
        "language.googleapis.com"
        "translation.googleapis.com"
        "identitytoolkit.googleapis.com"
    )

    for service in "${services[@]}"; do
        local test_url="https://${service}/test?key=${API_KEY}"
        # Use curl to only fetch status code
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "$test_url")
        if [ "$http_code" != "403" ] && [ "$http_code" != "401" ]; then
            log "VULN" "API Key might be usable with: $service (HTTP $http_code)"
        else
            log "SUCCESS" "API Key restricted for: $service"
        fi
    done
}

# =============================================
# MOBILE FIREBASE PATHS CHECK
# =============================================

check_mobile_firebase_paths() {
    log "INFO" "Checking Mobile-Specific Firebase Paths"
    
    local mobile_paths=(
        "/users"
        "/tokens"
        "/devices"
        "/sessions"
        "/profiles"
        "/settings"
        "/config"
        "/notifications"
        "/messages"
        "/posts"
        "/orders"
        "/payments"
        "/products"
    )

    for path in "${mobile_paths[@]}"; do
        local url="${FIREBASE_URL}${path}.json"
        local resp
        resp=$(curl -s -w "HTTP_STATUS:%{http_code}" "$url")
        local http_code
        http_code=$(echo "$resp" | tr -d '\r' | sed -n 's/.*HTTP_STATUS:\([0-9]\{3\}\)$/\1/p')
        local body
        body=$(echo "$resp" | sed -e 's/HTTP_STATUS:[0-9]\{3\}$//')
        
        if [ "$http_code" = "200" ] && [ -n "$body" ] && [ "$body" != "null" ]; then
            log "VULN" "DATA EXPOSURE: $path is publicly readable"
            echo "Sample: $(echo "$body" | head -c 200)" | tee -a "$LOG_FILE"
        fi
    done
}

# =============================================
# MAIN EXECUTION FUNCTION
# =============================================

run_comprehensive_pentest() {
    log "INFO" "Starting Comprehensive Mobile App Pentest"
    
    test_firebase_security
    test_google_maps_apis
    test_firebase_services
    test_google_ml_apis
    test_firebase_storage
    check_api_restrictions
    check_mobile_firebase_paths
    
    log "INFO" "Comprehensive pentest completed"
}

# =============================================
# RESULTS SUMMARY
# =============================================

generate_summary() {
    log "INFO" "Generating Pentest Summary"
    
    local summary_file="$OUTPUT_DIR/summary.txt"
    
    echo "MOBILE PENTEST SUMMARY" > "$summary_file"
    echo "======================" >> "$summary_file"
    echo "Date: $(date)" >> "$summary_file"
    echo "Target: $FIREBASE_URL" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count vulnerabilities (best-effort)
    local firebase_vulns
    firebase_vulns=$(grep -c "VULNERABLE\|DATA EXPOSURE" "$LOG_FILE" || true)
    local api_vulns
    api_vulns=$(grep -c "API Key might be usable\|API Key.*VULNERABLE" "$LOG_FILE" || true)
    local total_vulns=$((firebase_vulns + api_vulns))
    
    echo "VULNERABILITY SUMMARY" >> "$summary_file"
    echo "====================" >> "$summary_file"
    echo "Total Vulnerabilities: $total_vulns" >> "$summary_file"
    echo "Firebase Issues: $firebase_vulns" >> "$summary_file"
    echo "API Key Issues: $api_vulns" >> "$summary_file"
    echo "" >> "$summary_file"
    
    echo "DETAILED FINDINGS" >> "$summary_file"
    echo "=================" >> "$summary_file"
    grep -n "VULNERABLE\|DATA EXPOSURE\|might be usable" "$LOG_FILE" >> "$summary_file" || true
    
    echo "" >> "$summary_file"
    echo "SECURITY RECOMMENDATIONS" >> "$summary_file"
    echo "========================" >> "$summary_file"
    echo "1. Implement Firebase Security Rules" >> "$summary_file"
    echo "2. Restrict API Keys to specific services & domains" >> "$summary_file"
    echo "3. Use App Check for additional protection" >> "$summary_file"
    echo "4. Implement proper authentication" >> "$summary_file"
    echo "5. Regular security audits" >> "$summary_file"
    
    log "SUCCESS" "Summary generated: $summary_file"
    
    echo -e "\n${GREEN}=== PENTEST COMPLETED ===${NC}"
    echo -e "Total vulnerabilities found: ${RED}$total_vulns${NC}"
    echo -e "Firebase issues: ${YELLOW}$firebase_vulns${NC}"
    echo -e "API key issues: ${YELLOW}$api_vulns${NC}"
    echo -e "Full results: ${CYAN}$OUTPUT_DIR/${NC}"
    echo -e "Summary: ${CYAN}$summary_file${NC}"
}

# =============================================
# ARGUMENT PARSING
# =============================================

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --url)
                FIREBASE_URL="$2"
                shift 2
                ;;
            --key)
                API_KEY="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --fast)
                FAST_MODE=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                # Positional arguments
                if [ -z "$FIREBASE_URL" ]; then
                    FIREBASE_URL="$1"
                elif [ -z "$API_KEY" ]; then
                    API_KEY="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [ -z "$FIREBASE_URL" ] || [ -z "$API_KEY" ]; then
        echo -e "${RED}Error: Firebase URL and API Key are required${NC}"
        show_usage
        exit 1
    fi
}

# =============================================
# MAIN EXECUTION
# =============================================

main() {
    show_banner
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Initialize setup
    initialize
    
    # Run comprehensive pentest
    run_comprehensive_pentest
    
    # Generate summary
    generate_summary
    
    log "SUCCESS" "Mobile pentest completed successfully!"
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
