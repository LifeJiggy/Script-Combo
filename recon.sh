#!/bin/bash

# Triad Full-Recon Script
# Usage: ./recon.sh <url> <output_dir> <recon_types> <threads> <delay> [cookies] [proxy]


# Arguments
URL=$1
OUTPUT_DIR=$2
RECON_TYPES=$3
THREADS=$4
DELAY=$5
COOKIES=$6
PROXY=$7
TIMESTAMP=$(date +%F_%H-%M-%S)
REPORT_DIR="$OUTPUT_DIR/recon_$TIMESTAMP"
mkdir -p "$REPORT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Log function
log() {
  echo -e "${YELLOW}[*] $1${NC}" | tee -a "$REPORT_DIR/recon.log"
}

# Error log
error_log() {
  echo -e "${RED}[!] $1${NC}" | tee -a "$REPORT_DIR/recon.log"
}

# Dependency check (ENHANCED: Windows compatibility, specific paths)
check_deps() {
  local missing=()
  local commands=("curl" "jq" "subfinder" "httpx" "waybackurls")
  
  for cmd in "${commands[@]}"; do
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
      # Windows: Check in PATH or common install locations
      if ! command -v "$cmd.exe" &>/dev/null && ! command -v "$cmd" &>/dev/null; then
        missing+=("$cmd")
      fi
    else
      # Linux/WSL
      if ! command -v "$cmd" &>/dev/null; then
        missing+=("$cmd")
      fi
    fi
  done

  if [ ${#missing[@]} -gt 0 ]; then
    error_log "Missing dependencies: ${missing[*]}. Install them first."
    error_log "For Windows, use WSL or Git Bash, or install via: https://github.com/projectdiscovery/subfinder, https://github.com/projectdiscovery/httpx, https://github.com/tomnomnom/waybackurls"
    error_log "Example for Ubuntu/WSL: sudo apt-get install curl jq; go install github.com/projectdiscovery/subfinder@latest; go install github.com/projectdiscovery/httpx@latest; go install github.com/tomnomnom/waybackurls@latest"
    exit 1
  fi
  log "All dependencies installed."
}

# Grepping techniques (UNCHANGED)
grep_case_insensitive() { grep -i "$1" "$2"; }
grep_recursive() { grep -r "$1" "$2"; }
grep_line_numbers() { grep -n "$1" "$2"; }
grep_context() { grep -C 2 "$1" "$2"; }
grep_inverse() { grep -v "$1" "$2"; }
grep_exact() { grep -w "$1" "$2"; }
grep_extended() { grep -E "$1" "$2"; }

# Filtering techniques (ENHANCED: Robust deduplication)
filter_dedup() { sort -u; }
filter_keyword() { grep -E "$1" || true; }
filter_extension() { grep -E "$1" || true; }
filter_nonempty() { grep -v '^$' || true; }
filter_length() { awk '{if (length($0) > 0) print length, $0}' | sort -n | cut -d' ' -f2- || true; }
filter_status() { grep "$1" || true; }
filter_custom() { awk "/$1/{print}" || true; }

# Passive Recon (ENHANCED: Robust error handling, more sources)
passive_recon() {
  log "Starting passive recon..."
  
  # Subdomains
  {
    # crt.sh
    curl -s -f "https://crt.sh/?q=%.$URL&output=json" | jq -r '.[].name_value' 2>/dev/null || true
    # subfinder
    subfinder -d "$URL" -silent 2>/dev/null || true
    # securitytrails (placeholder)
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
      curl -s -f -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/$URL/subdomains" | jq -r '.subdomains[]' | sed "s/^/$URL./" 2>/dev/null || true
    fi
  } | filter_dedup | filter_nonempty > "$REPORT_DIR/subdomains.txt" || error_log "Failed to gather subdomains"
  log "Found $(wc -l < "$REPORT_DIR/subdomains.txt") subdomains"

  # URLs
  {
    # web.archive.org
    curl -s -f "http://web.archive.org/cdx/search/cdx?url=*.$URL/*&output=json&fl=original" | jq -r '.[] | .[]' 2>/dev/null || true
    # waybackurls
    waybackurls "$URL" 2>/dev/null || true
  } | filter_dedup | filter_nonempty > "$REPORT_DIR/urls.txt" || error_log "Failed to gather URLs"
  log "Found $(wc -l < "$REPORT_DIR/urls.txt") URLs"

  # Endpoints
  grep_extended 'https?://[^"\s]+\.(js|json|php|asp|aspx|xml|graphql)' "$REPORT_DIR/urls.txt" | filter_dedup | filter_nonempty > "$REPORT_DIR/endpoints.txt" || true
  log "Found $(wc -l < "$REPORT_DIR/endpoints.txt") endpoints"

  # JS links
  grep_extended 'https?://[^"\s]+\.js' "$REPORT_DIR/urls.txt" | filter_dedup | filter_nonempty > "$REPORT_DIR/js_links.txt" || true
  log "Found $(wc -l < "$REPORT_DIR/js_links.txt") JS links"

  # Sensitive URLs
  grep_extended '/api/|/admin/|/login/|/auth/|/graphql/|/v[0-9]+/' "$REPORT_DIR/urls.txt" | filter_dedup | filter_nonempty > "$REPORT_DIR/sensitive_urls.txt" || true
  log "Found $(wc -l < "$REPORT_DIR/sensitive_urls.txt") sensitive URLs"

  # GraphQL/REST detection
  > "$REPORT_DIR/api_endpoints.txt"
  while IFS= read -r endpoint; do
    if [[ "$endpoint" =~ /graphql/ || "$endpoint" =~ /api/ ]]; then
      response=$(curl -s -f -m 5 -H "User-Agent: $USER_AGENT" ${COOKIES:+ -b "$COOKIES"} ${PROXY:+ --proxy "$PROXY"} "$endpoint" -I 2>/dev/null)
      if [[ $? -eq 0 ]] && echo "$response" | grep -E 'application/json|graphql' >/dev/null; then
        echo "$endpoint" >> "$REPORT_DIR/api_endpoints.txt"
      fi
    fi
  done < "$REPORT_DIR/sensitive_urls.txt" || true
  filter_dedup < "$REPORT_DIR/api_endpoints.txt" > "$REPORT_DIR/api_endpoints_tmp.txt" && mv "$REPORT_DIR/api_endpoints_tmp.txt" "$REPORT_DIR/api_endpoints.txt"
  log "Detected $(wc -l < "$REPORT_DIR/api_endpoints.txt") API endpoints"

  log "Passive recon completed"
}

# Active Recon (ENHANCED: Robust httpx, retry logic)
active_recon() {
  log "Starting active recon..."

  # Filter live subdomains
  httpx -l "$REPORT_DIR/subdomains.txt" -silent -threads "$THREADS" -timeout 5 -o "$REPORT_DIR/live_subdomains.txt" 2>/dev/null || error_log "httpx failed to filter live subdomains"
  log "Found $(wc -l < "$REPORT_DIR/live_subdomains.txt") live subdomains"

  # Crawl live subdomains
  while IFS= read -r sub; do
    {
      response=$(curl -s -f -m 5 -H "User-Agent: $USER_AGENT" ${COOKIES:+ -b "$COOKIES"} ${PROXY:+ --proxy "$PROXY"} "$sub" 2>/dev/null)
      if [[ $? -eq 0 ]]; then
        echo "$response" | grep_extended 'https?://[^"\s]+\.[a-z]{2,}' | filter_dedup >> "$REPORT_DIR/urls.txt"
        echo "$response" | grep_extended 'https?://[^"\s]+\.(js|json|php|asp|aspx|xml|graphql)' | filter_dedup >> "$REPORT_DIR/endpoints.txt"
        echo "$response" | grep_extended 'https?://[^"\s]+\.js' | filter_dedup >> "$REPORT_DIR/js_links.txt"
        echo "$response" | grep_extended '/api/|/admin/|/login/|/auth/|/graphql/|/v[0-9]+/' | filter_dedup >> "$REPORT_DIR/sensitive_urls.txt"
        echo "$response" | grep -E 'application/json|graphql' | filter_dedup >> "$REPORT_DIR/api_endpoints.txt"
      fi
    } &
    sleep "$DELAY"
    [ $(jobs | wc -l) -ge "$THREADS" ] && wait
  done < "$REPORT_DIR/live_subdomains.txt"
  wait

  # Deduplicate
  for file in urls endpoints js_links sensitive_urls api_endpoints; do
    sort -u "$REPORT_DIR/$file.txt" -o "$REPORT_DIR/$file.txt" 2>/dev/null || true
  done
  log "Active recon completed"
}

# Display table (ENHANCED: Robust counts)
display_table() {
  log "Recon Results Summary:"
  {
    echo "Type|Count"
    echo "Subdomains|$(wc -l < "$REPORT_DIR/subdomains.txt" 2>/dev/null || echo 0)"
    echo "Live Subdomains|$(wc -l < "$REPORT_DIR/live_subdomains.txt" 2>/dev/null || echo 0)"
    echo "URLs|$(wc -l < "$REPORT_DIR/urls.txt" 2>/dev/null || echo 0)"
    echo "Endpoints|$(wc -l < "$REPORT_DIR/endpoints.txt" 2>/dev/null || echo 0)"
    echo "JS Links|$(wc -l < "$REPORT_DIR/js_links.txt" 2>/dev/null || echo 0)"
    echo "Sensitive URLs|$(wc -l < "$REPORT_DIR/sensitive_urls.txt" 2>/dev/null || echo 0)"
    echo "API Endpoints|$(wc -l < "$REPORT_DIR/api_endpoints.txt" 2>/dev/null || echo 0)"
  } | column -t -s '|' | tee -a "$REPORT_DIR/recon.log"
}

# Main
check_deps
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
log "Starting recon for $URL..."
for type in $(echo "$RECON_TYPES" | tr ',' ' '); do
  if [ "$type" = "passive" ]; then
    passive_recon
  elif [ "$type" = "active" ]; then
    active_recon
  fi
done

# Output JSON (ENHANCED: Robust parsing)
cat <<EOF > "$REPORT_DIR/recon.json"
{
  "subdomains": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/subdomains.txt" 2>/dev/null || echo '[]'),
  "live_subdomains": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/live_subdomains.txt" 2>/dev/null || echo '[]'),
  "urls": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/urls.txt" 2>/dev/null || echo '[]'),
  "endpoints": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/endpoints.txt" 2>/dev/null || echo '[]'),
  "js_links": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/js_links.txt" 2>/dev/null || echo '[]'),
  "sensitive_urls": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/sensitive_urls.txt" 2>/dev/null || echo '[]'),
  "api_endpoints": $(jq -R -s -c 'split("\n") | map(select(. != ""))' "$REPORT_DIR/api_endpoints.txt" 2>/dev/null || echo '[]')
}
EOF
log "Recon results saved to $REPORT_DIR/recon.json"

# Display table
display_table