#!/bin/bash

# Check if URL argument is provided
if [ -z "$1" ]; then
    echo "Error: Please provide a URL as an argument"
    echo "Usage: $0 <domain or http(s)://domain[/path]>"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
input_url="$1"
domain=$(echo "$input_url" | sed 's/https\?:\/\///' | cut -d'/' -f1)
log_file="$domain/recon/recon.log"
start_time=$(date +%s)
nuclei_templates="/path/to/nuclei-templates" # Customize this path

# Function to log messages with color
log_message() {
    local type="$1"
    local message="$2"
    case "$type" in
        "INFO") echo -e "${GREEN}[+] $(date '+%Y-%m-%d %H:%M:%S') - $message${NC}" | tee -a "$log_file" ;;
        "WARN") echo -e "${YELLOW}[!] $(date '+%Y-%m-%d %H:%M:%S') - $message${NC}" | tee -a "$log_file" ;;
        "ERROR") echo -e "${RED}[-] $(date '+%Y-%m-%d %H:%M:%S') - $message${NC}" | tee -a "$log_file" ;;
    esac
}

# Create directory with error checking
create_dir() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir" || { log_message "ERROR" "Failed to create directory $dir"; exit 1; }
    fi
}

# Create file with error checking
create_file() {
    local file="$1"
    if [ ! -f "$file" ]; then
        touch "$file" || { log_message "ERROR" "Failed to create file $file"; exit 1; }
    fi
}

# Detect package manager
detect_package_manager() {
    if command -v apt &> /dev/null; then
        echo "apt"
    elif command -v yum &> /dev/null; then
        echo "yum"
    else
        echo "none"
    fi
}

# Install Go if missing
install_go() {
    if ! command -v go &> /dev/null; then
        log_message "WARN" "Go not found. Attempting to install..."
        pkg_mgr=$(detect_package_manager)
        case "$pkg_mgr" in
            "apt") sudo apt update && sudo apt install -y golang || { log_message "ERROR" "Failed to install Go. Install manually: https://golang.org/doc/install"; exit 1; } ;;
            "yum") sudo yum install -y golang || { log_message "ERROR" "Failed to install Go. Install manually: https://golang.org/doc/install"; exit 1; } ;;
            *) log_message "ERROR" "No supported package manager found. Install Go manually: https://golang.org/doc/install"; exit 1 ;;
        esac
    fi
}

# Install Go tool
install_go_tool() {
    local tool="$1"
    log_message "INFO" "Installing $tool..."
    case "$tool" in
        "assetfinder") go get -u github.com/tomnomnom/assetfinder ;;
        "subfinder") go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder ;;
        "httprobe") go get -u github.com/tomnomnom/httprobe ;;
        "waybackurls") go get -u github.com/tomnomnom/waybackurls ;;
        "nuclei") go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei && nuclei -update-templates ;;
        "gospider") go get -u github.com/jaeles-project/gospider ;;
        "subjack") go get -u github.com/haccer/subjack ;;
        "amass") go get -u github.com/OWASP/Amass/v3/... ;;
    esac
    [ $? -ne 0 ] && { log_message "ERROR" "Failed to install $tool. Check Go setup."; exit 1; }
}

# Check and install tools
check_and_install_tools() {
    local go_tools=("assetfinder" "subfinder" "httprobe" "waybackurls" "nuclei" "gospider" "subjack" "amass")
    local apt_tools=("nmap" "dnsrecon" "nikto" "sqlmap" "zap")
    local manual_tools=("eyewitness")
    local pkg_mgr=$(detect_package_manager)

    # Install Go
    install_go

    # Install Go tools
    for tool in "${go_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            install_go_tool "$tool"
        fi
    done

    # Install Apt/Yum tools
    for tool in "${apt_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            if sudo -n true 2>/dev/null; then
                log_message "INFO" "Installing $tool with $pkg_mgr..."
                case "$pkg_mgr" in
                    "apt") sudo apt update && sudo apt install -y "$tool" || log_message "WARN" "Failed to install $tool" ;;
                    "yum") sudo yum install -y "$tool" || log_message "WARN" "Failed to install $tool" ;;
                    *) log_message "WARN" "No package manager detected for $tool" ;;
                esac
            else
                log_message "WARN" "$tool not installed. Run 'sudo $pkg_mgr install $tool' or provide sudo access."
            fi
        fi
    done

    # Install manual tools
    for tool in "${manual_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_message "WARN" "$tool not installed. Install manually: git clone https://github.com/FortyNorthSecurity/EyeWitness.git; cd EyeWitness/Python/setup; ./setup.sh"
        fi
    done

    # Install OWASP ZAP CLI
    if ! command -v zap-cli &> /dev/null; then
        log_message "INFO" "Installing OWASP ZAP CLI..."
        pip install --user zapcli || log_message "WARN" "Failed to install zap-cli. Ensure Python and pip are installed."
    fi
}

# Kameeeeeee Hameeeeeeee Haaaaaaaaaa animation
kame_hame_ha_animation() {
    local pid
    {
        echo -ne "${BLUE}Kameeeeeee${NC} "
        sleep 0.6
        echo -ne "${BLUE}Hameeeeeeee${NC} "
        sleep 0.6
        echo -ne "${BLUE}Haaaaaaaaaa${NC} "
        sleep 0.6
        echo -ne "${YELLOW}HAAAAAAAAAA!${NC} "
        sleep 0.3
        echo -e "${YELLOW}*ENERGY BLAST*${NC}"
        sleep 0.3
    } &
    pid=$!
    sleep 2.4 # Total duration of animation
    kill $pid 2>/dev/null
    wait $pid 2>/dev/null
    echo -e "\033[1A\033[K" # Clear the line
}

# Find subdomains
find_subdomains() {
    log_message "INFO" "Finding subdomains with assetfinder, subfinder, and amass..."
    assetfinder "$domain" | grep "\.$domain\$" > "$domain/recon/assetfinder.txt" 2>/dev/null || log_message "WARN" "assetfinder failed"
    subfinder -d "$domain" > "$domain/recon/subfinder.txt" 2>/dev/null || log_message "WARN" "subfinder failed"
    amass enum -d "$domain" -o "$domain/recon/amass.txt" 2>/dev/null || log_message "WARN" "amass failed"
    cat "$domain/recon/assetfinder.txt" "$domain/recon/subfinder.txt" "$domain/recon/amass.txt" 2>/dev/null | sort -u > "$domain/recon/final.txt"
    rm -f "$domain/recon/assetfinder.txt" "$domain/recon/subfinder.txt" "$domain/recon/amass.txt" || log_message "WARN" "Failed to clean up temp files"
    [ ! -s "$domain/recon/final.txt" ] && { log_message "ERROR" "No subdomains found"; exit 1; }
}

# Check alive domains
check_alive_domains() {
    log_message "INFO" "Searching for alive domains..."
    sort -u "$domain/recon/final.txt" | httprobe -s -p http:80 -p https:443 > "$domain/recon/httprobe/full_alive.txt" 2>/dev/null || {
        log_message "ERROR" "httprobe failed"; exit 1;
    }
    cat "$domain/recon/httprobe/full_alive.txt" | sed 's/https\?:\/\///' | sort -u > "$domain/recon/httprobe/alive.txt"
}

# Check subdomain takeovers
check_takeovers() {
    log_message "INFO" "Checking for subdomain takeovers..."
    subjack -w "$domain/recon/final.txt" -t 100 -timeout 30 -ssl -v 3 -o "$domain/recon/potential_takeovers/potential_takeovers.txt" 2>/dev/null || log_message "WARN" "subjack failed"
}

# DNS enumeration
perform_dns_enumeration() {
    if command -v dnsrecon &> /dev/null; then
        log_message "INFO" "Performing DNS enumeration..."
        dnsrecon -d "$domain" -t std > "$domain/recon/dnsrecon.txt" 2>/dev/null || log_message "WARN" "dnsrecon failed"
    else
        log_message "WARN" "Skipping DNS enumeration: dnsrecon not installed"
    fi
}

# Port scanning
scan_ports() {
    if command -v nmap &> /dev/null; then
        log_message "INFO" "Scanning ports..."
        nmap -iL "$domain/recon/httprobe/alive.txt" -T4 -oA "$domain/recon/scans/scanned.txt" >/dev/null 2>&1 || log_message "WARN" "nmap failed"
    else
        log_message "WARN" "Skipping port scanning: nmap not installed"
    fi
}

# Scrape wayback data
scrape_wayback() {
    log_message "INFO" "Scraping wayback data..."
    waybackurls < "$domain/recon/final.txt" | sort -u > "$domain/recon/wayback/wayback_output.txt" 2>/dev/null || log_message "WARN" "waybackurls failed"
}

# Extract parameters
extract_params() {
    log_message "INFO" "Extracting parameters..."
    grep "?.*=" "$domain/recon/wayback/wayback_output.txt" | cut -d '=' -f 1 | sort -u | while read -r line; do
        echo "$line="
    done > "$domain/recon/wayback/params/wayback_params.txt" 2>/dev/null || log_message "WARN" "Parameter extraction failed"
}

# Extract files by extension
extract_extensions() {
    log_message "INFO" "Extracting files by extension..."
    while read -r line; do
        ext="${line##*.}"
        case "$ext" in
            "js") echo "$line" >> "$domain/recon/wayback/extensions/js1.txt" ;;
            "jsp"|"html") echo "$line" >> "$domain/recon/wayback/extensions/jsp1.txt" ;;
            "json") echo "$line" >> "$domain/recon/wayback/extensions/json1.txt" ;;
            "php") echo "$line" >> "$domain/recon/wayback/extensions/php1.txt" ;;
            "aspx") echo "$line" >> "$domain/recon/wayback/extensions/aspx1.txt" ;;
        esac
    done < "$domain/recon/wayback/wayback_output.txt"
    for ext in js jsp json php aspx; do
        [ -f "$domain/recon/wayback/extensions/${ext}1.txt" ] && sort -u "$domain/recon/wayback/extensions/${ext}1.txt" > "$domain/recon/wayback/extensions/$ext.txt" && rm -f "$domain/recon/wayback/extensions/${ext}1.txt"
    done
}

# Vulnerability scan with Nuclei
run_vulnerability_scan() {
    log_message "INFO" "Running vulnerability scan with Nuclei..."
    nuclei -l "$domain/recon/httprobe/full_alive.txt" -t "$nuclei_templates" -o "$domain/recon/nuclei.txt" 2>/dev/null || log_message "WARN" "nuclei failed"
}

# Web crawling
perform_web_crawling() {
    log_message "INFO" "Crawling with gospider..."
    gospider -S "$domain/recon/httprobe/full_alive.txt" -o "$domain/recon/gospider" 2>/dev/null || log_message "WARN" "gospider failed"
}

# Take screenshots
take_screenshots() {
    if command -v eyewitness &> /dev/null; then
        log_message "INFO" "Taking screenshots..."
        eyewitness --web -f "$domain/recon/httprobe/full_alive.txt" -d "$domain/recon/eyewitness" --no-prompt 2>/dev/null || log_message "WARN" "eyewitness failed"
    else
        log_message "WARN" "Skipping screenshots: eyewitness not installed"
    fi
}

# OWASP ZAP scan
run_zap_scan() {
    if command -v zap-cli &> /dev/null; then
        log_message "INFO" "Running OWASP ZAP scan..."
        zap-cli quick-scan -s "$domain/recon/httprobe/full_alive.txt" -o "$domain/recon/zap_report.html" 2>/dev/null || log_message "WARN" "zap-cli failed"
    else
        log_message "WARN" "Skipping OWASP ZAP scan: zap-cli not installed"
    fi
}

# SQLMap scan
run_sqlmap_scan() {
    if command -v sqlmap &> /dev/null; then
        log_message "INFO" "Running SQLMap on discovered URLs..."
        sqlmap -m "$domain/recon/wayback/wayback_output.txt" --batch --output-dir="$domain/recon/sqlmap" 2>/dev/null || log_message "WARN" "sqlmap failed"
    else
        log_message "WARN" "Skipping SQLMap scan: sqlmap not installed"
    fi
}

# Nikto scan
run_nikto_scan() {
    if command -v nikto &> /dev/null; then
        log_message "INFO" "Running Nikto scan..."
        nikto -h "$domain/recon/httprobe/full_alive.txt" -output "$domain/recon/nikto.txt" 2>/dev/null || log_message "WARN" "nikto failed"
    else
        log_message "WARN" "Skipping Nikto scan: nikto not installed"
    fi
}

# Show stats
show_stats() {
    local end_time=$(date +%s)
    local runtime=$((end_time - start_time))
    log_message "INFO" "Recon completed in $runtime seconds"
    log_message "INFO" "Results in $domain/recon/"
    [ -s "$domain/recon/httprobe/alive.txt" ] && log_message "INFO" "Found $(wc -l < "$domain/recon/httprobe/alive.txt") alive subdomains"
    [ -s "$domain/recon/potential_takeovers/potential_takeovers.txt" ] && log_message "INFO" "Found $(grep -v "Not Vulnerable" "$domain/recon/potential_takeovers/potential_takeovers.txt" | wc -l) potential takeovers"
}

# Cleanup on exit
cleanup() {
    log_message "INFO" "Cleaning up temporary files..."
    rm -f "$domain/recon/assetfinder.txt" "$domain/recon/subfinder.txt" "$domain/recon/amass.txt" "$domain/recon/wayback/extensions/"*1.txt 2>/dev/null
}

# Main execution with ASCII art and loading screen
main() {
    # Display ASCII art
    cat << 'EOF'
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢠⠳⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⢸⢸⢳⡙⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⡏⠀⠀⠀⢸⠀⠐⡜⣆⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢞⠵⢸⠀⠀⢀⡇⣸⠀⡆⠘⣌⢆⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⢞⡵⠁⡆⡇⠀⡠⠋⡼⠀⠀⡇⠀⠘⠈⢧⡏⡄⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⠀⠀⠀⠀⢀⡴⣡⡯⠀⢀⡇⣧⠞⠁⡰⠃⠀⠀⣧⠀⠀⠀⢸⡇⢃⢸⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⡀⠀⠀⢠⢎⡜⡿⠁⠀⢸⣇⡵⠁⠀⠀⠀⠀⠀⣿⠀⠀⠀⠈⠀⢸⣸⠘⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⢣⠀⡴⣡⣿⠁⠃⠀⢀⣾⡿⠁⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠈⡏⠀⢇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⠈⢇⡇⣿⡏⠀⠀⠀⣼⣿⠃⠀⠀⠀⠀⢀⠇⡰⣿⠀⠀⠀⠀⠀⡇⠁⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⠐⠄⠀⠏⡇⠀⠀⣧⣿⡇⡀⡜⢰⠀⠀⡘⡐⠁⠏⡆⠀⠀⡄⢠⡇⡄⠀⠈⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠦⢠⣧⠀⣆⣿⣿⢁⣷⣇⡇⠀⣴⣯⠀⠀⠀⡇⠀⣸⡇⣾⡿⠁⠀⡀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⠀⠀⠀⢀⢀⢠⠀⠸⣿⣆⢹⣿⣿⣾⣿⣿⣠⢾⠛⠁⠀⠀⠀⡇⡠⡟⣿⣿⠃⠀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠘⡶⣄⠀⢸⠸⣼⣧⡀⣿⣿⣾⣿⣿⣿⣿⣿⡇⠘⠀⡀⠀⠀⢠⠟⠀⠃⢹⣥⠃⠀⢠⢏⣜⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠙⡌⠳⢄⣣⠹⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⡇⠀⠀⢀⣄⣴⡢⠀⠀⠀⡿⣯⠀⠐⠁⠘⣻⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠘⢎⢶⣍⣀⠈⢿⣿⣿⣿⣿⣿⣿⣦⠑⣤⡀⠀⣰⠟⡿⠁⠀⠀⠈⠀⠁⠀⠀⡀⡰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠈⢣⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠘⣷⣾⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡵⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠑⣝⠻⠿⣿⣿⣿⣿⣿⣿⣿⣇⠀⣿⣿⣿⣇⣀⣤⠆⠀⠁⠀⠉⠀⠸⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⠉⡇⢸⣿⣿⣿⣿⣿⣿⣿⣼⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠐⢤⡀⠙⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠱⢬⣙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣏⡄⠀⠀⠀⠀⠀⠀⠈⠻⠆⠀⠈⠑⠒⣿⣦⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠑⠲⣼⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⣀⣀⣀⠀⠀⣀⣀⣠⣴⣾⣾⣿⣿⣿⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣘⣿⣷⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⠤⣀⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢘⣿⠟⣡⣶⣶⣤⡄⠙⣿⣿⣿⣿⣿⣿⣟⡛⠿⠿⣿⣿⣿⣿⣿⣿⣿⡿⠿⢿⣿⣿⣿⡿⠟⣩⣿⣿⣿⣿⡀⠀⠀⢏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣶⣿⢋⣼⢿⠿⢛⣿⠷⢶⣶⠂⠿⣿⣿⣿⣿⣿⣷⣶⣤⣀⡀⠉⠉⠀⠀⣀⣀⡀⠀⠀⠀⠠⢾⣿⣿⣿⣿⣿⠇⠀⠀⣘⠢⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣽⠁⠘⠁⠀⠀⠁⠀⠠⠟⠛⣿⣄⡩⢉⣿⣿⣿⣿⣿⡿⠋⠀⡠⣶⣶⣶⡶⣶⣶⣾⠿⠶⠀⠀⠻⣿⣿⣿⣿⠀⠀⠠⣿⣷⡘⢆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡸⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⣿⣿⣤⡈⣿⣿⣿⣿⡟⠁⣠⣾⡇⠀⣿⣿⣆⠀⠀⠀⠀⣀⣠⣆⠀⢹⣿⣿⡿⠀⠀⢠⣿⣿⣿⡘⡆⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⠁⣺⣿⣿⣿⡿⠀⢰⡟⠛⠇⠘⠿⣿⣇⠀⠀⣀⠀⢀⣽⣿⡀⠀⣿⣿⠃⠀⠀⢸⣿⣿⣿⣧⢸⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀⠀⠀⠀⢀⣴⠟⣿⠃⢰⠨⣿⣿⣿⠃⠀⣿⡇⢀⠀⢰⠀⠛⠛⠀⠀⠛⠀⠈⠉⠹⠇⠀⣿⡏⠀⠀⠀⣹⣿⣿⣿⣿⠘⢦⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⡆⠀⠀⠀⠀⣠⡶⠋⠁⡼⠃⠀⣾⠃⣿⣿⣿⠀⠀⡟⢀⡜⠀⢋⣠⣶⠀⠀⠒⠒⠀⠀⣶⡾⠀⢠⠏⠀⠀⣠⣾⣿⣿⣿⣿⢿⠁⠀⣣⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣼⣷⢤⣤⢶⠟⠁⠀⠀⠀⠀⢀⣼⡏⣸⣿⣿⣿⣇⠀⢻⣿⡇⠀⣿⣿⣿⠀⠀⣶⣶⠀⢸⣿⠃⠀⠎⠀⠀⠀⠿⣿⣿⣿⣿⡿⠀⠀⢀⣯⢇⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⠘⠁⠁⠀⠀⢀⣠⣴⣾⣿⠟⣰⣿⣿⣿⣿⣿⡄⠀⠻⠀⣠⣿⣿⣿⠀⠀⠉⠉⠀⠘⠁⢀⠌⠀⠀⠀⢀⠀⠀⠈⠉⠀⠀⠀⢀⣾⣿⡿⠀⠀
⠀⠀⠀⠀⠀⠀⡟⣿⡏⠀⠀⢀⣠⣾⣿⣿⡿⠛⣡⠀⣿⣿⣿⣿⣿⣿⣿⣦⣀⠈⠙⠻⠿⠿⠶⠾⠟⠃⠀⢀⠔⠁⠀⠀⠀⠀⣾⣆⠀⠀⠀⠀⣰⢀⣾⣿⣿⣧⡇⠀
⠀⠀⠀⠀⠀⢸⠁⣿⠃⢀⣴⣿⣿⣿⡟⢻⢁⣾⣿⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣄⣀⡀⠠⠤⠐⠊⠀⠀⠀⠀⠀⢀⡰⣿⣿⡆⠀⠀⣿⣧⣿⣿⣿⣿⣿⡇⠀
⠀⠀⠀⠀⠀⣌⠀⠘⢠⣿⣿⣿⡟⠁⢀⣏⣾⣿⡇⣸⣿⣿⣿⣿⣿⣟⠛⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠋⢱⣿⣿⣧⠀⢠⣿⣿⣿⣿⣿⣿⡏⢱⠀
⠀⠀⠀⠀⠀⠈⠑⠢⢿⣿⣿⡟⠀⢀⣾⣿⣿⡟⢠⣿⣿⣿⣿⡿⠿⢿⣿⣷⣶⣤⣤⣤⣄⣤⣤⣤⠤⠖⠂⠀⠀⣠⠊⠀⠀⠀⢿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⠇⢸⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⠣⢤⣈⣿⣿⠏⣰⣿⣿⣿⣷⣭⣍⣑⠂⠀⠀⠈⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⢀⡼⠁⠀⠀⠀⠀⠈⢿⢿⠀⣼⣿⣿⣿⣿⣿⣧⢴⣾⡄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠑⠚⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠶⠶⠶⠖⠒⠂⠀⠀⠀⠀⢠⠞⠀⠀⠀⠀⠀⠀⠀⠘⡄⠀⣿⣿⣿⣿⣿⣿⣡⣿⣿⡇
EOF

    # Setup directories and files
    create_dir "$domain/recon/scans"
    create_dir "$domain/recon/httprobe"
    create_dir "$domain/recon/potential_takeovers"
    create_dir "$domain/recon/wayback/params"
    create_dir "$domain/recon/wayback/extensions"
    create_dir "$domain/recon/gospider"
    create_dir "$domain/recon/eyewitness"
    create_dir "$domain/recon/sqlmap"  # New directory for SQLMap
    create_file "$log_file"

    # Start the recon process
    log_message "INFO" "Starting recon for $domain"
    echo -e "${GREEN}Charging up...${NC}"
    kame_hame_ha_animation
    log_message "INFO" "Power unleashed! Beginning reconnaissance..."

    # Execute all steps
    check_and_install_tools
    find_subdomains
    check_alive_domains
    check_takeovers
    perform_dns_enumeration
    scan_ports
    scrape_wayback
    extract_params
    extract_extensions
    run_vulnerability_scan
    perform_web_crawling
    take_screenshots
    run_zap_scan
    run_sqlmap_scan
    run_nikto_scan
    show_stats
    cleanup
}

# Trap Ctrl+C and exit
trap 'log_message "WARN" "Interrupted by user"; cleanup; exit 1' INT EXIT

main
