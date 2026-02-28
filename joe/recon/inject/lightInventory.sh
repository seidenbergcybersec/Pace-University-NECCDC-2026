#!/bin/bash

# --- BASH SETTINGS ---
set -u
shopt -s extglob

# --- COLORS ---
RED='\033[1;31m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- 0. ENSURE ROOT PRIVILEGES ---
if [[ $EUID -ne 0 ]]; then
    printf "${RED}Must be run as root, exiting!${NC}\n"
    exit 1
fi

# --- CONFIGURATION ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_FILE="/system_inventory_${HOSTNAME}_${TIMESTAMP}.txt"

header() {
    printf "\n${BLUE}[#] %s${NC}\n" "$1"
    printf '==================================================\n'
}

# Helper to check version of a command
get_version() {
    local cmd=$1
    local version_args=${2:-"--version"}
    if command -v "$cmd" &>/dev/null; then
        "$cmd" $version_args 2>&1 | head -n 1 | sed 's/^[[:space:]]*//'
    else
        echo "Not Installed"
    fi
}

# --- 1. NETWORK INTERFACES (IPv4, IPv6, MAC) ---
header "NETWORK INTERFACE INFO"
{
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")

    for iface in $INTERFACES; do
        echo "Interface: $iface"
        MAC=$(ip link show "$iface" | awk '/ether/ {print $2}')
        IPV4=$(ip -4 addr show "$iface" | awk '/inet / {print $2}')
        IPV6=$(ip -6 addr show "$iface" | awk '/inet6 / {print $2}')

        echo "  MAC:  ${MAC:-N/A}"
        echo "  IPv4: ${IPV4:-N/A}"
        echo "  IPv6: ${IPV6:-N/A}"
        echo "-----------------------"
    done
} | tee -a "$OUT_FILE"

# --- 2. OS NAME & VERSION ---
header "OPERATING SYSTEM"
{
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "OS Name:    $NAME"
        echo "Version:    $VERSION"
        echo "Kernel:     $(uname -r)"
    else
        echo "OS Info:    Unknown (no /etc/os-release)"
    fi
} | tee -a "$OUT_FILE"

# --- 3. ESSENTIAL SERVICES VERSIONS ---
header "ESSENTIAL SERVICES INVENTORY"
{
    printf "%-25s | %s\n" "SERVICE" "VERSION / STATUS"
    printf "%-25s | %s\n" "-------" "----------------"

    printf "%-25s | %s\n" "vsftpd" "$(get_version vsftpd "-v")"
    printf "%-25s | %s\n" "Teleport" "$(get_version teleport "version")"
    printf "%-25s | %s\n" "Semaphore" "$(get_version semaphore "version")"
    printf "%-25s | %s\n" "Grafana Alloy" "$(get_version alloy "--version")"
    printf "%-25s | %s\n" "MariaDB" "$(get_version mariadb "--version")"
    printf "%-25s | %s\n" "Nginx" "$(get_version nginx "-v")"

    if command -v wp &>/dev/null; then
        WP_VER=$(wp core version --allow-root 2>/dev/null || echo "Found, but wp-cli failed")
    elif [[ -f /var/www/html/wp-includes/version.php ]]; then
        WP_VER=$(grep "wp_version =" /var/www/html/wp-includes/version.php | cut -d"'" -f2)
    else
        WP_VER="Not Found in standard paths"
    fi
    printf "%-25s | %s\n" "WordPress" "$WP_VER"

    printf "%-25s | %s\n" "Falco Agent" "$(get_version falco "--version")"
    printf "%-25s | %s\n" "Falco Sidekick" "$(get_version falcosidekick "--version")"
    printf "%-25s | %s\n" "Grafana Server" "$(get_version grafana-server "-v")"
    printf "%-25s | %s\n" "Gitea" "$(get_version gitea "-v")"
    printf "%-25s | %s\n" "Docker" "$(get_version docker "--version")"

} | tee -a "$OUT_FILE"

# --- 4. DOCKER CHECK ---
if command -v docker &>/dev/null; then
    header "DOCKER CONTAINER VERSIONS"
    {
        echo "Checking for essential services running as containers:"
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | grep -Ei "teleport|semaphore|alloy|mariadb|nginx|wordpress|falco|grafana" || echo "No matching containers running."
    } | tee -a "$OUT_FILE"
fi

# --- 5. JSON GENERATION (for servers.json / draw.io netmap) ---
header "GENERATING JSON FOR NETMAP"

# Collect primary IP (prefer IPv4, fall back to non-link-local IPv6) and MAC
JSON_IP="unknown"
JSON_MAC="unknown"
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
    _ip=$(ip -4 addr show "$iface" | awk '/inet / {print $2}' | cut -d'/' -f1 | head -n1)
    _mac=$(ip link show "$iface" | awk '/ether/ {print $2}' | head -n1)
    if [[ -n "$_ip" ]]; then
        JSON_IP="$_ip"
        JSON_MAC="${_mac:-unknown}"
        break
    fi
done

# No IPv4 found — fall back to first non-loopback, non-link-local IPv6 address
if [[ "$JSON_IP" == "unknown" ]]; then
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo"); do
        _ip=$(ip -6 addr show "$iface" | awk '/inet6 / && !/fe80/ {print $2}' | cut -d'/' -f1 | head -n1)
        _mac=$(ip link show "$iface" | awk '/ether/ {print $2}' | head -n1)
        if [[ -n "$_ip" ]]; then
            JSON_IP="$_ip"
            JSON_MAC="${_mac:-unknown}"
            break
        fi
    done
fi

# Detect OS identifier for the Python icon map
JSON_OS="generic"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    ID_LOWER=$(echo "${ID:-generic}" | tr '[:upper:]' '[:lower:]')
    case "$ID_LOWER" in
        ubuntu)  JSON_OS="ubuntu"  ;;
        debian)  JSON_OS="debian"  ;;
        rocky)   JSON_OS="rocky"   ;;
        rhel|centos|almalinux) JSON_OS="rocky" ;;
        *)
            NAME_LOWER=$(echo "${NAME:-}" | tr '[:upper:]' '[:lower:]')
            if [[ "$NAME_LOWER" == *"windows"* ]]; then
                JSON_OS="windows"
            elif [[ "$NAME_LOWER" == *"pfsense"* ]]; then
                JSON_OS="pfsense"
            else
                JSON_OS="linux"
            fi
        ;;
    esac
fi

# Build the services string from what's actually installed
INSTALLED_SERVICES=()
for svc in vsftpd teleport semaphore alloy mariadb nginx falco grafana-server gitea docker; do
    command -v "$svc" &>/dev/null && INSTALLED_SERVICES+=("$svc")
done
if command -v wp &>/dev/null || [[ -f /var/www/html/wp-includes/version.php ]]; then
    INSTALLED_SERVICES+=("wordpress")
fi

SERVICES_STR=$(IFS=", "; echo "${INSTALLED_SERVICES[*]}")
[[ -z "$SERVICES_STR" ]] && SERVICES_STR="Unknown"

# Append JSON block directly to the txt file
{
    printf "\n--- servers.json ENTRY (copy object into your array) ---\n"
    printf '[\n'
    printf '  {\n'
    printf '    "hostname": "%s",\n' "${HOSTNAME}"
    printf '    "ip": "%s",\n'       "${JSON_IP}"
    printf '    "mac": "%s",\n'      "${JSON_MAC}"
    printf '    "os": "%s",\n'       "${JSON_OS}"
    printf '    "services": "%s"\n'  "${SERVICES_STR}"
    printf '  }\n'
    printf ']\n'
} | tee -a "$OUT_FILE"

# --- FINAL SUMMARY ---
printf "\n${GREEN}[!] Inventory collection complete.${NC}\n"
printf "Results saved to: %s\n" "$OUT_FILE"
printf "${YELLOW}[i] To add to servers.json: copy the { } object above and append it to your existing array.${NC}\n"

