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
OUT_FILE="system_inventory_${HOSTNAME}_${TIMESTAMP}.txt"

header() {
    printf "\n${BLUE}[#] %s${NC}\n" "$1"
    printf '==================================================\n'
}

# Helper to check version of a command
get_version() {
    local cmd=$1
    local version_args=${2:-"--version"}
    if command -v "$cmd" &>/dev/null; then
        # Most tools output version to stdout, some to stderr (like nginx/vsftpd)
        "$cmd" $version_args 2>&1 | head -n 1 | sed 's/^[[:space:]]*//'
    else
        echo "Not Installed"
    fi
}

# --- 1. NETWORK INTERFACES (IPv4, IPv6, MAC) ---
header "NETWORK INTERFACE INFO"
{
    # Get all non-loopback interfaces
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

    # vsftpd
    printf "%-25s | %s\n" "vsftpd" "$(get_version vsftpd "-v")"

    # Teleport (Agent/Admin)
    printf "%-25s | %s\n" "Teleport" "$(get_version teleport "version")"

    # Semaphore
    printf "%-25s | %s\n" "Semaphore" "$(get_version semaphore "version")"

    # Grafana Alloy
    printf "%-25s | %s\n" "Grafana Alloy" "$(get_version alloy "--version")"

    # MariaDB
    printf "%-25s | %s\n" "MariaDB" "$(get_version mariadb "--version")"

    # Nginx
    printf "%-25s | %s\n" "Nginx" "$(get_version nginx "-v")"

    # WordPress (Checked via WP-CLI or common paths)
    if command -v wp &>/dev/null; then
        WP_VER=$(wp core version --allow-root 2>/dev/null || echo "Found, but wp-cli failed")
    elif [[ -f /var/www/html/wp-includes/version.php ]]; then
        WP_VER=$(grep "wp_version =" /var/www/html/wp-includes/version.php | cut -d"'" -f2)
    else
        WP_VER="Not Found in standard paths"
    fi
    printf "%-25s | %s\n" "WordPress" "$WP_VER"

    # Falco Agent
    printf "%-25s | %s\n" "Falco Agent" "$(get_version falco "--version")"

    # Falco Sidekick (Often a container, checking binary if exists)
    printf "%-25s | %s\n" "Falco Sidekick" "$(get_version falcosidekick "--version")"

    # Grafana
    printf "%-25s | %s\n" "Grafana Server" "$(get_version grafana-server "-v")"

    # Docker
    printf "%-25s | %s\n" "Docker" "$(get_version docker "--version")"

} | tee -a "$OUT_FILE"

# --- 4. DOCKER CHECK (Optional, but useful for these services) ---
if command -v docker &>/dev/null; then
    header "DOCKER CONTAINER VERSIONS"
    {
        echo "Checking for essential services running as containers:"
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | grep -Ei "teleport|semaphore|alloy|mariadb|nginx|wordpress|falco|grafana" || echo "No matching containers running."
    } | tee -a "$OUT_FILE"
fi

cat "$OUT_FILE"
echo "\n\n\n"

printf "\n${GREEN}[!] Inventory collection complete.${NC}\n"
echo "Results saved to: $OUT_FILE"