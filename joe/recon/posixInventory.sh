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
OUT_DIR="/zxc/inventory_$TIMESTAMP"
BACKUP_DIR="/zxc/sys_backups_$TIMESTAMP"

# Create directory structure
mkdir -p "$OUT_DIR"/{configs,db,persistence,unit_files,docker_inspect,teleport,falco,nginx,alloy} "$BACKUP_DIR"

# --- HELPER FUNCTIONS ---
header() {
    printf "\n${BLUE}[#] %s${NC}\n" "$1"
    printf '==================================================\n'
}

command_exists() {
    type "$1" &>/dev/null
}

# --- 1. IDENTITY & SYSTEM ---
header "SYSTEM INFO"
{
    echo "Hostname: $HOSTNAME"
    echo "Kernel: $(uname -a)"
    [[ -f /etc/os-release ]] && cat /etc/os-release
} > "$OUT_DIR/os_info.txt"

header "DOMAIN IDENTIFICATION"
{
    # Samba Check
    if command_exists net; then
        # Using Bash variable assignment from subshell
        IP=$(net ads info 2>/dev/null | awk '/LDAP server:/ {print $3}')
        [[ -n "$IP" ]] && echo "DC address (Samba): $IP"
    fi

    # resolvectl check (Common on Debian/SUSE/RHEL 8+)
    if command_exists resolvectl; then
        # Use Bash pattern matching instead of complex awk where possible
        REALM=$(resolvectl domain | awk '/:/ {print $2}' | tail -n 1)
        if [[ -n "$REALM" ]]; then
            IP=$(resolvectl query "$REALM" 2>/dev/null | awk "/$REALM: / {print \$2}")
            [[ -n "$IP" ]] && echo "DC address (resolvectl): $IP"
        fi
    fi

    # Kerberos/SSSD Check
    [[ -f /etc/krb5.conf ]] && echo "Kerberos config found. Realm: $(grep 'default_realm' /etc/krb5.conf | awk '{print $3}')"
    [[ -f /etc/sssd/sssd.conf ]] && echo "SSSD Config Found"

} | tee "$OUT_DIR/domain_discovery.txt"

header "NETWORK TOPOLOGY & LISTENING"
{
    echo "--- Interfaces & Routes ---"
    ip addr 2>/dev/null || ifconfig 2>/dev/null
    ip route 2>/dev/null || route -n 2>/dev/null
    
    printf '\n--- DNS ---\n'
    [[ -f /etc/resolv.conf ]] && cat /etc/resolv.conf
    
    # Check multiple tools in order of preference
    printf '\n--- Listening Ports ---\n'
    if command_exists ss; then ss -tulpn;
    elif command_exists netstat; then netstat -tulpn;
    elif command_exists lsof; then lsof -i -n -P | grep LISTEN;
    fi
} > "$OUT_DIR/network.txt"


# --- 2. SERVICES ENUMERATION ---
header "CRITICAL SERVICES ENUMERATION"
# Expanded Filter Regex per requirements
FILTER_REGEX="samba|sssd|krb5|wordpress|teleport|nginx|apache|httpd|nfs|mysql|mariadb|postgres|docker|falco|loki|grafana|prometheus|ansible|teleport|docker|nginx|mariadb|mysql|vsftpd|semaphore|alloy|falco|samba|sssd|gitea"

{
    if [[ -d /run/systemd/system ]]; then
        echo "--- HIGH PRIORITY SERVICES ---"
        systemctl list-units --type=service --state=running | grep -Ei "$FILTER_REGEX"
        
        printf '\n--- EXPORTING RUNNING UNIT FILES ---\n'
        readarray -t RUNNING_SERVICES < <(systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}')
        
        for svc in "${RUNNING_SERVICES[@]}"; do
            [[ -z "$svc" ]] && continue
            systemctl cat "$svc" > "$OUT_DIR/unit_files/$svc.service" 2>/dev/null
        done
        echo "Exported ${#RUNNING_SERVICES[@]} unit files."

    else
        echo "--- RUNNING PROCESSES (Non-Systemd) ---"
        ps auxf
    fi
} > "$OUT_DIR/services.txt"

# --- 3. DOCKER DEEP DIVE (PODS/CONTAINERS CONFIG) ---
if command_exists docker; then
    header "DOCKER DEEP DIVE"
    {
        echo "[*] Capturing Docker Network and Daemon Config..."
        [[ -f /etc/docker/daemon.json ]] && cp /etc/docker/daemon.json "$OUT_DIR/configs/docker_daemon.json"
        
        docker ps -a --format "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}" > "$OUT_DIR/docker_list.txt"
        
        echo "[*] Capturing Container Start Commands and Configs..."
        readarray -t CONTAINERS < <(docker ps -a --format "{{.Names}}")
        for container in "${CONTAINERS[@]}"; do
            # This captures EVERYTHING: Mounts, Env, Entrypoint, Cmd, Labels
            docker inspect "$container" > "$OUT_DIR/docker_inspect/${container}_inspect.json"
        done
        
        docker network inspect $(docker network ls -q) > "$OUT_DIR/docker_inspect/networks.json" 2>/dev/null
    }
fi

# --- 4. CONFIGURATION EXTRACTION (CRITICAL SERVICES) ---
header "EXTRACTING SERVICE CONFIGS"

# Array of specific files to pull
CONFIG_PATHS=(
    "/etc/samba/smb.conf" "/etc/sssd/sssd.conf" "/etc/krb5.conf"
    "/etc/vsftpd.conf" "/etc/vsftpd/user_list" "/etc/vsftpd/chroot_list"
    "/etc/teleport.yaml" "/etc/semaphore/config.json"
    "/etc/alloy/config.alloy" "/etc/default/alloy"
    "/etc/falco/falco.yaml" "/etc/falco/falco_rules.yaml" "/etc/falco/falco_rules.local.yaml" "/etc/falco/sidekick.yaml" "/etc/falcosidekick/config.yaml"
    "/etc/nginx/nginx.conf" "/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf"
    "/etc/mysql/my.cnf" "/etc/my.cnf"
    "/var/www/html/wp-config.php" "/etc/ansible/ansible.cfg"
)

for cfg in "${CONFIG_PATHS[@]}"; do
    if [[ -f "$cfg" ]]; then
        cp --parents "$cfg" "$OUT_DIR/configs/" 2>/dev/null
    fi
done

# Special handling for directory-based configs
[[ -d /etc/nginx/conf.d ]] && cp -r /etc/nginx/conf.d "$OUT_DIR/nginx/"
[[ -d /etc/nginx/sites-enabled ]] && cp -r /etc/nginx/sites-enabled "$OUT_DIR/nginx/"
[[ -d /etc/mysql/mariadb.conf.d ]] && cp -r /etc/mysql/mariadb.conf.d "$OUT_DIR/configs/"
[[ -d /etc/vsftpd ]] && cp -r /etc/vsftpd "$OUT_DIR/configs/"
[[ -d /var/lib/teleport ]] && cp /var/lib/teleport/*.yaml "$OUT_DIR/teleport/" 2>/dev/null


# --- 5. USERS & PERSISTENCE ---
header "USER & SUDO AUDIT"
{
    echo "--- Users with Shells ---"
    grep -E 'sh$|bash$|zsh$' /etc/passwd
    
    printf '\n--- Sudoers (NOPASSWD) ---\n'
    grep -rEi "NOPASSWD|!authenticate" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
} > "$OUT_DIR/users.txt"

header "PERSISTENCE & AUTORUNS"
{
    # Check Crontabs for all users
    # getent is standard on RHEL/Debian/SUSE
    while read -r user; do
        CRON=$(crontab -u "$user" -l 2>/dev/null)
        [[ -n "$CRON" ]] && echo "User $user: $CRON"
    done < <(getent passwd | cut -d: -f1)

} > "$OUT_DIR/persistence/persistence_list.txt"

# Archive shell & PAM configs
tar -czf "$OUT_DIR/persistence/shell_and_pam_configs.tar.gz" \
    /etc/pam.d/ /root/.bash* /home/*/.bash* 2>/dev/null


header "TELEPORT CLUSTER AUDIT"
if command_exists tctl; then
    {
        echo "--- Teleport Auth Status ---"
        tctl status 2>/dev/null || echo "Could not get status (Auth server may be remote or down)"

        echo -e "\n--- Teleport Users ---"
        tctl users ls 2>/dev/null

        echo -e "\n--- Connected Boxes (Nodes) ---"
        tctl nodes ls 2>/dev/null

        echo -e "\n--- Registered Applications ---"
        tctl apps ls 2>/dev/null

        echo -e "\n--- Database Resources ---"
        tctl db ls 2>/dev/null

        echo -e "\n--- Active Roles ---"
        tctl auth ls 2>/dev/null

        # Export raw JSON for detailed analysis
        tctl nodes ls --format=json > "$OUT_DIR/teleport/nodes_raw.json" 2>/dev/null
        tctl users ls --format=json > "$OUT_DIR/teleport/users_raw.json" 2>/dev/null
        tctl apps ls --format=json > "$OUT_DIR/teleport/apps_raw.json" 2>/dev/null
    } > "$OUT_DIR/teleport/teleport_admin_inventory.txt"
    echo "[+] Teleport cluster data collected via tctl."
else
    echo "[-] tctl not found. This box might not be a Teleport Admin/Auth node."
fi


# --- 6. PRIVILEGE ESCALATION VECTORS ---
header "PRIVILEGE ESCALATION VECTORS"
{
    echo "--- SUID Binaries ---"
    find / -perm -4000 -type f 2>/dev/null
    printf '\n--- Capabilities ---\n'
    command_exists getcap && getcap -r / 2>/dev/null
} > "$OUT_DIR/priv_esc.txt"


# --- 7. DOCKER ---
if command_exists docker; then
    header "DOCKER ENUMERATION"
    {
        docker ps -a
        docker images
        docker network ls
    } > "$OUT_DIR/docker_info.txt"
fi



# --- 8. DATABASE BACKUP ---
header "DATABASE AUDIT & BACKUP"
if command_exists mariadb || command_exists mysql; then
    # Try to identify if it is MariaDB specifically
    DB_TYPE="mysql"
    command_exists mariadb && DB_TYPE="mariadb"
    
    echo "[*] Exporting $DB_TYPE Users and Full Dump..."
    # Attempting export via local socket (requires root)
    mysql -e "SELECT user, host FROM mysql.user;" > "$OUT_DIR/db/db_users.txt" 2>/dev/null
    mysqldump --all-databases --single-transaction --quick > "$BACKUP_DIR/${DB_TYPE}_full_backup.sql" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        echo "[+] Database backup successful."
    else
        echo "[!] Database backup failed (check permissions/socket)."
    fi
fi

# --- 9. FIREWALL RULES ---
header "FIREWALL CONFIG"
{
    command_exists iptables && iptables -L -n -v
    command_exists nft && nft list ruleset
    command_exists ufw && ufw status
    command_exists firewall-cmd && firewall-cmd --list-all
} > "$OUT_DIR/firewall.txt"





# --- FINAL PACKAGING ---
header "FINALIZING"
# Backup /etc
cp -r /etc "$BACKUP_DIR/etc_backup" 2>/dev/null

REPORT_NAME="/root/inventory_${HOSTNAME}_${TIMESTAMP}.tar.gz"
tar -czf "$REPORT_NAME" -C "$OUT_DIR" .

# Set immutable if available
#if command_exists chattr; then
#    chattr -R +i "$BACKUP_DIR" 2>/dev/null
#    echo "[+] Backups in $BACKUP_DIR set to immutable."
#fi

printf "\n${GREEN}[!] Inventory Complete!${NC}\n"
echo "Report: $REPORT_NAME"
echo "System Backups: $BACKUP_DIR"