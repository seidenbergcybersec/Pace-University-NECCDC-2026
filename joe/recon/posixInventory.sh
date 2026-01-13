#!/bin/sh

# --- 0. ENSURE ROOT PRIVILEGES ---
if [ "$(id -u)" -ne 0 ]; then
    # POSIX printf is used instead of echo -e for consistent color output
    printf '\033[1;31mMust be run as root, exiting!\033[0m\n'
    exit 1
fi

# --- CONFIGURATION ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="/zxc/inventory_$TIMESTAMP"
BACKUP_DIR="/zxc/sys_backups_$TIMESTAMP"

# mkdir -p is standard
mkdir -p "$OUT_DIR" "$BACKUP_DIR"
mkdir -p "$OUT_DIR/configs" "$OUT_DIR/db" "$OUT_DIR/persistence" "$OUT_DIR/unit_files"

# --- HELPER FUNCTIONS ---
header() {
    printf '\n\033[1;34m[#] %s\033[0m\n' "$1"
    printf '==================================================\n'
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- 1. IDENTITY & DOMAIN CONTROLLER DISCOVERY ---
header "DOMAIN IDENTIFICATION"
{
    # Samba Check
    if command_exists net; then
        IP=$(net ads info 2>/dev/null | grep 'LDAP server:' | awk '{print $3}')
        if [ -n "$IP" ]; then echo "DC address (Samba): $IP"; fi
    fi
    # resolvectl check
    if command_exists resolvectl; then
        # POSIX grep doesn't support -o or -P reliably; using awk instead
        REALM=$(resolvectl domain | awk '/:/ {print $2}' | tail -n 1)
        if [ -n "$REALM" ]; then
            IP=$(resolvectl query "$REALM" 2>/dev/null | grep "$REALM: " | awk '{print $2}')
            if [ -n "$IP" ]; then echo "DC address (resolvectl): $IP"; fi
        fi
    fi
    # Kerberos/SSSD Check
    if [ -f /etc/krb5.conf ]; then
        REALM=$(grep 'default_realm' /etc/krb5.conf | awk '{print $3}')
        echo "Kerberos config found. Default Realm: $REALM"
    fi
    if [ -f /etc/sssd/sssd.conf ]; then
        echo "SSSD Config Found"
    fi
} | tee "$OUT_DIR/domain_discovery.txt"

# --- 2. SYSTEM & NETWORKING ---
header "OS & KERNEL INFO"
{
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -a)"
    if [ -f /etc/os-release ]; then cat /etc/os-release; fi
} > "$OUT_DIR/os_info.txt"

header "NETWORK TOPOLOGY & LISTENING"
{
    echo "--- Interfaces & Routes ---"
    ip addr 2>/dev/null || ifconfig 2>/dev/null
    ip route 2>/dev/null || route -n 2>/dev/null
    printf '\n--- DNS ---\n'
    cat /etc/resolv.conf
    
    printf '\n--- Listening Ports (ss) ---\n'
    if command_exists ss; then ss -tulpn; fi
    printf '\n--- Listening Ports (netstat) ---\n'
    if command_exists netstat; then netstat -tulpn; fi
    printf '\n--- Listening Ports (lsof) ---\n'
    if command_exists lsof; then lsof -i -n -P | grep LISTEN; fi
    printf '\n--- Listening Ports (sockstat) ---\n'
    if command_exists sockstat; then sockstat; fi
} > "$OUT_DIR/network.txt"

# --- 3. FIREWALL RULES ---
header "FIREWALL CONFIG"
{
    echo "--- IPTables ---"
    if command_exists iptables; then iptables -L -n -v; fi
    printf '\n--- NFTables ---\n'
    if command_exists nft; then nft list ruleset; fi
    printf '\n--- UFW ---\n'
    if command_exists ufw; then ufw status; fi
    printf '\n--- Firewalld ---\n'
    if command_exists firewall-cmd; then firewall-cmd --list-all; fi
} > "$OUT_DIR/firewall.txt"

# --- 4. SERVICES & CRITICAL CONFIGS ---
header "SERVICES ENUMERATION"
FILTER_REGEX="samba|sssd|krb5|wordpress|teleport|nginx|apache|httpd|nfs|mysql|mariadb|postgres|docker|falco|loki|grafana|prometheus|ansible"

{
    # Check for systemd presence without bash-specific ps flags
    if [ -d /run/systemd/system ]; then
        echo "--- HIGH PRIORITY SERVICES ---"
        systemctl list-units --type=service --state=running | grep -Ei "$FILTER_REGEX"
        
        printf '\n--- EXPORTING RUNNING UNIT FILES ---\n'
        # Get list of running services
        RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}')
        
        for svc in $RUNNING_SERVICES; do
            systemctl cat "$svc" > "$OUT_DIR/unit_files/$svc.service" 2>/dev/null
            echo "Exported: $svc"
        done

        printf '\n--- ALL RUNNING SERVICES ---\n'
        systemctl list-units --type=service --state=running
        printf '\n--- ALL INSTALLED SERVICES ---\n'
        systemctl list-unit-files --type=service
    else
        echo "--- RUNNING PROCESSES (Non-Systemd/OpenRC) ---"
        ps aux
    fi
} > "$OUT_DIR/services.txt"

header "EXTRACTING CONFIGS"
# POSIX doesn't have arrays. We use a space-separated string.
CONFIG_PATHS="/etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf 
/etc/samba/smb.conf /etc/sssd/sssd.conf /etc/krb5.conf 
/etc/teleport.yaml /etc/mysql/my.cnf /etc/my.cnf 
/var/www/html/wp-config.php /etc/ansible/ansible.cfg 
/etc/prometheus/prometheus.yml /etc/grafana/grafana.ini 
/etc/falco/falco.yaml"

for cfg in $CONFIG_PATHS; do
    if [ -f "$cfg" ]; then
        # Using basename replacement via shell parameter expansion
        base=$(basename "$cfg")
        cp "$cfg" "$OUT_DIR/configs/${base}_backup"
    fi
done

# --- 5. USERS, SUDOERS & PERSISTENCE ---
header "USER & SUDO AUDIT"
{
    echo "--- Users with Shells ---"
    grep -E 'sh$|bash$|zsh$' /etc/passwd
    printf '\n--- Sudoers ---\n'
    if [ -f /etc/sudoers ]; then cat /etc/sudoers; fi
    if [ -d /etc/sudoers.d ]; then ls /etc/sudoers.d/; fi
    printf '\n--- NOPASSWD & !Authenticate Sudoers ---\n'
    if [ -f /etc/sudoers ] || [ -d /etc/sudoers.d ]; then
        grep -rEi "NOPASSWD|!authenticate" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
    fi
} > "$OUT_DIR/users.txt"

header "PERSISTENCE & AUTORUNS"
{
    echo "--- Persistence Files ---"
    ls -la /etc/rc.local /etc/init.d/ /etc/ld.so.preload /etc/modules 2>/dev/null
    printf '\n--- LD.SO Configuration ---\n'
    if [ -f /etc/ld.so.conf ]; then cat /etc/ld.so.conf; fi
    if [ -d /etc/ld.so.conf.d ]; then ls -F /etc/ld.so.conf.d/; fi
    
    printf '\n--- Cronjobs ---\n'
    # Use cut instead of awk for portability where possible
    for user in $(cut -f1 -d: /etc/passwd); do 
        CRON=$(crontab -u "$user" -l 2>/dev/null)
        if [ -n "$CRON" ]; then echo "User $user: $CRON"; fi
    done
    ls -R /etc/cron* 2>/dev/null
} > "$OUT_DIR/persistence/persistence_list.txt"

# Pack shell configs & PAM
tar -czf "$OUT_DIR/persistence/shell_and_pam_configs.tar.gz" \
    /etc/pam.d/ \
    /home/*/.bashrc /home/*/.zshrc /home/*/.profile /home/*/.xinitrc /home/*/.xsession /home/*/.config/autostart/*.desktop \
    /root/.bashrc /root/.zshrc /root/.profile \
    2>/dev/null

# --- 6. PRIVILEGE ESCALATION VECTORS ---
header "PRIVILEGE ESCALATION VECTORS"
{
    echo "--- SUID Binaries ---"
    find / -perm -4000 -type f 2>/dev/null
    printf '\n--- Capabilities (Including setuid) ---\n'
    if command_exists getcap; then getcap -r / 2>/dev/null; fi
    printf '\n--- World Writable Files ---\n'
    find / -type f -perm -o+w 2>/dev/null | grep -vE "^/proc|^/sys|^/dev"
} > "$OUT_DIR/priv_esc.txt"

# --- 7. DOCKER & CONTAINERS ---
header "CONTAINER ENUMERATION"
if command_exists docker; then
    {
        echo "--- All Containers (including stopped) ---"
        docker ps -a
        printf '\n--- Images ---\n'
        docker images
        printf '\n--- Networks ---\n'
        docker network ls
        printf '\n--- Compose Files ---\n'
        find / -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null
    } > "$OUT_DIR/docker_info.txt"
fi

# --- 8. DATABASE AUDIT ---
header "DATABASE AUDIT"
if command_exists mysql; then
    echo "[*] Auditing MySQL..."
    DB_USER="root"
    if mysql -u $DB_USER -e "SHOW DATABASES;" > "$OUT_DIR/db/mysql_databases.txt" 2>/dev/null; then
        mysql -u $DB_USER -e "SELECT user, host FROM mysql.user;" > "$OUT_DIR/db/mysql_users.txt"
        while read -r db; do
            if [ "$db" = "Database" ]; then continue; fi
            echo "Grants for $db" >> "$OUT_DIR/db/mysql_grants.txt"
            mysql -u $DB_USER -e "SELECT user, host FROM mysql.user WHERE Drop_priv='Y' OR Alter_priv='Y';" >> "$OUT_DIR/db/mysql_grants.txt"
        done < "$OUT_DIR/db/mysql_databases.txt"
        mysqldump -u $DB_USER --all-databases > "$BACKUP_DIR/mysql_full.sql" 2>/dev/null
    fi
fi

if command_exists psql; then
    echo "[*] Auditing PostgreSQL..."
    sudo -u postgres psql -t -c "SELECT datname FROM pg_database;" > "$OUT_DIR/db/psql_databases.txt" 2>/dev/null
    while read -r db; do
        if [ -z "$db" ]; then continue; fi
        # Trimming whitespace in POSIX
        db_clean=$(echo "$db" | awk '{$1=$1;print}')
        sudo -u postgres psql -d "$db_clean" -c "SELECT grantor,grantee,table_name,privilege_type FROM information_schema.role_table_grants;" > "$OUT_DIR/db/psql_grants_$db_clean.txt" 2>/dev/null
    done < "$OUT_DIR/db/psql_databases.txt"
fi

# --- 9. STORAGE ---
header "STORAGE & MOUNTS"
{
    if command_exists lsblk; then lsblk; fi
    printf '\n--- Mounts ---\n'
    # 'column' is not always in Alpine; if missing, just cat
    if command_exists column; then mount | column -t; else mount; fi
    printf '\n--- FSTAB ---\n'
    cat /etc/fstab
} > "$OUT_DIR/storage.txt"

# --- 10. COMMAND AVAILABILITY (LOTL) ---
header "LOTL BINARIES"
ls /usr/bin /usr/sbin /bin /sbin > "$OUT_DIR/available_binaries.txt"

# --- FINAL PACKAGING & IMMUTABILITY ---
header "FINALIZING"
cp -r /etc "$BACKUP_DIR/etc_backup" 2>/dev/null
REPORT_NAME="/root/inventory_$(hostname)_$TIMESTAMP.tar.gz"
tar -czf "$REPORT_NAME" -C "$OUT_DIR" .

if command_exists chattr; then
    chattr -R +i "$BACKUP_DIR" 2>/dev/null
    echo "[+] Backups in $BACKUP_DIR set to immutable (+i)."
fi

printf '\n\033[1;32m[!] Inventory Complete!\033[0m\n'
echo "Report: $REPORT_NAME"
echo "System Backups: $BACKUP_DIR"