#!/usr/bin/env bash

# --- 0. ENSURE ROOT PRIVILEGES ---
if [ "$(id -u)" -ne 0 ]; then
    printf '\e[1;31mMust be run as root, exiting!\e[0m\n'
    exit 1
fi

# --- CONFIGURATION ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_DIR="/zxc/inventory_$TIMESTAMP"
BACKUP_DIR="/zxc/sys_backups_$TIMESTAMP"
mkdir -p "$OUT_DIR" "$BACKUP_DIR"
mkdir -p "$OUT_DIR/configs" "$OUT_DIR/db" "$OUT_DIR/persistence"

# --- HELPER FUNCTIONS ---
header() {
    echo -e "\n\033[1;34m[#] $1\033[0m"
    echo "=================================================="
}

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# --- 1. IDENTITY & DOMAIN CONTROLLER DISCOVERY (Integrated from ident.txt) ---
header "DOMAIN IDENTIFICATION"
{
    FOUND_DC=false
    # Samba Check
    if command_exists net; then
        IP=$(net ads info 2>/dev/null | grep 'LDAP server:' | awk '{print $3}')
        [ -n "$IP" ] && echo "DC address (Samba): $IP" && FOUND_DC=true
    fi
    # resolvectl check
    if command_exists resolvectl; then
        REALM=$(resolvectl domain | grep -E ': (.*)' -o | awk '{print $2}' | tail -1)
        if [ -n "$REALM" ]; then
            IP=$(resolvectl query "$REALM" 2>/dev/null | grep "$REALM: " | awk '{print $2}')
            [ -n "$IP" ] && echo "DC address (resolvectl): $IP" && FOUND_DC=true
        fi
    fi
    # Kerberos/SSSD Check
    [ -f /etc/krb5.conf ] && echo "Kerberos config found. Default Realm: $(grep 'default_realm' /etc/krb5.conf | awk '{print $3}')"
    [ -f /etc/sssd/sssd.conf ] && echo "SSSD Config Found"
} | tee "$OUT_DIR/domain_discovery.txt"

# --- 2. SYSTEM & NETWORKING ---
header "OS & KERNEL INFO"
{
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -a)"
    [ -f /etc/os-release ] && cat /etc/os-release
} > "$OUT_DIR/os_info.txt"

header "NETWORK TOPOLOGY & LISTENING"
{
    echo "--- Interfaces & Routes ---"
    ip addr || ifconfig
    ip route || route -n
    echo -e "\n--- DNS ---"
    cat /etc/resolv.conf
    
    echo -e "\n--- Listening Ports (ss) ---"
    command_exists ss && ss -tulpn
    echo -e "\n--- Listening Ports (netstat) ---"
    command_exists netstat && netstat -tulpn
    echo -e "\n--- Listening Ports (lsof) ---"
    command_exists lsof && lsof -i -n -P | grep LISTEN
    echo -e "\n--- Listening Ports (sockstat) ---"
    command_exists sockstat && sockstat
} > "$OUT_DIR/network.txt"

# --- 3. FIREWALL RULES ---
header "FIREWALL CONFIG"
{
    echo "--- IPTables ---"
    command_exists iptables && iptables -L -n -v
    echo -e "\n--- NFTables ---"
    command_exists nft && nft list ruleset
    echo -e "\n--- UFW ---"
    command_exists ufw && ufw status
    echo -e "\n--- Firewalld ---"
    command_exists firewall-cmd && firewall-cmd --list-all
} > "$OUT_DIR/firewall.txt"

# --- 4. SERVICES & CRITICAL CONFIGS ---
header "SERVICES ENUMERATION"
FILTER_REGEX="samba|sssd|krb5|wordpress|teleport|nginx|apache|httpd|nfs|mysql|mariadb|postgres|docker|falco|loki|grafana|prometheus|ansible"

{
    if ps -p 1 -o comm= | grep -q systemd; then
        echo "--- HIGH PRIORITY SERVICES ---"
        systemctl list-units --type=service --state=running | grep -Ei "$FILTER_REGEX"
        
        echo -e "\n--- EXPORTING RUNNING UNIT FILES ---"
        # Get list of running services and export their unit file content
        RUNNING_SERVICES=$(systemctl list-units --type=service --state=running --no-legend --no-pager | awk '{print $1}')
        
        for svc in $RUNNING_SERVICES; do
            # systemctl cat is better than cp because it handles overrides/drop-ins
            systemctl cat "$svc" > "$OUT_DIR/unit_files/$svc.service" 2>/dev/null
            echo "Exported: $svc"
        done

        echo -e "\n--- ALL RUNNING SERVICES ---"
        systemctl list-units --type=service --state=running
        echo -e "\n--- ALL INSTALLED SERVICES ---"
        systemctl list-unit-files --type=service
    else
        echo "--- RUNNING PROCESSES (Non-Systemd) ---"
        ps auxwwf
    fi
} > "$OUT_DIR/services.txt"

header "EXTRACTING CONFIGS"
CONFIG_PATHS=(
    "/etc/nginx/nginx.conf" "/etc/apache2/apache2.conf" "/etc/httpd/conf/httpd.conf"
    "/etc/samba/smb.conf" "/etc/sssd/sssd.conf" "/etc/krb5.conf"
    "/etc/teleport.yaml" "/etc/mysql/my.cnf" "/etc/my.cnf"
    "/var/www/html/wp-config.php" "/etc/ansible/ansible.cfg"
    "/etc/prometheus/prometheus.yml" "/etc/grafana/grafana.ini"
    "/etc/falco/falco.yaml"
)
for cfg in "${CONFIG_PATHS[@]}"; do
    if [ -f "$cfg" ]; then
        cp "$cfg" "$OUT_DIR/configs/$(basename "$cfg")_backup"
    fi
done

# --- 5. USERS, SUDOERS & PERSISTENCE ---
header "USER & SUDO AUDIT"
{
    echo "--- Users with Shells ---"
    grep -E 'sh$|bash$|zsh$' /etc/passwd
    echo -e "\n--- Sudoers ---"
    cat /etc/sudoers 2>/dev/null
    ls /etc/sudoers.d/ 2>/dev/null
    echo -e "\n--- NOPASSWD & !Authenticate Sudoers ---"
    grep -rEi "NOPASSWD|!authenticate" /etc/sudoers /etc/sudoers.d/ 2>/dev/null
} > "$OUT_DIR/users.txt"

header "PERSISTENCE & AUTORUNS"
{
    echo "--- Persistence Files ---"
    ls -la /etc/rc.local /etc/init.d/ /etc/ld.so.preload /etc/modules 2>/dev/null
    echo -e "\n--- LD.SO Configuration ---"
    cat /etc/ld.so.conf
    ls -F /etc/ld.so.conf.d/
    
    echo -e "\n--- Cronjobs ---"
    for user in $(cut -f1 -d: /etc/passwd); do 
        CRON=$(crontab -u "$user" -l 2>/dev/null)
        [ -n "$CRON" ] && echo "User $user: $CRON"
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
    echo -e "\n--- Capabilities (Including setuid) ---"
    getcap -r / 2>/dev/null
    echo -e "\n--- World Writable Files ---"
    find / -type f -perm -o+w 2>/dev/null | grep -vE "^/proc|^/sys|^/dev"
} > "$OUT_DIR/priv_esc.txt"

# --- 7. DOCKER & CONTAINERS ---
header "CONTAINER ENUMERATION"
if command_exists docker; then
    {
        echo "--- All Containers (including stopped) ---"
        docker ps -a
        echo -e "\n--- Images ---"
        docker images
        echo -e "\n--- Networks ---"
        docker network ls
        echo -e "\n--- Compose Files ---"
        find / -name "docker-compose.yml" -o -name "docker-compose.yaml" 2>/dev/null
    } > "$OUT_DIR/docker_info.txt"
fi

# --- 8. DATABASE AUDIT (Integrated logic from ref files) ---
header "DATABASE AUDIT"

# MySQL / MariaDB
if command_exists mysql; then
    echo "[*] Auditing MySQL..."
    DB_USER="root"
    # Attempting login without password (assuming socket/root access)
    mysql -u $DB_USER -e "SHOW DATABASES;" > "$OUT_DIR/db/mysql_databases.txt" 2>/dev/null
    if [ $? -eq 0 ]; then
        # List users
        mysql -u $DB_USER -e "SELECT user, host FROM mysql.user;" > "$OUT_DIR/db/mysql_users.txt"
        # Enumerating privileges for each DB (Logic from mysql_audit.txt)
        while read db; do
            [ "$db" == "Database" ] && continue
            echo "Grants for $db" >> "$OUT_DIR/db/mysql_grants.txt"
            mysql -u $DB_USER -e "SELECT user, host FROM mysql.user WHERE Drop_priv='Y' OR Alter_priv='Y';" >> "$OUT_DIR/db/mysql_grants.txt"
        done < "$OUT_DIR/db/mysql_databases.txt"
        # Full Dump
        mysqldump -u $DB_USER --all-databases > "$BACKUP_DIR/mysql_full.sql" 2>/dev/null
    fi
fi

# PostgreSQL
if command_exists psql; then
    echo "[*] Auditing PostgreSQL..."
    # Logic from psql_audit.txt
    sudo -u postgres psql -t -c "SELECT datname FROM pg_database;" > "$OUT_DIR/db/psql_databases.txt" 2>/dev/null
    while read db; do
        [ -z "$db" ] && continue
        db_clean=$(echo $db | xargs)
        sudo -u postgres psql -d "$db_clean" -c "SELECT grantor,grantee,table_name,privilege_type FROM information_schema.role_table_grants;" > "$OUT_DIR/db/psql_grants_$db_clean.txt" 2>/dev/null
    done < "$OUT_DIR/db/psql_databases.txt"
fi

# --- 9. STORAGE ---
header "STORAGE & MOUNTS"
{
    lsblk
    echo -e "\n--- Mounts ---"
    mount | column -t
    echo -e "\n--- FSTAB ---"
    cat /etc/fstab
} > "$OUT_DIR/storage.txt"

# --- 10. COMMAND AVAILABILITY (LOTL) ---
header "LOTL BINARIES"
ls /usr/bin /usr/sbin /bin /sbin > "$OUT_DIR/available_binaries.txt"

# --- FINAL PACKAGING & IMMUTABILITY ---
header "FINALIZING"
cp -r /etc "$BACKUP_DIR/etc_backup" 2>/dev/null
tar -czf "/root/inventory_$(hostname)_$TIMESTAMP.tar.gz" -C "$OUT_DIR" .

# not setting immutable because it makes our own life harder

# Set immutable flag on backups
#if command_exists chattr; then
#    chattr -R +i "$BACKUP_DIR" 2>/dev/null
#    echo "[+] Backups in $BACKUP_DIR set to immutable (+i)."
#fi

echo -e "\n\e[1;32m[!] Inventory Complete!\e[0m"
echo "Report: /root/inventory_$(hostname)_$TIMESTAMP.tar.gz"
echo "System Backups: $BACKUP_DIR"