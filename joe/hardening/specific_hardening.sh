#!/bin/bash

# NECCDC Hardening Script
# Targets: WordPress Config, VSFTPD, MariaDB
# Supported: Debian, Rocky/RHEL, SUSE

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

echo "--- Starting NECCDC Hardening Script ---"

# 1. Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    OS="unknown"
fi

echo "[+] Detected OS: $OS"

# ---------------------------------------------------------
# TASK 1: WordPress Leak Validation
# ---------------------------------------------------------
echo "[*] Validating WordPress directories for leaked configs..."

# Common WP paths - Add more if your environment differs
WP_PATHS=("/var/www/html" "/var/www/wordpress" "/srv/www/htdocs")

for dir in "${WP_PATHS[@]}"; do
    if [ -d "$dir" ]; then
        echo "  - Checking $dir"
        
        # A. Find common backup extensions
        find "$dir" -type f \( -name "*.bak" -o -name "*.old" -o -name "*.save" -o -name "*.swp" -o -name "wp-config.php.*" \) -print | while read -r leak; do
            echo "    [!] POTENTIAL LEAK FOUND: $leak"
            # Uncomment the line below to auto-remove (Dangerous in competition!)
            # rm -f "$leak"
        done

        # B. Content Identity Check (Hash-based)
        if [ -f "$dir/wp-config.php" ]; then
            WP_HASH=$(md5sum "$dir/wp-config.php" | awk '{ print $1 }')
            find "$dir" -type f ! -name "wp-config.php" -exec md5sum {} + 2>/dev/null | grep "$WP_HASH" | while read -r line; do
                duplicate=$(echo "$line" | awk '{ print $2 }')
                echo "    [!] IDENTICAL CONFIG CONTENT FOUND: $duplicate"
            done
        fi
    fi
done

# ---------------------------------------------------------
# TASK 2: VSFTPD Security
# ---------------------------------------------------------
echo "[*] Hardening VSFTPD..."

case $OS in
    "debian"|"ubuntu") VSFTPD_CONF="/etc/vsftpd.conf" ;;
    "rocky"|"almalinux"|"rhel"|"fedora"|"sles"|"opensuse-leap") VSFTPD_CONF="/etc/vsftpd/vsftpd.conf" ;;
    *) VSFTPD_CONF="/etc/vsftpd.conf" ;;
esac

if [ -f "$VSFTPD_CONF" ]; then
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"
    
    # Ensure users are locked to their home directories
    sed -i 's/^#*chroot_local_user=.*/chroot_local_user=YES/' "$VSFTPD_CONF"
    # Modern vsftpd requires this if the root dir is writable
    if ! grep -q "allow_writeable_chroot" "$VSFTPD_CONF"; then
        echo "allow_writeable_chroot=YES" >> "$VSFTPD_CONF"
    fi

    # Disable dangerous anonymous uploads/writes
    sed -i 's/^#*anon_upload_enable=.*/anon_upload_enable=NO/' "$VSFTPD_CONF"
    sed -i 's/^#*anon_mkdir_write_enable=.*/anon_mkdir_write_enable=NO/' "$VSFTPD_CONF"
    sed -i 's/^#*anon_other_write_enable=.*/anon_other_write_enable=NO/' "$VSFTPD_CONF"
    
    # Banner to discourage Red Team
    sed -i 's/^#*ftpd_banner=.*/ftpd_banner=Authorized Access Only. All activity logged./' "$VSFTPD_CONF"


    # Enable logging of all FTP transactions
    sed -i 's/^#*xferlog_enable=.*/xferlog_enable=YES/' "$VSFTPD_CONF"
    
    # Ensure logs go to /var/log/vsftpd.log (default location)
    if ! grep -q "vsftpd_log_file" "$VSFTPD_CONF"; then
        echo "vsftpd_log_file=/var/log/vsftpd.log" >> "$VSFTPD_CONF"
    fi

    # THE "ALL THAT JAZZ" SETTING: Log every single FTP command and response
    sed -i 's/^#*log_ftp_protocol=.*/log_ftp_protocol=YES/' "$VSFTPD_CONF"

    # Disable standard ftpd format to get more detailed vsftpd-style logs
    sed -i 's/^#*xferlog_std_format=.*/xferlog_std_format=NO/' "$VSFTPD_CONF"

    # Ensure timestamps are in your local time instead of GMT
    sed -i 's/^#*use_localtime=.*/use_localtime=YES/' "$VSFTPD_CONF"

    # Create the log file manually to ensure permissions are correct
    touch /var/log/vsftpd.log
    chmod 600 /var/log/vsftpd.log


    systemctl restart vsftpd
    echo "  [+] VSFTPD secured and restarted."
else
    echo "  [-] VSFTPD config not found at $VSFTPD_CONF"
fi

# ---------------------------------------------------------
# TASK 3: MariaDB Localhost Binding
# ---------------------------------------------------------
echo "[*] Hardening MariaDB..."

# MariaDB config locations vary significantly
declare -a DB_CONFIGS=("/etc/mysql/mariadb.conf.d/50-server.cnf" "/etc/my.cnf.d/mariadb-server.cnf" "/etc/my.cnf" "/etc/mysql/my.cnf")

FORCED_BIND=false
for cfg in "${DB_CONFIGS[@]}"; do
    if [ -f "$cfg" ]; then
        # Check if bind-address exists in file
        if grep -q "bind-address" "$cfg"; then
            old_bind=$(grep -E '^[#]*bind-address' "$cfg")
            echo "  [i] Found bind-address in $cfg: $old_bind"

            sed -i 's/^#*bind-address.*/bind-address = 127.0.0.1/' "$cfg"

            FORCED_BIND=true
            echo "  [+] Set bind-address to 127.0.0.1 in $cfg"
        fi
    fi
done

# If bind-address wasn't found in any file, force it into the main config
if [ "$FORCED_BIND" = false ]; then
    if [ -f /etc/my.cnf ]; then
        echo -e "\n[mysqld]\nbind-address = 127.0.0.1" >> /etc/my.cnf
        echo "  [+] Added bind-address to /etc/my.cnf"
    fi
fi

systemctl restart mariadb || systemctl restart mysql
echo "  [+] MariaDB secured and restarted."

echo "--- Hardening Complete ---"