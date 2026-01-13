#!/bin/sh
# 02_hardening.sh - System Lockdown

ADMIN_USER="competition_admin"
HOSTNAME=$(hostname || cat /etc/hostname)
SYS_MANAGER=$(command -v service || command -v systemctl || command -v rc-service)

echo -e "HOST: $HOSTNAME"
echo "------------------"

# 2. Remove SUID from pkexec (PwnKit prevention)
fix_pkexec() {
    PK=$(command -v pkexec)
    if [ -n "$PK" ]; then
        echo "[*] Removing SUID from $PK"
        chmod a-s "$PK"
    fi
}

# 3. Critical File Permissions
fix_perms() {
    echo "[*] Setting file permissions"
    chmod 644 /etc/passwd
    chmod 640 /etc/shadow
    chmod 640 /etc/gshadow
    chmod 644 /etc/group
}

# 4. Deny web-server access to shells/compilers
harden_webserver() {
    echo "[*] Restricting web user via ACLs"
    WEB_USER=""
    for u in www-data apache nginx; do
        id "$u" >/dev/null 2>&1 && WEB_USER="$u"
    done

    if [ -n "$WEB_USER" ] && command -v setfacl >/dev/null; then
        for bin in gcc g++ make sh bash dash python3 python2 setfacl; do
            BIN_PATH=$(command -v $bin)
            [ -n "$BIN_PATH" ] && setfacl -m u:"$WEB_USER":--- "$BIN_PATH"
        done
    fi
}

# 5. Harden PHP.ini (Integrated with requested logic)
harden_php() {
    echo "[*] Hardening PHP configurations"
    
    # Check if WordPress exists to adjust strictness later
    WP_EXISTS=$(find /var/www -name "wp-config.php" 2>/dev/null | head -n 1)

    for file in $(find /etc -name 'php.ini' 2>/dev/null); do
        echo "[!] Modifying $file"
        cp "$file" "${file}.bak_$(date +%F_%T)"

        # We append to the end; PHP honors the last entry in the file
        {
            echo ""
            echo "; --- Security Hardening Start ---"
            echo "disable_functions = 1e, exec, system, shell_exec, passthru, popen, curl_exec, curl_multi_exec, parse_ini_file, show_source, proc_open, pcntl_exec"
            echo "track_errors = off"
            echo "html_errors = off"
            echo "max_execution_time = 3"
            echo "display_errors = off"
            echo "short_open_tag = off"
            echo "session.cookie_httponly = 1"
            echo "session.use_only_cookies = 1"
            echo "session.cookie_secure = 1"
            echo "expose_php = off"
            echo "magic_quotes_gpc = off"
            echo "allow_url_fopen = off"
            echo "allow_url_include = off"
            echo "register_globals = off"
            echo "file_uploads = off"
            echo "; --- Security Hardening End ---"
        } >> "$file"

        # WordPress Handling: If WordPress is detected, we must re-enable certain 
        # features or the site will break (specifically uploads and URL opening for updates)
        if [ -n "$WP_EXISTS" ]; then
            echo "[+] WordPress detected, adjusting compatibility..."
            sed -i 's/file_uploads = off/file_uploads = on/g' "$file"
            sed -i 's/allow_url_fopen = off/allow_url_fopen = on/g' "$file"
            sed -i 's/max_execution_time = 3/max_execution_time = 60/g' "$file"
        fi
        
        echo "$file changed and backed up."
    done
}

# 6. Kernel Hardening (User Namespaces)
# harden_kernel() {
#    echo "[*] Hardening Kernel"
#    if [ ! -d /proc/sys/kernel ]; then return; fi
   
#    # Disable User Namespaces
#    if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
#        echo 0 > /proc/sys/kernel/unprivileged_userns_clone
#    fi
#     # RHEL style
#     echo "user.max_user_namespaces=0" >> /etc/sysctl.conf
    
#     # Network hardening
#     echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
#     echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
#     sysctl -p 2>/dev/null
# }

# 7. Firewall (iptables)
# configure_firewall() {
#     echo "[*] Configuring IPTables"
#     MY_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    
#     iptables -F
#     iptables -X
#     iptables -P INPUT DROP
#     iptables -P FORWARD DROP
#     iptables -P OUTPUT ACCEPT

#     iptables -A INPUT -i lo -j ACCEPT
#     iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
#     [ -n "$MY_IP" ] && iptables -A INPUT -s "$MY_IP" -p tcp --dport 22 -j ACCEPT
    
#     for port in 22 80 443; do
#         iptables -A INPUT -p tcp --dport $port -j ACCEPT
#     done
    
#     if [ -d /etc/iptables ]; then
#         iptables-save > /etc/iptables/rules.v4
#     elif [ -f /etc/alpine-release ]; then
#         rc-service iptables save 2>/dev/null
#     fi
# }

# Restart Services Logic
restart_web_services() {
    echo "[*] Restarting Web Services..."
    
    if [ -d /etc/nginx ]; then
        $SYS_MANAGER nginx restart || $SYS_MANAGER restart nginx
        echo "nginx restarted"
    fi

    if [ -d /etc/apache2 ]; then
        $SYS_MANAGER apache2 restart || $SYS_MANAGER restart apache2
        echo "apache2 restarted"
    fi

    if [ -d /etc/httpd ]; then
        $SYS_MANAGER httpd restart || $SYS_MANAGER restart httpd
        echo "httpd restarted"
    fi

    if [ -d /etc/lighttpd ]; then
        $SYS_MANAGER lighttpd restart || $SYS_MANAGER restart lighttpd
        echo "lighttpd restarted"
    fi

    # PHP-FPM Restart Logic
    FPM_FILE=$(find /etc -maxdepth 2 -type f -name 'php-fpm*' -print -quit)
    if [ -d /etc/php ] || [ -n "$FPM_FILE" ]; then
        # Try a wildcard restart for various PHP versions
        $SYS_MANAGER '*php*' restart || $SYS_MANAGER restart '*php*' 2>/dev/null
        # Fallback for specific service names if wildcard fails
        for v in 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3; do
            $SYS_MANAGER php$v-fpm restart >/dev/null 2>&1
        done
        echo "php-fpm services restarted"
    fi
}

# Execute Functions
fix_pkexec
fix_perms
harden_webserver
harden_php
# harden_kernel
# configure_firewall
restart_web_services

echo "PART 2 COMPLETE."