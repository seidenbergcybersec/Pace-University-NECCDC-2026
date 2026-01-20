#!/usr/bin/env bash

# Store system information in variables
HOST=$(uname -n)
ADDR=$(ip r l | grep src | awk '{for (i=1;i<=NF;i++) if ($i == "src") {print $(i+1)};}')
CPU_CORES=$(lscpu | egrep -i "model name|socket")
OS=$(lsb_release -a | tail -4)
KERNEL=$(cat /proc/version)
NETSTAT=$(netstat -nltup)
SERVICES=$(systemctl list-units --type=service --state=running)
USERS=$(w)

# Function to display system information
show_system_info() {
    printf "\nHostname: $HOST \n\nCurrently logged in users: $USERS \n\nIP ADDRESS: \n$ADDR \n\n"
    printf "\n\nOperating System: \n$OS \n\nKernel: $KERNEL"
    printf "\n\nCurrent open ports: \n$NETSTAT"
    printf "\n\nCurrent running services: \n$SERVICES"
}

# Function to backup etc dir
backup_etc() {
    read -p "Do you want to backup /etc directory? (y/n): " choice
    if [[ $choice =~ ^[Yy]$ ]]; then
        cp -pr /etc "$BACKUP_DIR/etc.bak"
        echo "Creating compressed backup of /etc..."
        tar czf "$BACKUP_DIR/etc.tar.gz" -C / etc/
        echo "Complete /etc directory backed up to $BACKUP_DIR/etc.bak"
        echo "Compressed backup created at $BACKUP_DIR/etc.tar.gz"
    fi
}

# Function to backup service configs
backup_service_configs() {
    # Check for MySQL
    if systemctl is-active --quiet mysql; then
        read -p "MySQL is running. Backup its configuration? (y/n): " choice
        if [[ $choice =~ ^[Yy]$ ]]; then
            cp -p /etc/mysql/my.cnf "$BACKUP_DIR/mysql.cnf.bak" 2>/dev/null
            echo "MySQL config backed up to $BACKUP_DIR/mysql.cnf.bak"
        fi
    fi

    # Check for Apache
    if systemctl is-active --quiet apache2; then
        read -p "Apache is running. Backup its configuration? (y/n): " choice
        if [[ $choice =~ ^[Yy]$ ]]; then
            cp -pr /etc/apache2 "$BACKUP_DIR/apache2.bak"
            echo "Apache configs backed up to $BACKUP_DIR/apache2.bak"
        fi
    fi

    # Check for Nginx
    if systemctl is-active --quiet nginx; then
        read -p "Nginx is running. Backup its configuration? (y/n): " choice
        if [[ $choice =~ ^[Yy]$ ]]; then
            cp -pr /etc/nginx "$BACKUP_DIR/nginx.bak"
            echo "Nginx configs backed up to $BACKUP_DIR/nginx.bak"
        fi
    fi

    # Check for Splunk
    if systemctl is-active --quiet Splunkd || pgrep -x "splunkd" > /dev/null; then
        read -p "Splunk is running. Backup its configuration? (y/n): " choice
        if [[ $choice =~ ^[Yy]$ ]]; then
            # Backup both possible Splunk config locations
            if [ -d "/opt/splunk/etc" ]; then
                cp -pr /opt/splunk "$BACKUP_DIR/splunk_etc.bak"
                echo "Splunk configs backed up from /opt/splunk/etc"
            fi
            if [ -d "/opt/splunkforwarder/etc" ]; then
                cp -pr /opt/splunkforwarder/etc "$BACKUP_DIR/splunk_forwarder_etc.bak"
                echo "Splunk Forwarder configs backed up from /opt/splunkforwarder/etc"
            fi
        fi
    fi
}

# Function to suggest iptables rules
suggest_iptables_rules() {
    echo -e "\nBased on your open ports, here are recommended iptables rules:"
    echo "iptables -F INPUT  # Flush existing rules"
    echo "iptables -P INPUT DROP  # Set default policy to DROP"
    echo "iptables -A INPUT -i lo -j ACCEPT  # Allow loopback"
    echo "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    
    # Parse netstat output for open ports
    echo "$NETSTAT" | grep -E "LISTEN|^udp" | while read -r line; do
        # Extract port number and protocol
        port=$(echo "$line" | awk '{print $4}' | awk -F: '{print $NF}')
        proto=$(echo "$line" | awk '{print $1}')
        
        if [[ $port =~ ^[0-9]+$ ]]; then
            case $proto in
                "tcp")
                    echo "iptables -A INPUT -p tcp --dport $port -j ACCEPT  # Allow TCP port $port"
                    ;;
                "tcp6")
                    echo "ip6tables -A INPUT -p tcp --dport $port -j ACCEPT  # Allow TCP6 port $port"
                    ;;
                "udp")
                    echo "iptables -A INPUT -p udp --dport $port -j ACCEPT  # Allow UDP port $port"
                    ;;
                "udp6")
                    echo "ip6tables -A INPUT -p udp --dport $port -j ACCEPT  # Allow UDP6 port $port"
                    ;;
            esac
        fi
    done
}

# Main execution
echo "Starting system analysis script..."

# First prompt for system information
read -p $'\nWould you like to see general system information? (y/n): ' show_info
if [[ $show_info =~ ^[Yy]$ ]]; then
    show_system_info
    suggest_iptables_rules
fi

# Then prompt for backup procedure
read -p $'\nWould you like to start the backup procedure? (y/n): ' start_backup
if [[ $start_backup =~ ^[Yy]$ ]]; then
    # Create backup directory only if user wants to proceed with backup
    BACKUP_DIR="/root/secure_backups_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # Proceed with backups and security suggestions
    backup_etc
    backup_service_configs
    echo -e "\nScript completed. Backups stored in $BACKUP_DIR"
else
    echo -e "\nSkipping backup procedure. Script completed."
fi
