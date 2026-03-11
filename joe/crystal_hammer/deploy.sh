#!/bin/bash

# Exit on error
set -e

BINARY="./server/server_static"
KEY_PATH="../ansible/ssh/id_rsa"
SERVICE_NAME="ksysguardd"
REMOTE_BIN_PATH="/usr/local/bin/server_static"
LISTEN_PORT=6769

echo "--- Starting Deployment Process ---"

# 1. Check if local binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Compiled binary $BINARY not found. Run compile.sh first."
    exit 1
fi

# 2. Check if SSH private key exists
if [ ! -f "$KEY_PATH" ]; then
    echo "ERROR: SSH Key not found at $KEY_PATH"
    exit 1
fi

# 3. Get User Input
read -p "Enter Target IP Address: " TARGET_IP
read -p "Enter SSH Username: " SSH_USER

# SSH Options
SSH_OPTS="-i $KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# 4. Upload binary
echo "[1/3] Uploading binary to $TARGET_IP..."
cat "$BINARY" | ssh $SSH_OPTS "${SSH_USER}@${TARGET_IP}" "cat > /tmp/server_static"

# 5. Remote Configuration via SSH
echo "[2/3] Setting up service, security profiles, and firewall..."

ssh $SSH_OPTS "${SSH_USER}@${TARGET_IP}" << EOF
    # Move binary to system path and make executable
    sudo mv /tmp/server_static $REMOTE_BIN_PATH
    sudo chmod +x $REMOTE_BIN_PATH
    sudo chown root:root $REMOTE_BIN_PATH

    # --- AppArmor Configuration (Ubuntu/Debian) ---
    if command -v aa-status >/dev/null 2>&1 && sudo aa-status --enabled; then
        echo "AppArmor is active. Creating unconfined profile..."
        PROFILE_NAME=\$(echo "$REMOTE_BIN_PATH" | sed 's/^\///;s/\//./g')
        sudo tee /etc/apparmor.d/\$PROFILE_NAME > /dev/null <<AA_CONF
$REMOTE_BIN_PATH flags=(unconfined) {
  # Allow binary to run without AppArmor restrictions
}
AA_CONF
        sudo apparmor_parser -r /etc/apparmor.d/\$PROFILE_NAME
        echo "AppArmor profile loaded."
    fi

    # --- SELinux Configuration (RHEL/CentOS/Fedora) ---
    if command -v getenforce >/dev/null 2>&1 && [ "\$(getenforce)" != "Disabled" ]; then
        echo "SELinux is active (\$(getenforce)). Applying contexts..."
        sudo restorecon -v $REMOTE_BIN_PATH
        sudo chcon -t bin_t $REMOTE_BIN_PATH
        echo "SELinux contexts applied."
    fi

    # --- Firewall Configuration ---
    echo "Configuring firewall for port $LISTEN_PORT..."
    
    # 1. Check for firewalld (RHEL/CentOS/Fedora)
    if systemctl is-active --quiet firewalld; then
        echo "Detected firewalld. Opening port $LISTEN_PORT..."
        sudo firewall-cmd --permanent --add-port=$LISTEN_PORT/tcp
        sudo firewall-cmd --reload

    # 2. Check for UFW (Ubuntu/Debian)
    elif command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -q "active"; then
        echo "Detected UFW. Opening port $LISTEN_PORT..."
        sudo ufw allow $LISTEN_PORT/tcp

    # 3. Check for nftables
    elif systemctl is-active --quiet nftables; then
        echo "Detected nftables. Adding rule..."
        # Adds rule to the 'filter' table 'input' chain if it exists
        sudo nft add rule inet filter input tcp dport $LISTEN_PORT accept 2>/dev/null || \
        echo "Warning: nftables is active but 'inet filter input' chain not found. Manual config may be required."

    # 4. Fallback to iptables
    elif command -v iptables >/dev/null 2>&1; then
        echo "Detected iptables. Adding rule..."
        # Check if rule exists first to avoid duplicates
        sudo iptables -C INPUT -p tcp --dport $LISTEN_PORT -j ACCEPT >/dev/null 2>&1 || \
        sudo iptables -I INPUT -p tcp --dport $LISTEN_PORT -j ACCEPT
    else
        echo "No supported firewall (firewalld, ufw, nftables, iptables) detected or active."
    fi

    # --- Systemd Service ---
    echo "Creating systemd service..."
    sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<SERVICE
[Unit]
Description=kernel level protection and monitoring daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=$REMOTE_BIN_PATH -p $LISTEN_PORT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

    # Reload systemd, enable and start the service
    echo "Starting service..."
    sudo systemctl daemon-reload
    sudo systemctl enable ${SERVICE_NAME}
    sudo systemctl restart ${SERVICE_NAME}

    echo "Status check:"
    sudo systemctl is-active ${SERVICE_NAME}
EOF

echo "[3/3] Deployment to $TARGET_IP complete."
echo "======================================="
echo
echo "To run client:"
echo "cd ../client"
echo "./client_static -addr 10.0.15.100:6769"