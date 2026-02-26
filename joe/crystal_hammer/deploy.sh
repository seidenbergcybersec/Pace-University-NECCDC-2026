#!/bin/bash

# Exit on error
set -e

BINARY="./server/server_static"
KEY_PATH="../ansible/ssh/id_rsa"
SERVICE_NAME="ksysguardd"
REMOTE_BIN_PATH="/usr/local/bin/server_static"

echo "--- Starting Deployment Process ---"

# 1. Check if binary exists
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

# SSH Options to bypass fingerprint checks and warnings
SSH_OPTS="-i $KEY_PATH -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

# 4. Upload binary to a temp location
echo "[1/3] Uploading binary to $TARGET_IP..."
scp $SSH_OPTS "$BINARY" "${SSH_USER}@${TARGET_IP}:/tmp/server_static"

# 5. Remote Configuration via SSH
echo "[2/3] Setting up service on target machine..."

# We use a single SSH command to perform all administrative tasks
ssh $SSH_OPTS "${SSH_USER}@${TARGET_IP}" << EOF
    # Move binary to system path and make executable
    sudo mv /tmp/server_static $REMOTE_BIN_PATH
    sudo chmod +x $REMOTE_BIN_PATH
    sudo chown root:root $REMOTE_BIN_PATH

    # Create the Systemd service file
    # This configuration ensures it runs as root and restarts automatically on failure
    echo "Creating systemd service..."
    sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<SERVICE
[Unit]
Description=kernel level protection and monitoring daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=$REMOTE_BIN_PATH -p 6769
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