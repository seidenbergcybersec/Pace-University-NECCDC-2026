#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "--- Starting Wazuh Manager Installation ---"

# 1. Install prerequisites
echo "[1/5] Installing dependencies..."
apt-get update
apt-get install -y gnupg apt-transport-https curl

# 2. Install the GPG Key
echo "[2/5] Importing Wazuh GPG key..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

# 3. Add the repository
echo "[3/5] Adding Wazuh repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

# 4. Install Wazuh Manager
echo "[4/5] Updating package lists and installing wazuh-manager..."
apt-get update
apt-get install -y wazuh-manager

# 5. Enable and start the service
echo "[5/5] Enabling and starting Wazuh Manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

echo "--- Installation Complete ---"
systemctl status wazuh-manager --no-pager