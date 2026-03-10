#!/bin/bash

# Wazuh All-in-One Installation Script (v4.14)
# Designed for NECCDC - Single Node Installation

set -e

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root (sudo)."
   exit 1
fi

echo "======================================================="
echo " Wazuh All-in-One Installer - Initial Configuration"
echo "======================================================="

# 2. IP Detection and User Verification
DETECTED_IP=$(hostname -I | awk '{print $1}')

echo "Detected Local IP: $DETECTED_IP"
read -p "Is this the correct IP address for your Wazuh installation? (y/n): " confirm

if [[ $confirm == "y" || $confirm == "Y" || $confirm == "" ]]; then
    NODE_IP=$DETECTED_IP
else
    read -p "Please enter the correct IP address manually: " NODE_IP
fi

# Validation: Check if IP is empty
if [[ -z "$NODE_IP" ]]; then
    echo "ERROR: IP address cannot be empty. Exiting."
    exit 1
fi

echo "Proceeding with IP: $NODE_IP"
echo "-------------------------------------------------------"

# 3. Download installation assistant and config
echo "Downloading Wazuh scripts and configuration templates..."
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml

# 4. Generate config.yml
echo "Configuring config.yml for All-in-One setup..."
cat > config.yml <<EOF
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "$NODE_IP"

  # Wazuh server nodes
  server:
    - name: wazuh-1
      ip: "$NODE_IP"

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "$NODE_IP"
EOF

# 5. Generate Certificates and Passwords
echo "Generating security certificates and cluster keys..."
bash wazuh-install.sh --generate-config-files



echo "--         Wazuh Indexer         --"
# 6. Installation Phase
echo "Starting Wazuh Indexer installation..."
bash wazuh-install.sh --wazuh-indexer node-1

echo "--         Wazuh Idexer initialization         --"
echo "Initializing Indexer Cluster (this may take a minute)..."
bash wazuh-install.sh --start-cluster

echo "--         Wazuh Server         --"
echo "Starting Wazuh Server installation..."
bash wazuh-install.sh --wazuh-server wazuh-1

echo "--         Wazuh Dashboard         --"
echo "Starting Wazuh Dashboard installation..."
bash wazuh-install.sh --wazuh-dashboard dashboard

# 7. Final Summary and Credentials
echo ""
echo "======================================================="
echo "               INSTALLATION COMPLETE"
echo "======================================================="
echo "Dashboard URL: https://$NODE_IP"
echo "Username:      admin"
echo -n "Password:      "
# Extracts the admin password from the generated files
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1 | grep -v "admin" | tr -d " '"
echo "======================================================="
echo "IMPORTANT: All passwords are saved in ./wazuh-install-files.tar"
echo "To see all passwords, run: "
echo "tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt"