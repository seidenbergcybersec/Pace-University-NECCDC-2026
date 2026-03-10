#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "CRITICAL: This script must be run as root (sudo)."
   exit 1
fi

echo "Updating system packages..."
sudo apt update

# 1. Install nmap
echo "Installing nmap..."
sudo apt install -y nmap

# 2. Install Ansible
echo "Installing Ansible..."
sudo apt install -y software-properties-common
sudo add-apt-repository --yes --update ppa:ansible/ansible
sudo apt install -y ansible

# 3. Install Go (Golang)
# Using snap is the easiest way to get the latest stable version on Ubuntu
echo "Installing Go..."
sudo snap install go --classic

echo "Installing Basic tools..."
apt-get install -y coreutils bash curl git net-tools vim wget grep tar jq gpg nano otpclient

sudo apt install -y python3-pip
sudo apt install -y python3-passlib

# VS Code

sudo apt install -y wget gpg apt-transport-https


# --- VS Code Section (Idempotent) ---

# 1. Create the keyrings directory if it doesn't exist
sudo mkdir -p -m 755 /etc/apt/keyrings

# 2. Download and overwrite the key to ensure it's always there/fresh
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | sudo tee /etc/apt/keyrings/packages.microsoft.gpg > /dev/null
sudo chmod 644 /etc/apt/keyrings/packages.microsoft.gpg

# 3. Use a single source file and OVERWRITE it (using tee without -a) 
# instead of letting it conflict with other potential files.
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null

# 4. CRITICAL: Remove the conflicting default file if it exists 
# (This is likely what caused your specific error)
if [ -f /etc/apt/sources.list.d/microsoft-vscode.list ]; then
    sudo rm /etc/apt/sources.list.d/microsoft-vscode.list
fi

sudo apt update
sudo apt install -y code



gsettings set org.gnome.TextEditor spellcheck false


# Verification
echo "---------------------------------------"
echo "Installation complete! Versions:"
nmap --version | head -n 1
ansible --version | head -n 1
go version
echo "---------------------------------------"