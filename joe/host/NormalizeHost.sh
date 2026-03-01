#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

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

sudo apt install python3-pip
sudo apt install python3-passlib

# VS Code

sudo apt install -y wget gpg apt-transport-https

# 2. Import the Microsoft GPG key
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg

# 3. Add the VS Code repository
echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" | sudo tee /etc/apt/sources.list.d/vscode.list > /dev/null

# 4. Clean up the temporary gpg file
rm -f packages.microsoft.gpg

# 5. Update the package cache and install VS Code
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