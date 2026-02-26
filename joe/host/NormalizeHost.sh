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

sudo apt install curl

# Verification
echo "---------------------------------------"
echo "Installation complete! Versions:"
nmap --version | head -n 1
ansible --version | head -n 1
go version
echo "---------------------------------------"