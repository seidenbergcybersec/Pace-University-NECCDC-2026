#!/bin/bash

# Function to install ClamAV and Fail2Ban on Debian-based systems
install_debian() {
    echo "Updating package list..."
    sudo apt update -y

    echo "Installing ClamAV and Fail2Ban..."
    sudo apt install -y clamav clamav-daemon fail2ban

    echo "Updating ClamAV virus database..."
    sudo systemctl stop clamav-freshclam
    sudo freshclam
    sudo systemctl start clamav-freshclam
}

# Function to install ClamAV and Fail2Ban on RHEL-based systems
install_rhel() {
    echo "Installing EPEL repository..."
    sudo yum install -y epel-release

    echo "Installing ClamAV and Fail2Ban..."
    sudo yum install -y clamav clamav-update fail2ban

    echo "Updating ClamAV virus database..."
    sudo freshclam
}

# Function to run ClamAV scan
run_clamav_scan() {
    SCAN_DIRS=("/etc" "/var" "/home")
    REPORT_FILE="/var/log/clamav_scan_report_$(date +%Y%m%d_%H%M%S).log"

    echo "Running ClamAV scan on sensitive directories: ${SCAN_DIRS[*]}"
    sudo clamscan -r ${SCAN_DIRS[*]} --bell --infected --log="$REPORT_FILE"

    echo "Scan complete. Report saved to $REPORT_FILE"
}

# Detect the Linux distribution and call appropriate functions
if [ -f /etc/debian_version ]; then
    echo "Debian-based system detected."
    install_debian
elif [ -f /etc/redhat-release ]; then
    echo "RHEL-based system detected."
    install_rhel
else
    echo "Unsupported Linux distribution. Exiting."
    exit 1
fi

# Run ClamAV scan and generate report
run_clamav_scan

# Display completion message
echo "Installation and scan process completed successfully."
