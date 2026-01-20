#!/bin/bash

# Define variables
SPLUNK_DIR="/opt/splunk"
BACKUP_DIR="/backups/splunk"
SPLUNK_USER="splunk"

echo "Reverting Splunk defense changes..."

# 1. Remove any applied updates
echo "Removing Splunk updates..."
yum remove splunk -y || rpm -e splunk

# 2. Restore default password policies (if applicable)
echo "Resetting password policies..."
splunk edit auth ldap -minPwdLength 8 -mustChangePassword false || echo "Skipping password policy reset."

# 3. Revert permissions
echo "Restoring file permissions..."
chown -R root:root $SPLUNK_DIR/var/log/splunk
chmod -R 700 $SPLUNK_DIR/var/log/splunk
chattr -R -i $SPLUNK_DIR/var/log/splunk/*

# 4. Re-enable SELinux
echo "Re-enabling SELinux..."
setenforce 1
sed -i 's/^SELINUX=disabled/SELINUX=enforcing/' /etc/selinux/config

# 5. Remove backup data
echo "Removing backup directory..."
rm -rf $BACKUP_DIR

# 6. Disable Splunk service autostart
echo "Disabling Splunk service auto-start..."
systemctl disable splunk

# 7. Remove Splunk restart cron job
echo "Removing cron job for Splunk restart..."
crontab -l | grep -v 'splunk restart' | crontab -

# 8. Restore app monitoring
echo "Resetting app configurations..."
splunk display app list || echo "No apps to reset."
find $SPLUNK_DIR/etc/apps -type f -mtime -1 -delete

# 9. Remove modified user roles
echo "Reverting admin roles..."
splunk edit user admin -role admin

# 10. Re-enable disabled scheduled searches
echo "Enabling previously disabled searches..."
splunk enable savedsearch -name malicious_search || echo "No saved searches found to enable."

# 11. Open closed ports
echo "Reopening closed ports..."
iptables -D INPUT -p tcp --match multiport --dports 22,9997,8089 -j ACCEPT
iptables-save > /etc/sysconfig/iptables

# 12. Disable SSL encryption if enabled
echo "Disabling Splunk encryption..."
splunk edit server -sslEnable 0

# 13. Stop Splunk service
echo "Stopping Splunk service..."
sudo -u $SPLUNK_USER $SPLUNK_DIR/bin/splunk stop

# 14. Kill lingering Splunk processes
echo "Terminating any Splunk-related processes..."
pkill -f splunk

echo "Splunk has been restored to its original state."
