#!/bin/bash

# Define variables
SPLUNK_DIR="/opt/splunk"
BACKUP_DIR="/backups/splunk"
SPLUNK_PORT=8000
SPLUNK_USER="splunk"

# 1. Update Splunk to the latest version
sudo wget -O splunk-latest.rpm https://download.splunk.com/path-to-latest.rpm
sudo rpm -Uvh splunk-latest.rpm
sudo splunk apply shcluster-bundle

# 2. Enforce strong password policies
sudo splunk edit auth ldap -minPwdLength 12 -mustChangePassword true
sudo splunk enable auth-mfa

# 3. Fix permissions issues
sudo chown -R $SPLUNK_USER:$SPLUNK_USER $SPLUNK_DIR/var/log/splunk
sudo chmod -R 755 $SPLUNK_DIR/var/log/splunk
sudo chattr -i $SPLUNK_DIR/var/log/splunk/*

# 4. Check and disable SELinux temporarily
sudo setenforce 0

# 5. Implement adaptive monitoring
sudo splunk search "index=_audit action=login" | awk '{print $3}' | sort | uniq -c | sort -nr | head -10
sudo splunk search "index=_internal sourcetype=splunkd_access" | grep -i failed

# 6. Protect log integrity
sudo mkdir -p $BACKUP_DIR
sudo splunk backup data -location $BACKUP_DIR

# 7. Ensure service availability
sudo systemctl enable splunk
sudo chattr +i $SPLUNK_DIR/etc/system/local/*
(sudo crontab -l ; echo "* * * * * $SPLUNK_DIR/bin/splunk restart") | sudo crontab -

# 8. Secure forwarder connections dynamically
sudo splunk search "index=_internal sourcetype=splunkd" | awk '{print $4}' | sort | uniq -c | sort -nr | head -10

# 9. Monitor installed apps
sudo splunk display app list
sudo find $SPLUNK_DIR/etc/apps -type f -mtime -1
sudo splunk edit user admin -role limited_access

# 10. Disable malicious scheduled searches
sudo splunk search "index=_internal sourcetype=scheduler"
sudo splunk disable savedsearch -name malicious_search

# 11. Close unused ports dynamically
sudo netstat -tuln | grep LISTEN
sudo iptables -A INPUT -p tcp --match multiport --dports 22,9997,8089 -j ACCEPT

# 12. Enable encryption
sudo splunk edit server -sslEnable 1

# 13. Restart Splunk with correct user
sudo -u $SPLUNK_USER $SPLUNK_DIR/bin/splunk start

# 14. Kill any conflicting processes
sudo pkill -f splunk

echo "Splunk defense script executed successfully."
