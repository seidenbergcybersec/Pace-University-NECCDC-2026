#!/bin/bash
wget -O splunk-latest.rpm "https://download.splunk.com/products/splunk/releases/8.2.6/linux/splunk-8.2.6-a6fe1ee8894b-linux-2.6-x86_64.rpm"
sudo rpm -ivh splunk-latest.rpm
sudo /opt/splunk/bin/splunk start --accept-license
sudo yum install epel-release
sudo yum install jemalloc
