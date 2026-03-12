#!/bin/bash

# Wazuh Discord Integration Auto-Setup Script
# Based on maikroservice's guide

# Paths
WAZUH_PATH="/var/ossec"
OSSEC_CONF="$WAZUH_PATH/etc/ossec.conf"
INTEGRATIONS_PATH="$WAZUH_PATH/integrations"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- Wazuh Discord Integration Setup ---${NC}"

# 1. Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root.${NC}"
   exit 1
fi

# 2. Check if source files exist in current directory
if [[ ! -f "custom-discord" ]] || [[ ! -f "custom-discord.py" ]]; then
    echo -e "${RED}Error: custom-discord or custom-discord.py not found in current directory.${NC}"
    exit 1
fi

# 3. Prompt for Webhook URL
echo -e "Please enter your Discord Webhook URL:"
read -r WEBHOOK_URL

if [[ ! $WEBHOOK_URL == https://discord.com/api/webhooks/* ]]; then
    echo -e "${RED}Invalid URL. It should start with https://discord.com/api/webhooks/${NC}"
    exit 1
fi

# 4. Update ossec.conf
echo -e "${GREEN}Updating $OSSEC_CONF...${NC}"

# Create backup
cp $OSSEC_CONF "$OSSEC_CONF.bak_$(date +%F_%H-%M-%S)"

# Check if integration already exists to avoid duplicates
if grep -q "custom-discord" "$OSSEC_CONF"; then
    echo -e "${RED}Integration 'custom-discord' already exists in ossec.conf. Skipping XML injection.${NC}"
else
    # Insert the integration block after the </global> tag
    sed -i "/<\/global>/a \\
 <integration>\\
     <name>custom-discord</name>\\
     <hook_url>$WEBHOOK_URL</hook_url>\\
     <alert_format>json</alert_format>\\
 </integration>" "$OSSEC_CONF"
fi

# 5. Copy integration files and set permissions
echo -e "${GREEN}Copying integration files...${NC}"
cp custom-discord "$INTEGRATIONS_PATH/"
cp custom-discord.py "$INTEGRATIONS_PATH/"

chmod 750 "$INTEGRATIONS_PATH"/custom-discord*
chown root:wazuh "$INTEGRATIONS_PATH"/custom-discord*

# 6. Install Dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
if command -v apt-get &> /dev/null; then
    apt-get update && apt-get install -y python3-pip
elif command -v yum &> /dev/null; then
    yum install -y python3-pip
fi

# Use Wazuh's internal python pip if possible, otherwise system pip
if [[ -f "$WAZUH_PATH/framework/python/bin/pip3" ]]; then
    "$WAZUH_PATH/framework/python/bin/pip3" install requests
else
    pip3 install requests
fi

# 7. Restart Wazuh Manager
echo -e "${GREEN}Restarting Wazuh Manager...${NC}"
"$WAZUH_PATH/bin/wazuh-control" restart

echo -e "${GREEN}--- Setup Complete! ---${NC}"
echo "Check /var/ossec/logs/ossec.log for any integration errors."