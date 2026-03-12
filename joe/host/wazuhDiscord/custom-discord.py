#!/usr/bin/env python3

import sys
import requests
import json
import socket

try:
    # This creates a dummy connection to determine the primary network interface IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    DASHBOARD_URL = f"https://{local_ip}"
except Exception:
    # Fallback if the auto-detection fails
    DASHBOARD_URL = "https://YOUR_DASHBOARD_IP"


# read configuration
alert_file = sys.argv[1]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# 1. Filter: Drop any alert level 11 or less
alert_level = alert_json.get("rule", {}).get("level", 0)
if alert_level <= 11:
    sys.exit(0)

# Define color based on level
color = "15548997" if alert_level >= 12 else "16705372"

# Extract IDs for Links
# Note: In Wazuh integrations, the JSON usually contains the _source fields directly.
# We check both the root and the common nested locations.
doc_id = alert_json.get("_id", "N/A")
doc_index = alert_json.get("_index", "wazuh-alerts-*")
wazuh_id = alert_json.get("id", "N/A")

# Link 1: Single Document View
single_doc_url = f"{DASHBOARD_URL}/app/discover#/doc/wazuh-alerts-*/{doc_index}?id={doc_id}"

# Link 2: Explore Page (Filtered by Wazuh ID)
explore_url = (
    f"{DASHBOARD_URL}/app/data-explorer/discover#?_a=(discover:(columns:!(_source),"
    f"isDirty:!f,sort:!()),metadata:(indexPattern:'wazuh-alerts-*',view:discover))"
    f"&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"
    f"&_q=(filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,"
    f"index:'wazuh-alerts-*',key:id,negate:!f,params:(query:'{wazuh_id}'),"
    f"type:phrase),query:(match_phrase:(id:'{wazuh_id}')))),query:(language:kuery,query:''))"
)

# Agent details
agent_name = alert_json.get("agent", {}).get("name", "agentless")
agent_id = alert_json.get("agent", {}).get("id", "N/A")

# Prepare Discord Fields
fields = [
    {"name": "Agent", "value": f"{agent_name} ({agent_id})", "inline": True},
    {"name": "Level", "value": str(alert_level), "inline": True},
    {"name": "Timestamp", "value": alert_json.get("timestamp", "N/A"), "inline": False},
    {"name": "Links", "value": f"[View Document]({single_doc_url}) | [Explore Alert]({explore_url})", "inline": False}
]

# 2. Extract more information dynamically
data_fields = alert_json.get("data", {})
useful_keys = ["dstuser", "srcuser", "srcip", "dstip", "srcport", "dstport", "command", "status"]

for key in useful_keys:
    if key in data_fields:
        fields.append({
            "name": key.capitalize(),
            "value": str(data_fields[key]),
            "inline": True
        })

# Include full log if available
full_log = alert_json.get("full_log", "")
if full_log:
    short_log = (full_log[:1020] + '...') if len(full_log) > 1024 else full_log
    fields.append({"name": "Full Log", "value": f"```{short_log}```", "inline": False})

# Combine message details
payload = {
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {alert_json.get('rule', {}).get('id', 'N/A')}",
            "color": color,
            "description": alert_json.get("rule", {}).get("description", "No description"),
            "fields": fields,
            "footer": {"text": "Wazuh Discord Integration"}
        }
    ]
}

# send message to discord
r = requests.post(
    hook_url, 
    data=json.dumps(payload), 
    headers={"content-type": "application/json"}
)

sys.exit(0)