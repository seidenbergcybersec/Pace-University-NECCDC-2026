#!/usr/bin/env python3

import sys
import requests
import json
import socket

# --- CONFIGURATION & LIMITS ---
MAX_FIELD_VAL = 1000  # Discord limit is 1024
MAX_DESC = 3000       # Discord limit is 4096
MAX_TOTAL = 5500      # Discord total limit is 6000

def safe_truncate(text, limit):
    """Truncates string and adds ellipsis if needed."""
    if not text: return "N/A"
    text = str(text)
    return (text[:limit-3] + '...') if len(text) > limit else text

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    DASHBOARD_URL = f"https://{local_ip}"
except Exception:
    DASHBOARD_URL = "https://YOUR_DASHBOARD_IP"

# Read configuration
alert_file = sys.argv[1]
hook_url = sys.argv[3]

with open(alert_file) as f:
    alert_json = json.loads(f.read())

# Filter: Drop any alert level 11 or less
alert_level = alert_json.get("rule", {}).get("level", 0)
if alert_level <= 11:
    sys.exit(0)

color = "15548997" if alert_level >= 12 else "16705372"
wazuh_id = alert_json.get("id", alert_json.get("_id", "N/A"))
rule_desc = alert_json.get("rule", {}).get("description", "No description")

# 1. Truncate Description
clean_desc = safe_truncate(rule_desc, MAX_DESC)
formatted_description = f"## {clean_desc}\n"

# Agent details
agent_name = alert_json.get("agent", {}).get("name", "agentless")
agent_id = alert_json.get("agent", {}).get("id", "N/A")

# Prepare Fields
fields = [
    {"name": "Agent", "value": f"`{agent_name} ({agent_id})`", "inline": True},
    {"name": "Level", "value": f"🚨 `{alert_level}`", "inline": True},
    {"name": "ID", "value": f"`{wazuh_id}`", "inline": True},
]

# Extract dynamic data fields
data_fields = alert_json.get("data", {})
useful_keys = ["dstuser", "srcip", "srcport", "status", "command"]
for key in useful_keys:
    if key in data_fields:
        fields.append({
            "name": key.capitalize(),
            "value": f"`{safe_truncate(data_fields[key], MAX_FIELD_VAL)}`",
            "inline": True
        })

# 2. Aggressively truncate Full Log
full_log = alert_json.get("full_log", "")
if full_log:
    # We use a smaller limit for full_log to keep total payload safe
    short_log = safe_truncate(full_log, 800) 
    fields.append({"name": "Full Log", "value": f"```msgpath\n{short_log}```", "inline": False})

# Build Payload
payload = {
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {alert_json.get('rule', {}).get('id', 'N/A')}",
            "color": color,
            "description": formatted_description,
            "fields": fields,
            "footer": {"text": f"Timestamp: {alert_json.get('timestamp', 'N/A')}"}
        }
    ]
}

# 3. Try sending the full alert
try:
    headers = {"content-type": "application/json"}
    r = requests.post(hook_url, data=json.dumps(payload), headers=headers)
    
    # 4. If it fails (likely due to size or format), send a fallback emergency alert
    if r.status_code != 204 and r.status_code != 200:
        fallback_payload = {
            "content": f"⚠️ **Alert size too large for Embed.**\n**Rule:** {rule_desc}\n**Level:** {alert_level}\n**Agent:** {agent_name}\n**ID:** {wazuh_id}"
        }
        requests.post(hook_url, data=json.dumps(fallback_payload), headers=headers)

except Exception as e:
    # Last resort: Print to stderr so it appears in Wazuh logs
    print(f"Error sending to Discord: {str(e)}", file=sys.stderr)

sys.exit(0)