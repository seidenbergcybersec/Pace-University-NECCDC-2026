#!/bin/bash

# --- CONSTANTS ---
# Address of your auth service(can be found in teleport config on admin box)
AUTH_ADDR="teleport.15.chefops.tech:3080"
NEW_ADMIN_USER="pace"
BACKUP_FILE="teleport_dump_$(date +%s).yaml"
# Standard admin roles. Ensure these exist in your cluster.
ADMIN_ROLES="access,editor,auditor" 
SETUP_LINK_FILE="teleport_creds.txt"

set -e

# 1. Verify tsh session
if ! tsh status &> /dev/null; then
    echo "Error: No active tsh session. Please run: tsh login --proxy=$AUTH_ADDR"
    exit 1
fi

# Get current user name to avoid locking yourself out
CURRENT_USER=$(tsh status | grep "Logged in as" | awk '{print $4}')

echo "--- 1. Backing up users and roles ---"
tctl get users,roles --auth-server="$AUTH_ADDR" > "$BACKUP_FILE"
echo "Backup saved to $BACKUP_FILE"

# Users in Teleport must have at least one role. We create one with zero access.
echo "Creating restricted 'no-access' role..."
cat <<EOF | tctl create -f --auth-server="$AUTH_ADDR"
kind: role
version: v5
metadata:
  name: no-access
spec:
  allow: {}
  deny: {}
EOF

echo "--- 2. Creating Emergency Admin ---"
# This creates the user and saves the setup link
tctl users add "$NEW_ADMIN_USER" --roles="$ADMIN_ROLES" --logins="root,pace" --auth-server="$AUTH_ADDR" > "$SETUP_LINK_FILE"
echo "Emergency link saved to $SETUP_LINK_FILE"

echo "--- 3. Neutering other accounts (Removing Roles) ---"
# Get all users, excluding the new admin and yourself
# If you don't have jq, use: tctl get users --format=text --auth-server="$AUTH_ADDR" | tail -n +3
ALL_USERS=$(tctl get users --format=json --auth-server="$AUTH_ADDR" | jq -r '.[].metadata.name')

for user in $ALL_USERS; do
    if [[ "$user" == "$CURRENT_USER" || "$user" == "$NEW_ADMIN_USER" ]]; then
        echo "Skipping protected user: $user"
        continue
    fi
    
    echo "Neutering user: $user"
    # Overwrite their roles with the restricted role
    tctl users update "$user" --set-roles=no-access --auth-server="$AUTH_ADDR"

    # B. Lock the account (Session termination & Login prevention)
    tctl lock --user="$user" --message="Under investigation. Please contant security team immediately" --auth-server="$AUTH_ADDR"
done

echo "Done! Backup: $BACKUP_FILE | New user link: $SETUP_LINK_FILE"