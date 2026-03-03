#!/bin/bash

# --- CONFIGURATION ---
TARGET_USER="pace"
PASSWORD="PACEPACEPACE"
PUB_KEY="ssh-rsa AAAAB3Nza...[your_key_here]...user@host"
# ---------------------

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)."
  exit 1
fi

echo "Starting user setup for: $TARGET_USER"

# 1. Determine the Sudo/Wheel group
# Debian/Ubuntu usually use 'sudo', RHEL/Rocky/Suse usually use 'wheel'
if getent group sudo >/dev/null; then
    SUDO_GROUP="sudo"
elif getent group wheel >/dev/null; then
    SUDO_GROUP="wheel"
else
    # Fallback/Create group if neither exists
    SUDO_GROUP="sudo"
    groupadd -f "$SUDO_GROUP"
fi

# 2. Create or Update User
if id "$TARGET_USER" &>/dev/null; then
    echo "User $TARGET_USER already exists. Updating settings..."
    # Ensure the user has a home directory
    mkhomedir_helper "$TARGET_USER" 2>/dev/null || true
else
    echo "Creating user $TARGET_USER..."
    useradd -m -s /bin/bash "$TARGET_USER"
fi

# 3. Set Password
echo "$TARGET_USER:$PASSWORD" | chpasswd

# 4. Grant Passwordless Sudo
# We use a separate file in /etc/sudoers.d/ for clean management
SUDOERS_FILE="/etc/sudoers.d/90-$TARGET_USER"
echo "$TARGET_USER ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE"

# Add user to the appropriate group just in case
usermod -aG "$SUDO_GROUP" "$TARGET_USER"

# 5. Set up SSH Directory
USER_HOME=$(eval echo "~$TARGET_USER")
SSH_DIR="$USER_HOME/.ssh"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"

# 6. Make Public Key Exclusive
# By using > instead of >>, we overwrite existing keys
echo "$PUB_KEY" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown -R "$TARGET_USER:$TARGET_USER" "$SSH_DIR"

echo "Setup complete."
echo "User: $TARGET_USER"
echo "Sudo access: Enabled (Passwordless)"
echo "SSH Key: Set to exclusive"