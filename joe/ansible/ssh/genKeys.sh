#!/bin/sh

# 1. Get the absolute path of the directory where this script is located
# We use cd and pwd to ensure we get the full path regardless of how the script was invoked
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# 2. Define the target path for the private key
TARGET_FILE="$SCRIPT_DIR/id_rsa"

# 3. Check if the key already exists to prevent accidental overwriting
if [ -f "$TARGET_FILE" ]; then
    printf "Error: %s already exists. Aborting to prevent overwrite.\n" "$TARGET_FILE"
    exit 1
fi

# 4. Generate the RSA key pair
# -t rsa: Key type
# -b 4096: Bit length
# -f: Output file path
# -N "": Set an empty passphrase (standard for "default" automated keys)
ssh-keygen -t rsa -b 4096 -f "$TARGET_FILE" -N ""

# 5. Confirm completion
if [ $? -eq 0 ]; then
    printf "Successfully generated keys in: %s\n" "$SCRIPT_DIR"
    printf "Private key: %s\n" "$TARGET_FILE"
    printf "Public key:  %s.pub\n" "$TARGET_FILE"
else
    printf "An error occurred during key generation.\n"
    exit 1
fi