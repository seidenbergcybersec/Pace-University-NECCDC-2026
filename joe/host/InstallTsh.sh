#!/bin/bash

# Set the default version
DEFAULT_VERSION="18.7.1"

# Prompt the user for version
# -p: display prompt string
read -p "Enter Teleport version [default: $DEFAULT_VERSION]: " USER_VERSION

# If USER_VERSION is empty, use DEFAULT_VERSION
VERSION=${USER_VERSION:-$DEFAULT_VERSION}

FILENAME="teleport-v${VERSION}-linux-amd64-bin.tar.gz"
URL="https://cdn.teleport.dev/${FILENAME}"

echo "Starting Teleport v${VERSION} installation..."

# 1. Download the archive
echo "Downloading ${URL}..."
# Added -f to curl to fail if the URL is 404
curl -f -L -O "$URL"

# Check if the download succeeded
if [ $? -ne 0 ]; then
    echo "Error: Failed to download Teleport v${VERSION}. The version might not exist."
    exit 1
fi

# 2. Extract the files
echo "Extracting files..."
tar -xzf "$FILENAME"

# 3. Run the installer
echo "Running installer..."
cd teleport
sudo ./install

# 4. Cleanup
echo "Cleaning up installation files..."
cd ..
rm -rf teleport "$FILENAME"

echo "---------------------------------------"
echo "Installation complete!"
teleport version
tsh version