#!/bin/bash

# Set the desired version
VERSION="18.7.1"
FILENAME="teleport-v${VERSION}-linux-amd64-bin.tar.gz"
URL="https://cdn.teleport.dev/${FILENAME}"

echo "Starting Teleport v${VERSION} installation..."

# 1. Download the archive
echo "Downloading ${URL}..."
curl -O "$URL"

# Check if the download succeeded
if [ $? -ne 0 ]; then
    echo "Error: Failed to download Teleport. Please check the version number or your connection."
    exit 1
fi

# 2. Extract the files
echo "Extracting files..."
tar -xzf "$FILENAME"

# 3. Run the installer
echo "Running installer..."
cd teleport
sudo ./install

# 4. Cleanup (Optional but recommended)
echo "Cleaning up installation files..."
cd ..
rm -rf teleport "$FILENAME"

echo "Installation complete! You can check the version by running: teleport version"