#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Change directory to where the script is located
cd "$(dirname "${BASH_SOURCE[0]}")"

# Now you can safely run commands relative to the script's location
echo "Script is running from: $(pwd)"

echo "--- Starting Build Process ---"

# 1. Install Go and build dependencies
echo "[1/5] Checking/Installing Go..."
if ! command -v go &> /dev/null; then
    sudo apt update
    sudo apt install -y golang-go build-essential
else
    echo "Go is already installed: $(go version)"
fi

# 2. Validate Server RSA Key
echo "[2/5] Validating server/id_rsa.pub..."
PUB_KEY_PATH="./server/id_rsa.pub"
SERVER_GO_PATH="./server/server.go"

if [ ! -f "$PUB_KEY_PATH" ]; then
    echo "ERROR: $PUB_KEY_PATH not found! Halting process."
    exit 1
fi

# Read the public key content
RAW_PUB_KEY=$(cat "$PUB_KEY_PATH")
echo "Public key found."

# 3. Inject Public Key into server.go
echo "[3/5] Injecting Public Key into server.go..."

# We use sed with a pipe '|' delimiter because RSA keys contain forward slashes '/'
# This looks for the line containing the MARKING tag and replaces the whole line
# The use of double quotes allows variable expansion
sed -i "s|var encodedPubKey = .* // <<<MARKING>>>|var encodedPubKey = \"$RAW_PUB_KEY\" // <<<MARKING>>>|g" "$SERVER_GO_PATH"

echo "Injection successful."

# 4. Compile Server (Static)
echo "[4/5] Compiling Server (Static)..."
cd server
go mod download
# CGO_ENABLED=0 ensures a static binary without dynamic linking to libc
# -ldflags: -s (omit symbol table), -w (omit DWARF info), -extldflags "-static" (force static)
CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" -o server_static server.go
cd ..

# 5. Compile Client (Static)
echo "[5/5] Compiling Client (Static)..."
cd client
go mod download
CGO_ENABLED=0 go build -ldflags "-s -w -extldflags '-static'" -o client_static client.go
cd ..

echo "--- Process Complete ---"
echo "Binaries created:"
echo " - ./server/server_static"
echo " - ./client/client_static"