#!/usr/bin/env bash
#
# backup_docker_and_scp.sh
#
# Description:
#   1. Gathers Docker information (running containers, images, configs).
#   2. Saves Docker images to a tar archive.
#   3. Packages logs, docker info, and the image tar together.
#   4. Uses scp to transfer the archive from this VM to a specified host.

# -------------- CONFIGURABLE VARIABLES --------------

# Change to your VM’s username, IP, and target user/host as needed
REMOTE_USER="your_vm_username"
VM_IP="1.2.3.4"  # If needed, e.g. for referencing or multi-hop logic
HOST_USER="your_host_username"
HOST_IP="192.168.0.10"
HOST_DEST_DIR="/path/on/your/host"

# Name of the archive we create locally
BACKUP_ARCHIVE="docker_backup_$(date +%Y%m%d_%H%M%S).tar.gz"

# -------------- STEP 1: GATHER DOCKER INFORMATION --------------

echo "[+] Gathering Docker info..."
# Create a working directory (in /tmp or wherever you prefer)
WORK_DIR="/tmp/docker_backup"
mkdir -p "${WORK_DIR}"

# 1A. List running containers
docker ps > "${WORK_DIR}/docker_ps.txt"

# 1B. List images
docker images > "${WORK_DIR}/docker_images.txt"

# 1C. (Optional) Inspect each container for deeper info
for CID in $(docker ps -q); do
  docker inspect "${CID}" > "${WORK_DIR}/inspect_${CID}.json"
done

# -------------- STEP 2: SAVE DOCKER IMAGES --------------

echo "[+] Saving Docker images to a tarball..."
IMAGES_TAR="${WORK_DIR}/docker_images.tar"
# Capture all in-use images
docker save -o "${IMAGES_TAR}" $(docker images --format '{{.Repository}}:{{.Tag}}')

# -------------- STEP 3: PACKAGE THE DATA --------------

echo "[+] Creating final archive..."
tar -czf "${BACKUP_ARCHIVE}" -C "${WORK_DIR}" .

# -------------- STEP 4: SCP THE ARCHIVE TO HOST --------------

echo "[+] Transferring the archive to the host via SCP..."
# This scp command is typically run from the VM to the host.
# If you’re running this script on the VM, do the following:
scp "${BACKUP_ARCHIVE}" "${HOST_USER}@${HOST_IP}:${HOST_DEST_DIR}"

# Alternatively, if running from your host and pulling from the VM:
# scp "${REMOTE_USER}@${VM_IP}:/path/to/${BACKUP_ARCHIVE}" "${HOST_DEST_DIR}"

# -------------- CLEANUP (Optional) --------------

# Uncomment if you want to remove temporary files after transfer
# rm -rf "${WORK_DIR}"
# rm -f "${BACKUP_ARCHIVE}"

echo "[+] Done! Archive ${BACKUP_ARCHIVE} copied to ${HOST_USER}@${HOST_IP}:${HOST_DEST_DIR}"