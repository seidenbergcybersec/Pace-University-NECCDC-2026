#!/usr/bin/env bash
set -Eeuo pipefail

TELEPORT_SERVICE="teleport"
TELEPORT_CONFIG="/etc/teleport.yaml"
SSHD_CONFIG="/etc/ssh/sshd_config"
LOG_LINES=50

TARGET_HOST="${1:-}"
TARGET_PORT="${2:-443}"

print_section() {
  echo
  echo "=================================================="
  echo "$1"
  echo "=================================================="
}

print_ok() {
  echo "[OK] $1"
}

print_warn() {
  echo "[WARN] $1"
}

print_fail() {
  echo "[FAIL] $1"
}

get_ssh_service_name() {
  if systemctl list-unit-files | grep -q '^sshd\.service'; then
    echo "sshd"
  else
    echo "ssh"
  fi
}

SSH_SERVICE="$(get_ssh_service_name)"
TELEPORT_STATUS="FAIL"
SSH_STATUS="FAIL"
TELEPORT_CONFIG_STATUS="FAIL"
SSHD_SYNTAX_STATUS="FAIL"
CONNECTIVITY_STATUS="SKIPPED"

print_section "Host Info"
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "Date: $(date)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"

print_section "Network Info"
ip -brief address 2>/dev/null || ip addr
echo
ip route || true

print_section "Teleport Service Status"
if systemctl is-active --quiet "$TELEPORT_SERVICE"; then
  print_ok "Teleport is running"
  TELEPORT_STATUS="OK"
else
  print_fail "Teleport is NOT running"
fi
systemctl --no-pager --full status "$TELEPORT_SERVICE" || true

print_section "SSH Service Status"
if systemctl is-active --quiet "$SSH_SERVICE"; then
  print_ok "SSH ($SSH_SERVICE) is running"
  SSH_STATUS="OK"
else
  print_fail "SSH ($SSH_SERVICE) is NOT running"
fi
systemctl --no-pager --full status "$SSH_SERVICE" || true

print_section "Teleport Config"
if [[ -f "$TELEPORT_CONFIG" ]]; then
  print_ok "Found $TELEPORT_CONFIG"
  TELEPORT_CONFIG_STATUS="OK"
  ls -l "$TELEPORT_CONFIG"
else
  print_fail "Missing $TELEPORT_CONFIG"
fi

print_section "SSHD Config"
if [[ -f "$SSHD_CONFIG" ]]; then
  print_ok "Found $SSHD_CONFIG"

  for setting in PermitRootLogin PasswordAuthentication PubkeyAuthentication KbdInteractiveAuthentication UsePAM; do
    value="$(sshd -T 2>/dev/null | grep -i "^${setting,,} " || true)"
    if [[ -n "$value" ]]; then
      echo "$value"
    else
      print_warn "Could not determine effective value for $setting"
    fi
  done
else
  print_fail "Missing $SSHD_CONFIG"
fi

print_section "SSHD Syntax Check"
if command -v sshd >/dev/null 2>&1; then
  if sshd -t 2>/dev/null; then
    print_ok "sshd_config syntax is valid"
    SSHD_SYNTAX_STATUS="OK"
  else
    print_fail "sshd_config syntax is INVALID"
  fi
else
  print_warn "sshd command not found"
fi

print_section "Listening Ports"
ss -tulpn || true

print_section "Recent Teleport Logs"
journalctl -u "$TELEPORT_SERVICE" -n "$LOG_LINES" --no-pager || true

print_section "Recent SSH Logs"
journalctl -u "$SSH_SERVICE" -n "$LOG_LINES" --no-pager || true

print_section "Recent Logins"
who || true
echo
w || true
echo
if command -v last >/dev/null 2>&1; then
  last -n 10 || true
else
  print_warn "last command not found"
fi

print_section "Recent Failed Auth Events"
journalctl --since "2 hours ago" --no-pager 2>/dev/null | grep -Ei 'failed|failure|invalid user|authentication error|pam_unix|sshd' || true

if [[ -n "$TARGET_HOST" ]]; then
  print_section "Connectivity Test to ${TARGET_HOST}:${TARGET_PORT}"
  if command -v nc >/dev/null 2>&1; then
    if nc -zvw3 "$TARGET_HOST" "$TARGET_PORT"; then
      print_ok "TCP connection successful"
      CONNECTIVITY_STATUS="OK"
    else
      print_fail "TCP connection failed"
      CONNECTIVITY_STATUS="FAIL"
    fi
  else
    print_warn "nc not installed, trying /dev/tcp"
    if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${TARGET_HOST}/${TARGET_PORT}" 2>/dev/null; then
      print_ok "TCP connection successful"
      CONNECTIVITY_STATUS="OK"
    else
      print_fail "TCP connection failed"
      CONNECTIVITY_STATUS="FAIL"
    fi
  fi
fi

print_section "Summary"
echo "Teleport service:      $TELEPORT_STATUS"
echo "SSH service:           $SSH_STATUS"
echo "Teleport config:       $TELEPORT_CONFIG_STATUS"
echo "SSHD syntax:           $SSHD_SYNTAX_STATUS"
echo "Connectivity test:     $CONNECTIVITY_STATUS"
echo
echo "Health check complete."