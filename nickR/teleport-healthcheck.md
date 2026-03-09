# teleport-healthcheck.sh

## Purpose
teleport-healthcheck.sh is a diagnostic script used to quickly inspect the health of a Linux system that is expected to run Teleport and SSH services. It is designed to rapidly verify system state after logging into a host.

## Features
The script checks:
Host Info
Network Info
Teleport Service Status
SSH Service Status
Teleport Configuration Presence
SSH Configuration Settings
SSH Configuration Syntax Validation
Listening Network Ports
Recent Teleport Logs
Recent SSH Logs
Recent Logins
Authentication Failures
Optional Connectivity Test to a Remote Host

## Usage
Basic usage:
sudo ./teleport-healthcheck.sh

Connectivity test:
sudo ./teleport-healthcheck.sh <host> <port>

Example:
sudo ./teleport-healthcheck.sh google.com 443

## Example Output
The script outputs multiple sections including:
Host Info
Network Info
Teleport Service Status
SSH Service Status
SSHD Config
Listening Ports
Recent Logs
Summary

Example summary:
Teleport service: FAIL
SSH service: OK
Teleport config: FAIL
SSHD syntax: OK
Connectivity test: OK

## Requirements
Linux system with systemd
SSH installed
journalctl available

Optional tools:
nc (netcat)

## Notes
The script does not modify system configuration. It is intended for inspection and troubleshooting only.