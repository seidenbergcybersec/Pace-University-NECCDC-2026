#!/bin/bash

cat <<EOF >> /etc/falco/falco_rules.local.yaml

- rule: New Listening Port
  desc: Detects when a process starts listening on a new port
  condition: >
    evt.type=bind and fd.port != 0 and 
    not proc.name in (alloy, falco, teleport, sshd)
  output: "New port listening (user=%user.name command=%proc.cmdline port=%fd.port)"
  priority: CRITICAL

- rule: Native SSH Login
  desc: Detects native SSH usage
  condition: >
    evt.type=accept and fd.port=22 and proc.name=sshd
  output: "Native SSH Connection detected (user=%user.name remote_ip=%fd.cip)"
  priority: CRITICAL

- rule: VSFTPD File Upload
  desc: Detects file writes in the ftp directory
  condition: >
    open_write and directory_traversal and proc.name=vsftpd
  output: "File uploaded via VSFTPD (user=%user.name file=%fd.name)"
  priority: CRITICAL
EOF

# Hot reload Falco
kill -1 $(pidof falco)


echo "Now run\nsudo systemctl status falco"