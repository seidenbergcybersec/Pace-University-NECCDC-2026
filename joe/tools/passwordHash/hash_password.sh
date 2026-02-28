#!/usr/bin/env bash

# Prompt for password (silent)
read -s -p "Enter password: " PASSWORD
echo

# Optional: prompt for salt, or hardcode it
SALT="mysecretsalt"

# Generate sha512 hash using Ansible's password_hash filter
ansible all -i localhost, -m debug -a \
  "msg={{ password | password_hash('sha512', salt) }}" \
  -e "password=${PASSWORD} salt=${SALT}"
