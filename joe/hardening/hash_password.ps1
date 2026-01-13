#!/usr/bin/env pwsh

# Prompt for password (secure input)
$SecurePassword = Read-Host "Enter password" -AsSecureString

# Convert SecureString to plain text (required to pass to Ansible)
$Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr)

# Optional: prompt for salt or hardcode it
$Salt = "mysecretsalt"

# Generate sha512 hash using Ansible's password_hash filter
ansible all -i localhost, -m debug -a `
  "msg={{ password | password_hash('sha512', salt) }}" `
  -e "password=$Password salt=$Salt"
