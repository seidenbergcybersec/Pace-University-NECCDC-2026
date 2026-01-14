# NECCDC Blue Team Linux Operations Repository

This repository contains tools, scripts, and Ansible playbooks designed for rapid hardening, reconnaissance, and monitoring during the NECCDC competition. The codebase is optimized for diverse Linux distributions including Debian/Ubuntu, RHEL/CentOS, and Alpine.

## Prerequisites

* Ansible (installed on the control node)
* Python 3.x
* SSH access to target machines
* Sudo privileges on all targets

## Infrastructure Configuration

The repository is configured via the `ansible/` directory:
* **ansible.cfg**: Sets default inventory to `inventory.ini` and disables SSH host key checking for speed.
* **inventory.ini**: Defines target hosts (pfsense, grafana, teleport, wordpress, kiosk). Update the `ansible_user` and `ansible_ssh_pass` here before starting.

---

## Ansible Playbooks

### 1. IAM Hardening (fix_users.yml)
Performs initial environment lockdown. It creates a management user, updates root passwords, locks non-essential accounts, and enforces key-based SSH authentication.

* **Arguments**:
    * `root_pass`: (Required) The new password for the root account.
    * `admin_pass`: (Required) The password for the new admin user.
    * `pubkey`: (Required) The SSH public key string to be authorized for the admin user.
    * `target`: (Optional) Target group (default: `my_servers`).
* **Usage**:
```bash
ansible-playbook ansible/playbooks/fix_users.yml -e "root_pass=NewRoot123 admin_pass=NewAdmin123 pubkey='$(cat ansible/ssh/id_rsa.pub)'"
```

### 2. Fast Recon and Exfiltration (run_recon.yml)
Executes the POSIX inventory script on targets, compresses the gathered data, and downloads the resulting archive to the local machine for analysis.

* **Variables (configured in vars/settings.yml)**:
    * `remote_recon_script`: Path to the recon script.
    * `source_folder`: Directory where results are staged on the remote host.
    * `local_results_path`: Directory on the control node where archives are stored.
* **Usage**:
```bash
ansible-playbook ansible/playbooks/run_recon.yml
```

### 3. General Script Execution (script_run.yml)
A generic wrapper to push and execute any local script or binary to remote hosts.

* **Arguments**:
    * `script`: (Required) Local path to the script/binary.
    * `script_args`: (Optional) Arguments to pass to the script.
    * `root`: (Optional) Set to `true` to run with sudo (default: `false`).
    * `target`: (Optional) Target group (default: `my_servers`).
* **Usage**:
```bash
ansible-playbook ansible/playbooks/script_run.yml -e "script=./tools/normalize.sh root=true"
```

### 4. Wazuh Agent Deployment (wazuh_agent.yml)
Automates the installation of the Wazuh agent across different OS families.

* **Arguments**:
    * `wazuh_manager_ip`: (Required) The IP address of the Wazuh Manager server.
    * `wazuh_version`: (Optional) Specific version to install (default: 4.14.1-1).
* **Usage**:
```bash
ansible-playbook ansible/playbooks/wazuh_agent.yml -e "wazuh_manager_ip=10.0.10.50"
```

---

## Core Defensive and Recon Scripts

### System Hardening (hardening/02_hardening.sh)
Removes SUID from pkexec, fixes critical file permissions, applies ACLs to web server users, and hardens `php.ini` with WordPress compatibility checks.

* **Local Execution**:
```bash
sudo ./hardening/02_hardening.sh
```
* **Ansible Execution**:
```bash
ansible-playbook ansible/playbooks/script_run.yml -e "script=./hardening/02_hardening.sh root=true"
```

### POSIX Inventory (recon/posixInventory.sh)
A distribution-agnostic script for gathering system state, networking, firewall rules, running services, persistence, and database configurations.

* **Local Execution**:
```bash
sudo ./recon/posixInventory.sh
```
* **Ansible Execution**:
```bash
ansible-playbook ansible/playbooks/script_run.yml -e "script=./recon/posixInventory.sh root=true"
```
*Note: Using `run_recon.yml` is preferred as it automatically downloads the results.*

### Environment Normalization (tools/normalize.sh)
Ensures essential tools (`jq`, `net-tools`, `vim`, `iptables`, `curl`) are installed on all systems regardless of the package manager.

* **Local Execution**:
```bash
sudo ./tools/normalize.sh
```
* **Ansible Execution**:
```bash
ansible-playbook ansible/playbooks/script_run.yml -e "script=./tools/normalize.sh root=true"
```

### Immutable Attribute Removal (tools/unmute.sh)
Recursively removes the `+i` (immutable) flag from files and directories to clean up Red Team persistence.

* **Local Execution**:
```bash
sudo ./tools/unmute.sh /var/www/html
```
* **Ansible Execution**:
```bash
ansible-playbook ansible/playbooks/script_run.yml -e "script=./tools/unmute.sh script_args=/var/www/html root=true"
```

---

## Network Scanning and Discovery

### RustScan Wrapper (scanning/scanning.py)
High-speed port discovery using RustScan. Automatically saves results to JSON.

* **Usage**:
```bash
python3 scanning/scanning.py -a 10.0.10.0/24 --batch-size 5000
```

### Nmap Detail Scanner (scanning/nmap_service_scanner.py)
Processes the JSON output from `scanning.py` to perform deep service versioning and script scanning.

* **Usage**:
```bash
python3 scanning/nmap_service_scanner.py scanning/scanResults/rust_results_example.json
```

---

## Utility Tools
* **Password Hashing**: Use `hardening/hash_password.py` or `hardening/hash_password.sh` to generate SHA-512 hashes for the `fix_users.yml` playbook variables.
* **Key Generation**: Use `ansible/ssh/genKeys.sh` to create the SSH key pair used by the management account.
* **Port Reference**: Refer to `CommonPorts.md` for a comprehensive list of services and their expected ports in the competition environment.