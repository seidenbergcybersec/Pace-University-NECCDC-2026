First run:
`host/NormalizeHost.sh` - going to install basic libs and tools needed like nmap, curl.

Then someone runs the scanner. Someone else is opening firewall with the firewall person and looking at the arp/ndp tables to find ips.

After getting ips either way, find teleport(usually url given in creds) and find its version:
`curl -k https://teleport.15.chefops.tech:3080/webapi/find | jq '.server_version'`

Install TSH on your local box:
```bash
cd joe/host/
./InstallTsh.sh
```

Then login to the cluster:
`tsh login --user=admin --proxy=teleport.15.chefops.tech --insecure`


# Securing Teleport

Run:
```bash
cd hardening/teleport/
./teleport_harden.sh
```

Make sure that auth address inside the script is correct.
Open `teleport_creds.txt`, follow the link and setup new account's password.
From new account delete roles of previous account and give it "no-access" role. 
Also lock the default account:
`tctl lock --user="admin" --message="Under investigation. Please contant security team immediately" --auth-server="$AUTH_ADDR"`

Relogin to tsh:
```bash
tsh logout
tsh login --user=pace --proxy=teleport.15.chefops.tech --insecure
```

As a result:
All roles were removed from all accounts except for newly created "pace".
All accounts were locked permanently with a polite message, preventing any login and terminating any current sessions.

# Ansible Preparation:

Dump teleport ssh config to a file for ansible:

```bash
cd ansible/
tsh config > teleport_config
```

List all ssh nodes:
`tsh ls`

Use exactly these node names in ansible inventory.ini file like that:
`ansible_node_name ansible_host=teleport_node_name.teleport ansible_user=root`

# User level harden

When the inventory.ini is populated with teleport nodes' names(or ips), run these commands:

Generate a secure password:
```bash
cd /passwordGen
./gen.sh
```

Generate an ssh keypair:
```bash
cd ansible/ssh
./genKeys.sh
```

Run the user hardening script:
```bash
cd ansible/
ansible-playbook playbooks/fix_users.yml -e "target=some_target root_pass=NewRoot123 admin_pass=NewAdmin123 pubkey='$(cat ssh/id_rsa.pub)'"
```

Lock old account(using teleport access or direct ssh using the new account)
```bash
sudo usermod -L admin
sudo usermod -s /sbin/nologin debian
```

If ansible fails cause of old python verision, install new one via Teleport
```bash
sudo apt-get install python3.11 -y # debian
sudo yum install python311 -y # rhel
zypper install python311 # suse
```

MAKE SURE to read through the ssh config and make sure that nothing overrides it. If any additional configs are included(`Include ...`) check them too.
Also run this command and ensure that only pace is allowed:
`sshd -T | grep -i "allowusers"`


# Service level harden

This service hardening will 
* search for leaked configs on wordpress.
* harden vsftpd config and enable logs.
* rebind mariadb to localhost only.

```bash
ansible-playbook playbooks/script_run.yml -e "script=../../hardening/specific_hardening.sh root=true"
```

# Falco alert hardening

```bash
ansible-playbook playbooks/script_run.yml -e "script=../../hardening/alerting/falco.sh root=true"
```

# Basic hardening (optional)

This basic hardening will
* configure php
* Restrict running compilers and shells for web users via ACLs
* enforce strict permissions on /etc/passwd,shadow and others.

```bash
ansible-playbook playbooks/script_run.yml -e "script=../../hardening/basic_hardening.sh root=true"
```

# Crystal hammer deployment

This section requires you to already have generated ssh keys in your ansible folder as well as an account available on remote machine with natural ssh access

Create ssh keys:
```bash
cd crystal_hammer/
cp ../ansible/ssh/id_rsa ./client
cp ../ansible/ssh/id_rsa.pub ./server
```

Compile both server and client:

```bash
cd crystal_hammer
./compile.sh
```

Deploy to remote server:

```bash
cd crystal_hammer
./deploy.sh
```

if the binary is not running due to firewall missing, install one:
```bash
sudo apt update && sudo apt install ufw # debian
sudo dnf install epel-release -y && sudo dnf install ufw # rocky
sudo zypper install ufw # suse
```


# Recon

Recon should be performed after initial secural of all critical servers.

## Light recon(for inventory inject)

This will collect light information about core services and OS:
* os info
* network info - mac, ip
* docker containers
* core services running and their versions

```bash
cd ansible
ansible-playbook playbooks/light_recon.yml -e "target=some_target"
```

The resulting file will be in `ansible/results/target/system_inventory_*`


## Inventory map

Run python script `python3 diagram.py --auto` (--auto means that it will traverse the ansible folder and search for results of light_recon script execution). This will generate a `competition_network.drawio` file. 
Open [diagrams.net](https://app.diagrams.net/) and select File -> Import From -> Device and select the file generated.
Manually review the network map and reorder/rename boxes/subnets if needed. Use template_subnet to copy paste boxes or subnets if you will need more.


## Heavy recon and backups

This will:
* Indentify system OS
* Domain controller connection if any
* Network interfaces, routes, dns, open ports.
* Enumare running services. Filter for critical.
* collect docker configs.
* extract all configs in /etc/
* audit sudo users.
* collect info on autoruns
* teleport current nodes and other info.
* DB backups
* firewall configs backup

```bash
ansible-playbook playbooks/run_recon.yml -e "target=some_target"
```

Resulting achive will be in ansible/results/target/

# Wazuh

Install wazuh on host by running:
```bash
cd host
./wazuh.sh
```