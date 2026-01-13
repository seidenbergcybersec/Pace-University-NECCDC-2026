| Port | Service Name |
| :--- | :--- |
| **22** | **SSH** (Remote Linux management / Ansible / Teleport Node Join) |
| **53** | **DNS** (Active Directory / pfSense Resolver / Bind) |
| **67 / 68** | **DHCP** (IPv4 Address Assignment - pfSense) |
| **80** | **HTTP** (Nginx / WordPress / pfSense WebGUI / ACME Cert Renewal) |
| **88** | **Kerberos** (Active Directory Authentication) |
| **123** | **NTP** (Network Time Protocol - Critical for AD/Teleport synchronization) |
| **135** | **RPC Endpoint Mapper** (Active Directory / Windows Server management) |
| **137 / 138** | **NetBIOS** Name Service / Datagram (Legacy Windows Networking) |
| **139** | **NetBIOS** Session Service (Windows File Sharing) |
| **161 / 162** | **SNMP** (Network Monitoring / pfSense Status for Grafana) |
| **389** | **LDAP** (Active Directory Directory Services / Federation) |
| **443** | **HTTPS** (Web Traffic / Teleport Proxy / pfSense WebGUI) |
| **445** | **SMB / CIFS** (Windows File Server / Active Directory Group Policy) |
| **500 / 4500** | **IPsec VPN** (pfSense Site-to-Site Connectivity) |
| **514 / 6514** | **Syslog / Syslog-TLS** (Centralized Logging - Falco/pfSense to Log Server) |
| **546 / 547** | **DHCPv6** (IPv6 Client/Server Address Assignment) |
| **636** | **LDAPS** (Secure LDAP / Federation) |
| **1194** | **OpenVPN** (Remote Access VPN - pfSense) |
| **1433** | **MSSQL** (Microsoft SQL Server Database) |
| **2049** | **NFS** (Network File System - Linux File Server) |
| **2375 / 2376** | **Docker API** (Containerization management - Plain/TLS) |
| **3000** | **Grafana** (Monitoring Visualization Dashboard) |
| **3022** | **Teleport SSH** (Teleport internal SSH protocol) |
| **3023** | **Teleport Proxy** (Client SSH connections to Access Plane) |
| **3024** | **Teleport Reverse Tunnel** (Connecting nodes behind firewalls to Proxy) |
| **3025** | **Teleport Auth** (Teleport Auth Server API) |
| **3080** | **Teleport Web** (Web UI and Application Access) |
| **3100** | **Loki** (Log Aggregation utility for Grafana) |
| **3268 / 3269** | **Global Catalog** (AD Multi-domain forest searching / Secure GC) |
| **3306** | **MySQL / MariaDB** (WordPress Database) |
| **3389** | **RDP** (Windows Remote Desktop - Windows Workstation/Server) |
| **5060** | **Falco gRPC** (IDS output/event stream for Falco Sidekick) |
| **5432** | **PostgreSQL** (Database utility for various Linux applications) |
| **5985 / 5986** | **WinRM** (Ansible Windows Management - HTTP/HTTPS) |
| **6379** | **Redis** (Object Cache for WordPress/Performance utility) |
| **8080** | **Alternative HTTP** (Nginx upstream / Application testing) |
| **8765** | **Falco web server** built-in falco web server |
| **9000** | **PHP-FPM** (FastCGI utility for WordPress/Nginx processing) |
| **9090** | **Prometheus** (Monitoring Time-Series Database) |
| **9093** | **Alertmanager** (Utility for Prometheus alerts) |
| **9100** | **Node Exporter** (Prometheus utility for Linux hardware metrics) |
| **9182** | **Windows Exporter** (Prometheus utility for Windows Server metrics) |
| **51820** | **WireGuard VPN** (High-performance VPN - pfSense/Linux) |
| **ICMP** | **Ping** (Diagnostics - Essential for IPv6 Neighbor Discovery) |