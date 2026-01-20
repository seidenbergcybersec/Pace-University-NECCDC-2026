#!/bin/bash
#==============================
# 4) Anti-DoS/DDoS Measures
#==============================

#--- 4.1 Drop invalid packets ---
#     Invalid packets are often a sign of malicious or misconfigured traffic
iptables -A INPUT -m state --state INVALID -j DROP

#--- 4.2 Limit ICMP (ping) rate ---
#     Allow some pings but drop if the rate is too high
echo "[+] Limiting ICMP echo requests..."
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

#--- 4.3 TCP SYN flood protection (basic rate limiting) ---
#     Limit new TCP connections to a certain rate
echo "[+] Limiting incoming TCP SYN requests..."
iptables -A INPUT -p tcp --syn -m limit --limit 5/s --limit-burst 10 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP


echo "[+] Basic iptables anti-DDoS rules applied."
