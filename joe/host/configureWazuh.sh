echo "Customizing rule levels (SSH Login -> Level 13)..."


 overwrite="yes" overwrite="yes" overwrite="yes"



cat > /var/ossec/etc/rules/local_rules.xml <<EOF
<!--

vsftpd rules

-->

<group name="syslog,vsftpd,">
  <rule id="11401" level="13" overwrite="yes">
    <if_sid>11400</if_sid>
    <match>CONNECT: Client</match>
    <group>connection_attempt,</group>
    <description>vsftpd: FTP session opened.</description>
  </rule>

  <rule id="11402" level="13" overwrite="yes">
    <if_sid>11400</if_sid>
    <match>OK LOGIN: </match>
    <description>vsftpd: FTP Authentication success.</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,pci_dss_10.2.5,gpg13_7.1,gpg13_7.2,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="11404" level="13" overwrite="yes">
    <if_sid>11400</if_sid>
    <match>OK UPLOAD: </match>
    <description>vsftpd: FTP server file upload.</description>
  </rule>

  <rule id="11451" level="13" frequency="8" timeframe="120" overwrite="yes">
    <if_matched_sid>11403</if_matched_sid>
    <same_source_ip />
    <description>vsftpd: FTP brute force (multiple failed logins).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_11.4,gpg13_7.1,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SI.4,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
</group>
EOF


cat >> /var/ossec/etc/rules/local_rules.xml <<EOF
<!--

mysql rules

-->

<group name="mysql_log,">
  <rule id="50106" level="13" overwrite="yes">
    <if_sid>50100</if_sid>
    <match>Access denied for user</match>
    <description>MySQL: authentication failure.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_8.7,gpg13_7.1,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,hipaa_164.312.d,hipaa_164.312.e.1,hipaa_164.312.e.2.I,hipaa_164.312.e.2.II,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_SC.2,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,tsc_PI1.4,tsc_PI1.5,</group>
  </rule>

  <rule id="50120" level="13" overwrite="yes">
    <if_sid>50100</if_sid>
    <match>mysqld ended|Shutdown complete</match>
    <description>MySQL: shutdown message.</description>
    <mitre>
      <id>T1529</id>
    </mitre>
    <group>service_availability,pci_dss_10.6.1,gpg13_4.14,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="50121" level="13" overwrite="yes">
    <if_sid>50100</if_sid>
    <match>mysqld started|mysqld restarted</match>
    <description>MySQL: startup message.</description>
    <group>service_availability,gpg13_4.14,</group>
  </rule>

  <rule id="50125" level="13" overwrite="yes">
    <if_sid>50100</if_sid>
    <regex>^MySQL log: \d+ \S+ \d+ [ERROR]</regex>
    <description>MySQL: error.</description>
    <group>gpg13_4.3,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="50126" level="13" overwrite="yes">
    <if_sid>50125</if_sid>
    <match>Fatal error:</match>
    <description>MySQL: fatal error.</description>
    <mitre>
      <id>T1499</id>
    </mitre>
    <group>service_availability,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="50181" level="13" overwrite="yes">
    <if_sid>50100</if_sid>
    <regex>^MySQL log: \d+-\d+-\d+T\d+:\d+:\d+.\d+\.+ \d+ [ERROR]</regex>
    <description>MySQL: error.</description>
    <group>gpg13_4.3,gdpr_IV_35.7.d,</group>
  </rule>

  <rule id="50182" level="13" overwrite="yes">
    <if_sid>50181</if_sid>
    <match>Fatal error:</match>
    <description>MySQL: fatal error.</description>
    <mitre>
      <id>T1499</id>
    </mitre>
    <group>service_availability,pci_dss_10.6.1,gpg13_4.1,gdpr_IV_35.7.d,hipaa_164.312.b,nist_800_53_AU.6,</group>
  </rule>
</group>


EOF

cat >> /var/ossec/etc/rules/local_rules.xml <<EOF
<!--

nginx rules

-->
<group name="nginx,web,">
  <rule id="31310" level="13" overwrite="yes">
    <if_sid>31301</if_sid>
    <match>failed (2: No such file or directory)|is not found (2: No such file or directory)</match>
    <description>Nginx: Server returned 404 (reported in the access.log).</description>
  </rule>

    
  <!-- Detects common OS commands in the URI -->
  <rule id="100001" level="13">
    <if_sid>31100</if_sid> <!-- Assuming 31100 is your nginx-accesslog base rule -->
    <match>whoami|/etc/passwd|/etc/shadow|id|/bin/sh|/bin/bash|system\(|exec\(|passthru\(</match>
    <description>Webshell command execution attempt detected in URI</description>
    <mitre>
      <id>T1505.003</id> <!-- Mitre: Webshell -->
      <id>T1059</id>     <!-- Mitre: Command and Scripting Interpreter -->
    </mitre>
    <group>web_attack,cmd_execution,</group>
  </rule>

  <!-- Detects common webshell filenames -->
  <rule id="100002" level="13">
    <if_sid>31100</if_sid>
    <match>shell.php|cmd.php|ws.php|c99.php|r57.php|b374k.php|tunnel.php|weevely.php</match>
    <description>Access to known webshell filename detected</description>
    <mitre>
      <id>T1505.003</id>
    </mitre>
  </rule>

  <rule id="100003" level="13" frequency="15" timeframe="60">
    <if_matched_sid>31310</if_matched_sid> <!-- Uses the 404 rule from your snippet -->
    <same_source_ip />
    <description>Multiple 404 errors from same source: Possible directory fuzzing for webshells</description>
    <mitre>
      <id>T1595</id> <!-- Mitre: Active Scanning -->
    </mitre>
    <group>reconnaissance,</group>
  </rule>

  <rule id="100004" level="13">
    <if_sid>31100</if_sid>
    <match>nc%20-e|/dev/tcp/|python%20-c|perl%20-e|bash%20-i</match>
    <description>Reverse shell execution attempt via web request</description>
    <mitre>
      <id>T1059</id>
    </mitre>
  </rule>

</group>
EOF


cat >> /var/ossec/etc/rules/local_rules.xml <<EOF
<!--

ssh rules

-->

<group name="syslog,sshd,">

  <rule id="5710" level="13" overwrite="yes">
    <if_sid>5700</if_sid>
    <match>illegal user|invalid user</match>
    <description>sshd: Attempt to login using a non-existent user</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5712" level="13" frequency="8" timeframe="120" ignore="60" overwrite="yes">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>sshd: brute force trying to get access to the system. Non existent user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_SI.4,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_11.4,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5715" level="14" overwrite="yes">
    <if_sid>5700</if_sid>
    <match>^Accepted|authenticated.$</match>
    <description>sshd: authentication success.</description>
    <mitre>
      <id>T1078</id>
      <id>T1021</id>
    </mitre>
    <group>authentication_success,gdpr_IV_32.2,gpg13_7.1,gpg13_7.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.5,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5716" level="13" overwrite="yes">
    <if_sid>5700</if_sid>
    <match>^Failed|^error: PAM: Authentication</match>
    <description>sshd: authentication failed.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5718" level="13" overwrite="yes">
    <if_sid>5700</if_sid>
    <match>not allowed because</match>
    <description>sshd: Attempt to login using a denied user.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,invalid_login,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5727" level="13" overwrite="yes">
    <if_sid>5700</if_sid>
    <match>failed: Address already in use.</match>
    <description>sshd: Attempt to start sshd when something already bound to the port.</description>
    <group>gdpr_IV_35.7.d,gpg13_4.3,hipaa_164.312.b,nist_800_53_AU.6,nist_800_53_CM.1,pci_dss_10.6.1,pci_dss_2.2.3,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="5758" level="13" overwrite="yes">
    <if_sid>5700,5710</if_sid>
    <match>^error: maximum authentication attempts exceeded </match>
    <description>Maximum authentication attempts exceeded.</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failed,gpg13_7.1,</group>
  </rule>

  <rule id="5760" level="13" overwrite="yes">
    <if_sid>5700,5716</if_sid>
    <match>Failed password|Failed keyboard|authentication error</match>
    <description>sshd: authentication failed.</description>
    <mitre>
      <id>T1110.001</id>
      <id>T1021.004</id>
    </mitre>
    <group>authentication_failed,gdpr_IV_35.7.d,gdpr_IV_32.2,gpg13_7.1,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_10.2.5,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

</group>

EOF

# Fix permissions for the rules file
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
chmod 660 /var/ossec/etc/rules/local_rules.xml

echo "Restarting Wazuh Manager to apply rule changes..."
systemctl restart wazuh-manager