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


<group name="teleport,">
  <!-- Base rule to match any Teleport log -->
  <rule id="100100" level="0">
    <decoded_as>teleport</decoded_as>
    <description>Teleport event accumulated.</description>
  </rule>

  <!-- ############################################ -->
  <!-- AUTHENTICATION & ACCESS RULES                -->
  <!-- ############################################ -->

  <!-- T1000I: Local Login Success -->
  <rule id="100101" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1000I</field>
    <description>Teleport: User $(dstuser) logged in locally.</description>
  </rule>

  <!-- T1000W: Local Login Failed -->
  <rule id="100102" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1000W</field>
    <description>Teleport: Local authentication failure for user $(dstuser). Reason: $(error)</description>
  </rule>

  <!-- T1001I: SSO Login Success -->
  <rule id="100103" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1001I</field>
    <description>Teleport: User $(dstuser) logged in via SSO.</description>
  </rule>

  <!-- T1010I: SSO Test Flow Login -->
  <rule id="100104" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1010I</field>
    <description>Teleport: User $(dstuser) performed an SSO test flow login.</description>
  </rule>

  <!-- T1012I: Headless Login Requested -->
  <rule id="100105" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1012I</field>
    <description>Teleport: Headless login requested for user $(dstuser).</description>
  </rule>

  <!-- T3007W: Auth Attempt Failed (Principal mismatch) -->
  <rule id="100106" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T3007W</field>
    <description>Teleport: Authentication attempt failed. Principal mismatch for user $(dstuser).</description>
  </rule>

  <!-- ############################################ -->
  <!-- USER & ROLE MANAGEMENT                       -->
  <!-- ############################################ -->

  <!-- T1002I: User Created -->
  <rule id="100107" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1002I</field>
    <description>Teleport: New user created: $(name).</description>
  </rule>

  <!-- T1004I: User deleted -->
  <rule id="100107" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1004I</field>
    <description>Teleport: User deleted: $(name). By $(dstuser)</description>
  </rule>

  <!-- T1003I: User updated -->
  <rule id="100107" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1003I</field>
    <description>Teleport: User updated: $(name)</description>
  </rule>

  <!-- T1005I: User Password Updated -->
  <rule id="100108" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T1005I</field>
    <description>Teleport: Password updated for user $(dstuser).</description>
  </rule>

  <!-- T6000I: Reset Password Token Created -->
  <rule id="100109" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T6000I</field>
    <description>Teleport: Password reset token generated for user $(dstuser).</description>
  </rule>

  <!-- T9000I: User Role Created -->
  <rule id="100110" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T9000I</field>
    <description>Teleport: New security role created by $(dstuser).</description>
  </rule>

  <!-- T9002I: User Role Updated -->
  <rule id="100111" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T9002I</field>
    <description>Teleport: Security role updated by $(dstuser).</description>
  </rule>

  <!-- ############################################ -->
  <!-- INFRASTRUCTURE & BOT MANAGEMENT              -->
  <!-- ############################################ -->

  <!-- T7000I: Trusted Cluster Created -->
  <rule id="100112" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T7000I</field>
    <description>Teleport: New Trusted Cluster established by $(dstuser).</description>
  </rule>

  <!-- TJT00I: Join Token Created -->
  <rule id="100113" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TJT00I</field>
    <description>Teleport: Node/Service join token created by $(dstuser).</description>
  </rule>

  <!-- TB001I: Bot Created -->
  <rule id="100114" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TB001I</field>
    <description>Teleport: Machine ID Bot "$(name)" created by $(dstuser).</description>
  </rule>

  <!-- TJ001I: Bot Joined (Success) -->
  <rule id="100115" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TJ001I</field>
    <description>Teleport: Bot joined cluster successfully using method $(method).</description>
  </rule>

  <!-- TJ001E: Bot Join Failed -->
  <rule id="100116" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TJ001E</field>
    <description>Teleport: Bot join failed. Error: $(error)</description>
  </rule>

  <!-- TJ002I: Instance Joined -->
  <rule id="100117" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TJ002I</field>
    <description>Teleport: New instance joined the cluster: $(node_name).</description>
  </rule>

  <!-- TJ002E: Instance Join Failed -->
  <rule id="100118" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TJ002E</field>
    <description>Teleport: Instance join failed for $(node_name).</description>
  </rule>

  <!-- ############################################ -->
  <!-- RESOURCE & SESSION ACTIVITY                  -->
  <!-- ############################################ -->

  <!-- TAP03I: Application Created -->
  <rule id="100119" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TAP03I</field>
    <description>Teleport: Dynamic application resource "$(name)" created by $(dstuser).</description>
  </rule>

  <!-- TAP05I: Application Deleted -->
  <rule id="100120" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TAP05I</field>
    <description>Teleport: Dynamic application resource "$(name)" deleted by $(dstuser).</description>
  </rule>

  <!-- TDB05I: Database Deleted -->
  <rule id="100121" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TDB05I</field>
    <description>Teleport: Database resource "$(name)" removed from cluster by $(dstuser).</description>
  </rule>

  <!-- TS001I: SFTP Open -->
  <rule id="100122" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TS001I</field>
    <description>Teleport: SFTP session opened by user $(dstuser) on path $(path).</description>
  </rule>

  <!-- T3005I: SCP Upload -->
  <rule id="100123" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T3005I</field>
    <description>Teleport: File upload (SCP) detected. User: $(dstuser), Path: $(path).</description>
  </rule>

  <!-- T5001I: Access Request Updated -->
  <rule id="100124" level="13">
    <if_sid>100100</if_sid>
    <field name="code">T5001I</field>
    <description>Teleport: Access Request updated (Approved/Denied) by $(updated_by).</description>
  </rule>

  <!-- TC000I: Certificate Issued -->
  <rule id="100125" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TC000I</field>
    <description>Teleport: Certificate issued for identity $(dstuser).</description>
  </rule>

  <!-- TV005I: Device Enrolled -->
  <rule id="100126" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TV005I</field>
    <description>Teleport: Trusted device enrolled by user $(dstuser).</description>
  </rule>

  <!-- ############################################ -->
  <!-- SECURITY POLICY & AUDIT CHANGES              -->
  <!-- ############################################ -->

  <!-- TLK00I: Lock Created -->
  <rule id="100127" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TLK00I</field>
    <description>Teleport: Session/User Lock created by $(dstuser). Access restricted.</description>
  </rule>

  <!-- TLK01I: Lock Deleted -->
  <rule id="100128" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TLK01I</field>
    <description>Teleport: Session/User Lock removed by $(dstuser).</description>
  </rule>

  <!-- TEA002I: External Audit Storage Disabled -->
  <rule id="100129" level="13">
    <if_sid>100100</if_sid>
    <field name="code">TEA002I</field>
    <description>Teleport: CRITICAL - External Audit Storage has been DISABLED by $(dstuser).</description>
    <group>pci_dss_10.2.6,gdpr_IV_30,security_relevant,</group>
  </rule>

</group>

EOF

# Fix permissions for the rules file
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
chmod 660 /var/ossec/etc/rules/local_rules.xml



cat >> /var/ossec/etc/decoders/teleport.xml <<EOF
<!-- Parent Decoder for Teleport -->
<decoder name="teleport">
  <program_name>^teleport</program_name>
</decoder>

<decoder name="teleport-fields">
  <parent>teleport</parent>
  <!-- 
    Each group uses (?=.*?\bKEY[:"\s]+([^"\s,\]]+))?
    - (?=...) is a positive lookahead (finds it anywhere).
    - .*? ensures it scans the whole line.
    - \b ensures we match the exact word (e.g., matching 'event' and not 'event_type').
    - The trailing '?' after the group makes it optional, so the decoder won't fail if a field is missing.
  -->
  <regex type="pcre2">(?=.*?\bcode[:"\s]+([^"\s,\]]+))?(?=.*?\bevent[:"\s]+([^"\s,\]]+))?(?=.*?\bname[:"\s]+([^"\s,\]]+))?(?=.*?\buser[:"\s]+([^"\s,\]]+))?(?=.*?\btime[:"\s]+([^"\s,\]]+))?(?=.*?\bmethod[:"\s]+([^"\s,\]]+))?(?=.*?\bsuccess[:"\s]+([^"\s,\]]+))?(?=.*?\berror[:"\s]+([^"\]]+))?(?=.*?\buid[:"\s]+([^"\s,\]]+))?(?=.*?\blogin[:"\s]+([^"\s,\]]+))?(?=.*?\bpath[:"\s]+([^"\s,\]]+))?(?=.*?\bworking_directory[:"\s]+([^"\s,\]]+))?(?=.*?\bupdated_by[:"\s]+([^"\s,\]]+))?(?=.*?\bnode_name[:"\s]+([^"\s,\]]+))?(?=.*?\bcommand[:"\s]+([^"\s,\]]+))?</regex>
  <order>code, event, name, user, time, method, success, error, uid, login, path, working_directory, updated_by, node_name, command</order>
</decoder>

EOF
chown root:wazuh /var/ossec/etc/decoders/teleport.xml
chmod 660 /var/ossec/etc/decoders/teleport.xml

echo "Restarting Wazuh Manager to apply rule changes..."
systemctl restart wazuh-manager