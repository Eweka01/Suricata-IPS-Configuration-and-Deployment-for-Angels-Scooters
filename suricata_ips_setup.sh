#!/bin/bash
# Suricata IPS Setup Script

# Access Suricata Logs
sudo tail -f /var/log/suricata/eve.json

# Edit Suricata Rules File
sudo nano /etc/suricata/rules/suricata.rules

# Add the following rules to the rules file
echo "
# Drop Path Traversal Attempts
drop http any any -> any any (msg:\"Path Traversal Detected\"; flow:to_server,established; content:\"../\"; http_uri; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

# Drop SQL Injection Attempts
drop http any any -> any any (msg:\"SQL Injection Attempt\"; flow:to_server,established; pcre:\"/select\\b.*\\bfrom\\b/i\"; http_uri; nocase; classtype:web-application-attack; sid:2000002; rev:1;)

# Drop Command Injection Attempts
drop http any any -> any any (msg:\"Command Injection Attempt\"; flow:to_server,established; content:\"/etc/passwd\"; http_uri; classtype:web-application-attack; sid:2000003; rev:1;)

# Block Specific Malicious IPs
drop ip 80.252.240.121 any -> any any (msg:\"Blocked IP - Malicious Activity\"; sid:2000005; rev:1;)
drop ip 115.85.112.193 any -> any any (msg:\"Blocked IP - Malicious Activity\"; sid:2000006; rev:1;)
drop ip 188.226.191.66 any -> any any (msg:\"Blocked IP - Malicious Activity\"; sid:2000007; rev:1;)
" | sudo tee -a /etc/suricata/rules/suricata.rules

# Validate Rules Syntax
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Restart Suricata to Apply Rules
sudo systemctl restart suricata

# Enable Managed Ruleset (Etnetera's Aggressive Rules)
sudo suricata-update enable-source etnetera/aggressive
sudo suricata-update

# Monitor Fast Logs to Verify Traffic
sudo tail -f /var/log/suricata/fast.log
