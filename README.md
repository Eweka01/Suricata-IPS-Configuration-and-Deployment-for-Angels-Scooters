# Suricata IPS Configuration and Deployment for Angels & Scooters

## Project Overview
This project involves configuring Suricata as an Intrusion Prevention System (IPS) to secure the "Angels & Scooters" website from malicious traffic. The setup leverages NFQUEUE for packet handling and implements custom rules to block malicious activities while allowing legitimate user traffic.

## Network Topology

<img width="542" alt="Screenshot 2025-01-18 at 4 40 32 PM" src="https://github.com/user-attachments/assets/6d18ac7c-ed75-4b80-aed8-70e29d90e073" />

The network setup includes:
- **Desktop:** `192.168.6.1`
- **Firewall:** `192.168.6.4` (interfaces: `enp1s9` for internet and `enp1s10` for the internal network)
- **Server:** `192.168.10.2` (hosting the "Angels & Scooters" website)

## Objectives
1. Inspect Suricata logs to identify malicious activity.
2. Create and deploy custom IPS rules to block malicious traffic.
3. Enable and test managed rulesets for enhanced protection.

---

## Steps Taken

### 1. Suricata Log Analysis
- Accessed the Suricata event log located at `/var/log/suricata/eve.json` using the following command:
  ```bash
  sudo tail -f /var/log/suricata/eve.json
  ```
  <img width="1728" alt="Screenshot 2025-01-18 at 4 17 16 PM" src="https://github.com/user-attachments/assets/8ce60aa0-66db-47d3-8af2-89d541f4987a" /> <img width="1728" alt="Screenshot 2025-01-18 at 4 38 19 PM" src="https://github.com/user-attachments/assets/c824ec0c-27d0-4842-a99f-b80e5d493708" />


- Observed malicious traffic targeting the "Angels & Scooters" website.
- Example of malicious IPs identified:
  - **115.85.112.193**
  - **80.252.240.121**
  - **188.226.191.66**

### 2. Creating Custom IPS Rules
- Wrote custom rules to block identified malicious traffic and common web application attacks (e.g., SQL injection, command injection).
- Edited the rules file at `/etc/suricata/rules/suricata.rules`:
  ```bash
  sudo nano /etc/suricata/rules/suricata.rules
  ```
- Added the following rules:

  ```
  # Drop Path Traversal Attempts
  drop http any any -> any any (msg:"Path Traversal Detected"; flow:to_server,established; content:"../"; http_uri; nocase; classtype:web-application-attack; sid:2000001; rev:1;)

  # Drop SQL Injection Attempts
  drop http any any -> any any (msg:"SQL Injection Attempt"; flow:to_server,established; pcre:"/select\b.*\bfrom\b/i"; http_uri; nocase; classtype:web-application-attack; sid:2000002; rev:1;)

  # Drop Command Injection Attempts
  drop http any any -> any any (msg:"Command Injection Attempt"; flow:to_server,established; content:"/etc/passwd"; http_uri; classtype:web-application-attack; sid:2000003; rev:1;)

  # Block Specific Malicious IPs
  drop ip 80.252.240.121 any -> any any (msg:"Blocked IP - Malicious Activity"; sid:2000005; rev:1;)
  drop ip 115.85.112.193 any -> any any (msg:"Blocked IP - Malicious Activity"; sid:2000006; rev:1;)
  drop ip 188.226.191.66 any -> any any (msg:"Blocked IP - Malicious Activity"; sid:2000007; rev:1;)
  ```

### 3. Testing Rule Syntax
- Validated the syntax of the rules:
  ```bash
  sudo suricata -T -c /etc/suricata/suricata.yaml -v
  ```
- Resolved any errors, such as ensuring the proper use of `http_uri` with `content` or `pcre` keywords.

### 4. Restarting Suricata
- Applied the updated rules by restarting Suricata:
  ```bash
  sudo systemctl restart suricata
  ```

### 5. Enabling Managed Rulesets
- Enabled the Emerging Threats ruleset for additional protection:
  ```bash
  sudo suricata-update enable-source etnetera/aggressive
  sudo suricata-update
  ```
- Verified the inclusion of new rules in `/var/lib/suricata/rules/suricata.rules`.

### 6. Monitoring Logs
- Monitored the Suricata log file to confirm that malicious traffic was being dropped:
  ```bash
  sudo tail -f /var/log/suricata/fast.log
  ```
- Verified that legitimate traffic to the "Angels & Scooters" website remained unaffected.

---

## Results
1. Successfully blocked malicious traffic from the identified IPs and common web application attack patterns.
2. Verified that normal user traffic to the "Angels & Scooters" website was uninterrupted.
3. Enhanced security posture with both custom and managed rulesets.

---

## Challenges and Resolutions
- **Rule Syntax Errors:**
  - Encountered errors with `http_uri` usage. Resolved by adding appropriate `content` or `pcre` keywords.
- **Log Noise:**
  - Filtered logs to focus on relevant alerts by tailoring rules and reviewing the eve.json file.

---

## Future Enhancements
1. Automate periodic rule updates using a cron job for `suricata-update`.
2. Implement more detailed logging and alerting to monitor new attack patterns.
3. Expand rules to cover additional threat vectors, such as DNS-based attacks.

---

## Conclusion
The Suricata IPS was successfully configured and deployed to secure the "Angels & Scooters" website. This implementation effectively blocks malicious activity while ensuring uninterrupted legitimate traffic, demonstrating a practical approach to intrusion prevention in a small business network.

