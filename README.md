# 🛡️ BlueTeam-Handbook  
### The Ultimate SOC1/2 Interview & Knowledge Guide  

Welcome to **BlueTeam-Handbook**, your one-stop resource for mastering **SOC1/2 interview questions** and sharpening your **Blue Team defensive security skills**.  
This handbook covers everything from **SIEMs** to **Incident Response**, with categorized questions, explanations, and real-world scenarios.  

---

## 📑 Table of Contents  

- [SOC Fundamentals](#-soc-fundamentals)  
- [SIEM](#-siem-security-information-and-event-management)  
- [Network Security](#-network-security)  
- [Endpoint Security](#-endpoint-security)  
- [Threat Intelligence & Hunting](#-threat-intelligence--hunting)  
- [Malware Analysis](#-malware-analysis-basic-for-soc)  
- [Incident Response](#-incident-response)  
- [Cloud Security](#-cloud-security)  
- [Vulnerabilities & Exploits](#-vulnerabilities--exploits)  
- [Security Tools](#-security-tools)  
- [Case Study Questions](#-case-study-questions)  
- [Behavioral & Scenario Questions](#-behavioral--scenario-questions)  

---

## 🏢 SOC Fundamentals  

### ❓ What is a SOC and why do organizations need it?  
A **Security Operations Center (SOC)** is a centralized unit that **monitors, detects, analyzes, and responds** to cybersecurity incidents.  
Organizations need a SOC to:  
- Provide **24/7 monitoring** of systems and networks.  
- Detect **anomalies, intrusions, and threats** in real-time.  
- Support **incident response** and reduce business impact.  
- Ensure compliance with **regulatory frameworks** (ISO 27001, PCI-DSS, HIPAA, etc.).

### ❓ Explain SOC roles & tiers (L1, L2, L3, Threat Hunter, IR).  

- **Tier 1 (SOC Analyst / Alert Triage):**  
  - Monitors SIEM alerts.  
  - Performs **initial triage**.  
  - Escalates real incidents to Tier 2.  

- **Tier 2 (Incident Responder):**  
  - Performs **deep analysis** of alerts.  
  - Investigates **log correlations, network traffic, malware samples**.  
  - Coordinates containment & remediation.  

- **Tier 3 (Threat Hunter / SME):**  
  - Hunts for **unknown/advanced threats** using hypothesis-driven searches.  
  - Creates **detection rules & playbooks**.  
  - Supports Tier 1 & 2.  

- **Incident Response Team (IR):**  
  - Specialized responders handling **containment, eradication, recovery**.  
  - Works closely with legal, PR, and management.  

### ❓ What is the difference between detection and prevention?  

- **Detection:**  
  - Identifying suspicious or malicious activity **after it occurs**.  
  - Example: SIEM alert for failed login attempts.  

- **Prevention:**  
  - Blocking malicious activity **before it causes harm**.  
  - Example: Firewall blocking malicious IP addresses.  

👉 A mature SOC uses **both detection and prevention** to strengthen defense.  

### ❓ What types of data/logs does a SOC collect?  
- **Network logs:** Firewall, IDS/IPS, proxies, routers.  
- **Endpoint logs:** Antivirus, EDR, Windows Event IDs, Sysmon.  
- **Authentication logs:** Active Directory, LDAP, IAM systems.  
- **Application logs:** Web servers, databases.  
- **Cloud logs:** AWS CloudTrail, Azure Monitor, GCP Logs.

📸 *[Common Log Data types]*  


### ❓ What is the Cyber Kill Chain model?  
The **Cyber Kill Chain** by `Lockheed Martin` describes attacker steps:  
1. Reconnaissance  
2. Weaponization  
3. Delivery  
4. Exploitation  
5. Installation  
6. Command & Control  
7. Actions on Objectives

👉 SOC teams map detections and defenses to each phase.

📸 *[Cyber Kill Chain model]*  


### ❓ What is the MITRE ATT&CK framework and why is it important for SOC?  
- **MITRE ATT&CK** is a knowledge base of **tactics, techniques, and procedures (TTPs)** used by adversaries.  
- Helps SOC teams to:  
  - Map alerts to known attacker behaviors.  
  - Develop detection use cases.  
  - Guide threat hunting.  
  - Identify coverage gaps.


### ❓ What are common SOC challenges?  
- **Alert fatigue:** Too many false positives.  
- **Tool overload:** Managing multiple tools without integration.  
- **Skill gap:** Shortage of trained SOC analysts.  
- **Evolving threats:** Adapting to zero-days and new attack techniques.  
- **Visibility gaps:** Missing logs or blind spots in monitoring.  

---

## 📊 SIEM (Security Information and Event Management)  

### ❓ What is a SIEM and how does it work?  
A **SIEM** collects, correlates, and analyzes security events from multiple sources in real-time.  
It helps SOC teams **detect, investigate, and respond** to threats efficiently.  
- **Data sources:** Logs from firewalls, endpoints, servers, applications, and cloud services.  
- **Functions:** Aggregation, normalization, correlation, alerting, reporting.  

### ❓ Name 3 popular SIEM tools and their advantages.  
- **Splunk:** Powerful search, dashboarding, and app ecosystem.  
- **QRadar:** Advanced correlation engine and threat intelligence integration.  
- **Wazuh / ELK:** Open-source, customizable, great for learning and labs.


### ❓ What’s the difference between a correlation rule and a detection use case?  
- **Correlation Rule:** Combines multiple events to generate an alert.  
  - Example: 5 failed logins + 1 successful login = alert.  
- **Detection Use Case:** Broader scenario the SOC wants to detect, often implemented via rules, dashboards, or playbooks.  

### ❓ What is log normalization in SIEM?  
Log normalization is the process of **standardizing log data** from different sources so the SIEM can **correlate and analyze** it effectively.  

### ❓ What is the difference between real-time and historical analysis in SIEM?  
- **Real-time:** Detects threats as they occur using live data streams.  
- **Historical:** Investigates past incidents or trends using stored logs.  

### ❓ What is a SIEM dashboard?  
A **dashboard** visualizes key metrics, alerts, and trends for SOC analysts.  

📸 *[Example Wazuh SIEM dashboard]*  

### ❓ What is the difference between on-premises and cloud SIEM?  
- **On-premises:** Installed in local infrastructure; full control, higher maintenance.  
- **Cloud SIEM:** Hosted in the cloud; scalable, easier deployment, often subscription-based.  

### ❓ Describe a typical SIEM architecture.  
- **Data Sources:** Endpoints, network devices, applications, cloud logs.  
- **Log Collection Layer:** Agents or syslog servers collect and forward data.  
- **Parsing & Normalization Layer:** Converts raw logs into structured events.  
- **Correlation & Analysis Layer:** Applies rules, detection logic, and machine learning.  
- **Storage Layer:** Retains historical logs for investigation and compliance.  
- **Presentation Layer:** Dashboards, alerts, reports for SOC analysts.  

📸 *[Example ELK SIEM architecture]*  

### ❓ What is the workflow of a SIEM in a SOC?  
1. **Log Collection:** Gather logs from multiple sources.  
2. **Normalization:** Convert logs to a standard format.  
3. **Correlation & Detection:** Identify patterns, anomalies, or threats.  
4. **Alerting:** Generate alerts for suspicious events.  
5. **Investigation:** SOC analysts review alerts, perform triage, escalate if needed.  
6. **Response:** Containment, mitigation, and remediation of incidents.  
7. **Reporting:** Metrics, KPIs, compliance reports.

📸 *[SIEM workflow]*  

### ❓ What are the key challenges in SIEM deployment?  
- Handling **large volumes of logs** without performance loss.  
- **False positives** from poorly tuned rules.  
- Integrating **diverse data sources** from different vendors.  
- Maintaining **retention policies** for compliance.  
- **Skill gaps**: SOC staff need SIEM expertise.  

### ❓ What is the difference between agent-based and agentless log collection?  
- **Agent-based:** Software installed on endpoints to forward logs securely and reliably.  
- **Agentless:** Collects logs remotely (e.g., via syslog, API) without installing software on endpoints.

### ❓ How does a SIEM support threat hunting?  
- Provides **historical data and correlations** for hunting.  
- Allows analysts to **query logs** across multiple sources.  
- Integrates **MITRE ATT&CK and threat intelligence feeds**.  
- Helps identify **unknown/advanced threats** proactively.  

### ❓ How does a SIEM integrate with SOAR?  
- SIEM generates alerts.  
- SOAR automates **playbooks** to investigate, contain, and remediate incidents.  
- Reduces **manual effort** and improves **response speed**.

---

## 🌐 Network Security  

### ❓ Explain the difference between the OSI and TCP/IP models.  
- **OSI (7 layers):** Application, Presentation, Session, Transport, Network, Data Link, Physical.  
- **TCP/IP (4 layers):** Application, Transport, Internet, Network Access.  
- OSI is theoretical; TCP/IP is practical and used in real networking.  

### ❓ How would you detect a DDoS attack?  
- **Indicators:** Unusual traffic spikes, service unavailability, abnormal bandwidth usage.  
- **Detection tools:** NetFlow, IDS/IPS, SIEM alerts, firewall logs.  
- **SOC action:** Identify attack type (volumetric, application-layer, protocol), mitigate via rate-limiting, WAF, scrubbing.  

### ❓ IDS vs IPS – key differences.  
- **IDS (Intrusion Detection System):** Monitors and alerts on suspicious traffic, but does not block.  
- **IPS (Intrusion Prevention System):** Detects and blocks malicious traffic in real-time.  

### ❓ What are common types of network attacks?  
- DDoS / DoS  
- Man-in-the-Middle (MITM)  
- ARP Spoofing  
- DNS Poisoning  
- Port Scanning & Reconnaissance  

### ❓ What is a firewall and what are its types?  
- **Firewall:** A security device that monitors and controls traffic based on rules.  
- **Types:**  
  - Packet Filtering Firewall  
  - Stateful Inspection Firewall  
  - Application Firewall (WAF)  
  - Next-Gen Firewall (NGFW)  

### ❓ Explain the difference between symmetric and asymmetric encryption.  
- **Symmetric:** Same key for encryption/decryption (AES, DES). Fast but key distribution is hard.  
- **Asymmetric:** Public/private key pair (RSA, ECC). Secure key exchange, but slower.  

### ❓ What is a VPN and how does it secure communication?  
- **VPN (Virtual Private Network):** Encrypts traffic between user and network over public internet.  
- Uses tunneling protocols (IPSec, SSL/TLS).  
- Ensures **confidentiality, integrity, and authentication**.  

📸 *[VPN tunnel diagram]*  

### ❓ Explain Zero Trust Network Security.  
- "Never trust, always verify."  
- Every request is authenticated, authorized, and encrypted.  
- Reduces lateral movement risks.  

### ❓ What is network segmentation and why is it important?  
- Dividing a network into smaller zones with limited communication.  
- Prevents lateral movement, improves performance, enforces least privilege.  
- Example: Separating user VLANs from critical servers.  

### ❓ How does DNS monitoring help in SOC operations?  
- Detects suspicious domains (C2 servers, phishing).  
- Monitors unusual DNS queries (fast-flux, tunneling).  
- Can trigger alerts in SIEM.  
📸 *[Insert screenshot: DNS query log analysis]*  

### ❓ What is SSL/TLS inspection and why is it used?  
- Decrypts encrypted traffic at the firewall/proxy for inspection.  
- Detects malware hidden in HTTPS.  
- Balance between **security and privacy**.  


### ❓ How would you investigate a suspicious IP connection?  
1. Identify source/destination IP from logs.  
2. Check against threat intelligence feeds.  
3. Look for unusual ports or protocols.  
4. Correlate with other alerts (endpoint logs, firewall).  
5. Escalate if confirmed malicious.  

---

## 💻 Endpoint Security  

### ❓ What is the difference between Antivirus (AV) and Endpoint Detection & Response (EDR)?  
- **Antivirus (AV):** Signature-based detection of known malware. Limited against advanced threats.  
- **EDR:** Provides real-time monitoring, detection, and response capabilities for suspicious activities on endpoints. Includes behavior analysis, process monitoring, and forensic data.  

### ❓ How would you investigate a suspicious process on an endpoint?  
1. Identify the process (PID, parent process).  
2. Check file location & digital signature.  
3. Correlate with Sysmon logs (event 1 – process creation).  
4. Search hash in VirusTotal/Threat Intel.  
5. Review network connections (Sysmon event 3).  
6. Escalate or terminate process if malicious.  

### ❓ What is Sysmon and how is it used in SOC?  
- **Sysmon (System Monitor):** Windows tool that logs detailed system activity.  
- Captures process creation, network connections, file modifications, registry changes.  
- Provides visibility for **threat hunting** and **incident investigations**.  

### ❓ How would you investigate a potential ransomware infection on an endpoint?  
1. Identify suspicious process activity (mass file changes).  
2. Look for unusual **file extensions**.  
3. Detect network connections to C2.  
4. Isolate endpoint immediately.  
5. Check logs for initial infection vector (phishing, exploit).  

### ❓ How do you monitor Linux endpoints in SOC?  
- Use auditd, Sysmon for Linux, OSSEC/Wazuh agents.  
- Monitor `/var/log/auth.log` for login activity.  
- Watch for suspicious processes, privilege escalations, and cron jobs.  

### ❓ What are Indicators of Compromise (IoCs) on endpoints?  
- Suspicious processes (explorer.exe spawning cmd.exe).  
- Abnormal network connections.  
- Malicious file hashes.  
- Unexpected registry changes.  
- Disabled security tools.  


---

## 🔎 Threat Intelligence & Hunting  

❓ What is an IoC vs IoA?  
❓ Explain the MITRE ATT&CK framework.  
❓ Give an example of a hunting query.  

📸 *[Insert screenshot: MITRE ATT&CK Navigator view]*  

---

## 🐛 Malware Analysis (Basic for SOC)  

❓ What are common types of malware?  
❓ How would you analyze a suspicious file hash?  
❓ What is the role of a sandbox?  

📸 *[Insert screenshot: Any.Run malware analysis]*  

---

## 🚨 Incident Response  

❓ What are the 6 phases of the IR lifecycle?  
❓ How do you classify incident severity?  
❓ What would you do in case of ransomware detection?  
📸 *[Insert screenshot: Incident response playbook flow]*  

---

## ☁️ Cloud Security  

❓ Explain the shared responsibility model.  
❓ How would you detect abnormal IAM activity in AWS?  
❓ Name one cloud-native logging service.  

---

## 🕳️ Vulnerabilities & Exploits  

❓ What is CVE & CVSS?  
❓ Difference between vulnerability scanning and penetration testing?  
❓ How do you handle zero-days?  

---

## 🛠️ Security Tools  

- SIEM: Splunk, QRadar, ELK, Wazuh  
- SOAR: Shuffle, Cortex XSOAR  
- IDS/IPS: Snort, Suricata  
- Threat Feeds: MISP, OTX  

📸 *[Insert screenshot: Splunk dashboard with alerting]*  

---

## 📚 Case Study Questions  

- How would you investigate a brute-force attack?  
- How would you analyze phishing email headers?  
- What steps would you take during lateral movement detection?  

---

## 👥 Behavioral & Scenario Questions  

- How do you prioritize multiple alerts?  
- Tell me about a time you solved a difficult incident.  
- How do you keep yourself updated with the latest threats?  
