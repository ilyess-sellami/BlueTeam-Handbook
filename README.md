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

---

## 📊 SIEM (Security Information and Event Management)  

❓ What is SIEM and how does it work?  
❓ Name 3 popular SIEM tools and their advantages.  
❓ What’s the difference between a correlation rule and a detection use case?  
📸 *[Insert screenshot of a SIEM dashboard]*  

---

## 🌐 Network Security  

❓ Explain OSI vs TCP/IP models.  
❓ How would you detect a DDoS attack?  
❓ IDS vs IPS – key differences.  
📸 *[Insert screenshot: Wireshark packet capture analysis]*  

---

## 💻 Endpoint Security  

❓ What is EDR vs Antivirus?  
❓ Explain common Windows Event IDs (4624, 4625, 4688).  
❓ How would you investigate a suspicious process?  
📸 *[Insert screenshot: Sysmon logs visualization]*  

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
