# SOC-Lab
Security Operations Center Lab

Content of the Lab

- Architecture setup, creation of Endpoints, attacker machine, monitoring machine, SIEM
- Logging setup: Endpoint setup for ubuntu and windows, monitoring
- SIEM setup: logs receiving, alerts, dashboards
- workbook setup
- Basic Attacks and analysis: phishing and credential exposure, nmap scan, ssh and rdp bruteforce, privileges escalation, persistence 
- Network traffic analysis and detection: telnet connection, C2, DNS tunneling
- Malware static and dynamic analysis, exfiltration IoC, sigma and yara updates, incident response

Technical Stack
- Ubuntu logs: syslog, rsyslog, auditd
- Windows logs: WinEvent, Sysmon
- Network monitoring: Suricata
- Malware monitoring: YARA
- Log forwarding: Splunk Universal Forwarder
- SIEM: Splunk Enterprise dashboards and alerts
- Attacks generated from Kali using hydra, metasploit, python3

