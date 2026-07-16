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
- Network monitoring: Suricata, Zeek
- Malware monitoring: YARA
- Log forwarding: Splunk Universal Forwarder
- SIEM: Splunk Enterprise dashboards and alerts
- Attacks generated from Kali using hydra, metasploit, python3


Encontered problems:
- Ubuntu monitoring VM crashed, not enough space to handle the logs. I re created the machine efficiently with the documentation. And adjusted the allowed size of the other VMs
- Windows endpoint: the initial configuration of yara was that yara was triggered any time a file is created, but the logs were added to a new file, and yara kept triggering on the newly created log file. This used so much resources that it crashed both the windows endpoint in the VM and the host computer. when rebooting the host, I completely recreated the Windows endpoint, using the documentation I redacted, and changed the yara triggering events.