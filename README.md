# SOC-Lab
Security Operations Center Lab

Content of the Lab

- Architecture setup, creation of Endpoints, attacker machine, monitoring machine, SIEM
- Logging setup: Endpoint setup for ubuntu and windows, monitoring
- SIEM setup: logs receiving, parsing of the fields, create Sigma rules, custom python script to translate sigma rules into splunk alerts, creation of SIEM dashboards
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


Encontered problems and what I learned from them:
- Ubuntu monitoring VM crashed, not enough space to handle the logs. I re created the machine efficiently using the documentation from this repository. This also led to adjusting the allowed size of the other VMs, and making clones of each VM.
- Windows endpoint: the initial configuration of yara was that yara was triggered any time a file is created, but the logs were added to a new file, and yara kept triggering on the newly created log file. This used so much resources that it crashed both the windows endpoint in the VM and the host computer. when rebooting the host, I completely recreated the Windows endpoint, using the documentation, and switched from the execution of yara from triggering events to a scheduled task.
- creating sigma and splunk alerts takes up a lot of time. In order to speed things up, I wrote an automation script adapted to the sigma rules of the lab, to create splunk alerts faster. This reduces the risk of error and increases the efficiency.
- throughout the setup, testing is really important. I encountered many configuration problems that if not fixed during testing, could have led to failure to detect malicious activity.
- Splunk Free does not allow creation of planned alert: need to create reports and run them manually. In order to avoid having to run one report for each splunk alert, I created another script to concatenate all alerts by platform, to be able to run all splunk alerts and collect them at once.
- auditd encodes in hexadecimal the command line arguments if it contains special characters: I realized it while testing the alerts. Two points are learned from this: testing is paramount, and a macro was added to parse the command line properly.
- logrotate recrée les fichiers avec mauvaises permissions donc les logs bash sudo et sshd ne sont plus écrits par syslog (solution chmod 666 sur les fichiers de logs, changement de la conf logrotate)




Index

Proposition d'organisation du readme:
## Lab Objectives

## Architecture

## Data Collection

## Detection Engineering

## Attack Scenarios

## Incident Response

## Lessons Learned

## Technical Stack