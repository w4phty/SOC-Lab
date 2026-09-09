# Incident overview

The incident scenario simulates an attack, including the following phases: reconnaissance, initial access, privilege escalation, data collection and exfiltration, and defense evasion. The architecture has been detailed previously:
    - Attacker machine : Kali Linux (10.10.10.1)
    - Endpoint: Ubuntu (10.10.10.2)
    - Monitoring machine (10.10.10.4)
    - SIEM: Splunk, logs are forwarded from the Ubuntu Endpoint (rsyslog, auditd, YARA) and the monitoring machine (zeek, suricata, tcpdump)


Three levels of report are available:
- the **incident timeline**, right below
- [investigation.md](./investigation.md): the **detailed investigation**, queries, evidence, conclusion
- incident-response.md : the actions to detect, contain, eradicate and recover from the incident
- executive_report.pdf: the **executive report** including the environment monitored, key findings, recommandations

# Incident timeline

This timeline summarizes the incident investigated. It provides a high-level view of the attack progression, the telemetry used to reconstruct each phase and the detection coverage.

| Time | Phase | Activity | Source | Pivot fields | Detection coverage |
| - | - | - | - | - | - |
| 18:11:09 | Reconnaissance | Host discovery scan | Suricata, Zeek, tcpdump | source IP (10.10.10.1) | Detected (SPL-01 and SPL-19)
| 18:12:53 | Reconnaissance | TCP port scan against 10.10.10.2 | Suricata, Zeek, tcpdump | source IP (10.10.10.1), destination IP (10.10.10.2) | Detected (SPL-01 and SPL-19)
| 18:13:05 | Reconnaissance | FTP service interaction | tcpdump | source IP (10.10.10.1), destination IP (10.10.10.2) | Not detected, observed in tcpdump
| 18:17:25 | Credential access | SSH bruteforce against user charlie | sshd | user (charlie) | Detected (SPL-16)
| 18:19:00 | Initial access | Successful SSH access to 10.10.10.2 | sshd | user (charlie), source IP (10.10.10.1) | Detected (SPL-21)
| 18:19:10 | Discovery | Host and account discovery commands | Auditd | user (charlie), parent process ID (4351), session ID (7) | Detected (SPL-18)
| 18:22:57 | Privilege escalation | SUID binary abuse to obtain a root shell | Auditd | user (charlie), parent process ID (4351, 4415, 4416) | Partially detected (SPL-13)
| 18:27:43 | Persistence | Malicious cron job created | Auditd, YARA | auditd key (cron_change), parent process ID (4415) | Detected (SPL-30 and SPL-09)
| 18:30:13 | Persistence | SSH key-based persistence established | Auditd, sshd |  user (charlie), source IP (10.10.10.1), process ID (4444) | Not detected, observed through Auditd and sshd telemetry
| 18:31:14 | Collection | Sensitive files collected | Auditd | parent process ID (4416) | Partially detected (SPL-18)
| 18:34:55 | Exfiltration | Sensitive data exfiltrated over HTTP | Zeek, tcpdump, Auditd | source IP (10.10.10.2), destination IP (10.10.10.1), source port (34162), destination port (443) | Detected (SPL-25)
| 18:37:02 | Defense evasion | Shell history modified | Auditd | user (charlie), parent process ID (4416) | Not detected, observed through Auditd telemetry


# Detection coverage & detection improvement

Different detection levels:
- detected, alert raised in SIEM
- the malicious action itself did not trigger an alert, but the related activity did.
- not detected, but observed in the telemetry when investigating the surrounding activity of an alert

Improvement that need to be done based on this incident coverage:

1. **Critical** : add an auditd rule to watch any changes made on `~/.ssh/authorized_keys` for all users
2. **High** : create a Sigma rule to detect the SUID abuse
3. **High**: create a new Sigma rule to detect SSH key-based authentication
4. **Medium**: extend the account dicovery alerts to commands such as whoami and sudo -l
5. **Low**: add a new Sigma rule concerning defense evasion 
6. **Low**: add application-level visibility (FTP)


