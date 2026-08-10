## Sigma rules

For this lab, 29 Sigma rules are created based on some common MITRE ATT&CK tactics and techniques. The goal is to cover a wide enough range of attack phases.
The Sigma rules are divided in 3 categories: Windows, Linux and Network.
The uuids used in the sigma rules are generated using the script uuid_generator.py. The Sigma rules are created using the normalized fields as seen in the previous section [02-normalization](../02-normalization/).

### Windows Sigma Rules

| Rule ID | Description | MITRE Tactic | MITRE Technique | Technique ID |
|---|---|---|---|---|
| [SPL-04](./windows/04-execution-powershell.yaml) | Powershell execution | Execution | Command and Scripting Interpreter – PowerShell | T1059.001 |
| [SPL-05](./windows/05-execution-windows-command-shell.yaml) | Command shell execution | Execution | Command and Scripting Interpreter – Windows Command Shell | T1059.003 |
| [SPL-08](./windows/08-execution-malicious-user-execution.yaml) | Malicious user execution | Execution | User Execution | T1204 |
| [SPL-10](./windows/10-persistence-scheduled-task.yaml) | Scheduled task | Persistence | Scheduled Task/Job – Scheduled Task | T1053.005 |
| [SPL-11](./windows/11-persistence-event-triggered-execution.yaml) | Event triggered execution | Persistence | Event Triggered Execution | T1546 |
| [SPL-12](./windows/12-persistence-create-account.yaml) | Account creation | Persistence | Create Account | T1136 |
| [SPL-15](./windows/15-privilege-escalation-uac-bypass.yaml) | UAC Bypass | Privilege Escalation | Command and Scripting Interpreter – Windows Command Shell | T1053.005 |
| [SPL-16](./windows/16-credential-access-brute-force-windows.yaml) | Credential Brute force | Credential Access | Brute Force | T1110 |
| [SPL-17](./windows/17-credential-access-credential-dumping.yaml) | Credential dumping | Credential Access | OS Credential Dumping | T1003 |
| [SPL-18](./windows/18-discovery-account-windows.yaml) | Account discovery | Discovery | Account Discovery | T1087 |
| [SPL-20](./windows/20-lateral-movement-rdp.yaml) | RDP Connection | Lateral Movement | Remote Services – Remote Desktop Protocol | T1021.001 |
| [SPL-22](./windows/22-lateral-movement-alternate-authentication.yaml) | Alternate Authentication | Lateral Movement | Use Alternate Authentication Material | T1550 |
| [SPL-28](./windows/28-credential-dumping-yara.yaml) | Credential dumping - YARA | Credential Access | OS Credential Dumping | T1003 |
| [SPL-29](./windows/29-powershell-dropper-yara.yaml) | Powershell dropper - YARA | Execution | Command and Scripting Interpreter – PowerShell | T1059.001 |


### Linux Sigma Rules

| Rule ID | Description | MITRE Tactic | MITRE Technique | Technique ID |
|---|---|---|---|---|
| [SPL-06](./linux/06-execution-unix-shell.yaml) | Unix shell execution | Execution | Command and Scripting Interpreter – Unix Shell | T1059.004
| [SPL-07](./linux/07-execution-python.yaml) | Python execution | Execution | Command and Scripting Interpreter – Python | T1059.006
| [SPL-09](./linux/09-persistence-cron.yaml) | Persistence via cron | Persistence | Scheduled Task/Job – Cron | T1053.003
| [SPL-13](./linux/13-privilege-escalation-setuid-setgid.yaml) | Usage of setuid/setgid | Privilege Escalation | Abuse Elevation Control Mechanism -  Setuid and Setgid | T1548.001
| [SPL-14](./linux/14-privilege-escalation-sudo.yaml) | Usage of sudo | Privilege Escalation | Abuse Elevation Control Mechanism -  Sudo and Sudo Caching | T1548.003
| [SPL-16](./linux/16-credential-access-brute-force-linux.yaml) | Credential bruteforce | Credential Access | Brute Force | T1110
| [SPL-18](./linux/18-discovery-account-linux.yaml) | Account discovery | Discovery | Account Discovery | T1087
| [SPL-21](./linux/21-lateral-movement-ssh.yaml) | SSH Connection | Lateral Movement | Remote Services – SSH | T1021.004
| [SPL-26](./linux/26-unix-shell-yara.yaml) | Unix shell - YARA | Execution | Command and Scripting Interpreter – Unix Shell | T1059.004
| [SPL-27](./linux/27-execution-python-yara.yaml) | Python execution - YARA | Execution | Command and Scripting Interpreter – Python | T1059.006


### Network Sigma Rules

| Rule ID | Description | MITRE Tactic | MITRE Technique | Technique ID |
|---|---|---|---|---|
| [SPL-01](./network/01-reconnaissance-active-scanning.yaml) | Active scanning | Reconnaissance | Active Scanning | T1595
| [SPL-02](./network/02-reconnaissance-phishing.yaml) | Phishing for credentials | Reconnaissance | Phishing for Information | T1598
| [SPL-03](./network/03-intial-access-phishing.yaml) | Initial access phishing | Initial Access | Phishing | T1566
| [SPL-19](./network/19-discovery-network-service.yaml) | Service discovery | Discovery | Network Service Discovery | T1046
| [SPL-23](./network/23-command-and-control-web.yaml) | Suspicious web traffic | Command and Control | Application Layer Protocol - Web Protocols | T1071.001
| [SPL-24](./network/24-command-and-control-dns.yaml) | Suspicious DNS | Command and Control | Application Layer Protocol – DNS | T1071.004
| [SPL-25](./network/25-exfiltration-web.yaml) | Exfiltration web | Exfiltration | Exfiltration Over Web Service | T1567









