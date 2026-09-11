# Incident Summary

A Linux workstation was compromised following a successful SSH brute-force attack.Sensitive HR data relating to up to 126 current and former employees was exfiltrated. The incident was detected in the SIEM. The attack is contained and the workstation is restored. 

# Timeline

18:11	Reconnaissance activity detected
18:19	Initial access achieved through SSH brute force
18:20	Incident detected and investigation initiated
19:10	Containment completed
19:22	Eradication completed
19:48	Recovery completed

# Impact Assessment

A single non-privileged account was compromised. The attacker was able to obtain high privileges. This led to the discovery and exfiltration of sensitive data:
    - list of users, rights, groups, password hashes
    - Human Resources archive, containing personnal data, including name, phone number, email address, postal address, banking information and salary. The exposition concerns all current and previous employees, up to a total of 126 people.

The confidentiality of this data has been compromised. 

# Actions taken

- detection of opened session, suppression of any suspect session
- detection of suspect active network connection
- detection of the persistence on each user account of the compromised host
- neutralize the compromise account
- block the attacker IP address at a network level, for any inbound or outbound connection
- deletion of the SSH-based persistence
- deletion of the malicious scheduled job and its associated bash script
- rotate all secrets viewed or exfiltrated, regenerate all SSH keys
- disable the SUID on the exploited binary


# Evidence and Findings

The attack used the following techniques:
- Reconnaissance: host and port scan
- Initial access: successful brute-force on a discovered SSH account
- Discovery: commands on the endpoint
- Privilege escalation: abusing a SUID-enabled binary
- Persistence: creating a malicious scheduled job and adding an SSH key-based access
- Collection: looking for sensitive data and gathering files
- Exfiltration: sending the collected data over HTTP traffic
- Defense evasion: removing traces of the attack from the shell history

The detailed evidence of each step is available in the investigation report.

# Root Cause

- no IPS in place: could have blocked the host and port scan
- lack of user awareness: the username displayed on the FTP banner is llikely to be used in a bruteforce attack. the SSH password of the user account was not strong enough. no MFA enabled.
- Dangerous SUID set on binaries which allows a fast privilege escalation
- sensitive cleartext data exposure

# Lessons learned

- part of the activity was only partially detected: complete the Sigma rules to widen the detection range (SSH key-based access creation and SSH key-based authentication, exploitation of SUID enabled binaries)
- set up a detection tool to detect dangerous SUID before it can be exploited
- security awareness training: create difficult passwords, avoid exposing usernames
- enable multi factor authentication
- encrypt sensitive data if possible