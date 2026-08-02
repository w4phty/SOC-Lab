## Linux alerts

### SPL-06. Unix Shell - Bash reverse shell
Sigma rule: [sigma-rule-06](sigma-rules/linux/06-execution-unix-shell.yaml)

Splunk alert:
```
index="linux_os" sourcetype="linux_audit"
(process_name="bash" AND (
    command_line="*/dev/tcp/*"
    OR command_line="*bash -i*"
    OR command_line="*0>&1*"
    OR command_line="*nc -e*"
))
| eval alert_name="Execution - Bash reverse shell",
    rule_id="SPL-06",
    mitre_technique="T1059.004",
    severity="critical",
    sigma_id="7cfaca8b-c223-4348-ba7c-1166f1d36a03",
    platform="Linux",
    datasource="Audit"
| collect index=siem_alerts 
```


### SPL-07. Execution - Backdoor or reverse shell
Sigma rule: [sigma-rule-07](sigma-rules/linux/07-execution-python.yaml)

Splunk alert:
```
index="linux_os" sourcetype="linux_audit"
(
    executable="*/python3"
    OR executable="*/python"
)
AND
(
    command_line="*import socket*"
    OR command_line="*import subprocess*"
    OR command_line="*subprocess.Popen*"
    OR command_line="*connect(*"
)
| eval alert_name="Execution - Backdoor or reverse shell",
    rule_id="SPL-07",
    mitre_technique="T1059.006",
    severity="high",
    sigma_id="d61b394c-7428-467d-95f7-a944eee888ef",
    platform="Linux",
    datasource="Audit"
| collect index=siem_alerts
```


### SPL-09. Persistence - Suspicious cron modification
Sigma rule: [sigma-rule-09](sigma-rules/linux/09-persistence-cron.yaml)

Splunk alert:
```
index="linux_os" sourcetype="linux_audit"
(
    command_line="*crontab -e*"
    OR command_line="*crontab -l*"
    OR command_line="*>> /etc/crontab*"
    OR command_line="*/etc/cron.d/*"
    OR command_line="*crontab*"
)
OR
(
    name="*/etc/cron.d/*"
    OR name="*/etc/crontab*"
    OR name="*/var/spool/cron/*"
)
| eval alert_name="Persistence - Suspicious cron modification",
    rule_id="SPL-09",
    mitre_technique="T1053.003",
    severity="medium",
    sigma_id="3a7a1520-c76a-4d8d-a73e-6dc75298e7c5",
    platform="Linux",
    datasource="Audit"
| collect index=siem_alerts 
```


### SPL-13. Privilege Escalation - setuid/setgid
Sigma rule: [sigma-rule-13](sigma-rules/linux/13-privilege-escalation-setuid-setgid.yaml)

Splunk alert:
```
index="linux_os" sourcetype="linux_audit"
(
    command_line="*chmod +s*"
    OR command_line="*chmod u+s*"
    OR command_line="*chmod 4755*"
    OR command_line="*chmod 2755*"
    OR command_line="*find / -perm -4000*"
    OR command_line="*find / -perm -u=s*"
)
| eval alert_name="Privilege Escalation - setuid/setgid",
    rule_id="SPL-13",
    mitre_technique="T1548.001",
    severity="high",
    sigma_id="0fae9ca7-b70b-403d-983e-d59b001818c8",
    platform="Linux",
    datasource="Audit"
| collect index=siem_alerts 
```


### SPL-14. Privilege Escalation - Sudo
Sigma rule: [sigma-rule-14](sigma-rules/linux/14-privilege-escalation-sudo.yaml)

Splunk alert:
```
index="linux_os" sourcetype="sudo"
(
    command_line="*/bin/bash*"
    OR command_line="*/bin/sh*"
    OR command_line="*chmod +s*"
    OR command_line="*nc -e*"
    OR command_line="*python3 -c*"
    OR command_line="*vim -c*"
    OR command_line="*less /etc/shadow*"
)
| eval alert_name="Privilege Escalation - Sudo",
    rule_id="SPL-14",
    mitre_technique="T1548.003",
    severity="high",
    sigma_id="114948fc-10f8-4901-85f9-bf42c8ea189f",
    platform="Linux",
    datasource="Sudo"
| collect index=siem_alerts
```


### SPL-16. Credential Access - SSH Bruteforce
Sigma rule: [sigma-rule-16](sigma-rules/linux/16-credential-access-brute-force-linux.yaml)

Splunk alert:
```
index="linux_os" sourcetype="sshd"
authentication_action="*Failed password*"
| bin _time span=5m
| stats count by user _time
| where count > 10
| eval alert_name="Credential Access - SSH Bruteforce",
    rule_id="SPL-16",
    mitre_technique="T1110",
    severity="high",
    sigma_id="e518646b-495a-457f-8fa9-1fbb5bf76f2c",
    platform="Linux",
    datasource="Sshd"
| collect index=siem_alerts 
```


### SPL-18. Discovery - Linux account enumeration
Sigma rule: [sigma-rule-18](sigma-rules/linux/18-discovery-account-linux.yaml)

Splunk alert:
```
index="linux_os" sourcetype="linux_audit"
(
    command_line="*/etc/passwd*"
    OR command_line="*/etc/shadow*"
    OR command_line="*getent passwd*"
    OR command_line="*id -a*"
    OR command_line="*w -h*"
    OR command_line="*lastlog*"
)
| eval alert_name="Discovery - Linux account enumeration",
    rule_id="SPL-18",
    mitre_technique="T1087",
    severity="low",
    sigma_id="96d0a298-2714-4842-95a5-db4b7eaaca78",
    platform="Linux",
    datasource="Audit"
| collect index=siem_alerts  
```


### SPL-21. Lateral Movement - outbound SSH Connection
Sigma rule: [sigma-rule-21](sigma-rules/linux/21-lateral-movement-ssh.yaml)

Splunk alert:
```
index="linux_os" sourcetype="sshd"
authentication_action="*Accepted password*"
| eval alert_name="Lateral Movement - outbound SSH Connection",
    rule_id="SPL-21",
    mitre_technique="T1021.004",
    severity="low",
    sigma_id="f3404019-e217-4cc9-b19d-3fd5d6a5f817",
    platform="Linux",
    datasource="Sshd"
| collect index=siem_alerts 
```


### SPL-26. Execution - Reverse Shell
Sigma rule: [sigma-rule-26](sigma-rules/linux/26-unix-shell-yara.yaml)

Splunk alert:
```
index="linux_os" sourcetype="yara"
alert_name="*Linux_Reverse_Shell_Indicators*"
| eval alert_name="Execution - Reverse Shell",
    rule_id="SPL-26",
    mitre_technique="T1059.004",
    severity="critical",
    sigma_id="8423de65-4aa3-4ca8-807a-989acb164c13",
    platform="Linux",
    datasource="YARA"
| collect index=siem_alerts
```


### SPL-27. Execution - Python Backdoor
Sigma rule: [sigma-rule-27](sigma-rules/linux/27-execution-python-yara.yaml)

Splunk alert:
```
index="linux_os" sourcetype="yara"
alert_name="*Python_Backdoor_Indicators*"
| eval alert_name="Execution - Python Backdoor",
    rule_id="SPL-27",
    mitre_technique="T1059.006",
    severity="high",
    sigma_id="02de2b02-ea38-439a-8099-a9d987d509c7",
    platform="Linux",
    datasource="YARA"
| collect index=siem_alerts 
```