## Windows alerts

### SPL-04. Execution - Powershell encoded commands or downloads
Sigma rule: [sigma-rule-04](sigma-rules/windows/04-execution-powershell.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
executable="*\powershell.exe"
AND
(
    command_line="*-EncodedCommand*"
    OR command_line="*-enc *"
    OR command_line="*-e *"
    OR command_line="*FromBase64String*"
    OR command_line="*DownloadString*"
    OR command_line="*IEX(*"
    OR command_line="*Invoke-Expression*"
    OR command_line="*-WindowStyle Hidden*"
    OR command_line="*-nop*"
)
| eval alert_name="Execution - Powershell encoded commands or downloads",
    rule_id="SPL-04",
    mitre_technique="T1059.001",
    severity="high",
    sigma_id="5710827d-9730-451b-8832-c19ef151a2bb",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts
```


### SPL-05. Execution - Windows Command Shell
Sigma rule: [sigma-rule-05](sigma-rules/windows/05-execution-windows-command-shell.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
executable="*\cmd.exe"
AND
(
    command_line="*whoami /all*"
    OR command_line="*net user /domain*"
    OR command_line="*net group "domain admins"*"
    OR command_line="*systeminfo*"
    OR command_line="*tasklist /v*"
    OR command_line="*& echo*"
    OR command_line="*/c powershell*"
)
| eval alert_name="Execution - Windows Command Shell",
    rule_id="SPL-05",
    mitre_technique="T1059.003",
    severity="medium",
    sigma_id="ba2b0f31-3eff-461b-a537-8a0e070ce817",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts
```


### SPL-08. User Execution - Suspicious process chain
Sigma rule: [sigma-rule-08](sigma-rules/windows/08-execution-malicious-user-execution.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(
    parent_executable="*\outlook.exe"
    OR parent_executable="*\chrome.exe"
    OR parent_executable="*\firefox.exe"
    OR parent_executable="*\msedge.exe"
    OR parent_executable="*\winword.exe"
    OR parent_executable="*\excel.exe"
    OR parent_executable="*\acrord32.exe"
)
AND
(
    executable="*\powershell.exe"
    OR executable="*\cmd.exe"
    OR executable="*\wscript.exe"
    OR executable="*\mshta.exe"
    OR executable="*\rundll32.exe"
)
| eval alert_name="User Execution - Suspicious process chain",
    rule_id="SPL-08",
    mitre_technique="T1204",
    severity="high",
    sigma_id="39fba7a7-0b5c-4cb2-9b64-6e6e8289efe6",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```


### SPL-10. Persistence - Scheduled task creation
Sigma rule: [sigma-rule-10](sigma-rules/windows/10-persistence-scheduled-task.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
executable="*\schtasks.exe"
AND
command_line="*/create*"
| eval alert_name="Persistence - Scheduled task creation",
    rule_id="SPL-10",
    mitre_technique="T1053.005",
    severity="medium",
    sigma_id="dfcaf5e0-0c1a-4d20-bae7-5adfd733faa1",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```


### SPL-11. Persistence - Wmic or powershell subscription events
Sigma rule: [sigma-rule-11](sigma-rules/windows/11-persistence-event-triggered-execution.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(executable="*\wmic.exe" AND command_line="*eventsubscription*")
OR
(executable="*\powershell.exe" AND (
    command_line="*Register-WmiEvent*"
    OR command_line="*__EventFilter*"
    OR command_line="*CommandLineEventConsumer*"
))
| eval alert_name="Persistence - Wmic or powershell subscription events",
    rule_id="SPL-11",
    mitre_technique="T1546",
    severity="medium",
    sigma_id="716e00cd-8006-445f-abd2-2f0f9954684a",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```

 
### SPL-12. Persistence - Windows user account creation
Sigma rule: [sigma-rule-12](sigma-rules/windows/12-persistence-create-account.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Security"
event_code="4720"
| eval alert_name="Persistence - Windows user account creation",
    rule_id="SPL-12",
    mitre_technique="T1136",
    severity="medium",
    sigma_id="a6abdb51-cbf2-49aa-a23d-bb0bc34a06eb",
    platform="Windows",
    datasource="Security"
| collect index=siem_alerts 
```


### SPL-15. Privilege Escalation - UAC workaround via known LOLBin
Sigma rule: [sigma-rule-15](sigma-rules/windows/15-privilege-escalation-uac-bypass.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(
    parent_executable="*\fodhelper.exe"
    OR parent_executable="*\eventvwr.exe"
    OR parent_executable="*\computerdefaults.exe"
    OR parent_executable="*\sdclt.exe"
)
AND
(
    executable="*\cmd.exe"
    OR executable="*\powershell.exe"
)
| eval alert_name="Privilege Escalation - UAC workaround via known LOLBins",
    rule_id="SPL-15",
    mitre_technique="T1548.002",
    severity="high",
    sigma_id="cc1386dd-3dcd-401a-889f-b93dd34a77c7",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```


### SPL-16. Credential Access - Windows account bruteforce
Sigma rule: [sigma-rule-16](sigma-rules/windows/16-credential-access-brute-force-windows.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Security"
event_code="4625"
| bin _time span=5m
| stats count by hostname _time
| where count > 10
| eval alert_name="Credential Access - Windows account bruteforce",
    rule_id="SPL-16",
    mitre_technique="T1110",
    severity="high",
    sigma_id="e518646b-495a-457f-8fa9-1fbb5bf76f2c",
    platform="Windows",
    datasource="Security"
| collect index=siem_alerts 
```


### SPL-17. Credential Access - credentials dumping
Sigma rule: [sigma-rule-17](sigma-rules/windows/17-credential-access-credential-dumping.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(
    command_line="*sekurlsa::logonpasswords*"
    OR command_line="*lsadump::sam*"
    OR command_line="*privilege::debug*"
    OR command_line="*kerberos::list*"
)
OR
(
    command_line="*procdump*"
    OR command_line="*lsass*"
)
| eval alert_name="Credential Access - credentials dumping",
    rule_id="SPL-17",
    mitre_technique="T1003",
    severity="critical",
    sigma_id="3207e611-4d94-4850-9aba-e43c33534171",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts  
```

 
### SPL-18. Discovery - Windows account enumeration
Sigma rule: [sigma-rule-18](sigma-rules/windows/18-discovery-account-windows.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(
    command_line="*net user*"
    OR command_line="*net localgroup administrators*"
    OR command_line="*net group "domain admins"*"
    OR command_line="*whoami /groups*"
    OR command_line="*Get-ADUser*"
    OR command_line="*Get-LocalUser*"
)
| eval alert_name="Discovery - Windows account enumeration",
    rule_id="SPL-18",
    mitre_technique="T1087",
    severity="low",
    sigma_id="96d0a298-2714-4842-95a5-db4b7eaaca78",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```

 
### SPL-20. Lateral Movement - RDP connection
Sigma rule: [sigma-rule-20](sigma-rules/windows/20-lateral-movement-rdp.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Security"
event_code="4624"
AND
logon_type="10"
| eval alert_name="Lateral Movement - RDP connection",
    rule_id="SPL-20",
    mitre_technique="T1021.001",
    severity="low",
    sigma_id="06c6b62c-234b-4482-8f56-c2c60c7afefc",
    platform="Windows",
    datasource="Security"
| collect index=siem_alerts 
```


### SPL-22. Lateral Movement - Alternative authentication indicator
Sigma rule: [sigma-rule-22](sigma-rules/windows/22-lateral-movement-alternate-authentication.yaml)

Splunk alert:
```
index="windows_os" sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(
    command_line="*sekurlsa::pth*"
    OR command_line="*over-pass-the-hash*"
    OR command_line="*/ptt*"
)
| eval alert_name="Lateral Movement - Alternative authentication indicators",
    rule_id="SPL-22",
    mitre_technique="T1550",
    severity="high",
    sigma_id="e079b92e-8797-49d2-aa94-8b24935fce88",
    platform="Windows",
    datasource="Sysmon"
| collect index=siem_alerts 
```


### SPL-28. Credential Access - Mimikatz
Sigma rule: [sigma-rule-28](sigma-rules/windows/28-credential-dumping-yara.yaml)

Splunk alert:
```
index="windows_os" sourcetype="yara"
alert_name="*Mimikatz_Indicators*"
| eval alert_name="Credential Access - Mimikatz",
    rule_id="SPL-28",
    mitre_technique="T1003",
    severity="critical",
    sigma_id="2ab9b86a-c229-45c6-85c2-ddb406876957",
    platform="Windows",
    datasource="YARA"
| collect index=siem_alerts 
```

 
### SPL-29. Execution - PowerShell Droppe
Sigma rule: [sigma-rule-29](sigma-rules/windows/29-powershell-dropper-yara.yaml)

Splunk alert:
```
index="windows_os" sourcetype="yara"
alert_name="*PowerShell_Dropper_Indicators*"
| eval alert_name="Execution - PowerShell Dropper",
    rule_id="SPL-29",
    mitre_technique="T1059.001",
    severity="high",
    sigma_id="389d33e5-02ac-4d73-b366-5ad1fdbbc9eb",
    platform="Windows",
    datasource="YARA"
| collect index=siem_alerts
```
