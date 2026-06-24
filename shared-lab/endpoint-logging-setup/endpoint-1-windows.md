## Overview

Events logged by Windows Event Log can be seen through the Event Viewer. Each event type is assigned to a unique event ID.

This Lab will forward the security logs and the system logs to the SIEM, to enable the monitoring of authentication, user and group management, and services.

The following Event IDs will be useful to detect malicious activity:
- Successful Logon (4624) and Failed Logon (4625): to detect suspicious RDP/network logins, brute force or password spraying
- User account created (4720), enabled (4722), changed (4738): an attacker may create a backdoor account or enable an old account
- User account disabled (4725) or deleted (4726): an attacker may disable privileged legitimate accounts to slow down the security team
- User password change (4723) or reset (4724): an attacker could reset a password to gain access to the targeted account
- User added to a local security group (4732) or removed from a local security group (4733): to detect potential backdoors added to privileged groups such as the Administrators group

To look up any event ID, we can use the following resource: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/


Powershell history is stored in the PSReadLine history file: `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`. However in this lab, the monitoring will rely on PowerShell Operational logs, rather than the command history. Script Block Logging and Module Logging are not enabled in this lab, only the default PowerShell Operational logs are collected.

In this Lab, we will configure Sysmon to provide more detailed logs, and install the Splunk Universal Forwarder to forward logs to the SIEM.

## Sysmon

Sysmon is a free tool from the Microsoft Sysinternals suite. Once installed, Sysmon logs are found in Event Viewer under Applications & Services -> Microsoft -> Windows -> Sysmon -> Operational. It provides very detailed logs, whereas native Windows logs provide limited data for each event.

The following event IDs will be specifically useful:
- Event ID 1 for process creation which gives process information, binary information, parent information and user context
- Event ID 11 for file creation and 13 for registry value set, to detect files dropped by malware or its changes to the registry, used for persistence
- Event ID 3 for network connection and 22 for DNS query, to detect traffic from untrusted processes or to known malicious destinations


#### Sysmon installation and configuration:
- Sysmon must be downloaded from the Sysinternals website
- We also need a configuration file, to define which events will be captured and the filter rules to balance log volume and visibility. The configuration file used for the lab is from the SwiftOnSecurity Github repository: https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml
- Rename the configuration file as sysmonconfig.xml, open a Command Prompt and load the configuration:
```
> Sysmon64.exe -accepteula -i sysmonconfig.xml
```


#### Sysmon verifications:
- Verify the loaded configuration:
```
> sysmon64 -c
```
- The service should be running, it can be checked with PowerShell:
```
> Get-Service Sysmon64
```
- Verify that logs are being generated:
```
> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```


## Yara

Pipeline yara


## Splunk Universal Forwarder

The Splunk Universal Forwarder must be downloaded from the Splunk website.
Following the MSI installer steps, we configure the receiving Indexer with the IP and port of the machine hosting the Splunk Indexer (192.168.1.52:9997).

To check that the service is running, type the following in PowerShell:
```
> Get-Service SplunkForwarder
```
And in a Command Prompt, verify that the logs are forwarded as configured:
```
> cd "C:\Program Files\SplunkUniversalForwarder\bin"
> splunk list forward-server
```
The output should be:
```
Active forwards:
    192.168.1.52:9997
```


Then create the file `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf` with the following content, to specify which logs will be forwarded to Splunk:

```
[WinEventLog://Security]
disabled = 0
index = windows_os
current_only = 0

[WinEventLog://System]
disabled = 0
index = windows_os
current_only = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows_os
current_only = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows_os
current_only = 0
```

The last step is to restart the splunk forwarder in PowerShell:
```
> Restart-Service SplunkForwarder
```

To verify that the logs are accessible in Splunk, we use the Splunk instance configured in the SIEM setup section of this repository.
Any new event generated on the Windows endpoint should now be forwarded to Splunk and be searchable through the dashboard, with the index windows_os.
