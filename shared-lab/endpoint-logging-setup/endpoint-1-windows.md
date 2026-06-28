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

The YARA pipeline detection will work as follows for this lab:
- Sysmon detects the creation of a new file
- An Event with the ID 11 is generated
- A task configured in the Task Scheduler detects this event
- The task triggers the invoke-yara.ps1
- YARA analyzes the detected file
- If a rule matches, an event log is created
- The log is sent to splunk through splunk universal forwarder

#### Installation

YARA is downloaded from `https://github.com/VirusTotal/yara/releases` and stored in the `C:\tools\yara\` directory.
Verify the version from a Command Prompt terminal with `> yara32.exe --version`.

#### YARA rules

The first YARA rule detects common mimikatz strings such as `sekurlsa::logonpasswords` which is a command that allows an attacker to extract cleartext passwords and NTLM hashes, `kerberos::list` which lists kerberos tickets or `lsadump::sam` which dumps hashes from the SAM database.


Here is the content of the first rule, stored in the `C:\tools\yara\rules\mimikatz.yar` file:
```
rule Mimikatz_Indicators
{
    meta:
        description = "Detects common Mimikatz strings"
        date = "2026-06-25"

    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa::logonpasswords" ascii nocase
        $s3 = "kerberos::list" ascii nocase
        $s4 = "privilege::debug" ascii nocase
        $s5 = "lsadump::sam" ascii nocase

    condition:
        2 of them
}
```

The second rule detects traces of a malicious powershell scripts, looking for techniques such as base64 encoding, remote script downloading, or executing code received as text.

Here is the content of the first rule, stored in the `C:\tools\yara\rules\powershell.yar` file:

```
rule PowerShell_Dropper_Indicators
{
    meta:
        description = "Detects powershell dropper indicators"
        date = "2026-06-25"

    strings:
        $s1 = "powershell -enc" ascii nocase
        $s2 = "FromBase64String" ascii nocase
        $s3 = "DownloadString" ascii nocase
        $s4 = "IEX(" ascii nocase
        $s5 = "Invoke-Expression" ascii nocase

    condition:
        2 of them
}
```

#### YARA script and scheduled task

Windows Event Log requires a log source to exist before any program can write entries to it. This means that we first need to create an Event Log source for YARA:
`New-EventLog -LogName Application -Source YARA`.

The next step is to create an `invoke-yara.ps1` script that will retrieve the file path of the last Sysmon Create File Event (ID 11), and if the extension matches one of the monitored extensions, the script runs YARA against the file. If YARA detects a match, the scan result is written to the Windows Event Log. Below is the content of the `C:\yara\scripts\invoke-yara.ps1` script:
```
$Event = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -MaxEvents 1

$Xml = [xml]$Event.ToXml()

$AllowedExt = @(".exe",".dll",".ps1",".bat",".vbs")

$TargetFile = (
    $Xml.Event.EventData.Data |
    Where-Object {$_.Name -eq "TargetFilename"}
).'#text'


if ($AllowedExt -contains [IO.Path]::GetExtension($TargetFile)) -and (Test-Path $TargetFile)
{
    $Result = & C:\tools\yara\yara32.exe `
        C:\tools\yara\rules\*.yar `
        $TargetFile

    if ($Result)
    {
        Write-EventLog `
            -LogName Application `
            -Source YARA `
            -EventId 9001 `
            -EntryType Warning `
            -Message $Result
    }
}
```

The execution policy needs to be updated to allow the execution of the script on the endpoint: `Set-ExecutionPolicy RemoteSigned -Scope LocalMachine`.

The scheduled task can now be created in the Task Scheduler. The task is named `SOC - YARA trigger`. The trigger is "On an event", based on the `Microsoft-Windows-Sysmon/Operational` log, using `Sysmon` source and Event ID 11.
The action program is `powershell.exe` with the arguments `-ExecutionPolicy Bypass -File C:\yara\scripts\invoke-yara.ps1`.


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

[WinEventLog://Application]
index=windows_os
sourcetype=yara
```

The last step is to restart the splunk forwarder in PowerShell:
```
> Restart-Service SplunkForwarder
```

To verify that the logs are accessible in Splunk, we use the Splunk instance configured in the SIEM setup section of this repository.
Any new event generated on the Windows endpoint should now be forwarded to Splunk and be searchable through the dashboard, with the index windows_os.
