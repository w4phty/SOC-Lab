## Detection Engineering

This section contains the detection engineering part of the lab. The main goal is to collect logs from Windows and Linux endpoints and from network activity, normalize the fields, create detection rules using Sigma, convert them to Splunk searches and display the results in Splunk dashboards.

The detection workflow is:

**Log Collection → Field Normalization → Sigma Rules → Splunk Alerts → Dashboards**


### Splunk setup

The lab uses Splunk (free version) as a SIEM. 
Four indexes are created: windows_os, linux_os, monitoring and siem_alerts. A receiving port is configured to receive all the logs forwarded by the endpoints and the monitoring machine of the lab. The lab uses the TCP port 9997.

After setting up the Splunk Forwarder on each endpoint, an additional step is required to allow incoming traffic on port 9997 to receive the logs:
```
netsh advfirewall firewall add rule name="Splunk 9997" dir=in action=allow protocol=TCP localport=9997
```

### Log collection

Log sources depend on each endpoint. For the [Windows endpoint](./01-collection/endpoint-1-windows.md), logs are collected from WinEventLog System and Security, Powershell logs, Sysmon, and YARA.
For the [Linux endpoint](./01-collection/endpoint-2-ubuntu.md), logs are collected from rsyslog, auditd, and YARA.
The [monitoring machine](./01-collection/monitoring-machine-setup.md) collects network logs with Zeek and Suricata.
All the logs are forwarded to the SIEM through Splunk Forwarder.

### Field normalization

The logs collected do not use the same field names depending on the data source. The goal of this step is to normalize the fields so that detection rules can use the same fields for different data sources.
Field normalization is done with the splunk configuration files [props.conf](./02-normalization/props.conf) and [transforms.conf](./02-normalization/transforms.conf). 

Audit records belonging to a single auditd event are split accross multiple log records of different types (SYSCALL, EXECVE, CWD, PATH). In order to properly rebuild each audit event from the forwarded logs, an additional [SPL report](./02-normalization/linux_auditd_aggregate) is required. The report aggregates the audit records by audit event id, and produces normalized logs in a dedicated sourcetype. The report can be run regularly by the analyst to update the normalized data used in alert detection. In an Enterprise Splunk version, the report can be replaced by a scheduled SPL search to automate the normalization process.


### Sigma Detection Rules

The detection rules are written using the Sigma format. The rules are based on the normalized fields and organized by platform and activity type. They can be found in the following directories:
- [03-sigma-rules/windows](./03-sigma-rules/windows/)
- [03-sigma-rules/linux](./03-sigma-rules/linux/)
- [03-sigma-rules/network](./03-sigma-rules/network/)


### Convert Sigma rules to Splunk searches

The Sigma rules are converted to splunk searches using the custom automation script [custom_sigma2splunk.py](./04-splunk-alerts/custom_sigma2splunk.py).
Since the lab uses the free version of Splunk, scheduled alerts cannot be used. 
To work around this limitation, the detection searches are saved as reports and executed using a time range corresponding to the beginning of the attack scenario being investigated.

The reports are created using the automation script [splunk_report_generator.py](./04-splunk-alerts/splunk_report_generator.py):
- [report-windows.spl](./04-splunk-alerts/report-windows.spl)
- [report-linux.spl](./04-splunk-alerts/report-linux.spl)
- [report-network.spl](./04-splunk-alerts/report-network.spl)
- [report-all.spl](./04-splunk-alerts/report-all.spl)

At this point, all alerts are tested. During the tests, we verify that the logs are properly collected, that the fields are normalized correctly, and that the alerts are raised as expected when running the reports.


### Splunk Dashboards

The dashboards are created based on the alerts stored in the `siem_alerts` index. The dashboards provide information on the detected activity. They include:
- Overview
- Threat Hunting
- Windows Security
- Linux Security
- Network Security
- Malware overview
- Investigation

A [lookup.csv](./05-dashboards/lookup.csv) file is used to enrich the alerts with MITRE ATT&CK Tactics and Techniques.

The dashboard screenshots and documentation are available in the directory [05-dashboards](./05-dashboards/).