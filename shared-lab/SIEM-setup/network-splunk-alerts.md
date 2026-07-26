## Network alerts

### SPL-01. Reconnaissance - TCP SYN port scan
Sigma rule: [sigma-rule-01](sigma-rules/network/01-reconnaissance-active-scanning.yaml)

Splunk alert:
```
index="monitoring" sourcetype="suricata"
alert_signature="*Possible TCP SYN Scan*"
| eval alert_name="Reconnaissance - TCP SYN port scan",
    rule_id="SPL-01",
    mitre_technique="T1595",
    severity="medium",
    sigma_id="031fe431-9cd8-45ca-b65d-7a4198f5f843"
| collect index=siem_alerts 
```


### SPL-03. Initial Access - Executable file download
Sigma rule: [sigma-rule-03](sigma-rules/network/03-intial-access-phishing.yaml)

Splunk alert:
```
index="monitoring" sourcetype="suricata"
alert_signature="*Download EXE File*"
| eval alert_name="Initial Access - Executable file download",
    rule_id="SPL-03",
    mitre_technique="T1566",
    severity="medium",
    sigma_id="af7ff266-98a5-4ef3-a94c-b6502f7ea96a"
| collect index=siem_alerts 
```


### SPL-19. Discovery - Network service discovery
Sigma rule: [sigma-rule-19](sigma-rules/network/19-discovery-network-service.yaml)

Splunk alert:
```
index="monitoring" sourcetype="suricata"
alert_signature="*Possible TCP SYN Scan*"
| eval alert_name="Discovery - Network service discovery",
    rule_id="SPL-19",
    mitre_technique="T1046",
    severity="medium",
    sigma_id="423b4887-328e-439d-bbf4-263169a10ad5"
| collect index=siem_alerts 
```


### SPL-23. Command and Control - C2 web traffic
Sigma rule: [sigma-rule-23](sigma-rules/network/23-command-and-control-web.yaml)

Splunk alert:
```
index="monitoring" sourcetype="suricata"
alert_signature="*Cleartext Credentials*"
| eval alert_name="Command and Control - C2 web traffic",
    rule_id="SPL-23",
    mitre_technique="T1071.001",
    severity="high",
    sigma_id="2683bc20-d66f-4950-bc14-6a9c2839883b"
| collect index=siem_alerts 
```


### SPL-24. Command and Control - DNS Tunneling or C2
Sigma rule: [sigma-rule-24](sigma-rules/network/24-command-and-control-dns.yaml)

Splunk alert:
```
index="monitoring" sourcetype="suricata"
(
    alert_signature="*Possible DGA Domain*"
    OR alert_signature="*Long subdomain*"
    OR alert_signature="*Possible base64 tunneling*"
)
| eval alert_name="Command and Control - DNS Tunneling or C2",
    rule_id="SPL-24",
    mitre_technique="T1071.004",
    severity="high",
    sigma_id="6c7c1bcc-9c31-4fed-a9b2-bd2051de9633"
| collect index=siem_alerts 
```


### SPL-25. Exfiltration - Web data transfer
Sigma rule: [sigma-rule-25](sigma-rules/network/25-exfiltration-web.yaml)

Splunk alert:
```
index="monitoring" sourcetype="zeek_conn"
(dest_port="443" AND duration>=30 AND orig_bytes>=5000000)
| eval alert_name="Exfiltration - Web data transfer",
    rule_id="SPL-25",
    mitre_technique="T1567",
    severity="medium",
    sigma_id="1f854909-8ff8-4200-b039-37327f6e4468"
| collect index=siem_alerts 
```