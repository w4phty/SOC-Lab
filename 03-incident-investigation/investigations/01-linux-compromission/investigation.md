# Investigation

## Reconnaissance

### Detection 

Network recon related alerts are detected based on Suricata detection rules. They trigger when large SYN TCP traffic is detected in a short amount of time. Both alerts SPL-01 and SPL-19 are based on the same Suricata detection rule.

![Figure-01](./evidence/04-alerts-reconnaissance.PNG)

_Figure-01: Reconnaissance alerts_

### Host Discovery 

We pivot to Zeek connection logs using the source IP address (10.10.10.1) and the timestamp (18:12:53) observed in the alerts as pivot fields. The SPL request is as follows:
```
index="monitoring" sourcetype="*zeek*" src_ip="10.10.10.1" dest_ip="*"
| stats count by dest_ip
```
zeek logs show the following connection around the time of the alerts:
| dest_ip | count
| - | -
| 10.10.10.2 | 747
| 10.10.10.4 |	1


Packet-level telemetry is reviewed to validate the network activity associated with the alerts.

The packet capture shows ARP requests originating from 10.10.10.1 and targeting the 10.10.10.0/24 subnet. Only two hosts respond to the ARP requests in the captured traffic (10.10.10.2 and 10.10.10.4). The two TCP SYN packets followed by RST/ACK responses correspond to the active hosts identified during discovery and explain the traffic that triggered the first Suricata SYN-scan alert at 18:12. The host discovery scan itself was not detected.

![Figure-02](./evidence/01-discovery-traffic-analysis.PNG)

_Figure-02: Packet-level evidence of network host discovery_

### Port Discovery

Following the host discovery, the packet capture shows TCP SYN requests originating from 10.10.10.1 and targeting 10.10.10.2 on a wide range of port numbers. This can be associated with a port scan targeting the 10.10.10.2 host. A few ports responded with the SYN/ACK flags and are probably opened (21, 22, 139, 445), indicating that FTP, SSH, SMB-related services are exposed and could be investigated by an attacker.
Wireshark request to find open ports responding to the port scan:
`ip.src == 10.10.10.2 && tcp.flags.syn == 1 && tcp.flags.ack == 1`

![Figure-03](./evidence/02-service-discovery-traffic-analysis.PNG)

_Figure-03: Packet-level evidence of service discovery on the targeted host_

### Service Interaction

The packet capture also shows an FTP connection immediately after the Service discovery scan ends. The connection is initiated from 10.10.10.1, and does not lead to a successful connection to the ftp server. However the banner `Welcome to charlie's FTP service.` is shown to the user that initiated the connection. This connection is not detected in the SIEM.

![Figure-04](./evidence/03-ftp-traffic-analysis.PNG)

_Figure-04: Packet-level evidence of an FTP connection on the targeted host_


### Conclusion

Both SPL-01 and SPL-19 are confirmed as true positives. Packet-level and Zeek telemetry show reconnaissance activity originating from 10.10.10.1 against 10.10.10.2, including host discovery followed by a TCP SYN port scan. The scan identified several exposed services, including FTP, SSH, and SMB. The packet capture also shows a subsequent FTP connection that did not result in a successful session. 


## Initial access

### Detection

SSH related alerts are detected based on sshd logs. The SPL-16 alert is triggered when a large number of failed connection attempt concerning the same user. The SPL-21 alert is triggered when an SSH connection is successfully established.

![Figure-05](./evidence/05-alerts-initial-access.PNG)

_Figure-05: SSH related Alerts_

### SSH Bruteforce

We pivot to sshd logs using the pivot fields user (charlie) and the timestamp (18:15:00) to define the investigation window. The sshd logs show a high volume of failed connection around the alert timestamp.

![Figure-06](./evidence/06-failed-ssh-logins.PNG)

_Figure-06: Failed SSH logins_


This SPL request is executed to get indicators about the brute force attempt:
```
index="linux_os" sourcetype="sshd" user=charlie
| stats 
    count(eval(match(_raw,"Failed password|authentication failure"))) as failures
    min(_time) as first_attempt
    max(_time) as last_attempt
  by src_ip
| convert ctime(first_attempt) ctime(last_attempt)
```

The result shows requests originating from a single IP address (10.10.10.1).
| src_ip |	failures |	first_attempt |	last_attempt
| - | - | - | -
| 10.10.10.1 |	208 |	08/29/2026 18:17:25 |	08/29/2026 18:18:22

### Succesful SSH connection

Sshd logs show that 2 succesffull SSH connection are established for the user charlie, originating from the src_ip 10.10.10.1, respectively at 18:18:22.000 and 18:19:00.000 when looking for the keywords "Accepted password". 

However, the pam events show 3 successive ssh sessions concerning the targeted account.

![Figure-07](./evidence/07-ssh-sessions.PNG)

_Figure-07: SSH sessions_

The first session was opened and closed almost immediately after the successful authentication. It is consistent with the brute-force tool validating the discovered credentials, as its timestamp immediately follows the last observed failed authentication attempt. (18:18:22).

The second session was opened shortly after and closed almost 30 minutes later, using the compromised account. This indicates that an SSH session was established using the compromised account. The start time of this session matches the timestamp of the first SSH connection alert (18:19:00).

A third session was established before the second session was closed, also using the compromised account. However, this session timeline does not match with any SSH alerts. The reason why this session was not detected will be investigated as the timeline progresses.

### Conclusion

Both SPL-16 and SPL-21 are confirmed as true positives. A bruteforce attack is observed, originating from the source IP address 10.10.10.1, and targeting the user account charlie, with 208 failed connection attempts within 57 seconds. A subsequent successful authentication was observed, indicating that a valid user/password combination was used. Three sessions associated with the compromised account are identified. The second session stayed open for about 30 minutes. The third session was not detected in the SIEM. 


## Discovery

## Privilege escalation

## Persistence

## Exfiltration