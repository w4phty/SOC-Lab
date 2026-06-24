## Overview

The monitoring VM is already able to capture traffic on the internal network between the endpoints and the attacker, as specified in the architecture/network-overview.md file.
This VM is dedicated to monitoring the traffic, to do so the following tools are configured:
- Suricata, to detect suspicious activity and raise alerts. These alerts can be triggered when an attacker attempts to map the target network, through nmap scans, or to detect smb exploitation or command and control phases.
- Zeek, to log any network-related event. It is especially useful when recreating the timeline after an attack.

The log rotation is handled respectively by log management systems provided by Suricata and Zeek.

## Suricata

### Installation
```
$ sudo apt install suricata
$ suricata --build-info
```

For this lab, the version is 6.0.4.

### Configuration

First of all, Suricata needs to know which interface it will listen on. In this case, the `enp0s8` interface for the internal network. This can be specified in the file `/etc/suricata/suricata.yaml` under the option `af-packet`. The variable `$HOME_NET` needs to contain the internal network mask.

Use the following command to update the available Suricata rules: 
```
$ sudo suricata-update
```

Then, we need to know the default path where the rules are stored:
```
$ sudo grep rule-files /etc/suricata/suricata.yaml -A 20 -B 20
```
This gives `default-rule-path: /etc/suricata/rules`.
We can now create a new file in this directory for the custom rules of the lab: `/etc/suricata/rules/custom.rules`.


The following rules are added to the custom.rules file:
```
# Network scan detection (Discovery)
alert tcp any any -> $HOME_NET any (msg:"SOC-LAB Possible TCP SYN Scan"; flags:S; threshold:type both, track by_src, count 20, seconds 5; sid:1000001; rev:1;)


# Exe files download (Initial access)
alert http any any -> $HOME_NET any (msg:"Download EXE File"; flow:established,to_client; fileext:"exe"; sid:1000002; rev:1;)


# Cleartext credentials detection (Credentials exposure)
alert http any any -> any any (msg:"SOC-LAB Cleartext Credentials"; http.request_body; pcre:"/(password|passwd|pwd|token)=/i"; sid:1000003; rev:1;)


# DNS suspicious domains detection (Command and control, DNS extraction)

# DGA Domains (Domain Generation Algorithm domains)
alert dns $HOME_NET any -> any any (msg:"Possible DGA Domain"; dns.query; pcre:"/^[a-z0-9]{20,}\.(com|net|org)$/Ri"; sid:1000004; rev:1;)

#Long subdomains
alert dns $HOME_NET any -> any any (msg:"Long subdomain"; dns.query; pcre:"/^[A-Za-z0-9_-]{40,}\./"; sid:1000005; rev:1;)

# Base 64
alert dns $HOME_NET any -> any any (msg:"Possible base64 tunneling"; dns.query; pcre:"/[A-Za-z0-9+\/]{30,}={0,2}\./"; sid:1000006; rev:1;)
```

The `custom.rules` file needs to be specified in `suricata.yaml` under `rule-files`. Other default rules files can be added such as files, http-events, smb-events, smtp-events, nfs-events, kerberos-events, to widen the alert scope.

Now we can load the configuration with 
`$ sudo suricata -T -c /etc/suricata/suricata.yaml`. If successful, the output should be `Configuration provided was successfully loaded`.
The last configuration step is to restart Suricata: `$ sudo systemctl restart suricata`.


### Configuration check

To verify that alerts are effectively raised in Suricata, we first need to simulate a behavior that is supposed to be detected.
To do so, we run an Nmap scan from the Kali machine, targeting the Ubuntu endpoint:
```
$ nmap -sC -sV -e eth1 10.0.0.2 
```

Verify the alerts with:
```
$ cat /var/log/suricata/eve.json | grep scan
```
We should see the message specified in the custom.rules file: `SOC-LAB Possible TCP SYN Scan`.


## Zeek

### Installation

Installation is done following the steps from the Zeek official documentation on https://docs.zeek.org/en/master/install.html

```
$ echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
$ curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
$ sudo apt update
$ sudo apt install zeek-8.0
$ zeek --version
```

### Configuration

Update the interface in the `/opt/zeek/etc/node.cfg` file so that Zeek logs the traffic from the internal network:
```
[zeek]
type=standalone
host=localhost
interface=enp0s8
```

In the directory `/opt/zeek/bin`, we can deploy Zeek and verify its status:
```
$ sudo ./zeekctl deploy
$ sudo ./zeekctl status
$ sudo ./zeekctl check
```

Zeek logs are stored in the `/opt/zeek/logs/current` directory. As traffic flows, the following files should be written to: conn.log, dns.log, http.log, ssl.log, files.log

### Configuration check

Watch any incoming Zeek log with:
```
$ tail -f conn.log
```

Generate a ping from the Kali machine towards the Ubuntu Endpoint:
```
$ ping -I eth1 10.0.0.2
```

The generated ICMP traffic appears in the conn.log file. It is also worth noting that it also appears in the Suricata logs, if any configured suricata alert matches the event occuring.

## Splunk Forwarder

The Splunk Universal forwarder is installed following the same steps as specified in the /endpoint-logging-setup/endpoint-1-ubuntu.md file. The inputs are configured as follows:

```
[monitor:///var/log/suricata/eve.json]
index=monitoring
sourcetype=suricata

[monitor:///opt/zeek/logs/current/conn.log]
index=monitoring
sourcetype=zeek_conn

[monitor:///opt/zeek/logs/current/dns.log]
index=monitoring
sourcetype=zeek_dns

[monitor:///opt/zeek/logs/current/http.log]
index=monitoring
sourcetype=zeek_http
```

To access Zeek logs, elivated permissions are required. Therefore we need to add the user splunkfwd to the zeek group. The logs will now be owned by the zeek group, and it will have read and execution rights. This is done with the following commands:
```
$ sudo usermod -aG zeek splunkfwd
$ sudo chgrp -R zeek /opt/zeek/logs
$ sudo chmod -R g+rX /opt/zeek/logs
```

To verify that the logs are accessible in Splunk, we use the Splunk instance configured in the SIEM setup section of this repository.
Any generated traffic on the internal network should now be forwarded to Splunk and be searchable through the dashboard, with the index monitoring.