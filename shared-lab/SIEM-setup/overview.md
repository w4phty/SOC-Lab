SIEM Setup


1. Installation de Splunk
- installation
- config des index


Splunk
Splunk trial -> splunk free

username: admin
password: admin123

Ajouter un port d'écoute pour les logs envoyés par Splunk Forwarder:
Settings
→ Forwarding and Receiving
→ Configure Receiving
→ New Receiving Port
9997



Créer l'index:
Settings
→ Indexes
→ New Index
linux_os
-> New Index 
windows_os


vérifier que splunk forwarder est connecté:
sudo /opt/splunkforwarder/bin/splunk list forward-server

recherche dans splunk:
index=linux_os



splunk forwrder will start with account splunkfwd



param windows pour accepter traffic sur 9997:

netsh advfirewall firewall add rule name="Splunk 9997" dir=in action=allow protocol=TCP localport=9997

refaire liste de splunk: doit être OK