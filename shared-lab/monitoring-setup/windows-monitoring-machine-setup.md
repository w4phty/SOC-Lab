vérif que écoute ok: déjà fait


Suricata:
Suricata cherche des comportements malveillants à partir de règles.
exemples: scan nmap, exploitation smb, c2
-> Utile pour détection

sudo apt install suricata
vérifier:
suricata --build-info
-> donne suricata version 6.0.4

config:
sudo vim /etc/suricata/suricata.yaml
trouver et modifier la config de l'interface: doit écouter sur le réseau interne entre VM
af-packet:
  - interface: enp0s8
changer $HOME_NET

mettre à jour les règles:
- mettre à jour: sudo suricata-update

-> ajoute plusieurs règles par défaut

les règles suricata:
https://rules.emergingthreats.net/open/

Voir où les rules sont stockées:
sudo grep rule-files /etc/suricata/suricata.yaml -A 20 -B 20
doit donner le chemin des rules: default-rule-path: /etc/suricata/rules
créer un nouveau fichier pour ces rules custom:
/etc/suricata/rules/custom.rules

ajouter des règles existantes et des custom:
ajouter les règles dans un fichier custom.rules
puis ajouter dans suricata.yaml: 
rule-files:
  - local.rules

files; http-events, smb-events, smtp-events, nfs-events, kerberos-events

Règles à ajouter:
Donner la raison de chacune et le détail de la détection

- Détection scan Nmap (Reconnaissance)
alert tcp any any -> $HOME_NET any (
    msg:"SOC-LAB Possible Nmap SYN Scan";
    flags:S;
    threshold:type both, track by_src, count 20, seconds 5;
    sid:1000001;
    rev:1;
)

- Téléchargement fichiers exe (Initial access)
alert http any any -> $HOME_NET any (msg:"Download EXE File"; flow:established,to_client; fileext:"exe";
    sid:1000002; rev:1;)

- Détection de credentials en clair
alert http any any -> any any (
    msg:"SOC-LAB Cleartext Credentials";
    http.request_body;
    pcre:"/(password|passwd|pwd|token)=/i";
    sid:1000003;
    rev:1;
)

- Détection DNS C2: plus complexe, ensemble de quelques règles
Domaines longs: expliquer DGA
alert dns $HOME_NET any -> any any (
    msg:"Possible DGA Domain";
    dns.query;
    pcre:"/^[a-z0-9]{20,}\.(com|net|org)$/Ri";
    sid:1000004;
    rev:1;
)
Détecte des domaines du type :
xj7k2m9q4z8v1n5p3r2.com

sous domaines longs:
alert dns $HOME_NET any -> any any (
    msg:"Long subdomain";
    dns.query;
    pcre:"/^[A-Za-z0-9_-]{40,}\./";
    sid:1000005;
    rev:1;
)

Exemple :

aGVsbG93b3JsZGFiY2RlZmdoaWprbG1ub3BxcnN0.example.com

base64 dans la requete:
alert dns $HOME_NET any -> any any (
    msg:"Possible base64 tunneling";
    dns.query;
    pcre:"/[A-Za-z0-9+\/]{30,}={0,2}\./";
    sid:1000006;
    rev:1;
)

Exemple :

Y29uZmlkZW50aWFsZGF0YQ==.domain.com

Charger et tester la config:
sudo suricata -T -c /etc/suricata/suricata.yaml
doit donner: Configuration provided was successfully loaded

Redémarrer suricata:
sudo systemctl restart suricata

Vérifier les alertes dans suricata:


Générer du traffic
Nmap depuis Kali sur un endpoint
nmap -sC -sV -e eth1 10.0.0.2 

Vérifier les alertes:
tail /var/log/suricata/eve.json | grep scan
-> renvoit des alertes Possible network scan from 10.0.0.1 to 10.0.0.2

Zeek
Observe et journalise tout, observe le réseau mais ne cherche pas spécifiquement des attaques
-> Utile pour le contexte et investigation

Installation
follow steps for linux on https://docs.zeek.org/en/master/install.html
echo 'deb https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek-8.0
zeek --version

Config:
sudo vim /opt/zeek/etc/node.cfg

Modifier la config pour écouter sur la bonne interface:
[zeek]
type=standalone
host=localhost
interface=eth1


export PATH=$PATH:/opt/zeek/bin:/opt/zeek/sbin

Vérifier la configuration:
cd /opt/zeek/bin
sudo ./zeekctl check

Démarrer et vérifier zeek:
sudo ./zeekctl deploy
sudo ./zeekctl status
-> doit donner running

Logs zeek:
cd /opt/zeek/logs/current
doit avoir, au fur et à mesure du traffic:
conn.log
dns.log
http.log
ssl.log
files.log

Surveiller les logs: tail sur les fichiers concernés
tail -f conn.log

Vérification: ping de kali vers endpoint ubuntu
ping -I eth1 10.0.0.2

Note: la requête apparait aussi dans Suricata:
cat /var/log/suricata/eve.json | grep "10\."



Différence zeek et suricata et pourquoi il faut les 2:


ajout splunk forwarder:
[monitor:///var/log/suricata/eve.json]
index=suricata
sourcetype=suricata:json

[monitor:///opt/zeek/logs/current/conn.log]
index=zeek
sourcetype=zeek:conn

[monitor:///opt/zeek/logs/current/dns.log]
index=zeek
sourcetype=zeek:dns

[monitor:///opt/zeek/logs/current/http.log]
index=zeek
sourcetype=zeek:http


