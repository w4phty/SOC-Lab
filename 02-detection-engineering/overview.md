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


2. Normalisation des champs

tests dans splunk, création du mapping dans props.conf (lien vers une copie du fichier)
et des regex dans transforms.conf (lien vers une copie du fichier)

ajout d'un macro pour auditd command line
rex max_match=0 field=_raw "(?<arg_field>a\d+)=(?<arg>[^\s]+)"
| eval arg=trim(arg,"\"")
| eval pair=mvzip(arg_field,arg,"=")
| mvexpand pair
| rex field=pair "(?<arg_field>a\d+)=(?<arg>.*)"
| eval pos=tonumber(replace(arg_field,"a",""))
| eval decoded_arg=if(match(arg,"^[0-9A-Fa-f]+$"),
                      urldecode(replace(arg,"([0-9A-Fa-f]{2})","%\1")),
                      arg)
| sort 0 _time pos
| stats list(decoded_arg) AS args by _time
| eval decoded_cmd=mvjoin(args," ")

3. Ecriture des règles sigma
-> basé sur les champs mappés
-> mapping MITRE, et fichier pour le lookup

!!! revoir les liens vers les fichiers sigma depuis les fichiers alertes splunk

4. transformation des règles sigma en règles splunk
-> script d'automatisation custom sigma -> splunk
-> enregistrement des alertes dans splunk
Schedule : toutes les 5 minutes
Time range : Last 5 minutes
Trigger condition : Number of Results > 0
Trigger : Once (une seule fois par exécution de la recherche)
-> avec splunk free pas possible d'enregistrer des alertes récurrente
méthode: enregistrer un report, le lancer avec un timerange correspondant au début de l'attaque pour éviter les doublons
lien fichiers spl qui contiennent les reports

à la fin des reports:
| eval _raw="alert_name=\"".alert_name."\" rule_id=\"".rule_id."\" mitre_technique=\"".mitre_technique."\" severity=\"".severity."\" sigma_id=\"".sigma_id."\" platform=\"".platform."\" datasource=\"".datasource."\""
| collect index=siem_alerts
et besoin d'ajouter des regex pour lire les champs

!!! ajouter le mapping des timestamp pour les avoir dans les alertes

ici alertes arrivent dans stash, ok pour lab mais en environnement réel, il faudrait une vraie datasource

ajouter screenshot alert fields

5. tests de toutes les règles et vérification de la remontée des alertes

6. création des dashboards

screenshots des dashboards