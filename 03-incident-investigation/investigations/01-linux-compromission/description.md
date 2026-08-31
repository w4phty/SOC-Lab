- scan nmap réseau -> doit déclencher alerte réseau
- scan de ports et services sur 10.10.10.2 > doit déclencher alerte réseau
- tentative de co ftp > ne déclenche pas d'alertes, visibles dans la capture réseau et les logs zeek, à corréler, voir que ça donne un username
- brute force ssh: doit déclencher alertes bruteforce et alerte lateral movement. visible dans la capture réseau aussi.
- co ssh avec le password trouvé: doit générer alerte lateral movement
- reconnaissance doit déclencher alerte de reconnaissance
- recherche élévation de privlège doit remonter plusieurs alertes, sur crontab et sur find / -perm -u=s
- execution de l'élévation de privilèges: ne remonte pas d'alertes mais permet de passer root, transition et commande visible dans les logs auditd
- création du script backup: doit remonter dans une alerte bash auditd et plus tard avec yara
- ajout dans crontab: doit générer alerte crontab
- ajout de clé ssh doit générer alerte clé ssh persistence, à corréler avec alerte co ssh juste après (test de la clé ssh ajoutée pour persistence)
- collecte de données : à chercher dans auditd
- exfiltration: doit remonter une alerte réseau, et visible dans zeek et capture réseau, Archive remonte une alerte mais pas shadow



actions à mettre en place:
surveillance de authorized_keys (règles auditd à ajouter, la règle actuelle n'est pas suffisante)