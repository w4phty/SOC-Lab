# Playbook de threat hunting — Beacon C2 Python custom
## Balisage périodique HTTP vers serveur Flask attaquant, exécution de commandes à la demande

**Statut du document** : experimental (lab SOC personnel)
**Nature de ce document** : contrairement aux trois playbooks précédents (réponse à alerte), celui-ci est un **playbook de threat hunting** — la démarche part d'une hypothèse à vérifier, pas d'une alerte qui se déclenche. C'est une différence méthodologique volontaire et assumée dans ce document, pas un oubli de détection.

---

## 0. Pourquoi ce scénario ne déclenche (probablement) aucune alerte existante

À dire explicitement dans le rapport, plutôt que de le découvrir en cours de route :

- Le canal de communication est un **protocole applicatif custom** (requêtes HTTP vers un serveur Flask maison) : aucune signature Suricata connue (ni communautaire ET, ni tes règles custom) ne correspond à ce trafic, qui ressemble structurellement à n'importe quel appel HTTP légitime.
- Les commandes exécutées **par** le beacon sur l'hôte (une fois reçues) génèrent des événements EXECVE/Sysmon tout à fait normaux — rien ne les distingue *a priori* d'une commande tapée par un administrateur, sauf le contexte (absence de session interactive correspondante, timing corrélé au beaconing).
- **Conséquence méthodologique** : la détection ne peut pas venir d'une règle basée sur une signature de contenu. Elle doit venir d'une **analyse comportementale** — régularité du trafic (beaconing), volumétrie, et corrélation temporelle entre balisage réseau et exécution de commandes côté hôte.

---

## 1. Vue d'ensemble et mapping ATT&CK

| # | Comportement | Tactique MITRE | Technique | Code |
|---|---|---|---|---|
| 1 | Balisage périodique (check-in régulier) | Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| 2 | Encodage des communications (si le beacon encode ses échanges) | Command and Control | Data Encoding: Standard Encoding | T1132.001 |
| 3 | Exécution des commandes reçues du C2 | Execution | Command and Scripting Interpreter | T1059.004 (Linux) / T1059.001 (Windows) |
| 4 | Retour des résultats de commande au C2 | Command and Control | (même canal que #1) | T1071.001 |

---

## 2. Phase 1 — Formuler l'hypothèse de chasse

Une chasse commence par une hypothèse falsifiable, pas par "je regarde les logs et je verrai bien". Ici :

> **Hypothèse** : si un implant C2 est présent sur le réseau, il génère des connexions sortantes périodiques (beaconing) vers une même destination, avec un intervalle de temps régulier, indépendamment de toute activité utilisateur — un comportement statistiquement différent du trafic web humain (irrégulier, en rafales, corrélé aux heures de bureau/à l'activité de la souris/clavier).

Cette hypothèse guide directement la méthode de la phase suivante : on ne cherche pas un contenu suspect, on cherche une **régularité statistique**.

---

## 3. Phase 2 — Détection de la régularité (beaconing) via Zeek conn

**Source** : Zeek conn (`src_ip`, `dest_ip`, `src_port`, `dest_port`, `protocol`, `duration`, `conn_status`).

> ⚠️ Rappel de gap déjà connu : `orig_bytes`/`resp_bytes` ne sont pas mappés dans ce lab — l'analyse classique de beaconing s'appuie souvent aussi sur une taille de payload constante en plus de la régularité temporelle. On travaille donc uniquement sur l'intervalle de temps entre connexions, ce qui reste largement suffisant pour ce cas.

### Méthode
1. Isoler toutes les connexions sortantes vers chaque IP externe/inhabituelle distincte, sur la fenêtre d'analyse.
2. Pour chaque paire (`src_ip`, `dest_ip`), calculer l'écart de temps entre connexions successives.
3. Une régularité marquée (écarts quasi identiques, faible variance) est le signal recherché — un utilisateur humain ne génère jamais des requêtes à intervalles aussi constants.

### Requête SPL (reproductible)
```spl
index=network sourcetype=zeek_conn
| sort src_ip, dest_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval delta_seconds = _time - prev_time
| where isnotnull(delta_seconds)
| stats count as nb_connexions, avg(delta_seconds) as intervalle_moyen, stdev(delta_seconds) as ecart_type by src_ip, dest_ip
| eval coefficient_variation = round(ecart_type / intervalle_moyen, 3)
| where nb_connexions > 10
| sort coefficient_variation
```
Un `coefficient_variation` proche de 0 = intervalle très régulier = signal de beaconing fort. C'est la même logique que l'outil open-source RITA (AI Beacon Score), simplifiée en SPL pur.

### Résultat attendu
Une paire (`src_ip` = hôte victime, `dest_ip` = serveur Flask attaquant) avec un nombre de connexions élevé et un coefficient de variation faible se détache nettement du reste du trafic — c'est ta cible d'investigation.

### Décision
Dès qu'une paire se détache clairement, basculer vers l'analyse pcap détaillée (phase 3) pour confirmer et qualifier le contenu.

---

## 4. Phase 3 — Analyse détaillée du trafic (Wireshark / tshark)

C'est ici que se fait la majorité du travail, comme tu l'anticipais.

### 4.1 Confirmer la régularité au niveau paquet

```bash
tshark -r capture.pcap -Y "ip.addr==<ip_c2> and tcp.port==<port>" -T fields -e frame.time_epoch -e ip.src -e ip.dst
```
Exporter vers un tableur ou un script Python (`pandas`) pour calculer et visualiser les deltas entre requêtes — un histogramme des intervalles rend la régularité immédiatement visible (pic net autour d'une valeur, contrairement à une distribution étalée pour du trafic humain).

### 4.2 Examiner le contenu applicatif (si HTTP en clair — cas le plus probable pour un beacon custom simple)

```bash
# Lister toutes les requêtes vers le serveur C2
tshark -r capture.pcap -Y "http and ip.dst==<ip_c2>" -T fields -e frame.time -e http.request.method -e http.request.uri -e http.user_agent

# Extraire le corps des requêtes/réponses (commandes envoyées, résultats renvoyés)
tshark -r capture.pcap -Y "http and ip.dst==<ip_c2>" -T fields -e http.file_data
```

**Points à observer :**
- **User-Agent** : un beacon custom utilise souvent le User-Agent par défaut de la librairie HTTP (`python-requests/x.x.x`) — signal fort, très rarement vu dans du trafic navigateur légitime.
- **URI** : motif fixe/répétitif (`/checkin`, `/task`, `/beacon`...) plutôt que la diversité d'URLs d'une navigation normale.
- **Structure des requêtes** : GET répétés pour le "check-in" (polling), suivis de POST quand une commande est disponible et exécutée — le motif GET/GET/GET/POST/GET/GET... est lui-même un signal.
- **Encodage** : si le corps des requêtes/réponses est en base64 ou autre encodage simple, le décoder pour lire les commandes/résultats en clair (`base64 -d` sur le contenu extrait).

### 4.3 Si le beacon utilise HTTPS (TLS)

Contenu applicatif invisible, mais la régularité temporelle (phase 2) reste exploitable, et le TLS lui-même laisse des métadonnées utiles :
```bash
tshark -r capture.pcap -Y "tls.handshake.type==1 and ip.dst==<ip_c2>" -T fields -e tls.handshake.extensions_server_name -e tls.handshake.ja3
```
Un JA3 (empreinte de la stack TLS cliente) inhabituel ou ne correspondant à aucun navigateur/outil connu du parc est un signal indépendant de la régularité — à documenter même si non exploité plus loin dans ce lab.

### Décision
Régularité confirmée + motif applicatif cohérent avec du polling C2 (User-Agent d'une librairie, URI fixe, alternance GET/POST) → passer en confirmation host-side.

---

## 5. Phase 4 — Corrélation côté hôte (auditd / Sysmon)

**Objectif** : confirmer que l'hôte identifié en phase 2/3 exécute effectivement des commandes en cohérence temporelle avec le trafic réseau observé — c'est ce qui transforme "trafic suspect" en "compromission confirmée".

### Méthode
1. Prendre les horodatages des requêtes POST identifiées en phase 3 (probables "livraisons de commande").
2. Chercher dans auditd EXECVE (`command_line`, via ton lookup `execve_decode`) tout process lancé dans une fenêtre de quelques secondes autour de chaque POST.
3. Vérifier le parent du process (`comm`/`executable`) : si le process du beacon lui-même (ex: `python3 beacon.py`) apparaît comme parent des commandes exécutées, c'est la confirmation directe du lien entre canal réseau et exécution locale.

### Requête SPL
```spl
index=linux_os sourcetype=linux_audit type=EXECVE
| eval command_line=... (via ton lookup execve_decode)
| where _time > "<horodatage_POST_debut>" AND _time < "<horodatage_POST_fin>"
| table _time, hostname, command_line
```

### Sur Windows (si l'hôte cible est Windows)
```spl
index=windows sourcetype=WinEventLog:Sysmon EventCode=1
| where _time > "<horodatage_POST_debut>" AND _time < "<horodatage_POST_fin>"
| table _time, hostname, parent_executable, executable, command_line
```

### Pivot endpoint (si le processus tourne encore)
```bash
# Linux
ps auxf | grep -i python
ss -tnp | grep <port_c2>
```
```powershell
# Windows
Get-Process | Where-Object {$_.ProcessName -match "python"}
Get-NetTCPConnection -RemoteAddress <ip_c2>
```

### Décision
Process du beacon identifié et actif → passer directement en confinement (section 7), le canal est toujours ouvert.

---

## 6. Phase 5 — Reconstituer la timeline complète des commandes exécutées via le C2

### Méthode
Pour chaque requête POST identifiée en phase 3 (commande livrée) : associer la commande décodée (si visible dans le trafic, phase 3) avec le process EXECVE correspondant côté hôte (phase 4) — les deux doivent correspondre. S'ils divergent, creuser (possible commande non exécutée, échec, ou méthode d'exécution différente de celle attendue).

Cette table devient la pièce centrale de `investigation.md` pour ce scénario :

| Horodatage | Requête réseau (URI/contenu) | Commande décodée | Process EXECVE correspondant | Résultat renvoyé au C2 |
|---|---|---|---|---|
| | | | | |

### Décision
Une fois la timeline complète reconstituée, évaluer l'étendue de ce que l'attaquant a pu faire via ce canal (les commandes exécutées disent tout — reconnaissance seule ? collecte de données ? tentative de persistence ?). Si les commandes recoupent des techniques déjà vues dans les autres playbooks (ex: `cat /etc/shadow`, création de tâche planifiée), fusionner ce dossier avec le playbook concerné à partir de la phase correspondante.

---

## 7. Détection live, confinement, éradication, remédiation

### 7.1 Détection live
```bash
# Linux — process et connexion actifs
ps auxf | grep -i python
ss -tnp | grep <ip_c2>
lsof -i -P -n | grep <ip_c2>
```
```powershell
# Windows
Get-Process | Where-Object {$_.ProcessName -match "python"}
Get-NetTCPConnection -RemoteAddress <ip_c2>
```

**Vérifier un mécanisme de persistence du beacon lui-même** (non précisé dans le scénario — à investiguer, ne pas assumer) :
```bash
crontab -l; cat /etc/crontab; ls -la /etc/cron.d/
systemctl list-unit-files --state=enabled | grep -vE '^(systemd|cron|ssh|network)'
```
```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}
Get-CimInstance Win32_Service | Where-Object {$_.PathName -match "python"}
```

### 7.2 Confinement
```bash
# Couper la connexion active / tuer le process du beacon
kill -9 <pid_beacon>
iptables -A OUTPUT -d <ip_c2> -j DROP
```
```powershell
Stop-Process -Id <pid_beacon> -Force
New-NetFirewallRule -DisplayName "Block-C2" -Direction Outbound -RemoteAddress <ip_c2> -Action Block
```

### 7.3 Éradication
```bash
# Supprimer le script/binaire du beacon (chemin identifié en phase 4)
rm -f <chemin_beacon>
# Supprimer toute persistence trouvée en 7.1
crontab -e   # retrait manuel de l'entrée si trouvée
systemctl disable --now <service_trouvé>; rm -f /etc/systemd/system/<service_trouvé>
```

### 7.4 Vérification post-remédiation
```bash
ps auxf | grep -i python        # doit être vide
ss -tnp | grep <ip_c2>          # doit être vide
```
Puis rejouer la requête SPL de la phase 2 (recherche de beaconing) sur une fenêtre postérieure à la remédiation — le coefficient de variation ne doit plus révéler cette paire `src_ip`/`dest_ip`.

---

## 8. Actions de suivi recommandées

1. **Haute** — industrialiser la requête SPL de détection de beaconing (section 3) en recherche planifiée régulière plutôt qu'en hunt ponctuel : c'est un des rares cas où une approche analytique généraliste (pas une signature) apporte une vraie valeur de détection durable.
2. **Moyenne** — si l'organisation dispose d'un outil dédié (Zeek + RITA, ou équivalent commercial de détection de beaconing), le mentionner comme amélioration structurelle plutôt que de tout faire à la main en SPL.
3. **Moyenne** — envisager la capture systématique du JA3/JA3S pour tout trafic TLS sortant (nécessite Zeek avec le script JA3 activé, non configuré actuellement dans ce lab).
4. **Basse** — ajouter une règle Suricata générique sur les User-Agent de librairies HTTP courantes (`python-requests`, `curl`, `Go-http-client`) vus en trafic sortant vers des IP externes non répertoriées — signal faible seul, mais utile en corrélation.

---

## 9. Template — Evidence & Timeline Tracker

Identique aux autres playbooks, avec une colonne supplémentaire pour la preuve statistique de beaconing.

| Horodatage | Hôte | Source | Élément observé | Coefficient de variation (si applicable) | Technique MITRE | Analyste | Verdict |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
