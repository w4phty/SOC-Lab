# Playbook d'investigation — Intrusion Windows complète
## Scan nmap → Découverte SMB → Fuite d'identifiants → Connexion distante → Reconnaissance → Privesc (Unquoted Service Path) → Persistence (compte admin + scheduled task) → Collection → Exfiltration

**Statut du document** : experimental (lab SOC personnel)
**Portée** : hôte Windows (Family Edition, pas de RDP) — Sysmon, WinEventLog:Security/System/PowerShell/Application, YARA — corrélé au trafic réseau (Suricata/Zeek) et à la capture tcpdump brute (rétention 2 jours).
**Note d'outillage attaquant** : scan effectué avec `nmap` depuis la VM Ubuntu du lab (voir remarque en tête de conversation) — pas de script Python custom, la variante n'apporte rien à la détection.

---

## 0. Vue d'ensemble de la chaîne d'attaque

| # | Phase | Tactique MITRE | Technique | Code |
|---|---|---|---|---|
| 1 | Scan nmap de la machine | Reconnaissance | Active Scanning | T1595.001 / T1595.002 |
| 2 | Découverte + énumération SMB (partages RH, Backup) | Discovery | Network Share Discovery | T1135 |
| 3 | Identifiants trouvés dans un partage | Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 |
| 4 | Connexion distante avec les identifiants (SMB, pas RDP) | Lateral Movement / Initial Access | Remote Services: SMB/Windows Admin Shares / Valid Accounts | T1021.002 / T1078 |
| 5 | Reconnaissance interne (whoami, systeminfo, net user...) | Discovery | System Owner/User, System Info, Account, Permission Groups, Process, Share Discovery | T1033 / T1082 / T1087.001 / T1069.001 / T1057 / T1135 |
| 6 | Élévation de privilèges — Unquoted Service Path | Privilege Escalation | Hijack Execution Flow: Path Interception by Unquoted Path | T1574.009 |
| 7a | Persistence — création d'un compte administrateur local | Persistence | Create Account: Local Account | T1136.001 |
| 7b | Persistence — scheduled task avec reverse shell | Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| 8 | Collection — rassemblement et archivage des données | Collection | Archive Collected Data: Archive via Utility / Data from Local System | T1560.001 / T1005 |
| 9 | Exfiltration via Invoke-WebRequest | Exfiltration | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | T1048.003 |

**Continuité avec le playbook Linux** : les phases 7a et 6 réutilisent directement des règles Sigma déjà construites (`t1136_create_account.yml`, `t1053_005_scheduled_task.yml`) — bonne nouvelle, pas de nouvelle règle à écrire pour celles-ci. Les gaps connus (`LogonType` et `Account_Name` non mappés sur WinEventLog:Security) s'appliquent identiquement ici et sont rappelés à chaque phase concernée plutôt que redémontrés.

---

## 1. Principes d'utilisation (rappel)

Même structure que le playbook Linux : verdicts standardisés (`TP-Confirmed`, `TP-Contained`, `FP`, `Benign-Authorized`, `Suspicious-Monitoring`), tracker Evidence & Timeline à tenir à jour phase par phase (modèle en fin de document), toujours croiser au moins deux sources avant de conclure.

**Différence de méthode demandée pour ce document** : la corrélation pcap et les points de pivot vers l'endpoint sont intégrés **directement dans chaque phase**, pas dans une section séparée — pour que l'analyste n'ait pas à faire l'aller-retour entre deux parties du document en pleine investigation.

---

## 2. Phase 1 — Scan nmap de la machine (T1595.001 / T1595.002)

**Sources SIEM** : Suricata (`alert_signature`, `src_ip`, `dest_ip`).
**Règle Sigma existante** : `network/t1595_active_scanning.yml` (réutilisée telle quelle, aucune différence avec le scénario Linux à ce stade).

### Investigation SIEM
1. Identifier `src_ip`, la fenêtre temporelle, et confirmer que l'hôte Windows fait partie des cibles (`dest_ip`).
2. Vérifier si un scan de service/version (`-sC -sV`, donc trafic applicatif après le SYN scan) suit immédiatement — regarder les connexions Zeek conn sur les ports usuels Windows (135, 139, 445, 3389 même si RDP est désactivé ici — un scan touche quand même le port pour tester).

### Corrélation pcap
Le scan lui-même n'apporte pas grand-chose de plus en pcap qu'en Zeek/Suricata (motif de scan déjà visible en métadonnées). Utile seulement si on veut confirmer l'outil exact utilisé (signature TCP/IP caractéristique de nmap, options utilisées) :
```bash
tshark -r capture.pcap -Y "ip.addr==<ip_attaquant> and tcp.flags.syn==1 and tcp.flags.ack==0"
```

### Pivot endpoint
Aucun à ce stade — rien n'a encore touché la machine Windows elle-même au-delà du niveau réseau.

### Décision
Scan confirmé touchant les ports SMB → surveillance renforcée de l'hôte, sans action de confinement à ce stade seul.

---

## 3. Phase 2 — Découverte et énumération SMB (partages RH, Backup) (T1135)

**Sources SIEM** : Suricata (si des règles ET du ruleset communautaire couvrent l'énumération SMB — vérifier `alert_signature` contenant "SMB" pendant l'investigation, aucune règle custom dédiée actuellement), Zeek conn (`dest_port=445`).

> ⚠️ **Gap de détection** : aucune règle Sigma/Suricata custom ne couvre spécifiquement l'énumération de partages SMB dans ce lab. Seule la connexion au port 445 est visible en métadonnées. Recommandation : ajouter une règle Suricata sur les motifs `smb2.cmd` de type Tree Connect répétés depuis une même source en peu de temps (signature d'énumération), ou s'appuyer sur le ruleset Emerging Threats déjà chargé si une règle SMB enum y figure.

### Investigation SIEM
1. Confirmer la connexion `dest_port=445` depuis la `src_ip` du scan (phase 1), immédiatement après.
2. Chercher plusieurs connexions/rétablissements rapprochés vers ce port (signature d'énumération avec des outils type `smbclient`/`smb-enum-shares`, qui ouvrent et referment plusieurs sessions).

### Corrélation pcap — **valeur forte ici**
Le protocole SMB transite les noms de partages en clair au niveau protocolaire (Tree Connect Request/Response), même quand l'authentification est challenge-response (NTLM). Si le chiffrement SMB3 n'est pas activé sur cet hôte (à vérifier — probable dans ce lab), le pcap permet de **lister précisément quels partages ont été énumérés et dans quel ordre** :
```bash
tshark -r capture.pcap -Y "smb2.cmd==3" -T fields -e frame.time -e smb2.tree
```
C'est une preuve directe que l'attaquant a bien vu les partages "RH" et "Backup", même sans log applicatif Windows dédié.

### Pivot endpoint
Vérifier sur l'hôte Windows lui-même la configuration des partages et leurs permissions NTFS/partage effectives :
```powershell
Get-SmbShare
Get-SmbShareAccess -Name "RH"
Get-SmbShareAccess -Name "Backup"
```
Objectif : comprendre pourquoi un compte non-administrateur a pu lister/lire ces partages (mauvaise configuration ACL à corriger, pas juste un symptôme de l'incident).

### Recommandation
Activer l'audit de partage réseau (stratégie d'audit avancée Windows : *Audit File Share* + *Audit Detailed File Share*, EventID 5140/5145) — non activé par défaut, donc probablement absent de ce lab actuellement. Sans ça, aucune trace applicative Windows de l'accès aux partages n'existe, seul le pcap comble ce vide.

### Décision
Énumération SMB confirmée touchant des partages nommés "RH"/"Backup" (probabilité forte de données sensibles) → passer en investigation active, ne pas attendre la suite de la chaîne.

---

## 4. Phase 3 — Découverte d'identifiants dans un partage (T1552.001)

**Sources SIEM** : aucune source dédiée dans ce lab (pas d'EventID 5145 activé, pas de DLP). C'est la même limite que la phase 2.

> ⚠️ **Gap de détection** : sans audit de partage détaillé (5145) ni solution de classification de données, la lecture d'un fichier spécifique contenant des identifiants à l'intérieur d'un partage **n'est pas observable côté SIEM**.

### Corrélation pcap — **résout une partie du gap**
Si le fichier contenant les identifiants a été **téléchargé** (lu intégralement) via SMB non chiffré, son contenu est reconstructible depuis le pcap :
```bash
tshark -r capture.pcap -Y "smb2.filename contains \".txt\" or smb2.filename contains \".xlsx\" or smb2.filename contains \".docx\"" -T fields -e frame.time -e smb2.filename
# Puis reconstruction du contenu du fichier via l'export d'objets SMB de Wireshark :
tshark -r capture.pcap --export-objects smb,exported_files/
```
`--export-objects smb` reconstruit littéralement les fichiers transférés sur disque — c'est la preuve la plus forte disponible dans ce lab pour cette phase, à documenter avec le hash du fichier extrait.

### Pivot endpoint
Aller identifier manuellement, sur le partage lui-même, quel fichier contenait des identifiants en clair (mauvaise pratique à corriger indépendamment de l'incident) :
```powershell
Get-ChildItem -Path "\\<hote>\RH","\\<hote>\Backup" -Recurse | Select-Object FullName, LastWriteTime
Select-String -Path "\\<hote>\RH\*","\\<hote>\Backup\*" -Pattern "password|motdepasse|identifiant" -SimpleMatch
```

### Décision
Identifiant(s) confirmé(s) exposé(s) → indépendamment de la suite de l'investigation, **ce compte doit être considéré comme compromis dès cette phase** et son mot de passe changé, même avant confirmation d'une connexion réussie.

---

## 5. Phase 4 — Connexion distante avec les identifiants trouvés (T1021.002 / T1078)

**Précision de scénario** : pas de RDP (édition Windows Family). La connexion se fait donc très probablement via les partages d'administration SMB (`ADMIN$`, `C$`) avec un outil type PsExec/Impacket (`psexec.py`, `wmiexec.py`), ou WinRM si activé.

**Sources SIEM** : WinEventLog:Security (`event_code`, `hostname`, `ip_address`), Sysmon (première commande exécutée après connexion).

> ⚠️ **Gap déjà connu** : `LogonType` n'est pas mappé — impossible de confirmer directement qu'il s'agit d'un logon type 3 (réseau, cohérent avec SMB) plutôt qu'un autre type. `Account_Name` non plus — impossible de filtrer précisément sur le compte compromis identifié en phase 3 sans recherche texte de secours sur `message`.

### Investigation SIEM
1. Chercher un `EventID 4624` (ou tentatives `4625` suivies d'un `4624`) sur `hostname` dans la fenêtre suivant la phase 3, avec `ip_address` correspondant à l'attaquant.
2. Si l'outil utilisé est de type PsExec/Impacket : chercher côté Sysmon la création d'un service temporaire (nom aléatoire ou connu, ex: `PSEXESVC`) — visible comme un nouveau process avec `parent_executable` = `services.exe`.
3. Si WMI (wmiexec) : chercher `executable` = `WmiPrvSE.exe` comme parent de la première commande exécutée — signature caractéristique.

### Corrélation pcap — **très utile pour confirmer la méthode exacte**
Les outils PsExec/Impacket laissent des empreintes reconnaissables au niveau SMB (noms de pipes nommés) :
```bash
tshark -r capture.pcap -Y "smb2.tree contains \"IPC\$\"" -T fields -e frame.time -e smb2.filename
```
Cherche spécifiquement des pipes comme `\PSEXESVC`, `\svcctl`, `\atsvc`, `\winreg` — leur présence confirme la méthode d'accès distant utilisée, information précieuse pour le rapport (signature d'outil = piste d'attribution/TTP de l'attaquant).

### Pivot endpoint — **obligatoire**
```powershell
query user          # ou qwinsta — confirme si une session est encore active
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624,4625} -MaxEvents 50 | Format-Table TimeCreated, Id, Message -Wrap
Get-Service | Where-Object {$_.Name -like "PSEXESVC*"}   # trace résiduelle d'un service PsExec temporaire
```

### Décision
Connexion confirmée avec le compte identifié en phase 3 → **c'est le "patient zero" de l'incident**, comme pour le scénario Linux (phase 4 du playbook précédent). Basculer en investigation host-based complète à partir de cet horodatage.

### Recommandation
Mapper `LogonType` et `Account_Name` dans Splunk (déjà identifié comme priorité côté Linux/SSH — ce gap touche donc **deux scénarios différents**, ce qui en fait une correction encore plus prioritaire pour le lab dans son ensemble).

---

## 6. Phase 5 — Reconnaissance interne (T1033 / T1082 / T1087.001 / T1069.001 / T1057 / T1135)

**Sources SIEM** : Sysmon (`command_line`, `executable`, `parent_executable`), corrélé au pipeline pySigma construit précédemment.

> ⚠️ **Gap** : aucune règle Sigma Windows actuelle ne couvre ce bloc de reconnaissance (`whoami`, `hostname`, `systeminfo`, `ipconfig`, `net user`, `net localgroup`, `tasklist`, `net share`) de façon groupée — `t1087_account_discovery_windows.yml` couvre partiellement `net user`/`net localgroup`, mais pas `systeminfo`/`ipconfig`/`tasklist`/`net share`. À étendre (proposition en fin de document).

### Investigation SIEM
1. Extraire, via `command_line` (Sysmon EventID 1), toute la séquence de commandes exécutées par le compte compromis depuis l'horodatage de la phase 4.
2. Repérer spécifiquement : `whoami`, `hostname`, `systeminfo`, `ipconfig /all`, `net user`, `net localgroup administrators`, `tasklist /v`, `net share`.
3. Construire la timeline complète — pièce maîtresse du dossier, comme côté Linux.
4. Noter si l'attaquant a utilisé cmd.exe natif ou PowerShell (change le type de log à consulter en détail : Sysmon process creation dans les deux cas, mais PowerShell donne accès en plus au log PowerShell Operational).

### Corrélation pcap
Si la commande a été exécutée via un canal type wmiexec (semi-fileless, retour de sortie via SMB), le contenu texte des commandes/résultats peut être partiellement visible dans le flux SMB (`IPC$`) selon le tooling utilisé — plus complexe à extraire que pour un simple exfil HTTP, mais à tenter avec Wireshark "Follow Stream" sur la session SMB identifiée en phase 4 si la timeline SIEM est incomplète.

### Pivot endpoint
Si la timeline Sysmon semble incomplète (ex: process déjà terminé, log tourné), vérifier directement :
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 200 | Where-Object {$_.Id -eq 1} | Format-Table TimeCreated, Message -Wrap
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 200 | Where-Object {$_.Id -eq 400 -or $_.Id -eq 800}
```

### Décision
Séquence de reconnaissance confirmée → identifier si `net share` a révélé d'autres partages non encore explorés (élargir le scope de l'investigation aux nouveaux partages découverts).

---

## 7. Phase 6 — Élévation de privilèges : Unquoted Service Path (T1574.009)

**Principe de la vulnérabilité** : un service Windows configuré avec un chemin d'exécutable contenant des espaces mais **sans guillemets** (ex: `C:\Program Files\My App\service.exe` au lieu de `"C:\Program Files\My App\service.exe"`) permet à Windows d'essayer d'exécuter séquentiellement `C:\Program.exe`, puis `C:\Program Files\My.exe`, etc. Un attaquant avec droits d'écriture sur un de ces chemins intermédiaires peut y déposer un exécutable malveillant.

**Sources SIEM** : Sysmon (`command_line`, `executable`, `parent_executable` = `services.exe` au redémarrage/déclenchement du service).

> ⚠️ **Gap** : aucune règle Sigma actuelle ne couvre l'exploitation d'un Unquoted Service Path. `t1548_002_uac_bypass.yml` couvre un mécanisme différent (bypass UAC). À créer (proposition en fin de document) : détection d'un process avec `parent_executable` = `services.exe` et un `executable` situé dans un chemin correspondant à une interception classique (`C:\Program.exe`, `C:\Program Files\<Vendor>.exe`, etc.), combinée à l'absence du service légitime attendu à cet endroit.

### Investigation SIEM
1. Chercher un process Sysmon avec `parent_executable` se terminant par `\services.exe` et un `executable` inhabituel (hors des chemins standards Windows/Program Files complets).
2. Confirmer l'horodatage : doit coïncider avec un redémarrage du service vulnérable (manuel via `net start <service>` par l'attaquant, ou déclenchement système).
3. Vérifier si l'exécutable malveillant déposé correspond à une détection YARA (`PowerShell_Dropper_Indicators` si le payload est un script PowerShell encodé, sourcetype yara Windows, champ `alert`).

### Corrélation pcap
Peu pertinent à ce stade — l'exploitation est purement locale sur l'hôte (pas de trafic réseau généré par le dépôt du fichier lui-même, sauf si le fichier malveillant a été livré via la session SMB déjà établie en phase 4, auquel cas le même export d'objets SMB que la phase 3 peut le récupérer).

### Pivot endpoint — **obligatoire pour confirmer/corriger la vulnérabilité elle-même**
```powershell
# Identifier TOUS les services vulnérables au chemin non quoté sur l'hôte (pas seulement celui exploité)
Get-CimInstance -ClassName Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and $_.PathName -match ' '
} | Select-Object Name, DisplayName, PathName, StartMode
```
Cette commande doit être exécutée **quel que soit le résultat de l'investigation SIEM** — elle révèle l'ensemble de la surface d'attaque restante sur l'hôte, pas seulement le service déjà exploité.

### Décision
Élévation confirmée (process avec droits élevés/SYSTEM issu du service détourné) → **incident critique**, même traitement que pour le privesc root côté Linux : l'hôte n'est plus considéré comme fiable.

---

## 8. Phase 7 — Persistence : compte administrateur local + scheduled task (T1136.001 / T1053.005)

### 7a. Création d'un compte administrateur local

**Sources SIEM** : WinEventLog:Security, `EventID 4720` (création de compte) **suivi** d'un `EventID 4732` (ajout au groupe Administrateurs local) — vérifier si 4732 est bien émis dans ce lab (dépend de la même stratégie d'audit que 4720, généralement couplée).
**Règle Sigma existante** : `windows/t1136_create_account.yml` — **réutilisable directement**, bonne nouvelle.

> ⚠️ Gap : la règle actuelle ne filtre que sur `EventID 4720`, pas sur l'ajout au groupe Administrateurs (4732) qui est la partie la plus critique ici (un compte créé sans droits n'est pas le même niveau de risque qu'un compte créé ET rendu administrateur). À étendre.

#### Investigation SIEM
1. Chercher `EventID 4720` sur `hostname` après la phase 6 (privesc confirmée — cohérent, il faut déjà être élevé pour créer un compte admin).
2. Chercher `EventID 4732` juste après, confirmant l'ajout au groupe Administrateurs.
3. Corréler avec Sysmon `command_line` contenant `net user /add` ou `New-LocalUser` (PowerShell).

#### Pivot endpoint — **obligatoire**
```powershell
Get-LocalGroupMember -Group "Administrators"
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
```
Comparer avec une liste de référence connue des comptes légitimes — tout compte non reconnu dans le groupe Administrateurs est une preuve directe de persistence.

### 7b. Scheduled task avec reverse shell

**Sources SIEM** : Sysmon (`executable` = `schtasks.exe`, `command_line` contenant `/create`).
**Règle Sigma existante** : `windows/t1053_005_scheduled_task.yml` — **réutilisable directement**.

#### Investigation SIEM
1. Chercher l'événement `schtasks.exe /create` correspondant, extraire le nom de la tâche et sa configuration depuis `command_line` (déclencheur, action).
2. Si la reverse shell est lancée via PowerShell encodé dans l'action de la tâche, corréler avec `windows/t1059_001_powershell_encoded.yml` et `windows/t1059_001_powershell_dropper_yara.yml` — probable double détection ici, bon signal de confiance si les deux se déclenchent ensemble.
3. Vérifier le déclencheur configuré (`/sc onstart`, `/sc onlogon`...) — détermine la persistence effective au reboot.

#### Corrélation pcap — **valeur forte si la reverse shell se déclenche pendant la fenêtre de capture**
Une reverse shell PowerShell classique (`-nop -w hidden -e <base64>` établissant un socket TCP brut) n'est généralement **pas chiffrée** (sauf si le payload implémente lui-même du TLS) :
```bash
tshark -r capture.pcap -Y "tcp.port==<port_reverse_shell>" -z follow,tcp,ascii,<stream_id>
```
Peut révéler l'intégralité des commandes tapées par l'attaquant après le déclenchement de la tâche — comme pour le service systemd côté Linux.

#### Pivot endpoint — **obligatoire**
```powershell
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, State, Actions
schtasks /query /fo LIST /v | Select-String -Pattern "TaskName|Task To Run|Schedule Type" -Context 0,2
```

### Décision (7a + 7b)
Comme côté Linux : la remédiation doit couvrir **les deux mécanismes simultanément** (suppression du compte admin ET de la tâche planifiée) pour éviter qu'un des deux serve de filet de sécurité à l'attaquant pour revenir après le nettoyage du premier.

---

## 9. Phase 8 — Collection : rassemblement et archivage (T1560.001 / T1005)

**Sources SIEM** : Sysmon (`command_line` contenant `Compress-Archive`, `tar.exe` si utilisé, ou `7z.exe` si l'outil est présent sur l'hôte).

> ⚠️ **Gap** : aucune règle Sigma actuelle ne couvre la création d'archive comme signal de collection. À créer.

### Investigation SIEM
1. Chercher `command_line` contenant `Compress-Archive` (natif PowerShell) ou l'exécution d'un utilitaire d'archivage tiers.
2. Identifier les chemins source inclus dans l'archive (révèle précisément quelles données ont été ciblées — souvent visible directement dans les paramètres de la commande).
3. Noter le chemin et le nom du fichier archive généré — devient un IOC direct à rechercher aussi bien sur le disque que dans le trafic d'exfiltration (phase 9).

### Corrélation pcap
Pas de trafic réseau à ce stade (opération locale) — rien à corréler ici directement, mais le nom de fichier identifié servira de filtre pour la phase suivante.

### Pivot endpoint
```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *.zip -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-4) }
```
Objectif : localiser l'archive elle-même si elle n'a pas encore été supprimée après exfiltration — preuve matérielle directe du contenu collecté.

### Décision
Confirmer que les données archivées recoupent les fichiers identifiés en phase 2/3 (partages RH/Backup) — si de nouvelles données non vues précédemment apparaissent dans l'archive, élargir le scope de l'investigation.

---

## 10. Phase 9 — Exfiltration via Invoke-WebRequest (T1048.003)

**Sources SIEM** : Sysmon (`command_line` contenant `Invoke-WebRequest` ou son alias `iwr`), Zeek conn (`dest_port` de destination), log PowerShell Operational (`message`, si le module logging capture le détail de la commande).

> ⚠️ **Gap** : même situation que côté Linux — la règle `network/t1567_exfiltration_web_service.yml` filtre sur `dest_port: 443`. Si `Invoke-WebRequest` cible un port non standard ou du HTTP simple, elle ne se déclenchera pas. À vérifier au cas par cas et élargir la règle comme recommandé précédemment.

### Investigation SIEM
1. Chercher `command_line` contenant `Invoke-WebRequest`/`iwr`, avec la méthode utilisée (`-Method Post` probable pour envoyer l'archive), l'URI cible, et le chemin du fichier envoyé (`-InFile`).
2. Confirmer via Zeek conn la connexion sortante correspondante vers l'IP/port cible.
3. Vérifier si le trafic est HTTP ou HTTPS (détermine ce qui est récupérable en pcap, cf. ci-dessous).

### Corrélation pcap — **déterminant selon le protocole utilisé**
```bash
# Si HTTP simple (comme le scénario Linux) :
tshark -r capture.pcap -Y "http.request.method==POST" -z follow,tcp,ascii,<stream_id>
# Si HTTPS : seules les métadonnées de connexion et le SNI restent visibles
tshark -r capture.pcap -Y "tls.handshake.extensions_server_name"
```
Si HTTP simple, le contenu exact de l'archive exfiltrée est récupérable en pcap — preuve directe et exploitable (comparaison de hash avec l'archive trouvée en phase 8 sur le disque).

### Pivot endpoint
```powershell
Get-WinEvent -LogName "Windows PowerShell" -MaxEvents 100 | Where-Object {$_.Message -match "Invoke-WebRequest"}
netstat -ano | findstr ESTABLISHED
```

### Décision
Exfiltration confirmée = **incident majeur**, identique au traitement de la phase 9 côté Linux (notification, blocage, isolement, préservation d'image disque).

---

## 11. Récapitulatif — statut de détection par phase

| Phase | Détection automatique | Statut |
|---|---|---|
| 1. Scan nmap | `t1595_active_scanning.yml` | ✅ Couvert |
| 2. Énumération SMB | — | ❌ Non couvert (gap métadonnées/pcap uniquement) |
| 3. Identifiants dans partage | — | ❌ Non couvert (nécessite audit 5145 + pcap) |
| 4. Connexion distante (SMB/PsExec) | — | ⚠️ Partiel (event 4624/4625 dispo, LogonType/Account_Name non mappés) |
| 5. Reconnaissance interne | `t1087_account_discovery_windows.yml` | ⚠️ Partiel (systeminfo/ipconfig/tasklist/net share non couverts) |
| 6. Privesc Unquoted Service Path | — | ❌ Non couvert, règle à créer |
| 7a. Persistence compte admin | `t1136_create_account.yml` | ⚠️ Partiel (4732 ajout groupe non filtré) |
| 7b. Persistence scheduled task | `t1053_005_scheduled_task.yml` | ✅ Couvert |
| 8. Collection (archive) | — | ❌ Non couvert, règle à créer |
| 9. Exfiltration Invoke-WebRequest | `t1567_exfiltration_web_service.yml` | ⚠️ Ne se déclenche pas si port/protocole différent de 443 |

**3 couvertes/partielles solides, 4 partielles à corriger, 3 non couvertes.** Comparable au résultat Linux (2/6/2) — cohérent, et ça montre que les mêmes catégories de gaps (audit détaillé non activé, seuils de règles trop étroits) se répètent des deux côtés, ce qui en fait un vrai axe d'amélioration transverse du lab plutôt que des incidents isolés.

---

## 12. Commandes de détection live, confinement, éradication et remédiation

### 12.1 Détection live (lecture seule, à exécuter en premier)

**Sessions actives**
```powershell
query user
qwinsta
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} -MaxEvents 20 | Format-Table TimeCreated, Message -Wrap
```

**Connexions réseau actives / reverse shell**
```powershell
Get-NetTCPConnection -State Established | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
netstat -ano | findstr ESTABLISHED
Get-Process -Id <owning_process_id>   # identifier le process derrière une connexion suspecte
```

**Vérification de persistence**
```powershell
Get-LocalGroupMember -Group "Administrators"
Get-LocalUser | Select-Object Name, Enabled, PasswordLastSet
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, State
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' }
```

**Traces résiduelles d'outils distants**
```powershell
Get-Service | Where-Object {$_.Name -like "PSEXESVC*"}
Get-Process | Where-Object {$_.Name -match "wmiprvse|psexec"}
```

### 12.2 Confinement

**Couper la session/connexion active de l'attaquant**
```powershell
# Session interactive identifiée via query user
logoff <ID_session>
# Connexion réseau active (ex: session SMB/PsExec toujours ouverte)
Stop-Process -Id <owning_process_id> -Force
```
> ⚠️ Même remarque que côté Linux : si le compte admin ou la scheduled task ne sont pas neutralisés dans la foulée, couper la session seule ne fait que retarder le retour de l'attaquant.

**Neutraliser le compte compromis (celui trouvé en phase 3) et le compte admin créé (phase 7a)**
```powershell
Disable-LocalUser -Name "<compte_compromis>"
Disable-LocalUser -Name "<compte_admin_rogue>"
```

**Blocage réseau local (à défaut de pare-feu périmétrique)**
```powershell
New-NetFirewallRule -DisplayName "Block-Attacker-In" -Direction Inbound -RemoteAddress <ip_attaquant> -Action Block
New-NetFirewallRule -DisplayName "Block-Attacker-Out" -Direction Outbound -RemoteAddress <ip_attaquant> -Action Block
```

### 12.3 Éradication

**Retirer le compte administrateur rogue (préserver la preuve avant suppression)**
```powershell
Get-LocalUser -Name "<compte_admin_rogue>" | Export-Clixml -Path C:\IR\evidence_rogue_account.xml
Remove-LocalGroupMember -Group "Administrators" -Member "<compte_admin_rogue>"
Remove-LocalUser -Name "<compte_admin_rogue>"
```

**Supprimer la scheduled task malveillante**
```powershell
Unregister-ScheduledTask -TaskName "<nom_tache>" -Confirm:$false
# ou
schtasks /delete /tn "<nom_tache>" /f
```

**Corriger la vulnérabilité Unquoted Service Path (racine du problème, pas juste le symptôme)**
```powershell
# 1. Supprimer le binaire malveillant déposé dans le chemin d'interception
Remove-Item -Path "C:\Program.exe" -Force -ErrorAction SilentlyContinue   # exemple, adapter au chemin réel identifié
# 2. Corriger le chemin du service légitime pour qu'il soit correctement quoté
sc.exe config <nom_service> binpath= "\"C:\Program Files\Vendor\App\service.exe\""
# 3. Vérifier qu'aucun AUTRE service du système n'est vulnérable au même défaut (durcissement, pas juste réparation ponctuelle)
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' }
```

**Nettoyer les données collectées/résiduelles**
```powershell
Get-ChildItem -Path C:\Users -Recurse -Include *.zip -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-4) } | Remove-Item -Force
```

**Rotation des secrets exposés (phase 3)**
```powershell
# Forcer le changement de mot de passe pour tous les comptes trouvés dans les fichiers exposés
net user <compte> * /random   # ou intégration avec un outil de gestion centralisée des mots de passe
```

### 12.4 Récupération et vérification post-remédiation
```powershell
Get-LocalGroupMember -Group "Administrators"                                              # doit être la liste de référence connue
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"}                                # tâche malveillante absente
Get-CimInstance -ClassName Win32_Service | Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match ' ' }  # zéro résultat idéalement
Get-NetTCPConnection -State Established                                                   # pas de connexion résiduelle suspecte
query user                                                                                 # pas de session résiduelle
```

**À consigner dans le rapport final** : horodatage de chaque commande, résultat obtenu, nom de l'analyste — identique au format utilisé côté Linux, pour garder un rapport homogène entre les deux OS.

---

## 13. Actions de suivi recommandées (par priorité)

1. **Critique** — mapper `LogonType` et `Account_Name` dans Splunk (impacte à la fois ce scénario et le brute force SSH Linux : correction transverse prioritaire).
2. **Critique** — activer l'audit détaillé des partages (EventID 5140/5145), actuellement absent, seul le pcap comble ce vide dans ce lab.
3. **Haute** — créer une règle Sigma pour l'exploitation Unquoted Service Path (`parent_executable`=services.exe + chemin d'interception connu).
4. **Haute** — créer une règle Sigma pour la collection via `Compress-Archive`/archivage.
5. **Moyenne** — étendre `t1087_account_discovery_windows.yml` à `systeminfo`, `ipconfig`, `tasklist`, `net share`.
6. **Moyenne** — étendre `t1136_create_account.yml` pour inclure `EventID 4732` (ajout au groupe Administrateurs), pas seulement la création du compte.
7. **Moyenne** — élargir `t1567_exfiltration_web_service.yml` au-delà du port 443 (déjà identifié côté Linux, confirmé nécessaire ici aussi).
8. **Basse** — ajouter une règle Suricata dédiée à l'énumération SMB (Tree Connect répétés).

---

## 14. Template — Evidence & Timeline Tracker

Identique au modèle utilisé côté Linux, pour garder un format homogène entre les deux playbooks.

| Horodatage | Hôte | Source de log | Commande / événement brut | Technique MITRE | Analyste | Verdict | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
