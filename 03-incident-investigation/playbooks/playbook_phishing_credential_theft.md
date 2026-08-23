# Playbook d'investigation — Phishing avec vol d'identifiants
## Email reçu → Clic sur lien → Saisie d'identifiants sur page piégée → Envoi en clair à l'attaquant

**Statut du document** : experimental (lab SOC personnel)
**Portée** : poste victime Windows **ou** Ubuntu (navigateur), corrélé au trafic réseau (Suricata) et à la capture tcpdump brute.
**Point de départ honnête** : ce lab n'a **aucune source de log de messagerie** (pas de passerelle mail/serveur mail forwardé vers Splunk) — gap déjà identifié dans les playbooks précédents pour T1598. La seule détection automatisée actuelle sur toute cette chaîne est le déclenchement réseau au moment de l'envoi des identifiants en clair. Ce playbook part de cette réalité plutôt que de la maquiller : il documente précisément ce qui est détectable automatiquement, et ce qui nécessite une investigation manuelle.

---

## 0. Vue d'ensemble de la chaîne d'attaque

| # | Étape | Tactique MITRE | Technique | Code |
|---|---|---|---|---|
| 1 | Email de phishing reçu | Initial Access | Phishing: Spearphishing Link | T1566.002 |
| 2 | Clic sur le lien par l'utilisateur | Execution | User Execution: Malicious Link | T1204.001 |
| 3 | Saisie des identifiants sur la page piégée | Reconnaissance / Credential Access | Phishing for Information: Spearphishing Link | T1598.003 |
| 4 | Envoi des identifiants en clair à l'attaquant (HTTP) | — (signal réseau observable) | Complète T1566.002 / T1598.003 | — |
| 5 (suite potentielle) | Réutilisation des identifiants volés ailleurs | Initial Access | Valid Accounts | T1078 |

**Note de tagging MITRE** : la saisie d'identifiants sur une page de phishing n'a pas de technique dédiée unique dans ATT&CK — selon l'objectif final, on la classe sous T1566.002 (le vecteur d'accès initial reste le lien) ou T1598.003 (si l'angle est la collecte d'informations en vue d'une utilisation ultérieure). Les deux tags sont légitimes et souvent utilisés ensemble dans un vrai rapport — le préciser dans ton dossier montre que tu comprends la nuance plutôt que d'appliquer un tag au hasard.

**Deux points d'entrée possibles dans ce playbook** :
- **A. Alerte automatique** : la règle Suricata "SOC-LAB Cleartext Credentials" (sid 1000003) se déclenche — c'est un signal *tardif*, l'attaquant a déjà les identifiants au moment où l'analyste est notifié.
- **B. Signalement utilisateur** : l'utilisateur signale lui-même avoir cliqué sur un lien suspect ou reçu un email douteux — signal *précoce*, permet d'agir avant même la fuite d'identifiants si le signalement précède la saisie.

Un vrai SOC doit être prêt à traiter les deux cas. Ce playbook les couvre l'un après l'autre.

---

## 1. Principes d'utilisation (rappel)

Mêmes verdicts standardisés (`TP-Confirmed`, `TP-Contained`, `FP`, `Benign-Authorized`, `Suspicious-Monitoring`) et même tracker Evidence & Timeline que les playbooks précédents (modèle en fin de document).

---

## 2. Phase 1 — Triage initial : quel est le point d'entrée dans l'investigation ?

### Cas A — Déclenché par l'alerte Suricata (détection tardive)
**Source SIEM** : Suricata (`alert_signature` = "SOC-LAB Cleartext Credentials", `src_ip`, `dest_ip`, `alert_severity`).
**Règle Sigma existante** : le signal est actuellement inclus dans `network/t1071_001_c2_web_protocols.yml`, taggé T1071.001 (C2).

> ⚠️ **Gap de tagging important** : cette règle Suricata unique (`pcre` sur `password|passwd|pwd|token=` dans le corps HTTP) se déclenche aussi bien pour un vrai C2 mal implémenté que pour ce scénario de phishing — **ce sont deux histoires complètement différentes avec la même signature réseau**. Un analyste doit distinguer les deux au cas par cas (contexte : y a-t-il eu un email/clic avant ? quel est le domaine de destination ?), pas se fier au tag automatique seul. Recommandation : dupliquer la règle avec un tag T1598.003/T1566.002 dédié pour ce contexte, et documenter dans la description de la règle que la distinction se fait par corrélation temporelle avec l'activité navigateur de l'utilisateur (phase 3 ci-dessous), pas par la signature seule.

Si c'est ce point d'entrée : l'attaquant a **déjà** les identifiants. Passer directement en investigation active, ne pas attendre de confirmation supplémentaire avant de commencer le confinement du compte (section 7).

### Cas B — Signalement utilisateur (détection précoce, idéale)
Aucune source SIEM disponible pour ce cas dans ce lab (pas de bouton "Signaler le phishing" ni de log associé) — entièrement manuel. L'utilisateur transmet l'email suspect (transfert en pièce jointe `.eml`/`.msg`, jamais en transfert direct pour éviter de réactiver des liens) ou décrit ce qu'il a cliqué/saisi.

### Décision de triage
1. Le mot de passe a-t-il été saisi et soumis (pas juste le lien cliqué) ? Détermine si on est en confinement de compte immédiat ou en analyse préventive.
2. Le compte a-t-il des privilèges élevés ou un accès à des données sensibles ? Détermine la priorité.
3. D'autres utilisateurs ont-ils reçu le même email (campagne large ou ciblée) ? À vérifier en section 3.

---

## 3. Phase 2 — Analyse de l'email reçu

Entièrement manuelle dans ce lab (pas de log de messagerie). C'est le cœur du travail d'analyse pour ce type d'incident, indépendamment de la maturité de détection automatisée.

### 3.1 Analyse des en-têtes (headers)

Récupérer le fichier `.eml` brut (jamais une capture d'écran seule — les en-têtes ne sont pas visibles dans l'aperçu habituel du client mail).

**Points à vérifier systématiquement :**

| Élément | Ce qu'on cherche | Signal d'alerte |
|---|---|---|
| `From` affiché vs adresse réelle | Usurpation d'identité visuelle | Nom affiché légitime, adresse réelle différente |
| `Reply-To` | Détournement de réponse | `Reply-To` différent de `From` |
| Chaîne `Received` (de bas en haut = chronologique) | Origine réelle du message | IP/serveur d'envoi incohérent avec l'expéditeur prétendu |
| `SPF` / `DKIM` / `DMARC` (dans `Authentication-Results`) | Authentification du domaine expéditeur | `fail` ou `softfail` sur l'un des trois |
| `Message-ID` | Cohérence avec le domaine prétendu | Domaine du Message-ID différent du domaine expéditeur |
| Urgence/pression dans le corps | Ingénierie sociale classique | "Action requise immédiatement", "compte suspendu sous 24h" |

```bash
# Extraction rapide des en-têtes clés depuis un fichier .eml
grep -iE "^(From|Reply-To|Return-Path|Received|Message-ID):" phishing.eml
grep -i "Authentication-Results" phishing.eml
```

### 3.2 Analyse des liens (sans cliquer)

**Toujours défanguer avant de partager/documenter** (`hxxp://` au lieu de `http://`) pour éviter tout clic accidentel ultérieur, y compris par un autre analyste lisant le rapport.

```bash
# Extraire toutes les URLs du corps de l'email sans les ouvrir
grep -oE 'https?://[^ ">]+' phishing.eml
```

Pour chaque URL trouvée :
1. **Âge du domaine** (`whois <domaine>`) — un domaine enregistré depuis quelques jours/semaines est un signal fort.
2. **Réputation** — vérifier sur un service de threat intel (VirusTotal, urlscan.io) **sans soumettre depuis le poste de la victime** (utiliser un poste d'analyse dédié/isolé, jamais le poste compromis lui-même, pour ne pas alerter l'attaquant si l'infrastructure surveille les visites).
3. **Détonation en sandbox** si l'outillage le permet (urlscan.io capture une capture d'écran + le code source de la page sans risque pour l'analyste).
4. **Comparaison typosquatting** avec le domaine légitime attendu (ex: `secure-login-portal.com` vs le vrai domaine de l'organisation).

### 3.3 Pièces jointes (si présentes)
Non mentionné dans ce scénario (lien uniquement), mais à vérifier systématiquement même quand ce n'est "pas censé" être le vecteur — un email peut combiner les deux. Si présentes : hash (`sha256sum`), vérification VirusTotal, jamais d'ouverture directe.

### Décision
Confirmer que l'email est bien un phishing (pas un faux positif de signalement utilisateur) avant de déclencher les actions de confinement — mais dans le doute, prioriser la prudence : mettre en attente le compte plutôt que d'attendre une confirmation à 100 %.

---

## 4. Phase 3 — Analyse de la page de collecte d'identifiants

### Investigation
1. Depuis le poste d'analyse isolé (jamais le poste victime), visiter l'URL défanguée reformattée, **sans jamais soumettre de vraies données**.
2. Examiner le code source de la page : formulaire de connexion, à quelle URL le formulaire POST ses données (`<form action="...">`) — c'est l'IP/domaine qu'on retrouvera dans l'alerte réseau.
3. Vérifier si la page imite visuellement un service légitime connu (portail interne, service cloud) — aide à évaluer quel type d'identifiants est visé et donc l'impact potentiel.
4. Noter l'infrastructure d'hébergement (hébergeur, pays, CDN éventuel) pour le dossier IOC.

### Pivot endpoint (poste victime) — vérifier ce qui reste en local
**Windows :**
```powershell
# Historique de navigation (Edge/Chrome) autour de l'horodatage du clic
Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" -ErrorAction SilentlyContinue
# Fichiers téléchargés récemment (si la page a aussi tenté un drive-by download)
Get-ChildItem "$env:USERPROFILE\Downloads" | Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-2)}
```
**Ubuntu :**
```bash
# Historique Firefox (exemple, adapter selon navigateur)
sqlite3 ~/.mozilla/firefox/*.default*/places.sqlite "SELECT url, datetime(last_visit_date/1000000,'unixepoch') FROM moz_places ORDER BY last_visit_date DESC LIMIT 20;"
ls -la ~/Downloads --time-style=full-iso
```
Objectif : confirmer que rien d'autre que la saisie d'identifiants n'a eu lieu (pas de téléchargement/exécution additionnel — sinon ce playbook doit être complété par les phases de reconnaissance/persistence des playbooks Linux/Windows déjà écrits, l'incident devient alors plus large qu'un simple vol d'identifiants).

### Corrélation avec le scan YARA périodique
Si un fichier a été déposé (drive-by ou pièce jointe malgré tout), le scan YARA planifié (`yara-scan.sh` côté Linux, mécanisme équivalent côté Windows) peut l'avoir détecté indépendamment. Rechercher côté Splunk (`alert` du sourcetype yara) sur la fenêtre correspondante.

---

## 5. Phase 4 — Envoi des identifiants en clair : le signal réseau

**Sources SIEM** : Suricata (`alert_signature`, `src_ip`, `dest_ip`), Zeek conn.

### Investigation SIEM
1. Confirmer `src_ip` = poste de la victime, `dest_ip` = infrastructure identifiée en phase 3.
2. Noter l'horodatage exact — c'est le moment où le compte doit être considéré comme compromis, point de départ du confinement.
3. Vérifier s'il y a eu plusieurs soumissions (l'utilisateur a pu se tromper de mot de passe et retenter — chaque tentative est potentiellement capturée par l'attaquant).

### Corrélation pcap — **preuve la plus forte de tout ce playbook**
La règle Suricata confirme *qu'*un motif `password=`/`token=` a été vu, mais le pcap donne le **contenu exact** transmis (identifiant ET mot de passe en clair, puisque non chiffré par construction du scénario) :
```bash
tshark -r capture.pcap -Y "http.request.method==POST and ip.dst==<ip_attaquant>" -z follow,tcp,ascii,<stream_id>
```
Ou plus directement, pour isoler le corps de la requête :
```bash
tshark -r capture.pcap -Y "http.request.method==POST and ip.dst==<ip_attaquant>" -T fields -e http.file_data
```
> ⚠️ **Traitement de la preuve** : le mot de passe en clair extrait est une donnée sensible en soi. Le stocker dans le dossier d'incident de façon chiffrée/restreinte, ne jamais le coller en clair dans un ticket ou un rapport partagé largement — seul le fait qu'il ait fuité doit être documenté, pas sa valeur, sauf besoin strictement justifié (ex: vérifier un pattern de réutilisation).

### Décision
Fuite d'identifiants confirmée avec certitude (contenu exact visible en pcap) → déclenche immédiatement la section 7 (confinement), sans attendre d'autres signaux.

---

## 6. Phase 5 — Évaluer la portée : réutilisation des identifiants volés

C'est l'étape qui relie ce playbook aux deux playbooks précédents (Linux SSH brute force, Windows SMB) : un identifiant volé par phishing peut ensuite être réutilisé comme **vecteur d'accès initial valide** (T1078), sans avoir besoin de brute force.

### Investigation — pivoter vers les autres sources déjà en place
1. Rechercher toute tentative d'authentification (réussie ou non) avec le username identifié, sur **tous les hôtes du lab**, dans les heures/jours suivant la fuite :
   - Linux : `sourcetype=sshd`/`linux_auth`, recherche texte sur le username (limitation déjà connue : pas de `src_ip` fiable, cf. playbook Linux section 5).
   - Windows : `WinEventLog:Security` `EventID 4624`/`4625`, recherche texte sur `message` (limitation déjà connue : `Account_Name` non mappé).
2. Vérifier si le même mot de passe est réutilisé sur d'autres comptes/services du lab (mauvaise hygiène fréquente côté utilisateur — à documenter comme constat, pas juste comme risque théorique).
3. Si une connexion réussie est trouvée avec ce compte sur un autre hôte → **fusionner ce dossier avec le playbook Linux ou Windows concerné**, à partir de sa phase "connexion avec identifiants trouvés/compromis" — ce phishing devient alors le vecteur d'accès initial documenté d'une chaîne d'attaque plus large.

### Décision
Même en l'absence de réutilisation confirmée, considérer le compte comme compromis et appliquer la remédiation complète (section 7) — l'absence de preuve de réutilisation n'est pas une preuve d'absence, l'attaquant peut simplement ne pas avoir encore agi.

---

## 7. Détection live, confinement, éradication et remédiation

### 7.1 Détection live (à exécuter en premier)

**Vérifier si le compte compromis est actuellement en session active, sur tous les hôtes du lab**
```powershell
# Windows
query user
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} -MaxEvents 30 | Where-Object {$_.Message -match "<username>"}
```
```bash
# Linux
who
last -a | grep "<username>"
```

**Rechercher toute activité suspecte déjà en cours avec ce compte (recon, exécution de commandes)**
```bash
# Splunk (indépendant de l'OS)
index=* "<username>" (sourcetype=sshd OR sourcetype=WinEventLog:Security OR sourcetype=auditd) earliest=-24h
```

### 7.2 Confinement (immédiat, dès confirmation phase 4)

**Neutraliser le compte compromis partout où il existe**
```powershell
# Windows (compte local ou AD selon contexte)
Disable-LocalUser -Name "<username>"
```
```bash
# Linux
sudo usermod -L <username>
sudo usermod -s /usr/sbin/nologin <username>
```

**Révoquer toute session active du compte**
```powershell
# Windows — forcer la déconnexion de toute session active
logoff <ID_session>
```
```bash
# Linux — tuer toute session active de l'utilisateur
sudo pkill -KILL -u <username>
```

**Bloquer l'infrastructure de phishing identifiée**
```bash
# Pare-feu (exemple iptables, à adapter selon l'équipement réel)
iptables -A OUTPUT -d <ip_attaquant> -j DROP
```
```powershell
New-NetFirewallRule -DisplayName "Block-Phishing-Infra" -Direction Outbound -RemoteAddress <ip_attaquant> -Action Block
```
Ajouter également le domaine à la liste de blocage DNS/proxy si l'infrastructure du lab le permet (résolution DNS bloquée = protection même si l'IP change).

### 7.3 Éradication

**Rotation immédiate du mot de passe compromis, et de tout mot de passe réutilisé identifié en phase 5**
```powershell
net user <username> * /random
```
```bash
sudo passwd -e <username>   # force le changement au prochain login — insuffisant seul si compromission confirmée, préférer une rotation immédiate pilotée par l'IT plutôt que de compter sur l'utilisateur
```

**Nettoyer les traces locales si un fichier a été déposé sur le poste (drive-by identifié en phase 3)**
```powershell
Get-ChildItem "$env:USERPROFILE\Downloads" | Where-Object {$_.LastWriteTime -gt "<horodatage_incident>"} | Remove-Item -Force
```

**Si réutilisation confirmée ailleurs (phase 5)** : appliquer intégralement les procédures d'éradication du playbook Linux ou Windows concerné à partir du point de compromission identifié — ne pas traiter cette étape comme un incident isolé si une chaîne plus large est confirmée.

### 7.4 Actions organisationnelles (au-delà du technique)

1. **Rechercher les autres destinataires** de la même campagne de phishing (même expéditeur/sujet/lien) — sans log de messagerie centralisé, ceci nécessite une demande manuelle aux autres utilisateurs ou l'accès a posteriori aux boîtes mail si l'organisation le permet. À noter comme limite actuelle du lab.
2. **Soumettre l'URL/le domaine malveillant** à des listes de blocage publiques et au registrar/hébergeur (signalement abuse) — réduit l'impact pour d'autres victimes potentielles hors du périmètre du lab.
3. **Notifier l'utilisateur sans blâme** : objectif = qu'il continue à signaler les prochains cas suspects plutôt que de les cacher par crainte de sanction. C'est un point de maturité SOC à mentionner explicitement dans un rapport professionnel.
4. **Documenter comme un cas "détecté tardivement"** si on est passé par le Cas A (alerte réseau) plutôt que le Cas B (signalement précoce) — sert de justification concrète pour la recommandation ci-dessous (priorité 1).

### 7.5 Vérification post-remédiation
```powershell
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} -MaxEvents 10 | Where-Object {$_.Message -match "<username>"}  # doit être vide après confinement
```
```bash
last -a | grep "<username>" | head -5   # doit être vide après confinement
```
Confirmer l'absence de nouvelle connexion avec le compte sur l'ensemble des hôtes du lab dans les heures suivant la remédiation.

---

## 8. Actions de suivi recommandées (par priorité)

1. **Critique** — le gap le plus structurant de ce playbook : **aucune visibilité de messagerie** dans le lab. Tant que ce n'est pas comblé (serveur mail avec logs forwardés, ou a minima un mécanisme de signalement utilisateur outillé), toute détection de phishing dans ce lab reste **tardive par construction** (Cas A uniquement, jamais Cas B). C'est la priorité la plus impactante de tous les playbooks écrits jusqu'ici.
2. **Haute** — séparer le tag MITRE de la règle Suricata "Cleartext Credentials" : une règle/alerte dédiée T1598.003 pour ce contexte, distincte de la règle C2 (T1071.001) actuelle qui les confond.
3. **Haute** — mapper `src_ip`/`Account_Name` (déjà identifié dans les deux playbooks précédents) : condition nécessaire pour automatiser la corrélation de la phase 5 (réutilisation d'identifiants) au lieu de la faire manuellement à chaque fois.
4. **Moyenne** — mettre en place un mécanisme, même basique, de signalement utilisateur (boîte mail dédiée `phishing@lab.local` avec log de soumission) pour activer le Cas B.
5. **Basse** — ajouter un script de vérification automatique de réputation de domaine (whois + âge du domaine) déclenché sur toute URL vue dans le trafic HTTP sortant, en complément de la règle Suricata existante.

---

## 9. Template — Evidence & Timeline Tracker

Identique aux playbooks précédents, pour garder un format homogène sur l'ensemble du repo.

| Horodatage | Hôte | Source (log / manuel) | Élément observé | Technique MITRE | Analyste | Verdict | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
