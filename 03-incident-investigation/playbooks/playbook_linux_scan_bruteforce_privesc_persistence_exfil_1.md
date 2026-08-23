# Playbook d'investigation — Intrusion Linux complète
## Scan externe → Découverte FTP → Brute force SSH → Reconnaissance interne → Privesc SUID → Persistence (clé SSH + service systemd) → Exfiltration → Anti-forensics

**Statut du document** : experimental (lab SOC personnel)
**Portée** : hôte Ubuntu du lab (rsyslog + auditd + YARA), corrélé au trafic réseau (Suricata/Zeek)
**Objectif** : guider un analyste N1/N2 étape par étape, du triage initial jusqu'à la clôture de l'incident, sans sauter d'étape critique.

---

## 0. Vue d'ensemble de la chaîne d'attaque

| # | Phase | Tactique MITRE | Technique | Code |
|---|---|---|---|---|
| 1 | Scan réseau global | Reconnaissance | Active Scanning: IP Block Scan | T1595.001 |
| 2 | Scan de ports/services | Reconnaissance | Active Scanning: Vulnerability/Service Scanning | T1595.002 |
| 3 | Bannière FTP → username | Reconnaissance | Active Scanning (service enumeration) | T1595 |
| 4 | Brute force SSH | Credential Access → Initial Access | Brute Force / Valid Accounts | T1110.001 / T1078 |
| 5 | Reconnaissance interne | Discovery | System Owner/User, Account, Permission Groups, File/Dir Discovery | T1033 / T1087.001 / T1069.001 / T1083 |
| 6 | Escalade SUID | Privilege Escalation | Abuse Elevation Control Mechanism: Setuid/Setgid | T1548.001 |
| 7a | Persistence clé SSH | Persistence | Account Manipulation: SSH Authorized Keys | T1098.004 |
| 7b | Persistence service systemd | Persistence | Create or Modify System Process: Systemd Service | T1543.002 |
| 8 | Collecte de données sensibles | Collection | Data from Local System / Unsecured Credentials | T1005 / T1552.001 |
| 9 | Exfiltration HTTP | Exfiltration | Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol | T1048.003 |
| 10 | Anti-forensics | Defense Evasion | Indicator Removal: Clear Command History | T1070.003 |

**Correction par rapport à un tag naïf** : l'exfiltration ici (curl HTTP brut vers un port 8080, sans TLS, vers une IP arbitraire) correspond mieux à **T1048.003** qu'à T1567 (Exfiltration Over *Web Service*, qui désigne normalement l'usage détourné d'un service web légitime type cloud storage). Le distinguo compte pour la justesse du dossier d'incident.

---

## 1. Principes d'utilisation de ce playbook

- Une phase = une section. Chaque section indique : la source de log exacte, la ou les règles Sigma associées (existantes ou à créer), les étapes d'investigation, les points de décision, et les actions de confinement possibles.
- Ne jamais conclure une phase sur une seule source. Toujours croiser au moins deux logs quand c'est possible (ex: auditd + réseau).
- Consigner chaque preuve dans le tracker en fin de document (section 12), au fur et à mesure — pas a posteriori.
- Un "gap de détection" identifié dans ce document (encadré ⚠️) n'est pas une raison de sauter l'étape d'investigation : il signifie juste qu'il faut chercher la preuve manuellement plutôt que de compter sur une alerte automatique.

### Codes de verdict standard à utiliser dans le tracker

| Code | Signification |
|---|---|
| TP-Confirmed | Vrai positif confirmé, activité malveillante avérée |
| TP-Contained | Vrai positif, mesures de confinement appliquées |
| FP | Faux positif, activité légitime |
| Benign-Authorized | Activité légitime autorisée (test, exercice) |
| Suspicious-Monitoring | Doute raisonnable, mise sous surveillance renforcée sans action immédiate |

---

## 2. Phase 1 — Scan réseau global (T1595.001)

**Sources disponibles** : Suricata (`alert_signature`, `src_ip`, `dest_ip`, `alert_severity`), Zeek conn.
**Règle Sigma existante** : `network/t1595_active_scanning.yml` (basée sur sid 1000001 "SOC-LAB Possible TCP SYN Scan").

### Étapes d'investigation
1. Identifier l'IP source du scan, le nombre d'hôtes cibles touchés (`dest_ip` distincts), et la fenêtre temporelle.
2. Déterminer si la source est externe (Internet) ou interne (mouvement latéral déjà en cours depuis un autre hôte compromis) — ça change complètement le niveau de gravité initial.
3. Rechercher d'autres scans émis par la même IP source dans les jours précédents (persistance de la menace, reconnaissance étalée).
4. Noter les IP/hôtes ciblés par le scan pour les mettre sous surveillance renforcée dans les phases suivantes.

### Décision
- Scan externe isolé, non suivi d'autre activité → `Suspicious-Monitoring`, pas d'action immédiate (bruit de fond Internet fréquent).
- Scan suivi d'un scan de ports ciblé sur le même hôte (phase 2) → passer en investigation active.

### Confinement possible
Aucun à ce stade seul. Ajouter l'IP source à une watchlist.

---

## 3. Phase 2 — Scan de ports et services (`nmap -sC -sV`) (T1595.002)

**Sources** : Suricata (mêmes champs), Zeek conn (`dest_port` multiples depuis la même `src_ip` en peu de temps).
**Règle Sigma existante** : `network/t1046_network_service_discovery.yml` (réutilise le même sid 1000001).

### Étapes d'investigation
1. Lister tous les `dest_port` contactés par la même `src_ip` sur l'hôte ciblé, dans les minutes suivant le scan de la phase 1.
2. Confirmer la présence des ports FTP (21) et SSH (22) dans les ports scannés — ce sont les deux services qui seront exploités ensuite, donc leur présence ici oriente directement la suite de l'investigation.
3. Vérifier qu'aucun service inattendu n'a aussi été identifié (élargir le scope si oui).

### Décision
- Ports FTP + SSH confirmés dans le scan → escalade en investigation active, ouvrir un dossier d'incident même si rien n'est encore compromis.

### Confinement possible
Envisager un blocage préventif de l'IP source si la politique du SOC le permet à ce stade (dépend du contexte réel).

---

## 4. Phase 3 — Découverte FTP et fuite de bannière (T1595)

> ⚠️ **Gap de détection majeur** : il n'existe **aucune visibilité applicative sur le protocole FTP** dans ce lab. Ni Zeek (pas de log `ftp.log` configuré/mappé), ni Suricata (aucune règle FTP écrite), ni logs endpoint (pas de service FTP côté hôte scanné — c'est le service de l'attaquant qui est contacté, pas un service local). Seule la métadonnée de connexion (Zeek conn : `src_ip`, `dest_ip`, `dest_port=21`, `duration`) est visible. Le contenu de la bannière (et donc le username qui y fuite) **n'est pas observable dans les logs actuels**.

### Étapes d'investigation (avec la visibilité limitée actuelle)
1. Confirmer via Zeek conn qu'une connexion `dest_port=21` a bien eu lieu entre la source du scan et l'hôte cible, juste après la phase 2.
2. Sans visibilité applicative, cette étape reste **déduite, pas confirmée** dans le dossier d'incident — le noter explicitement comme hypothèse, pas comme fait établi.
3. Amélioration recommandée pour la suite du lab : activer le script Zeek `ftp` (log `ftp.log` avec les champs `user`, `command`, `reply_msg`) et l'ajouter au mapping Splunk, ou écrire une règle Suricata avec `ftp.command` / `ftp.reply` pour capturer les bannières.

### Décision
Ne jamais présenter cette étape comme "détectée" dans un rapport tant que la visibilité applicative FTP n'existe pas — présente-la comme un gap assumé, c'est plus crédible en entretien qu'une fausse confiance.

---

## 5. Phase 4 — Brute force SSH réussi (T1110.001 → T1078)

**Sources** : sourcetype `sshd` (texte brut `Failed password` / `Accepted password`), `linux_auth`.
**Règle Sigma existante** : `linux/t1110_ssh_brute_force.yml`.

> ⚠️ **Gap déjà identifié précédemment** : `src_ip` n'est pas mappé pour `sshd`/`linux_auth` dans ce lab. Le seuil de la règle actuelle compte par `user`, pas par IP source — donc si l'attaquant brute-force plusieurs comptes en parallèle à faible volume chacun, la règle peut ne pas se déclencher. **C'est le gap le plus prioritaire à corriger** (extraction `rex` de l'IP depuis `_raw`, comme discuté).

### Étapes d'investigation
1. Compter les occurrences `Failed password` pour le username identifié (ou déduit) juste avant le succès.
2. Repérer l'événement `Accepted password` (ou `Accepted publickey` si ce n'est pas un brute force classique — vérifier que c'est bien du mot de passe) : **son horodatage exact devient le "patient zero" de l'incident**.
3. Croiser avec Zeek conn : connexion `dest_port=22` depuis la même `src_ip` que les phases 1 et 2 — confirme qu'il s'agit bien du même acteur.
4. Déterminer si le compte est un compte standard, un compte de service, ou un compte avec des droits sudo (directement lié à la gravité de la phase 6).

### Décision
- Succès confirmé → **incident confirmé**, pas juste une alerte. Basculer immédiatement en investigation "host-based" complète à partir de cet horodatage.

### Confinement possible
- Désactivation temporaire du compte compromis (`usermod -L`), forcer un changement de mot de passe.
- Dans un contexte réel avec `src_ip` disponible : blocage de l'IP attaquante au pare-feu périmétrique.
- Isolement réseau de l'hôte si la politique de confinement du SOC le permet dès ce stade (à arbitrer selon le niveau de compromission suspecté).

---

## 6. Phase 5 — Reconnaissance interne post-compromission

**Sources** : auditd (`type=EXECVE`), avec `command_line` reconstruit via le lookup `execve_decode` mis en place précédemment.
**Règle Sigma existante** : `linux/t1087_account_discovery_linux.yml`.

> ⚠️ **Gap** : la règle actuelle ne couvre que `cat /etc/passwd`, `cat /etc/shadow`, `getent passwd`, `id -a`, `w -h`, `lastlog`. Elle **ne couvre pas** `whoami`, `hostname`, `sudo -l`, ni l'énumération de fichiers locaux (`find`, `ls -la` récursif) — tous présents dans ce scénario. À étendre (proposition en section 11).

### Étapes d'investigation
1. Extraire, via `command_line`, **toute la séquence de commandes** exécutées par le compte compromis dans les minutes suivant le login SSH réussi (pivot temporel = horodatage de la phase 4). C'est la pièce maîtresse du dossier.
2. Repérer spécifiquement : `id`, `hostname`, `sudo -l`, `cat /etc/passwd`, `cat /etc/shadow` (probable échec de permission — le noter, c'est un signal en soi), `find / -perm -4000`, `find / -perm -2000`.
3. Construire la timeline complète, commande par commande, avec horodatage — c'est ce tableau qui servira de colonne vertébrale au rapport d'incident final.
4. Identifier si un binaire SUID inhabituel (hors liste standard : `passwd`, `sudo`, `mount`, `ping`...) a été repéré dans les résultats du `find` — c'est l'élément déclencheur logique de la phase suivante.

### Décision
- Étendre le scope de l'investigation à tous les comptes découverts via `/etc/passwd` s'ils semblent avoir aussi été testés (croiser avec de nouveaux échecs d'authentification sur ces comptes).
- Confirmer le niveau de privilège actuel de l'attaquant (pas encore root à ce stade).

---

## 7. Phase 6 — Escalade de privilèges via SUID (T1548.001)

**Sources** : auditd EXECVE (`command_line`, `executable`, `uid`).
**Règle Sigma existante** : `linux/t1548_001_setuid_setgid.yml`.

> ⚠️ **Gap important** : cette règle détecte l'**ajout** du bit setuid (`chmod +s`, `chmod 4755`) ou sa **recherche** (`find -perm -4000`). Elle ne détecte **pas l'exploitation** d'un binaire SUID déjà présent (technique GTFOBins classique : `find . -exec /bin/sh -p \; -quit`, `vim -c ':!sh'`, etc.). C'est pourtant l'action réelle de cette phase du scénario. À combler avec une règle dédiée listant les binaires GTFOBins connus lancés avec les options d'échappement typiques (proposition section 11).

### Étapes d'investigation
1. Identifier le binaire SUID exploité et sa ligne de commande complète (`command_line`).
2. Vérifier le changement d'UID effectif juste après (commande `id` suivante dans la timeline auditd — confirme `uid=0` ou `euid=0`).
   > Note : le champ `euid` n'est pas confirmé mappé dans votre fichier — vérifier, sinon s'appuyer sur la commande `id` explicite lancée par l'attaquant lui-même pour confirmer.
3. Horodater précisément le moment de bascule root — nouveau point de repère majeur dans la timeline.

### Décision
- **Root confirmé → incident critique.** Dans un contexte réel : escalade immédiate vers le management/CISO, l'hôte n'est plus considéré comme fiable (compromission totale).

### Confinement possible
- Isolement réseau immédiat recommandé dans un cas réel dès confirmation root.
- Préservation de l'état système pour analyse forensic avant toute remédiation (snapshot disque si VM).

---

## 8. Phase 7 — Persistence

### 7a. Ajout d'une clé SSH dans `~/.ssh/authorized_keys` (T1098.004)

> ⚠️ **Gap critique — visibilité actuellement nulle.** En reprenant votre configuration auditd fournie précédemment, aucune règle `-w` ne surveille `~/.ssh/authorized_keys` ou le dossier `.ssh` d'un utilisateur. Une redirection shell (`echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys`) n'émet **qu'un seul EXECVE** (pour `echo`), et l'écriture elle-même via redirection shell n'est **pas capturée** par vos règles actuelles (pas de watch fichier sur ce chemin). Si l'attaquant utilise un éditeur (`vim`, `nano`, `tee`) pour écrire la clé, la commande sera visible dans EXECVE — mais la modification du fichier lui-même ne sera pas confirmée par un événement dédié.
>
> **Recommandation concrète** : ajouter dans `/etc/audit/rules.d/soc.rules` une règle de surveillance dédiée par utilisateur connu, par exemple :
> ```
> -w /home/charlie/.ssh/authorized_keys -p wa -k ssh_persistence
> -w /root/.ssh/authorized_keys -p wa -k ssh_persistence
> ```
> (`auditd` ne supporte pas les wildcards dans les chemins de `-w` — il faut soit une règle par utilisateur connu du lab, soit un contrôle d'intégrité de fichier planifié en complément.)

#### Étapes d'investigation (avec la visibilité actuelle limitée)
1. Chercher dans EXECVE toute commande contenant `authorized_keys` (`echo`, `cat`, `tee`, `vim`, `nano`) dans la fenêtre post-privesc.
2. Si présente, extraire la clé publique ajoutée — **IOC direct et réutilisable** (recherche de cette même clé sur d'autres hôtes du parc = détection de réutilisation par le même attaquant).
3. Vérification manuelle recommandée en complément : comparer l'horodatage de modification du fichier (`stat ~/.ssh/authorized_keys`) avec la timeline d'incident.

### 7b. Service systemd malveillant `/etc/systemd/system/backdoor.service` (T1543.002)

**Sources** : auditd `-w /etc/systemd/system -p wa -k systemd_change` (déjà configuré ✅ — bonne visibilité ici, contrairement à 7a).
**Règle Sigma** : aucune actuellement dédiée bien que la source existe — à créer (proposition section 11).

#### Étapes d'investigation
1. Rechercher les événements auditd `key=systemd_change` sur `/etc/systemd/system` dans la fenêtre post-privesc.
2. En parallèle, chercher dans EXECVE les commandes `systemctl daemon-reload`, `systemctl enable backdoor.service`, `systemctl start backdoor.service`.
3. Le contenu exact du fichier (`ExecStart=...`) n'est **pas visible dans les logs** (le watch auditd confirme une écriture, pas le contenu) — la commande qui a écrit le fichier (`echo`/`cat`/`tee`/éditeur) l'est en revanche via EXECVE, avec le `command_line` complet reconstruit.
4. Récupération manuelle du contenu du fichier sur l'hôte pour confirmer le `ExecStart` malveillant (reverse shell attendue).
5. Vérifier l'état du service (`systemctl status backdoor.service`) pour savoir s'il est actif.
6. Corréler avec le réseau : chercher une connexion sortante (Suricata/Zeek) coïncidant avec le démarrage du service — c'est probablement l'ouverture de la reverse shell elle-même.

### Décision (7a + 7b)
- Toute persistence confirmée = la remédiation doit **survivre à un reboot** : désactivation ET suppression du service (`systemctl disable --now backdoor.service && rm /etc/systemd/system/backdoor.service`), suppression de la clé SSH injectée, **avant** de considérer l'hôte comme assaini.
- Vérifier également l'absence de la 3ᵉ technique de persistence mentionnée dans le scénario original (cron `@reboot`) même si elle n'a pas été utilisée ici — bon réflexe pour ne rien assumer.

---

## 9. Phase 8 — Collecte de données sensibles (T1005 / T1552.001)

**Sources** : auditd EXECVE (`command_line` révèle les commandes `cat`, `cp`, `tar` sur les fichiers sensibles).

### Étapes d'investigation
1. Dans la timeline EXECVE, chercher toute commande de lecture/copie sur `/etc/shadow`, `~/.ssh/id_rsa` (ou autres clés privées), et tout fichier applicatif sensible du lab.
2. Confirmer l'ordre chronologique : la collecte doit précéder l'exfiltration (phase 9) — si l'ordre est inversé dans la timeline, creuser (possible activité manquée en amont).
3. Lister précisément quelles données ont été consultées vs. réellement exfiltrées (les deux ne sont pas toujours identiques).

### Décision
Toute lecture confirmée de `/etc/shadow` ou de clés privées = à traiter comme une fuite de secrets **avérée**, indépendamment de la confirmation d'exfiltration réseau : ces secrets doivent être considérés comme compromis et **rotés** (changement de tous les mots de passe/clés concernés), même si le transfert réseau n'est pas confirmé à 100 %.

---

## 10. Phase 9 — Exfiltration HTTP (T1048.003)

**Sources** : auditd EXECVE (commande `curl` complète avec URL, fichier, rate-limit), Zeek conn (`dest_port=8080`, `duration`).

> ⚠️ **Gap** : aucune règle Suricata custom actuelle ne couvre spécifiquement ce pattern d'exfiltration (POST HTTP volumineux vers un port non standard). La règle Sigma `network/t1567_exfiltration_web_service.yml` construite précédemment filtre sur `dest_port: 443` — **elle ne se déclenche pas sur ce scénario** (port 8080, HTTP en clair). C'est une vraie divergence entre la détection existante et ce cas d'usage précis, à corriger (proposition section 11) plutôt qu'à ignorer.

### Étapes d'investigation
1. Extraire la commande `curl` complète via `command_line` (grâce au lookup `execve_decode`) : elle révèle directement l'URL de destination, le fichier exfiltré (`test-exfil.bin`), et la limitation de débit — **IOC directement exploitable** (IP:port du serveur de réception de l'attaquant).
2. Confirmer via Zeek conn la connexion sortante correspondante (`dest_port=8080`, durée cohérente avec le débit limité à 200k/s et la taille du fichier).
3. Vérifier si le fichier `test-exfil.bin` correspond bien aux données identifiées en phase 8 (contenu réellement sensible archivé sous ce nom, ou juste un test/POC dans le cadre du lab).

### Décision
Exfiltration confirmée = **incident majeur**. Dans un contexte réel : déclenchement des procédures de notification (juridique, RGPD si données personnelles, direction).

### Confinement possible
- Blocage de l'IP/port de destination en sortie (pare-feu).
- Isolement complet de l'hôte.
- Préservation de l'image disque pour une analyse forensic approfondie avant toute remédiation.

---

## 11. Phase 10 — Anti-forensics : effacement de l'historique (T1070.003)

**Sources** : auditd EXECVE (`history -c`, `unset HISTFILE`, `export HISTFILE=/dev/null`), **et** événement `key=file_delete` déjà configuré (`-a always,exit -F arch=b64 -S unlink -k file_delete`) si le fichier `.bash_history` est directement supprimé plutôt que vidé en mémoire.

### Étapes d'investigation
1. Rechercher l'événement précis (`history -c` en EXECVE, ou `unlink`/`unlinkat` sur `.bash_history`) — **son horodatage devient la borne de fin de la fenêtre d'activité active de l'attaquant** sur l'hôte, utile pour cadrer le rapport d'incident.
2. Point important à noter dans le rapport : le fait que cet événement soit **quand même visible** dans auditd (et déjà transmis à Splunk avant toute tentative de nettoyage local) démontre que l'attaquant n'a pas pu supprimer les traces côté SIEM — un des bénéfices concrets du forwarding centralisé à mettre en avant.
3. Vérifier si l'attaquant a aussi tenté d'agir sur `/var/log/auth.log`, `/var/log/sudo.log`, ou `/var/log/audit/audit.log` localement (`shred`, `rm`, `truncate`, `> fichier`) — si oui, ajouter la technique **T1070.002 (Clear Linux or Mac System Logs)** au dossier d'incident.

### Décision
La présence de cette étape est un signal de sophistication de l'attaquant (pas une activité opportuniste basique) → doit influencer à la hausse la priorité globale de l'incident et motiver une investigation forensic plus poussée (possibilité de retour de l'attaquant).

---

## 12. Template — Evidence & Timeline Tracker

À dupliquer pour chaque investigation réelle.

| Horodatage | Hôte | Source de log | Commande / événement brut | Technique MITRE | Analyste | Verdict | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

---

## 13. Récapitulatif — statut de détection par phase

| Phase | Détection automatique | Statut |
|---|---|---|
| 1. Scan réseau | `t1595_active_scanning.yml` | ✅ Couvert |
| 2. Scan de ports | `t1046_network_service_discovery.yml` | ✅ Couvert |
| 3. Bannière FTP | — | ❌ Non couvert (gap de visibilité applicative) |
| 4. Brute force SSH | `t1110_ssh_brute_force.yml` | ⚠️ Partiel (pas de seuil par IP) |
| 5. Reconnaissance interne | `t1087_account_discovery_linux.yml` | ⚠️ Partiel (whoami/hostname/sudo -l manquants) |
| 6. Privesc SUID (exploitation) | `t1548_001_setuid_setgid.yml` | ⚠️ Partiel (couvre l'ajout du bit, pas l'exploitation GTFOBins) |
| 7a. Persistence clé SSH | — | ❌ Non couvert (aucun watch auditd sur authorized_keys) |
| 7b. Persistence service systemd | — | ⚠️ Source dispo (`systemd_change`), pas de règle Sigma dédiée |
| 8. Collecte de données | — | ❌ Non couvert par une règle dédiée (visible manuellement via EXECVE) |
| 9. Exfiltration HTTP | `t1567_exfiltration_web_service.yml` | ⚠️ Ne se déclenche pas sur ce scénario (port 443 ≠ port 8080) |
| 10. Anti-forensics | — | ⚠️ Source dispo (`file_delete`), pas de règle Sigma dédiée |

**Sur 10 phases : 2 couvertes, 6 partiellement couvertes, 2 non couvertes.** C'est un résultat honnête et normal pour un premier passage de détection — le documenter tel quel dans ton repo (avec ce tableau) est nettement plus convaincant en entretien qu'un lab qui prétend tout détecter.

---

## 14. Actions de suivi recommandées (par priorité)

1. **Critique** — ajouter un watch auditd sur `~/.ssh/authorized_keys` par utilisateur connu du lab.
2. **Critique** — mapper `src_ip` pour sshd/linux_auth (extraction `rex`), condition de tout confinement réseau fiable.
3. **Haute** — créer une règle Sigma pour l'exploitation SUID (GTFOBins) distincte de celle sur l'ajout du bit.
4. **Haute** — créer une règle Sigma pour T1543.002 (service systemd), la source de log existe déjà.
5. **Moyenne** — étendre `t1087_account_discovery_linux.yml` à whoami/hostname/sudo -l.
6. **Moyenne** — élargir ou dupliquer `t1567_exfiltration_web_service.yml` pour couvrir les ports HTTP non standard (8080) en plus du 443.
7. **Basse** — créer une règle Sigma pour T1070.003 (clear history).
8. **Amélioration lab** — ajouter la visibilité applicative FTP (Zeek `ftp.log` ou règle Suricata dédiée).

---

## 15. Corrélation avec la capture réseau brute (tcpdump, rétention 2 jours)

**Principe** : Suricata/Zeek donnent des métadonnées et des alertes, mais pas le contenu applicatif complet. Le pcap brut comble une partie des gaps identifiés plus haut — à condition de l'extraire **avant l'expiration de la rétention de 2 jours**. Dès qu'un incident touchant ces phases est confirmé, extraire et archiver le pcap concerné en dehors de la fenêtre de rotation devient une priorité opérationnelle immédiate, pas une tâche de fin d'investigation.

| Phase | Valeur ajoutée du pcap | Commande d'extraction indicative |
|---|---|---|
| 1-2. Scan réseau/ports | Confirmation fine du motif de scan (ordre des ports, timing exact entre paquets SYN) | `tcpdump -r capture.pcap "host <ip_attaquant>"` |
| 3. Bannière FTP | **Résout le gap identifié en section 4** : FTP est en clair, le pcap contient donc la bannière et le username qui a fuité, en texte intégral | `tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg` |
| 4. Brute force SSH | SSH est chiffré : le contenu (username/mot de passe testés) reste invisible, mais le pcap confirme indépendamment le **nombre exact de tentatives**, le **timing précis**, et surtout **l'IP:port source réelle** — ce qui contourne le gap `src_ip` non mappé dans Splunk pour cette source | `tshark -r capture.pcap -Y "tcp.port==22 and ip.addr==<ip_attaquant>" -T fields -e frame.time -e tcp.flags` |
| 5-8. Recon interne, privesc, persistence, collecte | Ces actions passent par le tunnel SSH déjà établi : **contenu illisible** (chiffré). Le pcap confirme uniquement la présence et la durée d'une session interactive active (volumétrie, keep-alives), utile pour borner la fenêtre d'activité sans en connaître le détail | `tshark -r capture.pcap -Y "tcp.port==22" -T fields -e frame.time -e tcp.len` |
| 7b. Service systemd (si reverse shell type `bash -i >&/dev/tcp/...`) | **Point critique** : une reverse shell `/dev/tcp` n'est **pas chiffrée**. Si le service backdoor en ouvre une, le pcap contient l'intégralité des commandes tapées par l'attaquant en clair après la persistence — bien plus riche que les logs auditd seuls | `tshark -r capture.pcap -Y "tcp.port==<port_reverse_shell>" -z follow,tcp,ascii,<stream_id>` |
| 9. Exfiltration HTTP | **Résout un gap majeur** : le `curl` était en HTTP simple (pas HTTPS) vers le port 8080 — le corps de la requête POST (`--data-binary`) est donc **recoupable intégralement** dans le pcap, permettant de confirmer exactement quelles données sont sorties, octet pour octet | `tshark -r capture.pcap -Y "http.request.method==POST and tcp.port==8080" -z follow,tcp,ascii,<stream_id>` |

**À consigner dans le rapport** : pour chaque preuve extraite du pcap, noter le nom du fichier pcap, le stream ID Wireshark/tshark, et un hash (`sha256sum`) du pcap au moment de l'extraction — traçabilité de la preuve en cas de suite judiciaire ou d'audit interne.

---

## 16. Quand pivoter vers l'endpoint (au-delà du SIEM)

Règle générale : **toute phase marquée ⚠️ ou ❌ dans le tableau de la section 13 est, par définition, un moment où le SIEM seul ne suffit pas** — c'est le signal qu'il faut aller vérifier directement sur l'hôte. Au-delà de cette règle générale, voici les points de pivot obligatoires sur ce scénario précis :

| Moment | Pourquoi pivoter maintenant | Ce qu'on va chercher sur l'hôte |
|---|---|---|
| Dès confirmation phase 4 (brute force réussi) | C'est le vrai point de départ de l'incident — ne plus attendre les alertes suivantes pour commencer la vérification live | Sessions actives (`who`, `w`), process SSH en cours |
| Après phase 5 (recon interne) | Confirmer l'étendue exacte de ce que l'attaquant a pu consulter, au-delà de ce que révèle `command_line` (ex: contenu réellement lu dans `/etc/shadow` si la lecture a réussi) | Permissions effectives du compte, contenu des fichiers consultés |
| Dès confirmation phase 6 (privesc root) | Le compte n'est plus fiable : il faut vérifier en direct, pas seulement via les logs qui pourraient eux-mêmes être altérés une fois root obtenu | `id`, `sudo -l`, historique shell actuel, process root actifs |
| Phase 7 (persistence) — **pivot obligatoire, pas optionnel** | Gap de détection confirmé (section 8) : les logs ne peuvent ni confirmer ni infirmer la présence d'une clé SSH injectée ou d'un service systemd tant que les règles ne sont pas corrigées — seule une vérification directe sur l'hôte donne une réponse fiable | `cat ~/.ssh/authorized_keys` (tous les comptes), `systemctl list-unit-files \| grep -i backdoor`, `crontab -l` pour tous les users, `ls -la /etc/cron.d/` |
| Après phase 9 (exfiltration) | Vérifier s'il reste des fichiers préparés/archivés sur le disque (staging), et si l'outil d'exfiltration tourne encore | `ls -la` sur les répertoires temporaires/home, `ps aux \| grep curl`, connexions réseau actives |
| Après phase 10 (anti-forensics) | Les logs pourraient être partiellement compromis à partir de cet instant : la vérification live devient la source la plus fiable pour la suite | État réel de `.bash_history`, `$HISTFILE`, dernière activité shell |

---

## 17. Commandes de détection live et de remédiation à inclure dans le rapport

Structuré selon le cycle standard de réponse à incident (détection → confinement → éradication → récupération). **Toujours préserver les preuves avant de remédier** — une commande de nettoyage exécutée trop tôt peut détruire une preuve nécessaire à la suite du dossier.

### 17.1 Détection live (lecture seule, à exécuter en premier)

**Sessions actives / présence de l'attaquant en ce moment**
```bash
who                          # sessions interactives actuellement ouvertes
w                             # idem, avec la commande en cours par session
last -a | head -30            # historique des connexions récentes, avec IP source
ss -tnp | grep ':22'          # connexions SSH établies, avec PID
```

**Connexions réseau suspectes / reverse shell active**
```bash
ss -tnp                       # toutes les connexions actives avec PID/process
lsof -i -P -n                 # alternative si ss limité, mappe socket -> process
ps auxf                       # arborescence des process, repère un parent inhabituel (ex: sshd -> bash -> nc)
```

**Vérification de persistence (à faire pour CHAQUE compte utilisateur du système, pas seulement le compte compromis)**
```bash
for u in $(cut -f1 -d: /etc/passwd); do
  echo "== $u =="; cat /home/$u/.ssh/authorized_keys 2>/dev/null
done
systemctl list-unit-files --state=enabled | grep -vE '^(systemd|cron|ssh|network)'
find /etc/systemd/system -maxdepth 1 -newer /etc/hostname -type f
crontab -l -u <user_compromis> 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.d/
find / -perm -4000 -type f 2>/dev/null   # comparer à une baseline connue du système sain
```

**État de l'historique shell (fenêtre d'activité, anti-forensics)**
```bash
echo $HISTFILE
stat ~/.bash_history
```

### 17.2 Confinement (une fois les preuves capturées)

**Couper la session active de l'attaquant sans tuer tout le serveur**
```bash
# Identifier le PID exact via w/who/ss avant de cibler
kill -9 <pid_session_attaquant>
# Ou, si systemd-logind est utilisé, plus propre :
loginctl terminate-user <user_compromis>
```
> ⚠️ Attention à l'ordre : si une persistence automatique (service systemd, cron) n'est pas encore désactivée, tuer la session ne fait qu'interrompre temporairement l'accès — l'attaquant (ou son implant) peut revenir immédiatement. Traiter confinement de session et éradication de la persistence **dans la même fenêtre d'intervention**, pas en deux temps espacés.

**Neutraliser le compte compromis**
```bash
usermod -L <user_compromis>                    # verrouille le mot de passe
usermod -s /usr/sbin/nologin <user_compromis>   # empêche toute nouvelle connexion shell
```
> Ne pas se contenter de forcer un changement de mot de passe (`passwd -e`) si le compte est confirmé compromis avec persistence par clé SSH : la clé injectée contourne le mot de passe. Le retrait de la clé (ci-dessous) est indispensable en complément.

**Blocage réseau (à défaut d'un contrôle périmétrique déjà en place)**
```bash
iptables -A OUTPUT -d <ip_attaquant> -j DROP
iptables -A INPUT -s <ip_attaquant> -j DROP
```
> Un blocage au pare-feu périmétrique (ou EDR/NDR central) est préférable à un blocage local uniquement — un attaquant root peut modifier les règles iptables locales. Demander le blocage en parallèle côté équipe réseau.

### 17.3 Éradication (suppression de la persistence)

**Retirer la clé SSH injectée — jamais supprimer tout le fichier en aveugle**
```bash
# 1. Identifier précisément la ligne injectée (comparer avec une sauvegarde connue si disponible)
cat ~/.ssh/authorized_keys
# 2. Supprimer uniquement la ligne correspondant à la clé de l'attaquant (remplacer le motif)
sed -i '/<empreinte_ou_extrait_unique_de_la_cle_attaquant>/d' ~/.ssh/authorized_keys
```

**Supprimer le service systemd malveillant**
```bash
systemctl stop backdoor.service
systemctl disable backdoor.service
rm -f /etc/systemd/system/backdoor.service
systemctl daemon-reload
systemctl reset-failed
```

**Retirer toute entrée cron injectée si trouvée (persistence non utilisée ici mais à vérifier systématiquement)**
```bash
crontab -e -u <user_compromis>     # retrait manuel interactif, plus sûr qu'un sed aveugle
ls -la /etc/cron.d/                # vérifier l'absence de fichier ajouté récemment
```

**Traiter les fuites de secrets confirmées (phase 8)**
```bash
# Rotation de TOUS les secrets consultés/exfiltrés, pas seulement ceux du compte initial
passwd <chaque_user_concerné>          # nouveaux mots de passe
# Régénérer et redistribuer toute clé SSH présente dans /etc/shadow ou home dirs consultés
```

### 17.4 Récupération et vérification post-remédiation
```bash
# Revérifier l'absence de persistence après nettoyage
for u in $(cut -f1 -d: /etc/passwd); do cat /home/$u/.ssh/authorized_keys 2>/dev/null; done
systemctl list-unit-files --state=enabled | grep -i backdoor   # doit être vide
find / -perm -4000 -type f 2>/dev/null   # comparer de nouveau à la baseline
who; w                                    # confirmer l'absence de session résiduelle
```

**À consigner dans le rapport final** : horodatage de chaque commande exécutée, résultat obtenu, et nom de l'analyste — ce tableau devient la section "actions de remédiation" du rapport d'incident.
