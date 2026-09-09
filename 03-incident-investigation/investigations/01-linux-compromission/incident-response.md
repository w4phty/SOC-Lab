Contain → Eradicate → Recover → Validate

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
