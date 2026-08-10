écriture d'un script python pour automatiser l'écriture des alertes splunk à partir des règles sigma.

Utilisation de splunk free: pas possible d'utiliser les alertes programmées donc création de reports: windows, linux, network et global.

2 parties:
- custom_sigma2splunk.py : traduction de chaque règles sigma en requête spl
- splunk_report_generator.py : concaténation des requêtes splunk renvoyées par custom_sigma2splunk.py sous forme de reports directement utilisables dans splunk

Utilisation: 


Avantage:
- gain de temps initial pour la création des reports et pour les mises à jour
- gain de fiabilité, permets d'éviter les erreurs humaines


ici alertes arrivent dans stash, ok pour lab mais en environnement réel, il faudrait une vraie datasource

Lien vers les reports