# Accès aux partages natifs

Cette extension du fork ajoute une politique d’accès au proxy public natif de
LERD. Elle nécessite ce binaire personnalisé ; le binaire standard ne fournit
pas ce contrat. La publication reste pilotée par `public:share` et son arrêt.
Modifier une politique ne démarre ni ne ferme un partage.

## Configuration portable

Dans la configuration globale LERD :

```yaml
share:
  public_base_domain: dev.example.com
  public_listen: "127.0.0.1:8089"
  trusted_proxies:
    - "127.0.0.1/32"
```

`public_listen` vide désactive l’ingress commun. Son adresse est choisie par
l’opérateur, sans adresse imposée. Changer l’adresse d’écoute nécessite le
redémarrage du daemon. Les autres réglages sont relus à chaque requête.
L’ingress commun route le Host exact vers un partage public actif. Un nom
inconnu, un partage arrêté ou un nom ambigu est refusé avec HTTP 403.
Les ports publics individuels restent disponibles avec **le même contrôle**.
Les partages LAN et le dashboard gardent leurs mécanismes existants.

Le proxy frontal doit terminer TLS et remplacer `X-Forwarded-For` par une seule
adresse IP de visiteur préalablement validée. LERD ne lit cet en-tête que lorsque
le pair réseau appartient à `trusted_proxies`. Une valeur manquante, une liste
d’adresses, un port ou une valeur invalide venant de ce pair est refusé. Les
en-têtes envoyés par un pair non approuvé ne changent jamais son identité IP.
N’approuver que les pairs effectivement contrôlés : un réseau approuvé trop
large permettrait à ses machines de déclarer une fausse identité.

## API locale pour les plugins

`GET /api/share-access?site=demo&branch=` retourne :

```json
{"version":1,"site":"demo","branch":"","inherited":false,"parent_revision":0,"mode":"closed","networks":[],"users":[],"rate":{"requests_per_second":0,"burst":60},"revision":0,"enforcement":"native"}
```

`site` est le nom interne LERD. `branch` est la branche native normalisée du
worktree, champ `branch` de `/api/sites`, et non son libellé Git `git_branch`.
Sans override, un worktree hérite de la politique et des comptes du site parent.
La réponse indique `inherited:true` et `parent_revision`, toujours égal à la
révision actuelle du parent. `revision` est la révision CAS propre à la branche ;
elle peut rester supérieure à zéro après une réinitialisation vers l’héritage.
Un parent absent est traité comme une politique `closed`.

`PUT` sur la même URL reçoit :

```json
{"site":"demo","branch":"","mode":"ip_and_password","networks":["192.0.2.0/24"],"credentials":[{"username":"reader","password":"change-this-password"}],"remove_users":[],"rate":{"requests_per_second":5,"burst":60},"revision":0}
```

Pour créer ou remplacer l’override d’un worktree, transmettre aussi le
`parent_revision` obtenu par GET. Les comptes hérités sont conservés côté
serveur lorsque l’override est créé. Réinitialiser explicitement vers l’héritage
avec `{"site":"demo","branch":"feature-a","inherit":true,"revision":2,"parent_revision":4}`.
Cette opération exige les révisions de branche et de parent lues par le client ;
une révision périmée retourne 409. Une modification ultérieure du parent ne
change pas un override existant.

Une politique parent absente est fermée, révision 0. Toute écriture réussie
incrémente la révision de la cible ; une révision périmée retourne 409. Une cible inconnue retourne
404 et une entrée invalide 400. Les protections d’autorité et CSRF du dashboard
s’appliquent. Un plugin local utilise son jeton natif pour ses requêtes.
Les réponses, erreurs et exports ne contiennent jamais de mot de passe ni de hash.
Les écritures depuis un navigateur exigent l’origine exacte du dashboard,
même si une application voisine est considérée « same-site ». Le proxy du
dashboard doit conserver son Host réel et transmettre son schéma HTTPS.
Un proxy local sur loopback peut transmettre ce schéma même lorsqu’il supprime
les en-têtes d’identité ; cela ne lui accorde aucune autorité supplémentaire.
Cette vérification couvre aussi les écritures des endpoints plugins marqués
`loopback_only`, avant le lancement de leur script.

Modes : `closed`, `public`, `ip`, `password`, `ip_and_password`,
`ip_or_password`. Les modes IP exigent au moins un CIDR IPv4 ou IPv6 valide.
`denial_status` vaut 403 par défaut, y compris pour les anciennes politiques,
ou 404 pour un refus fermé/IP avec une réponse neutre « page not found ».
Le challenge Basic reste 401 et la limitation de requêtes 429.
Les modes avec mot de passe exigent au moins un compte après les mutations.
Une mutation de compte remplace son secret ; `remove_users` retire des comptes.
Tout mot de passe non vide est accepté, sans longueur minimale ni limite bcrypt
de 72 octets. Le plafond technique du corps JSON reste de 64 Kio. Les nouveaux
secrets sont condensés en SHA-256, encodés en Base64 sans remplissage, puis
stockés en bcrypt avec le préfixe versionné `$lerd$sha256-bcrypt$v1$`.
Les anciens hashes bcrypt restent reconnus sans modification ; changer leur
mot de passe utilise automatiquement le nouveau format.
L’authentification Basic de la barrière utilise l’en-tête Authorization, retiré
avant l’application seulement lorsqu’il a servi à cette authentification.
Avec `ip_or_password`, une IP autorisée conserve l’authentification de
l’application, notamment Bearer. Avec `password` ou `ip_and_password`, un seul
en-tête HTTP ne peut pas porter simultanément le Basic de la barrière et un
Bearer applicatif ; l’application doit tenir compte de cette contrainte.

La limite `requests_per_second` est un nombre fini entre 0 et 100000 ; 0 la
désactive. `burst` est un entier entre 1 et 10000. Le seau est distinct pour
chaque site, branche et IP effective. Les tentatives refusées comptent aussi.
Un dépassement retourne 429 avec `Retry-After`. Il s’agit de requêtes, pas de
bande passante. Le compteur est en mémoire, remis à zéro au redémarrage ou à la
modification de la révision. Au maximum 10000 identités sont conservées ; au-delà,
les nouvelles identités sont refusées jusqu’à expiration des anciennes.

## Sauvegarde et restauration

`share-access.json` dans le dossier de configuration LERD contient les politiques
et leurs hashes bcrypt, sous permissions 0600. Les écritures API sont atomiques.
Une lecture impossible, un format non reconnu ou une configuration corrompue
ferme l’accès. Ne pas éditer ce fichier en parallèle des écritures du daemon.

`GET /api/share-access?export=1` exporte les politiques sans secrets. Les noms
de comptes restent présents pour la lisibilité ; les secrets doivent être
recréés sur la cible avant de pouvoir appliquer un mode avec authentification.
Cet export sert de référence portable, sans import automatique permissif.
Une sauvegarde privée complète du fichier conserve les hashes pour une
restauration à identité identique. Les CIDR approuvés, le domaine et l’écoute
globale doivent être adaptés à la nouvelle machine.

Cette évolution locale n’inclut pas de publication amont. Avant remplacement du
binaire, sauvegarder le binaire et la configuration, préparer les politiques
existantes, puis vérifier les accès directs et ceux du proxy frontal. Ne retirer
une ancienne barrière qu’après ces vérifications. Le retrait du fork exige de
rétablir cette barrière ou de fermer les ports : le binaire standard ignore ces
politiques.
