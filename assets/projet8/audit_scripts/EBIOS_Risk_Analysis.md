# Analyse de risques (EBIOS RM) – Résultats de l’audit OpenSCAP sur `iam-app`

Ce document présente trois scénarios de risques élaborés à partir des résultats de l’audit OpenSCAP réalisé sur le serveur applicatif `iam-app` (Ubuntu 20.04).  
Chaque fiche de risque suit la logique d’une analyse EBIOS RM simplifiée : vulnérabilité technique observée, bien support et bien essentiel, source de menace, scénario de menace, impacts potentiels et mesures de sécurité recommandées.

---

## 1. Risque lié aux accès d’administration SSH

### Référence technique

**Vulnérabilité OpenSCAP**  
Règle : `xccdf_org.ssgproject.content_rule_sshd_disable_root_login`  
Résultat : `fail`  

Le compte `root` est autorisé à se connecter directement en SSH, ce qui constitue un point d’entrée critique sur le serveur.

### Biens concernés

**Bien support**  
Service SSH (`sshd`) exposé sur le serveur applicatif `iam-app`.

**Bien essentiel**  
Intégrité et confidentialité de l’ensemble des données et services hébergés sur le serveur IAM (application Flask, éventuelles bases de données, fichiers de configuration et journaux).

### Source de menace

Attaquant externe disposant d’un accès réseau au port SSH (Internet ou réseau non maîtrisé).  
La menace peut provenir soit d’un attaquant humain, soit d’un outil automatisé (botnet réalisant des attaques par dictionnaire).

### Scénario de menace

L’attaquant cible directement le compte `root` en SSH, en lançant une attaque par force brute sur le couple identifiant / mot de passe.  
Tant que le service SSH accepte la connexion directe de `root`, la compromission du mot de passe entraîne immédiatement une élévation de privilèges maximale.  
L’attaquant n’a plus besoin de réaliser une escalade de privilèges supplémentaire, ce qui réduit la complexité de l’attaque.

### Impacts potentiels

**Confidentialité**  
Impact critique.  
Une fois connecté en tant que `root`, l’attaquant peut lire tous les fichiers du système, exfiltrer les journaux, les données applicatives et toute information sensible stockée sur le serveur.

**Intégrité**  
Impact critique.  
L’attaquant peut modifier les configurations, altérer les journaux pour effacer ses traces, installer des portes dérobées et manipuler le code de l’application.

**Disponibilité**  
Impact critique.  
L’attaquant peut supprimer des fichiers système, interrompre des services ou déployer un rançongiciel, entraînant l’indisponibilité complète du service IAM.

### Mesures de sécurité recommandées

Désactiver la connexion SSH directe du compte `root` en modifiant le fichier `/etc/ssh/sshd_config` et en positionnant le paramètre :

```text
PermitRootLogin no
``` 

Recharger la configuration du service SSH et vérifier que la connexion directe en root n’est plus autorisée.

Compléter ce durcissement par une politique d’authentification basée sur des clés SSH plutôt que sur des mots de passe, et limiter les comptes autorisés à se connecter au serveur (groupe d’administrateurs dédié).

---

## 2. Risque lié à la protection mémoire (ASLR)

### Référence technique

**Vulnérabilité OpenSCAP**  
Règle : `xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space`  
Résultat : `fail`  

La randomisation de l’espace d’adressage mémoire (ASLR) n’est pas activée ou n’est pas configurée au niveau recommandé.

### Biens concernés

**Bien support**  
Noyau (kernel) du système d’exploitation Ubuntu exécuté sur le serveur `iam-app`.

**Bien essentiel**  
Intégrité de l’exécution des processus applicatifs, en particulier l’application Python Flask et les services associés.

### Source de menace

Attaquant externe exploitant une vulnérabilité de type corruption mémoire dans l’application ou dans une bibliothèque utilisée par l’application (dépassement de tampon, utilisation de pointeurs non contrôlés, etc.).

### Scénario de menace

L’application présente (ou présentera) une vulnérabilité de type dépassement de tampon.  
Sans ASLR ou avec une randomisation insuffisante, les adresses mémoire des segments de code et de données restent prévisibles d’un lancement à l’autre.  
L’attaquant peut alors construire un exploit fiable, par exemple en plaçant un shellcode à une adresse estimée et en réorientant l’exécution du programme vers cette zone mémoire.

L’absence de randomisation rend la mise au point de l’exploit nettement plus simple et augmente la probabilité de réussite d’une attaque visant à exécuter du code arbitraire sur le serveur.

### Impacts potentiels

**Intégrité**  
Impact élevé.  
L’attaquant peut exécuter du code de son choix dans le contexte du processus vulnérable, altérer le comportement de l’application, modifier des données en mémoire ou installer des composants malveillants.

**Disponibilité**  
Impact moyen.  
Les tentatives d’exploitation peuvent provoquer des plantages répétés de l’application ou du service concerné, entraînant des interruptions plus ou moins longues du service IAM.

### Mesures de sécurité recommandées

Activer la randomisation complète de l’espace d’adressage mémoire au niveau du noyau, en positionnant le paramètre suivant :

```bash
sysctl -w kernel.randomize_va_space=2
```

Rendre cette configuration persistante au redémarrage en ajoutant ou en modifiant la ligne correspondante dans le fichier `/etc/sysctl.conf` :

```text
kernel.randomize_va_space = 2
```

Appliquer ensuite les paramètres avec :

```bash
sysctl -p
```

Ce paramétrage ne dispense pas de corriger les vulnérabilités applicatives, mais il élève le niveau de résistance du système face aux attaques d’exploitation mémoire.

---

## 3. Risque lié à l’architecture de stockage (/var non isolé)

### Référence technique

**Vulnérabilité OpenSCAP**  
Règle : `xccdf_org.ssgproject.content_rule_partition_for_var`  
Résultat : `fail`  

Le répertoire `/var` n’est pas placé sur une partition dédiée. Il partage la même partition que la racine (`/`).

### Biens concernés

**Bien support**  
Système de fichiers du serveur, incluant la partition racine et les répertoires de journaux et de données applicatives.

**Bien essentiel**  
Disponibilité du service IAM fourni par l’application hébergée sur `iam-app`.  
Par extension, respect des engagements de disponibilité (SLA) associés à ce service.

### Source de menace

Deux types de sources de menace sont considérés :  

- Comportement anormal d’un processus interne (boucle de logs, dysfonctionnement d’une application générant un volume excessif de données dans `/var`).  
- Attaquant externe cherchant à provoquer un déni de service en saturant les journaux ou d’autres répertoires sous `/var` par des requêtes massives.

### Scénario de menace

Dans un premier cas, une application ou un service se met à générer un volume important de journaux dans `/var/log` (erreur de configuration, bug, boucles de tentatives de connexion, etc.).  
Dans un second cas, un attaquant génère un trafic intensif pour provoquer la création d’un grand nombre de logs ou de fichiers temporaires dans `/var`.

Comme `/var` se trouve sur la même partition que la racine, la saturation de l’espace disque sous `/var` entraîne la saturation de la partition système dans son ensemble.  
Lorsque le disque atteint 100 % d’occupation, le système d’exploitation ne peut plus créer de fichiers temporaires, de nouveaux journaux ou de sockets.  
Cela conduit à des dysfonctionnements généralisés, allant jusqu’au blocage du système ou à l’impossibilité d’ouvrir une session, y compris en SSH.

### Impacts potentiels

**Disponibilité**  
Impact critique.  
L’arrêt des services applicatifs, l’impossibilité de se connecter au serveur et l’éventuelle nécessité d’une intervention manuelle lourde (nettoyage, redémarrage en mode de secours) peuvent entraîner une indisponibilité prolongée du service IAM.

Les impacts sur la confidentialité et l’intégrité sont indirects dans ce scénario, mais des opérations de restauration peu maîtrisées peuvent également conduire à des pertes de données ou à des incohérences si la situation est mal gérée.

### Mesures de sécurité recommandées

Sur le plan architectural, la mesure de sécurité cible consiste à revoir le schéma de partitionnement du serveur afin de placer au minimum les répertoires `/var`, `/home` et `/tmp` sur des partitions dédiées, idéalement sous forme de volumes logiques (LVM).  
Cela permet de limiter l’impact d’une saturation sur une seule partition et de dimensionner différemment l’espace alloué aux journaux et aux données système.

En complément, et de manière plus immédiate dans un contexte de laboratoire, il est recommandé de :  

- Mettre en place une configuration de rotation des journaux (`logrotate`) plus agressive et adaptée aux volumes générés par les services.  
- Surveiller l’espace disque disponible sur la partition système à l’aide d’outils de monitoring et d’alertes, afin de détecter précocement toute dérive.  
- Limiter, lorsque cela est possible, le niveau de verbosité des journaux en environnement de production.