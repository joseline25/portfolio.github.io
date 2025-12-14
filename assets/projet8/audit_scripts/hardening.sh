#!/bin/bash

# ==========================================
# Script de Hardening 
# Cible : Ubuntu 20.04
# Objectif : Corriger les non-conformités OpenSCAP
# ==========================================

echo "[*] Démarrage du processus de durcissement..."

# --- 1. Correction SSH : Désactiver le login Root ---
echo "[+] Sécurisation du service SSH..."

# On sauvegarde le fichier de config au cas où
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# On utilise sed pour modifier la ligne PermitRootLogin
# On remplace "PermitRootLogin yes" (ou commenté) par "PermitRootLogin no"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# On redémarre le service pour appliquer
systemctl restart sshd

if [ $? -eq 0 ]; then
    echo "    -> Succès : Login Root désactivé."
else
    echo "    -> Erreur lors du redémarrage SSH."
fi


# --- 2. Correction Système : Activer l'ASLR (Randomize VA Space) ---
echo "[+] Activation de la protection mémoire ASLR..."

# Application immédiate (en mémoire)
sysctl -w kernel.randomize_va_space=2 > /dev/null

# Application persistante (pour le prochain redémarrage)
# On vérifie si la ligne existe déjà pour éviter les doublons
if grep -q "kernel.randomize_va_space" /etc/sysctl.conf; then
    sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space = 2/' /etc/sysctl.conf
else
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
fi

echo "    -> Succès : ASLR configuré sur 2 (Full Randomization)."


# --- Fin ---
echo "[*] Durcissement terminé."