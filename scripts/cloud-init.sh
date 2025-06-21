#!/bin/bash

set -e  # Exit on error

# Log everything to console + file + syslog
exec > >(tee -a /var/log/intake-bootstrap.log | logger -t intake-init -s) 2>&1

echo "[+] Installing Dokku v0.35.20"
wget -NP . https://dokku.com/bootstrap.sh --inet4-only
DOKKU_TAG="v0.35.20"
sudo DOKKU_TAG=$DOKKU_TAG bash bootstrap.sh

echo "[+] Clearing global Dokku domain"
dokku domains:clear-global

echo "[+] Setting inTake MOTD"
chmod -x /etc/update-motd.d/* || true

cat << "EOF" > /etc/motd
 __________________
< Welcome To inTake >
 ------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||

A lightweight developer PaaS  
powered by Dokku

👉 https://demo.gointake.ca
==========================================
EOF

echo "✅ Setup complete!"
