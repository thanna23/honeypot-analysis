#!/usr/bin/env bash
# Install the Cowrie SSH honeypot on a fresh Ubuntu 24.04 EC2 instance
# (Parts 3 and 4 of the guide as one script).
#
# What it does:
#   1. installs system packages
#   2. creates a "cowrie" user (Cowrie refuses to run as root)
#   3. installs Cowrie in a virtual environment and sets a believable hostname
#   4. starts Cowrie on port 2222 and restarts it after reboots
#   5. moves the real SSH to port 22222
#   6. redirects port 22 to Cowrie (2222) and keeps the rule after reboots
#
# BEFORE running, in the AWS security group (or you will lock yourself out):
#   - add an inbound rule: Custom TCP 22222 from My IP
# AFTER it finishes:
#   - test the real SSH in a NEW terminal, keeping this one open:
#       ssh -i ~/.ssh/honeypot-key.pem -p 22222 ubuntu@<PUBLIC_IP>
#   - only then change the port 22 rule's source to Anywhere-IPv4 (0.0.0.0/0)
#
# Run on the server as ubuntu:   sudo bash install.sh
# It also works unattended as EC2 user data (runs as root at first boot).
# Safe to run more than once.

set -euo pipefail

HONEYPOT_HOSTNAME="web-prod-02"   # the name attackers see in the fake shell
REAL_SSH_PORT=22222               # your real admin SSH
COWRIE_PORT=2222                  # Cowrie's default listening port
COWRIE_HOME=/home/cowrie/my-honeypot

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo bash $0" >&2
    exit 1
fi

# never stop to ask questions during apt installs
export DEBIAN_FRONTEND=noninteractive

# --- 1. System packages ------------------------------------------------------
apt-get update
apt-get upgrade -y
apt-get install -y python3-pip python3-venv libssl-dev libffi-dev \
    build-essential libpython3-dev python3-minimal authbind

# --- 2. Dedicated cowrie user ------------------------------------------------
if ! id cowrie >/dev/null 2>&1; then
    adduser --disabled-password --gecos "" cowrie
fi

# --- 3. Install Cowrie as the cowrie user ------------------------------------
sudo -u cowrie -H bash <<EOF
set -euo pipefail
mkdir -p "$COWRIE_HOME" && cd "$COWRIE_HOME"
[ -d cowrie-env ] || python3 -m venv cowrie-env
source cowrie-env/bin/activate
python -m pip install --upgrade pip
python -m pip install cowrie
[ -f etc/cowrie.cfg ] || cowrie init

# set the fake hostname: replace it if already set, otherwise add the section
if grep -q '^hostname' etc/cowrie.cfg; then
    sed -i 's/^hostname.*/hostname = $HONEYPOT_HOSTNAME/' etc/cowrie.cfg
elif grep -q '^\[honeypot\]' etc/cowrie.cfg; then
    sed -i '/^\[honeypot\]/a hostname = $HONEYPOT_HOSTNAME' etc/cowrie.cfg
else
    printf '\n[honeypot]\nhostname = %s\n' "$HONEYPOT_HOSTNAME" >> etc/cowrie.cfg
fi
EOF

# --- 4. Start Cowrie, and restart it after reboots ---------------------------
CRON_LINE="@reboot cd $COWRIE_HOME && ./cowrie-env/bin/cowrie start"
# add the line to cowrie's crontab only if it isn't there yet
( crontab -u cowrie -l 2>/dev/null | grep -vF "$CRON_LINE" || true; echo "$CRON_LINE" ) \
    | crontab -u cowrie -

# "restart" also works if it's already running
sudo -u cowrie -H bash -c "cd $COWRIE_HOME && ./cowrie-env/bin/cowrie restart"

# --- 5. Move the real SSH to port 22222 --------------------------------------
# turns "#Port 22" or "Port 22" into "Port 22222"
sed -i -E "s/^#?Port .*/Port $REAL_SSH_PORT/" /etc/ssh/sshd_config
grep -q "^Port $REAL_SSH_PORT" /etc/ssh/sshd_config \
    || echo "Port $REAL_SSH_PORT" >> /etc/ssh/sshd_config

# Ubuntu 24.04 starts SSH through ssh.socket, which reads the port from sshd_config
systemctl daemon-reload
systemctl restart ssh.socket
if ! ss -tln | grep -q ":$REAL_SSH_PORT "; then
    systemctl restart ssh
fi

# --- 6. Redirect port 22 to Cowrie and keep it after reboots -----------------
# -C checks whether the rule already exists, so it isn't added twice
iptables -t nat -C PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$COWRIE_PORT" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port "$COWRIE_PORT"

# answer "Yes" to saving the rules in advance, so the install doesn't stop to ask
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
apt-get install -y iptables-persistent
netfilter-persistent save

# --- Check -------------------------------------------------------------------
echo
echo "Listening ports (expect $COWRIE_PORT for Cowrie and $REAL_SSH_PORT for real SSH):"
ss -tln | grep -E ":($COWRIE_PORT|$REAL_SSH_PORT) " || true
echo
echo "Done. Test the real SSH on port $REAL_SSH_PORT in a new terminal before"
echo "opening port 22 to Anywhere-IPv4 in the security group."
