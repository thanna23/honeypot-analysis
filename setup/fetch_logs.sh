#!/usr/bin/env bash
# Download the latest Cowrie logs from the honeypot into data/raw/.
#
# The server's IP is never written in this file (it must not end up on GitHub).
# Put it in a .env file in the project root, which .gitignore already excludes:
#     HONEYPOT_IP=1.2.3.4
# or pass it for one run:
#     HONEYPOT_IP=1.2.3.4 ./setup/fetch_logs.sh
#
# Optional: HONEYPOT_KEY to use a different key (default ~/.ssh/honeypot-key.pem)
#
# Usage, from anywhere:
#     ./setup/fetch_logs.sh

set -euo pipefail

# work from the project root (one folder up from this script)
cd "$(dirname "$0")/.."

# read HONEYPOT_IP (and HONEYPOT_KEY) from .env if they weren't given already
if [ -z "${HONEYPOT_IP:-}" ] && [ -f .env ]; then
    set -a; source .env; set +a
fi

if [ -z "${HONEYPOT_IP:-}" ]; then
    echo "HONEYPOT_IP is not set. Add a line HONEYPOT_IP=<server public IP> to .env" >&2
    exit 1
fi

KEY="${HONEYPOT_KEY:-$HOME/.ssh/honeypot-key.pem}"
REAL_SSH_PORT=22222
LOG_DIR=/home/cowrie/my-honeypot/var/log/cowrie

echo "Downloading logs from the honeypot..."
# download to a temporary file first, so a failed download
# doesn't overwrite the previous logs.tgz
ssh -i "$KEY" -p "$REAL_SSH_PORT" -o ConnectTimeout=15 "ubuntu@$HONEYPOT_IP" \
    "sudo tar czf - -C $LOG_DIR ." > logs.tgz.part \
    || {
        rm -f logs.tgz.part
        echo "Download failed. If it timed out, your home IP may have changed:" >&2
        echo "update the 'My IP' rule for port $REAL_SSH_PORT in the security group." >&2
        exit 1
    }
mv logs.tgz.part logs.tgz

# unpack into data/raw/ (each download is a full copy, so files are just replaced)
mkdir -p data/raw
tar xzf logs.tgz -C data/raw

# short summary of what's now on your laptop
files=$(ls data/raw/cowrie.json* | wc -l)
events=$(cat data/raw/cowrie.json* | wc -l)
echo "Done: $files log file(s), $events events in data/raw/"
