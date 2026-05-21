#!/bin/sh
set -eu
LOG_DIR="/var/log/modsec"
LOG_FILE="${LOG_DIR}/audit.log"
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"
: >"$LOG_FILE"
chmod 666 "$LOG_FILE"
echo "[modsec-init] Created ${LOG_FILE} ($(wc -c <"$LOG_FILE") bytes)"
