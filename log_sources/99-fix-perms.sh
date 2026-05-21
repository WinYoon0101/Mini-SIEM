#!/bin/sh
set -eu

echo "[modsec] Preparing audit log directory..."
LOG_DIR="/var/log/modsec"
LOG_FILE="${LOG_DIR}/audit.log"

mkdir -p "$LOG_DIR"
# Volume Docker mới thường là root:root 755 — mở quyền trước khi touch/chown
chmod 777 "$LOG_DIR" 2>/dev/null || true

if [ ! -f "$LOG_FILE" ]; then
  : >"$LOG_FILE" || touch "$LOG_FILE"
fi

if id nginx >/dev/null 2>&1; then
  chown -R nginx:nginx "$LOG_DIR" 2>/dev/null || true
fi
chmod 777 "$LOG_DIR" "$LOG_FILE" 2>/dev/null || true

if [ ! -w "$LOG_FILE" ]; then
  echo "[modsec] ERROR: ${LOG_FILE} is not writable" >&2
  ls -lan "$LOG_DIR" >&2 || true
  exit 1
fi

echo "[modsec] Audit log ready: $(ls -lan "$LOG_FILE")"
