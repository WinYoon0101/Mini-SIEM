#!/bin/sh
echo "Fixing permissions for ModSecurity audit log..."
mkdir -p /var/log/modsec
touch /var/log/modsec/audit.log
chown -R nginx:nginx /var/log/modsec
chmod 777 /var/log/modsec/audit.log
echo "Permissions fixed."
