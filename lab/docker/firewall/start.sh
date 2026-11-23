#!/bin/sh
set -e
syslogd -n -R "${SYSLOG_TARGET:-10.40.0.100:5514}" -L &
sleep 1
/lab/rules.sh "${MODE:-office}"
exec ulogd -c /etc/ulogd.conf
