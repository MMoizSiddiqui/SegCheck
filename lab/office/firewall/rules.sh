#!/bin/sh
# PaySecure Ltd access matrix.  Usage: rules.sh office | fixed
#   office : as found by the auditor, including one legacy misconfiguration
#   fixed  : after remediation (legacy rule removed)
# Every NEW connection decision is logged: SEGCHECK-ACCEPT (approved flow) or SEGCHECK-DROP.
set -e
MODE="${1:-office}"
GUEST=10.20.0.0/24 CORP=10.40.0.0/24 HR=10.50.0.0/24 DMZ=10.60.0.0/24 SRV=10.70.0.0/24 CDE=10.30.0.0/24
WEB=10.60.0.10 FILESRV=10.70.0.10 PAYAPI=10.30.0.10 CARDDB=10.30.0.20

allow() {  # allow <src> <dst> <proto> <ports> <label>
    iptables -A FORWARD -s "$1" -d "$2" -p "$3" -m multiport --dports "$4" -m conntrack --ctstate NEW \
        -j NFLOG --nflog-group 1 --nflog-prefix "SEGCHECK-ACCEPT $5"
    iptables -A FORWARD -s "$1" -d "$2" -p "$3" -m multiport --dports "$4" -j ACCEPT
}

iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Approved business flows
allow "$CORP" "$WEB" tcp 80,443 corp-web
allow "$CORP" "$FILESRV" tcp 445,389,8080 corp-servers
allow "$HR" "$FILESRV" tcp 445,389,8080 hr-servers
allow "$DMZ" "$PAYAPI" tcp 8443 checkout-payment-api
allow "$CORP" "$FILESRV" udp 53 corp-dns
if [ "$MODE" = "office" ]; then
    # Legacy reporting rule left behind by a decommissioned BI project (the finding).
    allow "$CORP" "$CARDDB" tcp 5432 legacy-reporting
fi

# Everything else between zones is denied and logged (PCI DSS 1.3.1 / 1.3.2 / 1.4.2)
iptables -A FORWARD -j NFLOG --nflog-group 1 --nflog-prefix SEGCHECK-DROP
iptables -A FORWARD -j DROP
echo "office firewall mode: $MODE"
