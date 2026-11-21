#!/bin/sh
# Audit host: one address per tested zone. Policy routing makes traffic from each address
# leave through that zone's firewall interface, exactly as a laptop plugged into that VLAN.
set -e
for zone in 20 40 60 30; do
    address="10.$zone.0.100"
    device=$(ip -o -4 addr show | awk -v a="$address/24" '$4 == a {print $2}')
    ip route replace "10.$zone.0.0/24" dev "$device" src "$address" table "$zone"
    ip route replace 10.0.0.0/8 via "10.$zone.0.1" dev "$device" table "$zone"
    ip rule add from "$address" lookup "$zone" priority "$((100 + zone))" 2>/dev/null || true
done
exec su segcheck -s /bin/sh -c "mkdir -p /home/segcheck/data && chmod 700 /home/segcheck/data && cd /app && SEGCHECK_CONTAINER=1 SEGCHECK_SETUP_TOKEN='$SEGCHECK_SETUP_TOKEN' python scripts/run_review_instance.py --data-dir /home/segcheck/data --host 0.0.0.0 --port 5000"
