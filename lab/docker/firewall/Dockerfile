# PaySecure core firewall: iptables FORWARD access matrix; decisions logged via NFLOG -> ulogd -> syslog.
FROM alpine:3.20
RUN apk add --no-cache iptables ulogd busybox-extras
COPY ulogd.conf /etc/ulogd.conf
COPY rules.sh start.sh /lab/
RUN chmod 755 /lab/*.sh
ENTRYPOINT ["/lab/start.sh"]
