# Generic office system: listens on the TCP/UDP ports in $SERVICES; routes other zones via its firewall.
FROM python:3.12-alpine
RUN apk add --no-cache iproute2
COPY services.py /lab/services.py
ENTRYPOINT ["/bin/sh", "-c", "ip route replace 10.0.0.0/8 via $GATEWAY && ip route del default && exec python -u /lab/services.py"]
