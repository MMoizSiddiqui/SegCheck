"""Replay genuine pfSense filterlog messages captured from the project's VirtualBox lab."""
import json
import socket
import time
from pathlib import Path

from segcheck_web.services.firewall_connector import DeviceListener, parse_firewall_line

CAPTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "pfsense-events.jsonl"  # real pfSense filterlog capture


def real_messages():
    return [json.loads(line)["raw_message"] for line in CAPTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_every_captured_pfsense_message_parses_as_a_block():
    messages = real_messages()
    assert len(messages) >= 4
    for message in messages:
        event = parse_firewall_line(message)
        assert event is not None, message
        assert event["format"] == "pf_filterlog" and event["action"] == "block"
        assert event["source_ip"] == "10.20.0.100" and event["destination_ip"] == "10.30.0.10"
        assert event["protocol"] == "tcp" and event["destination_port"] == 8080
        assert event["interface"] == "em2" and event["rule"] == "1791895687"


def test_real_pfsense_messages_flow_through_the_live_listener():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    listener = DeviceListener({"id": "pfsense", "name": "pfSense", "kind": "pfsense", "log_port": port, "log_sender_ip": "127.0.0.1"}, "127.0.0.1", None)
    listener.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            for message in real_messages():
                sender.sendto(message.encode(), ("127.0.0.1", port))
        for _ in range(40):
            if listener.stats["parsed"] >= len(real_messages()):
                break
            time.sleep(0.05)
        assert listener.stats["parsed"] == len(real_messages()) and listener.stats["unparsed"] == 0
        assert {event["action"] for event in listener.events} == {"block"}
    finally:
        listener.stop()
