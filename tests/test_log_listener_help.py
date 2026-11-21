"""The firewall log listener explains every problem with its feed and says how to fix it."""
import socket
import time

from segcheck_web.services.firewall_connector import DeviceListener
from test_environment_workflow import app  # noqa: F401  (fixture for the page test)


def device(port, sender="127.0.0.1"):
    return {"id": "fw", "name": "Core firewall", "kind": "pfsense", "log_port": port, "log_sender_ip": sender}


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(condition):
    for _ in range(40):
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_port_already_in_use_is_explained_with_the_fix():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as busy:
        busy.bind(("127.0.0.1", 0))
        port = busy.getsockname()[1]
        listener = DeviceListener(device(port), "127.0.0.1", None)
        listener.start()
        status = listener.status()
        assert not status["listening"]
        assert f"UDP port {port} is already used" in status["error"]
        assert any("Choose another port" in tip for tip in status["advice"])
        assert any("same port in the firewall" in tip for tip in status["advice"])


def test_address_not_on_this_pc_is_explained():
    listener = DeviceListener(device(free_udp_port()), "203.0.113.77", None)  # documentation address, never local
    listener.start()
    status = listener.status()
    assert "203.0.113.77 is not an address of this PC" in status["error"]
    assert any("Use this PC as the probe" in tip for tip in status["advice"])


def test_logs_from_another_sender_point_to_the_right_ip():
    port = free_udp_port()
    listener = DeviceListener(device(port, sender="10.99.99.1"), "127.0.0.1", None)
    listener.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"<134>filterlog: something", ("127.0.0.1", port))
        assert wait_for(lambda: listener.stats["rejected_sender"] == 1)
        tips = listener.status()["advice"]
        assert any("arriving from 127.0.0.1" in tip and "10.99.99.1" in tip for tip in tips)
    finally:
        listener.stop()


def test_unrecognised_format_is_explained():
    port = free_udp_port()
    listener = DeviceListener(device(port), "127.0.0.1", None)
    listener.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(b"hello, this is not a firewall log", ("127.0.0.1", port))
        assert wait_for(lambda: listener.stats["unparsed"] == 1)
        assert any("format is not recognised" in tip for tip in listener.status()["advice"])
    finally:
        listener.stop()


def test_silence_after_a_minute_lists_the_usual_causes():
    listener = DeviceListener(device(free_udp_port()), "127.0.0.1", None)
    listener.start()
    try:
        assert listener.status()["advice"] == []  # just started: nothing to say yet
        listener.started -= 61
        tips = " ".join(listener.status()["advice"])
        assert "remote logging" in tips and "Windows Firewall" in tips and "netsh" in tips
    finally:
        listener.stop()


def test_network_page_shows_the_problem_and_its_fixes(authenticated_client, monkeypatch):
    from werkzeug.datastructures import MultiDict
    from test_environment_workflow import configure
    from segcheck_web.extensions import db  # noqa: F401
    from segcheck_web.services.environment import save_device, settings
    from segcheck_web.services.firewall_connector import ConnectorRegistry

    app = authenticated_client.application
    with app.app_context():
        configure()
        save_device(MultiDict([("name", "Edge FW"), ("kind", "pfsense"), ("revision", str(settings()[0].revision)),
                               ("zones", "guest"), ("zones", "cde"), ("logging", "on"),
                               ("log_sender_ip", "10.20.0.1"), ("log_port", "5514")]))
        device_id = next(d["id"] for d in settings()[1]["devices"] if d["name"] == "Edge FW")
    broken = {device_id: {"connected": False, "listening": False, "parsed": 0,
                          "error": "UDP port 5514 is already used by another program on this PC.",
                          "advice": ["Choose another port for this device (for example 5515) and save it again."]}}
    monkeypatch.setattr(ConnectorRegistry, "status", lambda self: broken)
    page = authenticated_client.get("/audit/", base_url="https://localhost").data
    assert b"UDP port 5514 is already used by another program on this PC." in page
    assert b'class="device-advice small"' in page and b"Choose another port for this device" in page
