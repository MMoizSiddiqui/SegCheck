"""SegCheck runs on a PC inside the department being tested; it finds that department itself."""
from test_environment_workflow import app, configure, form  # noqa: F401

from segcheck_web.extensions import db
from segcheck_web.services import environment
from segcheck_web.services.environment import EnvironmentError, save_zone, settings, use_this_machine, zone_for


def test_zone_is_found_from_this_pcs_address(app):
    with app.app_context():
        configure()
        assert zone_for(["192.168.1.5", "10.20.0.57"]) == ("guest", "10.20.0.57")
        assert zone_for(["192.168.1.5"]) == (None, None)


def test_most_specific_subnet_wins(app):
    with app.app_context():
        configure()
        save_zone(form(zone_key="kiosk", name="Kiosk", cidr="10.40.0.0/24", revision=settings()[0].revision))
        assert zone_for(["10.40.0.9"]) == ("kiosk", "10.40.0.9")


def test_use_this_pc_sets_the_probe_to_this_pc(app, monkeypatch):
    with app.app_context():
        configure()
        monkeypatch.setattr(environment, "local_addresses", lambda: ["10.30.0.77"])
        position = use_this_machine(form(revision=settings()[0].revision))
        assert position["zone"] == "cde" and position["address"] == "10.30.0.77"
        _, payload = settings()
        assert payload["source_zone"] == "cde" and payload["source_ip"] == "10.30.0.77"
        assert payload["organization"] == "Example Bank"  # kept


def test_use_this_pc_explains_when_no_zone_matches(app, monkeypatch):
    with app.app_context():
        configure()
        monkeypatch.setattr(environment, "local_addresses", lambda: ["172.16.5.5"])
        try:
            use_this_machine(form(revision=settings()[0].revision))
            raise AssertionError("expected an explanation")
        except EnvironmentError as exc:
            assert "172.16.5.5" in str(exc) and "Add this department's subnet" in str(exc)
        db.session.rollback()
