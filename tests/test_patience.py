"""Waiting for answers: answers are final, silence is tried again (unless the firewall logged the block), and the
waits follow how fast this network really answers."""
from segcheck.probe import ProbeOutcome
from segcheck_web.services.patience import Patience, is_answer, is_silence
from segcheck_web.services.report_view import explain

SILENT = ProbeOutcome("inconclusive", "connection_timeout; not proof of firewall filtering", 1000.0, "10.40.0.100")
OPEN = ProbeOutcome("reachable", "tcp_connect_succeeded", 12.0, "10.40.0.100")
REFUSED = ProbeOutcome("inconclusive", "connection_refused_service_may_be_closed; not proof of segmentation", 3.0, "10.40.0.100")


def scripted(*outcomes):
    calls = []

    def try_once(wait):
        calls.append(wait)
        return outcomes[len(calls) - 1]
    return try_once, calls


def test_an_answer_is_final_and_never_retried():
    for outcome in (OPEN, REFUSED):
        try_once, calls = scripted(outcome)
        assert Patience().attempt(try_once, "10.30.0.20", 5432, "tcp") is outcome and calls == [1.0]


def test_silence_is_tried_again_with_a_longer_wait():
    try_once, calls = scripted(SILENT, SILENT)
    patience = Patience()
    final = patience.attempt(try_once, "10.30.0.20", 22, "tcp")
    assert calls == [1.0, 3.0] and final.state == "inconclusive" and patience.second_tries == 1
    assert "no reply in 2 tries (1 s, then 3 s)" in final.reason and final.reason.startswith("connection_timeout;")
    assert "Tried twice" in explain(final.reason)["text"]


def test_a_lost_packet_or_slow_service_is_caught_on_the_second_try():
    slow = ProbeOutcome("reachable", "tcp_connect_succeeded", 1800.0, "10.40.0.100")
    try_once, calls = scripted(SILENT, slow)
    patience = Patience()
    final = patience.attempt(try_once, "10.30.0.20", 5432, "tcp")
    assert final.state == "reachable" and patience.answered_on_second_try == 1, "an open door is not missed"
    assert final.started_at and final.completed_at and final.duration_ms >= 0
    label = explain(final.reason)
    assert label["label"] == "Connected (2nd try)" and "path is open" in label["text"]


def test_a_block_already_in_the_firewall_log_needs_no_second_try():
    try_once, calls = scripted(SILENT)
    seen = []
    patience = Patience(lambda host, port, protocol, since: seen.append((host, port, protocol)) or True)
    final = patience.attempt(try_once, "10.30.0.20", 22, "tcp")
    assert final.state == "inconclusive" and calls == [1.0] and seen == [("10.30.0.20", 22, "tcp")]
    assert "blocked by the firewall (its log shows it)" in final.reason and final.reason.startswith("connection_timeout;")
    assert explain(final.reason)["label"] == "Blocked (logged)" and "blocked, and proven" in explain(final.reason)["text"]


def test_waits_follow_the_slowest_real_answer_within_bounds():
    patience = Patience()
    assert (patience.first_wait(), patience.second_wait()) == (1.0, 3.0)
    patience._learn(ProbeOutcome("reachable", "tcp_connect_succeeded", 500.0))  # a slow network: 0.5 s answers
    assert (patience.first_wait(), patience.second_wait()) == (2.0, 4.0)
    patience._learn(ProbeOutcome("reachable", "tcp_connect_succeeded", 5000.0))
    assert (patience.first_wait(), patience.second_wait()) == (3.0, 6.0), "never longer than the fixed maximum"
    patience._learn(SILENT)
    assert patience.slowest == 5.0, "silence is not an answer: it does not stretch the waits"


def test_what_counts_as_silence_and_as_an_answer():
    udp_silent = ProbeOutcome("inconclusive", "udp_snmpv3_discovery_no_reply; silence is not proof of filtering", 1000.0)
    udp_closed = ProbeOutcome("inconclusive", "udp_dns_query_port_unreachable_reported; not proof", 2.0)
    ping_silent = ProbeOutcome("inconclusive", "icmp_no_echo_reply; not proof of segmentation", 1000.0)
    no_route = ProbeOutcome("inconclusive", "socket_error_network_unreachable; not proof of segmentation", 0.5)
    assert is_silence(udp_silent) and is_silence(ping_silent) and is_silence(SILENT)
    assert not is_silence(udp_closed) and not is_silence(no_route) and not is_silence(REFUSED)
    assert is_answer(udp_closed) and is_answer(REFUSED) and is_answer(OPEN) and not is_answer(no_route)


def test_a_late_firewall_log_is_waited_for_briefly_instead_of_retrying(monkeypatch):
    """Firewalls send logs with a delay: the block arrives just after the first wait. Wait for it; do not retry."""
    monkeypatch.setattr("segcheck_web.services.patience.LOG_POLL", 0.01)
    arrivals = iter([False, False, True])
    try_once, calls = scripted(SILENT)
    patience = Patience(lambda host, port, protocol, since: next(arrivals))
    final = patience.attempt(try_once, "10.30.0.20", 22, "tcp")
    assert "its log shows it" in final.reason and calls == [1.0] and patience.second_tries == 0


def test_no_log_within_the_grace_means_a_second_try(monkeypatch):
    monkeypatch.setattr("segcheck_web.services.patience.LOG_GRACE", 0.05)
    monkeypatch.setattr("segcheck_web.services.patience.LOG_POLL", 0.01)
    try_once, calls = scripted(SILENT, SILENT)
    patience = Patience(lambda host, port, protocol, since: False)
    patience.attempt(try_once, "10.30.0.20", 22, "tcp")
    assert calls == [1.0, 3.0] and patience.second_tries == 1


# ------------------------------------------------------------------ the run watcher (early stop)
import pytest  # noqa: E402
from segcheck_web.services.patience import RunStopped, RunWatch  # noqa: E402


def _local(code):
    return ProbeOutcome("inconclusive", f"{code}; not proof of segmentation", 0.5)


@pytest.mark.parametrize("code,words", [
    ("socket_error_source_address_unavailable", "Step 1 address is no longer available"),
    ("socket_error_access_denied_by_local_policy", "Security software on this PC"),
])
def test_attempts_that_never_leave_this_pc_stop_the_run_after_three(code, words):
    watch = RunWatch()
    watch.check(_local(code))
    watch.check(_local(code))
    with pytest.raises(RunStopped) as stopped:
        watch.check(_local(code))
    assert words in str(stopped.value) and "What to do:" in str(stopped.value) and len(str(stopped.value)) <= 500


def test_one_bad_attempt_between_good_ones_does_not_stop_the_run():
    watch = RunWatch()
    for outcome in (_local("socket_error_network_unreachable"), OPEN, _local("socket_error_network_unreachable"), SILENT):
        watch.check(outcome)


def test_logs_set_up_but_none_arriving_stops_after_eight_silent_attempts_when_nothing_answered():
    watch = RunWatch(lambda since: False, " on UDP port 5514 of 10.40.0.100")
    for _ in range(7):
        watch.check(SILENT)
    with pytest.raises(RunStopped) as stopped:
        watch.check(SILENT)
    assert "UDP port 5514" in str(stopped.value) and "Step 3b" in str(stopped.value) and len(str(stopped.value)) <= 500


def test_no_early_stop_when_logs_arrive_or_something_already_answered_or_no_logs_were_set_up():
    for watch in (RunWatch(lambda since: True), RunWatch(None)):
        for _ in range(20):
            watch.check(SILENT)
    found = RunWatch(lambda since: False)
    found.check(OPEN)  # a real open door: the run is producing proof, so it finishes
    for _ in range(20):
        found.check(SILENT)


def test_no_route_never_stops_the_run():
    """A network that is not routed from this PC is a real result; other targets may still be reachable."""
    watch = RunWatch()
    for _ in range(30):
        watch.check(_local("socket_error_network_unreachable"))


def test_report_explains_no_route_as_a_note_not_a_broken_setup():
    from segcheck_web.services.report_view import run_problems
    details = [{"destination_host": "10.30.0.20", "reason": "socket_error_network_unreachable; not proof"}] * 3
    problems = run_problems({"devices": []}, details, {}, {"unproven": 0})
    assert [p["tone"] for p in problems] == ["info"] and "No route from this PC" in problems[0]["title"]
    assert "10.30.0.20" in problems[0]["text"]
