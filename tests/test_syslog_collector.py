import json
import pytest
import segcheck.syslog_collector as collector

from segcheck.syslog_collector import (
    TokenBucketRateLimiter,
    parse_filterlog,
    store_event,
)


SAMPLE_MESSAGE = (
    "<134>Nov  5 21:54:16 filterlog[36186]: "
    "1,95,,1791895687,em2,match,block,in,4,0x0,,64,"
    "19641,0,DF,6,tcp,60,10.20.0.100,10.30.0.10,"
    "44638,8080,0,S,4244710613,,64240,,mss;sackOK;TS;nop;wscale"
)


def test_parse_real_pfsense_block_event():
    event = parse_filterlog(SAMPLE_MESSAGE)

    assert event["parse_status"] == "parsed"
    assert event["event_type"] == "pf_filterlog"
    assert event["rule_tracker"] == "1791895687"
    assert event["interface"] == "em2"
    assert event["action"] == "block"
    assert event["direction"] == "in"
    assert event["protocol"] == "tcp"
    assert event["source_ip"] == "10.20.0.100"
    assert event["destination_ip"] == "10.30.0.10"
    assert event["source_port"] == 44638
    assert event["destination_port"] == 8080


def test_unrecognized_message_is_not_treated_as_firewall_event():
    event = parse_filterlog("This is not a pfSense filterlog message")

    assert event["event_type"] == "unknown"
    assert event["parse_status"] == "unrecognized_format"


def test_short_filterlog_message_is_not_parsed_as_complete():
    event = parse_filterlog("<134>Nov 5 21:54:16 filterlog: 1,2,3")

    assert event["event_type"] == "pf_filterlog"
    assert event["parse_status"] == "insufficient_fields"


def test_invalid_ip_fields_are_rejected():
    message = SAMPLE_MESSAGE.replace(
        "10.20.0.100", "not-an-ip"
    )
    event = parse_filterlog(message)

    assert event["parse_status"] == "invalid_fields"


def test_event_is_persisted_as_jsonl(tmp_path):
    output = tmp_path / "evidence" / "events.jsonl"

    record = {
        "event_id": "test-event-001",
        "sender_ip": "10.20.0.1",
        "raw_message": SAMPLE_MESSAGE,
        "parsed": parse_filterlog(SAMPLE_MESSAGE),
    }

    store_event(output, record)

    saved_records = output.read_text(encoding="utf-8").splitlines()

    assert len(saved_records) == 1
    saved = json.loads(saved_records[0])
    assert saved["event_id"] == "test-event-001"
    assert saved["raw_message"] == SAMPLE_MESSAGE
    assert saved["parsed"]["action"] == "block"
    assert saved["parsed"]["destination_port"] == 8080


def test_store_event_rejects_evidence_file_capacity(tmp_path):
    from segcheck.syslog_collector import EvidenceStorageError, store_event

    evidence = tmp_path / "events.jsonl"
    store_event(evidence, {"event_id": "first"}, max_bytes=100)

    with pytest.raises(EvidenceStorageError, match="capacity reached"):
        store_event(evidence, {"event_id": "second"}, max_bytes=35)

    assert evidence.read_bytes() == b'{"event_id":"first"}\n'


def test_store_event_rejects_incomplete_trailing_record(tmp_path):
    from segcheck.syslog_collector import EvidenceStorageError, store_event

    evidence = tmp_path / "events.jsonl"
    evidence.write_bytes(b'{"event_id":"incomplete"}')

    with pytest.raises(EvidenceStorageError, match="incomplete trailing"):
        store_event(evidence, {"event_id": "next"})

    assert evidence.read_bytes() == b'{"event_id":"incomplete"}'


def test_store_event_rejects_symlink_destination(tmp_path):
    from segcheck.syslog_collector import EvidenceStorageError, store_event

    target = tmp_path / "target.jsonl"
    target.write_bytes(b"")
    link = tmp_path / "linked.jsonl"

    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not available in this environment.")

    with pytest.raises(EvidenceStorageError):
        store_event(link, {"event_id": "blocked"})

    assert target.read_bytes() == b""


def test_store_event_rejects_non_regular_destination(tmp_path):
    from segcheck.syslog_collector import EvidenceStorageError, store_event

    directory = tmp_path / "events.jsonl"
    directory.mkdir()

    with pytest.raises(EvidenceStorageError):
        store_event(directory, {"event_id": "blocked"})


def test_store_event_rejects_hard_linked_evidence_on_posix(tmp_path):
    import os
    from segcheck.syslog_collector import EvidenceStorageError, store_event

    if os.name != "posix":
        pytest.skip("Hard-link protection check is POSIX-specific.")

    evidence = tmp_path / "events.jsonl"
    alias = tmp_path / "alias.jsonl"
    evidence.write_bytes(b"")
    os.chmod(evidence, 0o640)
    original_mode = evidence.stat().st_mode & 0o777
    os.link(evidence, alias)

    with pytest.raises(EvidenceStorageError, match="hard links"):
        store_event(evidence, {"event_id": "blocked"})

    assert evidence.read_bytes() == b""
    assert alias.read_bytes() == b""
    assert evidence.stat().st_mode & 0o777 == original_mode


class FakeClock:
    def __init__(self, initial=100.0):
        self.current = initial

    def __call__(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds


def test_rate_limiter_allows_initial_burst_then_rejects_excess():
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        rate_per_second=100,
        burst_capacity=3,
        clock=clock,
    )

    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False


def test_rate_limiter_refills_tokens_over_time():
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        rate_per_second=2,
        burst_capacity=1,
        clock=clock,
    )

    assert limiter.allow() is True
    assert limiter.allow() is False

    clock.advance(0.5)

    assert limiter.allow() is True
    assert limiter.allow() is False


def test_rate_limiter_never_exceeds_burst_capacity_after_idle_period():
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        rate_per_second=2,
        burst_capacity=3,
        clock=clock,
    )

    clock.advance(100)

    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False


def test_rate_limiter_does_not_create_tokens_when_clock_moves_backwards():
    clock = FakeClock()
    limiter = TokenBucketRateLimiter(
        rate_per_second=2,
        burst_capacity=1,
        clock=clock,
    )

    assert limiter.allow() is True
    clock.advance(-10)

    assert limiter.allow() is False

    clock.advance(10.5)

    assert limiter.allow() is True


@pytest.mark.parametrize(
    "rate, burst",
    [
        (0, 1),
        (-1, 1),
        (float("inf"), 1),
        (float("nan"), 1),
        (True, 1),
        (1, 0),
        (1, -1),
        (1, True),
        (1, 1.5),
    ],
)
def test_rate_limiter_rejects_invalid_configuration(rate, burst):
    with pytest.raises(ValueError):
        TokenBucketRateLimiter(
            rate_per_second=rate,
            burst_capacity=burst,
            clock=FakeClock(),
        )


def test_rate_limiter_rejects_non_finite_clock_value():
    with pytest.raises(ValueError, match="finite timestamp"):
        TokenBucketRateLimiter(
            clock=lambda: float("inf"),
        )


class FakeCollectorSocket:
    def __init__(self, datagrams):
        self.datagrams = list(datagrams)
        self.timeout = None
        self.bound_address = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def bind(self, address):
        self.bound_address = address

    def recvfrom(self, size):
        if self.datagrams:
            data, address = self.datagrams.pop(0)
            assert len(data) <= size
            return data, address
        raise KeyboardInterrupt

    def close(self):
        self.closed = True


def test_run_collector_rate_limits_and_aggregates_rejections(monkeypatch, capsys):
    clock = FakeClock()
    valid_message = SAMPLE_MESSAGE.encode("utf-8")

    fake_socket = FakeCollectorSocket([
        (valid_message, ("127.0.0.2", 514)),
        (b"x" * (collector.MAX_MESSAGE_SIZE + 1), ("127.0.0.1", 514)),
        (valid_message, ("127.0.0.1", 514)),
        (valid_message, ("127.0.0.1", 514)),
    ])
    persisted = []

    monkeypatch.setattr(
        collector.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )
    monkeypatch.setattr(
        collector,
        "store_event",
        lambda path, record: persisted.append((path, record)),
    )

    result = collector.run_collector(
        "127.0.0.1",
        5514,
        ["127.0.0.1"],
        "test-evidence.jsonl",
        rate_per_second=1,
        burst_capacity=1,
        clock=clock,
    )

    assert result == {
        "accepted_messages": 1,
        "unexpected_sender_messages": 1,
        "oversized_messages": 1,
        "rate_limited_messages": 1,
        "stop_reason": "rate_limit_exceeded",
    }
    assert len(persisted) == 1
    assert persisted[0][0] == "test-evidence.jsonl"
    assert fake_socket.timeout == 1.0
    assert fake_socket.bound_address == ("127.0.0.1", 5514)
    assert fake_socket.closed is True

    output = capsys.readouterr().out
    assert "Message rate limit exceeded" in output
    assert "Unexpected sender messages: 1" in output
    assert "Oversized messages: 1" in output
    assert "Rate-limited messages: 1" in output


def test_run_collector_keyboard_interrupt_closes_socket(monkeypatch):
    fake_socket = FakeCollectorSocket([])

    monkeypatch.setattr(
        collector.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    result = collector.run_collector(
        "127.0.0.1",
        5514,
        ["127.0.0.1"],
        "test-evidence.jsonl",
    )

    assert result["accepted_messages"] == 0
    assert result["stop_reason"] == "keyboard_interrupt"
    assert fake_socket.closed is True


def test_run_collector_rejects_invalid_port_before_opening_socket(monkeypatch):
    socket_created = []

    monkeypatch.setattr(
        collector.socket,
        "socket",
        lambda *args, **kwargs: socket_created.append(True),
    )

    with pytest.raises(ValueError, match="port"):
        collector.run_collector(
            "127.0.0.1",
            70000,
            ["127.0.0.1"],
            "test-evidence.jsonl",
        )

    assert socket_created == []



def test_run_collector_stops_gracefully_on_sigterm(monkeypatch):
    registered = {}
    registrations = []
    previous_handler = object()

    def fake_getsignal(signum):
        assert signum == collector.signal.SIGTERM
        return previous_handler

    def fake_signal(signum, handler):
        assert signum == collector.signal.SIGTERM
        registrations.append(handler)
        if handler is not previous_handler:
            registered["handler"] = handler
        return previous_handler

    class SigtermSocket(FakeCollectorSocket):
        def recvfrom(self, size):
            registered["handler"](collector.signal.SIGTERM, None)
            raise collector.socket.timeout()

    fake_socket = SigtermSocket([])

    monkeypatch.setattr(collector.signal, "getsignal", fake_getsignal)
    monkeypatch.setattr(collector.signal, "signal", fake_signal)
    monkeypatch.setattr(
        collector.socket,
        "socket",
        lambda *args, **kwargs: fake_socket,
    )

    result = collector._run_with_sigterm_handler(
        "127.0.0.1",
        5514,
        ["127.0.0.1"],
        "test-evidence.jsonl",
    )

    assert result["stop_reason"] == "signal_requested"
    assert result["accepted_messages"] == 0
    assert fake_socket.timeout == 1.0
    assert fake_socket.closed is True
    assert len(registrations) == 2
    assert registrations[0] is registered["handler"]
    assert registrations[1] is previous_handler
