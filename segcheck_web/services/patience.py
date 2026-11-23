"""How long to wait for an answer, and when to try a silent attempt again.

An answer (connected, refused, port closed) is final: it came back, so there is nothing to wait for. Silence is not:
a packet can be lost, or a busy, distant or VPN network can be slower than the first wait. So a silent attempt is
tried once more with a longer wait, unless the firewall's own log already shows it blocked that exact attempt (then
the silence is explained and proven, and a second try would only add time).

The waits follow the network actually being tested: SegCheck notes how long real answers take during the run and
waits several times longer than the slowest one (as TCP itself and tools such as nmap do), within fixed bounds.
"""
from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from segcheck.probe import ProbeOutcome

FIRST_WAIT_MIN, FIRST_WAIT_MAX = 1.0, 3.0    # seconds: the first try
SECOND_WAIT_MIN, SECOND_WAIT_MAX = 3.0, 6.0  # seconds: the second try of a silent attempt
FIRST_FACTOR, SECOND_FACTOR = 4, 8           # times the slowest answer seen so far
LOG_GRACE = 2.0  # seconds: firewalls send their log lines with a delay (often batched about once a second)
LOG_POLL = 0.1


def is_silence(outcome: ProbeOutcome) -> bool:
    code = outcome.reason.split(";")[0].strip()
    return outcome.state == "inconclusive" and (code == "connection_timeout" or code.endswith("no_reply")
                                                or code == "icmp_no_echo_reply")


def is_answer(outcome: ProbeOutcome) -> bool:
    code = outcome.reason.split(";")[0].strip()
    return outcome.state == "reachable" or code.startswith("connection_refused") or "port_unreachable" in code


def _stamp(moment: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=time.perf_counter() - moment)).isoformat(timespec="milliseconds")


class Patience:
    """Per-run waits that adapt to how fast this network really answers."""

    def __init__(self, logged_block=None):
        self.slowest = 0.0          # seconds: the slowest real answer seen in this run
        self.logged_block = logged_block  # (host, port, protocol, since) -> bool, or None without logs
        self.second_tries = 0
        self.answered_on_second_try = 0

    def first_wait(self) -> float:
        return round(min(FIRST_WAIT_MAX, max(FIRST_WAIT_MIN, FIRST_FACTOR * self.slowest)), 2)

    def second_wait(self) -> float:
        return round(min(SECOND_WAIT_MAX, max(SECOND_WAIT_MIN, SECOND_FACTOR * self.slowest)), 2)

    def _learn(self, outcome: ProbeOutcome):
        if is_answer(outcome):
            self.slowest = max(self.slowest, outcome.duration_ms / 1000)

    def _wait_for_log(self, host, port, protocol, since) -> bool:
        """Give the firewall's log line a moment to arrive; stop as soon as it is there."""
        deadline = time.perf_counter() + LOG_GRACE
        while True:
            if self.logged_block(host, port, protocol, since):
                return True
            if time.perf_counter() >= deadline:
                return False
            time.sleep(LOG_POLL)

    def attempt(self, try_once, host, port, protocol) -> ProbeOutcome:
        """try_once(wait_seconds) -> ProbeOutcome. Returns the final outcome of up to two tries."""
        started, since = time.perf_counter(), datetime.now(timezone.utc)
        first_wait = self.first_wait()
        first = try_once(first_wait)
        self._learn(first)
        if not is_silence(first):
            return first
        if self.logged_block is not None and self._wait_for_log(host, port, protocol, since):
            # The firewall logged blocking this very attempt: the silence is explained (and shown live as a proven block).
            code, _, rest = first.reason.partition(";")
            return replace(first, reason=f"{code.strip()}; blocked by the firewall (its log shows it);{rest}"[:512])
        second_wait = self.second_wait()
        self.second_tries += 1
        second = try_once(second_wait)
        self._learn(second)
        total_ms = round((time.perf_counter() - started) * 1000, 2)
        code, _, rest = second.reason.partition(";")
        if is_silence(second):
            note = f"no reply in 2 tries ({first_wait:g} s, then {second_wait:g} s)"
        else:
            self.answered_on_second_try += 1
            note = f"answered on the 2nd try after {second.duration_ms / 1000:.2f} s (slow network or a lost packet)"
        reason = f"{code.strip()}; {note};{rest}"[:512]
        return ProbeOutcome(second.state, reason, min(total_ms, 60000.0), second.source_ip or first.source_ip,
                            started_at=_stamp(started), completed_at=_stamp(time.perf_counter()))


# ------------------------------------------------------------------------------------------------ run watcher
# The attempt never reached the network, and every further attempt would fail the same way. ("No route" is NOT here:
# a network that is not routed from this PC is a real result, and other targets may still be reachable.)
LOCAL_FAILURES = {
    "socket_error_source_address_unavailable": (
        "This PC's Step 1 address is no longer available (the PC changed network, Wi-Fi reconnected, or the cable was "
        "pulled), so nothing could be sent.",
        "Open New audit, Step 1, pick the network this PC is in now, then run the audit again."),
    "socket_error_access_denied_by_local_policy": (
        "Security software on this PC refused to send the attempts (a local firewall or antivirus rule).",
        "Allow Python / SegCheck in this PC's firewall or antivirus, then run the audit again."),
}
STOP_AFTER_LOCAL_FAILURES = 3   # in a row
STOP_AFTER_SILENT_WITHOUT_LOGS = 8


class RunStopped(Exception):
    """The run cannot give a useful result; carries what happened and what to do."""


class RunWatch:
    """Stops a run early when its setup makes the rest pointless, and says why and how to fix it."""

    def __init__(self, any_log_since=None, firewall_hint=""):
        self.any_log_since = any_log_since  # (datetime) -> bool, or None when no log feed was set up
        self.firewall_hint = firewall_hint
        self.started = datetime.now(timezone.utc)
        self.local_streak, self.local_code, self.silent, self.attempts, self.answered = 0, "", 0, 0, 0

    def check(self, outcome: ProbeOutcome):
        self.attempts += 1
        code = outcome.reason.split(";")[0].strip()
        if code in LOCAL_FAILURES:
            self.local_streak = self.local_streak + 1 if code == self.local_code or not self.local_code else 1
            self.local_code = code
            if self.local_streak >= STOP_AFTER_LOCAL_FAILURES:
                what, fix = LOCAL_FAILURES[code]
                raise RunStopped(f"Stopped early after {self.attempts} attempts: {what} What to do: {fix} "
                                 "No report was saved, because these attempts never reached the network.")
        else:
            self.local_streak, self.local_code = 0, ""
        if is_answer(outcome):
            self.answered += 1  # the run already measures real things (an open door is proof even without logs)
        if is_silence(outcome):
            self.silent += 1
            if (self.any_log_since is not None and self.silent >= STOP_AFTER_SILENT_WITHOUT_LOGS and not self.answered
                    and not self.any_log_since(self.started)):
                raise RunStopped(
                    f"Stopped early after {self.attempts} attempts: Step 3 says the firewall sends its logs to this PC"
                    f"{self.firewall_hint}, but no log line has arrived, so nothing could be proven. What to do: do Step 3b on "
                    "the firewall and wait for 'Logs arriving' in Step 3, then run the audit again; or untick 'Connect its "
                    "logs' in Step 3a to audit without proof. No report was saved.")
