"""Scoped UDP Syslog collector for SegCheck's pfSense lab integration."""

import argparse
import csv
import ipaddress
import json
import math
import time
import os
import re
import socket
import signal
import threading
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .storage import default_evidence_path


MAX_MESSAGE_SIZE = 8192
MAX_EVIDENCE_FILE_BYTES = 60 * 1024 * 1024

FILTERLOG_PATTERN = re.compile(
    r"<(?P<priority>\d{1,3})>.*?filterlog(?:\[\d+\])?:\s*(?P<payload>.*)$"
)


def parse_filterlog(message):
    """Parse common pfSense IPv4/IPv6 filterlog CSV fields."""

    match = FILTERLOG_PATTERN.match(message)
    if not match:
        return {
            "event_type": "unknown",
            "parse_status": "unrecognized_format",
        }

    try:
        fields = next(csv.reader([match.group("payload")]))
    except (csv.Error, StopIteration):
        return {
            "event_type": "pf_filterlog",
            "parse_status": "malformed_csv",
        }

    event = {
        "event_type": "pf_filterlog",
        "parse_status": "parsed",
        "syslog_priority": int(match.group("priority")),
        "filterlog_fields": fields,
    }

    # Common pfSense filterlog field positions.
    if len(fields) < 22:
        event["parse_status"] = "insufficient_fields"
        return event

    try:
        source_ip = str(ipaddress.ip_address(fields[18]))
        destination_ip = str(ipaddress.ip_address(fields[19]))

        event.update({
            "rule_number": fields[0],
            "subrule_number": fields[1],
            "rule_tracker": fields[3],
            "interface": fields[4],
            "reason": fields[5],
            "action": fields[6].lower(),
            "direction": fields[7].lower(),
            "ip_version": fields[8],
            "protocol_id": fields[15],
            "protocol": fields[16].lower(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        })

        if event["protocol"] in ("tcp", "udp"):
            event["source_port"] = int(fields[20])
            event["destination_port"] = int(fields[21])

        if event["action"] not in ("pass", "block"):
            event["parse_status"] = "unexpected_action"

    except (ValueError, IndexError):
        event["parse_status"] = "invalid_fields"

    return event


class TokenBucketRateLimiter:
    """Bound accepted messages using a monotonic-clock token bucket."""

    def __init__(self, rate_per_second=100.0, burst_capacity=200, clock=None):
        if (
            isinstance(rate_per_second, bool)
            or not isinstance(rate_per_second, (int, float))
            or not math.isfinite(rate_per_second)
            or rate_per_second <= 0
        ):
            raise ValueError("rate_per_second must be a finite positive number.")

        if (
            isinstance(burst_capacity, bool)
            or not isinstance(burst_capacity, int)
            or burst_capacity <= 0
        ):
            raise ValueError("burst_capacity must be a positive integer.")

        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable.")

        self.rate_per_second = float(rate_per_second)
        self.burst_capacity = burst_capacity
        self._clock = clock or time.monotonic
        self._tokens = float(burst_capacity)
        self._last_refill = float(self._clock())

        if not math.isfinite(self._last_refill):
            raise ValueError("clock must return a finite timestamp.")

    def allow(self):
        """Consume one token, returning False when the rate limit is reached."""

        now = float(self._clock())

        if not math.isfinite(now):
            raise RuntimeError("Rate-limiter clock returned a non-finite value.")

        # A backwards clock adjustment must never create extra tokens.
        elapsed = max(0.0, now - self._last_refill)
        self._tokens = min(
            float(self.burst_capacity),
            self._tokens + elapsed * self.rate_per_second,
        )
        self._last_refill = max(self._last_refill, now)

        if self._tokens < 1.0:
            return False

        self._tokens -= 1.0
        return True


class EvidenceStorageError(RuntimeError):
    """Raised when evidence cannot be persisted safely."""


def _acquire_evidence_lock(lock_path):
    """Acquire a process-level lock for one evidence file."""

    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = None
    try:
        fd = os.open(lock_path, flags, 0o600)

        lock_stat = os.fstat(fd)
        if not stat.S_ISREG(lock_stat.st_mode):
            raise EvidenceStorageError("Evidence lock is not a regular file.")

        if os.name == "posix" and lock_stat.st_nlink != 1:
            raise EvidenceStorageError(
                "Evidence lock has multiple hard links."
            )

        if os.name == "posix":
            os.fchmod(fd, 0o600)

        if os.name == "nt":
            import msvcrt

            if lock_stat.st_size == 0:
                os.write(fd, b"\0")
                os.fsync(fd)

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)

        return fd

    except Exception as exc:
        if fd is not None:
            os.close(fd)

        if isinstance(exc, EvidenceStorageError):
            raise

        raise EvidenceStorageError(
            f"Could not acquire evidence-file lock: {exc}"
        ) from exc


def _release_evidence_lock(fd):
    """Release a previously acquired evidence-file lock."""

    try:
        if os.name == "nt":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def store_event(
    output_path,
    record,
    max_bytes=MAX_EVIDENCE_FILE_BYTES,
):
    """Safely append one bounded JSONL evidence record."""

    if (
        isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes <= 0
        or max_bytes > MAX_EVIDENCE_FILE_BYTES
    ):
        raise EvidenceStorageError(
            f"max_bytes must be between 1 and {MAX_EVIDENCE_FILE_BYTES}."
        )

    path = Path(output_path)

    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        encoded = (
            json.dumps(
                record,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8") + b"\n"
        )
    except (OSError, TypeError, ValueError) as exc:
        raise EvidenceStorageError(
            f"Could not prepare evidence record: {exc}"
        ) from exc

    if len(encoded) > max_bytes:
        raise EvidenceStorageError(
            "Evidence record exceeds the configured evidence-file limit."
        )

    lock_path = path.with_name(path.name + ".lock")
    lock_fd = _acquire_evidence_lock(lock_path)
    evidence_fd = None

    try:
        # O_BINARY keeps JSONL records byte-exact (LF) on Windows.
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)

        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK

        try:
            evidence_fd = os.open(path, flags, 0o600)

            file_stat = os.fstat(evidence_fd)

            if not stat.S_ISREG(file_stat.st_mode):
                raise EvidenceStorageError(
                    "Evidence destination is not a regular file."
                )

            if os.name == "posix" and file_stat.st_nlink != 1:
                raise EvidenceStorageError(
                    "Evidence destination has multiple hard links."
                )

            if os.name == "posix":
                os.fchmod(evidence_fd, 0o600)

            original_size = file_stat.st_size

            if original_size > max_bytes:
                raise EvidenceStorageError(
                    "Existing evidence file already exceeds its configured limit."
                )

            if original_size:
                os.lseek(evidence_fd, -1, os.SEEK_END)
                final_byte = os.read(evidence_fd, 1)

                if final_byte != b"\n":
                    raise EvidenceStorageError(
                        "Existing evidence file has an incomplete trailing "
                        "JSONL record; refusing to append."
                    )

            if original_size + len(encoded) > max_bytes:
                raise EvidenceStorageError(
                    "Evidence-file capacity reached; refusing to discard "
                    "or overwrite evidence."
                )

            written = 0

            try:
                while written < len(encoded):
                    count = os.write(evidence_fd, encoded[written:])

                    if count <= 0:
                        raise OSError(
                            "Evidence write made no forward progress."
                        )

                    written += count

                os.fsync(evidence_fd)

            except OSError as write_error:
                try:
                    os.ftruncate(evidence_fd, original_size)
                    os.fsync(evidence_fd)
                except OSError as rollback_error:
                    raise EvidenceStorageError(
                        "Evidence write failed and rollback also failed; "
                        "the evidence file may contain an incomplete record. "
                        f"Write error: {write_error}; "
                        f"rollback error: {rollback_error}"
                    ) from rollback_error

                raise EvidenceStorageError(
                    "Evidence write failed; partial append was rolled back: "
                    f"{write_error}"
                ) from write_error

        except EvidenceStorageError:
            raise
        except OSError as exc:
            raise EvidenceStorageError(
                f"Could not safely persist evidence: {exc}"
            ) from exc

    finally:
        try:
            if evidence_fd is not None:
                os.close(evidence_fd)
        finally:
            _release_evidence_lock(lock_fd)

def run_collector(
    bind_ip,
    port,
    allowed_senders,
    output_path,
    rate_per_second=100.0,
    burst_capacity=200,
    stop_event=None,
    clock=None,
):
    bind_ip = str(ipaddress.ip_address(bind_ip))

    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535.")

    allowed_senders = {
        str(ipaddress.ip_address(address))
        for address in allowed_senders
    }

    if not allowed_senders:
        raise ValueError("At least one allowed sender is required.")

    if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
        raise ValueError("stop_event must provide an is_set() method.")

    limiter = TokenBucketRateLimiter(
        rate_per_second=rate_per_second,
        burst_capacity=burst_capacity,
        clock=clock,
    )

    counters = {
        "accepted_messages": 0,
        "unexpected_sender_messages": 0,
        "oversized_messages": 0,
        "rate_limited_messages": 0,
        "stop_reason": "stop_requested",
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.settimeout(1.0)
        sock.bind((bind_ip, port))
    except Exception:
        sock.close()
        raise

    print("SegCheck Syslog collector started")
    print("Listening on {}:{}".format(bind_ip, port))
    print("Allowed sender(s): {}".format(", ".join(sorted(allowed_senders))))
    print("Evidence file: {}".format(output_path))
    print(
        "Message limit: {} per second; burst capacity: {}".format(
            rate_per_second,
            burst_capacity,
        )
    )

    try:
        while stop_event is None or not stop_event.is_set():
            try:
                data, address = sock.recvfrom(MAX_MESSAGE_SIZE + 1)
            except socket.timeout:
                continue

            sender_ip = address[0]

            if sender_ip not in allowed_senders:
                counters["unexpected_sender_messages"] += 1
                continue

            if len(data) > MAX_MESSAGE_SIZE:
                counters["oversized_messages"] += 1
                continue

            if not limiter.allow():
                counters["rate_limited_messages"] += 1
                counters["stop_reason"] = "rate_limit_exceeded"
                print(
                    "[ERROR] Message rate limit exceeded. "
                    "Stopping collection to avoid silently losing evidence."
                )
                break

            raw_message = data.decode("utf-8", errors="replace")
            parsed = parse_filterlog(raw_message)

            record = {
                "event_id": str(uuid.uuid4()),
                "received_at": datetime.now(timezone.utc).isoformat(),
                "sender_ip": sender_ip,
                "sender_port": address[1],
                "raw_message": raw_message,
                "parsed": parsed,
            }

            store_event(output_path, record)
            counters["accepted_messages"] += 1

        if stop_event is not None and stop_event.is_set():
            counters["stop_reason"] = "signal_requested"

    except KeyboardInterrupt:
        counters["stop_reason"] = "keyboard_interrupt"
        print("\nStopping SegCheck Syslog collector.")
    finally:
        sock.close()
        print("\nCollector session summary:")
        print("  Persisted messages: {}".format(counters["accepted_messages"]))
        print(
            "  Unexpected sender messages: {}".format(
                counters["unexpected_sender_messages"]
            )
        )
        print("  Oversized messages: {}".format(counters["oversized_messages"]))
        print("  Rate-limited messages: {}".format(counters["rate_limited_messages"]))
        print("  Stop reason: {}".format(counters["stop_reason"]))

    return counters


def _run_with_sigterm_handler(
    bind_ip,
    port,
    allowed_senders,
    output_path,
    rate_per_second=100.0,
    burst_capacity=200,
):
    """Run collection with a graceful SIGTERM-to-stop-event bridge."""

    stop_event = threading.Event()
    previous_handler = signal.getsignal(signal.SIGTERM)

    def handle_sigterm(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_sigterm)

    try:
        return run_collector(
            bind_ip,
            port,
            allowed_senders,
            output_path,
            rate_per_second=rate_per_second,
            burst_capacity=burst_capacity,
            stop_event=stop_event,
        )
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


def main():
    parser = argparse.ArgumentParser(
        description="Collect scoped pfSense Syslog evidence for SegCheck."
    )
    parser.add_argument("--bind", default="10.20.0.100")
    parser.add_argument("--port", type=int, default=5514)
    parser.add_argument("--allowed-sender", action="append", default=[])
    parser.add_argument(
        "--output",
        help="evidence JSONL path (default: private SegCheck evidence directory)",
    )
    parser.add_argument(
        "--rate-per-second",
        type=float,
        default=100.0,
        help="maximum sustained accepted-message rate (default: 100)",
    )
    parser.add_argument(
        "--burst-capacity",
        type=int,
        default=200,
        help="maximum initial message burst (default: 200)",
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    try:
        TokenBucketRateLimiter(
            rate_per_second=args.rate_per_second,
            burst_capacity=args.burst_capacity,
        )
        str(ipaddress.ip_address(args.bind))
    except ValueError as exc:
        parser.error(str(exc))

    senders = args.allowed_sender or ["10.20.0.1"]

    output_path = args.output or str(
        default_evidence_path("pfsense-events.jsonl")
    )

    counters = _run_with_sigterm_handler(
        args.bind,
        args.port,
        senders,
        output_path,
        rate_per_second=args.rate_per_second,
        burst_capacity=args.burst_capacity,
    )

    if counters["stop_reason"] == "rate_limit_exceeded":
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
