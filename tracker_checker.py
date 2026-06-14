#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tracker_checker.py

Python translation of adysec/tracker's tracker-checker/src/main.rs.
The goal is to keep the same operational logic:

1. Read trackers from an input file.
2. Extract and normalize http/https/udp/wss tracker announce URLs.
3. Filter trackers by blackstr.txt when it exists.
4. Check trackers concurrently.
5. Treat valid HTTP tracker responses as bencoded tracker responses.
6. Write alive trackers to trackers_best.txt.
7. Split alive trackers by protocol.
8. Maintain tracker_history.tsv.
9. Generate simple GitHub Pages-compatible static reports under docs/.

Dependencies:
    pip install requests

Usage:
    python tracker_checker.py
    python tracker_checker.py trackers.txt trackers_best.txt --workers 20
"""

from __future__ import annotations

import argparse
import html
import ipaddress
import random
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import ParseResult, urlsplit, urlunsplit

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Missing dependency: pip install requests") from exc

DEFAULT_TIMEOUT_SECS = 10
DEFAULT_WORKERS = 20
VERSION = "fixed-2026-06-14-resolve-sockaddr"


class Status(str, Enum):
    """Equivalent to the Rust Status enum."""

    ALIVE = "Alive"
    DEAD = "Dead"
    INVALID = "Invalid"


@dataclass
class CheckResult:
    """Equivalent to Rust CheckResult."""

    url: str
    status: Status
    ping_ms: Optional[int]


@dataclass
class TrackerHistory:
    """Equivalent to Rust TrackerHistory."""

    checks: int = 0
    alive_checks: int = 0
    first_seen_ts: int = 0
    first_alive_ts: int = 0
    last_seen_ts: int = 0
    last_alive_ts: int = 0
    streak_alive_start_ts: int = 0


TRACKER_RE = re.compile(r"(?i)(https?|udp|wss)://[^\s,]*?/announce")


# ---------------------------------------------------------------------------
# URL parsing / normalization
# ---------------------------------------------------------------------------


def parse_tracker_line(line: str) -> str:
    """
    Match Rust parse_tracker_line().

    If the input is a Markdown link like:
        [xxx](udp://tracker.example.com:80/announce)
    return only the URL part. Otherwise return trimmed text.
    """
    trimmed = line.strip()
    if trimmed.startswith("[") and "](" in trimmed and trimmed.endswith(")"):
        _, right = trimmed.split("](", 1)
        return right.rstrip(")")
    return trimmed


def collapse_path_slashes(path: str) -> str:
    """Collapse repeated slash characters in URL path, preserving a single slash."""
    out: List[str] = []
    prev_slash = False

    for ch in path:
        if ch == "/":
            if not prev_slash:
                out.append(ch)
            prev_slash = True
        else:
            out.append(ch)
            prev_slash = False

    return "".join(out) or "/"


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_tracker_url(raw: str) -> Optional[str]:
    """
    Match the Rust normalize_tracker_url() behavior as closely as Python allows.

    Rules:
    - Strip common punctuation wrappers.
    - Accept only http/https/udp/wss.
    - Require a host.
    - Host must be an IP address or contain a dot.
    - Normalize repeated path slashes.
    - Require path ending in /announce.
    - Drop query and fragment.
    - Drop default http:80 and https:443 ports.
    """
    candidate = raw.strip().strip("\"'<>[](){};,")
    candidate = candidate.rstrip(".")

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "udp", "wss"}:
        return None

    host = parsed.hostname
    if not host:
        return None

    if not _host_is_ip(host) and "." not in host:
        return None

    path = collapse_path_slashes(parsed.path)
    if not path.endswith("/announce"):
        return None

    port = parsed.port
    drop_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)

    # Rebuild netloc. Rust url::Url::to_string() normalizes enough for this use case.
    if ":" in host and not host.startswith("["):
        host_part = f"[{host}]"
    else:
        host_part = host

    if port is not None and not drop_default_port:
        netloc = f"{host_part}:{port}"
    else:
        netloc = host_part

    return urlunsplit((scheme, netloc, path, "", ""))


# ---------------------------------------------------------------------------
# Tracker response heuristics
# ---------------------------------------------------------------------------


def bdecode_simple(data: bytes) -> bool:
    """
    Same strict/simple heuristic as Rust bdecode_simple().

    It does not fully parse bencode. It only accepts dictionary-looking tracker
    responses beginning with 'd' and containing one of the expected tracker keys.
    """
    if not data or data[:1] != b"d":
        return False

    return (
            b"interval" in data
            or b"peers" in data
            or b"failure reason" in data
    )


def is_parked_or_expired_domain(content: bytes) -> bool:
    """
    Same parked/expired/fake-domain heuristic as Rust.

    It catches obvious domain parking pages, sale pages, expired pages and generic
    HTML landing pages that should not be treated as valid tracker responses.
    """
    text = content.decode("utf-8", errors="replace").lower()
    indicators = [
        "domain for sale",
        "domain is for sale",
        "buy this domain",
        "domain expired",
        "domain has expired",
        "this domain is expired",
        "register this domain",
        "domain available",
        "parked domain",
        "domain parking",
        "coming soon",
        "under construction",
        "page not found",
        "404 not found",
        "namecheap",
        "godaddy parked",
        "sedo domain parking",
        "domain portfolio",
        "premium domain",
        "afternic",
        "escrow.com",
        "dan.com/buy-domain",
        "undeveloped",
        "this webpage was generated by the domain owner",
        "hugedomains.com",
        "bodis.com",
        "sedoparking",
    ]

    if any(word in text for word in indicators):
        return True

    head = content[:500].decode("utf-8", errors="replace").lower()
    return "<html" in head or "<!doctype html" in head


# ---------------------------------------------------------------------------
# Protocol-specific checking
# ---------------------------------------------------------------------------


def check_http_tracker(url: str, timeout: float) -> Tuple[Status, Optional[int]]:
    """
    HTTP/HTTPS checker.

    Same logic as the Rust check_http_tracker():
    - Send a BitTorrent announce-like GET request.
    - Measure elapsed time in milliseconds.
    - Mark parked/expired domains as Invalid.
    - Mark bencoded tracker responses as Alive.
    - If HTTP 200 returns HTML or a huge body, mark Invalid.
    - If HTTP 200 is non-bencode and non-HTML, mark Dead.
    - 400/403 are only accepted when body still looks like tracker bencode.
    """
    peer_id_random = "".join(str(random.randint(0, 9)) for _ in range(12))
    peer_id = f"-RS0001-{peer_id_random}"

    params = {
        "info_hash": "00000000000000000000",
        "peer_id": peer_id,
        "port": "6881",
        "uploaded": "0",
        "downloaded": "0",
        "left": "0",
        "compact": "1",
        "event": "started",
    }

    try:
        started = time.perf_counter()
        response = requests.get(url, params=params, timeout=timeout)
        ping_ms = int((time.perf_counter() - started) * 1000)
    except requests.RequestException:
        return Status.DEAD, None

    status_code = response.status_code
    body = response.content or b""

    if is_parked_or_expired_domain(body):
        return Status.INVALID, ping_ms

    if bdecode_simple(body):
        return Status.ALIVE, ping_ms

    if status_code == 200:
        head = body[:200].decode("utf-8", errors="replace").lower()
        if "<html" in head or "<body" in head or "<head" in head:
            return Status.INVALID, ping_ms
        if len(body) > 50_000:
            return Status.INVALID, ping_ms
        return Status.DEAD, ping_ms

    if status_code in (400, 403):
        if bdecode_simple(body):
            return Status.ALIVE, ping_ms

    return Status.DEAD, ping_ms


def _resolve_first_addr(host: str, port: int, socket_type: int) -> Optional[Tuple[int, Tuple]]:
    """Resolve host:port and return (address_family, sockaddr)."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket_type)
    except socket.gaierror:
        return None
    if not infos:
        return None
    family, _socktype, _proto, _canonname, sockaddr = infos[0]
    return family, sockaddr


def check_udp_tracker(url: str, timeout: float) -> Tuple[Status, Optional[int]]:
    """
    UDP tracker checker.

    Same logic as Rust check_udp_tracker(): send UDP tracker connect request:
        connection_id: 0x41727101980
        action:        0
        transaction_id: random u32

    Any UDP response is treated as Alive; no response within timeout is Dead.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return Status.INVALID, None

    host = parsed.hostname
    if not host:
        return Status.INVALID, None

    port = parsed.port or 80
    resolved = _resolve_first_addr(host, port, socket.SOCK_DGRAM)
    if resolved is None:
        return Status.INVALID, None

    family, addr = resolved

    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return Status.DEAD, None

    try:
        sock.settimeout(timeout)
        connection_id = 0x41727101980
        action = 0
        transaction_id = random.getrandbits(32)
        req = struct.pack(">QII", connection_id, action, transaction_id)

        started = time.perf_counter()
        try:
            sock.sendto(req, addr)
        except OSError:
            return Status.DEAD, None

        try:
            # Rust accepts both >=8-byte and shorter responses as Alive.
            sock.recvfrom(16)
            ping_ms = int((time.perf_counter() - started) * 1000)
            return Status.ALIVE, ping_ms
        except OSError:
            return Status.DEAD, None
    finally:
        sock.close()


def check_wss_tracker(url: str, timeout: float) -> Tuple[Status, Optional[int]]:
    """
    WSS checker.

    Matches Rust logic: it does not perform a WebSocket TLS handshake.
    It only checks whether TCP connection to host:port succeeds.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return Status.INVALID, None

    host = parsed.hostname
    if not host:
        return Status.INVALID, None

    port = parsed.port or 443
    resolved = _resolve_first_addr(host, port, socket.SOCK_STREAM)
    if resolved is None:
        return Status.INVALID, None

    family, addr = resolved
    started = time.perf_counter()
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(addr)
            ping_ms = int((time.perf_counter() - started) * 1000)
            return Status.ALIVE, ping_ms
        finally:
            sock.close()
    except OSError:
        return Status.DEAD, None


def validate_tracker(tracker: str, timeout: float) -> CheckResult:
    """Dispatch to http/https, udp or wss checker by URL scheme."""
    try:
        parsed = urlsplit(tracker)
    except ValueError:
        return CheckResult(tracker, Status.INVALID, None)

    protocol = parsed.scheme.lower()
    if protocol in {"http", "https"}:
        status, ping_ms = check_http_tracker(tracker, timeout)
    elif protocol == "udp":
        status, ping_ms = check_udp_tracker(tracker, timeout)
    elif protocol == "wss":
        status, ping_ms = check_wss_tracker(tracker, timeout)
    else:
        status, ping_ms = Status.INVALID, None

    return CheckResult(tracker, status, ping_ms)


# ---------------------------------------------------------------------------
# Loading / filtering / writing
# ---------------------------------------------------------------------------


def dedupe_keep_order(items: Iterable[str]) -> List[str]:
    """Deduplicate while preserving input order."""
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def sort_and_dedupe(items: Iterable[str]) -> List[str]:
    """Sort then deduplicate, same as Rust sort_unstable()+dedup()."""
    return sorted(set(items))


def load_trackers(input_file: str) -> List[str]:
    """Read trackers, split commas as newlines, extract /announce URLs, normalize and dedupe."""
    path = Path(input_file)
    if not path.exists():
        raise RuntimeError(f"Error: {input_file} not found or unreadable")

    text = path.read_text(encoding="utf-8", errors="replace")
    normalized_text = text.replace(",", "\n")

    trackers: List[str] = []
    for line in normalized_text.splitlines():
        parsed_line = parse_tracker_line(line)
        if not parsed_line or parsed_line.startswith("#"):
            continue

        for matched in TRACKER_RE.finditer(parsed_line):
            normalized = normalize_tracker_url(matched.group(0))
            if normalized:
                trackers.append(normalized)

    return dedupe_keep_order(trackers)


def filter_blacklist(trackers: List[str], blacklist_file: str) -> List[str]:
    """Remove trackers containing any non-comment pattern from blackstr.txt."""
    path = Path(blacklist_file)
    if not path.exists():
        return trackers

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return trackers

    patterns = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    if not patterns:
        return trackers

    return [tracker for tracker in trackers if not any(p in tracker for p in patterns)]


def write_lines(path: Path, lines: Iterable[str]) -> None:
    """Write one line per item, always ending lines with '\n'."""
    path.parent.mkdir(parents=True, exist_ok=True) if path.parent != Path("") else None
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            f.write(line)
            f.write("\n\n")


def write_best_file(alive_items: List[CheckResult], output_file: str) -> None:
    """Write sorted unique alive trackers to the requested output file."""
    all_alive = sort_and_dedupe(item.url for item in alive_items)
    write_lines(Path(output_file), all_alive)


def tracker_protocol(url: str) -> str:
    """Return the protocol category used by reports."""
    try:
        scheme = urlsplit(url).scheme
    except ValueError:
        return "other"
    return scheme if scheme in {"http", "https", "udp", "wss"} else "other"


def split_best_file_by_protocol(output_file: str) -> None:
    """Split trackers_best.txt into protocol-specific files beside output_file."""
    output_path = Path(output_file)
    output_dir = output_path.parent if output_path.parent != Path("") else Path(".")

    content = output_path.read_text(encoding="utf-8", errors="replace")
    buckets: Dict[str, List[str]] = {"http": [], "https": [], "udp": [], "wss": []}

    for line in content.splitlines():
        tracker = line.strip()
        if not tracker:
            continue
        protocol = tracker_protocol(tracker)
        if protocol in buckets:
            buckets[protocol].append(tracker)

    write_lines(output_dir / "trackers_best_http.txt", sort_and_dedupe(buckets["http"]))
    write_lines(output_dir / "trackers_best_https.txt", sort_and_dedupe(buckets["https"]))
    write_lines(output_dir / "trackers_best_udp.txt", sort_and_dedupe(buckets["udp"]))
    write_lines(output_dir / "trackers_best_wss.txt", sort_and_dedupe(buckets["wss"]))


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


def load_tracker_history(path: Path) -> Dict[str, TrackerHistory]:
    """Load tracker_history.tsv. Supports old 7-field and new 8-field formats."""
    history: Dict[str, TrackerHistory] = {}
    if not path.exists():
        return history

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return history

    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) not in (7, 8):
            continue

        def to_int(value: str) -> int:
            try:
                return int(value)
            except ValueError:
                return 0

        url = parts[0]
        checks = to_int(parts[1])
        alive_checks = to_int(parts[2])
        first_seen_ts = to_int(parts[3])
        first_alive_ts = to_int(parts[4])
        last_seen_ts = to_int(parts[5])
        last_alive_ts = to_int(parts[6])

        if len(parts) == 8:
            streak_alive_start_ts = to_int(parts[7])
        elif last_seen_ts != 0 and last_seen_ts == last_alive_ts:
            # Backward compatibility with old history: if last run was alive,
            # start with a 1-run streak baseline.
            streak_alive_start_ts = last_seen_ts
        else:
            streak_alive_start_ts = 0

        history[url] = TrackerHistory(
            checks=checks,
            alive_checks=alive_checks,
            first_seen_ts=first_seen_ts,
            first_alive_ts=first_alive_ts,
            last_seen_ts=last_seen_ts,
            last_alive_ts=last_alive_ts,
            streak_alive_start_ts=streak_alive_start_ts,
        )

    return history


def save_tracker_history(path: Path, history: Dict[str, TrackerHistory]) -> None:
    """Save tracker_history.tsv sorted by URL."""
    lines = []
    for url in sorted(history.keys()):
        h = history[url]
        lines.append(
            f"{url}\t{h.checks}\t{h.alive_checks}\t{h.first_seen_ts}\t"
            f"{h.first_alive_ts}\t{h.last_seen_ts}\t{h.last_alive_ts}\t"
            f"{h.streak_alive_start_ts}"
        )
    write_lines(path, lines)


def update_tracker_history(history: Dict[str, TrackerHistory], results: List[CheckResult], now_ts: int) -> None:
    """Update counters, first/last timestamps and alive streak start timestamp."""
    for result in results:
        entry = history.setdefault(result.url, TrackerHistory())
        was_alive_last_run = entry.last_seen_ts != 0 and entry.last_seen_ts == entry.last_alive_ts

        entry.checks += 1
        if entry.first_seen_ts == 0:
            entry.first_seen_ts = now_ts
        entry.last_seen_ts = now_ts

        if result.status == Status.ALIVE:
            if not was_alive_last_run or entry.streak_alive_start_ts == 0:
                entry.streak_alive_start_ts = now_ts
            entry.alive_checks += 1
            if entry.first_alive_ts == 0:
                entry.first_alive_ts = now_ts
            entry.last_alive_ts = now_ts
        else:
            entry.streak_alive_start_ts = 0


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------


def generate_github_pages(
        results: List[CheckResult],
        history: Dict[str, TrackerHistory],
        input_file: str,
        output_file: str,
) -> None:
    """
    Generate docs/ static files.

    The Rust source emits a styled dashboard and public stats page. This Python
    version keeps the same data model and output files, with simpler HTML.
    """
    docs = Path("docs")
    public_stats = docs / "public-stats"
    public_stats.mkdir(parents=True, exist_ok=True)

    total = len(results)
    alive = sum(1 for r in results if r.status == Status.ALIVE)
    dead = sum(1 for r in results if r.status == Status.DEAD)
    invalid = sum(1 for r in results if r.status == Status.INVALID)

    protocol_counts = {"http": 0, "https": 0, "udp": 0, "wss": 0}
    for r in results:
        protocol = tracker_protocol(r.url)
        if protocol in protocol_counts:
            protocol_counts[protocol] += 1

    uptime_pct = 0.0 if total == 0 else alive * 100.0 / total
    ts = int(time.time())

    alive_list = sort_and_dedupe(r.url for r in results if r.status == Status.ALIVE)
    alive_http = sort_and_dedupe(
        r.url for r in results if r.status == Status.ALIVE and tracker_protocol(r.url) == "http"
    )
    alive_https = sort_and_dedupe(
        r.url for r in results if r.status == Status.ALIVE and tracker_protocol(r.url) == "https"
    )
    alive_udp = sort_and_dedupe(
        r.url for r in results if r.status == Status.ALIVE and tracker_protocol(r.url) == "udp"
    )
    alive_wss = sort_and_dedupe(
        r.url for r in results if r.status == Status.ALIVE and tracker_protocol(r.url) == "wss"
    )

    def streak_days(result: CheckResult) -> int:
        h = history.get(result.url)
        if not h or result.status != Status.ALIVE or h.streak_alive_start_ts == 0:
            return 0
        return ((ts - h.streak_alive_start_ts) // 86400) + 1

    def uptime_of(result: CheckResult) -> float:
        h = history.get(result.url)
        if not h or h.checks == 0:
            return 0.0
        return h.alive_checks * 100.0 / h.checks

    status_rank = {Status.ALIVE: 0, Status.DEAD: 1, Status.INVALID: 2}
    ordered = sorted(
        results,
        key=lambda r: (
            -streak_days(r),
            -uptime_of(r),
            r.ping_ms if r.ping_ms is not None else 2 ** 63 - 1,
            status_rank[r.status],
            r.url,
        ),
    )

    rows = []
    for r in ordered:
        status_text = {
            Status.ALIVE: "Online",
            Status.DEAD: "Dead",
            Status.INVALID: "Invalid",
        }[r.status]
        ping_text = f"{r.ping_ms} ms" if r.ping_ms is not None else "-"
        rows.append(
            "<tr>"
            f"<td>{html.escape(status_text)}</td>"
            f"<td><a href='{html.escape(r.url)}'>{html.escape(r.url)}</a></td>"
            f"<td>{html.escape(ping_text)}</td>"
            f"<td>{uptime_of(r):.2f}%</td>"
            f"<td>{streak_days(r)}</td>"
            "</tr>"
        )

    index_html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Tracker Status Dashboard</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ddd; padding: .4rem; }}
    th {{ text-align: left; }}
    .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
    .card {{ border: 1px solid #ddd; padding: 1rem; border-radius: .5rem; }}
    code {{ background: #f5f5f5; padding: .1rem .3rem; }}
  </style>
</head>
<body>
  <h1>Live Tracker Status</h1>
  <p>Generated by tracker-checker • input: <code>{html.escape(input_file)}</code> • output: <code>{html.escape(output_file)}</code></p>
  <p>
    <a href="trackers_best.txt">Download All</a> |
    <a href="trackers_best_http.txt">HTTP</a> |
    <a href="trackers_best_https.txt">HTTPS</a> |
    <a href="trackers_best_udp.txt">UDP</a> |
    <a href="trackers_best_wss.txt">WSS</a>
  </p>
  <div class="cards">
    <div class="card"><b>Global Uptime</b><br>{uptime_pct:.2f}%</div>
    <div class="card"><b>Total Checked</b><br>{total}</div>
    <div class="card"><b>Online</b><br>{alive}</div>
    <div class="card"><b>Dead</b><br>{dead}</div>
    <div class="card"><b>Invalid</b><br>{invalid}</div>
    <div class="card"><b>Protocols</b><br>H:{protocol_counts['http']} HS:{protocol_counts['https']} U:{protocol_counts['udp']} W:{protocol_counts['wss']}</div>
  </div>
  <h2>Trackers</h2>
  <table>
    <thead><tr><th>Status</th><th>URL</th><th>Ping</th><th>Uptime</th><th>Days</th></tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  <p>Generated timestamp (unix): {ts}</p>
</body>
</html>
"""

    public_stats_html = f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Public Tracker Stats</title></head>
<body>
  <h1>Privacy Tracker - Public Stats</h1>
  <p>No IP logging • UDP preferred • static report by tracker-checker</p>
  <p>TRACKERS CHECKED: {total}</p>
  <p>ONLINE: {alive}</p>
  <p>UPTIME: {uptime_pct:.2f}%</p>
  <p>UPDATED: {ts}</p>
  <p><a href="../index.html">Back to dashboard</a></p>
</body>
</html>
"""

    (docs / "index.html").write_text(index_html, encoding="utf-8")
    write_lines(docs / "trackers_best.txt", alive_list)
    write_lines(docs / "trackers_best_http.txt", alive_http)
    write_lines(docs / "trackers_best_https.txt", alive_https)
    write_lines(docs / "trackers_best_udp.txt", alive_udp)
    write_lines(docs / "trackers_best_wss.txt", alive_wss)
    (public_stats / "index.html").write_text(public_stats_html, encoding="utf-8")
    (docs / ".nojekyll").write_text("", encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> Tuple[str, str, int]:
    """
    Parse CLI while preserving the Rust behavior:
    - no args => trackers.txt trackers_best.txt DEFAULT_WORKERS
    - optional --workers N can appear among positional args.
    """
    parser = argparse.ArgumentParser(description="Tracker checker - Python strict mode")
    parser.add_argument("input", nargs="?", default="trackers.txt")
    parser.add_argument("output", nargs="?", default="trackers_best.txt")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    args = parser.parse_args(argv)
    return args.input, args.output, max(args.workers, 1)


def status_tag(status: Status) -> str:
    return {
        Status.ALIVE: "ALIVE",
        Status.DEAD: "DEAD",
        Status.INVALID: "INVALID",
    }[status]


def main(argv: Optional[List[str]] = None) -> int:
    input_file, output_file, workers = parse_args(argv)

    print("=" * 70)
    print("TRACKER CHECKER - PYTHON STRICT MODE")
    print("=" * 70)
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Workers: {workers}")
    print("=" * 70 + "\n")

    try:
        trackers = load_trackers(input_file)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1

    trackers = filter_blacklist(trackers, "blackstr.txt")
    trackers = sort_and_dedupe(trackers)

    if not trackers:
        print(f"Error: No trackers found in {input_file}", file=sys.stderr)
        return 1

    try:
        write_lines(Path(input_file), trackers)
    except OSError as exc:
        print(f"❌ Failed to write {input_file}: {exc}", file=sys.stderr)
        return 1

    print(f"Checking {len(trackers)} trackers with STRICT validation...")
    timeout = float(DEFAULT_TIMEOUT_SECS)
    total = len(trackers)

    all_results: List[CheckResult] = []
    alive: List[CheckResult] = []
    dead_count = 0
    invalid_count = 0
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(validate_tracker, tracker, timeout): tracker for tracker in trackers
        }
        for future in as_completed(future_map):
            result = future.result()
            completed += 1
            print(f"[{completed}/{total}] {status_tag(result.status)} {result.url}")

            all_results.append(result)
            if result.status == Status.ALIVE:
                alive.append(result)
            elif result.status == Status.DEAD:
                dead_count += 1
            elif result.status == Status.INVALID:
                invalid_count += 1

    print("Generating trackers_best.txt...")
    try:
        write_best_file(alive, output_file)
    except OSError as exc:
        print(f"❌ Failed to write {output_file}: {exc}", file=sys.stderr)
        return 1

    # print("Splitting trackers_best.txt by protocol...")
    # try:
    #     split_best_file_by_protocol(output_file)
    # except OSError as exc:
    #     print(f"❌ Failed to split {output_file}: {exc}", file=sys.stderr)
    #     return 1

    print("Generating GitHub Pages static files...")
    if len(all_results) != total:
        print("❌ internal result count mismatch", file=sys.stderr)
        return 1

    # history_path = Path("tracker_history.tsv")
    # history = load_tracker_history(history_path)
    # now_ts = int(time.time())
    # update_tracker_history(history, all_results, now_ts)
    #
    # try:
    #     save_tracker_history(history_path, history)
    #     generate_github_pages(all_results, history, input_file, output_file)
    # except OSError as exc:
    #     print(f"❌ Failed to write report files: {exc}", file=sys.stderr)
    #     return 1

    print(f"\nDone! Results saved to {output_file}")
    print(f"✓ Alive (Valid Trackers): {len(alive)}")
    print(f"✗ Dead: {dead_count}")
    print(f"⚠ Invalid (Parked/Expired/Not Trackers): {invalid_count}")
    print("GitHub Pages files: docs/index.html, docs/public-stats/index.html")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(["all_trackers_list.txt", "trackers_best_checked.txt", "--workers", "20"]))
