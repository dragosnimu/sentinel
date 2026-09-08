"""P3 unit tests: parsers, the inode-aware tailer, and event→row mapping.

The journald reader and the ingest daemon do real I/O against systemd and are
exercised during deploy verification; here we test the pure, tricky parts — the
regexes that face attacker-controlled log text, and the tailer's rotation logic.
"""

from __future__ import annotations

from datetime import datetime, timezone


# --- sshd parser -----------------------------------------------------------
def test_sshd_failed_password():
    from sentinel.collectors.sshd import parse_sshd

    ts = datetime.now(timezone.utc)
    e = parse_sshd("Failed password for root from 218.92.0.34 port 51234 ssh2", ts)
    assert e.source == "sshd" and e.action == "auth_fail"
    assert e.src_ip == "218.92.0.34" and e.username == "root"
    assert e.raw["invalid_user"] is False


def test_sshd_invalid_user_is_auth_fail():
    from sentinel.collectors.sshd import parse_sshd

    e = parse_sshd("Failed password for invalid user admin from 45.148.10.2 port 40022 ssh2",
                   datetime.now(timezone.utc))
    assert e.action == "auth_fail" and e.username == "admin"
    assert e.raw["invalid_user"] is True


def test_sshd_accepted_is_auth_ok():
    from sentinel.collectors.sshd import parse_sshd

    e = parse_sshd("Accepted publickey for operator from 198.51.100.25 port 55010 ssh2",
                   datetime.now(timezone.utc))
    assert e.action == "auth_ok" and e.username == "operator"


def test_sshd_ignores_noise():
    from sentinel.collectors.sshd import parse_sshd

    assert parse_sshd("Connection closed by 1.2.3.4 port 22", datetime.now(timezone.utc)) is None


# --- sshd log injection (F1): a forged "from <ip> port <n>" inside the
# attacker-chosen username must never become src_ip. Before the fix, an
# unanchored `.search` with a non-greedy `\S+` username matched a FAKE
# "Failed password ... from <ip> port <n>" embedded in the username instead of
# the real one sshd appends at the true end of the line — so `ssh_bruteforce`
# would group the incident under, and the decider could auto-block, an
# innocent forged third party while hiding the real attacker.
def test_sshd_injected_failed_password_uses_the_real_peer():
    from sentinel.collectors.sshd import parse_sshd

    msg = ("Invalid user x Failed password for root from 203.0.113.9 port 22 ssh2 "
           "from 198.51.100.7 port 4444")
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None and e.action == "auth_fail"
    assert e.src_ip == "198.51.100.7"          # the real peer, appended by sshd
    assert e.src_ip != "203.0.113.9"            # never the attacker-chosen fake
    assert e.username == "<invalid>"
    assert e.raw["suspicious_username"] is True


def test_sshd_injected_accepted_uses_the_real_peer():
    from sentinel.collectors.sshd import parse_sshd

    msg = ("Invalid user Accepted password for root from 203.0.113.9 port 4444 "
           "from 198.51.100.8 port 5555")
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None
    # It is genuinely an invalid-user attempt, not a real accepted login: must
    # never be reported as auth_ok, whatever the forged text inside the
    # username claims.
    assert e.action == "auth_fail"
    assert e.src_ip == "198.51.100.8"
    assert e.src_ip != "203.0.113.9"
    assert e.username == "<invalid>"


def test_sshd_injected_failed_password_from_genuine_failed_prefix_uses_real_peer():
    """The two injection tests above both start with `Invalid user`, so
    `_FAILED.search()` never even fires on them (its pattern requires the
    message to literally START with `Failed password|publickey for` after the
    optional unit prefix) — they only ever exercised `_INVALID`'s greedy
    username. With `_FAILED`'s username restored to the old non-greedy `\\S+`,
    a message that genuinely starts with `Failed password for` and contains a
    forged `from <ip> port <n>` inside the username would still pass this
    suite while parsing the attacker-chosen `203.0.113.9` as `src_ip` instead
    of the real peer sshd appends at the true end of the line."""
    from sentinel.collectors.sshd import parse_sshd

    msg = ("Failed password for invalid user a from 203.0.113.9 port 22 ssh2 "
           "from 198.51.100.7 port 4444 ssh2")
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None and e.action == "auth_fail"
    assert e.src_ip == "198.51.100.7"
    assert e.src_ip != "203.0.113.9"
    assert e.username == "<invalid>"


def test_sshd_injected_accepted_publickey_from_genuine_prefix_uses_real_peer():
    from sentinel.collectors.sshd import parse_sshd

    msg = ("Accepted publickey for root from 203.0.113.9 port 4444 "
           "from 198.51.100.8 port 5555")
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None and e.action == "auth_ok"
    assert e.src_ip == "198.51.100.8"
    assert e.src_ip != "203.0.113.9"
    assert e.username == "<invalid>"


def test_sshd_injected_accepted_password_from_genuine_prefix_uses_real_peer():
    from sentinel.collectors.sshd import parse_sshd

    msg = ("Accepted password for root from 203.0.113.9 port 4444 "
           "from 198.51.100.8 port 5555")
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None and e.action == "auth_ok"
    assert e.src_ip == "198.51.100.8"
    assert e.src_ip != "203.0.113.9"
    assert e.username == "<invalid>"


def test_sshd_username_with_spaces_is_flagged_not_trusted():
    """A username containing whitespace cannot be a real POSIX account name —
    it is text shaped to look like a different log line (seen for real on the
    host as an HTML fragment offered as a username). The event is kept (silent
    drop would hide the attack) but `username` must not carry the raw
    attacker text into an incident summary or alert unlabelled."""
    from sentinel.collectors.sshd import parse_sshd

    msg = 'Invalid user <!DOCTYPE html PUBLIC "- from 198.51.100.9 port 6000'
    e = parse_sshd(msg, datetime.now(timezone.utc))
    assert e is not None
    assert e.src_ip == "198.51.100.9"
    assert e.username == "<invalid>"
    assert e.raw["suspicious_username"] is True
    assert e.raw["raw_username"].startswith("<!DOCTYPE")


def test_sshd_normal_lines_are_not_flagged_suspicious():
    """Falsifies the flag the other way: an ordinary username must NOT be
    marked suspicious, or every real brute-force attempt would show
    `<invalid>` instead of the username actually tried."""
    from sentinel.collectors.sshd import parse_sshd

    e = parse_sshd("Failed password for root from 218.92.0.34 port 51234 ssh2",
                    datetime.now(timezone.utc))
    assert e.username == "root"
    assert e.raw["suspicious_username"] is False


# --- nginx parser ----------------------------------------------------------
def test_nginx_combined_line():
    from sentinel.collectors.nginx import parse_nginx

    e = parse_nginx('218.92.0.34 - - [31/Jul/2026:06:00:00 +0000] '
                    '"GET /wp-login.php?x=1 HTTP/1.1" 404 153 "-" "sqlmap/1.5"')
    assert e.source == "nginx" and e.action == "request"
    assert e.src_ip == "218.92.0.34"
    assert e.http_method == "GET" and e.http_path == "/wp-login.php" and e.http_query == "x=1"
    assert e.http_status == 404 and e.http_ua == "sqlmap/1.5"
    assert e.bytes_out == 153


def test_nginx_with_vhost_prefix():
    from sentinel.collectors.nginx import parse_nginx

    e = parse_nginx('sentinel.exemplu.ro 1.2.3.4 - - [31/Jul/2026:06:00:02 +0000] '
                    '"GET / HTTP/1.1" 302 0 "-" "curl/8"')
    assert e.http_host == "sentinel.exemplu.ro" and e.src_ip == "1.2.3.4"
    assert e.http_status == 302


def test_nginx_untrusted_path_is_bounded_not_executed():
    from sentinel.collectors.nginx import parse_nginx
    from sentinel.model.event import MAX_FIELD_LEN

    hostile = "/" + "A" * (MAX_FIELD_LEN + 100)
    e = parse_nginx(f'1.2.3.4 - - [31/Jul/2026:06:00:00 +0000] "GET {hostile} HTTP/1.1" 200 1 "-" "-"')
    assert len(e.http_path) <= MAX_FIELD_LEN + len("…[truncated]")
    assert e.http_path.endswith("…[truncated]")


# --- nginx record injection / ReDoS (F2) ------------------------------------
# `remote_user` is as attacker-chosen as any other field (HTTP Basic-Auth
# username on any vhost that uses it). Before this fix, `_LINE.search()`
# looked for the record pattern ANYWHERE in the line, so a `remote_user`
# crafted to contain its own fake `[time] "request" status bytes "referer"
# "ua"` tail let the FAKE fields win: parsing the line below with the old
# `.search()` returns an event reporting a clean `200` on `/fake` while the
# real request — a 404 probe on `/real` from an sqlmap user-agent — is
# discarded entirely. That is the record injection this fixes: a request that
# should raise `web.enumeration` instead reports as unremarkable.
def test_nginx_injected_remote_user_is_rejected_not_forged():
    from sentinel.collectors.nginx import parse_nginx

    line = ('203.0.113.5 - x [01/Jan/2026:00:00:00 +0000] "GET /fake HTTP/1.1" 200 1 "-" "-" '
            '[31/Jul/2026:06:00:00 +0000] "GET /real HTTP/1.1" 404 153 "-" "sqlmap/1.5"')
    e = parse_nginx(line)
    # `fullmatch` requires the WHOLE line to be one record; a fake tail
    # embedded in `remote_user` leaves the genuine trailing fields
    # unconsumed, so the line no longer fullmatches at all — rejected, never
    # parsed with the attacker's forged status/path standing in for the real
    # ones.
    assert e is None


def test_nginx_injected_remote_user_does_not_forge_src_ip():
    """`addr` is always the literal first token of the line under `fullmatch`
    (there is only one position to try, the start), so whatever a crafted
    `remote_user` does, `src_ip` can never come from attacker-controlled text
    — the property that matters for auto-block.

    Unlike the fake-tail line above (which is rejected outright and so proves
    nothing about `src_ip` specifically — an `if e is not None:` wrapping the
    assertion here used to make it pass vacuously whenever `e` was `None`,
    which is every run), this line is a well-formed SINGLE record whose Basic
    Auth username is itself shaped like an IP address — the shape a naive
    "pull the first IP-looking token out of the line" bug would grab instead
    of the real `$remote_addr`. The assertion runs unconditionally."""
    from sentinel.collectors.nginx import parse_nginx

    line = ('203.0.113.5 - 9.9.9.9 [01/Jan/2026:00:00:00 +0000] '
            '"GET / HTTP/1.1" 200 1 "-" "-"')
    e = parse_nginx(line)
    assert e is not None
    assert e.src_ip == "203.0.113.5"
    assert e.src_ip != "9.9.9.9"


# --- nginx `main` format (AlmaLinux/RHEL stock, adds trailing XFF field) ---
def test_nginx_main_format_with_trailing_xff_field_parses():
    """AlmaLinux's stock `log_format main` appends `"$http_x_forwarded_for"`
    after the UA; this is what production's tailed `/var/log/nginx/*access*
    .log` actually contains. Before allowing a trailing quoted-field group,
    `fullmatch` rejected EVERY line in this format — 6,536 events/day would
    go silent, not because of an attack, but because the parser only ever
    understood Ubuntu's `combined` format. Reads the 5-line fixture and
    checks each line both parses and yields the correct `src_ip`."""
    from pathlib import Path

    from sentinel.collectors.nginx import parse_nginx

    fixture = (Path(__file__).resolve().parents[1] / "fixtures" / "nginx-rhel"
               / "access-main-format.txt")
    lines = fixture.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5, "fixture drifted — this test assumes 5 sanitised lines"

    expected_ips = [
        "203.0.113.10", "198.51.100.23", "192.0.2.44", "203.0.113.9", "198.51.100.7",
    ]
    for line, ip in zip(lines, expected_ips):
        e = parse_nginx(line)
        assert e is not None, f"main-format line failed to parse: {line!r}"
        assert e.source == "nginx" and e.action == "request"
        assert e.src_ip == ip


def test_nginx_combined_format_without_trailing_field_still_parses():
    """Falsifies the fixture test the other way: Ubuntu's default `combined`
    format (no trailing XFF field at all) must still parse — the trailing
    group is optional (`*`, not `+`), so a regression that made it required
    would silently break every non-RHEL deployment while this repository's
    OWN test fixtures (which use `combined`) kept passing."""
    from sentinel.collectors.nginx import parse_nginx

    e = parse_nginx('203.0.113.20 - - [08/Sep/2026:10:15:05 +0000] '
                    '"GET /status HTTP/1.1" 200 4 "-" "curl/8.4.0"')
    assert e is not None
    assert e.src_ip == "203.0.113.20"


def test_nginx_x_forwarded_for_never_becomes_src_ip():
    """`$http_x_forwarded_for` is a request header the CLIENT sends; nothing
    in this deployment rewrites it, so an attacker can put anything there.
    `src_ip` must always be `$remote_addr` (the real TCP peer), never the
    trailing XFF field — even when the XFF value is itself a plausible,
    differently-owned IP address."""
    from sentinel.collectors.nginx import parse_nginx

    e = parse_nginx('203.0.113.30 - - [08/Sep/2026:10:15:06 +0000] '
                    '"GET / HTTP/1.1" 200 1 "-" "curl/8.4.0" "203.0.113.9"')
    assert e is not None
    assert e.src_ip == "203.0.113.30"
    assert e.src_ip != "203.0.113.9"


def test_nginx_100kb_non_matching_line_is_fast():
    """A 100 KB line that never matches the combined-log grammar used to cost
    65+ seconds of CPU under the old unanchored `.search()` — catastrophic
    backtracking retrying the whole pattern at every one of the line's
    100,000 starting offsets. Measured on this branch: 140 s for a 95 KB
    adversarial line before the fix. The collector must not be a CPU
    exhaustion vector for whoever can write one line to an access log."""
    import time

    from sentinel.collectors.nginx import parse_nginx

    payload = "1.2.3.4.5.6.7.8.9.0" * 5000  # ~95 KB, all address-class chars
    start = time.perf_counter()
    result = parse_nginx(payload)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.05, f"took {elapsed:.3f}s — regex is unanchored again"
    assert result is None  # never matched the grammar; correctly rejected


# --- no pre-match truncation (F4 / R2) --------------------------------------
# A pre-match length cap (formerly `_MAX_LINE_LEN = 8192`) used to truncate a
# line BEFORE either regex ran. Truncation almost always lands inside a still-
# open quoted field, so the line no longer fullmatches — a genuinely valid
# request longer than the cap silently vanished from the log, as if it had
# never happened. Production already logs lines of 7,966 bytes; worse, this
# made padding the UA or referer past the cap a way to make a request
# INVISIBLE to this collector — detection evasion dressed up as a safety
# limit. Measured: a 95 KB adversarial (non-matching) line costs ≤ 0.94 ms and
# a 1 MB valid line costs ≈ 0.23 ms under `fullmatch`, so the cap was never
# load-bearing for the ReDoS fix either.
def test_nginx_line_just_over_the_old_8kb_cap_still_parses():
    """The retired cap silently dropped anything past 8192 bytes. A valid
    line just over that boundary — well within nginx's OWN default ceiling
    (`large_client_header_buffers 4 8k;` ≈ 24.6 KB) — must parse normally."""
    from sentinel.collectors.nginx import parse_nginx

    padded_ua = "Mozilla/5.0 " + "A" * 8200
    line = (f'203.0.113.50 - - [08/Sep/2026:10:20:00 +0000] "GET /probe HTTP/1.1" '
            f'200 1 "-" "{padded_ua}"')
    assert len(line) > 8192
    e = parse_nginx(line)
    assert e is not None
    assert e.src_ip == "203.0.113.50"
    assert e.http_ua is not None and e.http_ua.startswith("Mozilla/5.0")


def test_nginx_30kb_valid_line_parses():
    """Beyond even nginx's default ceiling, a 30 KB valid line (a non-default
    `large_client_header_buffers`, or simply what the log actually contains)
    must still parse — the collector's job is to read what the log holds,
    not to enforce nginx's own configuration a second time."""
    from sentinel.collectors.nginx import parse_nginx

    padded_ua = "A" * 30000
    line = (f'198.51.100.77 - - [08/Sep/2026:10:20:01 +0000] "GET /probe HTTP/1.1" '
            f'200 1 "-" "{padded_ua}"')
    assert len(line) > 30000
    e = parse_nginx(line)
    assert e is not None
    assert e.src_ip == "198.51.100.77"


def test_nginx_line_over_hard_sanity_cap_is_refused_fast():
    """`_HARD_CAP` (1 MiB) is a resource-safety backstop, not a functional
    bound: no real nginx line gets anywhere near it. A line beyond it must be
    refused OUTRIGHT — never truncated and then handed to the regex, which is
    exactly the silent-drop shape this cap replaced — and rejecting it must
    not cost meaningfully more than an ordinary parse."""
    import time

    from sentinel.collectors.nginx import _HARD_CAP, parse_nginx

    hostile = "A" * (_HARD_CAP + 1000)
    line = f'1.2.3.4 - - [08/Sep/2026:10:20:02 +0000] "GET /{hostile} HTTP/1.1" 200 1 "-" "-"'
    start = time.perf_counter()
    result = parse_nginx(line)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.05
    assert result is None


# --- inode-aware tailer ----------------------------------------------------
def test_tailer_tails_on_first_sight_then_reads_new_lines(tmp_path):
    from sentinel.collectors.nginx_tail import read_new_lines

    log = tmp_path / "access.log"
    log.write_text("history one\nhistory two\n", encoding="utf-8")

    # First sight (cursor None): tail — do NOT replay the existing history.
    lines0, cursor = read_new_lines(str(log), None)
    assert lines0 == []

    # A partial line must not be read until the newline lands.
    with log.open("a", encoding="utf-8") as fh:
        fh.write("partial")
    lines1, cursor1 = read_new_lines(str(log), cursor)
    assert lines1 == []

    with log.open("a", encoding="utf-8") as fh:
        fh.write(" now complete\nsecond\n")
    lines2, _ = read_new_lines(str(log), cursor1)
    assert lines2 == ["partial now complete", "second"]


def test_tailer_handles_rotation(tmp_path):
    from sentinel.collectors.nginx_tail import read_new_lines

    log = tmp_path / "access.log"
    log.write_text("old\n", encoding="utf-8")
    _, cursor = read_new_lines(str(log), None)      # tail past "old"

    # Simulate rotation: replace the file (new inode) with fresh content. A new
    # inode is read from the start, not from the stale offset.
    log.unlink()
    log.write_text("fresh after rotate\n", encoding="utf-8")
    lines, _ = read_new_lines(str(log), cursor)
    assert lines == ["fresh after rotate"]


# --- event → row mapping ---------------------------------------------------
def test_event_row_tuple_shape():
    import json

    from sentinel.collectors.sshd import parse_sshd
    from sentinel.db.repo.events import _COLS, _row_tuple

    e = parse_sshd("Failed password for root from 1.2.3.4 port 5 ssh2", datetime.now(timezone.utc))
    row = _row_tuple(e)
    assert len(row) == len(_COLS)
    # raw is serialised to a JSON string for the jsonb column.
    raw_val = row[_COLS.index("raw")]
    assert isinstance(raw_val, str) and json.loads(raw_val)["invalid_user"] is False
    assert row[_COLS.index("reputation")] == []
