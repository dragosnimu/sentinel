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
