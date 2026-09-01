"""`op_backup_create` archives the FULL path relative to `/`, not just the
basename — proven by real `tar`, not by reading the argv it builds.

The bug this repairs, found while building the restore drill
(Funcționalitatea 07): archiving was `tar -cf a.tar -C <parent> <basename>`,
so a source like `/etc/nginx` was stored as members named `nginx/...` — not
`etc/nginx/...`. `restore.sh` and `op_restore_drill_verify` both extract with
`-C /`, so a real restore landed at `/nginx/...`, never at `/etc/nginx/...`.
Confirmed independently with plain `tar` and `tar -tf` before the fix; every
archive-based restore point on the production host would have restored to
the wrong place.

This sandbox has no standalone `zstd` binary (`tar --zstd` shells out to
one), so every test here drops `--zstd` from the tar invocation before it
runs. Two further, unrelated sandbox quirks, both purely artifacts of testing
POSIX-shaped production code on Windows, and neither one changes which paths
get archived, where they land, or the flags being exercised:

  * `_run` sets an explicit POSIX-style `PATH` (`/usr/local/sbin:...`) that
    does not exist as real directories on Windows, so the OS falls back to
    resolving `tar` on its own and finds Windows' bundled `bsdtar`
    (`System32\\tar.exe`) — which has no `--one-top-level`, the GNU-only flag
    that `op_restore_drill_verify`'s extraction relies on and that IS present
    on every target distribution (RHEL/AlmaLinux, Debian, Ubuntu all ship GNU
    tar as `/usr/bin/tar`). Calls that carry `--one-top-level` are redirected
    to whichever GNU tar this machine's normal, inherited PATH finds
    (`shutil.which`); every other call keeps using whatever `_run`'s own PATH
    resolves, i.e. `bsdtar` — which, usefully, agrees with Python's `pathlib`
    on what a leading `/` means (the current drive's root), unlike git-bash's
    GNU tar (see `_RealRoot` below). Routing every call through GNU tar
    indiscriminately was tried first and broke that agreement.
  * This git-for-windows build of GNU tar's own `--one-top-level` handling
    mishandles a native Windows path (`C:\\Users\\...`) passed as `-C` or
    `-f` — confirmed directly: the same call succeeds with a POSIX-style MSYS
    path (`/c/Users/...`) and fails, with a garbled path in its own error message,
    on the native form. So calls routed to GNU tar for `--one-top-level` also
    get their Windows-style path ARGUMENTS (not flags, not the `-C /` used by
    `op_backup_create`, which never reaches this branch — see the docstring
    on `_real_tar`) rewritten to that same MSYS form. This changes the STRING
    representation of an argument, never which real file it names or what
    `tar` does with it.

See `_real_tar` below for exactly what is and is not rewritten, and why.
"""

from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path

import pytest

import commands


def _find_gnu_tar() -> str | None:
    """Absolute path to a GNU tar on this machine, or `None`.

    Resolved from the process's OWN inherited PATH, not `_run`'s restricted
    one — `_run`'s PATH is correct for the Linux target and is exactly what
    resolves to the wrong tar here, on Windows.
    """
    candidate = shutil.which("tar")
    if not candidate:
        return None
    try:
        out = commands._run([candidate, "--version"], timeout=10)
    except Exception:  # noqa: BLE001
        return None
    return candidate if "GNU tar" in out.get("stdout", "") else None


GNU_TAR = _find_gnu_tar()


def _real_tar(monkeypatch, *, need_one_top_level: bool = False) -> list[list[str]]:
    """Strip `--zstd` from every tar invocation and delegate the rest,
    unchanged, to the real `_run` — a real `tar` process still runs, real
    files still move.

    A SEPARATE, per-call decision routes only invocations that actually carry
    `--one-top-level` (i.e. `op_restore_drill_verify`'s extraction, never
    `op_backup_create`'s archiving) to a real GNU tar found on the machine's
    normal PATH, because that flag is GNU-specific and Windows' bundled
    `bsdtar` — what `_run`'s own restricted PATH resolves to here — does not
    have it. Every OTHER tar call, including any `-C /` archiving, keeps
    running through whatever `_run`'s PATH finds, because on THIS sandbox that
    is `bsdtar`, and `bsdtar` and Python's `pathlib` agree on what a leading
    `/` means (the current drive's root) — unlike git-bash's GNU tar, whose
    MSYS layer translates `/` to its OWN install directory, which this
    unprivileged test process cannot write into. Routing every call through
    GNU tar indiscriminately was tried and failed for exactly that reason;
    see the git history of this file.

    `need_one_top_level=True` only controls whether the WHOLE TEST is skipped
    up front when no usable GNU tar exists — the per-call routing below is
    unconditional and harmless either way.
    """
    if need_one_top_level and GNU_TAR is None:
        pytest.skip("no GNU tar on this machine's PATH — --one-top-level "
                    "cannot be exercised for real here")
    real_run = commands._run
    executed: list[list[str]] = []

    def wrapper(argv, timeout=30, cwd=None):
        argv = list(argv)
        if argv and argv[0] == "tar":
            if "--zstd" in argv:
                argv = [a for a in argv if a != "--zstd"]
            if GNU_TAR and any(a.startswith("--one-top-level") for a in argv):
                argv[0] = GNU_TAR
                # GNU tar reads a `C:\...` archive path as `host:path` — the
                # old rsh-remote-archive syntax — and refuses it as a remote
                # connection, purely a Windows-sandbox artifact of a drive
                # letter followed by a colon. `--force-local` says "no,
                # that's a real local file", and is always safe to pass.
                # Harmless here because this branch never fires for a `-C /`
                # call — see the module docstring for why that matters.
                argv.insert(1, "--force-local")
                # This build's `--one-top-level` mishandles a native Windows
                # path argument (confirmed directly — see the module
                # docstring); an MSYS-style path naming the SAME real
                # location does not trip it. `argv[0]` (the executable Python
                # actually launches) is left alone — Windows' own process
                # launch needs a real Windows path there, not an MSYS one;
                # only the arguments tar itself parses are rewritten.
                argv = [argv[0]] + [_msys_path(a) for a in argv[1:]]
        executed.append(argv)
        return real_run(argv, timeout=timeout, cwd=cwd)

    monkeypatch.setattr(commands, "_run", wrapper)
    return executed


def _msys_path(arg: str) -> str:
    """`C:\\Users\\x` → `/c/Users/x`; anything else (flags, `tar`'s own
    absolute path) is returned unchanged. Same real location, different
    string form — see `_real_tar`'s docstring for why this is applied."""
    m = re.match(r"^([A-Za-z]):\\(.*)$", arg)
    if not m:
        return arg
    drive, rest = m.groups()
    return f"/{drive.lower()}/{rest.replace(chr(92), '/')}"


class _RealRoot:
    """A throwaway subtree of the REAL filesystem root `/`.

    `policy.check_path` requires an absolute POSIX-style path (leading `/`),
    and `op_backup_create`'s fixed line anchors tar at the literal string
    `"/"` — there is no `BACKUP_ROOT`-style seam for the SOURCE side, because
    in production there must not be one; a real restore has to land on the
    real root. So this creates real files under a uniquely-named directory
    directly beneath `/`, and removes them afterward. Nothing pre-existing is
    ever touched: the name is random per test and checked to be absent first.
    """

    def __init__(self):
        self.name = f"sentinel-drill-fix-test-{uuid.uuid4().hex[:12]}"
        self.root = Path("/") / self.name
        assert not self.root.exists(), (
            f"{self.root} already exists — refusing to reuse a real path")

    def __enter__(self) -> Path:
        self.root.mkdir()
        return self.root

    def __exit__(self, *exc):
        shutil.rmtree(self.root, ignore_errors=True)


def _extract(artifact: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    result = commands._run(["tar", "-xf", str(artifact), "-C", str(into)], timeout=60)
    assert result["exit_code"] == 0, result["stderr"]


def _posix_source(p: Path) -> str:
    """`p`, as the `/`-rooted POSIX string `policy.check_path` and
    `op_backup_create` see — e.g. `/sentinel-drill-fix-test-xxx/etc/nginx`."""
    return "/" + str(p).replace("\\", "/").lstrip("/")


def _posix_relative(p: Path) -> str:
    """`p` WITHOUT the leading `/` — the exact string the fixed
    `op_backup_create` stores as the archive's member-name anchor, and the
    exact path a caller must join under an extraction directory to find
    where the file actually landed."""
    return str(p).replace("\\", "/").lstrip("/")


# ---------------------------------------------------------------------------
def test_a_directory_source_lands_at_its_real_path_on_extraction(monkeypatch, tmp_path):
    """The exact case from the bug report: `/etc/nginx`, a directory with a
    file inside it."""
    _real_tar(monkeypatch)
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")

    with _RealRoot() as real_root:
        source = real_root / "etc" / "nginx"
        source.mkdir(parents=True)
        (source / "nginx.conf").write_text("server {}\n", encoding="utf-8")

        result = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-fix"})
        assert result["ok"] is True, result

        restored = tmp_path / "restored"
        _extract(Path(result["artifact"]), restored)

        # If this had been extracted with the real `-C /` that restore.sh
        # uses, it would land at exactly `source` — proven here by extracting
        # into an isolated directory and checking the SAME relative path
        # reappears under it.
        landed = restored / _posix_relative(source) / "nginx.conf"
        assert landed.is_file(), (
            f"expected {landed} after extraction; tree was: "
            f"{sorted(p.relative_to(restored) for p in restored.rglob('*'))}")
        assert landed.read_text(encoding="utf-8") == "server {}\n"
        # And the OLD bug's landing spot must NOT exist.
        assert not (restored / "nginx").exists(), (
            "the archive still stores only the basename, not the full path")


def test_a_single_file_source_lands_at_its_real_path(monkeypatch, tmp_path):
    """Sources are not always directories — `restore.sh` and the drill treat
    a `path` artifact the same way either way, so the fix must too."""
    _real_tar(monkeypatch)
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")

    with _RealRoot() as real_root:
        source = real_root / "etc" / "hostname"
        source.parent.mkdir(parents=True)
        source.write_text("blog\n", encoding="utf-8")

        result = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-fix2"})
        assert result["ok"] is True, result

        restored = tmp_path / "restored2"
        _extract(Path(result["artifact"]), restored)

        landed = restored / _posix_relative(source)
        assert landed.is_file(), sorted(restored.rglob("*"))
        assert landed.read_text(encoding="utf-8") == "blog\n"


def test_a_source_path_with_a_space_is_archived_and_restored_correctly(monkeypatch, tmp_path):
    _real_tar(monkeypatch)
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")

    with _RealRoot() as real_root:
        source = real_root / "var" / "www" / "my site"
        source.mkdir(parents=True)
        (source / "index.html").write_text("hi\n", encoding="utf-8")

        result = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-fix3"})
        assert result["ok"] is True, result

        restored = tmp_path / "restored3"
        _extract(Path(result["artifact"]), restored)

        landed = restored / _posix_relative(source) / "index.html"
        assert landed.is_file(), sorted(restored.rglob("*"))


def test_a_source_path_with_unusual_characters_is_archived_and_restored_correctly(
        monkeypatch, tmp_path):
    """Accents, parentheses, a leading dot on a component — none of these are
    shell metacharacters, and there is no shell here (`_run` never uses
    `shell=True`), but the archive member NAME construction has its own
    chance to mishandle them."""
    _real_tar(monkeypatch)
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")

    with _RealRoot() as real_root:
        source = real_root / "opt" / "app (v2) — café"
        source.mkdir(parents=True)
        (source / ".env.local").write_text("KEY=1\n", encoding="utf-8")

        result = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-fix4"})
        assert result["ok"] is True, result

        restored = tmp_path / "restored4"
        _extract(Path(result["artifact"]), restored)

        landed = restored / _posix_relative(source) / ".env.local"
        assert landed.is_file(), sorted(restored.rglob("*"))


def test_the_archive_member_names_carry_the_full_relative_path(monkeypatch, tmp_path):
    """Read the archive's own table of contents, not just the extracted tree —
    the most direct proof available that the fix changed what gets STORED,
    not just how this particular test happens to extract it."""
    _real_tar(monkeypatch)
    monkeypatch.setattr(commands, "BACKUP_ROOT", tmp_path / "backups")

    with _RealRoot() as real_root:
        source = real_root / "etc" / "nginx"
        source.mkdir(parents=True)
        (source / "nginx.conf").write_text("x", encoding="utf-8")

        result = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-fix5"})
        assert result["ok"] is True, result

        listing = commands._run(["tar", "-tf", result["artifact"]], timeout=30)
        assert listing["exit_code"] == 0, listing["stderr"]
        members = listing["stdout"].replace("\\", "/")
        relative = _posix_relative(source)
        assert relative in members or f"{relative}/" in members, (
            f"archive members do not carry the full relative path: {members!r}")
        assert "nginx.conf" in members
        # The old bug's shape: a member literally named just the basename,
        # with no path prefix at all.
        assert not members.strip().startswith(Path(source).name + "\n"), (
            "the first archive member is still the bare basename, not a "
            "path anchored at the source's parent chain")


# ---------------------------------------------------------------------------
# Old restore points, created before the fix, must stay honestly flagged —
# never retroactively treated as valid.
# ---------------------------------------------------------------------------
def test_an_old_format_archive_is_still_reported_structure_mismatch_not_upgraded(
        monkeypatch, tmp_path):
    """A restore point archived under the OLD code (basename-only members) is
    genuinely not restorable by `restore.sh` (`-C /`) — the fix must not hide
    that by making the drill's check pass for archives it did not create.

    Builds an old-shaped archive by hand (the exact `-C <parent> <basename>`
    invocation the buggy code used to run), then runs it through the REAL
    `op_restore_drill_verify` — proving the drill still calls it
    `structure_mismatch`, honestly, for exactly the restore points that
    cannot actually be restored.
    """
    import hashlib
    import json

    executed = _real_tar(monkeypatch, need_one_top_level=True)
    backup_root = tmp_path / "backups"
    monkeypatch.setattr(commands, "BACKUP_ROOT", backup_root)
    monkeypatch.setattr(commands, "DRILL_ROOT", backup_root / ".restore-drill")

    point_dir = backup_root / "20260601-old"
    point_dir.mkdir(parents=True)

    with _RealRoot() as real_root:
        source = real_root / "etc" / "nginx"
        source.mkdir(parents=True)
        (source / "nginx.conf").write_text("server {}\n", encoding="utf-8")

        # The OLD, buggy shape: `-C <parent> <basename>` — exactly what
        # `op_backup_create` built before this fix.
        artifact = point_dir / "etc_nginx.tar.zst"
        old_style = commands._run(
            ["tar", "-cf", str(artifact), "-C", str(source.parent), source.name],
            timeout=60)
        assert old_style["exit_code"] == 0, old_style["stderr"]

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    (point_dir / "manifest.json").write_text(json.dumps({"items": [
        {"artifact": "etc_nginx.tar.zst", "sha256": digest,
         "size_bytes": artifact.stat().st_size, "is_archive": True},
    ]}), encoding="utf-8")

    result = commands.op_restore_drill_verify(
        {"restore_point_id": "20260601-old", "sources": ["/etc/nginx"]})

    assert result["ok"] is True, result
    (item,) = result["items"]
    assert item["verdict"] == "structure_mismatch", (
        f"an old-format archive was reported as {item['verdict']!r} instead "
        f"of honestly flagged — it cannot actually be restored by restore.sh")
    assert item["matched_sources"] == []

    # And the fix is real tar work, not a stub: at least one tar invocation
    # actually ran for each phase (old-style create, drill extraction).
    tar_calls = [a for a in executed
                 if a and Path(a[0]).name.lower().startswith("tar")]
    assert any("-cf" in a for a in tar_calls)
    assert any("-xf" in a for a in tar_calls)


# ---------------------------------------------------------------------------
# The other half of the promise: a FIXED archive is genuinely proven
# restorable by the drill — not just "no longer flagged corrupt", but
# actually `restorable_verified`, extracted for real and matched for real.
# ---------------------------------------------------------------------------
def test_create_then_drill_end_to_end_reports_restorable_verified(monkeypatch, tmp_path):
    """The full pipeline, for real: `op_backup_create` archives a real
    directory with the fix in place, `op_backup_finalize` seals it exactly as
    production does, and `op_restore_drill_verify` extracts it into its own
    isolated directory and confirms the declared source reappears at the
    right path. No step here is stubbed or asserted on shape alone."""
    executed = _real_tar(monkeypatch, need_one_top_level=True)
    backup_root = tmp_path / "backups"
    monkeypatch.setattr(commands, "BACKUP_ROOT", backup_root)
    monkeypatch.setattr(commands, "DRILL_ROOT", backup_root / ".restore-drill")

    with _RealRoot() as real_root:
        source = real_root / "etc" / "nginx"
        source.mkdir(parents=True)
        (source / "nginx.conf").write_text("server {}\n", encoding="utf-8")

        created = commands.op_backup_create({
            "kind": "path", "source": _posix_source(source),
            "restore_point_id": "20260901-e2e"})
        assert created["ok"] is True, created

    sealed = commands.op_backup_finalize({"restore_point_id": "20260901-e2e"})
    assert sealed["ok"] is True, sealed

    # The declared source has to be the SAME string `op_backup_create` was
    # given — `_RealRoot` nests everything under a unique per-test prefix so
    # tests never collide, so the real declared path is NOT the literal
    # `/etc/nginx` from the bug report, it is that prefix's own `/etc/nginx`.
    declared_source = _posix_source(source)
    result = commands.op_restore_drill_verify(
        {"restore_point_id": "20260901-e2e", "sources": [declared_source]})
    assert result["ok"] is True, result
    (item,) = result["items"]
    assert item["verdict"] == "restorable_verified", (
        f"a correctly-archived source was reported {item['verdict']!r}: "
        f"{item.get('detail')!r}")
    assert item["matched_sources"] == [declared_source]

    tar_calls = [a for a in executed
                 if a and Path(a[0]).name.lower().startswith("tar")]
    assert any("-cf" in a for a in tar_calls), "no real archive was created"
    assert any("-xf" in a for a in tar_calls), "no real extraction ran"
