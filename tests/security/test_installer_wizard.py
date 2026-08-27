"""Installer and wizard invariants.

The wizard is the first thing a new operator runs, often as root, on a machine
they care about. Two classes of mistake matter here: leaking a secret into
somewhere it can be read later, and changing the host before the operator has
agreed to anything. Both are pinned below.
"""
from __future__ import annotations

import re
import stat
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WIZARD = (REPO / "scripts" / "wizard.sh").read_text(encoding="utf-8")
DISTRO = (REPO / "deploy" / "lib" / "distro.sh").read_text(encoding="utf-8")
INSTALL = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
PREFLIGHT = (REPO / "deploy" / "preflight.sh").read_text(encoding="utf-8")


# --- secrets ----------------------------------------------------------------
def test_secrets_are_read_with_echo_off():
    """A token typed in cleartext ends up in a screen recording, a screenshot,
    and the scrollback of whoever is pairing with you."""
    assert "ask_secret()" in WIZARD
    body = WIZARD.split("ask_secret()")[1].split("\n}")[0]
    assert "read -r -s" in body            # -s is the echo-off flag


def test_secrets_are_never_passed_as_arguments():
    """`ps` shows every process's argv to every user on the host. A bot token
    on a command line is a token given away."""
    for var in ("TELEGRAM_BOT_TOKEN", "ANTHROPIC_API_KEY"):
        # It may only appear where it is read, written to stdin, or saved to the
        # 0600 answers file — never interpolated into an ssh/bash command.
        for line in WIZARD.splitlines():
            if var not in line or line.strip().startswith("#"):
                continue
            assert not re.search(rf"(ssh|bash|sh) .*\$\{{?{var}", line), \
                f"{var} reaches a command line: {line.strip()}"


def test_secrets_travel_on_stdin():
    assert "build_secrets |" in WIZARD or "build_secrets >" in WIZARD
    assert "cat > /tmp/sentinel-secrets" in WIZARD


def test_saved_answers_file_is_locked_down():
    """It contains the bot token. Anything looser than 0600 hands it to every
    other account on the machine."""
    assert "umask 077" in WIZARD
    assert 'chmod 0600 "$SAVE_FILE"' in WIZARD
    assert "conține secrete" in WIZARD      # and it says so in the file itself


def test_secrets_are_removed_from_the_target_after_install():
    assert "rm -f /tmp/sentinel-secrets" in WIZARD


def test_packaging_excludes_the_secrets_directory():
    tar_line = next(l for l in WIZARD.splitlines() if "tar --exclude" in l)
    assert "secrets/*" in tar_line or "--exclude='secrets/*'" in WIZARD
    assert "--exclude='.git'" in WIZARD


# --- nothing changes before consent -----------------------------------------
def test_confirmation_precedes_every_mutation():
    """Everything above the confirmation must be questions and read-only checks;
    an installer that has already edited nginx by the time it asks is lying."""
    confirm_at = WIZARD.index("Din acest punct înainte se modifică serverul")
    for mutating in ("tar --exclude", "scp -q", "run_install"):
        assert WIZARD.index(mutating) > confirm_at, \
            f"{mutating!r} happens before the operator confirms"


def test_dry_run_exits_before_any_change():
    dry_at = WIZARD.index('"$DRY_RUN" == "yes"')
    install_at = WIZARD.index("Instalare")
    assert dry_at < install_at


def test_second_ssh_session_is_advised():
    # A locked-out operator with no second session has to use the provider's
    # console, which people discover they cannot reach at exactly the wrong time.
    assert "a doua sesiune SSH" in WIZARD


# --- distribution support ---------------------------------------------------
def test_both_families_are_handled_everywhere_they_branch():
    """A half-supported distribution is worse than a refused one: it leaves a
    machine that looks protected and is not."""
    for fn in ("pkg_install", "pkg_names_core", "pg_bootstrap", "pg_confdir",
               "python_pkg_names", "suricata_defaults_file",
               "security_module_allow_nginx_proxy"):
        body = _func(DISTRO, fn)
        assert "rhel)" in body, f"{fn} has no rhel branch"
        assert "debian)" in body, f"{fn} has no debian branch"


def test_unsupported_distribution_is_refused_by_name():
    assert "distro_supported" in INSTALL
    assert "unsupported distribution" in INSTALL
    assert "unsupported distribution" in INSTALL or "nesuportată" in WIZARD


def test_installer_has_no_hardcoded_package_manager_left():
    """Every dnf/apt call must go through the abstraction, or Debian support is
    fiction that fails halfway through an install."""
    offenders = [l.strip() for l in INSTALL.splitlines()
                 if re.search(r"^\s*(dnf|apt-get|yum|rpm -q) ", l)
                 and not l.strip().startswith("#")]
    assert not offenders, f"direct package-manager calls remain: {offenders[:3]}"


def test_no_hardcoded_postgres_paths_left():
    offenders = [l.strip() for l in INSTALL.splitlines()
                 if "/var/lib/pgsql" in l and not l.strip().startswith("#")]
    assert not offenders, f"RHEL-only postgres paths remain: {offenders[:3]}"


def test_systemd_is_required_not_assumed():
    """journald is the primary detection source; without it SSH brute-force is
    invisible, so the check belongs up front rather than as a later surprise."""
    assert "systemd is required" in PREFLIGHT
    assert "systemd" in WIZARD


def test_python_floor_matches_what_the_distros_ship():
    """3.10 covers Ubuntu 22.04 through AlmaLinux 9 with no third-party repo.
    Requiring 3.12 would have forced deadsnakes onto two supported targets."""
    assert "PYTHON_MIN_MINOR=10" in DISTRO
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in pyproject


# --- executable bits --------------------------------------------------------
def test_wizard_declares_a_shebang():
    assert WIZARD.startswith("#!/usr/bin/env bash")


def test_shell_files_use_unix_line_endings():
    """A CRLF shell script fails on Linux with a confusing 'bad interpreter'."""
    for name in ("scripts/wizard.sh", "deploy/lib/distro.sh",
                 "deploy/install.sh", "deploy/preflight.sh"):
        assert b"\r\n" not in (REPO / name).read_bytes(), f"{name} has CRLF"


# --- the upgrade path actually upgrades ------------------------------------
COMMON = (REPO / "deploy" / "lib" / "common.sh").read_text(encoding="utf-8")


def test_the_upgrade_steps_are_not_marker_gated():
    """`git pull` + re-run is the documented upgrade. With every step behind a
    completion marker, that re-run skipped the package copy AND the migrations,
    printed success, and changed nothing on the host."""
    assert "ALWAYS_STEPS=" in COMMON
    always = COMMON.split("ALWAYS_STEPS=", 1)[1].split('"', 2)[1]
    # Every step that carries content from the repo. An nginx fix that never
    # reaches the server is as useless as a code fix that never reaches it.
    for step in ("package", "migrate", "systemd", "nginx", "nginx_shared", "configs"):
        assert step in always, f"step {step} would be skipped on an upgrade"
    assert "! step_is_always" in COMMON


def test_suricata_is_re_run_on_every_deploy():
    """Pasul 35 scrie `/etc/default/suricata` și drop-in-ul systemd — conținut
    generat de instalator, deci conținut care se schimbă între versiuni. Cât a
    stat în afara listei, orice gazdă deja instalată îl sărea: reparația din
    25 august, care a oprit demonul din a captura pe o placă inexistentă, n-ar
    fi ajuns niciodată în producție fără un `--force-step 35` ținut minte de
    cineva. Operatorul a cerut intrarea în listă pe 26 august 2026, acceptând
    costul măsurat de ~3 minute pe deploy (332 s cu, 148 s fără,
    pe VM-ul de test)."""
    always = COMMON.split("ALWAYS_STEPS=", 1)[1].split('"', 2)[1]
    assert "suricata" in always.split(), \
        "pasul 35 e din nou sărit pe gazdele deja instalate"


def test_nftables_is_never_re_run_automatically():
    """Re-creating the table empties the named sets, which silently unblocks
    every attacker currently blocked. Refreshing config is worth a re-run;
    dropping a live blocklist is not."""
    always = COMMON.split("ALWAYS_STEPS=", 1)[1].split('"', 2)[1]
    assert "nftables" not in always


def test_documented_upgrade_command_matches_the_installer():
    deployment = (REPO / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
    upgrade = deployment.split("## 7. Upgrade", 1)[1].split("\n## ", 1)[0]
    # The doc promises both of these happen; the test above is what makes it true.
    assert "migrațiile noi se aplică" in upgrade
    assert "git pull" in upgrade


def test_deploy_probes_multiplexing_instead_of_assuming_it():
    """Multiplexing is an optimisation. Assuming it works turns a cosmetic
    Windows limitation into 'cannot reach the host', which sends the operator
    to debug a network that is fine."""
    deploy = (REPO / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    assert 'MUX="no"' in deploy
    # Probed with a real session: `-O check` answers a different question.
    probe = deploy.split('MUX="no"', 1)[1].split("ssh_run()", 1)[0]
    assert '"${USER}@${HOST}" true' in probe
    assert "-O exit" in probe               # the failed master is torn down


def test_deploy_replaces_the_remote_deploy_tree_rather_than_nesting():
    """`cp -r src dest` nests when dest exists, so the second deploy left the
    FIRST deploy's rollback.sh in place — the one script whose staleness bites."""
    deploy = (REPO / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    block = deploy.split("# Keep the extracted tree", 1)[1].split("ssh_run \"rm -rf", 1)[0]
    # Comments in this block quote the very command shapes under test, so
    # matching against them would check the prose instead of the code.
    code = "\n".join(l for l in block.splitlines() if not l.strip().startswith("#"))
    assert "rm -rf /opt/sentinel/deploy" in code
    assert code.index("rm -rf /opt/sentinel/deploy") < code.index("cp -r")
    assert "|| true" not in code            # a silent failure here ages rollback.sh


def test_every_privileged_command_gets_its_own_sudo():
    """`sudo a && b` elevates only `a`; the rest of the chain runs as the login
    user. Written as a chain, the tree removal succeeded as root and the copy
    that replaced it did not — leaving the host with no rollback.sh at all."""
    deploy = (REPO / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    for line in deploy.splitlines():
        stripped = line.strip()
        if not stripped.startswith("ssh_sudo ") or stripped.startswith("#"):
            continue
        # The argument is one command: no shell chaining inside the quotes,
        # unless it is explicitly re-wrapped in sh -c.
        arg = stripped.split("ssh_sudo ", 1)[1]
        if "sh -c" in arg:
            continue
        # `$( ... )` is evaluated by the LOCAL shell before the string is sent,
        # so chaining in there is not chaining under the remote sudo.
        arg = _strip_substitutions(arg)
        assert " && " not in arg, f"chained command under one sudo: {stripped}"
        assert "; " not in arg, f"chained command under one sudo: {stripped}"


def _strip_substitutions(text: str) -> str:
    """Remove `$( ... )` spans, counting nesting.

    A non-greedy regex is not enough: `$( ((PURGE)) && echo x )` closes three
    times, and stopping at the first `)` leaves the `&&` behind and fails the
    caller for a chain that never reaches the remote host."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("$(", i):
            depth, i = 1, i + 2
            while i < len(text) and depth:
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _func(source: str, name: str) -> str:
    m = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert m, f"function {name} not found"
    return m.group(0)


def test_entrypoint_scripts_are_executable_in_git():
    """`./scripts/wizard.sh` is the documented first command. Committed at 0644
    it fails on a fresh clone with 'Permission denied' — the mode has to live in
    git, not in whatever the author's filesystem happened to have."""
    import subprocess
    out = subprocess.run(["git", "ls-files", "-s", "--", "*.sh"],
                         cwd=REPO, capture_output=True, text=True).stdout
    if not out.strip():
        return  # not a git checkout (e.g. a source tarball)
    for line in out.strip().splitlines():
        mode, _, _, path = line.split(maxsplit=3)
        has_shebang = (REPO / path).read_bytes().startswith(b"#!")
        if has_shebang:
            assert mode == "100755", f"{path} has a shebang but is committed {mode}"


def test_no_shell_script_contains_a_stray_literal_backslash_n():
    r"""Twice now a scripted edit has written `\n` as two characters into a shell
    script instead of a real newline. In documentation that produced a command
    that would not run when pasted; in `install.sh` it put a spurious `n` into a
    `for` list. `bash -n` accepts both, so nothing catches it but this."""
    import re

    offenders = []
    for path in list((REPO / "deploy").rglob("*.sh")) + list((REPO / "scripts").rglob("*.sh")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            stripped = line.strip()
            # Text-producing commands legitimately contain \n, and so do comments.
            if stripped.startswith("#") or any(
                    k in line for k in ("printf", "echo", "sed ", "awk ", "grep ", "tr ")):
                continue
            for m in re.finditer(r"\n", line):
                # A trailing backslash is a line continuation, not this bug.
                if line.rstrip().endswith("\\") and m.end() >= len(line.rstrip()):
                    continue
                offenders.append(f"{path.relative_to(REPO)}:{lineno}")
    assert not offenders, f"literal \n in a shell script: {offenders}"


def test_the_nftables_ruleset_and_allowlist_are_persisted():
    """The table does not survive a reboot and nothing recreated it, so a host
    came back with no `inet sentinel` at all and every block failed silently for
    a day. The executor reloads these at startup."""
    install = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "libexec/sentinel-table.nft" in install
    assert "libexec/sentinel-allowlist.nft" in install


def test_the_blocklist_is_never_persisted():
    """"A reboot is always a way out of a self-inflicted block" is a guarantee
    this design makes and the operator has been told to rely on. Persisting the
    blocklist would quietly remove it."""
    install = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")
    block = install.split("libexec/sentinel-allowlist.nft", 1)[1].split("}", 1)[0]
    assert "blocklist" not in block.replace("blocklist are deliberately NOT", "")
    commands = (REPO / "executor" / "commands.py").read_text(encoding="utf-8")
    ensure = commands.split("def ensure_table", 1)[1].split("\ndef ", 1)[0]
    assert "blocklist" not in ensure or "NOT restored" in ensure
