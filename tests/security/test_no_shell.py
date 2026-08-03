"""Repo-wide invariants that a code review can miss.

These are cheap greps, and each one guards a property that is easy to break
accidentally and expensive to discover in production.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

REPO_ROOT = Path(__file__).resolve().parents[2]

PYTHON_DIRS = ("sentinel", "executor", ".claude/skills/sentinel-soc/scripts")


def python_files() -> list[Path]:
    files: list[Path] = []
    for directory in PYTHON_DIRS:
        files.extend((REPO_ROOT / directory).rglob("*.py"))
    return [f for f in files if "__pycache__" not in f.parts]


def code_only(path: Path) -> str:
    """The file's executable tokens, with comments and string literals removed.

    A plain grep cannot distinguish `subprocess.run(..., shell=True)` from a
    docstring explaining that shell=True is banned — and the modules most
    likely to explain the ban are exactly the ones that must not contain it.
    Tokenising makes the check mean what it says.
    """
    source = path.read_text(encoding="utf-8")
    pieces: list[str] = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            pieces.append(token.string)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return source  # unparseable: fall back to the raw text rather than pass
    return " ".join(pieces)


# ---------------------------------------------------------------------------
def test_no_shell_true_anywhere():
    """`shell=True` turns every argv allowlist in the codebase into decoration."""
    offenders = [
        str(f.relative_to(REPO_ROOT))
        for f in python_files()
        if re.search(r"shell\s*=\s*True", code_only(f))
    ]
    assert not offenders, f"shell=True found in: {offenders}"


def test_no_os_system():
    offenders = [
        str(f.relative_to(REPO_ROOT))
        for f in python_files()
        if re.search(r"\bos\s*\.\s*system\s*\(", code_only(f))
    ]
    assert not offenders, f"os.system() found in: {offenders}"


def test_no_eval_or_exec():
    pattern = re.compile(r"(?<![\w.])(eval|exec)\s*\(")
    offenders = [
        str(f.relative_to(REPO_ROOT))
        for f in python_files()
        if pattern.search(code_only(f))
    ]
    assert not offenders, f"eval()/exec() found in: {offenders}"


def test_no_hardcoded_secrets():
    """A committed key is a rotated key plus an incident. Catch it before push."""
    patterns = (
        re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),
        re.compile(r"\b\d{9,12}:AA[A-Za-z0-9_\-]{30,}\b"),   # Telegram bot token
        re.compile(r"(?i)(password|secret|api_key)\s*=\s*[\"'][^\"'{}<>$][^\"']{7,}[\"']"),
    )
    skip = {"test_no_shell.py"}   # this file contains the patterns themselves
    offenders: list[str] = []
    for f in python_files():
        if f.name in skip:
            continue
        text = f.read_text(encoding="utf-8")
        for pattern in patterns:
            if match := pattern.search(text):
                offenders.append(f"{f.relative_to(REPO_ROOT)}: {match.group()[:24]}...")
    assert not offenders, f"possible hardcoded secrets: {offenders}"


def test_shell_scripts_have_no_crlf():
    """A CRLF in a .sh or .service file fails on Linux as
    `bad interpreter: /bin/bash^M` — a confusing twenty minutes, and a real
    failure mode for a repo authored on Windows."""
    offenders: list[str] = []
    for pattern in ("**/*.sh", "**/*.service", "**/*.timer", "**/*.nft", "**/*.conf"):
        for f in REPO_ROOT.glob(pattern):
            if ".git" in f.parts or "node_modules" in f.parts:
                continue
            if b"\r\n" in f.read_bytes():
                offenders.append(str(f.relative_to(REPO_ROOT)))
    assert not offenders, f"CRLF line endings in: {offenders}"


def test_nftables_base_chain_is_policy_accept():
    """Sentinel is a deny-lister. `policy accept` is why it cannot lock anyone
    out by failing — only by explicitly blocking them. This single line removes
    most of the lockout risk in the design."""
    table = (REPO_ROOT / "deploy/nftables/sentinel-table.nft").read_text(encoding="utf-8")
    hooks = re.findall(r"type filter hook \w+ priority [^;]+;\s*policy (\w+)", table)
    assert hooks, "no base chains found in the nftables table"
    assert all(p == "accept" for p in hooks), f"a base chain is not policy accept: {hooks}"


def test_telegram_polling_allows_callback_queries():
    """Every inline button — block/unblock confirmations, /panic, the blocklist
    flush, the one-tap block on an alert — arrives as a callback_query. If
    long-polling's allowed_updates omits it, Telegram never delivers a single
    tap and every button silently does nothing. This is a regression guard for
    exactly that: allowed_updates=["message"] once shipped and broke all buttons.
    """
    svc = (REPO_ROOT / "sentinel/services/telegram_service.py").read_text(encoding="utf-8")
    m = re.search(r"allowed_updates\s*=\s*(\[[^\]]*\]|\w[\w.]*)", svc)
    assert m, "could not find allowed_updates in telegram_service.py"
    spec = m.group(1)
    assert "callback_query" in spec or "ALL_TYPES" in spec, (
        f"telegram polling must accept callback_query, got: {spec}")


def test_no_deployment_specific_addresses_are_hardcoded():
    """Sentinel must be installable on any host without editing its source.

    A public IP baked into the code or the shipped configs would be correct on
    exactly one deployment and silently wrong on every other — and invisible,
    because nobody reads a constants file looking for surprises. Site-specific
    addresses belong in `response.extra_allowlist` and `suricata.bpf_filter`,
    where the operator can see and change them.
    """
    skip_names = {"test_no_shell.py"}
    targets: list[Path] = [
        *python_files(),
        *(REPO_ROOT / "deploy").rglob("*.nft"),
        *(REPO_ROOT / "deploy").rglob("*.tmpl"),
        *(REPO_ROOT / "deploy").rglob("*.example"),
        *(REPO_ROOT / "deploy").rglob("*.conf"),
        *(REPO_ROOT / "deploy").rglob("*.rules"),
    ]

    offenders: list[str] = []
    for f in targets:
        if f.name in skip_names or "__pycache__" in f.parts:
            continue
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", f.read_text(encoding="utf-8")):
            octets = [int(o) for o in ip.split(".")]
            if any(o > 255 for o in octets):
                continue                                    # a version string, not an address
            if ip.startswith(("10.", "127.", "192.168.", "169.254.", "0.", "224.", "255.")):
                continue                                    # private, loopback, reserved
            if ip.startswith("172.") and 16 <= octets[1] <= 31:
                continue                                    # RFC1918
            if ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
                continue                                    # RFC 5737 documentation ranges
            offenders.append(f"{f.relative_to(REPO_ROOT)}: {ip}")

    assert not offenders, (
        "deployment-specific IP addresses are hard-coded: "
        f"{offenders}. Move them to response.extra_allowlist or suricata.bpf_filter."
    )


def test_auto_block_ships_disabled():
    """The first 72 hours are observe-only. Shipping this enabled is how you
    block your own uptime monitor at 3 a.m. on day one."""
    template = (REPO_ROOT / "deploy/config/sentinel.yaml.tmpl").read_text(encoding="utf-8")
    after = template.split("auto_block:", 1)[1]

    # The first non-comment `enabled:` after the key, wherever the explanatory
    # comment block ends. Anchoring on a character count would silently stop
    # checking anything the day someone extends the comment.
    setting = None
    for line in after.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("enabled:"):
            setting = stripped
            break
        if not line.startswith(("    ", "\t")):
            break   # left the auto_block block entirely

    assert setting == "enabled: false", \
        f"auto_block.enabled must ship as false, found: {setting!r}"


def test_dedicated_nginx_templates_do_not_hardcode_80_or_443():
    """In dedicated mode Sentinel must not claim the ports the host is for.

    A `listen 443` there would either collide with the existing service or
    displace it, and a monitoring agent that takes down what it monitors has
    inverted its purpose. The port comes from @@PUBLIC_PORT@@ instead.
    """
    for name in ("sentinel.conf.tmpl", "sentinel-default-deny.conf.tmpl"):
        template = (REPO_ROOT / "deploy/nginx" / name).read_text(encoding="utf-8")
        listens = re.findall(r"^\s*listen\s+([^;]+);", template, re.MULTILINE)
        assert listens, f"{name} has no listen directive"
        for directive in listens:
            assert "@@PUBLIC_PORT@@" in directive, (
                f"{name} has a hard-coded listen: {directive!r}. "
                "The port must come from @@PUBLIC_PORT@@."
            )


def test_shared_vhost_is_scoped_by_server_name_and_claims_no_default():
    """The shared vhost sits in a config directory full of the operator's sites.

    Two properties keep it from affecting them: every server block is selected by
    `server_name`, and none of them claims `default_server`. Claiming it would
    hijack which of THEIR vhosts answers a bare-IP request or an unknown Host —
    a behaviour change to their setup, not ours.
    """
    raw = (REPO_ROOT / "deploy/nginx/sentinel-shared.conf.tmpl").read_text(
        encoding="utf-8"
    )
    # Strip comments: the file *explains* why it declares no default_server, and
    # a naive substring check would trip over its own documentation.
    template = "\n".join(
        line for line in raw.splitlines() if not line.lstrip().startswith("#")
    )

    assert "default_server" not in template, (
        "the shared vhost claims default_server, which would hijack how the "
        "operator's own sites answer an unknown Host"
    )

    # Every server block must name itself. A block without server_name matches
    # by default-vhost fallback, which is the thing above.
    blocks = template.split("\nserver {")[1:]
    assert blocks, "no server blocks found"
    for i, block in enumerate(blocks):
        assert "server_name @@DOMAIN@@" in block, (
            f"server block {i} has no `server_name @@DOMAIN@@` — it would catch "
            "requests meant for other sites on this host"
        )

    # The point of shared mode: our own :80 block serves the ACME challenge, so
    # certificate issuance needs no change to anyone else's config.
    assert ".well-known/acme-challenge" in template
    assert re.search(r"^\s*listen\s+80;", template, re.MULTILINE), (
        "the shared vhost has no :80 block, so it cannot serve its own ACME "
        "challenge and certificates would need the operator to change their config"
    )


def test_shared_vhost_namespaces_its_rate_limit_zones():
    """A zone name colliding with one the operator already defined would make
    nginx refuse to load the whole configuration."""
    template = (REPO_ROOT / "deploy/nginx/sentinel-shared.conf.tmpl").read_text(
        encoding="utf-8"
    )
    zones = re.findall(r"zone=(\w+)", template) + re.findall(
        r"shared:(\w+):", template
    )
    assert zones, "no zones found"
    for zone in zones:
        assert zone.lower().startswith("sentinel"), (
            f"zone {zone!r} is not namespaced; it could collide with the "
            "operator's own configuration and break nginx for every site"
        )


def test_config_template_declares_the_public_port():
    template = (REPO_ROOT / "deploy/config/sentinel.yaml.tmpl").read_text(encoding="utf-8")
    assert "public_port: @@PUBLIC_PORT@@" in template


def _valid_config():
    """A config that passes validation, so a test can break exactly one thing.

    Telegram is disabled because `_validate` refuses an enabled bot with an empty
    chat-id allowlist — correct behaviour, but unrelated to what these tests are
    checking, and it would otherwise mask the real assertion.
    """
    from sentinel.config import Config

    cfg = Config()
    cfg.telegram.enabled = False
    return cfg


@pytest.mark.parametrize("port", [80, 443, 22])
def test_config_validation_refuses_reserved_ports(port):
    """Belt and braces: even a hand-edited config cannot take these."""
    from sentinel.config import _validate
    from sentinel.errors import ConfigError

    cfg = _valid_config()
    cfg.web.public_port = port
    with pytest.raises(ConfigError, match="reserved"):
        _validate(cfg)


def test_config_validation_refuses_colliding_ports():
    from sentinel.config import _validate
    from sentinel.errors import ConfigError

    cfg = _valid_config()
    cfg.web.public_port = cfg.web.port
    with pytest.raises(ConfigError, match="differ"):
        _validate(cfg)


def test_default_public_port_is_not_443():
    from sentinel.config import Config

    assert Config().web.public_port != 443
    assert Config().web.public_port not in (80, 22)


def test_default_nginx_mode_is_dedicated():
    """The default must be the one that touches nothing.

    `shared` writes into a config directory the operator's own sites live in.
    That is a reasonable choice, but it has to be chosen, not inherited.
    """
    from sentinel.config import Config

    assert Config().web.nginx_mode == "dedicated"


def test_shared_mode_permits_443():
    """In shared mode Sentinel binds nothing — the existing nginx already listens
    on 443 — so the port is a URL component, not a claim on the port."""
    from sentinel.config import _validate

    cfg = _valid_config()
    cfg.web.nginx_mode = "shared"
    cfg.web.public_port = 443
    _validate(cfg)   # must not raise


def test_shared_mode_still_refuses_to_bind_443_for_the_app():
    """The exemption is narrow: only `public_port`, never the app's own port."""
    from sentinel.config import _validate
    from sentinel.errors import ConfigError

    cfg = _valid_config()
    cfg.web.nginx_mode = "shared"
    cfg.web.public_port = 443
    cfg.web.port = 443
    with pytest.raises(ConfigError):
        _validate(cfg)


def test_shared_mode_rejects_a_nonstandard_public_port():
    """Shared mode means "a vhost on the existing nginx", which listens on 443.
    A high port there would silently not be served by anything."""
    from sentinel.config import _validate
    from sentinel.errors import ConfigError

    cfg = _valid_config()
    cfg.web.nginx_mode = "shared"
    cfg.web.public_port = 8443
    with pytest.raises(ConfigError, match="shared"):
        _validate(cfg)


def test_unknown_nginx_mode_is_refused():
    from sentinel.config import _validate
    from sentinel.errors import ConfigError

    cfg = _valid_config()
    cfg.web.nginx_mode = "whatever"
    with pytest.raises(ConfigError, match="nginx_mode"):
        _validate(cfg)


def test_secrets_example_contains_no_values():
    """The example file documents key names. A value in it is a leaked value."""
    example = (REPO_ROOT / "deploy/config/secrets.env.example").read_text(encoding="utf-8")
    for line in example.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        assert not value.strip(), f"{key} has a value in secrets.env.example"


def test_skill_frontmatter_is_present_and_descriptive():
    """Without a `description`, headless Claude never loads the skill, and the
    safety rules it carries silently do not apply."""
    skill = (REPO_ROOT / ".claude/skills/sentinel-soc/SKILL.md").read_text(encoding="utf-8")
    assert skill.startswith("---"), "SKILL.md must begin with YAML frontmatter"
    frontmatter = skill.split("---", 2)[1]
    assert re.search(r"^name:\s*sentinel-soc", frontmatter, re.MULTILINE)
    description = re.search(r"^description:\s*(.+)", frontmatter, re.MULTILINE | re.DOTALL)
    assert description and len(description.group(1)) > 120, \
        "the description drives skill selection; it must be specific"


def test_agent_definitions_have_required_frontmatter():
    for agent in (REPO_ROOT / ".claude/agents").glob("*.md"):
        text = agent.read_text(encoding="utf-8")
        assert text.startswith("---"), f"{agent.name} has no frontmatter"
        frontmatter = text.split("---", 2)[1]
        for field in ("name:", "description:", "tools:", "model:"):
            assert field in frontmatter, f"{agent.name} frontmatter is missing {field}"


# ---------------------------------------------------------------------------
# The PowerShell deploy script has to run on the shell Windows actually ships.
#
# Both of these failed in the field, and both fail at PARSE time — so the whole
# script dies before its first line runs, pointing at code the reader had no
# reason to suspect. Neither is caught by `pwsh -NoProfile -Command { ... }`,
# because pwsh IS 7.

def powershell_files() -> list[Path]:
    return list((REPO_ROOT / "scripts").rglob("*.ps1"))


def test_powershell_scripts_avoid_v7_only_syntax():
    """Stock Windows 10/11 ships Windows PowerShell 5.1. `pwsh` 7 is opt-in.

    A script that only parses on 7 defeats its own reason for existing: it is
    there so the operator does not have to install anything first.
    """
    v7_only = (
        (r"\)\?\.", "null-conditional `?.` — use an explicit if"),
        (r"\?\?", "null-coalescing `??` — use an explicit if"),
        (r'\$\(if\s*\(.*\{\s*"', 'a nested double-quoted string inside $(...) '
                                  "— 5.1's parser cannot do it; precompute a variable"),
        (r"-Parallel", "ForEach-Object -Parallel is 7+"),
        (r"\$PSStyle", "$PSStyle is 7+"),
        (r"-LeafBase", "Split-Path -LeafBase is 7+"),
    )
    offenders: list[str] = []
    for f in powershell_files():
        for number, line in enumerate(f.read_text(encoding="utf-8-sig").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue                      # a comment may name the construct
            for pattern, why in v7_only:
                if re.search(pattern, line):
                    offenders.append(f"{f.relative_to(REPO_ROOT)}:{number}: {why}")
    assert not offenders, "PowerShell 7-only syntax:\n  " + "\n  ".join(offenders)


def test_powershell_scripts_are_utf8_with_bom():
    """Windows PowerShell 5.1 decodes a BOM-less .ps1 as ANSI, not UTF-8.

    The script still runs, but every non-ASCII character in its output is
    mojibake — an em dash prints as `â€"`. The BOM is the only in-band way to
    tell 5.1 the file is UTF-8.
    """
    offenders = [
        str(f.relative_to(REPO_ROOT))
        for f in powershell_files()
        if not f.read_bytes().startswith(b"\xef\xbb\xbf")
        and any(b > 0x7F for b in f.read_bytes())
    ]
    assert not offenders, (
        f"non-ASCII .ps1 files without a UTF-8 BOM: {offenders}. "
        "PowerShell 5.1 will read them as ANSI."
    )


def _powershell_functions(text: str) -> list[tuple[str, str]]:
    """(name, body) for each `function X { ... }`, by brace depth.

    Crude, but it only has to handle the two scripts in this repo, and a real
    PowerShell parser is not available to pytest.
    """
    out: list[tuple[str, str]] = []
    for match in re.finditer(r"^function\s+([\w-]+)\s*\{", text, re.MULTILINE):
        depth, i = 0, match.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        out.append((match.group(1), text[match.end():i]))
    return out


def test_powershell_exit_code_helpers_do_not_leak_stdout():
    """`return $LASTEXITCODE` after an uncaptured native call returns an ARRAY.

    A PowerShell function returns everything written to its output stream, so a
    helper that runs `& ssh ...` and then returns the exit code hands back the
    remote command's stdout *and* the code. `(helper ...) -ne 0` then compares an
    array and is truthy whenever the remote command printed anything — the check
    inverts, and it inverts only on success, which is the worst possible way for
    it to be wrong. Route native output away from the pipeline, or do not return
    the code at all and let the caller read $LASTEXITCODE.
    """
    sinks = ("| Out-Null", "*>$null", "*> $null", "| Out-Host", "| Out-Default")
    offenders: list[str] = []
    for f in powershell_files():
        text = f.read_text(encoding="utf-8-sig")
        for name, body in _powershell_functions(text):
            if "return $LASTEXITCODE" not in body:
                continue
            for line in body.splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or not re.match(r"&\s*\$", stripped):
                    continue
                if not any(sink in stripped for sink in sinks):
                    offenders.append(f"{f.relative_to(REPO_ROOT)}: {name}(): {stripped}")
    assert not offenders, (
        "these helpers return $LASTEXITCODE but leave native stdout in the "
        "pipeline, so they return an array:\n  " + "\n  ".join(offenders)
    )


def test_admin_ip_flows_from_wrapper_to_installer():
    """The allowlisted admin address must survive the trip through sudo.

    sudo scrubs SSH_CLIENT, so the server cannot see where the operator connected
    from. The deploy wrappers read it over plain SSH and pass --admin-ip; lose any
    link in that chain and the allowlist ends up empty — which is precisely the
    state in which the first auto-block can lock the operator out.
    """
    checks = {
        "deploy/preflight.sh": "--admin-ip",     # accepts it
        "deploy/install.sh": "--admin-ip",       # accepts it
        "scripts/deploy.sh": "SSH_CONNECTION",   # captures it before sudo
        "scripts/deploy.ps1": "SSH_CONNECTION",  # captures it before sudo
    }
    missing = [
        rel for rel, token in checks.items()
        if token not in (REPO_ROOT / rel).read_text(encoding="utf-8-sig")
    ]
    assert not missing, f"admin-IP handling is missing from: {missing}"
    for rel in ("scripts/deploy.sh", "scripts/deploy.ps1"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8-sig")
        assert "--admin-ip" in text, f"{rel} captures the IP but never passes it on"


def test_no_leaking_return_traps_in_shell():
    """`trap '...' RETURN` inside a function is a foot-gun under `set -u`.

    Without `set -o functrace`, bash does not clear a function-scoped RETURN trap
    when that function returns — it fires again on the NEXT function return, where
    the local it referenced is gone, and `set -u` aborts with "unbound variable".
    Worse, it can delete a *different* function's local of the same name. Use
    explicit cleanup at the end of the function instead.
    """
    offenders: list[str] = []
    for f in (REPO_ROOT / "deploy").rglob("*.sh"):
        text = f.read_text(encoding="utf-8")
        if "functrace" in text:
            continue   # opts into local RETURN traps deliberately
        for number, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.search(r"trap.*RETURN", s):
                offenders.append(f"{f.relative_to(REPO_ROOT)}:{number}: {s}")
    assert not offenders, (
        "leaking RETURN traps (use explicit cleanup, or set -o functrace):\n  "
        + "\n  ".join(offenders)
    )


def test_every_template_placeholder_is_substituted_by_the_installer():
    """An @@PLACEHOLDER@@ the installer forgets to substitute ships literally.

    It then fails at the first thing that parses the file — here, a YAML load at
    the migrate step died on `public_port: @@PUBLIC_PORT@@`. Every @@X@@ token in
    a shipped template must have a matching `s|@@X@@|...|` in install.sh.
    """
    installer = (REPO_ROOT / "deploy/install.sh").read_text(encoding="utf-8")
    substituted = set(re.findall(r"s\|(@@[A-Z_]+@@)\|", installer))

    offenders: list[str] = []
    for tmpl in (REPO_ROOT / "deploy").rglob("*.tmpl"):
        for token in sorted(set(re.findall(r"@@[A-Z_]+@@", tmpl.read_text(encoding="utf-8")))):
            if token not in substituted:
                offenders.append(f"{tmpl.relative_to(REPO_ROOT)}: {token}")
    assert not offenders, (
        "template placeholders with no substitution in install.sh:\n  "
        + "\n  ".join(offenders)
    )


def test_nginx_templates_avoid_http2_on_directive():
    """`http2 on;` is nginx 1.25.1+. RHEL/AlmaLinux 9 ships nginx 1.20.1, which
    rejects it with `unknown directive "http2"` and fails `nginx -t` for the whole
    server. Enable HTTP/2 with the `listen ... http2` parameter instead, which
    works on 1.20 through current."""
    offenders: list[str] = []
    for tmpl in (REPO_ROOT / "deploy/nginx").glob("*.tmpl"):
        for number, line in enumerate(tmpl.read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.match(r"http2\s+on\s*;", s):
                offenders.append(f"{tmpl.name}:{number}")
    assert not offenders, (
        "`http2 on;` is 1.25.1+ and breaks nginx 1.20 (RHEL9). Use "
        f"`listen ... http2`: {offenders}"
    )


def test_comm_comparisons_force_c_collation():
    """`comm` checks sortedness with the locale's collation; a plain `sort` uses
    it too, but the two disagree on `@`, `-`, `.` in service names and on numeric
    vs lexical for ports. A baseline sorted in one run and compared in another
    then makes comm emit "not in sorted order" and garbage — read as "a service
    stopped", triggering a false rollback of a healthy install. Every comm over
    these lists must re-sort both sides with LC_ALL=C."""
    offenders: list[str] = []
    for f in (REPO_ROOT / "deploy").rglob("*.sh"):
        lines = f.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith("#") or "comm -" not in s:
                continue
            if "LC_ALL=C" not in s:
                offenders.append(f"{f.relative_to(REPO_ROOT)}:{number}: {s[:80]}")
    assert not offenders, (
        "comm without LC_ALL=C sort on both sides — collation mismatch causes "
        "false 'service stopped' rollbacks:\n  " + "\n  ".join(offenders)
    )
