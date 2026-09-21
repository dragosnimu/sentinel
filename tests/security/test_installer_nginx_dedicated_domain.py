"""Mod dedicat: pe :PUBLIC_PORT trebuie să existe un Host care ajunge la panou.

Măsurat pe gazda Ubuntu de producție, 18 septembrie 2026: două blocuri `server`
pe :8443, AMÂNDOUĂ cu `server_name _`, iar cel de refuz ținând `default_server`.
`_` nu e un wildcard — e un nume pe care niciun Host real nu-l egalează — deci
nimic nu potrivea vreunul dintre blocuri după nume, totul cădea pe
`default_server`, adică pe refuz, și fiecare cerere primea 444. În același timp
`systemctl is-active sentinel-web` spunea `active`, `ss -lntp` arăta nginx legat
pe port, iar instalatorul raporta succes la fiecare pas.

Ce previn testele de aici, în termeni de operator: **o configurație în care
fiecare cerere e refuzată trebuie să facă un test să pice.** Nu „vhost-ul are
numele X" — asta a fost prima reparație, și era tot o ghicire: `hostname -f` pe
gazda aia întoarce `n8n.cryptoitdata.eu`, iar operatorul ajunge la mașină prin
`n8n.srv1051579.hstgr.cloud`. Un vhost botezat după ghiceală nu rutează nimic,
blocul de refuz câștigă în continuare, iar operatorul primește tot 444 — aceeași
pană, produsă de reparația ei.

Așa că invariantul verificat aici e ACCESIBILITATEA, calculată din fișierele
chiar randate de funcția livrată:

    blocul care face `proxy_pass http://sentinel_app` e selectabil de nginx
    <=> are `default_server` pe portul lui, SAU are un `server_name` care e un
        nume adevărat (nu `_`)

Două configurații cinstite trec, a treia nu are cum:

  * cu `--domain`   — vhost după nume, blocul de refuz păstrează
                      `default_server` și închide orice alt Host;
  * fără `--domain` — vhost-ul E `default_server` și NU se instalează bloc de
                      refuz, deci portul răspunde la orice Host.

Restul fișierului verifică efectul, nu intenția: că verificarea de după reload
chiar cere `/healthz` și oprește pasul când nu ajunge nimic, că blocul de refuz
chiar refuză un Host necunoscut atunci când e configurat, și că ce mai stă între
operator și panou (ufw) se RE-măsoară la final și se tipărește ultimul.

Fiecare test rulează fragmentele LIVRATE din `deploy/install.sh` și șabloanele
din `deploy/nginx/`, nu o reimplementare a lor.
"""
from __future__ import annotations

import os
import re
import shutil
import stat as stat_module
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DEPLOY = REPO / "deploy"
INSTALL_SH = DEPLOY / "install.sh"
VHOST_TMPL = DEPLOY / "nginx" / "sentinel.conf.tmpl"
DENY_TMPL = DEPLOY / "nginx" / "sentinel-default-deny.conf.tmpl"
INSTALL = INSTALL_SH.read_text(encoding="utf-8")

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipsește din PATH — netestat, nu curat")]


# ---------------------------------------------------------------------------
# Decupaje din fișierul livrat
# ---------------------------------------------------------------------------
def _func(name: str, source: str = INSTALL) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{.*?^\}}", source, re.S | re.M)
    assert match, f"funcția {name} nu mai există în fișierul livrat"
    return match.group(0)


def _funcs(*names: str) -> str:
    return "\n".join(_func(n) for n in names) + "\n"


def _line(pattern: str) -> str:
    """O linie de la nivelul de sus al lui install.sh, luată ca atare.

    Copiată, nu rescrisă: dacă numele unei variabile globale se schimbă în
    instalator, testul merge după ea în loc să verifice o constantă moartă.
    """
    match = re.search(pattern, INSTALL, re.M)
    assert match, f"nu mai există în install.sh o linie care să potrivească {pattern!r}"
    return match.group(0)


def _p(path: Path) -> str:
    return str(path).replace("\\", "/")


def _write_stub(directory: Path, name: str, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat_module.S_IEXEC | stat_module.S_IXGRP | stat_module.S_IXOTH)
    return path


def _run(script: str, tmp_path: Path, extra_path: Path | None = None,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    harness = tmp_path / "harness.sh"
    harness.write_text(script, encoding="utf-8", newline="\n")
    environ = {**os.environ, "NO_COLOR": "1"}
    if extra_path is not None:
        environ["PATH"] = _p(extra_path) + os.pathsep + environ.get("PATH", "")
    if env:
        environ.update(env)
    return subprocess.run(
        [BASH, _p(harness)], cwd=DEPLOY, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=environ,
    )


_PREAMBLE = (
    "set -euo pipefail\n"
    "source ./lib/common.sh\n"
    # tls_dir vine din lib/distro.sh și întreabă gazda ce familie e; nimic din
    # ce se verifică aici nu depinde de răspuns.
    "tls_dir() { printf '%s' '/etc/ssl'; }\n"
    f'SCRIPT_DIR="{_p(DEPLOY)}"\n'
    'PUBLIC_PORT="8443"\n'
    'NGINX_MODE="dedicated"\n'
)


# ---------------------------------------------------------------------------
# Un parser minimal de blocuri `server`, cât să răspundă la o singură întrebare
# ---------------------------------------------------------------------------
class _ServerBlock:
    def __init__(self) -> None:
        self.listens: list[str] = []
        self.server_names: list[str] = []
        self.body: list[str] = []

    def ports(self) -> set[str]:
        out = set()
        for directive in self.listens:
            first = directive.split()[0]
            # `8443`, `[::]:8443`, `0.0.0.0:8443`
            out.add(first.rsplit(":", 1)[-1] if ":" in first else first)
        return out

    def is_default_for(self, port: str) -> bool:
        for directive in self.listens:
            first = directive.split()[0]
            this_port = first.rsplit(":", 1)[-1] if ":" in first else first
            if this_port == port and re.search(r"\bdefault_server\b", directive):
                return True
        return False

    def proxies_to_sentinel(self) -> bool:
        return any("proxy_pass http://sentinel_app" in line for line in self.body)

    def has_a_real_name(self) -> bool:
        return any(n != "_" for n in self.server_names)


def _without_comments(text: str) -> str:
    """Fișierul fără liniile de comentariu.

    Șabloanele își EXPLICĂ regulile în proză — `default_server`, `server_name
    _` și restul apar în comentarii. O aserțiune `in` pe textul brut ar potrivi
    explicația în locul directivei, deci ar rămâne verde (sau roșie) indiferent
    ce face fișierul. Exact tiparul care a trecut în repository-ul ăsta o dată.
    """
    return "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _server_blocks(text: str) -> list[_ServerBlock]:
    """Blocurile `server { ... }` de la nivelul de sus, fără comentarii."""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    blocks: list[_ServerBlock] = []
    depth = 0
    current: _ServerBlock | None = None
    for line in lines:
        stripped = line.strip()
        if current is None:
            if re.match(r"^server\s*\{", stripped):
                current = _ServerBlock()
                depth = stripped.count("{") - stripped.count("}")
            continue
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            blocks.append(current)
            current = None
            continue
        current.body.append(stripped)
        listen = re.match(r"^listen\s+([^;]+);", stripped)
        if listen:
            current.listens.append(listen.group(1).strip())
        name = re.match(r"^server_name\s+([^;]+);", stripped)
        if name:
            current.server_names.extend(name.group(1).split())
    assert current is None, "un bloc `server` a rămas deschis — parserul nu mai potrivește fișierul"
    return blocks


def _unreachability_reason(conf_dir: Path, port: str = "8443") -> str | None:
    """`None` dacă panoul e accesibil pe portul ăsta; altfel motivul, în text.

    Singura întrebare pusă: există vreun Host pentru care nginx selectează
    blocul care proxează spre Sentinel? Da, dacă blocul are `default_server`
    pe port (atunci îl prinde pe oricare) sau dacă are un `server_name` care e
    un nume adevărat (atunci îl prinde pe acela). `_` nu contează ca nume:
    nginx nu-l potrivește niciodată cu un Host real.
    """
    text = "\n".join(
        p.read_text(encoding="utf-8") for p in sorted(conf_dir.glob("*.conf")))
    blocks = [b for b in _server_blocks(text) if port in b.ports()]
    if not blocks:
        return f"niciun bloc server nu ascultă pe :{port}"
    app = [b for b in blocks if b.proxies_to_sentinel()]
    if not app:
        return f"niciun bloc de pe :{port} nu proxează spre sentinel_app"
    if len(app) > 1:
        return f"{len(app)} blocuri proxează spre sentinel_app pe :{port}"
    app_block = app[0]
    if app_block.has_a_real_name():
        return None
    if app_block.is_default_for(port):
        return None
    others = [b for b in blocks if b is not app_block and b.is_default_for(port)]
    return (
        f"blocul Sentinel de pe :{port} are server_name={app_block.server_names} "
        f"și nu e default_server, deci niciun Host nu-l selectează; "
        f"{len(others)} alt(e) bloc(uri) țin default_server pe port"
    )


def _render(tmp_path: Path, *, domain: str, foreign_default: str = "",
            preexisting_deny: bool = False) -> tuple[subprocess.CompletedProcess, Path]:
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir(parents=True, exist_ok=True)
    if preexisting_deny:
        # Ce e pe disc pe gazda din pană: blocul de refuz scris de o versiune
        # anterioară a instalatorului.
        (conf_dir / "sentinel-default-deny.conf").write_text(
            "server { listen 8443 ssl http2 default_server; server_name _; return 444; }\n",
            encoding="utf-8", newline="\n")
    proc = _run(
        _PREAMBLE
        + f'DOMAIN="{domain}"\n'
        + _funcs("render_dedicated_vhosts")
        + f'render_dedicated_vhosts "{_p(conf_dir)}" "{foreign_default}"\n',
        tmp_path)
    return proc, conf_dir


# ---------------------------------------------------------------------------
# Invariantul: nu există configurație randată în care totul e refuzat
# ---------------------------------------------------------------------------
def test_without_domain_every_host_reaches_the_dashboard(tmp_path):
    """PANA, direct. Fără `--domain`, randarea livrată trebuie să producă o
    configurație în care EXISTĂ un Host care ajunge la panou.

    Falsificat punând la loc perechea din pană — vhost cu `server_name _` fără
    `default_server` plus blocul de refuz cu `default_server` pe același port:
    verificatorul de accesibilitate întoarce motivul și testul pică.
    """
    proc, conf_dir = _render(tmp_path, domain="")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    reason = _unreachability_reason(conf_dir)
    assert reason is None, f"panoul e inaccesibil pe :8443 — {reason}"


def test_with_domain_the_dashboard_is_reachable_by_that_name(tmp_path):
    """Cealaltă configurație cinstită. Dacă `--domain` ar înceta să ajungă în
    `server_name`, vhost-ul ar rămâne fără nume iar blocul de refuz ar câștiga
    din nou — aceeași pană, pe cealaltă ramură."""
    proc, conf_dir = _render(tmp_path, domain="panou.example.test")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    reason = _unreachability_reason(conf_dir)
    assert reason is None, f"panoul e inaccesibil pe :8443 — {reason}"
    # Fără comentarii: șablonul își explică regula și pomenește `server_name`
    # de trei ori în proză. Astăzi niciuna dintre mențiuni nu are forma
    # `server_name <nume>;`, deci aserțiunile ar trece oricum — dar asta e
    # noroc, nu proiectare, și e chiar clasa de defect pe care fișierul ăsta
    # există ca s-o interzică.
    rendered = _without_comments((conf_dir / "sentinel.conf").read_text(encoding="utf-8"))
    assert re.search(r"^\s*server_name\s+panou\.example\.test;", rendered, re.M), rendered
    assert not re.search(r"^\s*server_name\s+_;", rendered, re.M), rendered


def test_the_parser_and_the_reachability_check_do_see_the_outage(tmp_path):
    """Testul testului. Un verificator de accesibilitate care întoarce mereu
    `None` ar face verde orice, inclusiv pana — exact felul în care în
    repository-ul ăsta au trecut teste care nu verificau nimic. Aici i se dă
    chiar perechea măsurată pe gazdă, scrisă de mână, și TREBUIE s-o refuze."""
    conf_dir = tmp_path / "pana"
    conf_dir.mkdir()
    (conf_dir / "sentinel-default-deny.conf").write_text(
        "server {\n    listen 8443 ssl http2 default_server;\n"
        "    listen [::]:8443 ssl http2 default_server;\n"
        "    server_name _;\n    return 444;\n}\n",
        encoding="utf-8", newline="\n")
    (conf_dir / "sentinel.conf").write_text(
        "server {\n    listen 8443 ssl http2;\n    listen [::]:8443 ssl http2;\n"
        "    server_name _;\n    location / {\n        proxy_pass http://sentinel_app;\n"
        "    }\n}\n",
        encoding="utf-8", newline="\n")
    reason = _unreachability_reason(conf_dir)
    assert reason is not None, \
        "verificatorul de accesibilitate a declarat accesibilă chiar configurația din pană"
    assert "niciun Host nu-l selectează" in reason, reason


# ---------------------------------------------------------------------------
# Cele două configurații, în detaliu
# ---------------------------------------------------------------------------
def test_without_domain_the_app_vhost_carries_default_server_on_both_families(tmp_path):
    """IPv4 ȘI IPv6. `default_server` e per-adresă-de-ascultare în nginx: dacă
    ar fi pus doar pe `listen 8443`, o cerere sosită pe `[::]:8443` ar cădea în
    continuare pe alt bloc — adică panoul ar merge de pe o familie și ar tăcea
    de pe cealaltă, ceea ce arată exact ca o pană intermitentă."""
    proc, conf_dir = _render(tmp_path, domain="")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rendered = (conf_dir / "sentinel.conf").read_text(encoding="utf-8")
    assert re.search(r"^\s*listen\s+8443\s+ssl\s+http2\s+default_server;", rendered, re.M), rendered
    assert re.search(r"^\s*listen\s+\[::\]:8443\s+ssl\s+http2\s+default_server;", rendered, re.M), rendered


def test_without_domain_no_deny_block_is_left_on_disk(tmp_path):
    """Gazda din pană ARE fișierul de refuz pe disc, scris de o versiune
    anterioară. Un re-deploy care doar se abține să-l mai scrie lasă 444 exact
    unde era, și instalarea raportează din nou succes. Trebuie ȘTERS.

    Falsificat scoțând `rm -f "$deny_conf"` de pe ramura fără domeniu — testul
    trebuie să găsească fișierul rămas.
    """
    proc, conf_dir = _render(tmp_path, domain="", preexisting_deny=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (conf_dir / "sentinel-default-deny.conf").exists(), \
        "blocul de refuz de la instalarea anterioară a rămas pe disc — 444 rămâne cu el"
    assert _unreachability_reason(conf_dir) is None


def test_without_domain_the_weaker_posture_is_said_out_loud(tmp_path):
    """Operatorul trebuie să afle, la instalare, că portul răspunde la orice
    Host — inclusiv la un scan pe IP gol. O postură mai slabă aleasă în tăcere
    e o postură pe care nimeni n-o poate corecta."""
    proc, _ = _render(tmp_path, domain="")
    out = proc.stdout + proc.stderr
    assert "ANY Host" in out, out
    assert "--domain" in out, out


def test_with_domain_the_deny_block_is_installed_and_holds_default_server(tmp_path):
    """Cu `--domain` postura tare rămâne postura tare: un scan pe :8443 nu
    trebuie să afle că există un panou de securitate aici. Dacă blocul de refuz
    ar dispărea odată cu reparația, reparația ar fi plătit accesibilitatea cu
    expunerea paginii de login."""
    proc, conf_dir = _render(tmp_path, domain="panou.example.test")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    deny = conf_dir / "sentinel-default-deny.conf"
    assert deny.exists(), "blocul catch-all de refuz nu s-a mai instalat cu --domain"
    # Fără comentarii, și pe DIRECTIVE, nu pe substring. Șablonul își explică
    # regula în proză: `default_server` apare la liniile 6 și 17 ale
    # comentariului, deci un `"default_server" in text` nu putea pica NICIODATĂ
    # — dovedit pe 18 sep 2026, cu `default_server` scos din amândouă liniile
    # `listen` și toate testele fișierului ăstuia rămase verzi.
    text = _without_comments(deny.read_text(encoding="utf-8"))
    assert re.search(r"^\s*server_name\s+_;\s*$", text, re.M), text
    assert len(re.findall(r"^\s*listen\s+.*\bdefault_server;", text, re.M)) == 2, \
        f"blocul de refuz nu mai revendică default_server pe amândouă familiile:\n{text}"
    assert re.search(r"^\s*return\s+444;", text, re.M), text
    # Și vhost-ul aplicației NU are voie să-l revendice și el: două
    # `default_server` pe același port e o configurație pe care nginx o refuză.
    # Fără comentarii: fișierul își EXPLICĂ regula, iar un `in` pe text brut ar
    # potrivi explicația și ar rămâne roșu pentru totdeauna.
    app = _without_comments((conf_dir / "sentinel.conf").read_text(encoding="utf-8"))
    assert "default_server" not in app, app


def test_the_deny_template_still_uses_the_literal_underscore():
    """Blocul de refuz NU se schimbă — el rămâne `_` cu `default_server`, ca să
    oprească accesul pe IP gol atunci când există un domeniu. Dacă ar căpăta și
    el numele randat, un scan pe adresa goală ar ajunge iar la pagina de
    login.

    Pe DIRECTIVE, nu pe substring, din același motiv ca mai sus: `_` și
    `default_server` apar amândouă în comentariul șablonului, care își explică
    regula. Un `in` pe textul brut e o aserțiune care nu poate pica.
    """
    text = _without_comments(DENY_TMPL.read_text(encoding="utf-8"))
    assert re.search(r"^\s*server_name\s+_;\s*$", text, re.M), \
        "sentinel-default-deny.conf.tmpl nu mai declară server_name _"
    assert len(re.findall(r"^\s*listen\s+.*\bdefault_server;", text, re.M)) == 2, \
        f"șablonul de refuz nu mai revendică default_server pe amândouă familiile:\n{text}"


def test_the_vhost_template_still_takes_its_name_and_its_default_from_markers():
    """Amândouă deciziile trebuie să vină din randare, nu din șablon. Un
    `server_name _` sau un `default_server` scris cu mâna în șablon ar face una
    dintre cele două configurații imposibilă, tăcut."""
    text = VHOST_TMPL.read_text(encoding="utf-8")
    directives = "\n".join(
        ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
    assert "server_name @@DOMAIN@@;" in directives, directives
    assert re.search(r"^\s*listen\s+@@PUBLIC_PORT@@\s+ssl\s+http2@@DEFAULT_SERVER@@;",
                     directives, re.M), directives
    assert re.search(r"^\s*listen\s+\[::\]:@@PUBLIC_PORT@@\s+ssl\s+http2@@DEFAULT_SERVER@@;",
                     directives, re.M), directives
    assert "server_name _;" not in directives, directives


# ---------------------------------------------------------------------------
# Coliziunea cu un default_server străin
# ---------------------------------------------------------------------------
def test_without_domain_a_foreign_default_server_stops_the_step(tmp_path):
    """Două `default_server` pe același port nu e o postură mai slabă, e un
    `nginx -t` care refuză ÎNTREAGA configurație — inclusiv siturile
    operatorului. Pasul trebuie să se oprească înainte să scrie ceva, cu cele
    două ieșiri spuse explicit."""
    proc, conf_dir = _render(tmp_path, domain="",
                             foreign_default="/etc/nginx/conf.d/altceva.conf")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "altceva.conf" in out, out
    assert "--domain" in out, out
    assert not (conf_dir / "sentinel.conf").exists(), \
        "a scris vhost-ul înainte să constate coliziunea"


def test_with_domain_a_foreign_default_server_only_skips_the_deny(tmp_path):
    """Cu `--domain`, un `default_server` străin nu e o coliziune: vhost-ul
    nostru e ales după nume. Se sare doar catch-all-ul, ca să nu i se strice
    blocul, iar panoul rămâne accesibil — dacă pasul ar muri și aici, o gazdă
    perfect funcțională n-ar mai putea fi instalată."""
    proc, conf_dir = _render(tmp_path, domain="panou.example.test",
                             foreign_default="/etc/nginx/conf.d/altceva.conf",
                             preexisting_deny=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (conf_dir / "sentinel-default-deny.conf").exists(), \
        "catch-all-ul nostru a rămas peste default_server-ul altcuiva"
    assert _unreachability_reason(conf_dir) is None
    assert "already declares default_server" in (proc.stdout + proc.stderr)


# ---------------------------------------------------------------------------
# Verificarea de după reload — cere efectiv, nu presupune
# ---------------------------------------------------------------------------
_CURL_STUB = (
    'args="$*"\n'
    'if [[ "$args" == *--resolve* ]]; then printf "%s" "${LOOP_CODE-}"; exit "${LOOP_RC:-0}"; fi\n'
    'if [[ "$args" == *"Host: "* ]]; then printf "%s" "${UNKNOWN_CODE-}"; exit "${UNKNOWN_RC:-0}"; fi\n'
    'printf "%s" "${NAME_CODE-}"; exit "${NAME_RC:-0}"\n'
)


def _run_verify(tmp_path: Path, *, domain: str, getent: str | None = None,
                **codes: str) -> subprocess.CompletedProcess:
    stubs = tmp_path / "bin"
    _write_stub(stubs, "curl", _CURL_STUB)
    _write_stub(stubs, "ip", 'printf "1: eth0    inet 203.0.113.9/24 scope global eth0\\n"\n')
    if getent is not None:
        _write_stub(stubs, "getent", getent)
    script = (
        _PREAMBLE
        + f'DOMAIN="{domain}"\n'
        + _line(r"^PENDING_OBSTACLES=\(\)$") + "\n"
        + _line(r"^CLOSING_NOTES=\(\)$") + "\n"
        + _line(r"^obstacle\(\).*$") + "\n"
        + _line(r"^closing_note\(\).*$") + "\n"
        + _line(r"^SENTINEL_ANSWERED=.*$") + "\n"
        + _funcs("https_code", "name_resolution_note", "verify_dashboard_answers")
        + "verify_dashboard_answers\n"
        + 'echo "PASSED_CHECK"\n'
        + 'if (( ${#PENDING_OBSTACLES[@]} )); then\n'
        + '    printf "OBSTACLE: %s\\n" "${PENDING_OBSTACLES[@]}"\n'
        + "fi\n"
    )
    return _run(script, tmp_path, extra_path=stubs, env={k: v for k, v in codes.items()})


def _fatal_text(proc: subprocess.CompletedProcess) -> str:
    """Textul lui `die`, nu orice text.

    Un `warn` și un `die` spun aceleași cuvinte; deosebirea e că unul oprește
    pasul. Un `assert "…" in stdout+stderr` nu le distinge — și atunci un `die`
    degradat în `warn` trece neobservat, fiindcă o eroare de mai jos omoară
    oricum scriptul și mesajul degradat e tot pe ecran. Aserțiunile se fac pe
    ce a spus CHIAR verdictul fatal.
    """
    out = proc.stdout + proc.stderr
    idx = out.find("[FATAL]")
    return out[idx:] if idx >= 0 else ""


def test_no_domain_a_refused_unknown_host_stops_the_step(tmp_path):
    """PANA, măsurată prin verificare. Fără `--domain` singurul fel de cerere
    care există e una cu un Host pe care gazda nu-l cunoaște. Dacă aia primește
    444, panoul e inaccesibil oricum ar naviga operatorul — iar instalarea NU
    are voie să se termine cu „Instalare completă".

    Falsificat schimbând `die` în `warn` pe ramura asta: verdictul fatal ajunge
    să fie al altei ramuri, iar testul pică pe conținutul lui.
    """
    proc = _run_verify(tmp_path, domain="", UNKNOWN_CODE="444")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" not in proc.stdout, proc.stdout
    fatal = _fatal_text(proc)
    assert "the only kind of request there is" in fatal, \
        f"pasul s-a oprit, dar nu din cauza Host-ului necunoscut: {fatal!r}"
    assert "444" in fatal, fatal


def test_no_domain_a_dead_connection_stops_the_step(tmp_path):
    """`000` — curl nu s-a putut conecta deloc — se tratează la fel de strict ca
    `444`, nu ca „nu știu, dau ok"."""
    proc = _run_verify(tmp_path, domain="", UNKNOWN_CODE="")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" not in proc.stdout, proc.stdout
    fatal = _fatal_text(proc)
    assert "the only kind of request there is" in fatal, fatal
    assert "000" in fatal, fatal


def test_a_probe_that_exits_nonzero_cannot_abort_the_installer(tmp_path):
    """Cazul confirmat: pe un port închis `curl` iese cu rc=7 fără să scrie
    nimic. Sub `set -euo pipefail`, un `code="$(curl …)"` scris DIRECT în pasul
    care decide abandonează asignarea, deci scriptul moare ACOLO, fără niciun
    mesaj despre ce s-a întâmplat — instalarea se oprește fără verdict.

    De asta sondarea stă într-o funcție proprie (`https_code`): eșecul ei nu
    poate lua cu el pasul care o cheamă.

    Falsificat inlinuind `curl` înapoi în `verify_dashboard_answers` (mutația
    M11b): scriptul moare înainte de verdict și testul nu mai găsește textul
    fatal.
    """
    proc = _run_verify(tmp_path, domain="", UNKNOWN_CODE="", UNKNOWN_RC="7")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" not in proc.stdout, proc.stdout
    assert "the only kind of request there is" in _fatal_text(proc), \
        f"pasul a murit fără verdict: {(proc.stdout + proc.stderr)!r}"


def test_the_code_curl_printed_before_failing_is_the_one_reported(tmp_path):
    """Cazul confirmat pe gazda Ubuntu, 8 sep 2026: nginx răspunde 444, dar
    peste HTTP/2 `curl` scrie codul cu `-w` ÎNAINTE să iasă cu o eroare de
    cadrare (rc=92). `|| true` în interiorul substituției e ce face ca „444" —
    codul pe care curl chiar l-a măsurat — să ajungă în mesaj. Fără el,
    subshell-ul moare înainte de `printf`, apelantul primește șir gol, iar
    operatorul citește „000": „n-am putut deschide conexiunea" în loc de
    „serverul a închis-o fără răspuns". Două cauze diferite, două remedii
    diferite.

    Falsificat inlinuind `curl` înapoi în pas (mutația M11b): substituția moare
    sub `set -e` înainte să apuce cineva să citească ce a scris curl.

    NU e falsificat de scoaterea lui `|| true` din `https_code` — verificat pe
    18 sep 2026, rămâne verde. Motivul e în comentariul funcției: curl rulează
    deja în subshell-ul lui `$( … )`, iar bash nu dă `errexit` acolo fără
    `inherit_errexit`, care nu e pus nicăieri în arborele ăsta. `|| true` e o
    a doua plasă, nu plasa.
    """
    proc = _run_verify(tmp_path, domain="", UNKNOWN_CODE="444", UNKNOWN_RC="92")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    fatal = _fatal_text(proc)
    assert "the only kind of request there is" in fatal, fatal
    assert "answered 444" in fatal, \
        f"codul pe care curl l-a măsurat s-a pierdut pe drum: {fatal!r}"


def test_no_domain_an_answering_dashboard_lets_the_step_continue(tmp_path):
    """Cazul pozitiv. Dacă verificarea ar opri pasul mereu, testele de mai sus
    n-ar dovedi nimic despre discriminare."""
    proc = _run_verify(tmp_path, domain="", UNKNOWN_CODE="200")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" in proc.stdout, proc.stdout


def test_with_domain_the_loopback_probe_is_what_decides(tmp_path):
    """Cu `--domain`, dovada că instalatorul răspunde de ea e că nginx-ul
    ACESTEI gazde servește numele. Dacă ăla dă 444, panoul e o conexiune închisă
    pentru orice vizitator, oricât de bine ar arăta DNS-ul.

    Falsificat schimbând `die` în `warn` pe ramura loopback: verdictul fatal
    ajunge să fie al altei ramuri, și testul pică pe conținutul lui.
    """
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       NAME_CODE="200", LOOP_CODE="444", UNKNOWN_CODE="444")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" not in proc.stdout, proc.stdout
    # Nu `"127.0.0.1" in out`: adresa apare în mai multe mesaje, deci ORICE
    # moarte a scriptului ar fi trecut drept moartea ASTA.
    fatal = _fatal_text(proc)
    assert "name pinned to 127.0.0.1" in fatal, \
        f"pasul s-a oprit, dar nu pe sonda de loopback: {fatal!r}"
    assert "answered 444" in fatal, fatal


def test_a_name_answered_by_someone_else_is_not_taken_as_proof(tmp_path):
    """Exact tiparul din CLAUDE.md, pe cealaltă față: un `200` la
    `https://<domeniu>/healthz` rezolvat normal NU dovedește că a răspuns
    nginx-ul nostru — numele poate arăta spre cu totul altă mașină, care are și
    ea un `/healthz`. Testul de mai sus dă 200 pe calea normală și 444 pe
    loopback, și pasul TREBUIE să moară: cele două sunt fapte diferite, iar
    singurul pe care îl controlează instalatorul e al doilea.
    """
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       NAME_CODE="200", LOOP_CODE="000", UNKNOWN_CODE="444")
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" not in proc.stdout, proc.stdout
    # Care moarte: cea de pe sonda pinată, nu oricare. Fără asta, un `die`
    # nimerit oriunde altundeva ar fi satisfăcut testul.
    assert "name pinned to 127.0.0.1" in _fatal_text(proc), _fatal_text(proc)


def test_with_domain_a_name_that_does_not_arrive_weakens_the_check_out_loud(tmp_path):
    """nginx rutează corect, dar numele nu ajunge de aici (DNS, sau un filtru
    pe drum). Nu e `die` — configurația scrisă e bună. Dar verificarea care
    rămâne e pinată pe loopback, deci e mai slabă, și asta trebuie SPUS, plus
    înregistrat pentru rezumatul final. O verificare slăbită în tăcere e
    verificarea care a raportat verde peste pana asta.

    Falsificat scoțând `warn`-ul „THE ROUTING CHECK WAS WEAKENED": testul nu
    mai găsește nici anunțul, nici obstacolul.
    """
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       getent='exit 1\n',
                       NAME_CODE="000", LOOP_CODE="200", UNKNOWN_CODE="444")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASSED_CHECK" in proc.stdout, proc.stdout
    out = proc.stdout + proc.stderr
    assert "WEAKENED" in out, out
    assert "does not resolve on this host at all" in out, out
    assert "OBSTACLE:" in proc.stdout, proc.stdout


def test_a_missing_getent_is_reported_as_unknown_not_as_a_clean_name(tmp_path):
    """CLAUDE.md: „nu pot verifica" ≠ „e curat". Fără `getent` pe PATH, motivul
    pentru care numele nu răspunde e NECUNOSCUT, și se spune ca atare în loc să
    se tacă."""
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       NAME_CODE="000", LOOP_CODE="200", UNKNOWN_CODE="444")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    # Fraza întreagă, nu cuvântul: „UNKNOWN" singur ar fi putut veni din orice
    # alt mesaj al pasului.
    assert "resolves at all is UNKNOWN" in out, out


def test_with_domain_the_deny_block_is_proven_to_refuse_not_assumed(tmp_path):
    """Întărirea promisă se măsoară. Dacă un Host necunoscut primește un
    răspuns, catch-all-ul NU refuză, iar un scan pe adresa asta află că aici e
    ceva — exact ce blocul de refuz există ca să prevină. Avertisment, nu `die`:
    panoul merge, postura e mai slabă decât i s-a spus operatorului.

    Falsificat scoțând ramura `*)` din `case`-ul de întărire — testul nu mai
    găsește avertismentul.
    """
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       NAME_CODE="200", LOOP_CODE="200", UNKNOWN_CODE="200")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "catch-all deny" in out and "NOT refusing" in out, out


def test_with_domain_a_refused_unknown_host_is_reported_as_the_hardening_holding(tmp_path):
    """Cazul pozitiv al întăririi: dacă avertismentul de mai sus ar apărea
    mereu, n-ar dovedi nimic despre discriminare."""
    proc = _run_verify(tmp_path, domain="panou.example.test",
                       NAME_CODE="200", LOOP_CODE="200", UNKNOWN_CODE="444")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "no response at all" in out, out
    assert "NOT refusing" not in out, out


def test_the_step_calls_the_verification_after_the_reload(tmp_path):
    """Dovada trebuie cerută DUPĂ ce configurația e în vigoare. Chemată
    înainte de `reload_nginx`, ar măsura configurația precedentă și ar trece
    verde peste exact pana asta."""
    # Fără comentarii: funcțiile din fișierul ăsta își EXPLICĂ deciziile, și un
    # `in` pe text brut potrivește proza. Testul de dedesubt a trecut exact așa
    # o dată — aserțiune pe prezența unui nume, nu pe apelul lui.
    body = _without_comments(_func("step_nginx"))
    assert "verify_dashboard_answers" in body, \
        "step_nginx nu mai cere nicio dovadă că panoul răspunde"
    assert body.index("reload_nginx") < body.index("verify_dashboard_answers"), \
        "verificarea rulează înainte de reload, deci măsoară configurația veche"


# ---------------------------------------------------------------------------
# Rezumatul final: ce mai stă între operator și panou
# ---------------------------------------------------------------------------
def _run_closing(tmp_path: Path, *, domain: str, ufw: str | None,
                 nginx_mode: str = "dedicated",
                 allow_ufw: str = "0") -> subprocess.CompletedProcess:
    stubs = tmp_path / "bin"
    marker = tmp_path / "ufw-was-asked"
    if ufw is not None:
        _write_stub(stubs, "ufw", f': > "{_p(marker)}"\n' + ufw)
    else:
        stubs.mkdir(parents=True, exist_ok=True)
    script = (
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'DOMAIN="{domain}"\n'
        f'NGINX_MODE="{nginx_mode}"\n'
        f'ALLOW_UFW="{allow_ufw}"\n'
        'PUBLIC_PORT="8443"\n'
        + _line(r"^PENDING_OBSTACLES=\(\)$") + "\n"
        + _line(r"^CLOSING_NOTES=\(\)$") + "\n"
        + _line(r"^obstacle\(\).*$") + "\n"
        + _line(r"^closing_note\(\).*$") + "\n"
        + _funcs("ufw_blocks_public_port", "report_closing_facts")
        + "report_closing_facts\n"
        + 'echo "END_OF_RUN"\n'
    )
    proc = _run(script, tmp_path, extra_path=stubs)
    proc.ufw_was_asked = marker.exists()   # type: ignore[attr-defined]
    return proc


_UFW_ACTIVE_CLOSED = (
    'printf "Status: active\\nDefault: deny (incoming), allow (outgoing), disabled (routed)\\n'
    'To                         Action      From\\n22/tcp                     ALLOW       Anywhere\\n'
    '5432/tcp                   ALLOW       Anywhere\\n"\n'
)
_UFW_ACTIVE_OPEN = (
    'printf "Status: active\\nDefault: deny (incoming), allow (outgoing), disabled (routed)\\n'
    'To                         Action      From\\n22/tcp                     ALLOW       Anywhere\\n'
    '8443/tcp                   ALLOW       Anywhere\\n"\n'
)


def test_a_closed_ufw_port_is_the_last_thing_on_screen_with_the_exact_command(tmp_path):
    """Defectul de raportare, direct. `preflight.sh` spune deja adevărul despre
    ufw — la minutul doi al unei instalări de un sfert de oră, după care rularea
    se termină cu „Instalare completă". Operatorul citește ultimul lucru de pe
    ecran și pleacă spre un panou care nu răspunde.

    Falsificat scoțând apelul `obstacle` de pe ramura 0 a lui `case`: rezumatul
    se termină fără nimic, exact ca înainte.
    """
    proc = _run_closing(tmp_path, domain="panou.example.test", ufw=_UFW_ACTIVE_CLOSED)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "CE MAI STĂ ÎNTRE TINE ȘI PANOU" in out, out
    assert "sudo ufw allow 8443/tcp" in out, out
    assert out.index("END_OF_RUN") > out.index("sudo ufw allow 8443/tcp"), \
        "rezumatul nu e ultimul lucru tipărit"


def test_ufw_is_re_measured_at_the_end_not_replayed_from_preflight(tmp_path):
    """Între preflight și bară trec sferturi de oră, iar operatorului i s-a spus
    la minutul doi să deschidă portul. Dacă a făcut-o între timp, a-i repeta
    instrucțiunea e o minciună mică fix acolo unde tocmai am promis adevărul.

    Două aserțiuni, fiindcă fiecare prinde altceva: că `ufw` chiar e INTEROGAT
    la final (marcajul), și că răspunsul lui de ACUM e cel folosit (fără
    obstacol).
    """
    proc = _run_closing(tmp_path, domain="panou.example.test", ufw=_UFW_ACTIVE_OPEN)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.ufw_was_asked, "ufw n-a fost întrebat la final — decizia e reluată, nu măsurată"
    assert "sudo ufw allow" not in proc.stdout, proc.stdout
    assert "CE MAI STĂ ÎNTRE TINE ȘI PANOU" not in proc.stdout, proc.stdout


def test_an_unreadable_ufw_is_unknown_not_fine(tmp_path):
    """`ufw status` cere root. Dacă nu se poate citi, dacă portul e deschis e
    NECUNOSCUT — iar o unealtă care colapsează „nu știu" în „e bine" e o unealtă
    care minte."""
    proc = _run_closing(tmp_path, domain="panou.example.test", ufw='exit 1\n')
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "NECUNOSCUT" in proc.stdout, proc.stdout
    assert "sudo ufw status verbose" in proc.stdout, proc.stdout


def test_no_ufw_on_the_host_raises_nothing(tmp_path):
    """Producția e AlmaLinux, unde ufw nici nu există. Un obstacol inventat
    acolo ar învăța operatorul să sară peste secțiunea asta — și atunci n-ar mai
    citi-o nici pe gazda unde chiar contează."""
    proc = _run_closing(tmp_path, domain="panou.example.test", ufw=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CE MAI STĂ ÎNTRE TINE ȘI PANOU" not in proc.stdout, proc.stdout


def test_shared_mode_is_not_told_to_open_a_port_it_does_not_bind(tmp_path):
    """În mod `shared` Sentinel nu deschide niciun port propriu: răspunde pe
    80/443, pe care ufw le lasă deja să intre, altfel siturile operatorului ar
    fi căzute. `sudo ufw allow 8443/tcp` acolo ar fi un sfat care deschide un
    port degeaba."""
    proc = _run_closing(tmp_path, domain="panou.example.test",
                        ufw=_UFW_ACTIVE_CLOSED, nginx_mode="shared")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "sudo ufw allow" not in proc.stdout, proc.stdout


def test_the_any_host_posture_is_repeated_in_the_closing_summary(tmp_path):
    """Spus o dată la pasul 33, pierdut în mijlocul unei instalări lungi. Postura
    cu care rămâne gazda trebuie să fie și ultimul lucru pe care îl vede
    operatorul, împreună cu steagul care o îngustează."""
    proc = _run_closing(tmp_path, domain="", ufw=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "DE ȘTIUT" in out, out
    assert "ORICE Host" in out, out
    assert "--domain" in out, out


def test_with_a_domain_the_any_host_note_is_absent(tmp_path):
    """Cazul negativ: dacă nota ar apărea mereu, n-ar spune nimic despre
    configurația chiar instalată."""
    proc = _run_closing(tmp_path, domain="panou.example.test", ufw=None)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ORICE Host" not in proc.stdout, proc.stdout


def test_main_prints_the_closing_facts_after_the_banner():
    """Ordinea E conținutul aici. Chemat înaintea barei, rezumatul ar fi din nou
    ceva ce derulează, iar ultimul lucru de pe ecran ar fi „Instalare
    completă"."""
    # Fără comentarii, și nu e o precauție teoretică: `main` MENȚIONEAZĂ
    # `report_closing_facts` în comentariul de lângă calculul lui banner_host.
    # Cu textul brut, aserțiunea de mai jos a trecut cu apelul șters — exact
    # „aserțiune pe prezența unui nume în loc de pe decizia luată din el".
    body = _without_comments(_func("main"))
    assert "report_closing_facts" in body, "main nu mai tipărește rezumatul de final"
    assert body.index('section "Instalare completă"') < body.index("report_closing_facts"), \
        "rezumatul se tipărește înaintea barei finale, deci tot derulează"


# ---------------------------------------------------------------------------
# URL-ul din bară
# ---------------------------------------------------------------------------
def _banner_host_snippet() -> str:
    """Calculul lui `banner_host` din `main`, exact octeții livrați."""
    body = _func("main")
    start = body.index("    local banner_host")
    end = body.index("\n    fi\n", start) + len("\n    fi\n")
    return body[start:end]


def _run_banner_host(tmp_path: Path, *, domain: str, ip_body: str) -> str:
    stubs = tmp_path / "bin"
    _write_stub(stubs, "ip", ip_body)
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        f'DOMAIN="{domain}"\n'
        "compute() {\n"
        + _banner_host_snippet()
        + '    printf "%s" "$banner_host"\n'
        + "}\n"
        "compute\n",
        tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


def test_without_a_domain_the_banner_prints_an_address_not_a_guessed_name(tmp_path):
    """Ghicirea numelui e chiar cauza penei, și bara era locul unde se vedea:
    `hostname -f` pe gazda de producție întoarce `n8n.cryptoitdata.eu`, iar
    operatorul ajunge la mașină prin alt nume. Fără `--domain` vhost-ul răspunde
    la orice Host, deci o adresă a gazdei e singurul URL care chiar se deschide.

    Falsificat revenind la `banner_host="${DOMAIN:-$(hostname -f …)}"` — testul
    primește un nume de gazdă în loc de adresă.
    """
    host = _run_banner_host(
        tmp_path, domain="",
        ip_body='printf "1: eth0    inet 203.0.113.9/24 scope global eth0\\n"\n')
    assert host == "203.0.113.9", host


def test_with_a_domain_the_banner_prints_the_domain(tmp_path):
    """Cazul pozitiv: cu `--domain`, numele din bară e chiar numele pe care
    vhost-ul îl servește și pe care verificarea /healthz l-a cerut efectiv."""
    host = _run_banner_host(
        tmp_path, domain="panou.example.test",
        ip_body='printf "1: eth0    inet 203.0.113.9/24 scope global eth0\\n"\n')
    assert host == "panou.example.test", host


def test_a_host_with_no_global_address_still_gets_a_banner(tmp_path):
    """O gazdă fără nicio adresă globală (doar NAT, doar IPv6 link-local) nu are
    ce adresă să primească. Bara trebuie să tipărească totuși ceva, nu un URL cu
    gaură în el — `https://:8443` e mai rău decât un nume aproximativ."""
    host = _run_banner_host(tmp_path, domain="", ip_body='printf ""\n')
    assert host, "bara a rămas fără gazdă deloc"
    assert ":" not in host, host


# ---------------------------------------------------------------------------
# --allow-ufw: un port inchis din decizie nu e un obstacol
# ---------------------------------------------------------------------------
def test_allow_ufw_turns_the_blocked_port_into_a_note_not_an_instruction(tmp_path):
    """Sfat gresit, dat ultimul, peste o decizie pe care operatorul tocmai a
    luat-o. `--allow-ufw` inseamna "las portul inchis, stiu ce fac" - pe gazda
    n8n chiar asa se ajunge la panou, printr-un tunel ssh, fiindca HSTS pe :443
    face certificatul autosemnat de pe :8443 inutilizabil in browser. Iar
    `deploy.ps1 -AllowUfw` trimite ALLOW_UFW=1 la fiecare livrare, deci linia
    asta e ultima pe care o vede operatorul la fiecare deploy.

    `preflight.sh` deosebeste deja cele doua cazuri (liniile 378 si 383);
    rezumatul de final le colapsase intr-unul. Rostul mutarii la final a fost
    ca un avertisment ADEVARAT sa nu mai treaca neobservat - n-are voie sa
    devina unul fals.

    Falsificat scotand ramura ALLOW_UFW: aceeasi stare redevine obstacol.
    """
    proc = _run_closing(tmp_path, domain="panou.example.test",
                        ufw=_UFW_ACTIVE_CLOSED, allow_ufw="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "CE MAI ST\u0102 \u00ceNTRE TINE \u0218I PANOU" not in out, out
    assert "DE \u0218TIUT" in out, out
    assert "ai cerut --allow-ufw" in out, out
    assert "tunel ssh" in out, out
    # Comanda ramane pe ecran, dar ca optiune, nu ca instructiune.
    assert "sudo ufw allow 8443/tcp" in out, out


def test_without_allow_ufw_the_very_same_ufw_state_is_still_an_obstacle(tmp_path):
    """Perechea de discriminare. Daca nota ar aparea si fara steag, ramura n-ar
    spune nimic despre alegerea operatorului - ar dezactiva pur si simplu
    avertismentul pentru toata lumea."""
    proc = _run_closing(tmp_path, domain="panou.example.test",
                        ufw=_UFW_ACTIVE_CLOSED, allow_ufw="0")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout
    assert "CE MAI ST\u0102 \u00ceNTRE TINE \u0218I PANOU" in out, out
    assert "ai cerut --allow-ufw" not in out, out


def test_allow_ufw_says_nothing_when_the_port_is_actually_open(tmp_path):
    """Steagul nu e o stare masurata, e un raspuns la una. Daca nota ar aparea
    si cu portul deschis, operatorul ar citi "portul e INCHIS" despre un port
    pe care tocmai l-a deschis - aceeasi minciuna mica, pe dos."""
    proc = _run_closing(tmp_path, domain="panou.example.test",
                        ufw=_UFW_ACTIVE_OPEN, allow_ufw="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ai cerut --allow-ufw" not in proc.stdout, proc.stdout
    assert "DE \u0218TIUT" not in proc.stdout, proc.stdout


def test_allow_ufw_does_not_swallow_an_unreadable_ufw(tmp_path):
    """"Nu s-a putut citi" ramane obstacol chiar si cu steagul: operatorul a
    acceptat un port inchis, nu o stare pe care nimeni n-a masurat-o. Un steag
    care inghite si necunoscutul e felul in care o unealta de monitorizare
    incepe sa minta."""
    proc = _run_closing(tmp_path, domain="panou.example.test",
                        ufw="exit 1\n", allow_ufw="1")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CE MAI ST\u0102 \u00ceNTRE TINE \u0218I PANOU" in proc.stdout, proc.stdout
    assert "NECUNOSCUT" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# default_server-ul strain se masoara din ce INCARCA nginx, nu de pe disc
# ---------------------------------------------------------------------------
def _dump(*files: tuple[str, str]) -> str:
    """Un `nginx -T` ca cel real: fiecare fisier precedat de antetul lui."""
    out = []
    for path, body in files:
        out.append("# configuration file " + path + ":")
        out.append(body)
    return "\n".join(out) + "\n"


_DEFAULT_BLOCK = (
    "server {\n    listen 8443 ssl http2 default_server;\n"
    "    listen [::]:8443 ssl http2 default_server;\n    server_name _;\n}\n"
)
_PLAIN_BLOCK = (
    "server {\n    listen 8443 ssl http2;\n    server_name panou.example.test;\n}\n"
)


def _run_foreign(tmp_path: Path, *, dump: str | None, nginx_rc: int = 0,
                 port: str = "8443") -> tuple[int, list[str], str]:
    stubs = tmp_path / "bin"
    if dump is not None:
        payload = tmp_path / "dump.txt"
        payload.write_text(dump, encoding="utf-8", newline="\n")
        _write_stub(stubs, "nginx",
                    'cat "' + _p(payload) + '"\nexit ' + str(nginx_rc) + "\n")
    else:
        stubs.mkdir(parents=True, exist_ok=True)
        # Altfel testul "gazda fara nginx" ar depinde tacut de masina care il
        # ruleaza: pe una cu nginx instalat ar masura cu totul altceva si ar
        # trece sau pica din motive care n-au legatura cu codul livrat.
        assert shutil.which("nginx") is None, \
            "exista un nginx real pe PATH, deci cazul 'nginx absent' NU a fost testat"
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        + _funcs("nginx_foreign_default_on_port")
        + "rc=0\n"
        + 'out="$(nginx_foreign_default_on_port "' + port + '" '
          "/etc/nginx/conf.d/sentinel.conf "
          '/etc/nginx/conf.d/sentinel-default-deny.conf)" || rc=$?\n'
        + 'echo "RC=$rc"\n'
        + 'printf "%s" "$out"\n',
        tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.splitlines()
    rc = int(lines[0].split("=", 1)[1])
    return rc, [ln for ln in lines[1:] if ln.strip()], proc.stdout + proc.stderr


def test_a_file_nginx_never_loads_cannot_be_reported_as_a_foreign_default(tmp_path):
    """Defectul pe care il previne - si e prevenire, nu o pana vie: un
    `conf.d/sentinel.conf.bak-<data>` lasat de o instalare fara `--domain`
    contine `listen 8443 ... default_server`, nu potriveste niciuna dintre
    excluderile pe nume, si ar face ca FIECARE deploy urmator fara `--domain`
    sa moara - "merge o data, apoi blocheaza re-deploy-ul", intrat pe usa din
    dos, si acum fatal in loc sa sara doar blocul de refuz. nginx nu include
    fisierul (globul din nginx.conf e `*.conf`), deci nginx nu-l raporteaza.
    Productia are chiar acum un astfel de fisier,
    `/etc/nginx/conf.d/sentinel-shared.conf.bak-selfsigned`.

    Fisierul E pe disc in testul asta, exact acolo unde o cautare recursiva
    l-ar gasi. Falsificat inlocuind sursa raspunsului cu `grep -rlE` peste
    arborele ala (mutatia M33): calea de backup apare si testul pica.
    """
    fake_etc = tmp_path / "etc" / "nginx" / "conf.d"
    fake_etc.mkdir(parents=True)
    (fake_etc / "sentinel.conf.bak-20260918").write_text(
        _DEFAULT_BLOCK, encoding="utf-8", newline="\n")
    (fake_etc / "sentinel.conf").write_text(
        _PLAIN_BLOCK, encoding="utf-8", newline="\n")

    rc, paths, out = _run_foreign(tmp_path, dump=_dump(
        ("/etc/nginx/nginx.conf", "http {\n}\n"),
        (_p(fake_etc / "sentinel.conf"), _PLAIN_BLOCK),
    ))
    assert rc == 1, "a raportat un default_server strain din nimic: " + str(paths) + out
    assert paths == [], paths


def test_a_block_nginx_does_load_is_reported_with_its_file(tmp_path):
    """Cazul pozitiv. Daca raspunsul ar fi mereu "nimic", testul de mai sus
    n-ar dovedi nimic despre discriminare, iar instalatorul ar scrie un al
    doilea `default_server` peste al operatorului - adica un nginx care refuza
    sa incarce nimic, inclusiv siturile lui."""
    rc, paths, out = _run_foreign(tmp_path, dump=_dump(
        ("/etc/nginx/nginx.conf", "http {\n}\n"),
        ("/etc/nginx/conf.d/altcineva.conf", _DEFAULT_BLOCK),
    ))
    assert rc == 0, out
    assert paths == ["/etc/nginx/conf.d/altcineva.conf"], paths


def test_our_own_two_files_are_not_another_vhost(tmp_path):
    """Fara `--domain`, vhost-ul NOSTRU tine `default_server`. Daca s-ar
    raporta pe sine, al doilea deploy ar muri pe propriul lui rezultat."""
    rc, paths, out = _run_foreign(tmp_path, dump=_dump(
        ("/etc/nginx/conf.d/sentinel.conf", _DEFAULT_BLOCK),
        ("/etc/nginx/conf.d/sentinel-default-deny.conf", _DEFAULT_BLOCK),
    ))
    assert rc == 1, out
    assert paths == [], paths


def test_a_longer_port_number_is_not_our_port(tmp_path):
    """`listen 84430 default_server` nu e `:8443`. Vechea cautare avea `[^;]*`
    imediat dupa port si ar fi numarat-o - un obstacol inventat care, fara
    `--domain`, opreste instalarea."""
    rc, paths, out = _run_foreign(tmp_path, dump=_dump(
        ("/etc/nginx/conf.d/altcineva.conf",
         "server {\n    listen 84430 ssl default_server;\n}\n"),
    ))
    assert rc == 1, out + str(paths)


def test_nginx_refusing_to_dump_is_could_not_look_not_nothing_there(tmp_path):
    """Al treilea raspuns, si motivul pentru care functia intoarce un cod si nu
    un boolean. Daca "n-am putut citi" ar fi citit ca "nu e nimic acolo",
    instalatorul ar scrie un al doilea `default_server` peste o configuratie pe
    care nici macar nu reuseste s-o citeasca."""
    rc, _, out = _run_foreign(tmp_path, dump="", nginx_rc=1)
    assert rc == 2, out


def test_a_host_without_nginx_is_also_could_not_look(tmp_path):
    """Aceeasi stare, alta cauza. `have nginx` fals nu inseamna "portul e
    liber"."""
    rc, _, out = _run_foreign(tmp_path, dump=None)
    assert rc == 2, out


def _foreign_default_block() -> str:
    """Blocul de masurare din `step_nginx`, exact octetii livrati."""
    body = _func("step_nginx")
    start = body.index("    local foreign_default=")
    end = body.index("\n    fi\n", start) + len("\n    fi\n")
    return body[start:end]


def test_the_step_does_not_report_our_own_vhost_to_itself(tmp_path):
    """Fara `--domain`, vhost-ul nostru E `default_server`, si nginx il
    raporteaza ca atare la deploy-ul urmator. Daca pasul n-ar spune functiei
    care fisiere sunt ale lui, a doua livrare ar muri pe rezultatul primei -
    "merge o data, apoi blocheaza fiecare re-deploy".

    Falsificat scotand cele doua cai din apel (mutatia M41).
    """
    stubs = tmp_path / "bin"
    payload = tmp_path / "dump.txt"
    payload.write_text(_dump(
        ("/etc/nginx/conf.d/sentinel.conf", _DEFAULT_BLOCK),
        ("/etc/nginx/conf.d/sentinel-default-deny.conf", _DEFAULT_BLOCK),
    ), encoding="utf-8", newline="\n")
    _write_stub(stubs, "nginx", 'cat "' + _p(payload) + '"\n')
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        'PUBLIC_PORT="8443"\n'
        + _funcs("nginx_foreign_default_on_port")
        + "measure() {\n"
        + _foreign_default_block()
        + '    printf "FOREIGN=[%s]\\n" "$foreign_default"\n'
        + "}\n"
        "measure\n",
        tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "FOREIGN=[]" in proc.stdout, proc.stdout + proc.stderr


def test_the_step_says_unknown_out_loud_when_it_could_not_look(tmp_path):
    """"Nu s-a putut citi" trebuie SPUS, nu tratat tacut ca "nimic acolo".
    Pasul merge mai departe deliberat - configuratia care nu parseaza poate fi
    chiar `sentinel.conf`-ul pe care rularea asta il inlocuieste, iar un `die`
    aici ar bloca deploy-ul care o repara - dar operatorul afla, si afla si ce
    anume prinde greseala daca exista: `nginx -t`, cu `duplicate default
    server`.

    Falsificat scotand `warn`-ul din ramura `fd_state == 2` (mutatia M34).
    """
    stubs = tmp_path / "bin"
    _write_stub(stubs, "nginx", "exit 1\n")
    proc = _run(
        "set -euo pipefail\n"
        "source ./lib/common.sh\n"
        'PUBLIC_PORT="8443"\n'
        + _funcs("nginx_foreign_default_on_port")
        + "measure() {\n"
        + _foreign_default_block()
        + '    printf "FOREIGN=[%s]\\n" "$foreign_default"\n'
        + "}\n"
        "measure\n",
        tmp_path, extra_path=stubs)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = proc.stdout + proc.stderr
    assert "UNKNOWN" in out, out
    assert "duplicate default server" in out, out
    assert "FOREIGN=[]" in proc.stdout, proc.stdout
