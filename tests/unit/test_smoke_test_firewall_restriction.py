"""Un `000` pe verificarea externă nu e eșec când firewall-ul gazdei închide portul dinadins.

Pe n8n, ufw e activ și deschide 8443 doar din rețelele Docker (`172.16.0.0/12`): Traefik e în
față, portul nu e public. Verificarea externă (`curl` de pe mașina operatorului) nu se conecta,
iar scriptul termina cu «Verificări eșuate. Nu considera deployment-ul reușit.», trimițând
operatorul după firewall-ul furnizorului sau după DNS — pe o gazdă sănătoasă, configurată
exact cum trebuie. Un eșec fals care apare la fiecare rulare învață operatorul să nu mai
citească raportul.

Reparația degradează la avertisment NUMAI cu dovadă din regulile gazdei (`ufw status verbose`):
ufw activ, politică implicită deny/reject pe intrare, cel puțin o regulă ALLOW pentru port pe
familia adresei operatorului și NICIUNA care îl admite. Orice altceva rămâne `[x]`: nicio
regulă, o regulă care te admite, ufw inactiv sau ilizibil, o regulă pe care scriptul n-o
înțelege, adresa necunoscută. Testele cer ambele jumătăți — o reparație care ar degrada totul
la avertisment ar trece doar testul de verde.

Ce NU reproduce simularea: un ufw și un sshd reale. `ssh` e o momeală care rulează comanda
printr-un `bash -c` local, `sudo` doar scoate `-n`, `ufw` tipărește ieșirea MĂSURATĂ pe gazda
n8n (24 nov 2026, `ufw status verbose`) sau variante ale ei, iar `python3` e interpretorul
local. Că `ufw status` raportează «inactive» când lanțurile nu sunt încărcate în nucleu nu s-a
putut verifica de aici.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = (ROOT / "scripts" / "smoke-test.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")

# Ieșirea reală, de pe gazda n8n.
UFW_N8N = """Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere                  
8443/tcp                   ALLOW IN    172.16.0.0/12              # Sentinel nginx -- doar din retelele Docker (traefik)
22/tcp (OpenSSH (v6))      ALLOW IN    Anywhere (v6)             
5432/tcp                   ALLOW IN    2a02:4780:3f:2161:0:306b:b0d6:1 # Hostinger -> Postgres
"""
OPERATOR = "188.25.61.167"


def _ufw(rules: str, default: str = "deny (incoming), allow (outgoing), deny (routed)",
         status: str = "active") -> str:
    return (f"Status: {status}\nLogging: on (low)\nDefault: {default}\nNew profiles: skip\n\n"
            "To                         Action      From\n--                         ------      ----\n"
            + rules)


def _function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", SMOKE, re.S | re.M)
    assert match, f"{name}() nu a fost găsită în smoke-test.sh"
    return match.group(0)


def _stub(directory: Path, name: str, body: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


PRELUDE = r"""
set -euo pipefail
PASS=0; FAIL=0; WARN=0
pass() { PASS=$((PASS+1)); printf 'PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf 'WARN %s\n' "$*"; }
HOST=h; USER=u; SSH_OPTS=(-p 22)
"""
R_FN = re.search(r"^r\(\) .*$", SMOKE, re.M).group(0)
FUNCS = (R_FN + "\n" + _function("measure_remote") + "\n" + _function("addr_in_cidr") + "\n"
         + _function("firewall_port_verdict") + "\n")


def _chain() -> str:
    """Lanțul verificării externe din scriptul LIVRAT, de la `curl` până la TLS."""
    a = SMOKE.index('    code="$(curl -s -o /dev/null')
    b = SMOKE.index("    if curl -s --max-time 15 -o /dev/null", a)
    return SMOKE[a:b]


class Result:
    def __init__(self, proc: subprocess.CompletedProcess):
        self.text = proc.stdout + ("\n[stderr] " + proc.stderr if proc.stderr.strip() else "")
        m = re.search(r"CONTOARE (\d+) (\d+) (\d+)", proc.stdout)
        assert m, f"scriptul nu a ajuns la contoare: {self.text!r}"
        self.passes, self.warns, self.fails = (int(m.group(i)) for i in (1, 2, 3))
        self.warn_lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("WARN ")]
        self.fail_lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("FAIL ")]


SS_N8N = ('LISTEN 0 511 0.0.0.0:8443 0.0.0.0:* users:(("nginx",pid=1,fd=6))\n'
          'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=2,fd=8))\n')


def _install_stubs(tmp: Path, ufw_out: str | None, *, ufw_rc: int = 0, python_ok: bool = True,
                   ss_out: str = SS_N8N, ss_rc: int = 0) -> dict[str, str]:
    """ssh/sudo/ufw/ss/python3/nginx momeală pe PATH; întoarce mediul pentru subproces."""
    bindir = tmp / "bin"
    _stub(bindir, "ssh", 'exec bash -c "${@: -1}"\n')
    _stub(bindir, "sudo",
          'if [[ -n "${SUDO_REFUSES:-}" ]]; then echo "sudo: a password is required" >&2; exit 1; fi\n'
          '[[ "$1" == -n ]] || { echo "sudo: a password is required" >&2; exit 1; }\nshift\nexec "$@"\n')
    if ufw_out is None:
        _stub(bindir, "ufw", "echo 'ufw: command not found' >&2; exit 127\n")
    else:
        (tmp / "ufw.txt").write_text(ufw_out, encoding="utf-8", newline="\n")
        _stub(bindir, "ufw", f'[[ "$*" == "status verbose" ]] || {{ echo "ufw: argumente: $*" >&2; exit 2; }}\n'
                             f'cat "{(tmp / "ufw.txt").as_posix()}"\nexit {ufw_rc}\n')
    (tmp / "ss.txt").write_text(ss_out, encoding="utf-8", newline="\n")
    _stub(bindir, "ss", f'[[ "$*" == "-tlnpH" ]] || {{ echo "ss: argumente: $*" >&2; exit 2; }}\n'
                        + (f"echo 'ss: netlink error' >&2; exit {ss_rc}\n" if ss_rc
                           else f'cat "{(tmp / "ss.txt").as_posix()}"\n'))
    if python_ok:
        _stub(bindir, "python3", f'exec "{Path(sys.executable).as_posix()}" "$@"\n')
    else:
        _stub(bindir, "python3", "echo 'python3: command not found' >&2; exit 127\n")
    return {**os.environ, "PATH": bindir.as_posix() + os.pathsep + os.environ.get("PATH", "")}


def _execute(tmp: Path, script: str, env: dict[str, str]) -> Result:
    path = tmp / "probe.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    return Result(subprocess.run([BASH, path.as_posix()], capture_output=True, text=True, cwd=tmp.as_posix(),
                                 encoding="utf-8", errors="replace", env=env, timeout=120))


def _run(tmp: Path, ufw_out: str | None, *, peer: str = OPERATOR, ufw_rc: int = 0,
         sudo_refuses: bool = False, python_ok: bool = True, loopback_failed: bool = False,
         port: str = "8443", ss_out: str = SS_N8N, ss_rc: int = 0) -> Result:
    """Rulează lanțul extern livrat cu un curl care nu se conectează (000) și un ufw fals."""
    env = _install_stubs(tmp, ufw_out, ufw_rc=ufw_rc, python_ok=python_ok, ss_out=ss_out, ss_rc=ss_rc)
    _stub(tmp / "bin", "curl", "printf 000; exit 7\n")
    if sudo_refuses:
        env["SUDO_REFUSES"] = "1"
    env["T_PORT"] = port   # prin mediu, nu lipit în text: un port ostil nu are voie să ajungă în harnaș
    script = (PRELUDE + FUNCS
              + 'DOMAIN=panou.test; WEB_PORT="$T_PORT"; URL_SUFFIX=":8443"\n'
              + f'peer="{peer}"\n'
              + "DASH_FAIL_BASE=0\n" + ("FAIL=1\n" if loopback_failed else "")
              + _chain()
              + '\nprintf "CONTOARE %s %s %s\n" "$PASS" "$WARN" "$FAIL"\n')
    return _execute(tmp, script, env)


def _dashboard(tmp: Path, *, app_ok: bool, nginx_ok: bool) -> Result:
    """Secțiunea «Dashboard» LIVRATĂ, de la `sect` până la verificarea TLS: `DASH_FAIL_BASE`
    își ia valoarea de acolo, nu de la harnaș, deci ordinea reală a liniilor e cea probată."""
    env = _install_stubs(tmp, UFW_N8N)
    _stub(tmp / "bin", "curl",
          'case "$*" in\n'
          f'  *127.0.0.1:8787*) printf {"200" if app_ok else "000"}; exit {0 if app_ok else 7} ;;\n'
          f'  *https://127.0.0.1:8443*) printf {"200" if nginx_ok else "000"}; exit {0 if nginx_ok else 7} ;;\n'
          "  *) printf 000; exit 7 ;;\nesac\n")
    # secțiunea cheamă și `sudo nginx -t` fără `-n` (ca pe gazdă, cu sudoers NOPASSWD): sudo-ul
    # acestei momeli lasă totul să treacă, iar `-n`-ul îl scoate dacă există
    _stub(tmp / "bin", "sudo", '[[ "$1" == -n ]] && shift\nexec "$@"\n')
    _stub(tmp / "bin", "nginx",
          '[[ "$1" == -t ]] && exit 0\necho "# configuration file /etc/nginx/nginx.conf:"\nexit 0\n')
    a = SMOKE.index('sect "Dashboard"')
    b = SMOKE.index("    if curl -s --max-time 15 -o /dev/null", a)
    funcs = "".join(_function(n) + "\n" for n in (
        "parse_nginx_vhost_name", "pick_probe_name", "probe_loopback", "report_loopback_probe"))
    script = (PRELUDE + "sect() { :; }\n" + FUNCS + funcs
              + 'DOMAIN=panou.test; DOMAIN_FLAG=""; WEB_PORT=8443; URL_SUFFIX=":8443"; NGINX_MODE=dedicated\n'
              + f'peer="{OPERATOR}"\n'
              + SMOKE[a:b] + "\nfi\n"
              + '\nprintf "CONTOARE %s %s %s\n" "$PASS" "$WARN" "$FAIL"\n')
    return _execute(tmp, script, env)


def _still_red(res: Result, why_contains: str | None = None) -> None:
    assert res.fails == 1 and res.warns == 0, res.text
    assert "did not connect" in res.fail_lines[0], res.text
    if why_contains:
        assert why_contains in res.fail_lines[0], res.text


# --- jumătatea verde: restricția e dovedită din regulile gazdei -----------------------------

def test_a_port_the_host_firewall_opens_only_to_docker_is_a_warning_naming_the_rule(tmp_path):
    """Ieșirea ufw REALĂ de pe n8n, adresa operatorului din afara 172.16.0.0/12. Înainte:
    `[x] ... did not connect` și «Nu considera deployment-ul reușit» pe o gazdă sănătoasă.
    Acum: `[!]` care numește regula ca motiv, fără niciun eșec."""
    res = _run(tmp_path, UFW_N8N)
    assert (res.fails, res.warns) == (0, 1), res.text
    w = res.warn_lines[0]
    assert "închis dinadins de firewall-ul gazdei (ufw)" in w, w
    assert "172.16.0.0/12" in w and OPERATOR in w and "8443/tcp ALLOW 172.16.0.0/12" in w, w


def test_a_deny_rule_does_not_stop_the_closed_port_from_being_proven(tmp_path):
    """Sub deny implicit, un DENY pe adresa ta doar restrânge mai mult; nu poate deschide portul."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             f"8443/tcp                   DENY IN     {OPERATOR}\n")
    res = _run(tmp_path, _ufw(rules))
    assert (res.fails, res.warns) == (0, 1), res.text


def test_a_rule_for_every_port_from_a_foreign_network_counts_as_a_restriction(tmp_path):
    """`Anywhere ALLOW IN 203.0.113.0/24` acoperă și 8443, dar nu te include."""
    res = _run(tmp_path, _ufw("Anywhere                   ALLOW IN    203.0.113.0/24\n"))
    assert (res.fails, res.warns) == (0, 1), res.text


def test_an_ipv6_operator_is_judged_by_the_ipv6_rules(tmp_path):
    """Operatorul pe IPv6: o regulă (v6) cu altă rețea îl lasă în afară; calculul de rețea se
    face pe gazdă, nu cu un compar de șiruri."""
    rules = "8443/tcp                   ALLOW IN    2a02:4780::/32\n"
    res = _run(tmp_path, _ufw(rules), peer="2001:db8::1")
    assert (res.fails, res.warns) == (0, 1), res.text
    assert "2a02:4780::/32" in res.warn_lines[0], res.text


# --- jumătatea roșie: tot ce nu e dovedit rămâne eșec ---------------------------------------

def test_a_rule_that_admits_the_operator_address_stays_a_failure(tmp_path):
    """Dacă regula te admite, firewall-ul NU e motivul: eșecul e real (DNS, nginx, altceva).
    Fără asta, orice `000` ar deveni avertisment cât timp există vreo regulă ufw."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "8443/tcp                   ALLOW IN    188.25.61.0/24\n")
    res = _run(tmp_path, _ufw(rules))
    _still_red(res, "te admite")


def test_a_rule_open_to_anywhere_stays_a_failure(tmp_path):
    res = _run(tmp_path, _ufw("8443/tcp                   ALLOW IN    Anywhere\n"))
    _still_red(res, "admite orice sursă")


@pytest.mark.parametrize("spec", ["8000:9000/tcp", "443,8443/tcp", "8443"])
def test_a_port_range_list_or_bare_number_rule_that_admits_anyone_is_read_as_covering_the_port(tmp_path, spec):
    """Regula poate fi un interval, o listă sau un număr gol (tcp+udp). Citită greșit ca
    «alt port», ar lăsa restricția «dovedită» deși o regulă deschisă acoperă portul."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             f"{spec}                  ALLOW IN    Anywhere\n")
    _still_red(_run(tmp_path, _ufw(rules)), "admite orice sursă")


def test_a_udp_only_rule_does_not_cover_a_tcp_port(tmp_path):
    """8443/udp nu deschide 8443/tcp: o regulă udp deschisă nu strică dovada, dar nici nu o
    face — singură, nu e nicio regulă tcp, deci eșecul rămâne."""
    res = _run(tmp_path, _ufw("8443/udp                   ALLOW IN    Anywhere\n"))
    _still_red(res, "nicio regulă ufw ALLOW")


def test_no_rule_for_the_port_stays_a_failure(tmp_path):
    """Fără nicio regulă pentru port nu pot spune că restricția e intenționată (poate e doar
    o instalare căreia i-a lipsit pasul de firewall)."""
    _still_red(_run(tmp_path, _ufw("22/tcp (OpenSSH)           ALLOW IN    Anywhere\n")),
               "nicio regulă ufw ALLOW")


def test_an_ipv6_operator_with_only_ipv4_rules_is_closed_out_and_the_rule_is_named(tmp_path):
    """Operator pe IPv6, singura regulă pentru port e v4 (172.16.0.0/12): pe IPv6 portul e
    închis de politica implicită deny, iar regula v4 e dovada că restricția e intenționată."""
    res = _run(tmp_path, UFW_N8N, peer="2001:db8::1")
    assert (res.fails, res.warns) == (0, 1), res.text


def test_default_allow_incoming_stays_a_failure(tmp_path):
    """Cu politica implicită allow, o regulă ALLOW pe un interval nu închide nimic."""
    res = _run(tmp_path, _ufw("8443/tcp                   ALLOW IN    172.16.0.0/12\n",
                              default="allow (incoming), allow (outgoing), disabled (routed)"))
    _still_red(res, "politica implicită")


def test_inactive_ufw_stays_a_failure(tmp_path):
    # restul ieșirii e IDENTIC cu cel al unei gazde sănătoase: doar `Status:` deosebește cazul
    res = _run(tmp_path, _ufw("8443/tcp                   ALLOW IN    172.16.0.0/12\n", status="inactive"))
    _still_red(res, "Status: active")


def test_a_ufw_that_cannot_be_read_stays_a_failure(tmp_path):
    """sudo care refuză sau ufw lipsă (gazdă cu firewalld/nft): nu pot citi regulile, deci nu
    pot dovedi nimic — «nu știu» nu devine «e în regulă»."""
    _still_red(_run(tmp_path, UFW_N8N, sudo_refuses=True), "nu pot citi")
    _still_red(_run(tmp_path, None), "nu pot citi")


def test_a_ufw_rule_the_script_cannot_parse_stays_a_failure(tmp_path):
    """Un profil de aplicație (`Nginx Full`) poate acoperi 8443 fără să spună: nu ghicesc."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "Nginx Full                 ALLOW IN    Anywhere\n")
    _still_red(_run(tmp_path, _ufw(rules)), "nu are o formă")


def test_a_source_with_an_interface_qualifier_stays_a_failure(tmp_path):
    rules = "8443/tcp                   ALLOW IN    172.16.0.0/12 on docker0\n"
    _still_red(_run(tmp_path, _ufw(rules)), "sursă pe care n-o știu citi")


def test_a_host_without_python3_cannot_prove_it_and_stays_a_failure(tmp_path):
    """Calculul de rețea se face pe gazdă; fără python3 răspunsul e «?», nu «nu ești în rețea»."""
    _still_red(_run(tmp_path, UFW_N8N, python_ok=False), "n-am putut calcula")


def test_an_unknown_operator_address_stays_a_failure(tmp_path):
    """Fără adresa operatorului nu se poate spune că regula nu-l include."""
    _still_red(_run(tmp_path, UFW_N8N, peer=""), "nu știu adresa ta")


def test_a_failed_loopback_check_never_downgrades_the_external_failure(tmp_path):
    """Dacă aplicația sau nginx nu răspund pe loopback, `000` extern poate fi pană reală, iar
    firewall-ul n-o explică. Avertismentul cere ca verificările de loopback să fi trecut."""
    res = _run(tmp_path, UFW_N8N, loopback_failed=True)
    # FAIL=1 e eșecul de loopback pus de harnaș; al doilea e verificarea externă, rămasă roșie
    assert res.fails == 2 and res.warns == 0 and "did not connect" in res.fail_lines[0], res.text
    assert "loopback" in res.fail_lines[0], res.text


def test_the_call_site_is_in_the_shipped_script_not_only_in_the_function():
    """Funcția probată de mai sus nu ajută dacă scriptul nu o cheamă pe ramura `000`."""
    assert "firewall_port_verdict" in _chain()


# --- runda 2: ce a trecut verde pe nedrept ---------------------------------------------------

def test_an_ipv6_rule_open_to_anywhere_stays_a_failure_for_an_ipv4_peer(tmp_path):
    """ssh-ul a venit pe IPv4, dar `curl` poate ajunge pe IPv6. Cu `8443/tcp ALLOW 172.16.0.0/12`
    plus `8443/tcp (v6) ALLOW Anywhere (v6)`, judecata doar pe familia peer-ului dădea «închis
    dinadins» pe un port deschis oricui pe IPv6. Orice familie care admite internetul ține
    eșecul roșu."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "8443/tcp (v6)              ALLOW IN    Anywhere (v6)\n")
    _still_red(_run(tmp_path, _ufw(rules)), "admite orice sursă")


@pytest.mark.parametrize("source", ["0.0.0.0/0", "::/0"])
def test_a_zero_length_prefix_is_anywhere_in_either_family(tmp_path, source):
    """`0.0.0.0/0` și `::/0` admit tot internetul, chiar dacă nu scriu «Anywhere»; pe familia
    CEALALTĂ nu se face calcul de rețea, deci trebuie recunoscute ca atare."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             f"8443/tcp                   ALLOW IN    {source}\n")
    _still_red(_run(tmp_path, _ufw(rules)), "admite orice sursă")


def test_a_v4_mapped_peer_is_judged_by_the_ipv4_rules(tmp_path):
    """`::ffff:188.25.61.167` e tot adresa IPv4 a operatorului: o regulă care îl admite pe
    IPv4 nu are voie să treacă drept „altă familie"."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "8443/tcp                   ALLOW IN    188.25.61.0/24\n")
    _still_red(_run(tmp_path, _ufw(rules), peer="::ffff:188.25.61.167"), "te admite")


@pytest.mark.parametrize("rules", [
    "8443/tcp                   LIMIT IN    Anywhere\n",
    "8443/tcp                   LIMIT       Anywhere\n",
], ids=["limit-in", "bare-limit"])
def test_a_limit_rule_admits_traffic_so_it_opens_the_port(tmp_path, rules):
    """`LIMIT` lasă să treacă conexiunile, cu limită de rată: un `8443 LIMIT Anywhere` e un
    port deschis, nu o restricție. Tratat ca DENY, scriptul ar fi spus «închis dinadins»."""
    _still_red(_run(tmp_path, _ufw("8443/tcp                   ALLOW IN    172.16.0.0/12\n" + rules)),
               "admite orice sursă")


def test_a_limit_rule_from_a_foreign_network_still_counts_as_a_restriction(tmp_path):
    """Contra-proba: LIMIT cu sursă străină e o regulă care restrânge, ca ALLOW."""
    res = _run(tmp_path, _ufw("8443/tcp                   LIMIT IN    203.0.113.0/24\n"))
    assert (res.fails, res.warns) == (0, 1), res.text


def test_the_bare_allow_form_without_a_direction_is_read(tmp_path):
    """ufw mai vechi scrie `ALLOW` fără `IN`. Dacă forma goală nu s-ar citi, o regulă deschisă
    din ea ar dispărea și portul ar părea restrâns."""
    rules = ("8443/tcp                   ALLOW       172.16.0.0/12\n"
             "8443/tcp                   ALLOW       Anywhere\n")
    _still_red(_run(tmp_path, _ufw(rules)), "admite orice sursă")
    res = _run(tmp_path / "b", _ufw("8443/tcp                   ALLOW       172.16.0.0/12\n")) \
        if (tmp_path / "b").mkdir() is None else None
    assert (res.fails, res.warns) == (0, 1), res.text


def test_an_outbound_rule_is_not_counted_as_inbound(tmp_path):
    """`ALLOW OUT Anywhere` privește traficul care iese; nu deschide portul pentru nimeni."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "8443/tcp                   ALLOW OUT   Anywhere\n")
    res = _run(tmp_path, _ufw(rules))
    assert (res.fails, res.warns) == (0, 1), res.text


def test_an_outbound_only_rule_is_no_evidence_of_a_restriction(tmp_path):
    _still_red(_run(tmp_path, _ufw("8443/tcp                   ALLOW OUT   172.16.0.0/12\n")),
               "nicio regulă ufw ALLOW")


# --- portul vine de la operator sau de la gazdă: nu se evaluează niciodată ----------------

@pytest.mark.parametrize("port", ["PASS[$(touch PWNED)]", "8443; touch PWNED", "a[$(touch PWNED)]", "0", "65536", "-1", "",
                                  "99999999999999999999"])
def test_a_hostile_or_invalid_port_is_never_evaluated_and_stays_a_failure(tmp_path, port):
    """`(( 10#$lo <= port ))` evalua `port` ca expresie aritmetică: `PASS[$(touch PWNED)]` din
    `--web-port` sau din sentinel.yaml-ul gazdei crea fișierul PE MAȘINA OPERATORULUI (măsurat).
    Acum portul se validează (doar cifre, 1-65535) înainte de orice folosire, iar rezultatul e
    «nu știu» — eșecul rămâne."""
    res = _run(tmp_path, UFW_N8N, port=port)
    assert not (tmp_path / "PWNED").exists(), "portul ostil a fost EXECUTAT"
    _still_red(res, "nu e un număr de port valid")


def test_a_ufw_port_range_with_absurd_digits_is_not_evaluated(tmp_path):
    """Intervalele din ufw au cel mult 5 cifre; ceva mai lung nu e un port și nu intră în `(( ))`."""
    rules = ("8443/tcp                   ALLOW IN    172.16.0.0/12\n"
             "1:99999999999999999999/tcp ALLOW IN    Anywhere\n")
    _still_red(_run(tmp_path, _ufw(rules)), "nu are o formă")


# --- Docker ocolește ufw ---------------------------------------------------------------------

def test_a_port_published_by_docker_proxy_is_not_proven_closed_by_ufw(tmp_path):
    """Porturile publicate de Docker trec prin DNAT, înaintea regulilor ufw: «ufw îl restrânge»
    ar fi fals pentru ele. `ss` arată docker-proxy pe port → «nu știu», eșecul rămâne."""
    ss = 'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("docker-proxy",pid=2,fd=8))\n'
    _still_red(_run(tmp_path, UFW_N8N, ss_out=ss), "docker-proxy")
    ss6 = 'LISTEN 0 4096 [::]:8443 [::]:* users:(("docker-proxy",pid=2,fd=8))\n'
    (tmp_path / "v6").mkdir()
    _still_red(_run(tmp_path / "v6", UFW_N8N, ss_out=ss6), "docker-proxy")


def test_docker_proxy_on_another_port_does_not_block_the_proof(tmp_path):
    """Contra-proba: docker-proxy pe 443 (Traefik, ca pe gazdă) nu are legătură cu 8443;
    default-ul din harnaș îl conține deja, iar testul principal trece cu el."""
    res = _run(tmp_path, UFW_N8N, ss_out=SS_N8N)
    assert "docker-proxy" in SS_N8N and (res.fails, res.warns) == (0, 1), res.text


def test_an_ss_that_cannot_be_read_does_not_prove_the_port_is_not_docker_published(tmp_path):
    _still_red(_run(tmp_path, UFW_N8N, ss_rc=1), "nu pot afla cine ascultă")


# --- ordinea reală din scriptul livrat ------------------------------------------------------

def test_dashboard_with_both_loopback_probes_green_downgrades_to_the_warning(tmp_path):
    """Contra-proba pentru testele de mai jos, pe SECȚIUNEA livrată (nu cu un harnaș care își
    pune singur `DASH_FAIL_BASE`)."""
    res = _dashboard(tmp_path, app_ok=True, nginx_ok=True)
    assert any("închis dinadins" in w for w in res.warn_lines), res.text
    assert res.fails == 0, res.text


@pytest.mark.parametrize("app_ok,nginx_ok", [(False, True), (True, False), (False, False)])
def test_a_failing_loopback_probe_keeps_the_external_failure_red_in_the_shipped_section(tmp_path, app_ok, nginx_ok):
    """`DASH_FAIL_BASE` trebuie luat ÎNAINTEA sondelor de loopback. Mutat după ele, un 8787 sau
    un nginx căzut ar fi fost numărat în bază, iar `000`-ul extern ar fi devenit «firewall-ul
    îl închide dinadins» pe o aplicație picată — exact eșecul real mascat."""
    res = _dashboard(tmp_path, app_ok=app_ok, nginx_ok=nginx_ok)
    assert not any("închis dinadins" in w for w in res.warn_lines), res.text
    assert any("did not connect" in f for f in res.fail_lines), res.text
    assert res.fails >= 2, res.text


def test_an_ipv6_operator_inside_an_ipv6_rule_stays_a_failure(tmp_path):
    """Regula `8443/tcp ALLOW IN 2a02:4780::/32` te admite pe IPv6 (2a02:4780::5): firewall-ul
    NU e motivul. Dacă o sursă IPv6 ar fi citită ca regulă v4, calculul de rețea ar fi sărit
    («altă familie»), regula ar părea o restricție, iar un `000` real ar deveni «închis dinadins»."""
    rules = "8443/tcp                   ALLOW IN    2a02:4780::/32\n"
    _still_red(_run(tmp_path, _ufw(rules), peer="2a02:4780::5"), "te admite")
