"""`scripts/vps-watchdog-conf-init.sh` - scriptul REAL, rulat cu fals-uri de `ssh`/`sudo`.

deploy/install.sh adopta watchdog-ul de pe o gazda doar unde exista
/etc/sentinel/vps-watchdog.conf. Pe productie fisierul nu exista, deci un deploy doar
avertizeaza, iar copia veche, scrisa de mana, cu pragul de RAM de 400 MB care a tacut la
OOM-ul din 21 oct, ruleaza mai departe. Scriptul creeaza acel fisier. Ce se strica pentru
operator daca el gresește, in ordinea gravitatii:

  * un conf cu HEALTH_DOMAINS gol: watchdog-ul nou e instalat, raporteaza "sanatos", iar
    site-urile clientilor nu mai sunt verificate de nimeni - nicio eroare nicaieri;
  * un conf scris peste unul facut de mana: se pierd ajustarile operatorului;
  * un conf cu proprietar/mod gresit sau pe care watchdog-ul il citeste altfel decat
    scriptul: domeniile apar in fisier, dar nu si in verificari;
  * domeniile clientilor in depozitul public.

Nu se reimplementeaza nimic: testele ruleaza scriptul asa cum e livrat. Ce se simuleaza si
ce NU are mediul asta:

  * `ssh` e un fals care executa LOCAL comanda de la distanta (`printf B64 | base64 -d |
    sudo -n bash`), deci scriptul de pe gazda ruleaza pe bune, doar ca pe masina asta si
    pe cai fabricate (`VPSW_CONF`, `VPSW_SOURCE`). `sudo` e un fals care nu urca la root.
  * `chown` e un fals care doar noteaza argumentele: pe masina asta nu se poate da un fisier
    lui root. De aceea proprietarul asteptat (`VPSW_OWNER`) e al utilizatorului de test.
    NU s-a verificat aici ca un `chown root:root` real reuseste - doar ca scriptul il cere si
    ca verificarea citeste proprietarul REAL al fisierului.
  * nu exista SELinux, nu exista o gazda cu /etc/sentinel root:sentinel 0750.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "vps-watchdog-conf-init.sh"
REMOTE = REPO / "scripts" / "lib" / "vps-watchdog-conf-init-remote.sh"   # partea care ruleaza pe gazda
WATCHDOG = REPO / "deploy" / "vps-watchdog" / "watchdog.sh"
CONF_EXAMPLE = REPO / "deploy" / "config" / "vps-watchdog.conf.example"

BASH = shutil.which("bash")
pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason="bash lipseste din PATH")]

# Domenii FICTIVE, in forma celor de pe gazda: o singura linie, trei nume.
DOMAINS = ["app.example.org", "status.example.org", "shop.example.net"]

OLD_SCRIPT = """#!/usr/bin/env bash
# VPS watchdog - FAZA 2: monitorizare + auto-remediere marginita (fix: starting=PENDING).
set -uo pipefail
SECRETS=/etc/sentinel/secrets.env
STATE_DIR=/opt/vps-watchdog/state
AUTO_FIX=1; MAX_FIX=3; UNHEALTHY_STREAK=2; EXCLUDE_AUTOFIX="root-app-1"
DISK_PCT_MAX=88; MEM_AVAIL_MIN_MB=400; SWAP_PCT_MAX=85; LOAD_PER_CORE_MAX=2.0
HEALTH_DOMAINS="{domains}"; CURL_TIMEOUT=10
[ -r "$SECRETS" ] && . "$SECRETS" || true
for d in $HEALTH_DOMAINS; do code=$(curl -s -o /dev/null -m "$CURL_TIMEOUT" "https://$d/api/health"); done
"""


def _old_script(domains: str = " ".join(DOMAINS)) -> str:
    return OLD_SCRIPT.replace("{domains}", domains)


def _msys(path: Path) -> str:
    """Calea ca o vede bash (pe Windows: /c/Users/...). Scriptul cere cai de forma /..."""
    out = subprocess.run([BASH, "-c", 'cd "$1" && pwd', "_", str(path)],
                         capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip().startswith("/"), (out.stdout, out.stderr)
    return out.stdout.strip()


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


class Result:
    def __init__(self, proc, fx: "Fx"):
        self.returncode = proc.returncode
        self.out = proc.stdout.decode("utf-8", errors="replace")
        self.err = proc.stderr.decode("utf-8", errors="replace")
        self.log = fx.log.read_text(encoding="utf-8").splitlines() if fx.log.exists() else []

    @property
    def text(self) -> str:
        return self.out + self.err

    @property
    def modes(self) -> list[str]:
        """Modul cerut de fiecare sesiune ssh, in ordine (create/verify/plan)."""
        return [l.split(" ", 1)[1] for l in self.log if l.startswith("MODE ")]

    def calls(self, prefix: str) -> list[str]:
        return [l for l in self.log if l.startswith(prefix)]


class Fx:
    """O "gazda" fabricata: un director /etc, un script vechi, fals-uri pe PATH."""

    def __init__(self, root: Path):
        self.root = root
        self.bin = root / "bin"
        self.etc = root / "etc"
        self.opt = root / "opt"
        for d in (self.bin, self.etc, self.opt):
            d.mkdir(parents=True, exist_ok=True)
        self.log = root / "ssh.log"
        self.conf = self.etc / "vps-watchdog.conf"
        self.source = self.opt / "watchdog.sh"
        self.write_source(_old_script())
        probe = root / "probe"
        probe.write_bytes(b"")
        # Proprietarul unui fisier proaspat creat aici, citit cu acelasi `stat` ca scriptul.
        self.owner = subprocess.run([BASH, "-c", 'stat -c "%U:%G" "$1"', "_", _msys(root) + "/probe"],
                                    capture_output=True, text=True).stdout.strip()
        assert re.fullmatch(r"[A-Za-z0-9._-]+:[A-Za-z0-9._-]+", self.owner), self.owner
        real_stat = subprocess.run([BASH, "-c", "command -v stat"], capture_output=True,
                                   text=True).stdout.strip()
        assert real_stat
        real = {}
        for name in ("ln", "sha256sum", "sort"):
            real[name] = subprocess.run([BASH, "-c", f"command -v {name}"], capture_output=True,
                                        text=True).stdout.strip()
            assert real[name], name
        # `ln` care iese cu 0 fara sa faca legatura: exact "comanda a reusit" fara efect.
        _stub(self.bin, "ln",
              '[ -n "${FAKE_LN_NOOP:-}" ] && exit 0\n'
              f'exec "{real["ln"]}" "$@"\n')
        # `sha256sum` care la a DOUA chemare (citirea inapoi) da alt rezultat: ce a scris scriptul
        # nu mai e ce se vede pe disc.
        _stub(self.bin, "sha256sum",
              'n=$(( $(cat "$FAKE_LOG.sha" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$FAKE_LOG.sha"\n'
              '[ -n "${FAKE_DIGEST_LIE:-}" ] && [ "$n" -ge 2 ] && { echo "deadbeefdead0000  -"; exit 0; }\n'
              f'exec "{real["sha256sum"]}" "$@"\n')
        # `sort` care scoate o cheie din lista de chei vazuta la citirea inapoi.
        _stub(self.bin, "sort",
              f'"{real["sort"]}" "$@" | if [ -n "${{FAKE_KEYS_DROP:-}}" ]; then grep -vx "$FAKE_KEYS_DROP"; else cat; fi\n')
        _stub(self.bin, "ssh",
              'echo "SSH $*" >> "$FAKE_LOG"\n'
              '[ -n "${FAKE_SSH_FAIL:-}" ] && { echo "ssh: connect to host: Connection refused" >&2; exit 255; }\n'
              'while [[ $# -gt 0 ]]; do\n'
              '  case "$1" in -o|-p|-i|-F) shift 2 ;; -*) shift ;; *) break ;; esac\n'
              'done\n'
              'shift\n'
              'cmd="$*"\n'
              '# o linie per sesiune, cu modul decodat din incarcatura base64\n'
              'b64=$(printf "%s" "$cmd" | sed -n "s/.*printf .%s. .\\([^ ]*\\). .*/\\1/p" | tr -d "\\047")\n'
              'echo "MODE $(printf "%s" "$b64" | base64 -d | sed -n "1s/^MODE=//p")" >> "$FAKE_LOG"\n'
              'eval "$cmd"\n')
        _stub(self.bin, "sudo",
              'echo "SUDO $*" >> "$FAKE_LOG"\n'
              '[ -n "${FAKE_SUDO_FAIL:-}" ] && { echo "sudo: a password is required" >&2; exit 1; }\n'
              '[ -n "${FAKE_SUDO_SILENT:-}" ] && exit 0\n'
              '[ "$1" = "-n" ] && shift\n'
              'exec "$@"\n')
        _stub(self.bin, "chown", 'echo "CHOWN $*" >> "$FAKE_LOG"\nexit "${FAKE_CHOWN_RC:-0}"\n')
        # `stat` care minte DOAR despre numele final al conf-ului (nu despre temporar): o
        # citire care nu coincide cu ce a scris scriptul.
        # Tot el, cu `FAKE_RACE`: la citirea temporarului (ultima verificare dinaintea publicarii)
        # creeaza numele final, ca si cum un alt proces ar fi ajuns primul - indiferent CU CE
        # comanda publica scriptul (`ln`, `mv`, `cp`), ca testul sa nu depinda de alegerea ei.
        _stub(self.bin, "stat",
              'if [ -n "${FAKE_STAT_LIE_MODE:-}" ] && [ "${*: -1}" = "$VPSW_CONF" ] && [[ "$*" == *%a* ]]; then\n'
              '  echo "$FAKE_STAT_LIE_MODE"; exit 0\n'
              'fi\n'
              'if [ -n "${FAKE_RACE:-}" ] && [[ "${*: -1}" == *vps-watchdog.conf.* ]] && [ ! -e "$VPSW_CONF" ]; then\n'
              '  printf "%s" "$FAKE_RACE" > "$VPSW_CONF"\n'
              'fi\n'
              f'exec "{real_stat}" "$@"\n')

    def write_source(self, text: str) -> None:
        self.source.write_bytes(text.encode("utf-8"))

    def put_conf(self, text: str) -> None:
        self.conf.write_bytes(text.encode("utf-8"))

    def run(self, *args: str, env_extra: dict | None = None) -> Result:
        return self.run_argv(list(args) if args else ["--host", "gazda-test"], env_extra)

    def run_argv(self, argv: list[str], env_extra: dict | None = None) -> Result:
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        env.update({
            "NO_COLOR": "1",
            "FAKE_LOG": _msys(self.root) + "/ssh.log",
            "VPSW_CONF": _msys(self.etc) + "/vps-watchdog.conf",
            "VPSW_SOURCE": _msys(self.opt) + "/watchdog.sh",
            "VPSW_OWNER": self.owner,
        })
        env.update(env_extra or {})
        self.log.unlink(missing_ok=True)   # jurnalul unei rulari, nu al tuturor de pana acum
        (self.root / "ssh.log.sha").unlink(missing_ok=True)
        proc = subprocess.run([BASH, str(SCRIPT), *argv], capture_output=True, env=env,
                              cwd=str(self.root), timeout=120)
        return Result(proc, self)

    def etc_listing(self) -> list[str]:
        return sorted(p.name for p in self.etc.iterdir())


@pytest.fixture
def fx(tmp_path) -> Fx:
    return Fx(tmp_path / "fx")


def _md5(p: Path) -> str:
    return hashlib.md5(p.read_bytes()).hexdigest()


def _conf_mode(p: Path) -> str:
    # `umask 077` ca pe gazda unde ruleaza scriptul: pe o montare Git Bash `noacl` `stat` deduce
    # modul din umask-ul procesului (vezi nota de la testele cu conf gresit), deci aici aserțiunea
    # nu poate dovedi nimic despre disc; pe Linux o face.
    return subprocess.run([BASH, "-c", 'umask 077; stat -c "%a" "$1"', "_", _msys(p.parent) + "/" + p.name],
                          capture_output=True, text=True).stdout.strip()


# ===========================================================================
# Calea buna: ce ajunge pe gazda si ce dovedeste scriptul
# ===========================================================================

def test_it_writes_the_conf_the_installer_looks_for_and_proves_it_in_a_second_session(fx):
    """Fara fisierul asta deploy-ul doar avertizeaza si copia veche (RAM 400 MB) ruleaza
    mai departe. Aici: fisierul apare, cu cele trei domenii si EXCLUDE_AUTOFIX din scriptul
    vechi; are modul 600; `chown` a fost cerut pe temporar cu proprietarul asteptat; scriptul
    ruleaza sub sudo de DOUA ori (scriere, apoi o sesiune SEPARATA de verificare), si nu
    pune domeniile clientilor pe terminal - doar numarul si o amprenta."""
    r = fx.run()
    assert r.returncode == 0, r.text
    text = fx.conf.read_text(encoding="utf-8")
    assert f'HEALTH_DOMAINS="{" ".join(DOMAINS)}"\n' in text, text
    assert 'EXCLUDE_AUTOFIX="root-app-1"\n' in text, text
    assert _conf_mode(fx.conf) == "600"
    assert fx.etc_listing() == ["vps-watchdog.conf"], fx.etc_listing()
    assert r.modes == ["create", "verify"], r.log
    assert len(r.calls("SUDO -n bash")) == 2, r.log
    chowns = r.calls("CHOWN ")
    assert len(chowns) == 1 and fx.owner in chowns[0] and "vps-watchdog.conf." in chowns[0], r.log
    assert "3 domenii" in r.out and "scris si verificat" in r.out, r.out
    assert not any(d in r.text for d in DOMAINS), "domeniile clientilor au ajuns pe terminal"


def test_the_conf_it_writes_is_read_back_by_the_real_watchdog(fx, tmp_path):
    """Cel mai grav esec e tacut: fisierul arata bine, dar watchdog-ul il citeste altfel si
    nu verifica niciun domeniu. Aici scriptul real de pe gazda ruleaza pe conf-ul produs si
    se numara ce URL-uri atinge: exact /api/health pe cele trei domenii."""
    assert fx.run().returncode == 0
    h = tmp_path / "wd"
    (h / "bin").mkdir(parents=True)
    (h / "proc").mkdir()
    (h / "state").mkdir()
    (h / "calls").mkdir()
    (h / "secrets.env").write_bytes(b"")
    for name, body in {
        "hostname": "echo testhost\n", "date": 'echo 1000000\n', "nproc": "echo 4\n",
        "sleep": "exit 0\n", "df": "printf 'Use%%\\n 40%%\\n'\n",
        "timeout": 'shift; exec "$@"\n', "docker": "exit 1\n",
        "curl": 'for a in "$@"; do last="$a"; done\n'
                'case "$*" in *-K*) cat >/dev/null; exit 0;; esac\n'
                'echo "$last" >> "$CALLS/urls"; printf 200\n',
    }.items():
        _stub(h / "bin", name, body)
    (h / "proc" / "meminfo").write_bytes(b"MemAvailable:   4096000 kB\n")
    (h / "proc" / "loadavg").write_bytes(b"0.10 0.20 0.30 1/500 12345\n")
    (h / "proc" / "vmstat").write_bytes(b"pswpin 0\npswpout 0\noom_kill 0\n")
    env = dict(os.environ)
    env["PATH"] = f"{h / 'bin'}{os.pathsep}{env['PATH']}"
    env.update({"WATCHDOG_CONF": fx.conf.as_posix(), "WATCHDOG_SECRETS": (h / "secrets.env").as_posix(),
                "WATCHDOG_STATE_DIR": (h / "state").as_posix(), "WATCHDOG_PROC": (h / "proc").as_posix(),
                "CALLS": (h / "calls").as_posix()})
    p = subprocess.run([BASH, str(WATCHDOG)], capture_output=True, env=env, cwd=str(h), timeout=120)
    assert p.returncode == 0, p.stderr.decode()
    urls = (h / "calls" / "urls").read_text(encoding="utf-8").split()
    assert sorted(urls) == sorted(f"https://{d}/api/health" for d in DOMAINS), urls


def test_a_commented_decoy_or_a_look_alike_name_is_not_the_assignment(fx):
    """Scriptul vechi are `for d in $HEALTH_DOMAINS` si poate comentarii cu valori mai vechi.
    Daca scriptul de init ar lua prima aparitie a numelui, conf-ul ar primi domenii dintr-un
    comentariu sau din `OLD_HEALTH_DOMAINS` - site-uri verificate care nu mai exista, si
    cele reale neverificate."""
    fx.write_source(
        '# HEALTH_DOMAINS="zz-decoy.example.org"\n'
        'OLD_HEALTH_DOMAINS="zz-stale.example.org"\n'
        + _old_script())
    r = fx.run()
    assert r.returncode == 0, r.text
    text = fx.conf.read_text(encoding="utf-8")
    live = re.sub(r"^#.*$", "", text, flags=re.M)   # antetul numeste calea de test: doar liniile active
    assert "zz-decoy" not in live and "zz-stale" not in live, text
    assert f'HEALTH_DOMAINS="{" ".join(DOMAINS)}"' in text


def test_exclude_autofix_is_carried_only_when_the_old_script_sets_it(fx):
    """install.sh cere sa se preia HEALTH_DOMAINS si EXCLUDE_AUTOFIX. Un container pe care
    auto-remedierea n-are voie sa-l reporneasca nu poate depinde de o valoare implicita care se
    poate schimba intr-o versiune viitoare. Dar fara atribuire in scriptul vechi nu se
    inventeaza nimic: conf-ul n-are cheia, iar watchdog-ul foloseste implicitul."""
    fx.write_source(_old_script().replace('EXCLUDE_AUTOFIX="root-app-1"', "EXCLUDE_AUTOFIX_UNSET=1"))
    r = fx.run()
    assert r.returncode == 0, r.text
    text = fx.conf.read_text(encoding="utf-8")
    assert "EXCLUDE_AUTOFIX" not in re.sub(r"^#.*$", "", text, flags=re.M), text
    assert f'HEALTH_DOMAINS="{" ".join(DOMAINS)}"' in text and "EXCLUDE_AUTOFIX absent" in r.out, (text, r.out)


# ===========================================================================
# Nu suprascrie, nu minte despre ce a gasit
# ===========================================================================

def test_it_never_overwrites_an_existing_conf_even_one_it_would_have_written_differently(fx):
    """Un conf facut de mana poate avea praguri ajustate. Rularea repetata sau gresita nu are
    voie sa-l inlocuiasca. Scriptul vechi lipseste aici (sursa nu e citita deloc cand conf-ul
    exista), iar octetii raman identici, fara resturi langa el."""
    mine = 'HEALTH_DOMAINS="keep.example.org"\nMEM_AVAIL_MIN_MB=1500\n'
    fx.put_conf(mine)
    fx.source.unlink()
    before = _md5(fx.conf)
    r = fx.run()
    assert r.returncode == 0, r.text
    assert _md5(fx.conf) == before and fx.conf.read_text(encoding="utf-8") == mine
    assert fx.etc_listing() == ["vps-watchdog.conf"], fx.etc_listing()
    assert "exista deja" in r.out, r.out


def test_running_it_twice_is_safe_and_the_second_run_says_so(fx):
    """Operatorul poate rula scriptul de doua ori (o intrerupere, o neincredere). A doua
    rulare nu scrie nimic, nu da eroare, si spune ca fisierul exista - nu raporteaza o
    scriere pe care n-a facut-o."""
    first = fx.run()
    assert first.returncode == 0, first.text
    mtime, digest = fx.conf.stat().st_mtime_ns, _md5(fx.conf)
    second = fx.run()
    assert second.returncode == 0, second.text
    assert "exista deja" in second.out and "scris si verificat" not in second.out, second.out
    assert (fx.conf.stat().st_mtime_ns, _md5(fx.conf)) == (mtime, digest)
    assert fx.etc_listing() == ["vps-watchdog.conf"]


# Modul NU se poate fabrica aici: montarea Git Bash de pe Windows e `noacl`, deci `chmod` nu
# schimba nimic iar `stat` raporteaza modul din umask-ul procesului care il citeste. Cazul
# "citibil de oricine" foloseste de aceea `stat`-ul fals care minte despre mod; pe un Linux real
# acelasi caz se poate face cu un `chmod 644` adevarat.
@pytest.mark.parametrize("what,content,env,needle", [
    ("world_readable", 'HEALTH_DOMAINS="a.example.org"\n', {"FAKE_STAT_LIE_MODE": "644"}, "modul 644"),
    ("wrong_owner", 'HEALTH_DOMAINS="a.example.org"\n', {"VPSW_OWNER": "nimeni-asta:nimeni-asta"}, "proprietar"),
    ("empty_domains", 'HEALTH_DOMAINS=""\n', {}, "gol"),
    ("no_domains_key", "MEM_AVAIL_MIN_MB=1500\n", {}, "HEALTH_DOMAINS"),
    ("bad_token", 'HEALTH_DOMAINS="a.example.org $(x)"\n', {}, "nu arata a nume de gazda"),
])
def test_an_existing_conf_that_is_wrong_is_reported_and_left_alone(fx, what, content, env, needle):
    """Un conf deja prezent dar gresit (citibil de oricine; cu lista goala, care opreste
    verificarea site-urilor) nu se repara in tacere si nu se declara bun. Scriptul iese cu
    eroare, spune ce nu e in regula, NU il modifica, si spune ca trebuie reparat de mana."""
    fx.put_conf(content)
    before = _md5(fx.conf)
    r = fx.run(env_extra=env)
    assert r.returncode != 0, f"{what}: conf-ul gresit a fost declarat bun\n{r.text}"
    assert needle in r.text, (what, r.text)
    assert _md5(fx.conf) == before
    assert "de mana" in r.err, r.err


def test_a_conf_that_appears_between_the_check_and_the_publish_is_not_overwritten(fx):
    """Doua rulari (sau o rulare si operatorul) pot concura. Publicarea prin `ln` esueaza
    daca numele exista; un `mv` ar fi suprascris (iar `mv -n` ar fi iesit cu 0 fara sa mute).
    Aici un "alt proces" scrie conf-ul chiar inainte de publicare (la ultima citire a
    temporarului, indiferent cu ce comanda publica scriptul): continutul lui trebuie sa
    ramana intact, scriptul sa raporteze ca exista deja (si, fiind gol de HEALTH_DOMAINS, sa
    iasa cu eroare), iar temporarul sa dispara."""
    r = fx.run(env_extra={"FAKE_RACE": "scris de altcineva\n"})
    assert fx.conf.read_text(encoding="utf-8") == "scris de altcineva\n"
    assert r.returncode != 0, r.text
    assert fx.etc_listing() == ["vps-watchdog.conf"], fx.etc_listing()
    assert "exista deja" in r.out and "de mana" in r.err, r.text


# ===========================================================================
# Refuza sa scrie un conf care opreste in tacere verificarea site-urilor
# ===========================================================================

@pytest.mark.parametrize("name,source,needle", [
    ("empty_value", _old_script(""), "gol"),
    ("blank_value", _old_script("   "), "gol"),
    ("no_assignment", "#!/usr/bin/env bash\nAUTO_FIX=1\n", "nicio atribuire"),
    ("two_assignments", _old_script() + 'HEALTH_DOMAINS="x.example.org"\n', "2 atribuiri"),
    ("only_in_a_comment", '# HEALTH_DOMAINS="a.example.org"\nAUTO_FIX=1\n', "nicio atribuire"),
    ("unquoted", "HEALTH_DOMAINS=a.example.org\n", "nicio atribuire"),
    ("not_a_hostname", _old_script("good.example.org not a host!"), "nu arata a nume de gazda"),
    ("leading_dash", _old_script("good.example.org -oProxyCommand"), "nu arata a nume de gazda"),
    ("two_excludes", _old_script() + 'EXCLUDE_AUTOFIX="x"\n', "EXCLUDE_AUTOFIX"),
])
def test_it_refuses_to_write_a_conf_without_usable_domains(fx, name, source, needle):
    """O lista goala NU esueaza nimic: dezactiveaza in tacere singura verificare care priveste
    site-urile clientilor, iar watchdog-ul ramane "sanatos". La fel o atribuire ambigua (care
    din doua?) sau un element care nu e un nume de gazda. In toate cazurile: eroare tare, cu
    motivul, si NIMIC scris - nici conf, nici temporar. Martorul pozitiv e testul de pe
    calea buna: aceeasi gazda cu o sursa valida scrie fisierul."""
    fx.write_source(source)
    r = fx.run()
    assert r.returncode != 0, f"{name}: a iesit cu 0\n{r.text}"
    assert needle in r.err, (name, r.err)
    assert fx.etc_listing() == [], (name, fx.etc_listing())


def test_the_old_script_is_data_and_never_executed(fx, tmp_path):
    """Scriptul vechi ruleaza ca root pe gazda; un domeniu cu `$(...)` sau backtick in el nu
    are voie sa fie evaluat de scriptul de init. Se citeste ca text, se valideaza token cu
    token si se refuza. Marcajul nu trebuie sa apara."""
    marker = _msys(tmp_path) + "/PWNED"
    fx.write_source(_old_script(f"ok.example.org $(touch {marker}) `touch {marker}`"))
    r = fx.run()
    assert r.returncode != 0, r.text
    assert not (tmp_path / "PWNED").exists(), "continutul scriptului vechi a fost executat"
    assert fx.etc_listing() == []


def test_a_missing_old_script_is_a_hard_stop(fx):
    """Fara scriptul vechi nu are de unde sa ia domeniile (de pilot, dupa un deploy care l-a
    inlocuit deja). Nu inventeaza o lista si nu scrie un conf gol."""
    fx.source.unlink()
    r = fx.run()
    assert r.returncode != 0 and "nu pot citi" in r.err, r.text
    assert fx.etc_listing() == []


# ===========================================================================
# --dry-run, conexiune, verificare
# ===========================================================================

def test_dry_run_reads_and_validates_but_writes_nothing(fx):
    """"Arata-mi ce ai scrie" nu are voie sa scrie. Se verifica efectul (directorul ramas
    gol, o singura sesiune ssh in modul `plan`), nu doar mesajul."""
    r = fx.run("--host", "gazda-test", "--dry-run")
    assert r.returncode == 0, r.text
    assert fx.etc_listing() == [], fx.etc_listing()
    assert r.modes == ["plan"], r.log
    assert "3 domenii" in r.out and "nimic nu a fost scris" in r.out, r.out
    fx.write_source("AUTO_FIX=1\n")
    no_domains = fx.run("--host", "gazda-test", "--dry-run")
    assert no_domains.returncode != 0, "dry-run a trecut peste o sursa fara domenii"
    assert fx.etc_listing() == []


@pytest.mark.parametrize("failure,needle", [
    ("FAKE_SSH_FAIL", "verdict"),
    ("FAKE_SUDO_FAIL", "verdict"),
    ("FAKE_SUDO_SILENT", "verdict"),   # iese cu 0 si nu spune nimic: zero iesire cu cod 0
])
def test_a_host_that_gives_no_verdict_is_a_failure_not_a_quiet_pass(fx, failure, needle):
    """Un ssh refuzat, un sudo care cere parola si un script de la distanta mort arata la fel:
    zero iesire. Zero iesire nu inseamna "nimic de raportat". Scriptul iese cu eroare si
    spune ce a zis ssh/sudo; nu scrie nimic."""
    r = fx.run(env_extra={failure: "1"})
    assert r.returncode != 0, r.text
    assert needle in r.err, r.err
    assert fx.etc_listing() == []


def test_the_wrong_owner_is_caught_before_the_file_gets_its_real_name(fx):
    """Un conf pe care nu-l poate citi sau scrie cine trebuie, aflat in locul gresit, ar fi
    adoptat de install.sh. `chown` poate iesi cu 0 fara efect (aici e un fals care nu face
    nimic): proprietarul REAL al temporarului se citeste inapoi si, daca nu e cel cerut,
    fisierul nu primeste numele final."""
    r = fx.run(env_extra={"VPSW_OWNER": "nimeni-asta:nimeni-asta"})
    assert r.returncode != 0, r.text
    assert fx.etc_listing() == [], fx.etc_listing()
    assert "nu-l public" in r.err, r.err


def test_the_verification_reads_the_disk_not_what_the_write_intended(fx):
    """Verificarea face o sesiune noua si citeste fisierul de pe disc. Aici `stat` minte
    exclusiv despre numele final (modul 644) dupa ce scrierea a reusit: scriptul trebuie sa
    iasa cu eroare, sa spuna "NU face deploy" si sa lase fisierul pentru inspectie. Fara
    sesiunea separata, "am scris cu modul 600" ar fi trecut drept dovada."""
    r = fx.run(env_extra={"FAKE_STAT_LIE_MODE": "644"})
    assert r.returncode != 0, r.text
    assert "modul 644" in r.err and "NU face deploy" in r.err, r.err
    assert fx.conf.exists(), "fisierul scris trebuia lasat pentru inspectie, nu sters pe tacute"
    assert r.modes == ["create", "verify"], r.log


def test_a_publish_that_exits_zero_without_effect_is_caught_by_the_readback(fx):
    """Exact tiparul de aici: `augenrules --load 2>/dev/null` a raportat "instalat" in
    /dev/null. Aici `ln` iese cu 0 fara sa faca legatura, deci scrierea "a reusit" iar fisierul
    nu exista. Sesiunea separata de verificare il cauta pe disc, nu in codul de iesire, si
    scriptul iese cu eroare si spune "NU exista" - nu "scris si verificat"."""
    r = fx.run(env_extra={"FAKE_LN_NOOP": "1"})
    assert r.returncode != 0, r.text
    assert "NU exista" in r.err and "scris si verificat" not in r.out, r.text
    assert not fx.conf.exists()


def test_what_is_read_back_must_be_what_was_written(fx):
    """Un fisier cu alte domenii decat cele citite din scriptul vechi (scriere partiala, alt
    proces) ar activa watchdog-ul pe o lista gresita. Numarul si amprenta citite inapoi se
    compara cu cele derivate la scriere; aici amprenta de la citire nu mai coincide."""
    r = fx.run(env_extra={"FAKE_DIGEST_LIE": "1"})
    assert r.returncode != 0, r.text
    assert "nu coincid cu cele scrise" in r.err and "NU face deploy" in r.err, r.err


def test_a_carried_exclude_list_that_is_missing_after_the_write_is_caught(fx):
    """EXCLUDE_AUTOFIX numeste containerele pe care auto-remedierea n-are voie sa le
    reporneasca. Daca domeniile ajung in conf dar lista de excluderi nu, watchdog-ul ar
    reporni ca root un container pe care operatorul il excluse. Cheia preluata din scriptul
    vechi trebuie sa existe in fisierul citit inapoi."""
    r = fx.run(env_extra={"FAKE_KEYS_DROP": "EXCLUDE_AUTOFIX"})
    assert r.returncode != 0, r.text
    assert "EXCLUDE_AUTOFIX trebuia preluat" in r.err, r.err


def test_a_second_name_on_an_existing_conf_is_reported(fx):
    """Un al doilea nume pe disc (o copie facuta cu `ln`, un temporar ramas) inseamna ca
    fisierul poate fi schimbat prin alta cale decat cea pe care o verifica operatorul."""
    fx.put_conf('HEALTH_DOMAINS="a.example.org"\n')
    os.link(fx.conf, fx.etc / "vps-watchdog.conf.old")
    r = fx.run()
    assert r.returncode != 0 and "nume pe disc" in r.err, r.text


def test_ssh_options_reach_ssh_and_a_missing_port_is_not_invented(fx):
    """Pe gazda reala operatorul foloseste un alias din fisierul lui de configurare ssh.
    `-p 22` pus implicit ar suprascrie un Port din acel fisier si ar face conexiunea sa ajunga
    la alt serviciu; `-F`, `-i` si `user@` trebuie sa ajunga la ssh. Niciun port daca nu s-a dat unul."""
    key = fx.root / "id_test"
    key.write_bytes(b"x")
    r = fx.run("--host", "contabo", "--user", "operator", "--key", _msys(fx.root) + "/id_test",
               "--ssh-config", "/some/ssh_config")
    assert r.returncode == 0, r.text
    sess = r.calls("SSH ")
    assert sess, r.log
    for line in sess:
        assert "-F /some/ssh_config" in line and "-i " in line and "operator@contabo" in line, line
        assert "-p " not in line, line
    with_port = fx.run("--host", "contabo", "--port", "2222")
    assert all("-p 2222" in l for l in with_port.calls("SSH ")), with_port.log


@pytest.mark.parametrize("args", [
    ["--host", "-oProxyCommand=x"], ["--host", "-V"], ["--host", "a b"], ["--host", "h", "--user", "-x"],
    ["--host", "h", "--port", "22; id"], [], ["--host", "h", "--bogus"],
])
def test_bad_arguments_are_refused_before_any_ssh(fx, args):
    """Un --host care incepe cu `-` ar fi citit de ssh ca optiune (ProxyCommand = executie de
    comenzi locale); un argument necunoscut nu se ignora. Nicio sesiune ssh nu porneste."""
    r = fx.run_argv(args)
    assert r.returncode != 0, r.text
    assert r.calls("SSH ") == [], r.log


# ===========================================================================
# Livrabilul: in depozit, public
# ===========================================================================

_DOTTED = re.compile(r"\b[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\b")
_OK_SUFFIX = {"sh", "conf", "env", "example", "service", "timer", "py", "tmp", "exe", "md"}


def _hostlike(text: str) -> list[str]:
    bad = []
    for tok in _DOTTED.findall(text):
        last = tok.rsplit(".", 1)[1]
        if (tok.endswith((".example.org", ".example.com", ".example.net")) or last in _OK_SUFFIX
                or last.isdigit() or tok == "A-Za-z0-9._"):
            continue
        bad.append(tok)
    return bad


def test_no_real_hostname_is_committed_in_the_script():
    """Domeniile sunt ale clientilor operatorului, iar depozitul e public. Scriptul le citeste
    de pe gazda la rulare; nu are voie sa contina niciunul. Garda pica la orice token `a.b`
    care nu e un nume de fisier cunoscut sau o gazda fictiva; martorul pozitiv de mai jos
    arata ca garda chiar prinde un domeniu."""
    assert _hostlike("x shop.client-corp.ro y") == ["shop.client-corp.ro"]
    assert _hostlike("app.example.org vps-watchdog.conf") == []
    for path in (SCRIPT, REMOTE):
        found = _hostlike(path.read_text(encoding="utf-8"))
        assert found == [], f"{path.name} contine nume care arata a gazda reala: {found}"


def test_the_example_lists_every_key_the_script_writes():
    """Sablonul din deploy/config e ce citeste operatorul care face conf-ul de mana. Daca
    scriptul scrie o cheie pe care sablonul n-o cunoaste (sau invers), cele doua cai spre
    acelasi fisier se desprind. Cheile scrise sunt luate DIN script, nu retastate aici."""
    script = REMOTE.read_text(encoding="utf-8")
    written = set(re.findall(r"printf '([A-Z][A-Z0-9_]*)=\"%s\"\\n'", script))
    assert {"HEALTH_DOMAINS", "EXCLUDE_AUTOFIX"} <= written, written
    example = CONF_EXAMPLE.read_text(encoding="utf-8")
    for key in written:
        assert re.search(rf"^#?{key}=", example, re.M), f"{key} lipseste din {CONF_EXAMPLE.name}"
    assert re.search(r"^HEALTH_DOMAINS=", example, re.M), "HEALTH_DOMAINS trebuie sa fie activ in sablon"


def _conf_get_awk(text: str) -> str:
    m = re.search(r"conf_get\(\)\{.*?awk -v k=\"\$2\" -v q=\"'\" '(.*?)\}' \"\$1\"", text, re.S)
    assert m, "conf_get nu a fost gasit"
    return m.group(1)


def test_the_read_back_parses_the_conf_exactly_like_the_watchdog():
    """Verificarea de pe gazda citeste conf-ul cu un `conf_get` copiat. Daca s-ar desprinde de
    cel din watchdog.sh (alte reguli pentru ghilimele, comentarii, ultima aparitie), scriptul ar
    declara "bine" un fisier pe care watchdog-ul il citeste altfel - tocmai defectul pe care
    citirea inapoi trebuie sa-l prinda. Programele awk sunt comparate ca text."""
    a = _conf_get_awk(REMOTE.read_text(encoding="utf-8"))
    b = _conf_get_awk(WATCHDOG.read_text(encoding="utf-8"))
    assert a.strip() and a == b, "conf_get din scriptul de init difera de cel din watchdog.sh"


def test_the_script_parses_and_is_lf_only():
    """Un CR in shebang opreste scriptul cu "bad interpreter" inainte de orice mesaj."""
    for path in (SCRIPT, REMOTE):
        assert b"\r" not in path.read_bytes(), path.name
        out = subprocess.run([BASH, "-n", str(path)], capture_output=True)
        assert out.returncode == 0, (path.name, out.stderr.decode())
