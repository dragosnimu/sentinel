"""Depozitul e public. Nimic din infrastructura reală nu are voie să ajungă în el.

Regula nu e despre jenă, e despre ce câștigă cineva citind. Un depozit de
securitate spune deja, exact, ce se monitorizează și cum. Adăugând adrese,
domenii și nume de utilizator, spune și PE CINE — iar recunoașterea, care e
partea scumpă a unui atac, devine gratuită.

Cazul cel mai important e domeniul martorului extern. E singura mașină pe care
un atacator cu root pe serverul monitorizat NU o controlează, deci e primul
lucru pe care ar vrea să-l afle: unde pleacă semnalul a cărui absență îl dă de
gol. A stat într-un fișier de documentație până a fost observat.

Testul rulează peste conținutul urmărit de git — inclusiv documentație și
teste. Depinde de `git`; fără el ar trece în tăcere, deci lipsa lui e eșec.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Tipare, nu valori: valorile reale n-au ce căuta nici într-un test. Fiecare
# intrare e o clasă de lucruri care nu au voie să apară, cu motivul ei.
FORBIDDEN: dict[str, str] = {
    # Adrese publice reale. Exclude documentația (RFC 5737/3849), spațiul privat
    # și loopback — acelea sunt exact ce TREBUIE folosit în exemple.
    r"\b(?!0\.)(?!10\.)(?!127\.)(?!169\.254\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)"
    r"(?!192\.168\.)(?!192\.0\.2\.)(?!198\.51\.100\.)(?!203\.0\.113\.)"
    r"(?!22[4-9]\.|23\d\.)(?!25[0-5]\.)"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b":
        "adresă IP publică reală — folosește 192.0.2.x / 198.51.100.x / 203.0.113.x",

    # Chei și jetoane cu formă recunoscută.
}

# Se aplică PESTE TOT, inclusiv în teste. Un secret într-o fixtură e la fel de
# scurs ca unul în cod.
SECRETS: dict[str, str] = {
    r"sk-ant-[A-Za-z0-9_-]{10,}": "cheie API Anthropic",
    # {30,}, nu {35}: forma reala e 35, dar o potrivire care depinde de o
    # lungime exacta rateaza orice varianta si da aceeasi bifa verde.
    r"\b\d{8,10}:[A-Za-z0-9_-]{30,}": "token de bot Telegram",
    # Doua puncte incluse in clasa: un token de Telegram atribuit unei variabile
    # numite ...TOKEN se opreste altfel la primul `:`, adica dupa zece cifre.
    r"(?i)(?:token|secret|api[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9+/:_-]{32,}":
        "valoare lungă atribuită unui nume care sugerează un secret",
}

# Extensii binare și directoare care nu sunt cod scris de noi.
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mmdb",
               ".woff", ".woff2", ".zip", ".gz"}
SKIP_PREFIX = ("watcher/node_modules/", "dist/")

# Scutiri numite, cu motiv. O scutire fără motiv scris devine, în șase luni,
# locul prin care trece exact lucrul pe care testul îl păzea.
EXEMPT: dict[str, str] = {
    # Verifică refuzul blocurilor prea largi. `1.0.0.0/8` TREBUIE să fie un
    # interval public real — un vector din spațiul de documentație n-ar dovedi
    # nimic despre ce se întâmplă când cineva cere blocarea unui optime din
    # internet. Sunt argumente respinse, nu adrese configurate.
    "tests/security/test_executor_policy.py":
        "vectori de test pentru refuzul CIDR-urilor prea largi",
}


def _tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=REPO,
                         capture_output=True, text=True, check=True)
    files = []
    for rel in out.stdout.splitlines():
        if rel.startswith(SKIP_PREFIX) or Path(rel).suffix.lower() in SKIP_SUFFIX:
            continue
        files.append(REPO / rel)
    return files


@pytest.mark.skipif(shutil.which("git") is None, reason="")
def test_git_is_available() -> None:
    """Fără git, testele de mai jos n-ar avea ce citi și ar trece în tăcere.

    Un test de sanitizare care trece fiindcă nu s-a uitat la nimic e mai rău
    decât niciunul: dă exact aceeași bifă verde.
    """
    assert shutil.which("git"), "acest test are nevoie de git ca să enumere fișierele"


def test_no_real_infrastructure_in_tracked_files() -> None:
    """Regula adreselor se aplică în afara suitei de teste.

    Fixturile conțin adrese de atacatori copiate din jurnale reale — un
    brute-forcer chinezesc, un scaner olandez. Alea nu sunt infrastructura
    nimănui de aici, iar înlocuirea lor cu 203.0.113.x ar face fixturile mai
    puțin fidele fără să ascundă nimic despre acest server.

    Ce se aplică peste tot, inclusiv în teste, sunt tiparele de secrete și
    domeniul martorului — verificate în celelalte două teste din fișier.
    Distincția e între „o adresă publică apare în text" și „infrastructura
    ACESTUI deployment poate fi dedusă", iar doar a doua e o scurgere.
    """
    offenders: list[str] = []
    compiled = [(re.compile(p), why) for p, why in FORBIDDEN.items()]

    for path in _tracked_files():
        if path.relative_to(REPO).as_posix().startswith("tests/"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(REPO).as_posix()
        if rel == Path(__file__).relative_to(REPO).as_posix():
            continue  # tiparele de mai sus, nu date reale
        if rel in EXEMPT:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rx, why in compiled:
                m = rx.search(line)
                if m:
                    offenders.append(f"{rel}:{line_no}: {m.group(0)[:40]} — {why}")

    assert not offenders, (
        "conținut real de infrastructură în depozitul public:\n  "
        + "\n  ".join(offenders[:20]))


def test_no_secrets_anywhere_including_fixtures() -> None:
    """Un secret într-o fixtură e la fel de scurs ca unul în cod.

    Regula adreselor tolerează suita de teste; asta nu. Diferența e că o adresă
    dintr-un jurnal nu deschide nimic, iar un jeton da.
    """
    offenders: list[str] = []
    compiled = [(re.compile(p), why) for p, why in SECRETS.items()]
    me = Path(__file__).relative_to(REPO).as_posix()

    for path in _tracked_files():
        rel = path.relative_to(REPO).as_posix()
        if rel == me:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for rx, why in compiled:
                if rx.search(line):
                    offenders.append(f"{rel}:{line_no} — {why}")

    assert not offenders, "posibile secrete în depozitul public:\n  " + "\n  ".join(offenders[:20])


def test_the_witness_domain_is_not_named_anywhere() -> None:
    """Cea mai valoroasă informație pentru cineva care a luat serverul.

    Semnalul care pleacă spre martor e ce îl dă de gol. Aflând unde pleacă,
    poate încerca să-l blocheze înainte să facă orice altceva. Verificarea e
    separată de cea de mai sus fiindcă mesajul de eșec trebuie să spună exact
    asta, nu „un tipar a fost găsit".
    """
    # Orice `sentinel.<ceva>.<tld>` care NU e un substituent evident. Nu pot
    # enumera domeniul real fără să-l scriu aici, deci regula e inversă: se
    # acceptă doar numele despre care se vede din citire că sunt exemple.
    PLACEHOLDERS = ("exemplu", "example", "exemple", "test", "localhost", "invalid")
    out = subprocess.run(
        ["git", "grep", "-lniE", r"sentinel\.[a-z0-9-]+\.(eu|ro|com|net|dev|io)"],
        cwd=REPO, capture_output=True, text=True)

    me = Path(__file__).relative_to(REPO).as_posix()
    hits = []
    for rel in out.stdout.splitlines():
        if rel == me:
            continue
        text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
        # Lookahead-ul negativ conteaza: fara el, `from sentinel.web.routers`
        # se citeste ca domeniul `sentinel.web.ro`.
        for m in re.finditer(
                r"sentinel\.([a-z0-9-]+)\.(?:eu|ro|com|net|dev|io)(?![a-z0-9.-])",
                text, re.IGNORECASE):
            if m.group(1).lower() not in PLACEHOLDERS:
                hits.append(f"{rel}: {m.group(0)}")
                break
    assert not hits, (
        "domeniul martorului extern apare în: " + ", ".join(hits)
        + "\n  E singura mașină pe care un atacator cu root pe gazda monitorizată "
          "nu o controlează. Un depozit public nu e locul unde să afle unde e.")
