"""Depozitul e public. Nimic din infrastructura reală nu are voie să ajungă în el.

Regula nu e despre jenă, e despre ce câștigă cineva citind. Un depozit de
securitate spune deja, exact, ce se monitorizează și cum. Adăugând adrese,
domenii și nume de utilizator, spune și PE CINE — iar recunoașterea, care e
partea scumpă a unui atac, devine gratuită.

Cazul cel mai important e domeniul martorului extern. E singura mașină pe care
un atacator cu root pe serverul monitorizat NU o controlează, deci e primul
lucru pe care ar vrea să-l afle: unde pleacă semnalul a cărui absență îl dă de
gol. A stat într-un fișier de documentație până a fost observat.

Testul rulează peste tot ce ar ajunge într-un push — urmărit sau
neurmărit-și-neignorat — și peste ambele versiuni ale fiecărui fișier, cea de pe
disc și cea din index. Depinde de `git`; fără el ar trece în tăcere, deci lipsa
lui e eșec.

## Limita cunoscută: UTF-16

Un fișier scris în UTF-16 (PowerShell 5.1 face asta la redirectare) se decodează
ca octeți intercalați cu NUL, deci o adresă IP din el nu se mai potrivește.
Scris aici fiindcă o limită nedocumentată e cea care mușcă: verificarea nu
raportează nimic, iar tăcerea ei arată identic cu „e curat".
"""

from __future__ import annotations

import functools
import re
import shutil
import subprocess
from pathlib import Path

import pytest

# Poarta documentata in docs/TESTARE.md e `pytest -m security`. Fisierul vecin
# a primit marcajul in aceeasi runda; asta, care apara scurgerea de
# infrastructura, ramasese fara.
pytestmark = pytest.mark.security

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


def _git(*args: str) -> list[str]:
    r"""Cai, despartite pe NUL.

    Fara `-z`, git citeaza numele non-ASCII: `docs/raport\304\203ri.md`. Calea
    aia nu exista pe disc, iar verificarea o sarea in tacere — intr-un depozit cu
    documentatie in romana, o chestiune de timp.
    """
    # `encoding="utf-8"` explicit, nu `text=True`: acela decodeaza cu
    # codificarea LOCALA (cp1252 pe Windows), deci o cale cu diacritice iese
    # stricata, fisierul „nu exista", iar verificarea il sarea in tacere. Git
    # da octeti UTF-8; ii citim ca atare.
    # `errors="replace"`, nu decodare stricta. Pe Windows, `subprocess` cu
    # `encoding=` decodeaza intr-un FIR separat; un UnicodeDecodeError acolo moare
    # tacut si `stdout` devine None cu `returncode=0`. Rezultatul ar fi
    # `None.split()`, adica o eroare fara legatura cu ce s-a intamplat.
    out = subprocess.run(["git", *args, "-z"], cwd=REPO, capture_output=True,
                         encoding="utf-8", errors="replace", check=True)
    return [p for p in (out.stdout or "").split(chr(0)) if p]


@functools.lru_cache(maxsize=None)
def _contents(rel: str) -> list[tuple[str, str]]:
    """TOATE versiunile care s-ar putea publica: discul SI indexul.

    `git commit` fara `-a` scrie INDEXUL. O versiune anterioara citea discul
    daca fisierul exista acolo, si cadea pe index doar cand nu exista — ceea ce
    face garda sa verifice o versiune in timp ce git publica alta.

    Fluxul care produce dezastrul nu e exotic; e chiar cel pe care depozitul il
    documenteaza ca reactie la o scurgere: `git add -A`, garda pica, editezi
    fisierul ca sa scoti adresa, rulezi din nou — verde — si comiti blobul vechi,
    deja pus in index. E mai rau decat lipsa garzii: da confirmarea exact in
    clipa in care omul crede ca a reparat.

    Deci nu alegem intre surse. Le citim pe amandoua, si le numim, ca mesajul de
    eroare sa spuna UNDE e problema.
    """
    # Rezultatul se cachează: fiecare fișier e citit de patru teste, iar un
    # `git show` per fișier per test însemna ~1330 de procese și dubla durata
    # suitei. `lru_cache` hash-uieste ARGUMENTELE, nu valoarea intoarsa, deci
    # lista se poate intoarce ca atare — o versiune anterioara o convertea in
    # tuplu „ca sa fie hashable", ceea ce era o neintelegere.
    out: list[tuple[str, str]] = []
    path = REPO / rel
    if path.is_file():
        try:
            # `errors="replace"` si aici, a treia locatie de decodare.
            #
            # O reparatie anterioara a pus-o la enumerare si la citirea din
            # index, si a sarit peste asta. Efectul: un fisier editat intr-un
            # editor cp1252 — scenariul numit chiar de comentariul de mai sus —
            # crapa la decodare, `except: pass` inghitea, si ramanea DOAR
            # versiunea din index. Adica exact versiunea curata, in timp ce
            # arborele de lucru continea adresa reala. Lista nu era goala, deci
            # nici garda de necitibilitate nu observa.
            out.append(("disc", path.read_bytes().decode("utf-8", errors="replace")))
        except OSError:
            pass
    # `errors="replace"` si verificare pe stdout, nu doar pe returncode.
    #
    # Un blob binar din index — `.ttf`, `.whl`, `.pcapng`, extensii pe care
    # `.gitattributes` le stie binare dar `SKIP_SUFFIX` nu le are — producea
    # `("index", None)` cu returncode 0. Lista nu era goala, deci
    # `test_every_enumerated_file_can_be_read` declara fisierul citit, iar
    # celelalte trei garzi crapau cu AttributeError in loc de mesajul lor.
    #
    # Cu `replace`, un binar devine text cu caractere de inlocuire — si atat mai
    # bine: o adresa IP scrisa in ASCII in interiorul unui binar ramane
    # gasibila, ceea ce sarind fisierul nu era.
    staged = subprocess.run(["git", "show", f":{rel}"], cwd=REPO, capture_output=True,
                            encoding="utf-8", errors="replace")
    if (staged.returncode == 0 and staged.stdout is not None
            and not any(t == staged.stdout for _, t in out)):
        out.append(("index", staged.stdout))
    return out


def _tracked_files() -> list[str]:
    """Tot ce ar ajunge intr-un push: urmarit SAU neurmarit-si-neignorat.

    Prima versiune enumera doar `git ls-files`, adica doar fisierele deja
    urmarite. Asta face garda sa anunte scurgerea abia DUPA ce a intrat in
    istoric — momentul in care „elimin-o" nu mai e o optiune.

    A costat imediat: un fisier de definitie de agent, scris cu adresa reala a
    serverului, utilizatorul SSH si numele cheii, statea neurmarit intr-un
    director urmarit. Urmatorul `git add` l-ar fi dus in depozitul public, iar
    garda ar fi tacut pana atunci.

    `--others --exclude-standard` adauga exact ce ar prinde un `git add -A`, si
    respecta `.gitignore` — un fisier ignorat constient ramane in afara
    verificarii, ceea ce e corect: acolo stau secretele, dinadins.
    """
    rels: list[str] = []
    for args in (("ls-files",), ("ls-files", "--others", "--exclude-standard")):
        for rel in _git(*args):
            if rel.startswith(SKIP_PREFIX) or Path(rel).suffix.lower() in SKIP_SUFFIX:
                continue
            rels.append(rel)
    return rels


@pytest.mark.skipif(shutil.which("git") is None, reason="")
def test_every_enumerated_file_can_be_read() -> None:
    """O cale care nu poate fi citita nu poate fi verificata.

    `_content` intorcea None si apelantii treceau mai departe — adica exact
    bifa verde care nu s-a uitat la nimic. Un fisier binar are extensia
    exclusa; orice altceva neciteibil e o gaura in acoperire, si trebuie sa se
    vada ca atare.
    """
    unreadable = [rel for rel in _tracked_files() if not _contents(rel)]
    assert not unreadable, (
        "fisiere enumerate dar necitibile, deci neverificate: "
        + ", ".join(unreadable[:10]))


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

    me = Path(__file__).relative_to(REPO).as_posix()
    for rel in _tracked_files():
        if rel.startswith("tests/") or rel == me or rel in EXEMPT:
            continue
        for source, text in _contents(rel):
            for line_no, line in enumerate(text.splitlines(), 1):
                for rx, why in compiled:
                    m = rx.search(line)
                    if m:
                        offenders.append(
                            f"{rel}:{line_no} ({source}): {m.group(0)[:40]} — {why}")

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

    for rel in _tracked_files():
        if rel == me:
            continue
        for source, text in _contents(rel):
            for line_no, line in enumerate(text.splitlines(), 1):
                for rx, why in compiled:
                    if rx.search(line):
                        offenders.append(f"{rel}:{line_no} ({source}) — {why}")

    assert not offenders, "posibile secrete în depozitul public:\n  " + "\n  ".join(offenders[:20])


def test_the_witness_domain_is_not_named_anywhere() -> None:
    """Cea mai valoroasă informație pentru cineva care a luat serverul.

    Semnalul care pleacă spre martor e ce îl dă de gol. Aflând unde pleacă,
    poate încerca să-l blocheze înainte să facă orice altceva. Verificarea e
    separată de cea de mai sus fiindcă mesajul de eșec trebuie să spună exact
    asta, nu „un tipar a fost găsit".
    """
    # Orice `sentinel.<ceva>.<tld>` care NU e un substituent evident. Nu pot
    # enumera domeniul real fara sa-l scriu aici, deci regula e inversa: se
    # accepta doar numele despre care se vede din citire ca sunt exemple.
    #
    # Enumerarea e aceeasi ca mai sus, NU `git grep`. Prima versiune folosea
    # `git grep`, care se uita doar la fisierele urmarite — adica exact defectul
    # reparat in `_tracked_files`, lasat intact in verificarea pe care
    # docstring-ul modulului o numeste „cazul cel mai important".
    PLACEHOLDERS = ("exemplu", "example", "exemple", "test", "localhost", "invalid")
    me = Path(__file__).relative_to(REPO).as_posix()
    rx = re.compile(r"sentinel\.([a-z0-9-]+)\.(?:eu|ro|com|net|dev|io)(?![a-z0-9.-])",
                    re.IGNORECASE)
    hits = []
    for rel in _tracked_files():
        if rel == me:
            continue
        for source, text in _contents(rel):
            for m in rx.finditer(text):
                if m.group(1).lower() not in PLACEHOLDERS:
                    hits.append(f"{rel} ({source}): {m.group(0)}")
                    break

    assert not hits, (
        "domeniul martorului extern apare în: " + ", ".join(hits)
        + "\n  E singura mașină pe care un atacator cu root pe gazda monitorizată "
          "nu o controlează. Un depozit public nu e locul unde să afle unde e.")
