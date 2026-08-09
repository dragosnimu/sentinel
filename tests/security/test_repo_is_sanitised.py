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

## Limita cunoscută: verificarea pe valoare are nevoie de magazia locală

`test_no_value_from_the_local_secret_store_appears_in_the_tree` compară arborele
cu valorile reale din `secrets/.env.local` — fișier ignorat de git, deci absent
pe o clonă proaspătă. Acolo testul se raportează SKIP, nu verde: „n-am putut
verifica" și „e curat" sunt stări diferite.

`addopts` din `pyproject.toml` conține `-rfEs` tocmai ca MOTIVUL skip-ului să
apară. Fără el, tot semnalul pe o altă mașină era cifra „1 skipped" dintr-o linie
de sumar — adică o propoziție scrisă cu grijă pe care n-o citea nimeni.

`-rfEs`, nu `-rs`: `-r` ÎNLOCUIEȘTE lista implicită (`fE`), deci un `-rs` singur
ar fi ascuns liniile „FAILED ...". Scris și aici, nu doar în `pyproject.toml`,
fiindcă un comentariu rămas în urmă e cum se reintroduce un bug reparat: cineva
aliniază configurația la el.

Pe mașina de pe care pleacă push-ul fișierul există. Nimic nu IMPUNE însă ca
push-ul să plece de acolo: nu e instalat niciun hook (`.git/hooks` are doar
`.sample`), `core.hooksPath` nu e setat. Garanția e disciplina operatorului, nu
un mecanism — scris aici fiindcă o garanție presupusă e cea care cedează.

Consecința: `pytest -m security` poate arăta un skip pe o mașină fără secrete,
deși `README.md` și `docs/TESTARE.md` cer ca testele de securitate să nu fie
sărite. Skip-ul spune exact ce nu s-a verificat; alternativa — să treacă verde
fără să se uite la nimic — e chiar tiparul pe care fișierul ăsta îl păzește.

## De ce NU există o verificare „numărul ăsta pare un chat id"

A existat una, o rundă: un număr lipit de un nume care conține „chat", acceptat
doar dacă era o fixtură cunoscută. Măsurată pe forme realiste, rata ei de ratare
a fost 21 din 28 — un indice (`allowed_chat_ids[0] == <id>`), un sufix
(`chat_id_2`), un argument pozițional (`send_message(<id>, ...)`), un id scris
ÎNAINTEA cuvântului, un nume fără „chat" în el (`TELEGRAM_OWNER_ID`), un antet de
tabel `psql` cu valoarea pe rândul de sub. Iar alarma falsă: 17 din 19 linii
legitime — `"chat_last_seen": <timestamp>`, `CHAT_HISTORY_MAX_BYTES`,
`SELECT chat_id ... WHERE created_at > <timestamp>`, până și `chat_id = 1000000`,
adică exact pragul pe care comentariul ei îl declara inofensiv.

Cauza nu e o expresie regulată prost scrisă, e că un chat id nu are formă
proprie: zece cifre, nedeosebite de un timestamp, de un port sau de o dimensiune.
Cele două erori nu pot scădea simultan — tot ce lărgește acoperirea lărgește și
zgomotul. O gardă care ratează majoritatea formelor și țipă la lucru corect nu e
o jumătate de protecție: e încredere fără acoperire, iar prima ei consecință
practică e cineva care o comentează la 22:00 ca să-și poată face treaba.

Deci se verifică VALOAREA: ori valoarea reală e în text, ori nu e. Fals pozitiv
nu are cum să dea. Ratări are — nu pe „numele de lângă", ci pe REPREZENTĂRI ale
aceleiași valori, iar alea se pot enumera, ceea ce o euristică de context nu
poate. Cele acoperite sunt în `_searchable_forms` și în testul lui.

Rămân ratate, știut și scris ca să nu fie descoperit de cineva la a treia
scurgere:

  - literalii adunați într-o listă, `["555", "000", "1111"]` — lipirea lor ar
    cere ștergerea oricărei virgule dintre ghilimele, adică lipirea oricăror
    două elemente alăturate din orice tablou din depozit;
  - continuarea de linie în interiorul unui literal: un backslash urmat imediat
    de newline, între ghilimele;
  - zerourile din față (`0005550001111`) — ilegale ca literal zecimal în Python,
    posibile în alte formate;
  - valorile DERIVATE, nu copiate: un id de supergrup `-100` + id, un hash, o
    codificare base64. Verificarea caută valoarea, nu funcții de ea.

Prețul celălalt e dependența de magazia locală, iar el e scris mai sus — nu
ascuns sub un nume de test care promite mai mult.

## Valorile reale nu au voie să existe într-o variabilă locală de test

`pytest -l` (`--showlocals`) randează variabilele locale ale FIECĂRUI cadru din
traceback. O primă variantă ținea `{cheie: valoare}` chiar în funcția de test:
mesajul de eșec nu tipărea nimic, dar `-l` tipărea parola de producție integral.
Iar momentul în care rulezi `-l` e exact momentul în care garda tocmai a picat.

De aceea scanarea stă în `_scan_secret_store`, care se întoarce cu ȘIRURI deja
formatate și nu asertează niciodată: când aserțiunea din test eșuează, cadrul
care a ținut valorile nu mai e pe stivă.
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

# Magazia locală de secrete: singurul loc din care se pot afla valorile reale
# fără să le scriu aici. E ignorată de git prin `.gitignore`, iar testul verifică
# asta înainte s-o citească — dacă ajunge vreodată urmărită, sursa de adevăr a
# gărzii ar fi ea însăși scurgerea.
SECRET_STORE = ("secrets/.env.local",)


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


# --- Valoarea reală: ce stă în magazia locală nu are voie în arbore ----------
#
# Verificarea asta nu ghicește. Ori valoarea din `secrets/.env.local` apare în
# text, ori nu apare — deci n-are nici fals-pozitive de explicat, nici forme
# ratate din cauza numelui de lângă. Ce poate rata sunt REPREZENTĂRI ale
# aceleiași valori, iar alea se enumeră mai jos și se verifică separat.

# Sub șase caractere o valoare se potrivește peste tot și verificarea ar deveni
# zgomot. Nu se sare tăcut: testul enumeră cheile prea scurte și pică, fiindcă
# „prea scurtă ca s-o caut" e o gaură de acoperire, nu o trecere.
MIN_SEARCHABLE_SECRET = 6

# Valori de probă pentru testele de mai jos: nu sunt ale nimănui, și nu sunt
# valoarea reală — un test care ar avea nevoie de ea ca să demonstreze ceva ar fi
# exact scurgerea de reparat. Trei lungimi, fiindcă un cont Telegram vechi are
# opt cifre și un supergrup treisprezece; o suită de probe toate de zece ar lăsa
# o prescurtare legată de lungime să intre neobservată.
_STANDIN = "5550001111"
_STANDIN_8 = "55500011"
_STANDIN_13 = "5550001111222"

# Doi literali lipiți sunt un singur șir: `"55500" "01111"` în Python, iar cu
# `+` în orice limbaj din depozit. `\+?` nu e un amănunt: lipirea implicită NU
# există în TypeScript, deci `+` e SINGURUL mod de a sparge un literal în
# `watcher/`, care e scanat de aceeași gardă.
_ADJACENT_QUOTES = re.compile(r"""["']\s*\+?\s*["']""")
# Grupuri de cifre despărțite de un separator, oricare din cele scrise de om.
_DIGIT_SEPARATOR = re.compile(r"(?<=[0-9])[ _,.-](?=[0-9])")


def _searchable_forms(text: str) -> tuple[str, ...]:
    """Copii ale textului în care o valoare rescrisă redevine căutabilă.

    Fiecare formă vine dintr-un mod real de a scrie același număr:

      - lipirea grupurilor: `5 550 001 111`, `5,550,001,111`, `5_550_001_111`,
        `5.550.001.111`, `555-000-1111`;
      - lipirea literalilor: `"55500" "01111"` și `"55500" + "01111"`, pe care un
        `in text` nu le vede deloc, deși sunt același șir pentru cine rulează
        codul. Varianta cu `+` e obligatorie: în TypeScript, care e jumătate din
        `watcher/`, lipirea implicită nici nu există.

    Efectele secundare (o adresă IP își pierde punctele, două șiruri fără
    legătură se lipesc) nu contează: copiile astea se folosesc DOAR ca să se
    caute în ele o valoare deja cunoscută, iar șansa ca lipirea să producă exact
    valoarea căutată e neglijabilă. Dacă totuși o produce, mesajul dă fișierul și
    linia, deci coincidența se vede din prima.

    Trei forme, nu patru: o variantă „doar cifre lipite, fără lipirea
    literalilor" ar fi acoperită în întregime de ultima, iar o cale redundantă e
    o cale care se poate șterge cu suita verde — adică o falsificare care nu
    demonstrează nimic. Așa, fiecare din cele trei se rupe singură, și când o
    rupi, testul de mai jos pică.
    """
    concat = _ADJACENT_QUOTES.sub("", text)
    return (text, concat, _DIGIT_SEPARATOR.sub("", concat))


def _value_matcher(value: str) -> re.Pattern[str]:
    """Tiparul care găsește valoarea, inclusiv scrisă în hexazecimal.

    Granițe de cifră pentru valorile numerice: un PIN de șase cifre din
    interiorul unui timestamp nu e PIN-ul, iar fără granițe garda ar cere
    ștergerea unor numere nevinovate până când cineva ar scoate-o din suită.

    Hexazecimalul e a doua reprezentare pe care o ia un id copiat dintr-un
    depanator sau dintr-un dump. Se cere prefixul `0x`: fără el, nouă caractere
    hexa s-ar potrivi din întâmplare în interiorul unui hash.

    Fără `(?i)` la mijloc de tipar — pe Python 3.11+ un flag global care nu e la
    început e eroare, iar tiparul ăsta se compune prin `|`. Insensibilitatea se
    scrie pe litere, unde chiar e nevoie de ea.
    """
    if not value.lstrip("-").isdigit():
        # Un secret nenumeric (parolă, jeton) se caută ca atare: dacă apare lipit
        # de altceva, tot a scăpat.
        return re.compile(re.escape(value))

    hexa = format(abs(int(value)), "x")
    insensitive = "".join(f"[{c}{c.upper()}]" if c.isalpha() else c for c in hexa)
    return re.compile(
        rf"(?<![0-9]){re.escape(value)}(?![0-9])"
        rf"|0[xX]0*{insensitive}(?![0-9a-fA-F])")


def _locations(text: str, value: str) -> list[int]:
    """Liniile pe care apare valoarea. `0` înseamnă „în fișier, linie nesigură".

    Sentinela `0` există fiindcă lipirea literalilor alăturați poate traversa
    linii: potrivirea e reală pe tot textul, dar nu se poate atribui unei linii.
    O versiune care ar întoarce lista goală în cazul ăsta ar transforma o
    potrivire adevărată într-o trecere tăcută — exact tiparul păzit aici.
    """
    rx = _value_matcher(value)
    if not any(rx.search(form) for form in _searchable_forms(text)):
        return []

    hits = [n for n, line in enumerate(text.splitlines(), 1)
            if any(rx.search(form) for form in _searchable_forms(line))]
    return hits or [0]


def _secret_store_values(rel: str) -> dict[str, str]:
    """`KEY=VALUE` din magazia locală. Valorile nu părăsesc procesul."""
    values: dict[str, str] = {}
    text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("\"'")
        if value:
            values[key.strip()] = value
    return values


def _scan_secret_store(sources: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """(scurgeri, chei necăutabile) — ȘIRURI deja formatate, niciodată valori.

    Funcția asta e singurul loc în care valorile reale sunt legate de un nume, și
    nu asertează nimic: se ÎNTOARCE. Când aserțiunea din test eșuează, cadrul de
    aici nu mai e pe stivă, deci `pytest -l` n-are ce randa din el.

    Nicio ieșire prin excepție nu are voie să ridice cadrul ăsta într-un
    traceback cu valorile în el — de aici cele DOUĂ clauze `except`, care golesc
    numele înainte să arunce mai departe. `f_locals` se citește la raportare, nu
    la ridicare, deci golirea ajunge la timp.

    Două, nu una, fiindcă `Exception` nu prinde `KeyboardInterrupt` și
    `SystemExit`. Un Ctrl-C în secundele de scanare ieșea pe lângă clauză, cadrul
    rămânea pe stivă plin, iar `--full-trace` îl randa — adică exact clipa în
    care cineva depanează garda. `BaseException` nu se transformă în altceva
    (un Ctrl-C trebuie să rămână Ctrl-C), doar se golește și se re-aruncă.
    """
    values: dict[str, tuple[str, str]] = {}
    too_short: list[str] = []
    offenders: list[str] = []
    key = value = src = text = None
    try:
        for source_rel in sources:
            for key, value in _secret_store_values(source_rel).items():
                if len(value) < MIN_SEARCHABLE_SECRET:
                    too_short.append(f"{key} ({source_rel})")
                else:
                    values[key] = (source_rel, value)

        for rel in _tracked_files():
            for source, text in _contents(rel):
                for key, (src, value) in values.items():
                    for line_no in _locations(text, value):
                        where = f"{rel}:{line_no}" if line_no else f"{rel} (linie nesigură)"
                        offenders.append(
                            f"{where} ({source}) — valoarea lui {key} din {src}")
    except Exception as exc:
        # Doar numele tipului: `str(exc)` al unei erori de regex citează tiparul,
        # iar tiparul e construit din valoare.
        name = type(exc).__name__
        values = {}
        key = value = src = text = None
        raise RuntimeError(f"scanarea magaziei de secrete a eșuat: {name}") from None
    except BaseException:
        # Ctrl-C, SystemExit, orice altceva care nu e `Exception`. Nu se
        # convertește — se golește cadrul și se lasă să plece mai departe.
        values = {}
        key = value = src = text = None
        raise
    return offenders, too_short


def test_the_value_matcher_sees_through_every_rewriting_of_the_same_value() -> None:
    """Fără asta, verificarea ar prinde doar forma copiată verbatim.

    O valoare rescrisă cu separatori, cu underscore, în hexazecimal sau spartă în
    doi literali alăturați e aceeași valoare pentru cine o citește din depozitul
    public. Fiecare formă de mai jos există fiindcă un om chiar scrie așa; dacă
    vreuna încetează să fie prinsă, valoarea trece pe lângă gardă și ajunge în
    depozit, unde rămâne și după ce e ștearsă din arbore.

    Probele au opt, zece și treisprezece cifre — un cont Telegram vechi, unul de
    azi, un supergrup — ca nicio prescurtare legată de lungime să nu poată intra
    neobservată.
    """
    for standin in (_STANDIN, _STANDIN_8, _STANDIN_13):
        n = int(standin)
        head, mid, tail = standin[:1], standin[1:4], standin[4:]
        forms = {
            "verbatim": f"x = {standin}",
            "în șir": f'x = "{standin}"',
            "în comentariu": f"# vezi {standin}",
            "underscore": f"x = {head}_{mid}_{tail}",
            "virgule": f"x = {head},{mid},{tail}",
            "spații": f"x = {head} {mid} {tail}",
            "puncte": f"x = {head}.{mid}.{tail}",
            "cratime": f"x = {standin[:3]}-{standin[3:6]}-{standin[6:]}",
            "hexazecimal": f"x = {hex(n)}",
            "hexazecimal cu majuscule": "x = 0X" + format(n, "X"),
            "doi literali alăturați": f'x = "{standin[:5]}" "{standin[5:]}"',
            "doi literali cu +": f'x = "{standin[:5]}" + "{standin[5:]}"',
            "doi literali cu + fără spații": f'x = "{standin[:5]}"+"{standin[5:]}"',
        }
        for name, form in forms.items():
            assert _locations(form, standin), \
                f"neprins ({len(standin)} cifre) — {name}: {form!r}"

    # Și nu orice: valoarea din interiorul unui număr mai lung nu e valoarea, iar
    # hexazecimalul fără prefix s-ar potrivi în orice hash.
    #
    # Cazul hexa are terminația `z` dinadins: cu un caracter hexa după el,
    # `(?![0-9a-fA-F])` ar respinge oricum potrivirea, iar proba ar trece și fără
    # cerința prefixului `0x` — adică ar demonstra altceva decât spune.
    hexa = format(int(_STANDIN), "x")
    for form in (f"x = 9{_STANDIN}", f"x = {_STANDIN}9", "x = 555000111",
                 f"h = 'zzz{hexa}zzz'"):
        assert not _locations(form, _STANDIN), f"alarmă falsă: {form!r}"

    # Sentinela: potrivire reală pe text, dar pe nicio linie. Trebuie raportată,
    # nu pierdută.
    across_lines = f'x = ("{_STANDIN[:5]}"\n     "{_STANDIN[5:]}")'
    assert _locations(across_lines, _STANDIN) == [0]

    # Un secret nenumeric se caută ca atare, inclusiv lipit de altceva.
    assert _locations("KEY=abcdef123456", "abcdef123456") == [1]

    # Și o valoare care conține ea însăși ce normalizarea mătură. Aici, ghilimele
    # alăturate: formele normalizate le șterg din text ȘI din valoare, deci doar
    # forma BRUTĂ o mai găsește. Proba e ce ține forma brută în listă — fără ea
    # se poate scoate ca redundantă, cu suita verde.
    assert _locations("""K = 'a" "b'""", 'a" "b') == [1]


@pytest.mark.skipif(
    shutil.which("git") is None,
    reason="fără git nu se pot enumera fișierele care ar pleca într-un push, "
           "deci nu se poate căuta în ele")
def test_no_value_from_the_local_secret_store_appears_in_the_tree() -> None:
    """Ce e în `secrets/` e, prin definiție, ce nu are voie să fie publicat.

    Chat id-ul operatorului a intrat de două ori în suita de teste — o constantă
    de modul și o valoare implicită de parametru — și nicio verificare nu s-a
    uitat la el. Singur nu deschide nimic (mai trebuie și jetonul botului), dar e
    un identificator stabil al persoanei într-un depozit public, iar acolo rămâne
    și după ce e șters din arbore. Aceeași verificare acoperă parola bazei,
    jetonul, cheia API și PIN-ul, fiindcă toate stau în același fișier.

    Mesajul de eșec numește cheia și locul, niciodată valoarea: un test de
    scurgere care tipărește secretul în propria ieșire îl mută dintr-un loc
    privat în altul public.
    """
    for src in SECRET_STORE:
        if not (REPO / src).is_file():
            pytest.skip(
                f"{src} lipsește, deci verificarea pe valoare NU s-a făcut — nu e "
                "o trecere. Pe o clonă proaspătă e normal; înainte de push, rulează "
                "pe mașina care are magazia de secrete.")
        # Dacă sursa de adevăr ajunge urmărită, ea e scurgerea, nu ce caută ea.
        # `check-ignore`: 0 = ignorat, 1 = NU e ignorat, ≥128 = git a eșuat.
        # Ultimul nu se confundă cu al doilea — „n-am putut afla" nu e „e în
        # regulă".
        ignored = subprocess.run(["git", "check-ignore", "-q", src], cwd=REPO,
                                 capture_output=True)
        assert ignored.returncode in (0, 1), (
            f"nu s-a putut afla dacă {src} e ignorat de git (cod "
            f"{ignored.returncode}) — verificarea nu se poate face în siguranță")
        assert ignored.returncode == 0, (
            f"{src} NU e ignorat de git — magazia de secrete e pe cale să fie "
            "publicată ea însăși")

    # Valorile trăiesc și mor în cadrul de mai jos. Aici nu ajunge decât text
    # deja formatat, ca `-l` să n-aibă ce scoate la iveală.
    offenders, too_short = _scan_secret_store(SECRET_STORE)

    assert not offenders, (
        "valori reale din magazia de secrete, în arborele publicabil:\n  "
        + "\n  ".join(offenders[:20]))
    assert not too_short, (
        "valori prea scurte ca să fie căutate fără zgomot, deci NEVERIFICATE: "
        + ", ".join(too_short))
