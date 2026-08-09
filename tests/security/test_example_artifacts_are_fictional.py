"""Un fișier de exemplu care își declară în text originea într-o gazdă reală.

Exemplul de inventar din `deploy/config/` a fost publicat cu inventarul real al
gazdei monitorizate: zece servicii, porturile lor, ce e expus la internet și cu
ce unitate systemd. Adică harta de recunoaștere, gratis, într-un depozit public.

Un inventar cu porturi reale n-are formă proprie — nu poți căuta „hartă de
servicii", fiindcă un exemplu fictiv bine scris arată exact la fel. Ce l-a dat
de gol a fost prima linie: *„completat prin descoperire pe <gazdă>, <dată>"*.
Fișierul spunea singur de unde vine. Asta e clasa pe care o prinde verificarea
de aici: un artefact care se prezintă ca exemplu și, în același text,
mărturisește că a fost completat dintr-un sistem real.

## Ce NU prinde — citește partea asta înainte să te bazezi pe ea

* **Un exemplu curățat de antet.** Cineva care șterge linia de proveniență și
  lasă porturile reale trece. Verificarea se uită la mărturisire, nu la
  conținut, fiindcă la conținut nu există criteriu.
* **O gazdă al cărei nume nu e construit pe un substantiv de mașină.** „pe
  srv01" e prins, „pe kepler" nu: un cuvânt oarecare nu se deosebește lexical
  de restul propoziției.
* **O proveniență scrisă pe două rânduri.** Potrivirea e pe linie, ca să nu
  lege un verb dintr-un paragraf de un substantiv din următorul.

Deci nu e o dovadă că exemplele sunt fictive. E o plasă pentru forma care a
scăpat o dată, într-un depozit unde revizia umană rămâne prima apărare.

## De ce doar fișierele de exemplu

Documentația are voie — și chiar are nevoie — să spună „măsurat pe gazda de
producție, 2026-07-31". Un raport care nu-și numește sursa nu e verificabil.
Diferența e că un document se citește ca descriere a unui sistem anume, iar un
fișier numit „example" se citește ca ficțiune și e copiat ca atare.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

# Poarta documentată în docs/TESTARE.md e `pytest -m security`.
pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]

# Ce se citește ca „exemplu": numele fișierului, nu directorul. `templates/` din
# aplicația web sunt șabloane Jinja de pagini, nu artefacte de copiat, iar
# scanarea lor ar adăuga zgomot fără să acopere nimic.
EXAMPLE_MARKERS = ("example", "exemplu", "sample", "template", ".tmpl", ".dist")

SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mmdb",
               ".woff", ".woff2", ".zip", ".gz"}
SKIP_PREFIX = ("watcher/node_modules/", "dist/")

# Scutiri numite, cu motiv scris. Goală azi; o intrare fără motiv e locul prin
# care trece, peste șase luni, exact lucrul pe care testul îl păzea.
EXEMPT: dict[str, str] = {}

# --- Tiparul -----------------------------------------------------------------
#
# Trei bucăți pe aceeași linie, în ordine: un verb de derivare, o legătură care
# arată spre sursă, și o sursă care numește un sistem anume sau momentul
# capturii.
#
# Verbele sunt de DERIVARE, nu de transfer: „completat/generat/extras". „Copiat
# pe server" înseamnă destinația, nu originea, și e o instrucțiune perfect
# normală într-un exemplu — de aia „copiat" lipsește dinadins din listă.
_DERIVED = (r"(?:completat[ăa]?|generat[ăa]?|extras[ăa]?|preluat[ăa]?"
            r"|exportat[ăa]?|capturat[ăa]?"
            r"|filled|generated|captured|exported|dumped|harvested|scraped)")

_LINK = r"(?:de\s+pe|din|from|off|pe|on)"

# Sursa, în trei forme, fiecare cu motivul ei:
#   1. un marcaj de producție — „din producție", „from prod", „live";
#   2. o dată de captură — un exemplu inventat n-are când să fie capturat;
#   3. un substantiv de mașină CU cifră — „srv01", „server-2", „host3".
#      Cifra e cerută dinadins, și nu din precauție teoretică: fără ea, garda
#      dă alarmă pe `deploy/config/secrets.env.example`, care are un titlu de
#      secțiune „Generated on the server" — o instrucțiune despre ce face
#      installer-ul, nu o mărturisire de proveniență. Verificat prin scoaterea
#      cifrei din tipar; a picat imediat pe fișierul acela. O gardă care sare
#      pe așa ceva e o gardă pe care cineva o scoate din suită.
_ORIGIN = (r"(?:produc[țt]ie|production|prod\b|live\b"
           r"|\d{4}-\d{2}-\d{2}"
           r"|(?:gazd[ăa]|host|server|srv|ma[șs]in[ăa])[\w-]*\d)")

# Umplutura e leneșă și limitată: legarea unui verb de un substantiv aflat la
# capătul celălalt al liniei ar produce potriviri care nu sunt propoziții.
# Limitele nu sunt decorative și nu sunt nici alese din burtă — sunt ținute din
# două direcții de `_MUST_BE_CAUGHT` (antetul real are 18 caractere între verb
# și legătură, deci strânse prea tare pică) și de cele două fraze lungi din
# `_MUST_NOT_FIRE` (lărgite, apar alarme false). Verificat: la 400/400 ambele
# fraze lungi se potrivesc; la 120/60 încă se potrivește cea în engleză.
_PROVENANCE = re.compile(
    _DERIVED + r"[^\n]{0,40}?\b" + _LINK + r"[^\n]{0,20}?" + _ORIGIN,
    re.IGNORECASE)


def _findings(text: str) -> list[tuple[int, str]]:
    """(linie, fragmentul potrivit) pentru fiecare mărturisire de proveniență.

    Funcția asta e și cea exercitată de testul care o verifică pe ea. O copie a
    logicii în test ar demonstra că merge copia.
    """
    out: list[tuple[int, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _PROVENANCE.search(line)
        if m:
            out.append((n, " ".join(m.group(0).split())[:80]))
    return out


def _git(*args: str) -> list[str]:
    """Căi, despărțite pe NUL.

    Fără `-z`, git citează numele non-ASCII, calea aia nu există pe disc, iar
    verificarea ar sări fișierul în tăcere. `encoding`/`errors` explicite: pe
    Windows decodarea implicită e cp1252 și un nume cu diacritice iese stricat.

    Lipsa lui git nu se tratează ca skip: fără enumerare nu s-a verificat nimic,
    iar „n-am putut" și „e curat" nu au voie să arate la fel. Mesajul spune care
    dintre ele e.
    """
    if shutil.which("git") is None:
        raise AssertionError(
            "git lipsește, deci nu s-a putut enumera nimic — verificarea NU s-a "
            "făcut. Asta e eșec, nu trecere.")
    out = subprocess.run(["git", *args, "-z"], cwd=REPO, capture_output=True,
                         encoding="utf-8", errors="replace", check=True)
    return [p for p in (out.stdout or "").split(chr(0)) if p]


def _example_files() -> list[str]:
    """Artefactele de exemplu care ar ajunge într-un push.

    Urmărite SAU neurmărite-și-neignorate: un fișier scris azi și încă
    neadăugat e exact cel pe care următorul `git add -A` îl publică. `ls-files`
    listează INDEXUL, deci aici intră și un fișier deja pregătit dar șters de pe
    disc — vezi `_contents` pentru de ce contează.
    """
    rels: list[str] = []
    for args in (("ls-files",), ("ls-files", "--others", "--exclude-standard")):
        for rel in _git(*args):
            if rel.startswith(SKIP_PREFIX) or Path(rel).suffix.lower() in SKIP_SUFFIX:
                continue
            name = Path(rel).name.lower()
            if any(marker in name for marker in EXAMPLE_MARKERS):
                rels.append(rel)
    return sorted(set(rels))


def _contents(rel: str) -> list[tuple[str, str]]:
    """TOATE versiunile care s-ar putea publica: discul ȘI indexul.

    `git commit` fără `-a` scrie INDEXUL. O primă versiune a fișierului ăstuia
    citea doar discul, ceea ce face garda să verifice o versiune în timp ce git
    publică alta — și e mai rău decât lipsa gărzii, fiindcă dă confirmarea exact
    în clipa în care omul crede că a reparat:

        git add -A            # antetul cu gazda reală intră în index
        pytest -m security    # pică, bine
        <editezi fișierul>    # discul e curat acum
        pytest -m security    # VERDE, deși indexul are încă blobul murdar
        git commit            # se publică versiunea din index

    Al doilea caz e ștergerea: `git rm --cached` lasă fișierul în index și îl
    scoate de pe disc, iar o gardă care sare peste ce nu există pe disc tace.

    Fluxul ăsta nu e ipotetic — e chiar cel pe care depozitul îl documentează ca
    reacție la o scurgere, și e defectul reparat deja o dată în
    `test_repo_is_sanitised.py`. Deci nu alegem între surse: le citim pe
    amândouă, și le numim, ca mesajul de eroare să spună UNDE e problema.
    """
    out: list[tuple[str, str]] = []
    path = REPO / rel
    if path.is_file():
        try:
            # `errors="replace"`: un fișier salvat de un editor cp1252 ar crăpa
            # la decodare strictă, excepția ar fi înghițită, și ar rămâne doar
            # versiunea din index — adică exact cea curată, în timp ce arborele
            # de lucru conține antetul real.
            out.append(("disc", path.read_bytes().decode("utf-8", errors="replace")))
        except OSError:
            pass
    staged = subprocess.run(["git", "show", f":{rel}"], cwd=REPO, capture_output=True,
                            encoding="utf-8", errors="replace")
    # Verificare pe stdout, nu doar pe returncode: un blob binar poate întoarce
    # cod 0 cu stdout None, iar lista n-ar mai fi goală, deci garda de
    # necitibilitate de mai jos ar declara fișierul citit.
    if (staged.returncode == 0 and staged.stdout is not None
            and not any(text == staged.stdout for _, text in out)):
        out.append(("index", staged.stdout))
    return out


# --- Formele care trebuie prinse, și cele care nu au voie să declanșeze -------

_MUST_BE_CAUGHT = {
    "antetul care a fost publicat":
        "# Sentinel asset inventory — completat prin descoperire pe srv01, 2026-07-31.\n",
    "același antet fără dată":
        "# Inventar completat prin descoperire pe srv01.\n",
    "gazda de producție, fără nume de mașină":
        "# inventar generat de pe gazda de producție\n",
    "engleză, gazda de producție":
        "# Values captured from the production host.\n",
    "engleză, doar data capturii":
        "# generated on 2026-07-31 by a discovery run\n",
    "prescurtat":
        "# config filled from prod\n",
    "mașină numerotată, alt substantiv":
        "# exemplu extras din server-2\n",
}

_MUST_NOT_FIRE = {
    "câmp de șablon Jinja":
        "**Generat:** {{ created_at_local }} · **Model:** {{ model }}\n",
    "instrucțiune despre ce face installer-ul":
        "# Fișierul real e generat de install.sh pe server, la instalare.\n",
    "derivare criptografică":
        "# entry_hash e generat din sha256(prev_hash + payload)\n",
    "versiune, nu gazdă":
        "# exportat din v1.2.3 al schemei\n",
    "verb de transfer: server-2 e destinația":
        "# Copiat pe server-2 de install.sh\n",
    "propoziție despre trafic real, fără proveniență":
        "# Tune down only after you have watched real traffic for a few days.\n",
    "generat local, fără sursă":
        "# Generated by secrets-init.sh.\n",
    # Cele două de mai jos există ca să țină limitele de umplutură din
    # `_PROVENANCE`. Fără ele, 40/20 ar fi cifre pe care nimic nu le apără:
    # lărgite la 400/400, restul suitei rămâne verde și rezultatul pe fișierele
    # reale e identic. Cu ele, lărgirea pică — verbul dintr-un capăt al frazei
    # se leagă de un substantiv fără nicio legătură cu el din celălalt.
    "frază lungă: verbul și cuvântul producție nu formează o proveniență":
        "# Pragul e generat din mediană+MAD pe 4 săptămâni, deci o oră cu trafic "
        "dublu față de aceeași oră de săptămâna trecută nu mai trece drept "
        "normală în producție.\n",
    "frază lungă în engleză, cu un nume de mașină la capătul celălalt":
        "# The baseline is generated from the host's own history, warmed up over "
        "14 days, so nothing alerts before there is enough of it to call a day "
        "on srv01 unusual.\n",
}


def test_the_provenance_pattern_catches_every_shape_and_stays_quiet_otherwise() -> None:
    """O gardă care prinde doar linia reparată azi n-a fost scrisă.

    Prima jumătate: dacă vreo formă de mai jos nu mai e prinsă, un exemplu
    completat de pe un server real poate fi publicat din nou fără ca nimic să
    spună ceva. A doua jumătate contează la fel: o gardă care sare pe o
    instrucțiune normală dintr-un fișier de configurație e o gardă pe care
    cineva o scoate din suită în două săptămâni, și atunci nu mai apără nimic.
    """
    missed = [name for name, text in _MUST_BE_CAUGHT.items() if not _findings(text)]
    assert not missed, "forme neprinse de gardă: " + ", ".join(missed)

    noisy = [f"{name}: {_findings(text)}"
             for name, text in _MUST_NOT_FIRE.items() if _findings(text)]
    assert not noisy, "garda dă alarmă falsă pe text legitim:\n  " + "\n  ".join(noisy)


def test_there_are_example_artifacts_to_check() -> None:
    """Fără fișiere enumerate, verificarea de mai jos trece fără să se uite la nimic.

    Depozitul livrează exemple de configurație și șabloane. Dacă enumerarea iese
    goală — marcaje redenumite, git indisponibil, altă structură — asta se vede
    ca eșec, nu ca bifă verde.
    """
    found = _example_files()
    assert len(found) >= 5, (
        "prea puține artefacte de exemplu enumerate ("
        + ", ".join(found) + ") — verificarea nu mai acoperă ce pretinde")


def test_every_enumerated_artifact_can_be_read() -> None:
    """O cale enumerată dar necitibilă e o gaură de acoperire, nu o trecere.

    Dacă nici discul, nici indexul nu dau conținut, verificarea de mai jos ar
    sări fișierul în tăcere și ar raporta verde pentru ceva la care nu s-a
    uitat. Extensiile binare sunt deja excluse; orice altceva necitibil trebuie
    să se vadă.
    """
    unreadable = [rel for rel in _example_files() if not _contents(rel)]
    assert not unreadable, (
        "artefacte enumerate dar necitibile, deci NEVERIFICATE: "
        + ", ".join(unreadable))


def test_no_example_artifact_claims_it_came_from_a_real_host() -> None:
    """Un exemplu completat dintr-o gazdă reală, publicat ca exemplu.

    S-a întâmplat: inventarul de active al serverului monitorizat, cu porturi,
    expuneri și unități systemd, a plecat într-un depozit public sub un nume
    care spunea „example". Ce urmează după e ireversibil — blobul rămâne
    accesibil după hash, și poate fi deja în forkuri și cache-uri. De aia
    momentul care contează e înainte de push, aici.

    Se verifică ambele versiuni ale fiecărui fișier, cea de pe disc și cea din
    index, fiindcă `git commit` publică indexul. Vezi `_contents`.
    """
    offenders: list[str] = []
    me = Path(__file__).relative_to(REPO).as_posix()

    for rel in _example_files():
        if rel == me or rel in EXEMPT:
            continue
        for source, text in _contents(rel):
            for line_no, fragment in _findings(text):
                offenders.append(f"{rel}:{line_no} ({source}): {fragment}")

    assert not offenders, (
        "artefact de exemplu care își declară originea într-un sistem real:\n  "
        + "\n  ".join(offenders[:20])
        + "\n  Dacă valorile chiar vin de pe o gazdă reală, nu rescrie antetul — "
          "rescrie valorile. Dacă nu vin, scoate propoziția care spune că vin.")
