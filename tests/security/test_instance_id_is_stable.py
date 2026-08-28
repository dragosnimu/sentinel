"""Identitatea instalării se generează o dată și nu se mai atinge niciodată.

`/etc/sentinel/instance_id` e ce deosebește serverul ăsta de celelalte într-un
panou care le adună pe toate. Are aceleași două moduri de eșec ca
`SENTINEL_BEACON_SECRET`, și pe amândouă le raportează cineva din afara gazdei,
târziu:

  * **regenerată** — istoria unui server se rupe în două, iar jumătatea veche
    arată ca un server care a tăcut;
  * **duplicată** (hostname, `/etc/machine-id` moștenit de o clonă) — două
    servere se contopesc într-o singură istorie, iar cifrele încetează să
    însemne ce spun.

Niciunul nu ridică vreo eroare nicăieri. Deci verificarea nu poate fi „pasul a
ieșit cu 0": testele de mai jos rulează PASUL LIVRAT — blocul dintre marcajele
`# --- 27` și `# --- 28` din `deploy/install.sh` — și se uită la ce a rămas pe
disc după el.

Din august 2026 fișierul a căpătat un al treilea mod de eșec, care nu e nici
regenerare, nici duplicare: **să nu existe deloc pe o gazdă care rulează cod
care are nevoie de el.** Expeditorul refuză să trimită un semnal pe care nu-l
poate atribui gazdei, deci un deploy care aduce codul nou fără fișier repornește
beaconul direct în tăcere, iar martorul sună o alarmă critică despre un server
sănătos. Trei grupuri de teste acoperă asta, și toate rulează cod livrat:

  * **secvența de pași** din `main`, cu fiecare marcaj deja pus — adică gazda din
    producție — ca să se probeze că `ensure_instance_id` nu e supusă marcajelor;
  * **poarta de repornire** (`start_beacon_unit`), care refuză să repornească
    beaconul peste un fișier care nu e o identitate;
  * **proba de fum** (`smoke_beacon_is_beating`), fiindcă „unitatea e activă" e
    exact tiparul din CLAUDE.md — contorul care avansează e faptul.

Restul fișierului leagă cele trei locuri în care e scrisă aceeași formă
(`^[0-9a-f]{32}$`) și verifică premisa fără de care nimic din asta nu se citește:
fișierul e `0640 root:sentinel`, deci CITIREA PRIN GRUP e singurul lucru care îl
face lizibil pentru daemoni.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "deploy" / "install.sh"
INSTALL = INSTALL_SH.read_text(encoding="utf-8")
BASH = shutil.which("bash")

# Motivul spune CE a încetat să ruleze, nu doar ce lipsește.
#
# `addopts` din pyproject.toml conține `-rfEs` tocmai ca motivul unui skip să
# apară. „no bash on PATH" nu e o informație: nimeni nu deduce din ea că tot ce
# leagă install.sh de sentinel/identity.py și de CHECK-ul din 0022 a fost sărit,
# iar „1 skipped" într-o linie de sumar arată exact ca sănătate.
_NO_BASH = (
    "bash lipsește din PATH, deci NU au rulat: corpusul care cere același "
    "verdict de la install.sh, de la sentinel/identity.py și de la modelul "
    "CHECK-ului din 0022; idempotența pasului 27; garda de NUL; și refuzul de a "
    "regenera o identitate existentă. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [pytest.mark.security,
              pytest.mark.skipif(BASH is None, reason=_NO_BASH)]

ID_ON_HOST = "aaaaaaaabbbbbbbbccccccccdddddddd"
STUB_ID = "0123456789abcdef0123456789abcdef"


def step27_source() -> str:
    """Pasul 27 așa cum se livrează, nu o copie a lui."""
    match = re.search(r"^# --- 27 -+\n(.*?)^# --- 28 -+$", INSTALL, re.S | re.M)
    assert match, "cannot find the step 27 block in install.sh"
    body = match.group(1)
    assert "ensure_instance_id()" in body, \
        "ensure_instance_id nu mai e în pasul 27 — testele de mai jos nu mai testează nimic"
    return body


def ensure_source() -> str:
    """Doar corpul lui `ensure_instance_id`, ca aserțiunile pe formă să nu
    prindă expresiile din `step_secrets`, care nu au legătură cu identitatea."""
    match = re.search(r"^ensure_instance_id\(\)\s*\{.*?^\}", INSTALL, re.S | re.M)
    assert match, "ensure_instance_id nu mai există în install.sh"
    return match.group(0)


HARNESS = """
source ./lib/common.sh
{step27}

# chown/chmod sunt înlocuite: nu există utilizator `sentinel` pe o mașină de
# dezvoltare, iar modurile POSIX nu supraviețuiesc sistemului ăstuia de fișiere.
# Apelurile se ÎNREGISTREAZĂ, fiindcă proprietarul și modul sunt exact
# proprietățile care fac fișierul lizibil pentru daemon.
chown() {{ printf 'chown %s\\n' "$*" >> "$CALLS"; }}
chmod() {{ printf 'chmod %s size=%s\\n' "$*" "$(wc -c < "$2" 2>/dev/null || echo -1)" >> "$CALLS"; }}

# Generarea trebuie să fie OBSERVABILĂ: „valoarea nu s-a schimbat" e mai slab
# decât „nu s-a bătut niciodată una nouă".
#
# Ce scrie e un ȘIR DE FORMAT, nu un argument, ca un test să poată produce
# octeți pe care un argument nu-i poate purta — `\\000` în primul rând.
openssl() {{ printf 'openssl %s\\n' "$*" >> "$CALLS"; printf '{stub}'; }}

{extra}
{entry}
printf 'RC=%s\\n' "$?"
"""


def run_ensure(tmp_path: Path, existing: str | None, stub: str = STUB_ID,
               entry: str = "ensure_instance_id", extra: str = "") -> dict:
    """`existing=None` nu șterge nimic — lasă directorul cum e, ca o a doua
    rulare peste prima să fie chiar o re-rulare, nu o instalare nouă."""
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    target = cfg / "instance_id"
    if existing is not None:
        target.write_text(existing, encoding="utf-8", newline="\n")

    calls = tmp_path / "calls.txt"
    # Golit la fiecare rulare: altfel „nu s-a apelat openssl" ar fi fals de la
    # apelul rulării anterioare, iar testul de idempotență ar pica pe propria
    # instrumentare în loc de pe cod.
    calls.unlink(missing_ok=True)
    script = tmp_path / "harness.sh"
    script.write_text(
        HARNESS.format(step27=step27_source(), stub=stub, entry=entry, extra=extra),
        encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True, text=True,
        env={**os.environ, "NO_COLOR": "1",
             "SENTINEL_CONFIG_DIR": str(cfg).replace("\\", "/"),
             "SENTINEL_USER": "sentinel",
             "CALLS": str(calls).replace("\\", "/")},
    )
    return {
        "proc": proc,
        "out": proc.stdout + proc.stderr,
        "file": target.read_text(encoding="utf-8").strip() if target.exists() else None,
        "leftover_tmp": (cfg / "instance_id.tmp").exists(),
        "calls": calls.read_text(encoding="utf-8") if calls.exists() else "",
    }


# ---------------------------------------------------------------------------
# Generarea
# ---------------------------------------------------------------------------
def test_a_fresh_host_gets_an_identity(tmp_path):
    """Cazul de bază. Fără el, toate testele „nu se regenerează" ar trece și
    peste un pas care nu generează niciodată nimic."""
    out = run_ensure(tmp_path, None)
    assert out["proc"].returncode == 0, out["out"]
    assert out["file"] == STUB_ID
    assert "rand -hex 16" in out["calls"], "identitatea nu vine din openssl rand"
    assert not out["leftover_tmp"], "fișierul temporar a rămas pe disc"


# ---------------------------------------------------------------------------
# Locul apelului: un deploy OBIȘNUIT, pe o gazdă unde totul e deja marcat
# ---------------------------------------------------------------------------
SEQUENCE = re.search(r"^(    run_step  1 preflight.*?run_step 40 notify.*?)$",
                     INSTALL, re.S | re.M)

# Fiecare `run_step N nume funcție` din secvența livrată — de aici se generează
# cioatele, ca lista să nu fie una scrisă de mână care rămâne în urmă.
STEP_CALLS = re.compile(r"^\s*run_step\s+(\d+)\s+(\S+)\s+(\S+)\s*$", re.M)

SEQUENCE_HARNESS = """
set -u
source ./lib/common.sh

SENTINEL_CONFIG_DIR="$CFG"
NGINX_MODE=dedicated

# Fiecare pas devine o cioată care doar se înregistrează. Ce se probează aici e
# ORCHESTRAREA — ce rulează pe un deploy obișnuit — nu ce face fiecare pas.
{stubs}
resolve_config() {{ :; }}
confirm() {{ return 0; }}
section() {{ :; }}

# Singurul lucru real din harnessul ăsta. Scrie un fișier, exact ca originalul,
# ca „a rulat" să fie un fapt de pe disc și nu o linie de jurnal.
ensure_instance_id() {{ printf 'ENSURED\\n' >> "$CALLS"; : > "$CFG/instance_id"; }}

# Cealaltă funcție necondiționată din secvență. Aici doar se înregistrează, ca
# secvența livrată să ruleze; poziția ei e probată în
# tests/security/test_installer_docker_access.py.
ensure_docker_access() {{ printf 'DOCKER_ACCESS\\n' >> "$CALLS"; }}

mkdir -p "$STATE_MARKERS"
{markers}

parse_force_steps ""
{sequence}
printf 'RC=%s\\n' "$?"
"""


def run_sequence(tmp_path: Path, marked: bool) -> dict:
    """Rulează secvența de pași LIVRATĂ, cu toți pașii cioate.

    `marked=True` e gazda din producție: fiecare marcaj de pas există deja, deci
    `run_step` sare fiecare corp. Ce mai rămâne să ruleze e exact ce nu e supus
    marcajelor.
    """
    assert SEQUENCE, "nu mai găsesc secvența de pași din install.sh"
    body = SEQUENCE.group(1)
    steps = STEP_CALLS.findall(body)
    assert len(steps) >= 20, f"am extras doar {len(steps)} pași — extractorul e rupt"

    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    calls = tmp_path / "calls.txt"
    state = tmp_path / "state"

    stubs = "\n".join(f"{fn}() {{ printf '{name}\\n' >> \"$CALLS\"; }}"
                      for _, name, fn in sorted({(n, nm, f) for n, nm, f in steps}))
    markers = "\n".join(
        f': > "$STATE_MARKERS/{int(num):02d}_{name}"' for num, name, _ in steps
    ) if marked else ""

    script = tmp_path / "sequence.sh"
    script.write_text(
        SEQUENCE_HARNESS.format(stubs=stubs, markers=markers, sequence=body),
        encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        cwd=str(REPO / "deploy"), capture_output=True, text=True,
        env={**os.environ, "NO_COLOR": "1",
             "SENTINEL_STATE_DIR": str(state).replace("\\", "/"),
             "CFG": str(cfg).replace("\\", "/"),
             "CALLS": str(calls).replace("\\", "/")})
    return {
        "proc": proc,
        "calls": calls.read_text(encoding="utf-8") if calls.exists() else "",
        "identity_exists": (cfg / "instance_id").exists(),
    }


def test_the_harness_sees_a_plain_rerun_skip_every_step(tmp_path):
    """Păzește garda.

    Dacă marcajele n-ar fi citite — alt nume de director, alt format — fiecare
    corp de pas ar rula, iar testul de mai jos ar trece fiindcă a rulat pasul 27,
    nu fiindcă apelul e în afara lui. Adică exact aserțiunea care nu verifică
    nimic.
    """
    fresh = run_sequence(tmp_path / "fresh", marked=False)
    assert "secrets" in fresh["calls"], fresh["proc"].stdout + fresh["proc"].stderr

    marked = run_sequence(tmp_path / "marked", marked=True)
    assert marked["proc"].returncode == 0, marked["proc"].stdout + marked["proc"].stderr
    assert "secrets" not in marked["calls"], \
        "marcajele nu opresc pașii — restul fișierului nu mai probează nimic"


def test_a_plain_redeploy_still_ensures_the_identity(tmp_path):
    """Gazda din producție: instalată înainte ca identitatea să existe.

    Toate marcajele sunt puse din ziua instalării, iar comanda de actualizare
    din documentație nu trece `--force-step 27`. Cât timp apelul a stat ÎN pasul
    27, un deploy obișnuit livra beaconul nou, îl repornea prin
    `step_start_services` (care E în ALWAYS_STEPS) și nu crea niciodată
    fișierul — deci expeditorul amuțea, iar martorul suna o alarmă critică
    despre un server sănătos, la 3–8 minute după deploy, repetată la 4 ore.

    Nicio documentație nu repară asta: o gazdă nu citește documentație. Deci
    proprietatea se probează pe secvența livrată, cu marcajele puse.
    """
    out = run_sequence(tmp_path, marked=True)
    assert out["proc"].returncode == 0, out["proc"].stdout + out["proc"].stderr
    assert "ENSURED" in out["calls"], \
        "un deploy obișnuit nu mai asigură identitatea instalării"
    assert out["identity_exists"]


def test_the_identity_is_ensured_before_the_services_are_restarted(tmp_path):
    """Ordinea, nu doar prezența.

    `step_start_services` repornește beaconul. Chemat înaintea identității, ar
    reporni exact expeditorul care tocmai a fost învățat să refuze un semnal fără
    nume — adică fereastra de tăcere ar exista oricum, doar mai scurtă.
    """
    out = run_sequence(tmp_path, marked=False)
    lines = out["calls"].split()
    assert "ENSURED" in lines and "start_services" in lines, out["calls"]
    assert lines.index("ENSURED") < lines.index("start_services")
    # Și înaintea migrării, care e cea care oglindește identitatea în bază.
    assert lines.index("ENSURED") < lines.index("migrate")


def test_an_existing_identity_is_never_regenerated(tmp_path):
    """Eșecul cel mai scump din pasul ăsta.

    O identitate regenerată rupe istoria unui server în două pe panoul comun:
    jumătatea veche arată ca un server care a amuțit — adică exact forma unei
    alarme reale — iar cea nouă apare ca un server pe care nimeni nu l-a
    instalat. Nimic nu raportează o defecțiune.
    """
    out = run_ensure(tmp_path, ID_ON_HOST + "\n")
    assert out["proc"].returncode == 0, out["out"]
    assert out["file"] == ID_ON_HOST
    assert "openssl" not in out["calls"], "s-a bătut o identitate nouă peste una existentă"


def test_a_rerun_is_idempotent(tmp_path):
    """Calea documentată de upgrade e `git pull` + re-rulare. Dacă a doua rulare
    schimbă valoarea, fiecare upgrade mută serverul în altă istorie."""
    first = run_ensure(tmp_path, None)
    second = run_ensure(tmp_path, None)   # același director, fișierul rămâne
    assert first["file"] == STUB_ID
    assert second["file"] == first["file"]
    assert "openssl" not in second["calls"]


def test_the_carried_identity_is_reasserted_as_readable_by_the_daemon(tmp_path):
    """Fișierul e `0640 root:sentinel` și procesele rulează ca `sentinel`: CITIREA
    PRIN GRUP e singurul lucru care îl face lizibil.

    O restaurare din backup care îl lasă `0600 root:root` nu produce nicio
    eroare la instalare — simptomul apare ore mai târziu, ca „nu pot citi
    identitatea", pe alt ecran. Deci modul și grupul se reafirmă și pe fișierul
    păstrat, nu doar pe cel nou.
    """
    out = run_ensure(tmp_path, ID_ON_HOST)
    assert "chown root:sentinel" in out["calls"], out["calls"]
    assert "chmod 0640" in out["calls"], out["calls"]


def test_the_mode_is_set_before_the_identity_exists(tmp_path):
    """Scris întâi și chmod după lasă o fereastră în care fișierul e lizibil de
    orice cont de pe gazdă. Identitatea nu e secretă, dar fereastra e aceeași
    greșeală pe care secrets.env a plătit-o deja o dată."""
    out = run_ensure(tmp_path, None)
    chmods = [l for l in out["calls"].splitlines() if l.startswith("chmod")]
    assert chmods, "fișierul temporar nu e niciodată chmod-uit"
    assert "0640" in chmods[0], chmods[0]
    assert chmods[0].endswith("size=0"), f"modul pus după conținut: {chmods[0]}"


def test_an_empty_file_is_not_an_identity_to_preserve(tmp_path):
    """Un fișier gol e o scriere care a eșuat, nu o valoare de păstrat. Păstrat,
    lasă gazda fără identitate pentru totdeauna, cu un „păstrată" verde pe
    ecran."""
    out = run_ensure(tmp_path, "\n")
    assert out["proc"].returncode == 0, out["out"]
    assert out["file"] == STUB_ID
    assert "gol" in out["out"], "înlocuirea unui fișier gol s-a făcut în tăcere"


# ---------------------------------------------------------------------------
# Efectul, nu codul de ieșire
# ---------------------------------------------------------------------------
def test_an_unmeasurable_file_is_never_regenerated_over(tmp_path):
    """Când nu se știe NIMIC despre fișier, singurul lucru interzis e să scrii.

    `read_instance_id_file` întoarce 3 când nu poate măsura fișierul — nici „are
    identitate", nici „nu are". Fără `die` pe ramura aia, valoarea rămâne goală
    și execuția curge exact ca pe un fișier gol: „era gol, se generează", apoi
    generează. Adică fix actul ireversibil pe care comentariul de deasupra spune
    că îl refuză, ajuns acolo pe drumul cel mai puțin probabil — care e și
    motivul pentru care nu l-ar fi observat nimeni cu mâna.

    Aici i se ia lui `wc` capacitatea de a răspunde; fișierul e o identitate
    perfect validă, și trebuie să iasă din pas neatinsă.
    """
    out = run_ensure(tmp_path, ID_ON_HOST, extra="wc() { return 1; }\n")
    assert out["proc"].returncode != 0, \
        "un fișier despre care nu se știe nimic nu a oprit pasul"
    assert out["file"] == ID_ON_HOST, "identitatea a fost suprascrisă"
    assert "openssl" not in out["calls"], "s-a generat peste un fișier nemăsurat"


def test_a_nul_padded_write_is_fatal(tmp_path):
    """Forma cea mai probabilă a unei scrieri întrerupte — și cea pe care garda
    pusă anume pentru ea nu o putea vedea.

    Un ext4/xfs care pierde curentul la mijlocul unei scrieri completează blocul
    cu NUL; nu taie fișierul. Re-citirea de după generare există exact pentru
    coruperea asta, dar o făcea printr-un `$(cat …)` — iar substituția de comandă
    din bash ARUNCĂ octeții NUL, tăcut, cu un avertisment pe stderr pe care
    nimeni nu-l citește. Deci un fișier de 33 de octeți se recitea ca 32 de hexa
    perfect valide: instalarea raporta verde, iar `sentinel/identity.py` refuza
    exact aceeași valoare ore mai târziu, prin „⚪ Nu pot citi identitatea".
    """
    out = run_ensure(tmp_path, None, stub=STUB_ID + r"\000")
    assert out["proc"].returncode != 0, \
        "o scriere completată cu NUL a fost raportată ca identitate generată"
    assert out["file"] is not None
    # Și fișierul stricat rămâne pe disc, nu e „reparat" cu încă o generare:
    # dacă valoarea aia a ajuns vreodată la un agregator, e tot ce mai există
    # din ea.
    assert b"\x00" in (tmp_path / "etc" / "instance_id").read_bytes()


def test_a_short_write_is_fatal_and_not_reported_as_success(tmp_path):
    """Codul de ieșire al lui openssl nu spune nimic despre ce a ajuns în fișier:
    redirectarea e a shell-ului. Un disc plin sau o cotă atinsă lasă în urmă un
    fișier trunchiat, iar o identitate trunchiată se poate ciocni cu alta la fel
    de trunchiată — fără ca nimic să raporteze ceva.

    Deci pasul recitește de pe disc și verifică forma. Aici i se dă exact asta.
    """
    out = run_ensure(tmp_path, None, stub="0123")
    assert out["proc"].returncode != 0, \
        "o identitate trunchiată a fost raportată ca generată cu succes"
    assert "hexa" in out["out"]


def test_a_file_of_the_wrong_shape_is_never_overwritten(tmp_path):
    """Poate fi singura copie a unei valori pe care panoul o cunoaște deja.

    Rescrierea „ca să reparăm" e ireversibilă și rupe istoria; refuzul e
    reversibil și îl pune pe operator în fața deciziei. Dar nu în tăcere: o
    identitate necitibilă lăsată nespusă e o gazdă care nu ajunge niciodată în
    panou, fără ca cineva să afle de ce.
    """
    junk = "NU-E-O-IDENTITATE"
    out = run_ensure(tmp_path, junk)
    assert out["proc"].returncode == 0, out["out"]
    assert out["file"] == junk, "un fișier nerecunoscut a fost suprascris"
    assert "openssl" not in out["calls"]
    assert "--force-step 27" in out["out"], "refuzul nu spune ce are de făcut operatorul"


def test_a_refused_file_is_not_reported_as_a_kept_identity(tmp_path):
    """Refuzul trebuie și să ARATE ca un refuz.

    Ramura de refuz s-a întors o dată din `return 0` într-un `current=""` care
    cădea în ramura de mai jos: fișierul rămânea neatins — deci testul de mai
    sus trecea — dar pasul tipărea linia VERDE „identitatea instalării păstrată"
    peste un fișier despre care tocmai avertizase că nu e o identitate.
    Intenția raportată drept efect, pe linia pe care operatorul o citește cel
    mai repede.
    """
    out = run_ensure(tmp_path, "NU-E-O-IDENTITATE")
    assert "păstrată" not in out["out"], \
        "un fișier refuzat e raportat ca identitate păstrată"
    assert "chmod" not in out["calls"], \
        "pasul a atins un fișier pe care spune că nu-l recunoaște"


def test_the_identity_is_never_printed_in_full(tmp_path):
    """Nu e secret, dar e identificatorul pe care agregatorul îl caută în antet,
    iar jurnalul de deploy ajunge des în alte locuri. Prefixul e de ajuns ca
    operatorul să compare două ecrane."""
    out = run_ensure(tmp_path, None)
    assert STUB_ID not in out["out"], "identitatea completă a ajuns în jurnalul de deploy"
    assert STUB_ID[:8] in out["out"], "nu se spune deloc ce identitate are gazda"


# ---------------------------------------------------------------------------
# Aceeași gramatică, trei limbaje — verificată prin VERDICT, nu prin text
# ---------------------------------------------------------------------------
#
# Versiunea dinainte a acestei secțiuni compara ȘIRURI: că expresia din
# `sentinel/identity.py` apare literal în `0022_instance_identity.sql` și de
# două ori în `install.sh`. Nu punea niciunul dintre cele trei să DECIDĂ ceva,
# deci nu putea pica pentru divergența pentru care exista. Două schimbări în
# Python care nu ating niciun caracter din șirul tiparului treceau întreaga
# suită: `re.compile(..., re.I)` și `raw.strip().lower()`. Amândouă fac Python
# să accepte majuscule pe care PostgreSQL le respinge — măsurat pe gazdă:
#
#         label        | sql_accepts
#     -----------------+-------------
#      good-32-lower   | t
#      uppercase       | f
#
# Consecința: scriitorul oglinzii din E1.4 citește o identitate cu majuscule,
# `INSERT` cade pe constrângere, rândul nu apare niciodată, iar
# `check_instance_identity` raportează „oglinda nu e scrisă încă" pentru
# totdeauna. Exact eșecul pe care 0022 spune că testul îl previne.
#
# Deci proprietatea testată e „cele trei sunt de acord pe INTRAREA asta", nu
# „cele trei fișiere conțin subșirul ăsta". Aserțiunea textuală rămâne, dar ca
# a doua plasă: ea prinde editarea tiparului, corpusul prinde schimbarea
# semanticii din jurul lui.

ID_CORPUS = "aaaaaaaabbbbbbbbccccccccdddddddd"

# (etichetă, octeții EXACȚI de pe disc, verdictul așteptat de la install.sh)
#
#   kept    — pasul a recunoscut valoarea și a păstrat-o
#   refused — nu a recunoscut-o și NU a atins fișierul
#   minted  — nu era nimic de păstrat, a generat
#
# Python trebuie să accepte exact cazurile `kept`, iar valoarea extrasă de cele
# două trebuie să fie identică. Pentru fiecare valoare acceptată, modelul de
# PostgreSQL trebuie și el s-o accepte — altfel oglinda nu se poate scrie.
CORPUS: list[tuple[str, bytes, str]] = [
    ("canonic",          ID_CORPUS.encode(),                          "kept"),
    # `openssl … > fișier` termină cu newline: dacă asta nu e „kept", nicio
    # instalare reală nu trece.
    ("trailing-lf",      (ID_CORPUS + "\n").encode(),                 "kept"),
    # `crlf` și `lone-cr` testează jumătatea BASH a lui `\r`. Python nu vede
    # niciodată un CR aici: `Path.read_text()` deschide cu `newline=None`, deci
    # traducerea universală de linii îl transformă în `\n` înainte de `strip`.
    # `cat` din bash îl vede și trebuie să-l taie ca spațiu — cele două ajung la
    # aceeași valoare pe drumuri diferite, și exact asta se verifică.
    ("crlf",             (ID_CORPUS + "\r\n").encode(),               "kept"),
    ("lone-cr",          (ID_CORPUS + "\r").encode(),                 "kept"),
    ("double-lf",        (ID_CORPUS + "\n\n").encode(),               "kept"),
    ("spaces",           ("  " + ID_CORPUS + "  ").encode(),          "kept"),
    ("tab",              ("\t" + ID_CORPUS + "\t").encode(),          "kept"),
    ("leading-zeros",    ("0" * 32).encode(),                         "kept"),
    # A treia valoare acceptată distinctă, și singurul motiv pentru care e aici:
    # până la ea, doar DOUĂ șiruri ajungeau vreodată la modelul de PostgreSQL,
    # amândouă omogene. Un model care vede doar „32 de „a"+„b"+„c"+„d"" și „32 de
    # zerouri" nu e pus să deosebească nimic.
    ("mixed-hex",        "0f1e2d3c4b5a69788796a5b4c3d2e1f0".encode(), "kept"),

    ("uppercase",        ID_CORPUS.upper().encode(),                  "refused"),
    ("31-chars",         ID_CORPUS[:31].encode(),                     "refused"),
    ("33-chars",         (ID_CORPUS + "a").encode(),                  "refused"),
    ("non-hex",          ("g" * 32).encode(),                         "refused"),
    ("junk",             b"NU-E-O-IDENTITATE",                        "refused"),
    ("interior-space",   (ID_CORPUS[:16] + " " + ID_CORPUS[16:]).encode(), "refused"),
    ("two-lines",        (ID_CORPUS + "\n" + ID_CORPUS).encode(),     "refused"),
    # `chr(0xFEFF)`, nu un U+FEFF literal în sursă. Un editor sau un filtru care
    # „curăță” BOM-uri din fișiere ar șterge caracterul din chiar linia asta, iar
    # încărcătura ar deveni identitatea canonică — al cărei verdict așteptat e
    # „refused”. Testul ar pica, dar despre cu totul altceva decât ce spune, iar
    # cauza reală ar fi invizibilă într-un diff.
    ("bom",              chr(0xFEFF).encode() + ID_CORPUS.encode(),      "refused"),
    # NBSP: `str.strip()` fără argument îl taie, `[[:space:]]` din bash nu.
    # De-asta cititorul taie explicit doar cele șase caractere ASCII.
    ("nbsp",             "\xa0".encode() + ID_CORPUS.encode() + "\xa0".encode(), "refused"),
    ("control-char",     (ID_CORPUS + "\x01").encode(),               "refused"),
    # NUL: o variabilă de shell nu îl poate conține, `$(cat …)` îl aruncă tăcut.
    # E forma pe care o ia o scriere întreruptă pe ext4/xfs — blocul se
    # completează cu NUL, nu se taie — adică fix coruperea împotriva căreia e
    # pusă re-citirea de după generare.
    ("nul-suffix",       (ID_CORPUS + "\x00").encode(),               "refused"),
    ("nul-interior",     (ID_CORPUS[:16] + "\x00" + ID_CORPUS[16:]).encode(), "refused"),
    ("nul-only",         b"\x00",                                     "refused"),

    ("empty",            b"",                                         "minted"),
    ("whitespace-only",  b"\n",                                       "minted"),
]

# Etichetele fără de care corpusul nu mai e corpus.
#
# Aici a stat un `len(CORPUS) >= 20` cu 22 de intrări — adică exact două
# ștergibile, iar cele două care codifică ambele constatări blocante ale rundei
# 1 (`uppercase` și `nul-suffix`) erau printre ele. Se puteau șterge în tăcere:
# pragul satisfăcut, suita verde, acoperirea dispărută. Un prag numeric păzește
# golirea listei și absolut nimic altceva.
#
# Mulțimea, nu numărul, și SCRISĂ DE MÂNĂ, nu derivată din `CORPUS`: o listă
# calculată din chiar lista pe care o păzește se golește odată cu ea. Se pot
# ADĂUGA cazuri oricând; nu se poate scoate niciunul fără să se șteargă și
# numele de aici — adică fără o decizie, luată într-un loc unde se vede.
REQUIRED_LABELS = frozenset({
    "canonic", "trailing-lf", "crlf", "lone-cr", "double-lf", "spaces", "tab",
    "leading-zeros", "mixed-hex",
    "uppercase", "31-chars", "33-chars", "non-hex", "junk", "interior-space",
    "two-lines", "bom", "nbsp", "control-char",
    "nul-suffix", "nul-interior", "nul-only",
    "empty", "whitespace-only",
})


def _postgres_would_accept(value: str) -> bool:
    """Ce ar face `instance_id ~ '^[0-9a-f]{32}$'` în PostgreSQL, scris pe litere.

    NU `re.fullmatch` cu același tipar: asta ar compara motorul de regex din
    Python cu el însuși și ar numi rezultatul „acord cu baza de date". Un martor
    care nu poate fi în dezacord nu e un martor. Scris manual, modelul chiar
    poate să nu fie de acord cu Python — și atunci testul pică, ceea ce e tot
    rostul lui.

    Ce modelează, și unde PostgreSQL diferă de Python:

      * `~` e potrivire parțială; `^` și `$` o ancorează. În PostgreSQL `$`
        înseamnă SFÂRȘITUL ȘIRULUI, pe când în Python `$` se potrivește și
        chiar înaintea unui `\\n` final — deci `re.match` ar accepta „…\\n" pe
        care baza îl respinge. De-asta cititorul folosește `fullmatch`.
      * `text` în PostgreSQL nu poate conține NUL: valoarea e refuzată de
        driver înainte să ajungă la constrângere.
      * clasele de caractere sunt literale aici, deci nu depind de locale.

    Cele două puncte pe care le am măsurate pe PostgreSQL 16.14 de pe gazdă
    (32 hexa minuscule → t, majuscule → f) sunt de acord cu modelul.
    """
    if len(value) != 32:
        return False
    return all(c in "0123456789abcdef" for c in value)


CORPUS_HARNESS = """
source ./lib/common.sh
{step27}

# Nu se înregistrează doar ca să nu strice: apelurile SUNT verdictul.
#   chmod pe fișierul însuși -> valoarea a fost recunoscută și păstrată
#   chmod pe .tmp            -> s-a generat una nouă
#   niciun chmod             -> a fost refuzată
# Verdictul se citește din comportamentul livrat, nu dintr-un text în română
# pe care o retraducere l-ar schimba fără să schimbe nimic real.
chown() {{ printf 'chown %s\\n' "$*" >> "$CALLS"; }}
chmod() {{ printf 'chmod %s\\n' "$*" >> "$CALLS"; }}
openssl() {{ printf 'openssl %s\\n' "$*" >> "$CALLS"; printf '%s' "{stub}"; }}

for dir in "$CORPUS"/*/; do
    dir="${{dir%/}}"
    SENTINEL_CONFIG_DIR="$dir"
    CALLS="${{dir}}/.calls"
    : > "$CALLS"
    rc=0
    # În subshell: `die` din common.sh face `exit 1`, iar un `|| rc=$?` NU
    # oprește asta — ar fi ucis harness-ul la primul caz care moare și ar fi
    # retezat restul buclei. Simptomul ar fi fost „cazuri lipsă din rulare",
    # adică o eroare zgomotoasă care numește cauza greșită.
    ( ensure_instance_id ) >/dev/null 2>&1 || rc=$?

    # Valoarea pe care CHIAR a extras-o pasul, prin funcția lui, nu printr-o
    # re-implementare în harness. Hexa, ca să treacă orice octet prin stdout.
    INSTANCE_ID_READ=""
    read_rc=0
    read_instance_id_file "${{dir}}/instance_id" || read_rc=$?
    # `-v`, altfel `od` comprimă liniile identice consecutive într-un `*` și
    # exact valorile cele mai interesante — 32 de caractere identice — se
    # întorc trunchiate, fără ca nimic să spună asta.
    printf 'CASE %s %s %s %s\\n' "$(basename "$dir")" "$rc" "$read_rc" \\
        "$(printf '%s' "$INSTANCE_ID_READ" | od -An -tx1 -v | tr -d ' \\n')"
done
"""


def _run_corpus(tmp_path: Path) -> dict[str, dict]:
    corpus = tmp_path / "corpus"
    corpus.mkdir(parents=True)
    before: dict[str, bytes] = {}
    for label, payload, _ in CORPUS:
        d = corpus / label
        d.mkdir()
        (d / "instance_id").write_bytes(payload)
        before[label] = payload

    script = tmp_path / "corpus.sh"
    script.write_text(
        CORPUS_HARNESS.format(step27=step27_source(), stub=STUB_ID),
        encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        cwd=REPO / "deploy", capture_output=True,
        # LC_ALL=C: în bash, ce anume e `[[:space:]]` depinde de locale, deci
        # tăierea marginilor unei valori cu octeți non-ASCII e nedeterministă
        # între mașini. Fixat aici ca testul să dea același rezultat oriunde.
        #
        # Limita, spusă și nu ascunsă: install.sh rulează sub locale-ul sesiunii
        # de deploy, nu sub ăsta. Nu contează pentru ce se afirmă mai jos —
        # orice valoare ACCEPTATĂ e ASCII pur, unde toate locale-urile taie la
        # fel, iar orice valoare cu octeți non-ASCII e refuzată în oricare
        # dintre ele (tăiată parțial sau deloc, ce rămâne tot nu e 32 de hexa).
        env={**os.environ, "NO_COLOR": "1", "SENTINEL_USER": "sentinel",
             "LC_ALL": "C",
             "CORPUS": str(corpus).replace("\\", "/")},
    )
    stdout = proc.stdout.decode("utf-8", "replace")
    out: dict[str, dict] = {}
    for line in stdout.splitlines():
        if not line.startswith("CASE "):
            continue
        _, label, rc, read_rc, *rest = line.split(" ")
        d = corpus / label
        calls = (d / ".calls").read_text(encoding="utf-8") if (d / ".calls").exists() else ""
        after = (d / "instance_id").read_bytes() if (d / "instance_id").exists() else None
        if int(rc) != 0:
            verdict = "died"
        elif f"chmod 0640 {str(d).replace(chr(92), '/')}/instance_id.tmp" in calls:
            verdict = "minted"
        elif f"chmod 0640 {str(d).replace(chr(92), '/')}/instance_id" in calls:
            verdict = "kept"
        else:
            verdict = "refused"
        out[label] = {
            "verdict": verdict,
            "rc": int(rc),
            "read_rc": int(read_rc),
            "value": bytes.fromhex(rest[0]).decode("utf-8", "replace") if rest and rest[0] else "",
            "before": before[label],
            "after": after,
        }
    assert out, f"harness produced no CASE lines:\n{stdout}\n{proc.stderr.decode('utf-8','replace')}"
    return out


def test_all_three_validators_agree_on_every_candidate(tmp_path):
    """Un corpus, trei validatoare, același verdict de la fiecare.

    `install.sh` scrie fișierul, `sentinel/identity.py` îl citește, iar
    `0022_instance_identity.sql` păstrează oglinda. O gramatică scrisă de trei
    ori, în trei limbaje, fără nimic care să le lege, e defectul livrat de
    0015/0020 — parserul accepta ce baza respingea, iar funcționalitatea nu a
    fost niciodată salvabilă.

    Aici consecința e mai urâtă și mai tăcută: o valoare acceptată de fișier și
    respinsă de `INSERT` lasă oglinda goală pentru totdeauna, iar
    autoverificarea raportează „instalare proaspătă" la nesfârșit. Nimic nu se
    aprinde roșu; serverul pur și simplu nu apare niciodată în panou.
    """
    from sentinel.identity import IdentityError, read_instance_id

    labels = {label for label, _, _ in CORPUS}
    missing = REQUIRED_LABELS - labels
    assert not missing, (
        "cazuri scoase din corpus fără să fie scoase și din REQUIRED_LABELS: "
        f"{sorted(missing)}")
    assert len(labels) == len(CORPUS), "etichete duplicate în corpus"

    ran = _run_corpus(tmp_path)
    assert set(ran) == labels, f"cazuri lipsă din rulare: {sorted(labels - set(ran))}"
    died = sorted(l for l, r in ran.items() if r["verdict"] == "died")
    assert not died, f"pasul a murit pe: {died}"

    disagreements: list[str] = []
    for label, payload, expected in CORPUS:
        got = ran[label]

        # 1. bash: verdictul livrat, față de tabelul care e specificația.
        if got["verdict"] != expected:
            disagreements.append(
                f"{label}: install.sh a zis {got['verdict']}, se aștepta {expected}")
            continue

        # 2. python: acceptă exact ce a păstrat bash.
        probe = tmp_path / "probe"
        probe.write_bytes(payload)
        try:
            py_value: str | None = read_instance_id(probe)
        except IdentityError:
            py_value = None

        bash_accepted = expected == "kept"
        if (py_value is not None) != bash_accepted:
            disagreements.append(
                f"{label}: install.sh {'acceptă' if bash_accepted else 'refuză'}, "
                f"sentinel/identity.py {'acceptă' if py_value else 'refuză'}")
            continue

        if not bash_accepted:
            # Și nu doar că a refuzat: nu a atins fișierul.
            if got["verdict"] == "refused" and got["after"] != payload:
                disagreements.append(f"{label}: fișier refuzat DAR modificat")
            # A treia îl refuză și ea. Fără ramura asta, modelul de PostgreSQL
            # nu putea fi contrazis de nimic: pașii de dinainte au dovedit deja
            # că orice valoare ajunsă până la el e 32 de hexa minuscule, deci un
            # model care întoarce mereu `True` trecea. Un martor care nu poate
            # spune „nu" nu e un martor.
            stripped = payload.decode("utf-8", "replace").strip(" \t\n\r\v\f")
            if _postgres_would_accept(stripped):
                disagreements.append(
                    f"{label}: refuzată de fișier și de cititor, dar CHECK-ul "
                    f"din 0022 ar accepta-o")
            continue

        # 3. aceeași valoare extrasă de amândouă.
        if got["value"] != py_value:
            disagreements.append(
                f"{label}: bash a extras {got['value']!r}, python {py_value!r}")
            continue

        # 4. și PostgreSQL o primește — altfel oglinda nu se poate scrie
        #    niciodată, iar verificarea minte liniștit pentru totdeauna.
        if not _postgres_would_accept(py_value):
            disagreements.append(
                f"{label}: acceptată de fișier, respinsă de CHECK-ul din 0022")

    assert not disagreements, "cele trei nu sunt de acord:\n  " + "\n  ".join(disagreements)


def test_the_postgres_model_says_what_postgres_said():
    """Modelul e martorul; un martor necalibrat nu e martor.

    `_postgres_would_accept` e singura reprezentare a bazei de date pe care o
    are suita asta — nu există PostgreSQL pe mașina care rulează testele. Dacă
    modelul e greșit, tot testul de mai sus devine o părere.

    Primele două rânduri sunt MĂSURATE, pe PostgreSQL 16.14 de pe gazdă, cu
    CHECK-ul din 0022 aplicat:

            label      | sql_accepts
        ---------------+-------------
         good-32-lower | t
         uppercase     | f

    Restul sunt consecințe ale aceleiași expresii, ținute aici ca modelul să nu
    poată fi „reparat" într-o formă care acceptă orice. Rândul cu `\\n` final e
    cel care contează cel mai mult: acolo `$` din PostgreSQL și `$` din Python
    NU înseamnă același lucru, iar el e motivul pentru care cititorul folosește
    `fullmatch`.
    """
    cases: list[tuple[str, bool]] = [
        (ID_CORPUS, True),                       # măsurat pe gazdă: t
        (ID_CORPUS.upper(), False),              # măsurat pe gazdă: f
        ("0f1e2d3c4b5a69788796a5b4c3d2e1f0", True),
        ("0" * 32, True),
        (ID_CORPUS + "\n", False),               # `$` = sfârșit de șir, nu „înainte de \n"
        (ID_CORPUS[:31], False),
        (ID_CORPUS + "a", False),
        ("g" * 32, False),
        (ID_CORPUS[:16] + " " + ID_CORPUS[16:], False),
        (ID_CORPUS[:31] + "\x00", False),        # `text` nu poate purta NUL
        ("", False),
    ]
    assert len(cases) == 11, "tabelul de calibrare s-a golit"
    wrong = [(value, expected) for value, expected in cases
             if _postgres_would_accept(value) is not expected]
    assert not wrong, f"modelul nu mai descrie CHECK-ul din 0022: {wrong}"


def test_the_shape_is_still_written_the_same_in_all_three_files():
    """A doua plasă, și e doar a doua.

    Corpusul de mai sus prinde schimbarea SEMANTICII din jurul tiparului
    (`re.I`, `.lower()`, alt fel de tăiere). Asta prinde editarea tiparului
    însuși într-unul din cele trei fișiere — pe care corpusul nu o vede când
    modelul de PostgreSQL rămâne scris pe litere.
    """
    from sentinel.identity import _INSTANCE_ID_RE

    shape = _INSTANCE_ID_RE.pattern
    assert shape == "^[0-9a-f]{32}$"

    migration = (REPO / "sentinel" / "db" / "migrations"
                 / "0022_instance_identity.sql").read_text(encoding="utf-8")
    assert f"CHECK (instance_id ~ '{shape}')" in migration, \
        "CHECK-ul din 0022 nu mai e aceeași expresie ca cea din sentinel/identity.py"

    # Bash: FIECARE potrivire de formă din funcție, nu o numărătoare pe tot
    # pasul 27 — acolo mai există două `=~` care nu au legătură cu identitatea.
    bash_shapes = re.findall(r"=~\s+(\S+)", ensure_source())
    assert bash_shapes, "ensure_instance_id nu mai validează forma deloc"
    assert set(bash_shapes) == {shape}, bash_shapes
    assert len(bash_shapes) >= 2, \
        "forma se verifică într-un singur loc: o dată la păstrare ȘI o dată după scriere"


def test_the_generator_produces_exactly_what_the_readers_demand():
    """32 de caractere hexa = `rand -hex 16`. `-hex 32` ar da 64 și fiecare
    cititor l-ar refuza; `-hex 8` ar da 16, acceptate de nimeni. Legătura dintre
    lungimea cerută și comanda care o produce e cea care se rupe la o editare
    grăbită."""
    assert "openssl rand -hex 16" in step27_source()


# ---------------------------------------------------------------------------
# Premisa: fișierul chiar e lizibil de procesul care îl citește
# ---------------------------------------------------------------------------
def test_the_daemon_user_is_in_the_group_that_owns_the_file():
    """`0640 root:sentinel` e lizibil DOAR prin grup.

    Dacă utilizatorul `sentinel` ar fi creat cu alt grup principal și fără
    apartenență la `sentinel`, fișierul ar fi ilizibil pentru fiecare serviciu,
    iar simptomul ar fi o verificare „unknown" permanentă, pusă pe seama
    fișierului în loc de pe a contului.
    """
    assert 'groupadd --system "$SENTINEL_USER"' in INSTALL
    assert re.search(r'useradd --system --gid "\$SENTINEL_USER"', INSTALL), \
        "utilizatorul sentinel nu mai are grupul sentinel ca grup principal"
    # Și directorul: 0750 root:sentinel, altfel nu se poate nici traversa.
    assert re.search(
        r'install -d -m 0750 -o root -g "\$SENTINEL_USER"\s+"\$SENTINEL_CONFIG_DIR"',
        INSTALL), "/etc/sentinel nu mai e traversabil de grupul sentinel"


@pytest.mark.parametrize("unit", ["sentinel-selfcheck.service", "sentinel-beacon.service"])
def test_the_units_that_read_the_identity_run_as_that_group(unit):
    """Cele două unități care au nevoie de identitate. `User=sentinel` fără
    `Group=sentinel` ar lăsa grupul la alegerea systemd, iar citirea prin grup e
    tot ce face fișierul lizibil."""
    text = (REPO / "deploy" / "systemd" / unit).read_text(encoding="utf-8")
    assert "User=sentinel" in text
    assert "Group=sentinel" in text
    # ProtectSystem=strict face totul read-only; /etc/sentinel trebuie declarat
    # explicit ca lizibil, altfel unitatea nu vede nici măcar fișierul.
    assert "ReadOnlyPaths=/etc/sentinel" in text


# ---------------------------------------------------------------------------
# Oglinda: un singur rând, impus de schemă
# ---------------------------------------------------------------------------
def test_the_mirror_table_can_hold_only_one_row():
    """Prin convenție („scriem doar un rând, avem grijă") cedează exact în cazul
    pentru care există tabela: două scrieri, două valori, iar un `SELECT` fără
    `ORDER BY` întoarce oricare. Verificarea ar compara fișierul cu un rând ales
    la întâmplare — nepotrivire într-o zi, niciuna în următoarea."""
    sql = (REPO / "sentinel" / "db" / "migrations"
           / "0022_instance_identity.sql").read_text(encoding="utf-8")

    # Definiția coloanei, nu formatarea ei. Versiunea dinainte cerea exact trei
    # spații între `only_row` și `boolean`; un `pg_format` peste fișier ar fi
    # picat șapte teste fără să schimbe nimic din ce face PostgreSQL. Un test
    # care pică la reformatare e un test pe care următorul om îl șterge.
    body = re.search(r"CREATE TABLE[^(]*instance_identity\s*\((.*?)\n\);",
                     sql, re.S)
    assert body, "tabela instance_identity nu se mai creează aici"
    column = next((c for c in re.split(r",\s*\n", body.group(1))
                   if re.match(r"\s*only_row\b", c)), None)
    assert column, "coloana only_row a dispărut — nimic nu mai limitează numărul de rânduri"

    flat = " ".join(column.split())
    assert re.search(r"\bonly_row\s+boolean\b", flat), flat
    assert "PRIMARY KEY" in flat, \
        "only_row nu mai e cheie primară: al doilea rând nu se mai lovește de unicitate"
    assert re.search(r"CHECK\s*\(\s*only_row\s*\)", flat), \
        "fără CHECK, un al doilea rând scris cu only_row = false intră liniștit"

    assert "COMMENT ON TABLE instance_identity" in sql


# ---------------------------------------------------------------------------
# Poarta de repornire: un beacon fără identitate NU se repornește în tăcere
# ---------------------------------------------------------------------------
def lift(*names: str) -> str:
    """Corpurile funcțiilor cerute, decupate verbatim din install.sh.

    Decupate, nu rescrise: un harness care reimplementează ce verifică a trecut
    deja verde peste cod rupt în depozitul ăsta.
    """
    out = []
    for name in names:
        match = re.search(rf"^{name}\(\)\s*\{{.*?^\}}", INSTALL, re.S | re.M)
        assert match, f"{name}() nu mai există în install.sh"
        out.append(match.group(0))
    return "\n".join(out)


BEACON_HARNESS = """
set -u
SENTINEL_CONFIG_DIR="$CFG"
INSTANCE_ID_READ=""

ok()   {{ printf 'ok %s\n'   "$*" >> "$CALLS"; }}
info() {{ printf 'info %s\n' "$*" >> "$CALLS"; }}
warn() {{ printf 'warn %s\n' "$*" >> "$CALLS"; }}
systemctl() {{ printf 'systemctl %s\n' "$*" >> "$CALLS"; }}
sleep() {{ :; }}

{bodies}
{call}
printf 'RC=%s\n' "$?"
"""


def run_beacon(tmp_path: Path, identity: str | None, bodies: str, call: str,
               **env: str) -> dict:
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    if identity is not None:
        (cfg / "instance_id").write_text(identity, encoding="utf-8", newline="\n")
    unit = tmp_path / "sentinel-beacon.service"
    unit.write_text("[Unit]\n", encoding="utf-8", newline="\n")

    calls = tmp_path / "calls.txt"
    calls.unlink(missing_ok=True)
    script = tmp_path / "beacon.sh"
    script.write_text(BEACON_HARNESS.format(bodies=bodies, call=call),
                      encoding="utf-8", newline="\n")
    proc = subprocess.run(
        [BASH, str(script).replace("\\", "/")],
        capture_output=True, text=True,
        env={**os.environ, "NO_COLOR": "1",
             "CFG": str(cfg).replace("\\", "/"),
             "UNIT": str(unit).replace("\\", "/"),
             "CALLS": str(calls).replace("\\", "/"), **env})
    return {"proc": proc,
            "calls": calls.read_text(encoding="utf-8") if calls.exists() else ""}


def start_beacon(tmp_path: Path, identity: str | None) -> dict:
    return run_beacon(tmp_path, identity,
                      lift("read_instance_id_file", "start_beacon_unit"),
                      'start_beacon_unit "$UNIT"')


def test_a_valid_identity_lets_the_beacon_be_restarted(tmp_path):
    """Cazul normal. Fără el, testele de mai jos ar trece și peste o poartă
    închisă permanent — adică peste un beacon care nu se mai actualizează
    niciodată, rulând la nesfârșit codul unei livrări vechi."""
    out = start_beacon(tmp_path, STUB_ID + "\n")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "systemctl restart sentinel-beacon.service" in out["calls"], out["calls"]


def test_a_missing_identity_stops_the_restart(tmp_path):
    """Repornit fără identitate, expeditorul refuză să trimită (asta e
    proiectarea din sentinel/report/beacon.py) și gazda amuțește pentru martor,
    care raportează corect o alarmă critică despre un server sănătos.

    Procesul vechi lăsat pornit continuă să bată cu codul dinaintea livrării —
    mai puțin rău decât tăcerea, fiindcă `code:current` din autodiagnostic îl
    raportează, iar tăcerea nu se raportează de nicăieri.
    """
    out = start_beacon(tmp_path, None)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "restart" not in out["calls"], out["calls"]
    assert "--force-step 27" in out["calls"], \
        "refuzul nu spune cum se repară — un refuz fără ieșire e o fundătură"


@pytest.mark.parametrize(
    "content",
    [STUB_ID[:20], STUB_ID.upper(), "nu-e-o-identitate", "\n",
     STUB_ID + " " + STUB_ID],
    ids=["truncat", "majuscule", "text", "gol", "doua-valori"])
def test_a_file_that_is_not_an_identity_stops_the_restart(tmp_path, content):
    """`ensure_instance_id` refuză DELIBERAT să rescrie un fișier existent dar
    nevalid — avertizează și iese cu 0. Deci cazul ăsta supraviețuiește pasului
    care ar fi trebuit să-l repare, și e singurul care mai ajunge la poarta asta
    după ce apelul a devenit necondiționat.
    """
    out = start_beacon(tmp_path, content)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "restart" not in out["calls"], out["calls"]


def test_the_gate_reads_the_file_through_the_null_safe_reader(tmp_path):
    """Un fișier completat cu NUL de un sistem de fișiere care a pierdut curentul
    e forma cea mai probabilă a unei scrieri parțiale. `$(cat …)` aruncă tăcut
    octetul, deci o valoare de 32 de hexa urmată de NUL ar fi trecut drept
    identitate validă aici, în timp ce sentinel/identity.py o refuză — adică
    instalare verde peste un beacon care nu poate porni."""
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "instance_id").write_bytes(STUB_ID.encode() + b"\x00")
    out = start_beacon(tmp_path, None)  # nu suprascrie: identity=None
    assert "restart" not in out["calls"], out["calls"]


# ---------------------------------------------------------------------------
# Aceeași poartă pentru expeditorul de loturi
#
# Cu o miză diferită, și de-asta are teste proprii în loc să fie presupusă din
# cele de mai sus: un beacon mut produce o alarmă critică FALSĂ la martor, iar un
# expeditor mut nu produce nicio alarmă externă — rândurile rămân în coadă și
# singurul care spune ceva e `ship:lag`, la următoarea rulare a
# `sentinel-selfcheck.timer`. Tăcerea aia e mai ușor de ratat, nu mai greu.
# ---------------------------------------------------------------------------
def start_shipper(tmp_path: Path, identity: str | None) -> dict:
    return run_beacon(tmp_path, identity,
                      lift("read_instance_id_file", "start_shipper_unit"),
                      'start_shipper_unit "$UNIT"')


def test_a_valid_identity_lets_the_shipper_be_restarted(tmp_path):
    """Cazul normal. Fără el, testele de mai jos ar trece și peste o poartă
    închisă permanent — adică peste un expeditor care nu se mai actualizează
    niciodată și rulează la nesfârșit codul unei livrări vechi."""
    out = start_shipper(tmp_path, STUB_ID + "\n")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "systemctl restart sentinel-shipper.service" in out["calls"], out["calls"]


def test_the_shipper_unit_is_enabled_even_when_it_will_not_be_started(tmp_path):
    """Activarea e NECONDIȚIONATĂ, și asta e jumătatea care a lipsit.

    Pasul de instalare copiază fiecare `deploy/systemd/*.service`, deci unitatea
    ajunge pe gazdă oricum. Copiată și neactivată, nu pornește la boot și nu
    pornește deloc: operatorul pune `ship.enabled: true`, repornește, și nu se
    întâmplă nimic — iar `scripts/smoke-test.sh`, care enumeră unitățile de pe
    disc, o găsește `inactive` fără timer și raportează deployment eșuat.

    Cazul verificat aici e cel mai strâns: identitate stricată, deci repornirea e
    refuzată. Activarea trebuie să se fi întâmplat oricum — altfel „turning it on
    later" e o sesiune de arheologie, exact ce spune comentariul beaconului.
    """
    out = start_shipper(tmp_path, "nu-e-o-identitate")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "systemctl enable sentinel-shipper.service" in out["calls"], out["calls"]
    assert "restart" not in out["calls"], out["calls"]


@pytest.mark.parametrize(
    "content",
    [None, STUB_ID[:20], STUB_ID.upper(), "nu-e-o-identitate", "\n"],
    ids=["lipsă", "truncat", "majuscule", "text", "gol"])
def test_a_file_that_is_not_an_identity_stops_the_shipper_restart(tmp_path, content):
    """Repornit peste o identitate stricată, un expeditor care EXPEDIA devine
    unul care nu mai expediază: `ship_once` întoarce `ShipResult(False, "fără
    identitate de instalare")` la fiecare rundă, iar rândurile nu ajung nicăieri
    cât timp nu se uită nimeni. Procesul vechi, lăsat pornit, expediază mai
    departe sub identitatea pe care a citit-o deja."""
    out = start_shipper(tmp_path, content)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "restart" not in out["calls"], out["calls"]
    assert "--force-step 27" in out["calls"], \
        "refuzul nu spune cum se repară — un refuz fără ieșire e o fundătură"


def test_the_deploy_step_calls_the_shipper_gate(tmp_path):
    """O poartă scrisă și nechemată nu apără nimic, iar tăcerea ei arată identic
    cu a uneia care a lăsat totul să treacă. Verificat pe textul livrat, fiindcă
    apelul trăiește în alt loc decât funcția."""
    assert re.search(r"^\s*start_shipper_unit /etc/systemd/system/"
                     r"sentinel-shipper\.service\s*$", INSTALL, re.M), \
        "start_shipper_unit nu mai e chemată din pasul de unități"


# ---------------------------------------------------------------------------
# Proba de fum: „activ" nu înseamnă „bate"
# ---------------------------------------------------------------------------
def run_smoke(tmp_path: Path, active: bool, seqs: list[str],
              interval: str | None = None) -> dict:
    """`seqs` sunt valorile pe care le întoarce `beacon_seq`, în ordine.

    `interval` scrie un `sentinel.yaml` adevărat, ca fereastra de așteptare să
    fie citită de codul livrat din configurație, nu injectată de harness.
    """
    feed = tmp_path / "seq.txt"
    feed.write_text("\n".join(seqs) + "\n", encoding="utf-8", newline="\n")
    if interval is not None:
        cfg = tmp_path / "etc"
        cfg.mkdir(parents=True, exist_ok=True)
        (cfg / "sentinel.yaml").write_text(
            "timezone: Europe/Bucharest\n"
            "web:\n  port: 8787\n  interval_s: 999\n"
            f"beacon:\n  enabled: true\n  interval_s: {interval}\n  timeout_s: 10\n",
            encoding="utf-8", newline="\n")
    bodies = lift("smoke_beacon_is_beating", "beacon_interval_s") + f"""
beacon_seq() {{
    local n
    n=$(( $(cat "$CFG/n" 2>/dev/null || echo 0) + 1 ))
    printf '%s' "$n" > "$CFG/n"
    sed -n "${{n}}p" "$FEED"
}}
systemctl() {{
    printf 'systemctl %s\n' "$*" >> "$CALLS"
    [[ "{int(active)}" == "1" ]]
}}
"""
    return run_beacon(tmp_path, None, bodies, "smoke_beacon_is_beating",
                      FEED=str(feed).replace("\\", "/"))


def test_the_smoke_test_passes_when_the_counter_advances(tmp_path):
    """Celălalt capăt: o poartă care se plânge mereu e una care se scoate."""
    out = run_smoke(tmp_path, active=True, seqs=["7063", "7064"])
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "ok beaconul bate" in out["calls"], out["calls"]


def test_an_active_beacon_that_never_sends_is_reported(tmp_path):
    """Faptul care ar fi prins pana din august 2026.

    `sentinel-beacon` poate fi `active` și complet mut: fără identitate,
    expeditorul nu trimite nimic și rămâne în picioare dinadins. Instalarea
    tipărea verde peste asta, iar prima veste era alarma critică a martorului —
    `is-active` verificat în loc de efect, cu un strat mai sus.
    """
    out = run_smoke(tmp_path, active=True, seqs=["7063"] * 30)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "warn" in out["calls"], out["calls"]
    assert "instance_id" in out["calls"], \
        "avertismentul nu numește cauza cea mai probabilă"


def test_an_inactive_beacon_is_not_a_smoke_test_failure(tmp_path):
    """Fără martor extern configurat, unitatea e oprită intenționat. A raporta
    asta ca defect la fiecare instalare e clasa de alarmă falsă care golește de
    sens toate celelalte avertismente ale instalatorului."""
    out = run_smoke(tmp_path, active=False, seqs=[""])
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "warn" not in out["calls"], out["calls"]
    assert "info" in out["calls"]


def test_the_inactive_line_states_what_was_seen_not_why(tmp_path):
    """Starea asta se atinge și cu martorul configurat perfect.

    Identitate coruptă → `ensure_instance_id` refuză rescrierea → poarta refuză
    repornirea → unitatea rămâne activată și nepornită. O propoziție care spune
    „martorul nu e configurat" e atunci o cauză pe care verificarea nu s-a uitat
    la ea, adică o liniștire inventată — chiar tiparul pentru care există
    funcția asta.
    """
    out = run_smoke(tmp_path, active=False, seqs=[""])
    assert "nu rulează" in out["calls"], out["calls"]
    assert "configurat" not in out["calls"], \
        "linia afirmă o cauză pe care nu a verificat-o"


def test_an_empty_answer_from_the_database_is_not_a_beat(tmp_path):
    """`beacon_seq` întoarce șir gol și când interogarea EȘUEAZĂ.

    Stderr-ul ei merge la /dev/null, deci postgres repornit, o limită de
    conexiuni atinsă sau un socket căzut arată identic cu „nu există rândul".
    Fără garda `-n`, primul astfel de eșec e „diferit de valoarea dinainte", iar
    instalarea tipărește o linie VERDE de succes cu dovada goală în ea —
    `beacon:seq 7098 → , în 5s`. Adică exact minciuna pe care funcția asta o
    oprește cu un strat mai jos: un cod de ieșire luat drept efect.
    """
    out = run_smoke(tmp_path, active=True, seqs=["7098"] + [""] * 30)
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "ok beaconul bate" not in out["calls"], out["calls"]
    assert "warn" in out["calls"]
    assert "7098" in out["calls"], "avertismentul nu spune la ce valoare a rămas"


def test_a_transient_probe_failure_does_not_end_the_wait(tmp_path):
    """Cealaltă jumătate: o sondă care clipește nu are voie să strice proba.

    Fără asta, garda `-n` s-ar putea implementa ca `return 1` la primul răspuns
    gol, iar o secundă de indisponibilitate a bazei în timpul instalării ar
    produce un avertisment despre un beacon perfect sănătos.
    """
    out = run_smoke(tmp_path, active=True, seqs=["7098", "", "", "7099"])
    assert "ok beaconul bate" in out["calls"], out["calls"]
    assert "7099" in out["calls"]


# ---------------------------------------------------------------------------
# Fereastra de așteptare se derivă din cadență
# ---------------------------------------------------------------------------
def test_a_slow_beacon_is_waited_for_instead_of_being_accused(tmp_path):
    """`beacon.interval_s` nu are limită superioară în `_validate`.

    Cu o fereastră fixă de 90 s, un interval de 120 s — perfectly valid — face
    proba de fum să se plângă la FIECARE instalare despre un beacon sănătos. Un
    avertisment care apare de fiecare dată e unul pe care operatorul îl
    filtrează, inclusiv în ziua în care e adevărat.

    Aici semnalul apare abia la a 21-a sondă, adică după 105 s: peste fereastra
    fixă, sub cea derivată (2 × 120).
    """
    out = run_smoke(tmp_path, active=True, seqs=["7098"] + [""] * 20 + ["7099"],
                    interval="120")
    assert out["proc"].returncode == 0, out["proc"].stderr
    assert "ok beaconul bate" in out["calls"], out["calls"]
    assert "105s" in out["calls"], out["calls"]


def test_a_fast_beacon_does_not_shorten_the_window_below_the_floor(tmp_path):
    """Cu `interval_s: 5`, `2 × interval` ar fi 10 secunde — două sonde.

    O repornire de serviciu sau o bază ocupată depășește asta banal, deci
    fereastra ar deveni o monedă aruncată. Podeaua de 90 s rămâne.
    """
    out = run_smoke(tmp_path, active=True, seqs=["7098"] + [""] * 10 + ["7099"],
                    interval="5")
    assert "ok beaconul bate" in out["calls"], out["calls"]
    assert "55s" in out["calls"], out["calls"]


def test_an_unreadable_config_falls_back_to_the_documented_default(tmp_path):
    """Nu există `sentinel.yaml` de citit.

    „Nu știu cadența" nu are voie să însemne „așteaptă oricât" și nici „nu
    aștepta": valoarea de rezervă e cea din `BeaconConfig`, deci fereastra e
    exact cea dinainte de schimbarea asta.
    """
    out = run_beacon(tmp_path, None, lift("beacon_interval_s"),
                     'printf "INTERVAL=%s\\n" "$(beacon_interval_s)" >> "$CALLS"')
    assert "INTERVAL=60" in out["calls"], out["calls"]


def test_the_interval_is_read_from_the_beacon_block(tmp_path):
    """Un `interval_s` există și în alte secțiuni din `sentinel.yaml`.

    Un `grep interval_s` peste tot fișierul ar lua prima potrivire — a altui
    subsistem — și ar produce o fereastră care n-are nicio legătură cu beaconul,
    în oricare dintre direcțiile greșite.
    """
    cfg = tmp_path / "etc"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "sentinel.yaml").write_text(
        "ingest:\n  interval_s: 7\n"
        "beacon:\n  enabled: true\n  interval_s: 45\n"
        "health:\n  interval_s: 900\n",
        encoding="utf-8", newline="\n")
    out = run_beacon(tmp_path, None, lift("beacon_interval_s"),
                     'printf "INTERVAL=%s\\n" "$(beacon_interval_s)" >> "$CALLS"')
    assert "INTERVAL=45" in out["calls"], out["calls"]
