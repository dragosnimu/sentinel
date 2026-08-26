"""Autentificarea panoului agregator trebuie să fie geamăna celei de pe server.

`sentinel/web/security.py` e ștacheta, scrisă așa în plan: „574 de linii. Nu se
coboară." Piesa de pe agregator e o rescriere în alt limbaj, cu altă bibliotecă
de Argon2 și cu alt TOTP — adică exact situația în care s-au născut cele patru
divergențe canonice dintre `sentinel/report/signing.py` și `aggregator/lib/verify.ts`,
descoperite una câte una, fiecare într-o pană.

## Ce apără testul ăsta, în termeni de ce se strică

Nimic din ce urmează nu produce un simptom în ziua în care se strică:

  * un parametru Argon2id coborât — parolele panoului devin mai ieftin de spart
    offline, iar panoul e SINGURUL control care apără istoricul derivat a N
    servere pe o găzduire partajată. Nimic nu arată altfel;
  * un algoritm TOTP care diferă printr-un digest sau printr-o trunchiere —
    codurile generate de telefonul operatorului nu se potrivesc niciodată, iar
    mesajul spune „cod incorect";
  * o fereastră mai largă la un capăt — un cod capturat rămâne valabil mai mult
    decât crede oricine citește documentația;
  * un vocabular de roluri divergent — un rol scris pe server nu există pe
    agregator, iar `CHECK`-ul îl refuză la prima scriere.

## Cum se probează, și de ce nu prin comparație de numere

Comparația de constante trece peste o bibliotecă ce ar ignora tăcut un parametru.
Deci acordul se cere prin EFECT, în ambele direcții:

  * un hash produs de agregator se dă verificatorului REAL al serverului
    (`security.verify_password`), iar acesta trebuie să-l accepte ȘI să spună că
    nu cere re-hash — adică `argon2-cffi` recunoaște parametrii ca fiind cei de
    azi. Un `m=32768` la celălalt capăt trece de orice comparație de șiruri și
    pică aici;
  * un hash produs de server se dă verificatorului agregatorului;
  * codurile TOTP se cer identice de la `pyotp` și de la implementarea de pe
    agregator, pentru mai multe contoare.

## De ce se cheamă `node`

Ca la celelalte teste trans-limbaj din depozit (`test_aggregator_secret_form.py`,
`test_aggregator_stream_columns.py`): partea de verificat e cea LIVRATĂ, nu o
transcriere a ei în Python. Lipsa lui `node` sau a lui `node_modules` e SKIP cu
motiv scris — „n-am putut verifica" și „e în regulă" sunt stări diferite.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU s-a verificat că autentificarea "
    "agregatorului are aceiași parametri ca cea de pe server. Nu e „în regulă”, "
    "e „neverificat”."
)
_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva. "
    "Rulează `npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

# Parolă și secret evident false, ca peste tot în teste.
PASSWORD = "parola-de-proba-pentru-acord-2026"
TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
COUNTERS = [0, 1, 58666666, 58666667, 99999999]

BRIDGE = """
import {
  ARGON2_HASH_BYTES, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_SALT_BYTES,
  ARGON2_TIME_COST, MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH, hashPassword,
  verifyPassword,
} from "../lib/auth/password.ts";
import {
  TOTP_DIGITS, TOTP_INTERVAL_S, TOTP_VALID_WINDOW, codeForCounter, verifyCode,
} from "../lib/auth/totp.ts";
import {
  CSRF_TOKEN_BYTES, PENDING_TOTP_TTL_S, SESSION_TOKEN_BYTES, hashToken, newToken,
} from "../lib/auth/session.ts";

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { raw += c; });
process.stdin.on("end", async () => {
  const input = JSON.parse(raw);
  const out = {
    constants: {
      ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_HASH_BYTES,
      ARGON2_SALT_BYTES, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH,
      TOTP_DIGITS, TOTP_INTERVAL_S, TOTP_VALID_WINDOW,
      SESSION_TOKEN_BYTES, CSRF_TOKEN_BYTES, PENDING_TOTP_TTL_S,
    },
    hashedHere: await hashPassword(input.password),
    verdictOnServerHash: await verifyPassword(input.serverHash, input.password),
    verdictOnWrongPassword: await verifyPassword(input.serverHash, input.password + "x"),
    totp: {},
    window: {},
    tokenHash: hashToken(input.password),
    tokenLength: newToken().length,
  };
  for (const counter of input.counters) {
    out.totp[String(counter)] = codeForCounter(input.totpSecret, counter);
  }
  // Fereastra, cerută prin efect: ce OFFSET-uri acceptă implementarea, la un
  // moment fix.
  for (const offset of [-3, -2, -1, 0, 1, 2, 3]) {
    const at = input.at;
    const counter = Math.floor(at / 30) + offset;
    const code = codeForCounter(input.totpSecret, counter);
    out.window[String(offset)] = verifyCode(input.totpSecret, code, at);
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def _run_bridge(payload: dict) -> dict:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-auth-parity-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        script.write_text(BRIDGE, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, "--import", "tsx", str(script)],
            input=json.dumps(payload), cwd=AGGREGATOR, capture_output=True,
            text=True, encoding="utf-8", timeout=300,
            env={**os.environ, "NO_COLOR": "1"},
        )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def bridge() -> dict:
    """O singură trecere prin Node pentru tot fișierul.

    Fiecare hash Argon2id costă ~150 ms la parametrii ceruți, iar pornirea lui
    `tsx` încă vreo secundă. Un proces per test ar face suita să coste minute
    pentru aceleași fapte.
    """
    from sentinel.web import security

    return _run_bridge({
        "password": PASSWORD,
        "serverHash": security.hash_password(PASSWORD),
        "totpSecret": TOTP_SECRET,
        "counters": COUNTERS,
        "at": 1_760_000_000,
    })


def test_the_two_ends_agree_on_the_argon2_parameters(bridge):
    """Un parametru coborât pe agregator nu se vede în niciun simptom.

    Panoul e singurul control care apără istoricul derivat a N servere pe o
    găzduire partajată — fără sandbox systemd, fără SELinux, fără fail2ban al
    nostru, cu personalul furnizorului având acces la bază. Ce se strică e că
    parolele devin mai ieftin de spart offline, iar asta se află abia după.
    """
    from sentinel.web import security

    hasher = security._HASHER
    constants = bridge["constants"]
    assert constants["ARGON2_TIME_COST"] == hasher.time_cost
    assert constants["ARGON2_MEMORY_KIB"] == hasher.memory_cost
    assert constants["ARGON2_PARALLELISM"] == hasher.parallelism
    assert constants["ARGON2_HASH_BYTES"] == hasher.hash_len
    assert constants["ARGON2_SALT_BYTES"] == hasher.salt_len

    # Și valorile chiar sunt cele scrise în plan, nu doar egale între ele: două
    # capete coborâte deodată ar trece aserțiunile de mai sus.
    assert (hasher.time_cost, hasher.memory_cost, hasher.parallelism) == (3, 65536, 2)


def test_a_hash_made_by_the_aggregator_is_current_for_the_server(bridge):
    """Acordul cerut prin EFECT, nu prin comparație de numere.

    O bibliotecă de Argon2 care ar ignora tăcut un parametru trece de orice
    comparație de constante. Aici hashul produs de agregator ajunge în fața
    verificatorului REAL al serverului: dacă parametrii ar diferi,
    `check_needs_rehash` ar cere ridicarea lui, iar asta e chiar semnalul.
    """
    from sentinel.web import security

    ok, needs_rehash = security.verify_password(bridge["hashedHere"], PASSWORD)
    assert ok, "serverul nu acceptă un hash produs de agregator"
    assert not needs_rehash, (
        "serverul acceptă hashul agregatorului dar îi cere ridicarea: parametrii "
        f"diferă. Hash: {bridge['hashedHere'].rsplit('$', 2)[0]}")

    # Și invers: verificatorul agregatorului acceptă un hash produs de server.
    assert bridge["verdictOnServerHash"] == {"ok": True, "needsRehash": False}
    assert bridge["verdictOnWrongPassword"]["ok"] is False


def test_the_two_ends_agree_on_the_password_length_bounds(bridge):
    """Plafonul de sus e o apărare împotriva arderii de CPU în Argon2, nu o
    preferință de stil, și rămâne comun.

    Minimele NU mai sunt egale de pe 19 august 2026, iar testul cere de aceea
    valorile EXACTE, nu egalitatea lor. Motivul: „egale" ar fi rămas verde dacă
    ambele capete ar fi alunecat împreună la 4, iar după ce o divergență devine
    permisă o dată, cea mai ieftină greșeală următoare e să pară că a fost
    permisă și a doua oară.

    Divergența e o decizie a operatorului, nu o scăpare: minimul agregatorului a
    fost coborât la 8 în aceeași zi în care al doilea factor a devenit opțional.
    Ce se pierde e scris în `aggregator/lib/auth/password.ts` — pe găzduirea
    partajată parola devine singurul control, iar plafonul global de eșecuri e
    tot ce mărginește ghicitul. Serverul rămâne la 12 fiindcă nimeni n-a cerut
    altceva, iar panoul lui e pe loopback.

    Eșecul pe care îl previne, azi: cineva „aliniază" cele două capete
    modificându-l pe cel greșit — coboară serverul la 8 în loc să ridice
    agregatorul — și niciun simptom nu apare în ziua aia.
    """
    from sentinel.web import security

    constants = bridge["constants"]
    assert security.MIN_PASSWORD_LENGTH == 12, (
        "ștacheta serverului s-a mișcat; ea n-a fost cerută de nimeni")
    assert constants["MIN_PASSWORD_LENGTH"] == 8, (
        "minimul agregatorului nu mai e cel decis pe 19 august 2026")
    assert constants["MAX_PASSWORD_LENGTH"] == 1024, (
        "plafonul de sus trebuie să rămână comun; el apără CPU-ul, nu stilul")

    # Plafonul de sus e un literal în `validate_password_strength`, nu o
    # constantă exportată; se citește deci prin PURTARE, de la funcția reală.
    limit = constants["MAX_PASSWORD_LENGTH"]
    security.validate_password_strength("a" * limit)
    with pytest.raises(ValueError):
        security.validate_password_strength("a" * (limit + 1))
    with pytest.raises(ValueError):
        security.validate_password_strength("a" * (constants["MIN_PASSWORD_LENGTH"] - 1))


def test_the_two_ends_produce_the_same_totp_codes(bridge):
    """Un digest sau o trunchiere diferită se vede ca „cod incorect", la fiecare
    încercare, pentru totdeauna — iar operatorul își schimbă parola crezând că
    aia e problema.

    Nu se compară constantele: se cer ACELEAȘI CIFRE de la `pyotp` — biblioteca
    reală a serverului — și de la implementarea agregatorului, pentru mai multe
    contoare, inclusiv două vecine.
    """
    import pyotp

    from sentinel.web import security

    constants = bridge["constants"]
    assert constants["TOTP_DIGITS"] == security.TOTP_DIGITS
    assert constants["TOTP_INTERVAL_S"] == security.TOTP_INTERVAL
    assert constants["TOTP_VALID_WINDOW"] == security.TOTP_VALID_WINDOW

    totp = pyotp.TOTP(TOTP_SECRET, digits=security.TOTP_DIGITS,
                      interval=security.TOTP_INTERVAL)
    mismatches = []
    for counter in COUNTERS:
        expected = totp.at(counter * security.TOTP_INTERVAL)
        got = bridge["totp"][str(counter)]
        if expected != got:
            mismatches.append(f"contorul {counter}: pyotp {expected}, agregator {got}")
    assert not mismatches, "coduri TOTP diferite: " + " · ".join(mismatches)
    # Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
    assert len(COUNTERS) >= 5


def test_the_accepted_totp_window_is_the_same_at_both_ends(bridge):
    """O fereastră mai largă la un capăt înseamnă că un cod capturat rămâne
    valabil mai mult decât spune documentația; una mai îngustă, că un ceas
    derapat cu 20 de secunde ține pe cineva afară."""
    accepted = {int(offset) for offset, counter in bridge["window"].items()
                if counter is not None}
    assert accepted == {-1, 0, 1}, f"agregatorul acceptă offset-urile {sorted(accepted)}"

    # Aceeași întrebare, pusă implementării serverului: ce offset-uri acceptă
    # `verify_totp_code`. Se compară MULȚIMILE, nu constanta.
    import time
    from unittest import mock

    import pyotp

    from sentinel.web import security

    at = 1_760_000_000
    totp = pyotp.TOTP(TOTP_SECRET, digits=security.TOTP_DIGITS,
                      interval=security.TOTP_INTERVAL)
    server_accepted = set()
    with mock.patch.object(time, "time", return_value=at):
        for offset in (-3, -2, -1, 0, 1, 2, 3):
            code = totp.at(at + offset * security.TOTP_INTERVAL)
            if security.verify_totp_code(TOTP_SECRET, code) is not None:
                server_accepted.add(offset)
    assert server_accepted == accepted, (
        f"serverul acceptă {sorted(server_accepted)}, agregatorul {sorted(accepted)}")


def test_the_two_ends_agree_on_the_session_token_shape(bridge):
    """Forma jetonului e o proprietate de securitate, nu o convenție.

    32 de octeți din CSPRNG e ce face imposibilă ghicirea; SHA-256 în bază e ce
    face un dump inutil. Un capăt care ar stoca jetonul, sau l-ar scurta, nu se
    vede în niciun test funcțional — sesiunile ar merge perfect.
    """
    from sentinel.db.repo import sessions

    constants = bridge["constants"]
    assert constants["SESSION_TOKEN_BYTES"] == sessions.TOKEN_BYTES
    assert constants["CSRF_TOKEN_BYTES"] == sessions.CSRF_BYTES
    assert constants["PENDING_TOTP_TTL_S"] == sessions.PENDING_TOTP_TTL_S

    # Hashul e ACELAȘI, nu doar „tot un sha256": cifrat altfel (majuscule,
    # base64, cu sare), un jeton mutat între cele două scheme n-ar mai fi
    # recunoscut, iar asta e chiar migrarea pe care cineva o va încerca într-o zi.
    assert bridge["tokenHash"] == sessions.hash_token(PASSWORD)
    assert len(bridge["tokenHash"]) == 64
    assert bridge["tokenLength"] == len(sessions.new_token())


def test_every_auth_constant_declared_cross_language_is_really_pinned_here(bridge):
    """Un nume scris într-o mulțime Python nu e o verificare.

    `CROSS_LANGUAGE_AUTH` din `test_shipper.py` scutește o constantă a
    agregatorului de la „declar-o receptor-only cu un motiv", pe temeiul că e
    verificată AICI. Măsurat pe 16 august 2026, temeiul nu era verificat de
    nimic: o constantă nouă în `lib/auth/session.ts` trecea censusul doar
    adăugându-i numele acolo. Ce se strică atunci nu se vede în nicio zi anume —
    se vede în ziua în care valoarea aia diferă de a serverului și nimeni n-a
    comparat-o niciodată: coduri TOTP care nu se potrivesc, sau un jeton mai
    scurt, sau un parametru Argon2id coborât la un singur capăt.

    Deci temeiul se cere prin EFECT, în două trepte:

      1. puntea poartă exact numele declarate. Numele sunt IMPORTURI din modulele
         livrate, deci unul inventat oprește `tsx` și fixture-ul pică;
      2. fiecare nume, stricat în răspunsul punții, trebuie să înroșească cel
         puțin una dintre verificările de mai sus. Un nume pe care nimic nu-l
         compară trece prin toate și e chiar defectul căutat.
    """
    import copy

    from tests.unit.test_shipper import CROSS_LANGUAGE_AUTH

    assert set(bridge["constants"]) == CROSS_LANGUAGE_AUTH, (
        "numele declarate trans-limbaj și cele purtate de punte diferă: "
        f"declarate în plus {sorted(CROSS_LANGUAGE_AUTH - set(bridge['constants']))}, "
        f"purtate nedeclarate {sorted(set(bridge['constants']) - CROSS_LANGUAGE_AUTH)}")

    # Verificările care compară puntea cu serverul. O verificare nouă se adaugă
    # aici; una uitată se vede ca „nimic nu compară constanta X", nu ca tăcere.
    checks = [
        test_the_two_ends_agree_on_the_argon2_parameters,
        test_the_two_ends_agree_on_the_password_length_bounds,
        test_the_two_ends_produce_the_same_totp_codes,
        test_the_two_ends_agree_on_the_session_token_shape,
    ]

    unpinned = []
    for name, value in sorted(bridge["constants"].items()):
        assert isinstance(value, int), f"{name} nu e un număr: {value!r}"
        broken = copy.deepcopy(bridge)
        # +1: cea mai mică schimbare posibilă. O verificare care n-o vede n-ar
        # vedea nici una mare — iar una mare (un secret întreg, o lungime
        # absurdă) ar putea pica din alt motiv decât comparația căutată.
        broken["constants"][name] = value + 1
        noticed = False
        for check in checks:
            try:
                check(broken)
            # Orice eșec e un „s-a văzut": o aserțiune, dar și un `ValueError`
            # din `validate_password_strength`, care e felul în care se pinuiește
            # plafonul de lungime — el nu e o constantă a serverului, ci purtare.
            except Exception:
                noticed = True
                break
        if not noticed:
            unpinned.append(name)

    assert not unpinned, (
        f"constante declarate trans-limbaj pe care nimic nu le compară cu "
        f"serverul: {unpinned}. Ori se scrie verificarea, ori numele se mută în "
        f"RECEIVER_ONLY cu motivul pentru care expeditorul nu-l vede.")


def _check_vocabulary(sql: str, column: str) -> set[str]:
    """Valorile dintr-un `CHECK (<coloană> IN (...))`, oricare ar fi ortografia."""
    match = re.search(rf"CHECK \(\s*(?:{column} IS NULL OR )?{column} IN \(([^)]*)\)",
                      sql)
    assert match, f"nu găsesc vocabularul lui {column}"
    return {value.strip().strip("'") for value in match.group(1).split(",")}


def test_the_two_ends_agree_on_the_closed_vocabularies():
    """Un rol scris pe server și inexistent pe agregator e un `CHECK` care refuză
    rândul la prima scriere — și un panou în care cineva nu poate fi adăugat, cu
    o eroare de bază de date drept explicație.

    Se citesc AMBELE fișiere de schemă, nu se copiază o listă cu un comentariu
    care spune că e la fel.
    """
    server = (REPO / "sentinel" / "db" / "migrations"
              / "0006_auth_audit.sql").read_text(encoding="utf-8")
    aggregator = (AGGREGATOR / "migrations" / "0008_auth.sql").read_text(encoding="utf-8")

    assert _check_vocabulary(server, "role") == _check_vocabulary(aggregator, "role")
    assert _check_vocabulary(server, "role") == {"owner", "operator", "viewer"}

    assert (_check_vocabulary(server, "result")
            == _check_vocabulary(aggregator, "result"))

    # `stage` a venit pe server abia în `0009_web_session.sql`.
    stages = (REPO / "sentinel" / "db" / "migrations"
              / "0009_web_session.sql").read_text(encoding="utf-8")
    assert _check_vocabulary(stages, "stage") == _check_vocabulary(aggregator, "stage")
    assert _check_vocabulary(aggregator, "stage") == {"password", "totp"}
