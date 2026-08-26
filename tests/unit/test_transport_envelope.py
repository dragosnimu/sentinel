"""Plicul de transport: ce trebuie să rămână adevărat după ce corpul devine opac.

Pana pe care o repară plicul e în capul lui `sentinel/report/envelope.py`:
marginea găzduirii agregatorului are un WAF cu punctaj care citește corpul JSON,
iar `session_commands` — singurul flux al cărui conținut e format din linii de
comandă — trece pragul la patru-șase apariții ale unei comenzi banale. Măsurat pe
gazdă: trei treceri, șase picate. Cererea primește 403 de la margine, cursorul
avansează doar pe ecoul filigranului, deci lotul se retrimite la infinit.

Fișierul ăsta păzește cele patru proprietăți fără de care reparația fie nu repară
nimic, fie strică altceva:

  1. **semnătura rămâne peste octeții DINĂUNTRU** — dacă ajunge peste plic,
     `aggregator/lib/verify.ts` nu mai e geamăn cu `signing.py`, iar simptomul e
     401 la fiecare lot, adică exact ce arată o cheie greșită;
  2. **textul comenzilor nu mai apare în clar pe sârmă** — asta E reparația, și
     se verifică pe octeții care pleacă, nu pe intenția de a-i comprima;
  3. **lotul iese identic la octet** din plic — un octet pierdut pe drum se vede
     tot ca 401, fiindcă semnătura e peste conținut;
  4. **cele două capete scriu aceeași formă de plic** — un prefix, o etichetă de
     codare sau o versiune scrise diferit fac receptorul să citească plicul ca
     JSON în clar. Iar plafoanele de decomprimare mărginesc chiar ce poate
     trimite expeditorul: sub ele fluxul primește 413 la fiecare rundă, iar
     `ship_once` nu deosebește un non-2xx de altul.

Decodorul din `_open` e scris a doua oară, cu mâna, și NU cheamă `envelope.py`:
altfel ar proba că modulul e invers cu el însuși. Că octeții produși aici sunt
citiți de implementarea TypeScript se probează cu vectorul comun din
`tests/fixtures/transport-envelope.json`, folosit și de
`aggregator/tests/envelope.test.ts`.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
from pathlib import Path

import pytest

from sentinel.report import envelope
from sentinel.report.envelope import EnvelopeError, wrap
from sentinel.report.signing import canonical, sign

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "transport-envelope.json"
ENVELOPE_TS = REPO / "aggregator" / "lib" / "envelope.ts"
INGEST_TS = REPO / "aggregator" / "lib" / "ingest.ts"


def _open(wire: bytes) -> bytes:
    """Octeții semnați, scoși din plic. Decodor de referință, scris cu mâna."""
    outer = json.loads(wire.decode("utf-8"))
    assert outer["enc"] == "gzip+base64"
    assert outer["v"] == 1
    return gzip.decompress(base64.b64decode(outer["body"], validate=True))


def _batch(rows: int = 24) -> dict:
    """Un lot de `session_commands` ca cel care primește 403 de la margine.

    Comenzile sunt cele din măsurătoare — muncă de administrare, nu sarcini de
    atacator. Contează fiindcă proba 2 caută EXACT șirurile astea în octeții care
    pleacă.
    """
    argv = ["cat /var/log/sentinel/shipper.log", "wc -c /tmp/body.json",
            "python3 /tmp/mkbody.py 400", "systemctl is-active sentinel-ship"]
    return {
        "instance_id": "a1b2c3d4e5f60718",
        "sent_at": "2026-08-25T09:30:00+00:00",
        "max_age_s": 300,
        "batch_seq": 4471,
        "cursors": {"session_commands": 4_100_000 + rows - 1},
        "rows": {"session_commands": [{
            "id": 4_100_000 + i,
            "session_id": 918_204,
            "session_key": "3f6a1c9de4b70582",
            "ts": "2026-08-25T09:%02d:00Z" % (i % 60),
            "username": "root",
            "exe": "/usr/bin/" + argv[i % len(argv)].split()[0],
            "argv": argv[i % len(argv)],
            "cwd": "/root",
            "tty": "pts/0",
            "pid": 20100 + i,
            "ppid": 20099,
            "success": True,
        } for i in range(rows)]},
    }


# ---------------------------------------------------------------------------
# 1. Semnătura e peste conținut, nu peste plic
# ---------------------------------------------------------------------------
def test_the_signature_is_over_the_content_inside_not_over_the_envelope():
    """Semnat peste plic, `aggregator/lib/verify.ts` nu mai e geamăn cu
    `signing.py` și niciun lot nu se mai verifică.

    Simptomul de pe gazdă ar fi 401 la fiecare rundă — indistinct de o cheie
    greșită sau de un secret rotit —, iar arhiva externă s-ar opri fără ca
    altceva să se plângă. Plicul comprimă, deci octeții lui depind de o
    bibliotecă și de un nivel de comprimare; a-i semna ar lega semnătura de
    versiunea zlib de pe gazdă.
    """
    payload = _batch()
    body = canonical(payload)
    signature = sign(payload, "cheia")
    packet = wrap(body)

    # Semnătura trimisă e cea peste CONȚINUT...
    assert signature == sign(payload, "cheia")
    # ...și e chiar HMAC-ul peste octeții pe care receptorul îi scoate din plic.
    assert _open(packet.wire) == body

    # Iar peste octeții plicului dă altceva — deci cele două nu pot fi confundate
    # printr-o coincidență.
    import hashlib
    import hmac
    over_wire = hmac.new(b"cheia", packet.wire, hashlib.sha256).hexdigest()
    assert over_wire != signature


# Perechea de aici — că `ship_once` chiar semnează conținutul și trimite plicul —
# stă în `test_shipper.py`, lângă dublurile de bază pe care le cere:
# `test_the_batch_travels_wrapped_and_the_signature_stays_over_the_content`.


# ---------------------------------------------------------------------------
# 2. Ce pleacă pe sârmă nu mai conține textul comenzilor. ASTA e reparația.
# ---------------------------------------------------------------------------
def test_no_command_text_survives_in_the_bytes_that_leave_the_host():
    """Proprietatea care repară pana, verificată pe OCTEȚI.

    Marginea punctează conținutul cererii. Cât timp `cat`, `wc -c` sau
    `python3 /tmp/mkbody.py` apar în clar în corp, patru-șase apariții urcă
    scorul peste prag și lotul primește 403 — pentru totdeauna, fiindcă acelea
    sunt chiar rândurile care nu pot pleca.

    Nu se verifică „am chemat gzip", se verifică absența șirurilor din octeții
    care ies pe ușă. O comprimare care ar lăsa antetul necomprimat, un nivel 0
    (stocare), sau o viitoare „optimizare" care sare peste loturile mici — toate
    trec de o probă pe intenție și pică aici.
    """
    payload = _batch()
    wire = wrap(canonical(payload)).wire

    needles = [b"cat /var/log", b"wc -c", b"python3 /tmp/mkbody.py",
               b"systemctl is-active", b"/usr/bin/", b"session_commands",
               b"3f6a1c9de4b70582"]
    present = [n for n in needles if n in wire]
    assert not present, (
        f"textul astora a plecat în clar: {present}. Marginea îl punctează, iar "
        f"la al patrulea-al șaselea tipar cererea primește 403.")

    # Și nu fiindcă lotul ar fi gol: aceleași șiruri SUNT în conținutul semnat.
    inner = canonical(payload)
    assert all(n in inner for n in needles)


def test_the_envelope_is_the_shape_that_measured_401_at_the_edge():
    """Ce a trecut de margine a fost base64 într-un câmp JSON — nu „ceva opac".

    Un corp binar cu alt `Content-Type` NU a fost probat pe gazdă, deci nu e o
    variantă pe care s-o afirmăm ca sigură. Proba asta ține forma la ce s-a
    măsurat: plicul e JSON, câmpul e base64, iar tipul cererii nu se schimbă.
    """
    wire = wrap(canonical(_batch())).wire
    outer = json.loads(wire.decode("utf-8"))
    assert set(outer) == {"enc", "v", "pad", "body"}
    assert outer["enc"] == "gzip+base64"
    assert re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", outer["body"])
    # ASCII curat: orice octet peste 0x7E ar fi corp binar strecurat într-un
    # câmp JSON, adică forma netestată.
    assert max(wire) <= 0x7E


# ---------------------------------------------------------------------------
# 3. Dus-întors identic la octet
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("rows", [1, 24, 400])
def test_a_batch_that_goes_through_the_envelope_comes_back_byte_identical(rows):
    """Un octet pierdut în plic se vede tot ca 401, nu ca „date stricate".

    Semnătura e peste conținut, deci orice transformare care nu e perfect
    reversibilă — o codificare care normalizează, un `strip()` binevoitor, un
    base64 cu linii tăiate — face receptorul să calculeze HMAC peste alți octeți
    și să refuze un lot valid, fără să numească nimeni cauza.
    """
    body = canonical(_batch(rows))
    assert _open(wrap(body).wire) == body


def test_a_body_with_romanian_diacritics_survives_the_round_trip():
    """Diacriticele trec prin `canonical()` neatinse, deci trebuie să treacă și
    prin plic: un `argv` cu ele ar opri altfel exact fluxul care le poartă."""
    payload = _batch(2)
    payload["rows"]["session_commands"][0]["argv"] = "grep -n 'măsurătoare' /etc/șir"
    body = canonical(payload)
    assert _open(wrap(body).wire) == body


# ---------------------------------------------------------------------------
# 4. Umplutura: inegalitatea receptorului e adevărată prin construcție
# ---------------------------------------------------------------------------
def test_the_sender_guarantees_the_ratio_the_receiver_checks():
    """Un plafon de raport pe care expeditorul îl poate încălca ar opri fluxul
    definitiv — și i-ar da oricui are shell pe gazdă o comandă prin care oprește
    arhiva externă.

    Măsurat: un singur rând cu un `argv` lung și repetitiv comprimă de 992 de
    ori, iar 8 MB din același octet de 1026 — deci raportul NU deosebește un lot
    legitim de o bombă. Ce-l face sigur e umplutura: expeditorul crește plicul
    până când inegalitatea receptorului e adevărată. Proba folosește chiar corpul
    cel mai comprimabil pe care îl poate produce un lot real.
    """
    payload = _batch(2)
    # `argv` e nemărginit la sursă și călătorește neatins — vezi
    # SESSION_COMMAND_STREAM. Un rând cu o linie de comandă generată e legitim.
    for row in payload["rows"]["session_commands"]:
        row["argv"] = "deploy --payload " + "x" * 400_000
    body = canonical(payload)
    packet = wrap(body)

    assert packet.padding_bytes > 0, (
        "corpul ăsta comprimă de sute de ori și n-a fost umplut deloc; "
        "receptorul l-ar refuza cu 413 la fiecare rundă")
    assert len(packet.wire) * envelope.MAX_INFLATE_RATIO >= len(body)
    assert _open(packet.wire) == body
    # Umplutura e o serie dintr-un singur caracter, iar caracterul NU e `A`: o
    # serie lungă de `A` e semnătura clasică a unei probe de depășire de tampon,
    # adică tocmai ce punctează un WAF.
    pad = json.loads(packet.wire)["pad"]
    assert set(pad) == {envelope.PAD_CHAR} and envelope.PAD_CHAR != "A"


def test_a_normal_batch_is_not_padded_at_all():
    """Umplutura e plata pentru un caz rar, nu un cost pe fiecare lot.

    Măsurat pe loturi reale de comenzi, raportul e între 8 și 26 — mult sub
    plafon. Dacă umplutura ar apărea și acolo, fiecare lot ar căra octeți degeaba
    și câștigul comprimării s-ar duce.
    """
    packet = wrap(canonical(_batch(400)))
    assert packet.padding_bytes == 0
    assert packet.ratio > 5, f"comprimarea nu mai câștigă nimic: {packet.ratio}"


def test_wrap_refuses_to_hand_over_an_envelope_the_receiver_would_reject(monkeypatch):
    """`wrap` verifică inegalitatea pe octeții CARE PLEACĂ, nu aritmetica ei.

    O umplutură calculată corect și SCRISĂ greșit ar produce plicuri respinse cu
    413 la fiecare rundă, iar de pe gazdă asta arată ca un agregator căzut:
    `ship_once` tratează orice non-2xx la fel și nu citește corpul.

    Defectul se pune în locul cel mai apropiat de realitate: caracterul de
    umplutură devine șirul gol, deci `padding` rămâne calculat corect și zero
    octeți ajung în plic. O verificare scrisă pe aritmetică — `if padding !=
    needed - …` — ar trece; una scrisă pe octeții finali pică.
    """
    payload = _batch(2)
    for row in payload["rows"]["session_commands"]:
        row["argv"] = "deploy --payload " + "x" * 400_000
    body = canonical(payload)

    monkeypatch.setattr(envelope, "PAD_CHAR", "")
    with pytest.raises(EnvelopeError, match="raportul"):
        wrap(body)


# ---------------------------------------------------------------------------
# 5. Cele două capete scriu aceeași formă de plic
# ---------------------------------------------------------------------------
def test_the_two_ends_agree_on_the_shape_of_the_envelope():
    """Un prefix scris diferit face receptorul să citească plicul ca JSON în
    clar, iar semnătura pică — 401 la fiecare lot, adică exact ce arată o cheie
    greșită, pe o gazdă căreia nu i se poate schimba identitatea.

    Numerele se CITESC din sursa TypeScript, ca o mutare de o singură parte să
    pice aici. Aceeași formă ca
    `test_the_two_ends_agree_on_the_batch_limits` din `test_shipper.py`.
    """
    text = ENVELOPE_TS.read_text(encoding="utf-8")

    def literal(name: str, pattern: str) -> str:
        found = re.findall(rf"^export const {name} = ({pattern});$", text, re.MULTILINE)
        assert len(found) == 1, f"{name}: {len(found)} definiții în lib/envelope.ts"
        return found[0]

    assert literal("ENVELOPE_ENCODING", r'"[^"]*"').strip('"') == envelope.ENVELOPE_ENCODING
    assert int(literal("ENVELOPE_VERSION", r"\d+")) == envelope.ENVELOPE_VERSION
    assert literal("ENVELOPE_PREFIX", r"'[^']*'").strip("'").encode("ascii") \
        == envelope.ENVELOPE_PREFIX
    assert int(literal("MAX_INFLATE_RATIO", r"\d+")) == envelope.MAX_INFLATE_RATIO

    # Prefixul nu e doar egal cu o constantă — e chiar începutul octeților care
    # pleacă. Fără linia asta, cele două capete ar putea fi de acord pe un șir pe
    # care expeditorul nu-l emite.
    assert wrap(canonical(_batch(1))).wire.startswith(envelope.ENVELOPE_PREFIX)

    # Forma canonică NU poate fi confundată cu un plic: cheile se emit sortate pe
    # puncte de cod, deci un payload începe cu `{"batch_seq":`. Dacă vreodată
    # apare un câmp de nivel superior care sortează înaintea lui și începe cu
    # `enc`, discriminatorul de la receptor devine ambiguu.
    assert canonical(_batch(1)).startswith(b'{"batch_seq":')

    # Plafonul absolut de decomprimare e ACELAȘI cu plafonul de corp al căii în
    # clar. Scris ca alt număr, plicul ar accepta mai mult sau mai puțin decât
    # calea pe care o înlocuiește, iar diferența s-ar vedea ca un flux oprit pe
    # un lot pe care `config-check` îl declară legal.
    inflated = re.findall(r"^export const MAX_INFLATED_BYTES = (\w+);$",
                          text, re.MULTILINE)
    assert inflated == ["MAX_BODY_BYTES"], inflated
    assert re.search(r"^export const MAX_BODY_BYTES = ",
                     INGEST_TS.read_text(encoding="utf-8"), re.MULTILINE)

    # Plafonul de sârmă e DERIVAT din cel de conținut, nu ales — vezi testul
    # următor pentru proprietatea pe care trebuie s-o satisfacă.
    wire = re.findall(r"^export const MAX_WIRE_BYTES = (.+);$", text, re.MULTILINE)
    assert wire == ["Math.ceil(MAX_INFLATED_BYTES * 4 / 3) + 4096"], wire


def test_the_wire_ceiling_is_never_smaller_than_what_the_plain_path_accepts():
    """Plicul nu are voie să accepte MAI PUȚIN decât calea pe care o înlocuiește.

    Un plic e base64 (`×4/3`) peste gzip, iar gzip nu comprimă nimic pe text de
    entropie mare — `argv` e nemărginit la sursă și influențat de cine are shell
    pe gazda monitorizată. Deci un lot care azi pleacă neîmpachetat poate deveni,
    împachetat, cu ~10% mai mare. Dacă plafonul de la citire ar rămâne cel de
    conținut, lotul acela ar fi refuzat definitiv după împachetare, iar de pe
    gazdă s-ar vedea ca un agregator căzut — `ship_once` nu deosebește un non-2xx
    de altul.

    Proba folosește chiar cel mai prost caz: `argv` din caractere ASCII
    imprimabile alese la întâmplare, adică cel mai puțin comprimabil conținut pe
    care îl poate purta forma canonică.
    """
    import random
    import string

    ts = ENVELOPE_TS.read_text(encoding="utf-8")
    max_body = int(re.search(r"^export const MAX_ROWS_PER_BATCH = ([\d_]+);$",
                             INGEST_TS.read_text(encoding="utf-8"),
                             re.MULTILINE).group(1).replace("_", "")) * int(
        re.search(r"^export const MAX_ROW_BYTES = ([\d_]+);$",
                  INGEST_TS.read_text(encoding="utf-8"), re.MULTILINE
                  ).group(1).replace("_", ""))
    assert "Math.ceil(MAX_INFLATED_BYTES * 4 / 3) + 4096" in ts
    max_wire = -(-max_body * 4 // 3) + 4096

    rng = random.Random(20260825)
    alphabet = "".join(c for c in string.printable[:95] if c not in '"\\')
    payload = _batch(1)
    row = payload["rows"]["session_commands"][0]
    # Cât mai aproape de plafonul de conținut, fără să treacă peste el.
    row["argv"] = "".join(rng.choice(alphabet) for _ in range(max_body - 1500))
    body = canonical(payload)
    assert len(body) <= max_body, "corpul de probă a depășit chiar plafonul de conținut"

    packet = wrap(body)
    assert len(packet.wire) > len(body), (
        "corpul de probă s-a comprimat; nu mai e cazul cel mai prost, deci proba "
        "nu mai spune nimic despre plafonul de sârmă")
    assert len(packet.wire) <= max_wire, (
        f"un corp de {len(body)} octeți — sub plafonul de conținut — iese pe "
        f"sârmă cu {len(packet.wire)}, peste plafonul de {max_wire}: lotul ar fi "
        f"refuzat la citire, definitiv")


def test_the_shared_vector_still_matches_what_the_sender_produces():
    """Vectorul comun e singura dovadă că partea TypeScript citește octeți
    PRODUȘI de partea Python.

    `aggregator/tests/envelope.test.ts` îl desface și cere `inner` înapoi. Dacă
    fișierul rămâne în urma formatului, proba de acolo ar dovedi că TypeScript
    citește un format pe care nimeni nu-l mai emite — verde, și fără valoare.
    Aici se verifică prospețimea lui.
    """
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    inner = fixture["inner"].encode("utf-8")
    wire = fixture["wire"].encode("ascii")

    # `inner` e chiar FORMA CANONICĂ a payload-ului, nu doar un JSON echivalent.
    # Fără linia asta, un vector refăcut ca să treacă testele ar putea purta un
    # JSON cu alte spații sau altă ordine a cheilor — iar proba din TypeScript,
    # care compară octeți, ar dovedi ceva despre octeții ăia, nu despre cei pe
    # care îi produce expeditorul.
    payload = json.loads(inner)
    assert canonical(payload) == inner, "`inner` nu e forma canonică a payload-ului"
    # Și e forma pe care o produce CHIAR expeditorul: fluxurile sunt un obiect
    # nume→rânduri, nu un tablou. Un vector de altă formă ar trece toate probele
    # de mai jos și n-ar mai semăna cu niciun lot real.
    assert isinstance(payload["rows"], dict) and "session_commands" in payload["rows"]
    assert isinstance(payload["cursors"], dict)
    assert payload["cursors"]["session_commands"] == \
        payload["rows"]["session_commands"][-1]["id"]

    # Plicul din fișier e încă unul pe care decodorul de referință îl deschide...
    assert _open(wire) == inner
    assert wire.startswith(envelope.ENVELOPE_PREFIX)
    # ...și e încă forma pe care `wrap` o produce azi pentru aceiași octeți.
    fresh = wrap(inner)
    assert _open(fresh.wire) == inner
    assert json.loads(fresh.wire).keys() == json.loads(wire).keys()
    # Semnătura din fișier e peste CONȚINUT, nu peste plic — partea TypeScript se
    # sprijină pe asta ca să probeze ordinea din protocol.
    assert fixture["signature"] == sign(json.loads(inner), fixture["secret"])
