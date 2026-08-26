"""Agregatorul verifică lanțul pe care îl produce CHIAR serverul.

`docs/PLAN-arhitectura-distribuita.md` §5 scrie că sistemul „nu verifică
înlănțuirea și nici nu are cu ce". Conducta de sincronizare îi dă cu ce, iar
`aggregator/lib/chain.ts` o face. Testul ăsta leagă cele două capete: lanțul se
construiește AICI cu `sentinel/db/repo/audit.py::_entry_hash` — funcția reală a
serverului, nu o imitație — și se dă verificatorului LIVRAT al agregatorului, în
TypeScript.

Ce ar rămâne nedovedit fără el: că regula pe care o aplică agregatorul e regula
după care serverul chiar construiește lanțul. Două implementări testate separat,
fiecare împotriva propriilor fixturi, pot fi amândouă verzi și în dezacord — iar
dezacordul aici înseamnă ori alarmă la fiecare lot (și atunci operatorul oprește
alarma), ori tăcere pe o rescriere reală de istorie.

## De ce se cheamă `node`

Ca la `test_aggregator_secret_form.py`: implementarea de verificat e cea
livrată. O transcriere a ei în Python ar fi exact greșeala pe care testul o
caută. Lipsa lui `node` sau a lui `node_modules` e SKIP cu motiv scris, nu
verde.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU s-a verificat că agregatorul înțelege "
    "lanțul produs de server. Nu e „în regulă”, e „neverificat”."
)
_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva. "
    "Rulează `npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

# Puntea: primește verigile și filigranul, cheamă verificatorul LIVRAT.
BRIDGE = """
import { verifyLinks } from "../lib/chain.ts";
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { raw += c; });
process.stdin.on("end", () => {
  const cases = JSON.parse(raw);
  const out = {};
  for (const [name, spec] of Object.entries(cases)) {
    out[name] = verifyLinks(spec.links, null, spec.confirmedThrough);
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def _verify(cases: dict[str, dict]) -> dict[str, dict]:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-chain-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        script.write_text(BRIDGE, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, "--import", "tsx", str(script)],
            input=json.dumps(cases), cwd=AGGREGATOR, capture_output=True,
            text=True, encoding="utf-8", timeout=180,
            env={**os.environ, "NO_COLOR": "1"},
        )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _server_chain(count: int, first_id: int = 100) -> list[dict]:
    """Un lanț construit cu funcția REALĂ a serverului.

    Aceeași înlănțuire ca în `audit.record`: `prev_hash` al primului rând e
    `GENESIS_HASH`, iar al fiecărui rând următor e `entry_hash`-ul celui
    dinainte.
    """
    from sentinel.db.repo.audit import GENESIS_HASH, _entry_hash

    links: list[dict] = []
    prev = GENESIS_HASH
    for i in range(count):
        payload = {
            "actor": "telegram:operator",
            "source": "telegram",
            "operation": "incident.close",
            "target": f"incident:{first_id + i}",
            "params": {"reason": "fals pozitiv"},
            "result": "ok",
            "detail": None,
        }
        digest = _entry_hash(payload, prev)
        links.append({"sourceId": first_id + i, "prevHash": prev, "entryHash": digest})
        prev = digest
    return links


def test_the_two_ends_agree_on_the_genesis_hash():
    """`prev_hash`-ul primului rând e o constantă scrisă în două limbaje.

    Dacă diferă, începutul dovedit al lanțului nu se mai recunoaște ca început:
    o instalare curată ar avea pentru totdeauna un capăt de jos „neverificat", și
    n-ar mai exista nicio diferență observabilă între „lanțul începe aici" și
    „primele rânduri au fost șterse".
    """
    import re

    from sentinel.db.repo.audit import GENESIS_HASH

    source = (AGGREGATOR / "lib" / "chain.ts").read_text(encoding="utf-8")
    found = re.findall(r'^export const GENESIS_HASH = "(.*)"\.repeat\((\d+)\);$',
                       source, re.MULTILINE)
    assert len(found) == 1, f"{len(found)} definiții GENESIS_HASH în agregator"
    unit, times = found[0]
    assert unit * int(times) == GENESIS_HASH


def test_the_aggregator_accepts_a_chain_the_server_actually_built():
    """Lanțul real trece; unul din care lipsește un rând nu.

    Fixturile inventate ale agregatorului pot fi verzi și greșite dacă regula lor
    de înlănțuire nu e cea a serverului. Aici verigile vin din `_entry_hash`.
    """
    links = _server_chain(5)
    without_middle = [link for link in links if link["sourceId"] != 102]

    verdicts = _verify({
        # Lanț întreg, tot sub filigran: nimic nu mai poate sosi, deci verdictul
        # e o afirmație, nu o așteptare.
        "intreg": {"links": links, "confirmedThrough": 104},
        # Un rând ȘTERS, sub filigran: ruptură.
        "sters": {"links": without_middle, "confirmedThrough": 104},
        # Aceeași gaură, dar peste filigran: „încă pe drum", nu ruptură. Cele
        # două cazuri TREBUIE să dea rezultate diferite — dacă nu, mecanismul e
        # ori alarmă falsă la fiecare restanță, ori tăcere pe o ștergere.
        "gol_legitim": {"links": without_middle, "confirmedThrough": 101},
    })

    assert verdicts["intreg"]["status"] == "ok", verdicts["intreg"]
    assert verdicts["intreg"]["checkedLinks"] == 4
    assert verdicts["intreg"]["verifiedThrough"] == 104

    assert verdicts["sters"]["status"] == "broken", verdicts["sters"]
    assert verdicts["sters"]["breakSourceId"] == 103

    assert verdicts["gol_legitim"]["status"] == "unknown", verdicts["gol_legitim"]
    assert verdicts["gol_legitim"]["breakSourceId"] is None


def test_a_reordered_chain_is_a_break():
    """Reordonarea e a doua formă pe care o prinde o verificare structurală.

    Nu e o ipoteză: schimbarea a două rânduri între ele rupe exact aceeași
    legătură, iar dacă verificatorul ar compara doar mulțimi de hash-uri (nu
    ORDINEA), ar trece verde peste o istorie rearanjată.
    """
    links = _server_chain(5)
    swapped = list(links)
    swapped[1], swapped[2] = (
        {**swapped[2], "sourceId": links[1]["sourceId"]},
        {**swapped[1], "sourceId": links[2]["sourceId"]},
    )
    verdicts = _verify({"reordonat": {"links": swapped, "confirmedThrough": 104}})
    assert verdicts["reordonat"]["status"] == "broken", verdicts["reordonat"]


def test_a_forged_but_consistent_chain_is_NOT_detected():
    """Limita, probată — nu doar scrisă în comentariu.

    Cine are root pe mașina monitorizată poate recalcula un lanț întreg, fals dar
    consistent, și îl poate expedia. Verificarea structurală îl acceptă, fiindcă
    e chiar structura pe care o cere. §5 din documentul de arhitectură o spune;
    testul ăsta există ca nimeni să nu citească „lanț verificat" ca „istorie
    dovedită".

    Ce ar prinde asta e recalcularea lui `entry_hash` din conținut, iar aia cere
    identitate de octeți între serializatorul Python și unul TypeScript — vezi
    `sentinel/report/signing.py` pentru de ce nu e o pariere pe care o facem.
    """
    forged = _server_chain(5)
    for link in forged:
        # Conținutul ar fi cu totul altul, dar lanțul rămâne consistent: fiecare
        # `prev_hash` e `entry_hash`-ul dinainte.
        link["sourceId"] += 1000
    verdicts = _verify({"fals": {"links": forged, "confirmedThrough": 1104}})
    assert verdicts["fals"]["status"] == "ok", (
        "verificarea structurală ar trebui să accepte un lanț fals-dar-consistent; "
        "dacă nu o mai face, limita din §5 s-a schimbat și documentația trebuie "
        "actualizată")
