"""Filigranul pe care îl trimite expeditorul trebuie să fie cel pe care îl cere agregatorul.

Cele două capete au vocabulare diferite pentru același număr. Expeditorul îl
numește `Batch.watermark` și îl deosebește de `Batch.position` — poziția locală,
care pe un flux mutabil e perechea `(updated_at, id)` și nu pleacă nicăieri.
Agregatorul îl primește ca `cursors.<flux>` și îl ECOUĂ, iar ecoul e singura
dovadă pe care expeditorul o acceptă ca să-și miște cursorul.

Dacă cele două nu sunt de acord asupra CĂRUI număr e, fiecare lot primește 400.
`ship_once` tratează orice non-2xx la fel și nu citește niciodată corpul, deci
simptomul e „expedierea s-a oprit", fără nimic care să spună de ce — aceeași
formă de pană ca la limitele de lot, și din același motiv: o valoare scrisă în
două locuri.

Alegerea nu e evidentă, și de-aia are nevoie de test. Pentru un flux mutabil sunt
DOI candidați plauzibili, iar amândoi sunt „ultimul" în vreun sens:

  * cel mai mare `id` din lot — ce trimite expeditorul;
  * `id`-ul ULTIMULUI rând în ordinea de expediere `(updated_at, id)` — care e
    poziția locală, și care e aproape întotdeauna ALT rând.

Testul de aici pune la treabă amândouă implementările REALE: calculează
filigranul cu `wire_watermark` din expeditor, apoi îl dă ingestiei adevărate a
agregatorului și cere să fie acceptat. Și cere ca celălalt candidat să fie
REFUZAT — altfel „sunt de acord" ar fi o afirmație despre un caz unde orice
număr trece.

## NU ȘTERGE testul ăsta ca „redundant"

E singurul lucru care ține `max(keys)` din `wire_watermark`. Măsurat: înlocuit cu
`keys[-1]`, TOATĂ suita TypeScript rămâne verde, fiindcă acolo fiecare fixtură e
ordonată crescător, deci ultima cheie E maximul. Numai un lot în ORDINEA DE
EXPEDIERE a unui flux mutabil — `(updated_at, id)`, unde ultimul rând trimis are
`id`-ul mic — desparte cele două, iar lotul ăla se construiește aici.

Deci cine „curăță" testul de aici lasă `max` nepinuit în aceeași mișcare, fără
ca nimic să pice.

## De ce se cheamă `node`

Fiindcă partea care verifică e cea LIVRATĂ, nu o transcriere a ei în Python. O a
doua transcriere ar fi exact greșeala pe care testul o caută. Lipsa lui `node`
sau a lui `node_modules` e SKIP cu motiv scris, nu verde: „n-am putut verifica"
și „e în regulă" sunt stări diferite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from sentinel.report.shipper import wire_watermark

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU s-a verificat că filigranul trimis e cel "
    "cerut de agregator. Nu e „în regulă”, e „neverificat”."
)
_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva. "
    "Rulează `npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

# Un lot de flux mutabil, în ORDINEA DE EXPEDIERE `(updated_at, id)`. Rândul cu
# `id` mare a fost atins demult; cel cu `id` mic a fost atins acum. Deci ultimul
# rând expediat NU e cel cu `id`-ul cel mai mare — chiar cazul în care cei doi
# candidați se despart.
SHIPPED_ROWS = [
    {"id": 900, "status": "open", "title": "acces refuzat"},
    {"id": 12, "status": "resolved", "title": "acces refuzat"},
]

# Puntea către ingestia REALĂ a agregatorului. Primește lotul și filigranul,
# întoarce verdictul. Fluxul e declarat aici, nu luat din registru, fiindcă
# `incidents` încă nu e înregistrat — ce se verifică e forma filigranului, nu
# lista fluxurilor.
BRIDGE = """
import { queryableDb } from "../lib/db.ts";
import { ingestStream } from "../lib/ingest.ts";
import { FakeServer, INSTANCE, baseEnv } from "../tests/sync-harness.ts";

// Al doilea flux, cu cheie TEXT. Declarat aici, ca si primul, fiindca ce se
// verifica e FORMA filigranului, nu lista fluxurilor inregistrate.
const TEXT_STREAM = {
  name: "selfcheck_state",
  table: "selfcheck_state_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "check_key"],
  watermark: "check_key",
  watermarkKind: "text",
  columns: [
    { source: "key", target: "check_key", kind: "text", nullable: false, maxBytes: 190 },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: 65535 },
    { source: "title", target: "title", kind: "text", nullable: false, maxBytes: 65535 },
  ],
};

const STREAM = {
  name: "incidents",
  table: "incident_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: 65535 },
    { source: "title", target: "title", kind: "text", nullable: false, maxBytes: 65535 },
  ],
};

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { raw += c; });
process.stdin.on("end", async () => {
  baseEnv();
  const cases = JSON.parse(raw);
  const out = {};
  for (const [name, item] of Object.entries(cases)) {
    const server = new FakeServer();
    const stream = item.stream === "text" ? TEXT_STREAM : STREAM;
    const result = await ingestStream(
      queryableDb(server), INSTANCE, stream, item.rows, item.watermark, 1);
    out[name] = result;
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def _ingest(cases: dict[str, dict]) -> dict[str, dict]:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-watermark-") as tmp:
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


def test_the_two_ends_agree_on_which_number_the_watermark_is() -> None:
    """Eșecul pe care îl previne: expedierea se oprește pentru totdeauna, cu 400.

    Dacă expeditorul trimite `id`-ul ultimului rând în ordinea `(updated_at, id)`
    — poziția lui locală, care e un candidat perfect plauzibil — iar agregatorul
    cere maximul lotului, atunci fiecare lot al fiecărui flux mutabil e respins.
    `ship_once` nu citește corpul răspunsului, deci operatorul vede doar un flux
    care rămâne în urmă, cu backoff până la o oră.
    """
    keys = [int(row["id"]) for row in SHIPPED_ROWS]
    sent = wire_watermark(keys)
    # Celălalt candidat: ultimul rând în ordinea de expediere. Dacă cele două ar
    # coincide, testul n-ar despărți nimic.
    position_key = keys[-1]

    verdicts = _ingest({
        "trimis-de-expeditor": {"rows": SHIPPED_ROWS, "watermark": sent},
        "pozitia-locala": {"rows": SHIPPED_ROWS, "watermark": position_key},
    })

    # Acordul, întâi: ce trimite un capăt, celălalt acceptă. Aserțiunea asta e
    # cea care pică dacă vreunul dintre capete se mută, iar mesajul ei trebuie să
    # fie primul citit — de-aia verificarea calității fixturii vine după.
    accepted = verdicts["trimis-de-expeditor"]
    assert accepted["ok"] is True, (
        f"agregatorul a REFUZAT filigranul pe care îl trimite expeditorul: {accepted}")
    assert accepted["watermark"] == sent, (
        "ecoul nu e filigranul trimis, deci expeditorul nu-și mută cursorul")

    assert sent != position_key, (
        "lotul de probă nu mai desparte cei doi candidați, deci ce urmează n-ar "
        "verifica nimic; alege alte chei")

    refused = verdicts["pozitia-locala"]
    assert refused["ok"] is False, (
        "agregatorul a acceptat și poziția locală ca filigran, deci testul nu "
        "deosebește nimic: cele două capete pot diverge fără să pice ceva")
    assert refused["kind"] == "invalid"


TEXT_ROWS = [
    {"key": "web", "status": "ok", "title": "Panoul"},
    {"key": "db", "status": "ok", "title": "Baza"},
    {"key": "Disk", "status": "degraded", "title": "Discul"},
]


def test_the_two_ends_agree_on_which_STRING_the_watermark_is() -> None:
    """Acelasi acord ca mai sus, pentru fluxurile cu cheie TEXT.

    Filigranul nu e o pozitie, e un jeton de ecou — deci nu trebuie sa fie un
    intreg, doar calculabil identic la ambele capete. Ce trebuie sa fie identic e
    ORDINEA: Python compara siruri pe puncte de cod, JavaScript pe unitati
    UTF-16, MariaDB pe octeti. Pe ASCII toate trei coincid, iar receptorul CERE
    ASCII imprimabil tocmai ca sa nu existe cazul in care nu coincid.

    Fixtura contine dinadins o cheie cu majuscula (`Disk`): sub o comparatie care
    ignora registrul, maximul ar fi `web`, iar sub una pe octeti e tot `web` —
    dar `Disk` < `db` doar pe octeti. Deci ordinea aleasa chiar se vede.
    """
    keys = [row["key"] for row in TEXT_ROWS]
    sent = wire_watermark(keys, "text")
    assert sent == "web", f"maximul pe octeti al {keys} nu e cel asteptat: {sent}"

    # Celalalt candidat plauzibil: cheia ultimului rand trimis, adica pozitia
    # locala. Daca cele doua ar coincide, testul n-ar desparti nimic.
    position_key = keys[-1]
    assert sent != position_key, "fixtura nu mai desparte cei doi candidati"

    verdicts = _ingest({
        "trimis-de-expeditor": {"rows": TEXT_ROWS, "watermark": sent,
                                "stream": "text"},
        "pozitia-locala": {"rows": TEXT_ROWS, "watermark": position_key,
                           "stream": "text"},
    })

    accepted = verdicts["trimis-de-expeditor"]
    assert accepted["ok"] is True, (
        f"agregatorul a REFUZAT filigranul text al expeditorului: {accepted}")
    assert accepted["watermark"] == sent, (
        "ecoul nu e filigranul trimis, deci expeditorul nu-si muta cursorul")

    refused = verdicts["pozitia-locala"]
    assert refused["ok"] is False, (
        "agregatorul a acceptat si pozitia locala ca filigran text")
    assert refused["kind"] == "invalid"


def test_a_text_watermark_of_the_wrong_type_is_refused() -> None:
    """Un intreg trimis pe un flux declarat text nu se converteste tacut.

    Convertit, cele doua capete ar compara siruri cu numere si maximul ar fi
    ales altfel la fiecare capat — iar cursorul n-ar mai avansa niciodata, pe
    loturi perfect valide.
    """
    verdicts = _ingest({
        "intreg-pe-flux-text": {"rows": TEXT_ROWS, "watermark": 3, "stream": "text"},
    })
    refused = verdicts["intreg-pe-flux-text"]
    assert refused["ok"] is False
    assert refused["kind"] == "invalid"


def test_a_batch_with_no_keys_has_no_watermark_to_send() -> None:
    """Eșecul pe care îl previne: ecoul cerut pentru un lot care n-a existat.

    Zero e un număr care arată ca un filigran. Trimis, ar cere agregatorului să
    confirme rânduri care n-au fost trimise niciodată — iar `prepareRows` chiar
    refuză lotul gol, deci cele două capete ar fi în dezacord tăcut despre ce
    înseamnă „n-am nimic de trimis".
    """
    with pytest.raises(ValueError, match="lot fără chei"):
        wire_watermark([])
