"""Coloanele pe care le trimite un flux trebuie să fie exact cele pe care le cunoaște receptorul.

Un flux e declarat în două locuri: `STREAMS` din `sentinel/report/shipper.py`
alege ce pleacă, `allStreams()` din `aggregator/lib/streams.ts` ce se acceptă.
Cele două liste sunt separate dinadins — un flux adăugat la un capăt trebuie să
fie o respingere zgomotoasă, nu o potrivire automată — dar odată ce AMÂNDOUĂ
declară același flux, mulțimile lor de coloane trebuie să coincidă.

Ce se strică altfel, în cele două direcții:

  * o coloană trimisă și necunoscută receptorului → `prepareRows` refuză lotul cu
    „câmp necunoscut", DINADINS (ignorată, ar fi un rând pierdut definitiv, fiindcă
    ce trece de cursor nu se retrimite). Fluxul se oprește la primul lot;
  * o coloană cunoscută receptorului și netrimisă → `prepareRows` refuză cu
    „lipsește câmpul". Tot la primul lot.

În ambele cazuri `ship_once` vede doar un non-2xx, nu citește niciodată corpul, și
raportează o rămânere în urmă cu backoff până la o oră. Adică simptomul e
„expedierea s-a oprit", iar cauza e o listă editată la un singur capăt.

Nu se compară ORDINEA: rândurile călătoresc ca obiecte, cu numele câmpurilor. Se
compară mulțimile, plus faptul că fiecare capăt cere aceleași câmpuri.

## De ce se cheamă `node`

Ca la celelalte teste trans-limbaj: partea de verificat e cea LIVRATĂ, nu o
transcriere a ei în Python. Lipsa lui `node` sau a lui `node_modules` e SKIP cu
motiv scris — „n-am putut verifica" și „e în regulă" sunt stări diferite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from sentinel.report.shipper import STREAMS

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU s-a verificat că cele două capete declară "
    "aceleași coloane. Nu e „în regulă”, e „neverificat”."
)
_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva. "
    "Rulează `npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

BRIDGE = """
import { allStreams } from "../lib/streams.ts";
const out = {};
for (const stream of allStreams()) {
  const carrier = stream.columns.find((c) => c.target === stream.watermark);
  out[stream.name] = {
    sources: stream.columns.map((c) => c.source),
    // Copiii, ca hartă „coloana-tablou -> câmpurile fiecărui element". Fără ei,
    // testul de mai jos ar compara doar scalarii, iar un copil declarat la un
    // singur capăt ar trece neobservat — exact cazul care oprește fluxul la
    // primul lot, cu 400 și fără corp citit.
    children: Object.fromEntries(
      (stream.children ?? []).map((c) => [c.source, c.columns.map((k) => k.source)])),
    cursor: stream.cursor,
    // Numele DE PE SERVER al coloanei de filigran. Receptorul redenumește
    // (`id` devine `source_id`, fiindcă `id`-ul de aici e al replicii), deci
    // comparația cu `key_column` trebuie făcută peste redenumire — altfel ar
    // compara două nume ale aceleiași coloane și ar cere să fie egale.
    watermarkSource: carrier === undefined ? null : carrier.source,
  };
}
process.stdout.write(JSON.stringify(out));
"""


def _receiver_streams() -> dict[str, dict]:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-stream-columns-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        script.write_text(BRIDGE, encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, "--import", "tsx", str(script)],
            cwd=AGGREGATOR, capture_output=True, text=True, encoding="utf-8",
            timeout=180, env={**os.environ, "NO_COLOR": "1"},
        )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def test_both_ends_declare_the_same_columns_for_a_shared_stream() -> None:
    """Eșecul pe care îl previne: fluxul se oprește la primul lot, cu 400.

    O coloană adăugată la un capăt și uitată la celălalt nu produce un mesaj
    despre coloane la operator — produce „expedierea a rămas în urmă", fiindcă
    `ship_once` nu citește corpul răspunsului.
    """
    receiver = _receiver_streams()
    shared = [s for s in STREAMS if s.name in receiver]
    assert shared, "niciun flux declarat la amândouă capetele: bucla ar trece goală"

    for stream in shared:
        theirs = receiver[stream.name]
        assert sorted(stream.columns) == sorted(theirs["sources"]), (
            f"fluxul {stream.name}: coloanele diferă între capete.\n"
            f"  doar la expeditor: {sorted(set(stream.columns) - set(theirs['sources']))}\n"
            f"  doar la receptor:  {sorted(set(theirs['sources']) - set(stream.columns))}")


def test_every_shipped_stream_is_known_to_the_receiver() -> None:
    """Direcția care doare, și care până pe 19 august 2026 nu era verificată.

    Testul de mai sus iterează `shared` — fluxurile pe care le declară AMÂNDOUĂ
    capetele — deci sare tăcut peste un flux pe care expeditorul îl trimite și
    receptorul nu-l cunoaște. Ăla e cazul rău, iar `test_a_mutable_stream_...`
    îl acoperea doar pentru fluxurile mutabile.

    Ce se strică: ruta de sincronizare nu refuză un flux necunoscut, îl OMITE
    din `accepted`. Deci răspunsul e 200, expeditorul nu vede nicio eroare, iar
    cursorul nu avansează niciodată. Simptomul e „expedierea a rămas în urmă",
    raportat de `ship:lag` peste ore, iar cauza e o listă editată la un capăt.

    Direcția cealaltă — receptorul cunoaște un flux pe care expeditorul nu-l
    trimite — NU e o eroare și nu se verifică: e o declarație nefolosită, care e
    chiar starea normală în timpul unei livrări în doi pași, cu receptorul
    actualizat primul. Ordinea aia e deliberată.
    """
    receiver = _receiver_streams()
    shipped = [s.name for s in STREAMS]
    assert shipped, "expeditorul nu declară niciun flux: bucla ar trece goală"

    necunoscute = [name for name in shipped if name not in receiver]
    assert necunoscute == [], (
        f"fluxuri trimise pe care receptorul nu le cunoaste: {necunoscute}.\n"
        f"  receptorul are: {sorted(receiver)}\n"
        "Un lot pe unul dintre ele primește 200 cu `accepted` gol, iar cursorul "
        "nu avansează niciodată — fără nicio eroare nicăieri.")


def test_both_ends_declare_the_same_sub_rows() -> None:
    """Coloanele-TABLOU, verificate ca și scalarii — și separat de ei.

    Un tablou nu circulă ca valoare: pleacă drept sub-rânduri atârnate de rândul
    părinte, într-o tabelă de legătură la receptor. Declarat la un singur capăt,
    rupe fluxul în una din două feluri, amândouă mute de pe gazdă:

      * doar la expeditor -> receptorul vede un câmp necunoscut pe părinte și
        refuză lotul;
      * doar la receptor -> receptorul cere fiecărui rând câmpul, nu-l primește,
        și refuză lotul.

    Se compară și NUMELE CÂMPULUI din fiecare element, nu doar numele coloanei:
    elementele sunt obiecte, iar un câmp scris altfel la un capăt e tot un câmp
    necunoscut.
    """
    receiver = _receiver_streams()
    shared = [s for s in STREAMS if s.name in receiver]
    assert shared, "niciun flux la amândouă capetele"

    # Mulțimea nu are voie să fie goală: fără niciun flux cu copii, aserțiunile
    # de mai jos ar fi vacuu adevărate pentru totdeauna. Aceeași regulă ca la
    # fluxurile mutabile.
    with_children = [s for s in shared if s.children]
    assert with_children, (
        "niciun flux cu sub-rânduri la expeditor. Receptorul are `detections` cu "
        "`detection_events` înregistrat, deci asta nu e „nimic de comparat”, e o "
        "divergență")

    for stream in shared:
        mine = {child.column: [child.field] for child in stream.children}
        theirs = receiver[stream.name]["children"]
        assert mine == theirs, (
            f"fluxul {stream.name}: sub-rândurile diferă între capete.\n"
            f"  expeditor: {mine}\n"
            f"  receptor:  {theirs}")


def test_a_mutable_stream_ships_the_column_it_is_ordered_by() -> None:
    """Eșecul pe care îl previne: fluxul mutabil tace din prima zi.

    Ordinea de expediere e `(updated_at, id)`, iar expeditorul își citește poziția
    locală din rândul selectat. Coloana de timp absentă din listă înseamnă
    `KeyError` la fiecare rundă — flux mut, nu flux cu eroare.

    Iar receptorul trebuie s-o cunoască la rândul lui, altfel o refuză ca pe un
    câmp necunoscut. Cele două cerințe sunt aceeași coloană, verificată din
    amândouă părțile.
    """
    receiver = _receiver_streams()
    mutable = [s for s in STREAMS if s.cursor_kind == "mutable"]
    # NU un skip, și nu o buclă care trece goală: o listă parametrizată ieșită
    # goală face fiecare aserțiune de mai jos vacuu adevărată, iar testul
    # raportează verde fără să fi comparat nimic. E clasa de eșec care a trecut
    # de trei ori prin depozitul ăsta, deci mulțimea verificată se afirmă
    # nevidă înainte de a fi parcursă.
    assert mutable, (
        "niciun flux mutabil la expeditor: acordul dintre cele două capete NU "
        "s-a verificat. Receptorul are `incidents` înregistrat "
        "(aggregator/lib/streams.ts), deci expeditorul care nu-l declară nu e "
        "„nimic de comparat”, e o divergență")
    # ...și fiecare dintre ele chiar e cunoscut de receptor, altfel bucla ar
    # compara un flux cu nimic.
    assert [s.name for s in mutable if s.name in receiver] == [s.name for s in mutable], (
        f"fluxuri mutabile pe care receptorul nu le cunoaște: "
        f"{[s.name for s in mutable if s.name not in receiver]}")

    for stream in mutable:
        assert stream.time_column in stream.columns, (
            f"{stream.name}: {stream.time_column} nu se expediază")
        assert stream.key_column in stream.columns, (
            f"{stream.name}: {stream.key_column} nu se expediază")
        theirs = receiver.get(stream.name)
        assert theirs is not None, f"{stream.name} nu e înregistrat la receptor"
        assert stream.time_column in theirs["sources"], (
            f"{stream.name}: receptorul nu cunoaște {stream.time_column}, deci ar "
            "refuza fiecare rând ca având un câmp necunoscut")
        # Și felul cursorului, scris la fel la amândouă capetele: din el iese
        # forma de scriere la receptor și ordinea de citire la expeditor.
        assert theirs["cursor"] == stream.cursor_kind, (
            f"{stream.name}: expeditorul îl crede {stream.cursor_kind}, receptorul "
            f"{theirs['cursor']} — unul citește actualizări, celălalt le ignoră")
        assert theirs["watermarkSource"] == stream.key_column, (
            f"{stream.name}: filigranul se ia din coloane diferite la cele două "
            f"capete — expeditorul din {stream.key_column!r}, receptorul din "
            f"{theirs['watermarkSource']!r} (nume de pe SERVER, peste redenumire)")
