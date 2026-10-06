"""The "AI content" label: one shape, on the right content, and only there.

The operator asked for a small, consistent label wherever what is on screen was written or judged
by the model, so they can tell at a glance which words are the model's and which are measured
facts. What goes wrong for them if this regresses:

* **Two shapes.** The label is written once per surface (a Jinja macro here, `aiBadge()` in the
  aggregator). If they drift apart, "AI content" on one screen and "AI-content" or a different
  colour on the other stops meaning "the model wrote this". Pinned: byte-identical markup, and
  identical declarations in the two stylesheets.
* **A label on something the model did not produce.** A badge on a measured field teaches the
  operator that the badge means nothing. Pinned: a row the model did not judge, and a plan nobody
  asked the model to draft, render NO label and no word that implies one.
* **A judgement without its label.** The inverse: the verdict card, the verdict in a list row, a
  model-drafted plan. Pinned on rendered output.
* **The label that fails contrast exactly when it is read.** A badge tinted over a hovered table
  row measured 3.93:1 in the dark theme; it is opaque now. Pinned with the design system's own
  arithmetic.

"Judged" is `ai_analyzed_at`, not `ai_severity`: `triage._clean` can reject the model's severity
and leave it empty while the incident WAS judged. A plan is "model-drafted" when `model` is set,
not by `generated_by`, which records who ASKED (see `planner.generate`).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "sentinel" / "web" / "templates"
SENTINEL_CSS = ROOT / "sentinel" / "web" / "static" / "css" / "sentinel.css"
PANEL_CSS = ROOT / "aggregator" / "public" / "panel.css"
PANEL_PAGE = ROOT / "aggregator" / "lib" / "panel-page.ts"
NOW = datetime(2026, 10, 5, 1, 56, tzinfo=timezone.utc)
BADGE_CLASS = 'class="ai-badge"'


def _env():
    from sentinel.web.jinja import build_env

    return build_env("Europe/Bucharest")


def _count(html: str) -> int:
    return html.count(BADGE_CLASS)


# ---------------------------------------------------------------- one shape


def _macro_markup() -> str:
    tpl = _env().from_string('{% import "_ai.html" as ai %}{{ ai.badge() }}')
    return tpl.render().strip()


def _ts_badge_markup() -> str:
    """The string `aiBadge()` returns, rebuilt from its literals (no node in a fresh clone)."""
    src = PANEL_PAGE.read_text(encoding="utf-8")
    m = re.search(r"export function aiBadge\(\): string [{](.*?)\n[}]", src, flags=re.S)
    assert m, "aiBadge() is gone from panel-page.ts"
    literals = re.findall(r"""'([^']*)'|"([^"]*)\"""", m.group(1))
    return "".join(a or b for a, b in literals)


def test_the_two_surfaces_write_the_label_byte_for_byte_the_same():
    """Eșecul pe care îl previne: „AI content" arată sau se scrie altfel pe agregator decât pe
    server — operatorul nu mai poate citi eticheta ca pe un semn, ci ca pe două decorațiuni."""
    server, agg = _macro_markup(), _ts_badge_markup()
    assert server and "AI content" in server, "positive control: the macro renders the label"
    assert server == agg, f"server {server!r} != aggregator {agg!r}"


def _declarations(path: Path, selector: str) -> dict[str, str]:
    css = re.sub(r"/[*].*?[*]/", "", path.read_text(encoding="utf-8"), flags=re.S)
    for m in re.finditer(r"([^{}]+)[{]([^{}]*)[}]", css):
        if " ".join(m.group(1).split()) == selector:
            return {k.strip(): " ".join(v.split()) for k, _, v in
                    (d.partition(":") for d in m.group(2).split(";")) if k.strip()}
    raise AssertionError(f"no rule {selector!r} in {path.name}")


@pytest.mark.parametrize("selector", [".ai-badge", ".ai-badge::before"])
def test_the_two_stylesheets_draw_the_label_with_the_same_declarations(selector):
    """Eșecul pe care îl previne: aceeași etichetă, culori sau forme diferite pe cele două ecrane."""
    a = _declarations(SENTINEL_CSS, selector)
    b = _declarations(PANEL_CSS, selector)
    assert a, "positive control: the rule has declarations"
    assert a == b, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}


def test_the_label_is_opaque_so_its_contrast_does_not_depend_on_the_row_under_it():
    """A 12% tint of the accent over a hovered row measured 3.93:1 (dark) and 4.49:1 (light).

    Eșecul pe care îl previne: eticheta devine ilizibilă exact când treci mouse-ul peste rând.
    `--accent-soft` e opac, deci perechea (accent pe accent-soft) e singura care contează, iar ea e
    măsurată cu aceeași aritmetică ca restul sistemului.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "design_system", ROOT / "tests" / "unit" / "test_design_system.py")
    ds = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ds)

    for path in (SENTINEL_CSS, PANEL_CSS):
        decls = _declarations(path, ".ai-badge")
        assert decls["background"] == "var(--accent-soft)", (path.name, decls["background"])
        assert decls["color"] == "var(--accent)"
    for theme in ("dark", "light"):
        system = ds._system(theme)
        ratio = ds.contrast_ratio(system["--accent"], system["--accent-soft"])
        assert ratio >= 4.5, f"{theme}: accent on accent-soft is {ratio:.2f}:1"


# ---------------------------------------------------------------- where it appears, server


def _incident_row(i: int, *, judged: bool, ai_severity: str | None = "medium",
                  confidence: float | None = 0.85):
    return SimpleNamespace(
        id=i, severity="high", title=f"Incident {i}", summary="x", actor_key="1.2.3.4",
        status="open", detection_count=3, first_detection_at=NOW, last_detection_at=NOW,
        notified_at=None, sev_dot="bad", auto_action=None,
        ai_severity=ai_severity if judged else None,
        ai_confidence=confidence if judged else None,
        ai_analyzed_at=NOW if judged else None,
        ai_sev_dot="warn")


def _list_html(rows):
    from sentinel.db.repo import incidents as inc

    user = SimpleNamespace(username="op", role="owner")
    return _env().get_template("incidents.html").render(
        user=user, active="incidents", rows=rows, counts={"total": len(rows)},
        filter_status=None, sort="recent", sorts=inc.SORTS, status_ro={"open": "deschis"},
        can_act=False, msg=None, csrf_token="t", open_rules=[], version="1")


def test_the_incident_list_labels_exactly_the_rows_the_model_judged():
    """Eșecul pe care îl previne: eticheta pe toate rândurile (nu mai spune nimic), pe niciunul
    (modelul pare nefolosit — plângerea operatorului), sau pe cele pe care modelul n-a pus mâna."""
    rows = [_incident_row(1, judged=True), _incident_row(2, judged=False),
            _incident_row(3, judged=True), _incident_row(4, judged=False)]
    html = _list_html(rows)
    assert _count(html) == 2
    # Per row, not just in total: the label sits in the rows of incidents 1 and 3.
    for i, expected in ((1, 1), (2, 0), (3, 1), (4, 0)):
        row_html = html.split(f'href="/incidents/{i}"')[1].split("</tr>")[0]
        assert _count(row_html) == expected, (i, row_html[:300])


def test_an_unjudged_row_says_nothing_that_implies_it_was_judged():
    """Un rând nejudecat rămâne cu „—": fără etichetă, fără severitate AI, fără procent."""
    html = _list_html([_incident_row(7, judged=False)])
    row = html.split('href="/incidents/7"')[1].split("</tr>")[0]
    assert _count(row) == 0
    assert "%" not in row and "AI content" not in row
    assert 'class="muted small">—</span>' in row


def test_a_judged_incident_without_a_usable_severity_is_still_labelled_and_says_unknown():
    """`triage._clean` can drop the model's severity; the incident WAS judged.

    Eșecul pe care îl previne: criteriul „judecat" devine `ai_severity`, iar un incident judecat
    cu o severitate respinsă pare nejudecat — și costul lui nu mai are nicio urmă pe ecran.
    """
    html = _list_html([_incident_row(5, judged=True, ai_severity=None, confidence=None)])
    row = html.split('href="/incidents/5"')[1].split("</tr>")[0]
    assert _count(row) == 1
    assert "— · —" in row, "unknown severity and confidence must read as unknown, not as 0%"


def test_the_list_shows_what_the_model_judged_and_when():
    """Severitate, încredere și moment, în rând — nu doar eticheta."""
    html = _list_html([_incident_row(1, judged=True, ai_severity="critical", confidence=0.97)])
    row = html.split('href="/incidents/1"')[1].split("</tr>")[0]
    assert "critical" in row and "97%" in row
    assert "05.10 04:56 EEST" in row, "the judged-at time must carry its zone, like every other time"


def _detail_html(*, judged: bool, verdict=None):
    user = SimpleNamespace(username="op", role="viewer")
    row = _incident_row(1, judged=judged)
    return _env().get_template("incident.html").render(
        user=user, active="incidents", inc=row, detections=[], verdict=verdict,
        status_ro={"open": "deschis"}, can_act=False, csrf_token="t",
        request=SimpleNamespace(query_params={}), version="1")


def test_the_incident_page_labels_the_verdict_card_and_the_ai_severity_beside_the_fact():
    verdict = {"severity": "medium", "is_false_positive": False, "confidence": 0.85,
               "recommended_action": "monitorizează", "summary_ro": "Probabil rutină.",
               "prompt_injection_detected": False}
    html = _detail_html(judged=True, verdict=verdict)
    assert _count(html) == 2, "one beside the AI severity in the summary, one on the verdict card"
    card = html.split("Analiză AI")[1]
    assert BADGE_CLASS in card.split("</h2>")[0], "the card heading carries the label"
    assert "Probabil rutină." in card and "Evaluat la" in card
    # The deterministic severity is a measured fact: no label next to it.
    summary = html.split("<h2>Rezumat</h2>")[1].split("</section>")[0]
    sev_row = summary.split("<dt>Severitate</dt>")[1].split("<dt>Stare</dt>")[0]
    assert sev_row.count(BADGE_CLASS) == 1 and "high" in sev_row


def test_the_incident_page_of_an_unjudged_incident_has_no_label_and_no_ai_card():
    html = _detail_html(judged=False, verdict=None)
    assert _count(html) == 0
    assert "Analiză AI" not in html and "AI content" not in html


def _plan(model):
    from sentinel.db.repo.patches import PlanRow

    p = PlanRow(
        id=1, plan_id=uuid.uuid4(), plan_hash="ab" * 32,
        plan={"target": {"asset_name": "nginx"}, "risk": {"blast_radius": "x"},
              "vulnerabilities": [], "apply": [], "restore_instructions_ro": "r"},
        status="validated", risk_level="medium", requires_reboot=False, reversible=True,
        estimated_downtime_s=5, asset_id=1, created_at=NOW, approved_by=None, approved_at=None,
        validation_errors=None, model=model)
    p.status_ro, p.pill, p.asset = "validat", "warn", "nginx"
    return p


def _patch_list_html(plans):
    user = SimpleNamespace(username="op", role="owner")
    return _env().get_template("patches.html").render(
        user=user, active="patches", rows=plans, restore_points=[], msg=None, csrf_token="t",
        version="1")


def _patch_detail_html(plan):
    user = SimpleNamespace(username="op", role="owner")
    return _env().get_template("patch.html").render(
        user=user, active="patches", p=plan, executions=[], steps=[], plan_json="{}",
        can_act=False, csrf_token="t", request=SimpleNamespace(query_params={}), version="1")


def test_a_model_drafted_plan_is_labelled_in_the_list_and_a_manual_one_is_not():
    html = _patch_list_html([_plan("claude-opus-5"), _plan(None)])
    first, second = html.split("</tr>")[1:3]
    assert _count(first) == 1 and _count(second) == 0
    assert 'class="muted small">—</span>' in second


def test_a_model_drafted_plan_is_labelled_where_its_words_are_and_a_manual_one_nowhere():
    drafted = _patch_detail_html(_plan("claude-opus-5"))
    manual = _patch_detail_html(_plan(None))
    # title, risk card, "what the plan does", "how to roll back manually"
    assert _count(drafted) == 4 and "claude-opus-5" in drafted
    assert _count(manual) == 0 and "AI content" not in manual and "Model" not in manual
    # The covered-vulnerabilities card is deterministic data from the database: no label in it.
    covered = drafted.split("Vulnerabilități acoperite")[1].split("</div>")[0]
    assert BADGE_CLASS not in covered


def test_no_template_writes_the_label_by_hand():
    """Every label goes through the macro; a hand-written copy is the second shape.

    Allowed: the explanatory note on the patches page names the label in quotes („AI content”),
    which is text about the label, not a label.
    """
    for path in sorted(TEMPLATES.glob("*.html")):
        if path.name == "_ai.html":
            continue
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"[{]#.*?#[}]", "", text, flags=re.S)
        assert "ai-badge" not in text, f"{path.name} writes the badge class by hand"
        for m in re.finditer("AI content", text):
            around = text[max(0, m.start() - 1):m.end() + 1]
            assert around == "„AI content”", f"{path.name} writes 'AI content' outside the macro"


def test_findings_get_no_ai_surface_because_the_column_has_never_been_written():
    """`findings.ai_assessment` has 0 non-null rows of 7631 (measured on production, 6 Oct 2026).

    Eșecul pe care îl previne: o pagină de vulnerabilități cu o coloană „AI" mereu goală — o
    suprafață pentru date care nu există, pe care operatorul ar citi ca „modelul n-a găsit nimic".
    """
    for name in ("findings.html", "_vuln.html"):
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        assert "ai_assess" not in text and "ai-badge" not in text and "AI content" not in text


# ---------------------------------------------------------------- the suggested action


_ACTIONS = ("monitorizează", "blochează", "investighează", "ignoră", "patch")
ACTION_ROW = "<dt>Acțiune sugerată</dt>"


def _verdict(action):
    return {"severity": "medium", "is_false_positive": False, "confidence": 0.85,
            "recommended_action": action, "summary_ro": "Probabil rutină.",
            "prompt_injection_detected": False}


def _card(verdict) -> str:
    """The "Analiză AI" card of the incident page, up to its closing tag."""
    return _detail_html(judged=True, verdict=verdict).split("Analiză AI")[1].split("</section>")[0]


@pytest.mark.parametrize("action", _ACTIONS)
def test_a_canonical_action_is_written_under_the_label(action):
    """Eșecul pe care îl previne: acțiunea sugerată dispare chiar și când modelul a răspuns
    corect — operatorul pierde singura recomandare pe care pagina o mai poate da."""
    card = _card(_verdict(action))
    assert f"{ACTION_ROW}<dd>{action}</dd>" in card


_GARBAGE = [
    pytest.param("unknown", id="unknown"),
    # Măsurat pe 6 oct 2026: șase caractere ASCII (backslash, u, 0103) în locul lui „ă".
    pytest.param("blocheaz" + chr(92) + "u0103", id="literal-escape-blocheaza"),
    pytest.param("investigheaz" + chr(92) + "u0103", id="literal-escape-investigheaza"),
    pytest.param("blocheaz", id="truncated-blocheaza"),
    pytest.param("investigheaza", id="folded-investigheaza"),
    pytest.param("Blochează", id="wrong-case"),
    pytest.param(" blochează", id="padded"),
    pytest.param("", id="empty"),
    pytest.param(None, id="null"),
    pytest.param(["blochează"], id="list-not-string"),
    pytest.param({"a": 1}, id="object-not-string"),
    pytest.param(7, id="number"),
    pytest.param("<img src=x onerror=1>", id="markup"),
]


@pytest.mark.parametrize("action", _GARBAGE)
def test_anything_but_a_canonical_action_omits_the_row_under_the_label(action):
    """Pe 6 oct 2026, 94% din verdictele judecate purtau `unknown` sau o diacritică ruptă.

    Eșecul pe care îl previne: „Acțiune sugerată: unknown" (sau „blocheaz" urmat de secvența ASCII
    care ține locul diacriticii) scris sub eticheta „AI content" — eticheta certifică gunoiul drept
    răspunsul modelului. Rândul lipsește
    cu totul: nici „—", nici textul. Restul cardului rămâne, iar pagina nu dă 500 pe un blob cu
    alt tip decât șir.
    """
    verdict = _verdict(action)
    card = _card(verdict)
    assert "Acțiune sugerată" not in card, "the row must be omitted, not blanked"
    if isinstance(action, str) and action.strip():
        assert action not in card, "the corrupt text reached the screen"
    # Everything else the model said is still there, under the same label.
    assert BADGE_CLASS in card.split("</h2>")[0]
    assert "Probabil rutină." in card and "Evaluat la" in card and "85%" in card


def test_a_verdict_blob_without_the_action_key_omits_the_row_too():
    verdict = _verdict("patch")
    del verdict["recommended_action"]
    assert "Acțiune sugerată" not in _card(verdict)


def test_the_filter_never_raises_whatever_the_blob_holds():
    """Un blob cu o listă sau un obiect în `recommended_action` nu poate da 500 pe pagină."""
    from sentinel.web.jinja import ai_action_filter

    assert ai_action_filter("blochează") == "blochează"  # positive control
    for junk in (None, 0, 1.5, [], ["patch"], {}, {"patch": 1}, b"patch", object()):
        assert ai_action_filter(junk) is None, junk


def test_the_three_lists_of_canonical_actions_are_the_same_list():
    """Eșecul pe care îl previne: producătorul primește o acțiune nouă (sau una redenumită), iar
    cele două panouri o ascund în tăcere ca „necanonică" — recomandarea dispare de pe ecran fără
    ca vreun test să pice."""
    from sentinel.ai import triage
    from sentinel.web import jinja as web_jinja

    src = (ROOT / "aggregator" / "lib" / "ai-verdict.ts").read_text(encoding="utf-8")
    m = re.search(r"export const AI_ACTIONS[^=]*=\s*\[(.*?)\];", src, flags=re.S)
    assert m, "AI_ACTIONS is gone from ai-verdict.ts"
    ts_list = tuple(re.findall(r'"([^"]+)"', m.group(1)))
    assert len(ts_list) == 5, "positive control: five words parsed from the TypeScript"
    assert tuple(triage._ACTION_ENUM) == web_jinja.AI_ACTIONS == ts_list


# ---------------------------------------------------------------- the dashboard insight


def test_the_ai_disagreement_insight_is_marked_as_model_derived():
    """Eșecul pe care îl previne: „Analiza AI a coborât severitatea la 6 din 10" apare în „Ce spun
    datele" fără etichetă, între măsurători, și se citește ca o măsurătoare — deși fără judecata
    modelului nu există nimic de numărat."""
    import asyncio

    from sentinel.analytics import insights

    class DB:
        async def fetch(self, sql, *a):  # noqa: ANN001, ANN002, ANN202
            return [{"severity": "high", "ai_severity": "low", "n": 6},
                    {"severity": "high", "ai_severity": "high", "n": 4}]

    found = asyncio.run(insights._ai_disagreement_insight(DB()))
    assert len(found) == 1, "positive control: the rule fires on 6 of 10 downgrades"
    assert found[0].ai_derived is True


def test_every_insight_rule_that_reads_a_model_column_is_marked():
    """Eșecul pe care îl previne: o regulă nouă peste `ai_severity`/`ai_verdict`/`ai_confidence`
    ajunge pe panou fără etichetă fiindcă cine a scris-o n-a știut de flag."""
    import ast

    path = ROOT / "sentinel" / "analytics" / "insights.py"
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    reading = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            body = ast.get_source_segment(src, node) or ""
            if re.search(r"\bai_(severity|verdict|confidence|analyzed_at)\b", body):
                reading.append((node.name, "ai_derived=True" in body))
    assert reading, "positive control: at least one rule reads a model column"
    assert all(marked for _, marked in reading), reading


def _insight_cards(insights) -> list[str]:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "dashboard_render", ROOT / "tests" / "unit" / "test_dashboard_render.py")
    sibling = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sibling)
    _context = sibling._context

    user_html = _env().get_template("dashboard.html").render(**_context(insights=insights))
    return user_html.split('<div class="insight ')[1:]


def test_the_dashboard_labels_the_marked_insight_and_only_that_one():
    from sentinel.analytics.insights import Insight

    cards = _insight_cards([
        Insight("info", "Titlu AI", "Detaliu.", None, {}, ai_derived=True),
        Insight("info", "Titlu măsurat", "Detaliu.", None, {}),
    ])
    assert len(cards) == 2
    ai_card, plain = cards
    assert _count(ai_card) == 1 and BADGE_CLASS in ai_card.split("</p>")[0], "label on the title"
    assert _count(plain) == 0
