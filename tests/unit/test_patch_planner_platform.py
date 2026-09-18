"""`sentinel/patch/planner.py` — the prompt has to say what host it is
actually running on, and the model must not be the source of the facts the
database already holds.

Eșecul măsurat pe gazda n8n (Ubuntu 24.04) pe 17 septembrie 2026:
`/planifica 2235` a produs un plan `validated`, dintr-o singură încercare, cu
`argv: ["dnf", "-y", "update", "polkitd"]` — un binar care nu există pe
Ubuntu — și `vulnerabilities: [{"finding_id": 0, "cve": "CVE-0000-00000", ...}]`
— identificatori inventați, pentru un finding fără CVE real. Cauza: promptul
spunea „AlmaLinux 9" ca literal indiferent de `cfg.platform.family`, iar
câmpul `vulnerabilities` era cerut modelului în loc să fie citit din bază.

Fișierul ăsta acoperă partea din `planner.py`: promptul e adevărat despre gazdă
(§1-§4), iar `generate()` nu mai lasă câmpul `vulnerabilities` la mila
modelului (§5). Contradicțiile pe care ar trebui să le respingă și validatorul,
chiar dacă fixup-ul de aici ar lipsi vreodată, sunt în
`tests/unit/test_patch_validator.py`.
"""
from __future__ import annotations

import asyncio
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.config import Config
from sentinel.patch import planner


FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def run(c):
    return asyncio.run(c)


# ---------------------------------------------------------------------------
# §1-§4 — the prompt names the real family, not a literal
# ---------------------------------------------------------------------------
def test_rhel_prompt_names_almalinux_and_dnf():
    text = planner._render_system("rhel")
    assert "AlmaLinux 9" in text
    assert "dnf -y update" in text


def test_debian_prompt_names_debian_and_apt_get_and_never_almalinux():
    """The defect, directly: a Debian host must never be told it is running
    AlmaLinux, and the guidance sentence has to point at the binary that
    actually exists there."""
    text = planner._render_system("debian")
    assert "AlmaLinux" not in text
    assert "Debian/Ubuntu" in text
    assert "apt-get" in text


def test_both_renderings_substitute_every_placeholder():
    """A silent `.replace` miss would leave a `%%...%%` token in the system
    prompt — syntactically harmless, and the model told nothing useful."""
    for family in ("rhel", "debian"):
        assert "%%" not in planner._render_system(family)


def test_debian_prompt_never_teaches_rpm_state():
    """`rpm_state` runs `rpm -q`, a binary the validator's own
    `_BACKUP_KIND_UNAVAILABLE_ON` (validator.py) says does not exist on a
    debian host — and now correctly refuses. Teaching the model a backup
    kind the validator will then reject is a guaranteed second-attempt
    failure, the same class of drift `_binary_allowlist_doc` already guards
    against for ordinary binaries."""
    text = planner._render_system("debian")
    assert "rpm_state" not in text


def test_rhel_prompt_still_teaches_rpm_state():
    """The mirror: `rpm_state` is real, useful guidance on the family it was
    designed for, and must not disappear there along with the debian fix."""
    text = planner._render_system("rhel")
    assert "rpm_state" in text


def test_an_unrecognised_family_refuses_instead_of_silently_becoming_rhel():
    """`Config` already refuses an unknown `platform.family` at load time, and
    `unplannable_reason` refuses to generate for one — but if either of those
    gates were ever bypassed, the prompt must not fall back to AlmaLinux by
    accident. A `KeyError`-shaped silent default here would be exactly the
    「probably rpm」 guess the rest of this module goes out of its way to
    avoid."""
    with pytest.raises(ValueError):
        planner._render_system("alpine")


def test_build_user_states_the_real_system_not_a_literal():
    ctx = {"package": "polkitd", "cve": None, "ecosystem": "deb"}
    text = planner._build_user(ctx, "debian")
    assert "Sistem: Debian/Ubuntu, pachete DEB prin apt-get." in text
    assert "AlmaLinux" not in text


def test_build_user_rhel_still_says_rpm_via_dnf():
    ctx = {"package": "polkitd", "cve": "CVE-2026-1", "ecosystem": "rpm"}
    text = planner._build_user(ctx, "rhel")
    assert "Sistem: AlmaLinux 9, pachete RPM prin dnf." in text


def test_binary_allowlist_doc_is_generated_not_hand_copied():
    """The prompt's rule 2 used to list binaries by hand and had already
    drifted from `PATCH_BINARY_ALLOWLIST` — `httpd`, `wp`, `certbot` named as
    allowed when the validator had stopped allowing them. Generated from the
    same table, the two cannot drift apart again — for whichever family a
    binary genuinely belongs to (`rhel`-only binaries are still expected on
    the `rhel` rendering; the cross-family subtraction is a separate test
    below)."""
    from sentinel.constants import PATCH_BINARY_ALLOWLIST
    from sentinel.patch.validator import PLATFORM_PACKAGE_BINARIES

    debian_only = PLATFORM_PACKAGE_BINARIES["debian"]
    doc = planner._binary_allowlist_doc("rhel")
    for binary in PATCH_BINARY_ALLOWLIST:
        if binary not in debian_only:
            assert binary in doc


def test_binary_allowlist_doc_never_offers_the_other_familys_package_manager():
    """`PATCH_BINARY_ALLOWLIST` has no opinion on `dnf` vs `apt-get` — it is
    the same set for both families — so rendering it whole told a Debian
    host `dnf` and `rpm` were fine, and `validate_plan`'s own
    `platform_family` check then rejected them on the very first attempt:
    a guaranteed second-attempt failure, the exact defect class this
    function exists to remove, reopened for backup kinds instead of
    ordinary binaries."""
    from sentinel.patch.validator import PLATFORM_PACKAGE_BINARIES

    rhel_doc = planner._binary_allowlist_doc("rhel")
    for binary in PLATFORM_PACKAGE_BINARIES["debian"]:
        assert binary not in rhel_doc.split(", "), (
            f"{binary!r} is debian-only but appears in the rhel prompt's allowlist")

    debian_doc = planner._binary_allowlist_doc("debian")
    for binary in PLATFORM_PACKAGE_BINARIES["rhel"]:
        assert binary not in debian_doc.split(", "), (
            f"{binary!r} is rhel-only but appears in the debian prompt's allowlist")


# ---------------------------------------------------------------------------
# §5 — the model is not the source of finding_id / cve / package
# ---------------------------------------------------------------------------
def _full_debian_plan() -> dict:
    """A structurally complete Debian plan, standing in for whatever the model
    actually returned — its `vulnerabilities` block is deliberately the
    fabricated one measured in production.

    Read from `tests/fixtures/debian_plan.json` rather than written out here,
    because `tests/security/test_plan_argvs_match_executor_policy.py` runs
    every argv in it through the executor's own `check_argv`. A private copy
    in this module would be the one plan nothing cross-checks — which is
    exactly how `apt-get -y install --only-upgrade polkitd` stayed in this
    fixture, and in the planner's prompt, for three rounds while the executor
    refused it.

    A fresh object each call: `generate()` overwrites `vulnerabilities` in
    place, and two tests call it twice.
    """
    return json.loads(
        (FIXTURES / "debian_plan.json").read_text(encoding="utf-8"))


def test_generate_overwrites_a_fabricated_vulnerabilities_block(monkeypatch):
    """The defect, end to end: the model fabricates `finding_id: 0` and
    `CVE-0000-00000` for a finding that genuinely has no CVE (a Debian/Ubuntu
    USN-tracked package). The plan that gets STORED must carry the finding's
    real id and no invented CVE — not what the model wrote."""
    captured: list = []

    async def _context(db, finding_id):
        return {"id": finding_id, "cve": None, "package": "polkitd",
                "ecosystem": "deb", "installed_version": "0.105-1",
                "fixed_version": "0.106-2", "severity": "medium",
                "cvss": None, "epss": None, "kev": False,
                "protected": False, "asset_id": None, "priority": 40}

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        return SimpleNamespace(
            ok=True, error=None, tool_input=_full_debian_plan(),
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    async def _store_plan(db, **kw):
        captured.append(kw)
        return 99

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)

    cfg = Config()
    cfg.platform.family = "debian"

    plan_db_id, status = run(planner.generate(object(), cfg, "sk-test", 2235))

    assert status == "validated", "plan rejected — see errors on the captured store_plan call"
    assert plan_db_id == 99
    stored_vulns = captured[0]["plan"]["vulnerabilities"]
    assert len(stored_vulns) == 1
    assert stored_vulns[0]["finding_id"] == 2235, (
        "the model's fabricated finding_id (0) reached the stored plan")
    assert stored_vulns[0]["cve"] is None, (
        "the model's fabricated CVE-0000-00000 reached the stored plan, for a "
        "finding that has no CVE at all")
    assert stored_vulns[0]["package"] == "polkitd"


def test_generate_survives_a_scored_finding(monkeypatch):
    """`findings.cvss`/`findings.epss` are `numeric(3,1)`/`numeric(5,4)`
    columns (0003_vuln.sql:56,61), and asyncpg has no codec configured for
    `numeric` anywhere in this project, so `_context` hands them back as
    `decimal.Decimal` — confirmed `data_type = numeric` on both hosts. Before
    this fix, `plan["vulnerabilities"]` copied `ctx["cvss"]`/`ctx["epss"]`
    straight through, and `plan_hash()`'s `json.dumps` raised `TypeError:
    Object of type Decimal is not JSON serializable` the moment a SCORED
    finding reached `/planifica` or `generate_for_kev` — the normal case, not
    an edge case; it only looked safe because every open `deb` finding on
    n8n happened to have a NULL score."""
    captured: list = []

    async def _context(db, finding_id):
        return {"id": finding_id, "cve": None, "package": "polkitd",
                "ecosystem": "deb", "installed_version": "0.105-1",
                "fixed_version": "0.106-2", "severity": "high",
                "cvss": Decimal("8.1"), "epss": Decimal("0.3120"), "kev": True,
                "protected": False, "asset_id": None, "priority": 90}

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        return SimpleNamespace(
            ok=True, error=None, tool_input=_full_debian_plan(),
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    async def _store_plan(db, **kw):
        captured.append(kw)
        return 7

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)

    cfg = Config()
    cfg.platform.family = "debian"

    plan_db_id, status = run(planner.generate(object(), cfg, "sk-test", 501))

    assert status == "validated", "plan rejected — see errors on the captured store_plan call"
    assert plan_db_id == 7
    stored_vulns = captured[0]["plan"]["vulnerabilities"]
    assert "cvss" not in stored_vulns[0]
    assert "epss" not in stored_vulns[0]


# ---------------------------------------------------------------------------
# `generate()` must actually WIRE `platform_family=` and `finding=` into
# `validate_plan` at generation time — the production path, not just at
# execution time (`runner.run_plan`'s own re-validation).
# ---------------------------------------------------------------------------
def test_generate_rejects_a_dnf_plan_against_a_debian_host(monkeypatch, good_plan):
    """The production defect this whole file exists to cover, reproduced
    without the fabricated-`vulnerabilities` step in the way: `good_plan` is
    an `rpm`-family plan (`dnf` in apply/rollback/backup restore_argv). If
    `generate()` ever again called `validate_plan(plan, finding=finding_facts)`
    without `platform_family=family`, this would validate clean against a
    debian host, exactly as `/planifica 2235` did on n8n on 17 sep 2026."""
    captured: list = []

    async def _context(db, finding_id):
        return {"id": finding_id, "cve": "CVE-2026-9999", "package": "nginx",
                "ecosystem": "deb", "installed_version": "1.20.1-14",
                "fixed_version": "1.20.1-16", "severity": "high",
                "cvss": None, "epss": None, "kev": False,
                "protected": False, "asset_id": None, "priority": 60}

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        return SimpleNamespace(
            ok=True, error=None, tool_input=good_plan,
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    async def _store_plan(db, **kw):
        captured.append(kw)
        return 55

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)

    cfg = Config()
    cfg.platform.family = "debian"

    plan_db_id, status = run(planner.generate(object(), cfg, "sk-test", 9001))

    assert status == "rejected_invalid", (
        "a dnf plan validated clean for a debian host — generate() stopped "
        "passing platform_family to validate_plan")
    codes = {e["code"] for e in captured[0]["validation_errors"]}
    assert "binary_wrong_platform" in codes, captured[0]["validation_errors"]


def test_generate_passes_family_and_finding_facts_to_validate_plan(monkeypatch):
    """`platform_family=` and `finding=` exist specifically to make
    cross-platform drift and identifier fabrication impossible to VALIDATE,
    not merely unlikely to be asked for (see `validate_plan`'s own
    docstring). Both are keyword arguments a caller can silently stop
    passing while `validate_plan(plan, ...)` still appears in the source —
    a grep would not notice. This asserts the exact values `generate()`
    hands over, the same way `tests/unit/test_patch_plan_on_request.py`
    pins `generated_by`."""
    captured_kwargs: list = []

    async def _context(db, finding_id):
        return {"id": finding_id, "cve": "CVE-2026-4321", "package": "curl",
                "ecosystem": "rpm", "installed_version": "7.0-1",
                "fixed_version": "7.0-2", "severity": "high",
                "cvss": None, "epss": None, "kev": False,
                "protected": False, "asset_id": 3, "priority": 70}

    async def _allowed(db, cfg):
        return True, ""

    async def _record(*a, **kw):
        return None

    async def _call(api_key, **kw):
        return SimpleNamespace(
            ok=True, error=None, tool_input={"schema_version": 1},
            usage=SimpleNamespace(input_tokens=1, output_tokens=1, cached_tokens=0))

    def _spy_validate(plan, **kw):
        captured_kwargs.append(kw)
        return SimpleNamespace(valid=True, errors=[])

    async def _store_plan(db, **kw):
        return 12

    monkeypatch.setattr(planner, "_context", _context)
    monkeypatch.setattr(planner.budget, "allowed", _allowed)
    monkeypatch.setattr(planner.budget, "record", _record)
    monkeypatch.setattr(planner, "call_structured", _call)
    monkeypatch.setattr(planner, "validate_plan", _spy_validate)
    monkeypatch.setattr(planner, "plan_hash", lambda plan: "h" * 8)
    monkeypatch.setattr(planner.repo, "store_plan", _store_plan)

    cfg = Config()
    cfg.platform.family = "rhel"

    plan_db_id, status = run(planner.generate(object(), cfg, "sk-test", 4242))

    assert status == "validated"
    assert len(captured_kwargs) == 1, (
        "validate_plan should be called exactly once when the first attempt validates")
    kw = captured_kwargs[0]
    assert kw.get("platform_family") == "rhel", (
        f"generate() did not pass cfg.platform.family through — got {kw!r}")
    assert kw.get("finding") == {
        "finding_id": 4242, "cve": "CVE-2026-4321", "package": "curl",
    }, f"generate() did not pass the deterministic finding facts through — got {kw!r}"


# ---------------------------------------------------------------------------
# §6 — the prompt teaches only forms the EXECUTOR also accepts
#
# Measured on 18 September 2026: the debian prompt taught `apt-get -y install
# --only-upgrade <pachet>`, which `executor/policy.py` refuses. The plan
# validated, reached Telegram, was approved, and would have died at apply step
# 1 — with the rollback in the same plan being `apt-get -y install <pachet>`,
# unpinned, which reinstalls the version the patch had just replaced. The
# prompt, the validator and the executor now agree by construction: these
# tests run the prompt's OWN examples through the executor's grammar.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("family", ["rhel", "debian"])
def test_the_prompts_own_commands_pass_the_executors_grammar(family):
    """The forms the model is TOLD to use must be forms that can run.

    A prompt that teaches a refused command buys a guaranteed failure: either
    a second Opus call (the retry) or, worse, an approved plan that dies
    mid-apply on the production host.
    """
    import policy

    facts = planner._PLATFORM_PROMPT_FACTS[family]
    values = {"pkg": "polkitd", "installed": "0.105-1", "fixed": "0.106-2"}
    for key in ("apply_argv", "rollback_argv"):
        argv = json.loads(facts[key].format(**values))
        assert policy.check_argv(argv) == argv, key


def test_the_debian_prompt_names_only_upgrade_only_to_forbid_it():
    """`--only-upgrade` is not on the executor's apt flag list and is
    deliberately not being added: under the pinned design it says less than
    the pin already does. The prompt used to teach it as THE update form,
    which is how every Debian plan came to carry a command that cannot run.

    It is still named once — as a prohibition, because a model that knows apt
    reaches for it unprompted — and the count is what this test pins: a
    second occurrence means it has crept back in as an example.
    """
    flat = " ".join(planner._render_system("debian").split())
    assert "`--only-upgrade` nu e acceptat" in flat, (
        "the prohibition is gone; the model will reach for the flag on its own")
    assert flat.count("--only-upgrade") == 1, (
        "--only-upgrade appears more than once — it is being taught again, "
        "not only forbidden")
    assert "--only-upgrade" not in planner._render_system("rhel"), (
        "an apt flag has no business in the AlmaLinux prompt at all")


def test_the_debian_prompt_teaches_the_pinned_pair_and_its_preflight():
    """The four pieces hold each other up: without the `equals` preflight the
    pinned rollback can name a version this host never had, and the operator
    would be handed a "rollback" that installs something arbitrary."""
    text = planner._render_system("debian")
    assert "--allow-downgrades" in text
    assert "equals: <versiunea instalată>" in text
    assert "at_least: <versiunea care repară>" in text


@pytest.mark.parametrize("family", ["rhel", "debian"])
def test_the_prompt_admits_a_pinned_rollback_can_still_fail(family):
    """A rollback pinned to a version that has left the archive fails at run
    time. That is far better than one that provably restores nothing — but
    the operator must not be told it is guaranteed, or the first failed
    rollback is also the first time anyone learns it was never certain."""
    text = planner._render_system(family)
    assert "nu mai există în" in text and "nu e o garanție" in text


def test_build_user_carries_the_real_versions_into_the_commands():
    """The model invented package/version combinations when it had to compose
    them itself (`finding_id: 0`, `CVE-0000-00000` came from the same habit).
    Handing it the exact strings from the database removes the step where it
    could guess."""
    ctx = {"package": "polkitd", "cve": None, "ecosystem": "deb",
           "installed_version": "0.105-1", "fixed_version": "0.106-2"}
    text = planner._build_user(ctx, "debian")
    assert '["apt-get", "-y", "install", "polkitd=0.106-2"]' in text
    assert ('["apt-get", "-y", "install", "--allow-downgrades", "polkitd=0.105-1"]'
            in text)
    assert 'equals: "0.105-1"' in text


def test_build_user_refuses_to_invent_a_rollback_version_it_does_not_have():
    """`installed_version` is NULL for some findings. Formatting it anyway
    would produce `polkitd=None` — a pin to a version that has never existed,
    which apt would either refuse or, worse, match against something
    unintended. "Unknown" has to stay visibly unknown, and the plan has to say
    it is not reversible."""
    ctx = {"package": "polkitd", "cve": None, "ecosystem": "deb",
           "installed_version": None, "fixed_version": "0.106-2"}
    text = planner._build_user(ctx, "debian")
    assert "polkitd=None" not in text
    assert "reversible: false" in text


def test_backup_kind_doc_reads_the_validators_table_not_a_hand_written_family():
    """`_backup_kind_doc` used to test `if family == "rhel"`, which agreed
    with the validator only by coincidence — one entry, two families. The day
    `rpm_state` becomes unavailable on rhel too (or a third family appears),
    a hand-written condition keeps teaching a kind the validator refuses, and
    every plan fails validation twice before being stored as rejected."""
    from sentinel.patch import validator as validator_mod

    original = validator_mod.BACKUP_KIND_UNAVAILABLE_ON["rpm_state"]
    try:
        validator_mod.BACKUP_KIND_UNAVAILABLE_ON["rpm_state"] = frozenset({"rhel"})
        assert "rpm_state" not in planner._backup_kind_doc("rhel"), (
            "the prompt still offers rpm_state to a family the validator now "
            "refuses it on — the table is not being read")
        assert "rpm_state" in planner._backup_kind_doc("debian")
    finally:
        validator_mod.BACKUP_KIND_UNAVAILABLE_ON["rpm_state"] = original
