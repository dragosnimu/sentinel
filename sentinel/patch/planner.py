"""Generate a patch plan for a finding, then refuse to trust it.

Transport: the Messages API with a forced tool call, not headless `claude -p`.
The headless transport exists for plans that genuinely need to read files on the
host — a PHP application's `composer.lock`, an nginx vhost. For an OS package on
AlmaLinux, which is what `dnf updateinfo` produces, every fact that matters
(package, installed version, fixed version, owning unit) is already known
deterministically. Passing exactly those facts is both cheaper and safer than
handing a model a shell, and it needs no Node runtime on the server.

The generation loop is deliberately unforgiving:

  1. Ask for a plan.
  2. Validate it with the deterministic validator.
  3. If invalid, ask ONCE more with the exact errors reinjected.
  4. If still invalid, store it as `rejected_invalid` and stop.

A plan is never partially fixed, never hand-patched into validity, and never
executed while invalid. The model is a drafting tool; the validator is the
authority, and it does not negotiate.
"""

from __future__ import annotations

import json
import time
from typing import Any

from sentinel.ai import budget
from sentinel.ai.client import call_structured
from sentinel.config import Config
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.patch.validator import CHECK_REQUIRED_FIELDS, plan_hash, validate_plan

log = get_logger(__name__)

MAX_ATTEMPTS = 2


def _check_fields_doc() -> str:
    """Render the per-kind required fields FROM the validator's own table.

    The prompt used to list the check kinds and nothing else, so the model had
    to invent the fields — and invented them wrong: `disk_free` with no
    `min_bytes`, `no_open_incident` with no `asset_id`. Both attempts were
    rejected for the same class of omission, which is real money spent on a
    guaranteed refusal.

    Generated rather than written out, because a hand-copied list drifts the
    first time a check kind gains a field, and the drift is invisible until a
    plan is rejected in production.
    """
    lines = [f"   · {kind}: {', '.join(fields)}"
             for kind, fields in sorted(CHECK_REQUIRED_FIELDS.items())]
    lines.append("   · pkg_version cere ÎN PLUS `equals` sau `at_least`")
    return "\n".join(lines)

PLANNER_SYSTEM = """\
Ești inginerul de patch-uri al agentului Sentinel, pe un server AlmaLinux 9.
Primești o vulnerabilitate confirmată și contextul ei determinist, și produci un
plan de remediere care va fi executat AUTOMAT, ca root, pe o mașină de producție.

REGULI ABSOLUTE — un plan care le încalcă este respins de validator, nu discutat:

1. Fiecare comandă este o listă `argv`, niciodată un șir. Fără shell, fără `|`,
   `&&`, `;`, `$(...)`, fără redirectări. Dacă ai nevoie de shell, planul e greșit.
2. Primul element al fiecărui argv trebuie să fie un binar din lista permisă:
   dnf, rpm, systemctl, nginx, httpd, apachectl, docker, git, npm, yarn,
   composer, pip, pip3, wp, mysqldump, mysql, pg_dump, psql, tar, zstd, gzip,
   cp, mv, ln, mkdir, install, chown, chmod, sed, test, sha256sum, certbot, curl.
   `rm` NU este permis. Nu ștergi nimic, niciodată.
3. Nu atinge niciodată: /opt/sentinel, /etc/sentinel, /var/lib/sentinel,
   /var/backups/sentinel, /root/.ssh, /etc/ssh, /etc/passwd, /etc/shadow,
   /etc/sudoers, /boot.
4. `preflight`, `health_check` și `post_verification` sunt verificări STRUCTURATE
   (obiecte cu `kind`), nu comenzi. Fiecare tip are câmpuri OBLIGATORII — dacă
   lipsește vreunul, planul e respins:
%%CHECK_FIELDS%%
5. Dacă există `backup`, trebuie să existe și o verificare `disk_free` în preflight.
6. Cel puțin o verificare din preflight trebuie să aibă `blocking: true`.
7. Un pas de `rollback` nu poate avea `on_failure: "rollback"` (ar fi recursiv);
   folosește `"abort"`.
8. Dacă `risk.reversible` este true, `rollback` nu poate fi gol.
9. Toate descrierile (`desc_ro`, `restore_instructions_ro`) sunt în română, clare
   pentru un operator care citește la 3 dimineața.
10. Fiecare `id` (de pas sau de verificare) trebuie să respecte `^[a-z0-9_]{2,16}$`
    — MAXIM 16 caractere. `verifica_disc` da; `protected_asset_gate` nu.

STRUCTURA EXACTĂ a câmpurilor obligatorii:
- `schema_version`: 1
- `target`: {asset_id: <int>, asset_name: "<nume>", protected: false,
  stack: "<stack>", unit: "<unit systemd sau null>"}
- `vulnerabilities`: [{finding_id: <int>, cve: "CVE-YYYY-NNNNN", package: "...",
  severity: "low|medium|high|critical"}]
- `risk`: {level: "low|medium|high|critical", blast_radius:
  "single-service|multi-service|host-wide", reversible: <bool>,
  requires_reboot: <bool>, estimated_downtime_s: <int>, confidence: <0..1>}
- `backup`: [{id, desc_ro, kind, source, restore_argv: [...], estimated_size_mb}]
  unde `source` depinde de `kind`:
    · `path`      → o cale absolută de fișier/director (ex. "/etc/nginx")
    · `rpm_state` → NUMELE PACHETULUI, nu o cale (ex. "curl"). Se salvează
      versiunea instalată, ca rollback-ul să o poată fixa.
    · `git_ref`   → calea depozitului git
  Un `rpm_state` cu o cale (ex. "/var/lib/rpm") este RESPINS de validator:
  `rpm -q` primește un nume de pachet, nu o cale, iar backup-ul ar eșua.
- `restore_instructions_ro`: text
Folosește exact valorile din contextul primit pentru asset_id, asset_name și
finding_id — nu le inventa.

Preferă soluția cea mai plictisitoare care funcționează. Pe AlmaLinux, aproape
întotdeauna asta înseamnă `dnf -y update <pachet>` plus repornirea unității,
nu o secvență inteligentă. Nu inventa pași. Nu presupune fișiere pe care nu ți
le-am arătat.

Răspunde DOAR prin apelul tool-ului `emit_patch_plan`."""

# Substituted, not f-stringed: the prompt is full of literal `{...}` describing
# the JSON shape, and an f-string would try to interpolate every one of them.
PLANNER_SYSTEM = PLANNER_SYSTEM.replace("%%CHECK_FIELDS%%", _check_fields_doc())


def _tool_schema() -> dict[str, Any]:
    """The tool the model must call. Loose enough that the model can express a
    plan, strict enough that obvious nonsense is rejected before the validator
    even runs — but the validator remains the real gate."""
    argv_step = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "^[a-z0-9_]{2,16}$"},
            "desc_ro": {"type": "string", "description": "descriere în română, ≥5 caractere"},
            "argv": {"type": "array", "items": {"type": "string"},
                     "description": "comanda ca listă; primul element = binar permis"},
            "timeout_s": {"type": "integer"},
            "on_failure": {"type": "string", "enum": ["rollback", "abort", "continue"]},
            "expect_exit": {"type": "array", "items": {"type": "integer"}},
        },
        "required": ["id", "desc_ro", "argv", "timeout_s", "on_failure"],
    }
    check_item = {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "desc_ro": {"type": "string"},
            "blocking": {"type": "boolean"},
            "check": {"type": "object", "description":
                      "obiect cu 'kind' și câmpurile cerute de acel kind"},
        },
        "required": ["id", "desc_ro", "blocking", "check"],
    }
    return {
        "name": "emit_patch_plan",
        "description": "Emite planul de patch validabil.",
        "input_schema": {
            "type": "object",
            "properties": {
                "schema_version": {"type": "integer"},
                "target": {"type": "object"},
                "vulnerabilities": {"type": "array", "items": {"type": "object"}},
                "risk": {"type": "object"},
                "preflight": {"type": "array", "items": check_item},
                "backup": {"type": "array", "items": {"type": "object"}},
                "apply": {"type": "array", "items": argv_step},
                "health_check": {"type": "array", "items": check_item},
                "rollback": {"type": "array", "items": argv_step},
                "post_verification": {"type": "array", "items": check_item},
                "restore_instructions_ro": {"type": "string"},
            },
            "required": ["schema_version", "target", "vulnerabilities", "risk",
                         "preflight", "backup", "apply", "health_check",
                         "post_verification", "restore_instructions_ro"],
        },
    }


async def _context(db: Database, finding_id: int) -> dict[str, Any] | None:
    """Everything the model is allowed to know, gathered deterministically."""
    row = await db.fetchrow(
        """
        SELECT f.id, f.cve, f.title, f.severity, f.cvss, f.epss, f.kev, f.priority,
               f.package, f.installed_version, f.fixed_version, f.ecosystem,
               f.scanner, f.location,
               a.id AS asset_id, a.name AS asset_name, a.kind AS asset_kind,
               a.systemd_unit, a.container_id, a.stack, a.criticality,
               a.is_internet_exposed, a.protected, a.vhost_file, a.webroot
        FROM findings f LEFT JOIN assets a ON a.id = f.asset_id
        WHERE f.id = $1
        """,
        finding_id)
    return dict(row) if row else None


def _build_user(ctx: dict[str, Any], errors: list[str] | None = None) -> str:
    parts = [
        "Vulnerabilitate confirmată (fapte deterministe, de încredere):",
        f"- CVE: {ctx.get('cve') or '—'}",
        f"- pachet: {ctx.get('package')} ({ctx.get('ecosystem') or 'rpm'})",
        f"- versiune instalată: {ctx.get('installed_version') or 'necunoscută'}",
        f"- versiune care repară: {ctx.get('fixed_version') or 'necunoscută'}",
        f"- severitate: {ctx.get('severity')} · CVSS {ctx.get('cvss') or '—'} · "
        f"KEV: {'DA' if ctx.get('kev') else 'nu'} · prioritate {ctx.get('priority')}",
        "",
        "Asset-ul afectat:",
        f"- id: {ctx.get('asset_id') or 'nespecificat (pachet la nivel de host)'}",
        f"- nume: {ctx.get('asset_name') or 'host'}",
        f"- tip: {ctx.get('asset_kind') or 'host'} · stack: {ctx.get('stack') or '—'}",
        f"- unit systemd: {ctx.get('systemd_unit') or 'niciunul'}",
        f"- container: {ctx.get('container_id') or 'nu rulează în container'}",
        f"- expus la internet: {'DA' if ctx.get('is_internet_exposed') else 'nu'}",
        f"- criticitate: {ctx.get('criticality') or 3}/5",
        "",
        "Sistem: AlmaLinux 9, pachete RPM prin dnf. Managerul de servicii e systemd.",
    ]
    if ctx.get("protected"):
        parts.append(
            "\nATENȚIE: asset-ul e marcat PROTEJAT. Validatorul respinge orice plan "
            "automat pentru el — spune asta în restore_instructions_ro și menține "
            "pașii minimi.")
    if errors:
        parts += [
            "",
            "ÎNCERCAREA ANTERIOARĂ A FOST RESPINSĂ DE VALIDATOR. Erori exacte:",
            *[f"  - {e}" for e in errors[:15]],
            "",
            "Corectează exact aceste erori. Nu schimba nimic altceva.",
        ]
    parts.append("\nApelează emit_patch_plan cu planul.")
    return "\n".join(parts)


async def generate(db: Database, cfg: Config, api_key: str,
                   finding_id: int) -> tuple[int | None, str]:
    """Generate, validate and store a plan for one finding.

    Returns (plan_db_id, status). Status is 'validated', 'rejected_invalid', or
    an error string. Never raises into the caller's loop.
    """
    ctx = await _context(db, finding_id)
    if ctx is None:
        return None, "finding inexistent"

    # A protected asset can never have an automated plan — the validator refuses
    # every one on principle. Discovering that after an Opus call costs real
    # money for a guaranteed rejection, so the gate belongs here, upstream.
    if ctx.get("protected"):
        log.info("skipping plan generation for protected asset",
                 extra={"finding": finding_id, "asset": ctx.get("asset_name")})
        return None, (f"asset protejat ({ctx.get('asset_name')}) — patch-urile "
                      "automate sunt interzise pentru el prin design; aplică manual")

    if not ctx.get("fixed_version"):
        return None, "nu se cunoaște o versiune care repară — nu există ce aplica"

    ok, reason = await budget.allowed(db, cfg)
    if not ok:
        return None, f"buget: {reason}"

    model = cfg.ai.model_patch
    errors: list[str] | None = None
    started = time.time()

    for attempt in range(1, MAX_ATTEMPTS + 1):
        result = await call_structured(
            api_key, model=model, system=PLANNER_SYSTEM,
            user=_build_user(ctx, errors), tool=_tool_schema(),
            max_tokens=8192, timeout=cfg.ai.timeout_s)
        await budget.record(
            db, purpose="patch_plan", model=model,
            input_tokens=result.usage.input_tokens,
            output_tokens=result.usage.output_tokens,
            cached_tokens=result.usage.cached_tokens,
            duration_ms=int((time.time() - started) * 1000))

        if not result.ok or result.tool_input is None:
            return None, f"model indisponibil: {result.error}"

        plan = result.tool_input
        validation = validate_plan(plan)
        if validation.valid:
            plan_db_id = await repo.store_plan(
                db, plan=plan, plan_hash=plan_hash(plan), status="validated",
                asset_id=ctx.get("asset_id"), finding_ids=[finding_id],
                generated_by="ai", model=model)
            log.warning("patch plan generated",
                        extra={"plan": plan_db_id, "finding": finding_id,
                               "attempt": attempt, "cve": ctx.get("cve")})
            return plan_db_id, "validated"

        errors = [f"{e.path}: {e.message}" for e in validation.errors]
        log.info("generated plan failed validation",
                 extra={"finding": finding_id, "attempt": attempt,
                        "errors": len(errors)})

    # Out of attempts. Stored anyway — an invalid plan is evidence about the
    # model and the prompt, and deleting it hides a pattern worth seeing.
    plan_db_id = await repo.store_plan(
        db, plan=plan, plan_hash=plan_hash(plan), status="rejected_invalid",
        asset_id=ctx.get("asset_id"), finding_ids=[finding_id],
        validation_errors=[{"path": e.path, "code": e.code, "message": e.message}
                           for e in validation.errors],
        generated_by="ai", model=model)
    log.error("patch plan rejected after retries",
              extra={"plan": plan_db_id, "finding": finding_id,
                     "errors": len(errors or [])})
    return plan_db_id, "rejected_invalid"


async def generate_for_kev(db: Database, cfg: Config, api_key: str,
                           limit: int = 3) -> list[tuple[int | None, str]]:
    """Draft plans for actively-exploited findings that have none yet.

    Only KEV, only with a known fix, only a few at a time: generation is the
    expensive model call in this system, and a plan for something nobody is
    exploiting can wait for a human to ask.
    """
    rows = await db.fetch(
        """
        SELECT f.id FROM findings f
        WHERE f.status = 'open' AND f.kev AND f.fixed_version IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM patch_plans p
              WHERE f.id = ANY(p.finding_ids)
                AND p.status IN ('validated','approved','applying','applied','scheduled')
          )
        ORDER BY f.priority DESC LIMIT $1
        """,
        limit)
    return [await generate(db, cfg, api_key, r["id"]) for r in rows]
