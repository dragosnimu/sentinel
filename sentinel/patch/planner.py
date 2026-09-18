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
from sentinel.constants import PATCH_BINARY_ALLOWLIST
from sentinel.db.engine import Database
from sentinel.db.repo import patches as repo
from sentinel.logging_setup import get_logger
from sentinel.patch.validator import (
    BACKUP_KIND_UNAVAILABLE_ON,
    CHECK_REQUIRED_FIELDS,
    PLATFORM_PACKAGE_BINARIES,
    plan_hash,
    validate_plan,
)

log = get_logger(__name__)

MAX_ATTEMPTS = 2

# Lista de statusuri „planul e încă viu" vine din `repo.LIVE_PLAN_STATUSES`, nu
# scrisă a doua oară aici: aceeași decizie e luată și de
# `repo.live_plan_for_finding`, pentru cererea manuală de pe Telegram. Două copii
# ar fi divergit, iar divergența ar fi fost invizibilă — una ar refuza o cerere
# pe care cealaltă o consideră necesară.
#
# Interpolare de text, nu parametru: rămâne o listă de literali constanți din
# cod (nimic din afară nu ajunge aici), iar forma `IN (...)` e chiar cea pe care
# `tests/unit/test_patch_planner_kev.py` o ia din interogarea reală și o rulează
# pe SQLite.
_LIVE_STATUS_LIST = ", ".join(f"'{status}'" for status in repo.LIVE_PLAN_STATUSES)

# Ecosistemul de pachete pe care planul îl poate CHIAR atinge, pe familie de
# distribuție — `platform.family` din configurație, scris de instalator.
#
# Măsurat pe gazda de producție pe 15 septembrie 2026: din 857 de findinguri
# deschise cu versiune care repară, 450 sunt `rpm` (scaner `dnf`) și 407 nu
# sunt — npm 185, alpine 82, go 80, composer 44, deb 16 — iar TOATE primele 12
# după prioritate sunt din a doua categorie. Cele 407 vin din `trivy_image`
# (conținutul unei imagini de container) și `trivy_fs` (lockfile-uri de
# aplicație): nu sunt pachete ale gazdei, iar reparația lor înseamnă
# reconstruirea imaginii sau `npm`/`composer` — binare pe care allowlist-ul
# executorului nu le mai conține (vezi docs/PATCHING.md §10, îngustat pe 8
# septembrie 2026). Un plan pentru ele nu poate exista, oricât de bun ar fi
# modelul: singurul final posibil e `rejected_invalid` sau un plan `dnf`
# plauzibil pentru un pachet Alpine, care pică la dry-run.
OS_PACKAGE_ECOSYSTEM: dict[str, str] = {"rhel": "rpm", "debian": "deb"}


def unplannable_reason(ecosystem: str | None, family: str) -> str | None:
    """Motivul pentru care findingul ăsta nu poate primi un plan pe gazda asta,
    sau `None` dacă poate. Determinist, fără bază de date și fără model — exact
    ca poarta de asset protejat din `generate`, și din același motiv: un refuz
    sigur nu merită două apeluri Opus.

    Funcție, nu o mulțime globală, fiindcă răspunsul depinde de gazdă: pe
    familia `rhel` se pot planifica pachete `rpm`, pe `debian` pachete `deb`.
    O familie necunoscută NU e tratată ca „probabil rpm" — „nu știu" și „e
    bine" sunt stări diferite, iar direcția sigură aici e refuzul.

    Textul întors e SIMPLU, fără marcaj: apelantul îl escapează și îl pune în
    mesajul lui (vezi `bot.cmd_planifica`). Un modul care nu vorbește cu
    Telegram n-are de unde ști în ce format e citit.
    """
    asteptat = OS_PACKAGE_ECOSYSTEM.get((family or "").strip().lower())
    if asteptat is None:
        return (f"gazda e declarată platform.family={family!r}, iar pentru "
                "familia asta nu se știe ce pachete poate atinge un plan — nu "
                "se cere unul pe ghicite")
    eco = (ecosystem or "").strip().lower()
    if not eco:
        return ("findingul nu spune din ce ecosistem e, deci nu se poate ști "
                "dacă e un pachet al gazdei — un plan cerut pe nesigur costă un "
                "apel la model ca să fie respins")
    if eco != asteptat:
        return (f"e o vulnerabilitate {eco}, nu un pachet al gazdei. Se pot "
                f"planifica doar pachetele de sistem {asteptat}: restul "
                "(conținut de container, lockfile-uri de aplicație) se repară "
                "reconstruind imaginea sau din depozitul aplicației, iar "
                "binarele alea nu sunt în allowlist-ul executorului "
                "(docs/PATCHING.md §10)")
    return None


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


def _binary_allowlist_doc(family: str) -> str:
    """The allowed binaries FOR THIS FAMILY, read from `sentinel.constants`
    and narrowed by `validator.PLATFORM_PACKAGE_BINARIES` — the same two
    tables the validator enforces.

    Written out by hand, this list had already drifted from
    `PATCH_BINARY_ALLOWLIST`: the prompt still named `httpd`, `wp`, `certbot`,
    `curl`... none of which the validator has allowed since the allowlist was
    narrowed for the executor work. A model told a binary is fine when the
    validator will reject it pays for a guaranteed second-attempt failure —
    generated from the one table the validator actually checks, the two
    cannot drift apart again.

    `PATCH_BINARY_ALLOWLIST` itself is platform-agnostic — it has no opinion
    on `dnf` vs `apt-get` — so listing it whole told a Debian host `dnf` and
    `rpm` were fine, and `validate_plan`'s own `platform_family` check then
    rejected them: the "guaranteed second-attempt failure" this function's
    docstring already promises to remove, reopened by omission. The OTHER
    family's package-manager binaries are subtracted here so the prompt never
    again offers a binary this host provably does not have.
    """
    other_families_binaries: set[str] = set()
    for fam, binaries in PLATFORM_PACKAGE_BINARIES.items():
        if fam != family:
            other_families_binaries |= binaries
    allowed = sorted(b for b in PATCH_BINARY_ALLOWLIST if b not in other_families_binaries)
    return ", ".join(allowed)


# `rpm_state` has no Debian equivalent — `BACKUP_KINDS` does not carry a
# `dpkg_state`, and the validator refuses `rpm_state` outright when
# `platform_family="debian"` (`BACKUP_KIND_UNAVAILABLE_ON` in validator.py).
# Teaching the model a kind the validator will then refuse is exactly the
# same class of drift `_binary_allowlist_doc` exists to prevent, for backup
# kinds instead of binaries.
def _backup_kind_doc(family: str) -> str:
    """Which backup kinds to teach, read from the validator's OWN table.

    This used to test `if family == "rhel"` in two places, which happened to
    agree with `BACKUP_KIND_UNAVAILABLE_ON` only because that table has
    exactly one entry and exactly two families exist. The moment a kind
    becomes unavailable on `rhel` too — or a third family appears — the
    hand-written condition would keep teaching a kind the validator refuses,
    which is the same drift-by-duplication the grammar had, spelled with an
    `if` instead of a regex.
    """
    unavailable = BACKUP_KIND_UNAVAILABLE_ON.get("rpm_state", frozenset())
    rpm_state_usable = family not in unavailable
    lines = ['    · `path`      → o cale absolută de fișier/director (ex. "/etc/nginx")']
    if rpm_state_usable:
        lines.append(
            '    · `rpm_state` → NUMELE PACHETULUI, nu o cale (ex. "curl"). Se salvează\n'
            '      versiunea instalată, ca rollback-ul să o poată fixa.')
    lines.append('    · `git_ref`   → calea depozitului git')
    doc = "\n".join(lines)
    if rpm_state_usable:
        doc += (
            '\n  Un `rpm_state` cu o cale (ex. "/var/lib/rpm") este RESPINS de validator:\n'
            '  `rpm -q` primește un nume de pachet, nu o cale, iar backup-ul ar eșua.')
    return doc


# What each platform family is called, and what "the boring update" looks like
# on it. Keyed exactly like `sentinel.constants.PLATFORM_FAMILIES` — nothing
# reaches `_render_system` with a family outside this dict, because
# `Config.platform.family` is refused at load time if it is not one of the two
# (`sentinel/config.py`), and `unplannable_reason` refuses to generate a plan
# for an ecosystem the family cannot own before the model is ever called.
#
# `update_example`/`apply_argv`/`rollback_argv` are the forms BOTH the
# validator and `executor/policy.py` accept — verified by
# `tests/security/test_plan_argvs_match_executor_policy.py`, which runs every
# argv in the plan fixtures through the executor's own `check_argv`. The
# debian pair used to be `apt-get -y install --only-upgrade <pachet>`, which
# the executor refuses (`--only-upgrade` is not on its flag list), together
# with a rollback that could only be `apt-get -y install <pachet>` — no
# version, so it reinstalled exactly the version the patch had just replaced.
# Both halves are now version-pinned, which is the only form apt has for
# going back: there is no `apt-get downgrade`.
_PLATFORM_PROMPT_FACTS: dict[str, dict[str, str]] = {
    "rhel": {
        "os_name": "AlmaLinux 9",
        "pkg_ecosystem": "pachete RPM prin dnf",
        "update_example": "dnf -y update <pachet>",
        "apply_argv": '["dnf", "-y", "update", "{pkg}"]',
        "rollback_argv": '["dnf", "-y", "downgrade", "{pkg}-{installed}"]',
    },
    "debian": {
        "os_name": "Debian/Ubuntu",
        "pkg_ecosystem": "pachete DEB prin apt-get",
        "update_example": "apt-get -y install <pachet>=<versiunea care repară>",
        "apply_argv": '["apt-get", "-y", "install", "{pkg}={fixed}"]',
        "rollback_argv":
            '["apt-get", "-y", "install", "--allow-downgrades", "{pkg}={installed}"]',
    },
}


def _update_recipe_doc(family: str) -> str:
    """Rețeta completă pentru un pachet de sistem, pe familia dată.

    Cele patru piese se țin una pe alta și de-aia sunt scrise împreună:
    preflight-ul fixează ce era instalat, apply-ul pune versiunea care repară,
    rollback-ul se întoarce la EXACT ce a văzut preflight-ul, iar
    post_verification confirmă efectul. Fără preflight, rollback-ul s-ar putea
    fixa pe o versiune pe care gazda n-a avut-o niciodată — de aceea nu e
    decor.
    """
    facts = _PLATFORM_PROMPT_FACTS[family]
    apply_argv = facts["apply_argv"].format(
        pkg="<pachet>", fixed="<versiunea care repară>", installed="<versiunea instalată>")
    rollback_argv = facts["rollback_argv"].format(
        pkg="<pachet>", fixed="<versiunea care repară>", installed="<versiunea instalată>")
    lines = [
        "REȚETA pentru un pachet de sistem — folosește-o ca atare, cele patru",
        "piese se sprijină una pe alta:",
        "  · preflight:         pkg_version {name: <pachet>, equals: <versiunea instalată>}",
        f"  · apply:             {apply_argv}",
        f"  · rollback:          {rollback_argv}",
        "  · post_verification: pkg_version {name: <pachet>, at_least: <versiunea care repară>}",
        "Preflight-ul NU e formalitate: dacă versiunea de pe gazdă nu e cea din",
        "contextul de mai sus, rollback-ul s-ar fixa pe o versiune greșită, deci",
        "planul trebuie să se oprească înainte să schimbe ceva.",
    ]
    if family == "debian":
        lines += [
            "Versiunea e OBLIGATORIE în ambele comenzi: `apt-get` nu are `downgrade`,",
            "iar `install <pachet>` fără `=versiune` reinstalează chiar versiunea",
            "vulnerabilă. Din același motiv `--allow-downgrades` e acceptat DOAR cu",
            "`install` și DOAR cu `=versiune` pe fiecare pachet; `--only-upgrade` nu",
            "e acceptat deloc.",
        ]
    lines += [
        "ONEST, și spune-o în `restore_instructions_ro`: un rollback fixat pe",
        "versiune poate totuși eșua la rulare dacă acea versiune nu mai există în",
        "depozit (arhivele curăță versiunile vechi). E mult mai bun decât unul care",
        "sigur nu restaurează nimic, dar nu e o garanție — nu-l prezenta ca atare.",
    ]
    return "\n".join(lines)

# The template, not yet rendered: still carries `%%...%%` placeholders for
# everything that depends on the host (family) or on another module's table
# (the check-kind fields, the binary allowlist). `PLANNER_SYSTEM` below is this
# template rendered for `rhel`, kept as a plain string because
# `tests/unit/test_patch_validator.py` imports it directly to prove the
# check-kind fields and the substitution both hold — `generate()` itself calls
# `_render_system(cfg.platform.family)` and never reads this name.
_PLANNER_SYSTEM_TEMPLATE = """\
Ești inginerul de patch-uri al agentului Sentinel, pe un server %%OS_NAME%%.
Primești o vulnerabilitate confirmată și contextul ei determinist, și produci un
plan de remediere care va fi executat AUTOMAT, ca root, pe o mașină de producție.

REGULI ABSOLUTE — un plan care le încalcă este respins de validator, nu discutat:

1. Fiecare comandă este o listă `argv`, niciodată un șir. Fără shell, fără `|`,
   `&&`, `;`, `$(...)`, fără redirectări. Dacă ai nevoie de shell, planul e greșit.
2. Primul element al fiecărui argv trebuie să fie un binar din lista permisă:
   %%BINARY_LIST%%.
   `rm` NU este permis. Nu ștergi nimic, niciodată.
   `systemctl` cere NUMELE COMPLET al unității — `nginx.service`, nu `nginx` —
   și doar acțiunile start/stop/restart/reload/status.
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
- `vulnerabilities`: un array cu cel puțin un obiect — poate fi `[{}]`. Conținutul
  lui e IGNORAT: după ce răspunzi, e înlocuit automat cu finding_id, cve, package
  și severitatea citite din baza de date, aceleași pe care le-ai primit mai jos
  în context. Nu inventa aici un CVE sau un finding_id — dacă mai sus scrie
  „CVE: —", findingul chiar nu are unul, iar planul e verificat contra
  identificatorului cerut, nu contra a ce pui tu în acest câmp.
- `risk`: {level: "low|medium|high|critical", blast_radius:
  "single-service|multi-service|host-wide", reversible: <bool>,
  requires_reboot: <bool>, estimated_downtime_s: <int>, confidence: <0..1>}
- `backup`: [{id, desc_ro, kind, source, restore_argv: [...], estimated_size_mb}]
  unde `source` depinde de `kind`:
%%BACKUP_KIND_DOC%%
- `restore_instructions_ro`: text
Folosește exact valorile din contextul primit pentru asset_id și asset_name —
nu le inventa. (finding_id, cve, package: vezi mai sus — sunt suplinite automat.)

Preferă soluția cea mai plictisitoare care funcționează. Pe %%OS_NAME%%, aproape
întotdeauna asta înseamnă `%%UPDATE_EXAMPLE%%` plus repornirea unității,
nu o secvență inteligentă. Nu inventa pași. Nu presupune fișiere pe care nu ți
le-am arătat.

%%UPDATE_RECIPE%%

Răspunde DOAR prin apelul tool-ului `emit_patch_plan`."""


def _render_system(family: str) -> str:
    """Render the planner's system prompt for one platform family.

    The prompt used to say "AlmaLinux 9" as a literal, independent of what
    `cfg.platform.family` actually held — correct for every host that existed
    when it was written, and silently wrong the day a Debian host joined the
    fleet: `unplannable_reason` correctly gated WHICH findings could get a
    plan by family, then this text told the model it was somewhere it was not,
    and it drafted `dnf` commands for a `deb` finding on Ubuntu. Substituted,
    not f-stringed: the template is full of literal `{...}` describing the
    JSON shape, and an f-string would try to interpolate every one of them.
    """
    facts = _PLATFORM_PROMPT_FACTS.get(family)
    if facts is None:
        raise ValueError(
            f"no prompt facts for platform.family={family!r} — Config already "
            "refuses an unknown family at load time, so reaching this means "
            "_PLATFORM_PROMPT_FACTS has drifted from "
            "sentinel.constants.PLATFORM_FAMILIES"
        )
    text = _PLANNER_SYSTEM_TEMPLATE
    text = text.replace("%%OS_NAME%%", facts["os_name"])
    text = text.replace("%%UPDATE_EXAMPLE%%", facts["update_example"])
    text = text.replace("%%BINARY_LIST%%", _binary_allowlist_doc(family))
    text = text.replace("%%CHECK_FIELDS%%", _check_fields_doc())
    text = text.replace("%%BACKUP_KIND_DOC%%", _backup_kind_doc(family))
    text = text.replace("%%UPDATE_RECIPE%%", _update_recipe_doc(family))
    return text


# The `rhel` rendering, importable as a plain string. Kept for
# `tests/unit/test_patch_validator.py`, which checks the check-kind fields and
# the placeholder substitution against a fixed string; `generate()` below does
# not read this name; it calls `_render_system(cfg.platform.family)`.
PLANNER_SYSTEM = _render_system("rhel")


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


def _exact_commands(ctx: dict[str, Any], facts: dict[str, str]) -> list[str]:
    """Cele două comenzi, scrise cu valorile REALE din baza de date.

    Șablonul de sistem descrie forma cu `<pachet>`/`<versiune>`; aici sunt
    chiar valorile pe care le-a citit `_context`, ca modelul să nu aibă de
    compus un nume de pachet cu o versiune — exact locul unde a inventat până
    acum.

    Dacă versiunea instalată lipsește din finding, rollback-ul fixat pe
    versiune NU se poate scrie: nu se ghicește una, se spune că nu există și
    se cere `reversible: false`. „Nu știu" și „e bine" sunt stări diferite, iar
    un rollback ghicit ar fixa o versiune pe care gazda n-a avut-o niciodată.
    """
    pkg = ctx.get("package")
    installed = ctx.get("installed_version")
    fixed = ctx.get("fixed_version")
    if not pkg or not fixed:
        return []
    out = ["", "Comenzile exacte pentru acest pachet (valorile sunt din baza de "
                "date — folosește-le ca atare, nu le rescrie):",
           f"- apply:    {facts['apply_argv'].format(pkg=pkg, fixed=fixed, installed=installed)}"]
    if installed:
        out += [
            f"- rollback: {facts['rollback_argv'].format(pkg=pkg, fixed=fixed, installed=installed)}",
            f"- preflight `pkg_version`: {{name: \"{pkg}\", equals: \"{installed}\"}}",
            f"- post_verification `pkg_version`: {{name: \"{pkg}\", at_least: \"{fixed}\"}}",
        ]
    else:
        out += [
            "- rollback: NU se poate fixa pe o versiune — findingul nu spune ce "
            "versiune e instalată acum. Pune `risk.reversible: false` și explică "
            "în `restore_instructions_ro` ce trebuie făcut manual; nu inventa o "
            "versiune de revenire.",
        ]
    return out


def _build_user(ctx: dict[str, Any], family: str, errors: list[str] | None = None) -> str:
    facts = _PLATFORM_PROMPT_FACTS[family]
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
        f"Sistem: {facts['os_name']}, {facts['pkg_ecosystem']}. Managerul de "
        "servicii e systemd.",
    ]
    parts += _exact_commands(ctx, facts)
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
                   finding_id: int, *, generated_by: str = "ai") -> tuple[int | None, str]:
    """Generate, validate and store a plan for one finding.

    Returns (plan_db_id, status). Status is 'validated', 'rejected_invalid', or
    an error string. Never raises into the caller's loop.

    `generated_by` records WHO asked, not who drafted — the model drafts either
    way. It defaults to `'ai'`, which is what `generate_for_kev` stores and what
    `unnotified_plans` holds back from the fast approval channel until
    `sentinel-patch-window` releases it (see `0043_patch_window.sql`). A plan the
    operator asked for by name is not unattended model output: it is attended by
    definition, it goes straight back to the chat that asked, and the same
    migration says so — "bucla rapidă oferă BUTONUL DE APROBARE direct pentru
    planurile care NU vin de la planner-ul automat". Passing a different value is
    how that path finally exists.
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
    family = cfg.platform.family
    system_prompt = _render_system(family)
    # The facts this plan is ABOUT, read from the database — the standard the
    # validator holds the model's own output to. Built once, from the same
    # `ctx` the model was shown, never from anything the model returns.
    finding_facts = {
        "finding_id": finding_id,
        "cve": ctx.get("cve"),
        "package": ctx.get("package"),
    }
    errors: list[str] | None = None
    started = time.time()

    for attempt in range(1, MAX_ATTEMPTS + 1):
        result = await call_structured(
            api_key, model=model, system=system_prompt,
            user=_build_user(ctx, family, errors), tool=_tool_schema(),
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
        if isinstance(plan, dict):
            # `vulnerabilities` is not the model's to invent. A model asked
            # for an identifier it does not have will produce one — measured
            # in production as `finding_id: 0` and `CVE-0000-00000`, both
            # schema-valid — so it is never asked: whatever it drafted here is
            # replaced with the same deterministic facts `_build_user` showed
            # it, straight from `ctx`. The validator's `finding=` check below
            # is the second, independent gate on the same facts — this
            # overwrite is not trusted to be the only thing standing between a
            # fabricated identifier and a stored plan.
            # `cvss`/`epss` are deliberately NOT carried into the plan.
            # `findings.cvss` and `findings.epss` are `numeric(3,1)` /
            # `numeric(5,4)` (0003_vuln.sql), and asyncpg has no codec
            # configured for `numeric` anywhere in this project, so `ctx`
            # holds them as `decimal.Decimal` — a type `json.dumps` refuses.
            # `plan_hash()` and `repo.store_plan` both serialise this dict to
            # JSON, so a scored finding (the normal case, not the edge case)
            # would crash plan generation right here. Nothing reads
            # `cvss`/`epss` back off a stored plan — `patch_flow.py` and the
            # validator only ever look at `cve`/`ecosystem`/`package` — so
            # there is no value in carrying a type hazard for a field nobody
            # consumes. The finding's own `cvss`/`epss` remain visible
            # wherever the operator actually reads them: the finding row
            # itself (`telegram/views.py`), not a copy inside the plan.
            plan["vulnerabilities"] = [{
                "finding_id": finding_id,
                "cve": ctx.get("cve"),
                "kev": bool(ctx.get("kev")),
                "package": ctx.get("package"),
                "current": ctx.get("installed_version"),
                "fixed_in": ctx.get("fixed_version"),
                "severity": ctx.get("severity"),
                # Not validated, not required — carried through so
                # `telegram/patch_flow.py` can pick the right advisory link
                # (Red Hat only makes sense for an `rpm` finding) without
                # guessing from the host it happens to run on.
                "ecosystem": ctx.get("ecosystem"),
            }]
        validation = validate_plan(plan, platform_family=family, finding=finding_facts)
        if validation.valid:
            plan_db_id = await repo.store_plan(
                db, plan=plan, plan_hash=plan_hash(plan), status="validated",
                asset_id=ctx.get("asset_id"), finding_ids=[finding_id],
                generated_by=generated_by, model=model)
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
        generated_by=generated_by, model=model)
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

    Și numai pentru ecosistemul pe care familia gazdei îl poate CHIAR atinge.
    `/planifica` trecea prin `unplannable_reason` de la început; bucla asta nu,
    deci pe gazda Debian cerea planuri pentru findinguri npm/alpine/go — două
    apeluri Opus fiecare, toate terminate în `rejected_invalid`, sau, mai rău,
    un plan `apt-get` plauzibil pentru un pachet dintr-o imagine de container.

    Filtrul e în SQL, nu după `LIMIT`: pe gazda de producție TOATE primele 12
    findinguri KEV după prioritate sunt din ecosisteme pe care gazda nu le
    poate atinge (vezi comentariul de la `OS_PACKAGE_ECOSYSTEM`), deci o
    filtrare de după selecție ar consuma cele trei sloturi pe rânduri
    imposibile și n-ar mai genera niciodată nimic. `unplannable_reason` rămâne
    poarta finală pe fiecare rând rămas — o singură decizie, luată într-un
    singur loc, chiar dacă interogarea ar fi cândva slăbită.
    """
    family = cfg.platform.family
    expected = OS_PACKAGE_ECOSYSTEM.get((family or "").strip().lower())
    if expected is None:
        # Familie necunoscută: nu se ghicește „probabil rpm". Același refuz ca
        # în `unplannable_reason`, doar că aici nu există un finding anume
        # despre care să se raporteze.
        log.warning("no KEV plans drafted: unknown platform family",
                    extra={"family": family})
        return []

    rows = await db.fetch(
        f"""
        SELECT f.id, f.ecosystem FROM findings f
        WHERE f.status = 'open' AND f.kev AND f.fixed_version IS NOT NULL
          AND lower(trim(f.ecosystem)) = $1
          AND NOT EXISTS (
              SELECT 1 FROM patch_plans p
              WHERE f.id = ANY(p.finding_ids)
                AND p.status IN ({_LIVE_STATUS_LIST})
          )
        ORDER BY f.priority DESC LIMIT $2
        """,
        expected, limit)

    results: list[tuple[int | None, str]] = []
    for r in rows:
        reason = unplannable_reason(r["ecosystem"], family)
        if reason is not None:
            log.info("KEV finding skipped as unplannable on this host",
                     extra={"finding": r["id"], "ecosystem": r["ecosystem"]})
            results.append((None, reason))
            continue
        results.append(await generate(db, cfg, api_key, r["id"]))
    return results
