"""Ce citește operatorul despre o actualizare de sistem — funcții pure, fără rețea și fără bază.

Două reguli de vocabular, păstrate aici fiindcă aici se scrie textul:

  * **«instalat», niciodată «actualizat»** pentru un pachet. `rpm` dovedește că versiunea e
    pe disc; nu dovedește că procesele care o folosesc o rulează. Un daemon pornit înainte de
    instalare rulează codul vechi până la restart, iar nucleul până la repornire. Fraza
    «actualizat» ar afirma exact ce nu s-a verificat (CLAUDE.md: confirmarea intenției în
    locul efectului).
  * **Ce s-a citit și ce NU s-a putut citi, pe rânduri separate.** «Serviciile nu au fost
    verificate» e o propoziție, nu o lipsă: tăcerea ar fi citită ca «sunt bine».

Nimic de aici nu cheamă runnerul, nu aprobă și nu înregistrează un plan: modulul doar scrie
text (un test o ține). Aplicarea rămâne `patch_flow`.
"""

from __future__ import annotations

import html
from typing import Any

from sentinel.patch import system_update as su

#: Cât din lista de pachete se arată într-un mesaj. Un lot are cel mult câteva zeci, dar un
#: mesaj Telegram are 4096 de caractere și textul planului trebuie să încapă înaintea
#: butoanelor.
MAX_LISTED = 12

#: Etichetele motivelor de reținere, în română. Codul vine din `system_update`; un cod pe care
#: nu-l cunosc se arată ca atare, nu se ascunde.
HELD_LABELS: dict[str, str] = {
    "install_only": "install-only (nucleu): fără cale de întoarcere, deci poarta îl refuză",
    "manual_only": "doar manual (docs/PATCHING.md §8)",
    "epoch_changed": "epoch diferit între instalat și reparație (alt depozit sau altă serie)",
    "multiple_versions": "mai multe versiuni instalate deodată",
    "validator": "respins de validator",
    "too_big": "nu încape într-un plan",
    "not_installed": "nu e instalat",
    "protected_asset": "asset protejat",
    "bad_name": "nume neacceptat",
    "foreign": "nu e un pachet al gazdei",
}


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _clip(value: Any, limit: int) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _fit(lines: list[str], limit: int) -> str:
    """Lipește liniile, scoțând LINII ÎNTREGI de la coadă cât depășește `limit`.

    Un mesaj peste 4096 de caractere nu se livrează deloc, iar o tăietură la mijlocul unui
    `<code>` îl face ilizibil pentru Telegram («can't parse entities»): fiecare element al
    listei e HTML închis, deci a-l scoate întreg păstrează restul valid."""
    out = list(lines)
    while len("\n".join(out)) > limit and len(out) > 1:
        out.pop()
    if len(out) < len(lines):
        out.append("<i>…(restul nu încape în mesaj)</i>")
    return "\n".join(out)


def is_update(plan: Any) -> bool:
    return isinstance(plan, dict) and su.update_meta(plan) is not None


def _names(names: list[str], limit: int = 8) -> str:
    shown = ", ".join(f"<code>{_esc(n)}</code>" for n in names[:limit])
    return shown + (f" …+{len(names) - limit}" if len(names) > limit else "")


def held_lines(held: list[su.Held]) -> list[str]:
    out: list[str] = []
    for h in held:
        label = HELD_LABELS.get(h.code, h.code)
        line = f"• {_names(h.packages)} — {_esc(label)}"
        # Mesajul validatorului e ce nu se poate ghici din cod: se arată.
        if h.code == "validator":
            line += f"\n   <i>{_esc(h.reason[:300])}</i>"
        out.append(line)
    return out


def _reports(sel: su.Selection) -> list[str]:
    lines: list[str] = []
    if sel.covered:
        lines.append("<b>Deja într-un plan deschis</b> (nu primesc al doilea): " + ", ".join(
            f"<code>{_esc(p)}</code> (#{pid}, {_esc(st)})" for p, pid, st in sel.covered[:8]))
    if sel.already:
        parts = []
        for name, version, reboot in sel.already[:8]:
            tail = " — instalat, așteaptă repornire" if reboot else " — instalat"
            parts.append(f"<code>{_esc(name)}</code> {_esc(version)}{tail}")
        lines.append("<b>Reparația e deja pe disc:</b> " + "; ".join(parts)
                     + "\n<i>Constatarea se închide la scanarea următoare. Dacă procesele care "
                       "folosesc pachetul rulează încă versiunea veche nu pot verifica de aici.</i>")
    if sel.pending_reboot:
        lines.append("<b>Instalat, așteaptă repornire</b> (verdictul scanării): " + _names(sel.pending_reboot)
                     + "\n<i>Un plan n-ar schimba nimic; o repornire o aplică. Sentinel nu repornește nimic.</i>")
    return lines


def selection_text(sel: su.Selection, *, only: str | None = None,
                   category_note: str | None = None,
                   previous: tuple[int, str] | None = None) -> str:
    """Mesajul care precede planul (sau care ține locul lui, când nu e niciun plan).

    `previous` = ultimul plan de update încheiat, `(id, stare)`. Dacă a eșuat sau a revenit, se
    spune ÎNAINTE de orice altceva: comanda propune un lot nou la cererea operatorului, iar un lot
    nou, oferit imediat după unul căzut, arată ca o continuare firească a unei gazde pe care
    nimeni n-a recitit-o."""
    lines: list[str] = []
    if previous is not None and previous[1] in ("failed", "rolled_back"):
        lines += [f"⚠️ <b>Ultimul lot (#{previous[0]}) a ieșit <code>{_esc(previous[1])}</code>.</b> "
                  "Citește-i rezultatul și starea reală a pachetelor înainte să aprobi altul — "
                  "comanda nu se oprește singură.", ""]
    if sel.lots:
        lot = sel.lots[0]
        rest = sum(len(other.packages) for other in sel.lots[1:])
        what = f"<code>{_esc(only)}</code> și ce se mișcă împreună cu el" if only else "sistem"
        lines.append(f"📦 <b>Actualizare ({what}) — lotul {lot.number} din {len(sel.lots)}</b> · "
                     f"{len(lot.packages)} pachete")
        lines.append("<i>Un lot = un plan = o singură tranzacție de pachete. Se aplică pe rând: "
                     "după ce se termină, îl propun pe următorul"
                     + (f" ({rest} pachete rămase)" if rest else "") + ".</i>")
    else:
        what = f"pentru <code>{_esc(only)}</code>" if only else "de sistem"
        lines.append(f"📦 <b>Nicio actualizare {what} de propus acum.</b>")

    held = held_lines(sel.held)
    if held:
        lines += ["", "<b>Reținute — nu le propun, și de ce:</b>", *held[:10]]
        if len(held) > 10:
            lines.append(f"<i>…și încă {len(held) - 10} grupuri</i>")
    reports = _reports(sel)
    for report in reports:
        lines += ["", report]
    if only and not sel.lots and not held and not reports:
        # Fără niciun motiv în mână, un răspuns gol s-ar citi ca «nu e nimic de făcut».
        lines += ["", f"<code>{_esc(only)}</code> nu are nicio constatare deschisă cu reparație în baza de "
                      "date (sau nu e un pachet al gazdei). Un update fără constatare nu se propune de "
                      "aici: planul n-ar avea o versiune țintă de verificat."]
    if category_note:
        lines += ["", category_note]
    return _fit(lines, 3800)


def plan_lines(plan: dict[str, Any]) -> list[str]:
    """Rândurile pe care `patch_flow.format_plan` le adaugă pentru un plan de update."""
    meta = su.update_meta(plan)
    if meta is None:
        return []
    pkgs = [p for p in meta["packages"] if isinstance(p, dict)]
    lines = [f"📦 <b>Actualizare de sistem</b> · lotul {meta.get('lot', '?')}/{meta.get('lots', '?')} · "
             f"{len(pkgs)} pachete, <b>o singură tranzacție</b>"]
    for p in pkgs[:MAX_LISTED]:
        mark = " 🔄" if p.get("reboot") else ""
        lines.append(f"• <code>{_esc(_clip(p.get('name'), 60))}</code> {_esc(_clip(p.get('before'), 40))} → "
                     f"{_esc(_clip(p.get('target'), 40))}{mark}")
    if len(pkgs) > MAX_LISTED:
        lines.append(f"<i>…și încă {len(pkgs) - MAX_LISTED}</i>")
    lines.append("")
    lines.append("⚠️ <b>Ce NU se verifică:</b> serviciile. După instalare, un proces pornit "
                 "înainte rulează încă codul vechi până la restart. Verificarea de sănătate "
                 "doar citește baza de date de pachete.")
    lines.append("🔔 <b>Așteaptă-te la alerte</b> <code>unit_change</code> (critice): <code>rpm</code> scrie "
                 "fișiere de unitate sub /usr/lib/systemd/system, iar regula nu are filtru de "
                 "sesiune (observat pe producție la o rulare manuală a lui dnf, cu procesul "
                 "python3.9). Sentinel nu le suprimă; la sfârșit îți arată ce a apărut cât a rulat.")
    return lines


def reboot_warning(plan: dict[str, Any]) -> str:
    """Textul din a doua atingere pentru un plan cu pachete care cer repornire.

    Pentru un plan de update, «serverul va reporni» ar fi FALS: Sentinel nu repornește nimic."""
    return ("\n⚠️ <b>Conține pachete care cer REPORNIRE</b> — Sentinel NU repornește serverul. "
            "După instalare vei vedea «instalat, așteaptă repornire», iar repornirea o faci tu.")


# ---------------------------------------------------------------------------
# Starea reală, după rulare
# ---------------------------------------------------------------------------
def _state_line(s: su.PkgState) -> str:
    name = f"<code>{_esc(s.name)}</code>"
    if s.state == su.STATE_TARGET:
        tail = " — instalat, <b>așteaptă repornire</b>" if s.reboot else " — instalat"
        return f"✅ {name} {_esc(s.now)}{tail}"
    if s.state == su.STATE_UNCHANGED:
        return f"↩️ {name} {_esc(s.now)} — neschimbat (cum era înainte)"
    if s.state == su.STATE_OTHER:
        return (f"⚠️ {name} {_esc(s.now)} — stare intermediară (înainte {_esc(s.before)}, "
                f"cerut {_esc(s.target)})")
    return f"❔ {name} — nu s-a putut citi"


def addendum(states: list[su.PkgState], status: str, *, read_error: str | None,
             detections: list[dict[str, Any]] | None, detections_error: str | None = None,
             budget: int = 1800) -> str:
    """Ce adaugă `patch_flow` la rezultatul unei aplicări de update.

    `status` e al runnerului (`succeeded`, `failed`, `rolled_back`, `rollback_failed`,
    `aborted`). Aici nu se corectează: se pune alături ce a citit gazda, iar dacă cele două
    nu sunt de acord, se spune.

    `budget` = câte caractere mai încap în mesajul Telegram după textul runnerului. Concluziile
    se scriu ÎNTÂI și nu se taie niciodată; lista pe pachete e ce se scurtează, cu un rând
    care spune câte lipsesc — un mesaj peste 4096 de caractere nu se livrează deloc.
    """
    head = ["", "<b>Starea reală a pachetelor</b> <i>(citită de pe gazdă după rulare, nu raportată de executor)</i>"]
    tail: list[str] = []
    state_lines: list[str] = []

    if read_error is not None:
        tail.append(f"❔ Nu am putut citi starea pachetelor: {_esc(read_error)}. Verifică cu "
                    "<code>rpm -q &lt;pachet&gt;</code> înainte de orice altă acțiune.")
    else:
        state_lines = [_state_line(s) for s in states]
        done = [s for s in states if s.state == su.STATE_TARGET]
        untouched = [s for s in states if s.state == su.STATE_UNCHANGED]
        if status == "succeeded":
            if len(done) == len(states):
                tail.append(f"<b>rpm confirmă:</b> toate cele {len(states)} pachete sunt instalate la "
                            "versiunea cerută sau mai nouă.")
            else:
                bad = ", ".join(s.name for s in states if s.state != su.STATE_TARGET)
                tail.append("⚠️ <b>Executorul a raportat succes, dar rpm NU confirmă</b> pentru: "
                            f"{_esc(bad)}. Nu te baza pe mesajul de sus.")
        elif len(untouched) == len(states):
            tail.append("<b>rpm confirmă:</b> toate pachetele sunt la versiunea de dinainte — "
                        "nu e nimic de restaurat, oricum ar suna starea de mai sus.")
        elif done and len(done) < len(states):
            tail.append("⚠️ <b>Stare mixtă:</b> unele pachete sunt la versiunea nouă, altele nu. "
                        "Decide tu, cu starea de mai sus în față.")
        elif done:
            tail.append("⚠️ Pachetele sunt la versiunea nouă, deși execuția n-a ieșit "
                        f"<code>succeeded</code> ({_esc(status)}).")

        if status == "succeeded" and done:
            pending = [s.name for s in done if s.reboot]
            if pending:
                tail.append("🔄 <b>Așteaptă repornire:</b> " + ", ".join(f"<code>{_esc(n)}</code>" for n in pending)
                            + ". Sentinel nu repornește nimic.")
            tail.append("<i>Serviciile care folosesc aceste pachete NU au fost verificate: un proces "
                        "pornit înainte de instalare rulează încă codul vechi până la restart. "
                        "<code>needs-restarting -s</code> (ca root) spune care.</i>")

    if detections_error is not None:
        tail.append(f"🔔 Nu am putut citi detecțiile din timpul execuției: {_esc(detections_error)}.")
    elif detections:
        total = sum(int(d.get("count", 0)) for d in detections)
        parts = []
        for d in detections[:5]:
            rule = str(d.get("rule_id", "?")).removeprefix("intrusion.")
            procs = ", ".join(d.get("processes") or []) or "proces necunoscut"
            parts.append(f"{_esc(rule)} ×{d.get('count')} ({_esc(d.get('severity'))}; {_esc(procs)})")  # noqa: RUF001
        tail.append(f"🔔 <b>{total} detecții grave</b> au apărut cât a rulat execuția: " + "; ".join(parts)
                    + ".\n<i>Sunt urma tranzacției DOAR dacă procesul numit e cel al managerului de "
                      "pachete (rpm, python3.9 = dnf). Sentinel nu le-a suprimat: verifică înainte să le închizi.</i>")

    fixed = len("\n".join(head)) + len("\n".join(["", *tail]))
    room = max(0, budget - fixed)
    shown: list[str] = []
    used = 0
    for line in state_lines:
        if used + len(line) + 1 > room:
            break
        shown.append(line)
        used += len(line) + 1
    if len(shown) < len(state_lines):
        shown.append(f"<i>…și încă {len(state_lines) - len(shown)} pachete (nu încap în mesaj)</i>")
    return "\n".join([*head, *shown, "", *tail])


# ---------------------------------------------------------------------------
# /update fără argument
# ---------------------------------------------------------------------------
def overview_text(*, categories: list[Any], sel: su.Selection | None, scanner: str,
                  open_plans: list[tuple[int, str]]) -> str:
    """Ce e actualizabil, pe categorii, cu cifre. `categories` vin din `system_update.category_counts`."""
    lines = ["📦 <b>Actualizări</b> — ce e deschis acum <i>(citit din baza de date; nu s-a pornit nimic)</i>", ""]
    for cat in categories:
        if cat.kind == "os":
            lines.append(f"<b>Sistem de operare</b> ({_esc(scanner)}): {cat.open_total} constatări "
                         f"deschise, {cat.with_fix} cu reparație")
            if sel is None:
                lines.append("   <i>ce se poate actualiza din ele nu s-a calculat</i>")
            elif sel.error:
                lines.append(f"   ❔ Nu pot spune ce se poate actualiza: {_esc(sel.error)}")
            else:
                planned = sum(len(lot.packages) for lot in sel.lots)
                held = sum(len(h.packages) for h in sel.held)
                lines.append(f"   • de actualizat: <b>{planned}</b> pachete"
                             + (f", în {len(sel.lots)} loturi (unul odată)" if sel.lots else ""))
                if sel.held:
                    lines.append(f"   • reținute: <b>{held}</b> pachete — motivul, la <code>/update sistem</code>")
                    for line in held_lines(sel.held)[:4]:
                        lines.append("      " + line)
                if sel.already or sel.pending_reboot:
                    lines.append(f"   • instalate, așteaptă repornire sau scanare: "
                                 f"<b>{len(sel.already) + len(sel.pending_reboot)}</b> pachete")
                if sel.covered:
                    lines.append(f"   • deja într-un plan deschis: <b>{len(sel.covered)}</b>")
        else:
            lines.append(f"<b>{_esc(cat.label.capitalize())}</b>: {cat.open_total} constatări deschise, "
                         f"{cat.with_fix} cu reparație — <i>nu se actualizează de aici</i>")
    if open_plans:
        pid, status = open_plans[0]
        lines += ["", f"⏳ Ai deja planul <b>#{pid}</b> (<code>{_esc(status)}</code>): "
                      f"<code>/patch {pid}</code>. Cât e deschis, nu propun altul."]
    lines += ["",
              "<code>/update sistem</code> — propune următorul lot de pachete de sistem",
              "<code>/update tot</code> — ca mai sus, plus ce nu se poate actualiza de aici",
              "<code>/update &lt;pachet&gt;</code> — un pachet, cu ce se mișcă împreună cu el"]
    return _fit(lines, 3900)


def other_categories_note(categories: list[Any]) -> str | None:
    """Ce NU se poate actualiza de aici, cu cifrele din baza de date — spus pe față, ca un
    `/update tot` care a propus doar pachetele de sistem să nu pară că a acoperit tot."""
    parts = [f"{_esc(c.label)}: {c.with_fix} constatări cu reparație" for c in categories
             if c.kind != "os" and c.with_fix]
    if not parts:
        return None
    return ("<b>Nu se actualizează de aici:</b> " + "; ".join(parts)
            + ". <i>Imaginile de container și dependențele aplicațiilor se repară reconstruind "
              "imaginea sau din depozitul aplicației, cu binare pe care executorul nu le are.</i>")
