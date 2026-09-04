"""Expeditorul de loturi către agregatorul extern.

Testul care contează în fișierul ăsta e cel despre ECOU. Un expeditor care
avansează cursorul pe HTTP 200 pierde rânduri definitiv și în tăcere: un edge
CDN, un vhost greșit rutat și un agregator care ignoră un flux necunoscut
răspund toate 200, cursorul trece peste rânduri care n-au ajuns nicăieri, și
nimeni nu poate observa lipsa — nici pe server, unde cursorul spune „trimis",
nici pe agregator, unde nimeni nu știe ce trebuia să fie acolo.

Restul fișierului păzește lucrurile fără de care regula aia n-ar avea efect:
că un lot netrimis nu consumă un număr de lot, că filigranul e ultimul rând DIN
LOT și nu capul tabelei, și că pragul de backfill se aplică o singură dată, la
prima rundă, nu de fiecare dată când agregatorul e în pană.
"""
from __future__ import annotations

import ast
import asyncio
import inspect
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ipaddress import ip_address

import re

import pytest

from sentinel.report import shipper

NOW = datetime.now(timezone.utc)

#: Inceputul lumii, ca in `to_timestamp(0)`. Cursorul unui flux de
#: agregate porneste de acolo: un contor orar are putine randuri, iar
#: istoricul lui e chiar ce vrea panoul.
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _hour_floor(moment):
    """`date_trunc('hour', …)`, ca in SQL."""
    return moment.replace(minute=0, second=0, microsecond=0)
ID_A = "0123456789abcdef0123456789abcdef"


def run(c):
    return asyncio.run(c)


def _row(id_: int, minutes_ago: float = 1.0, **over):
    """Un rând de audit ca cel pe care îl întoarce asyncpg."""
    row = {
        "id": id_,
        "at": NOW - timedelta(minutes=minutes_ago),
        "actor": "telegram:1",
        "source": "telegram",
        "operation": "block",
        "target": "192.0.2.10",
        # jsonb sosește din asyncpg ca TEXT, și așa pleacă.
        "params": '{"ip":"192.0.2.10"}',
        "result": "ok",
        "detail": None,
        "prev_hash": f"{id_ - 1:064d}",
        "entry_hash": f"{id_:064d}",
    }
    row.update(over)
    return row


# Valorile pe care le poate lua `pg_trigger.tgenabled`. `'R'` se declanșează DOAR
# pe o sesiune cu `session_replication_role = 'replica'`, deci pe una obișnuită e
# tot „prezent și fără efect" — la fel ca `'D'`.
TRIGGER_STATES = ("O", "A", "D", "R")


def _accepted_trigger_states(sql: str) -> set[str]:
    """Ce valori ale lui `tgenabled` lasă interogarea să treacă, citite din EA.

    Dubla trebuie să se poarte după filtrul scris, nu după cel presupus: altfel
    un `IN ('O','A')` schimbat înapoi în `<> 'D'` s-ar purta la fel aici și ar
    trece verde, deși pe baza reală lasă să treacă un trigger care nu rulează.
    """
    import re

    fragment = sql.split("tgenabled", 1)[1].split("\n", 1)[0]
    named = set(re.findall(r"'([A-Z])'", fragment))
    assert named, f"filtrul de tgenabled nu numește nicio valoare: {fragment!r}"
    if " IN " in fragment:
        return named
    if "<>" in fragment or "!=" in fragment:
        return set(TRIGGER_STATES) - named
    raise AssertionError(f"filtru de tgenabled nerecunoscut: {fragment!r}")


def _rollup_moment(row):
    """`updated_at` al unui rând de agregat, cu implicit lizibil.

    De la 0025 filigranul merge pe momentul RECALCULĂRII, nu pe eticheta
    intervalului. Fixturile mai vechi n-au coloana; implicitul e sfârșitul
    intervalului, adică prima dată când mentenanța l-ar fi putut scrie.
    """
    return row.get("updated_at") or (row["bucket"] + timedelta(hours=1))


class _DB:
    """Bază falsă care modelează cursoarele și tabelele, nu doar SQL-ul.

    Refuză orice interogare pe care n-o recunoaște: o bază falsă care întoarce
    `None` pentru tot trece peste o interogare greșită exact așa cum a făcut-o
    Postgres un an întreg pentru sonda `audit_head` a beaconului.

    Modelează AMÂNDOUĂ felurile de cursor, fiindcă `STREAMS` are amândouă
    felurile: tabela append-only citită pe `id` (`audit_log`) și una mutabilă
    citită pe `(updated_at, id)` (`incidents`), cu ceasul, `pg_trigger` și
    memo-ul ferestrei care vin cu ea. Implicitele sunt NEUTRE — trigger instalat,
    ceas normal, tabelă mutabilă goală, cursoare scriibile —, deci într-un test
    care se uită la `audit_log` fluxul mutabil e o operație nulă: nu pleacă nimic
    din el, dar nici nu cade nimic și nici nu tace ceva pe ascuns. Alternativa —
    o dublă care nu cunoaște al doilea flux — ar fi transformat fiecare rundă
    într-o `AssertionError` despre SQL nerecunoscut, iar „testul nu se uită la
    fluxul ăsta" ar fi ajuns să însemne „fluxul ăsta nu poate rula".

    Ceasul e o valoare (`self.now`), nu ora reală, fiindcă altfel un salt nu se
    poate PRODUCE într-un test — doar descrie. Tot ce conține `now()` se
    calculează din el, exact ca în bază.

    Și, mai important, își ia purtarea din TEXTUL instrucțiunii, nu din
    argumentele primite: un fals care filtrează după ce i s-a dat trece verde
    peste un `WHERE` din care clauza a dispărut, iar atunci testul verifică
    falsul. S-a întâmplat de trei ori în fișierul ăsta — fereastra de siguranță,
    mutarea cursorului, și departajarea pe cheie.
    """

    def __init__(self, rows=None, cursors=None, mutable=None, at=None, now=None,
                 trigger=True, window=None, clock_readable=True, timeline=None,
                 detections=None, findings=None, blocklist=None,
                 patch_plans=None, selfcheck=None, rollup=None, scans=None,
                 login_sessions=None, session_commands=None):
        self.audit = list(rows or [])
        # A DOUA tabelă append-only, goală implicit, din același motiv pentru
        # care cea mutabilă e goală: un test care se uită la `audit_log` trebuie
        # să vadă fluxul ăsta ca operație nulă, nu ca `AssertionError` despre SQL
        # nerecunoscut. Ține-le separate — un singur `self.audit` folosit pentru
        # amândouă ar face ca pragul de backfill al uneia să fie calculat din
        # rândurile celeilalte, iar simptomul e o a doua avertizare pe care
        # nimeni n-a cerut-o.
        self.timeline = list(timeline or [])
        self.detections = list(detections or [])
        # A treia tabela append-only, si cea cu cel mai mare volum din toate:
        # ~630 de comenzi pentru o logare interactiva, ~17 000 pentru un
        # deploy, masurat pe gazda pe 24 august 2026. Goala implicit, ca
        # celelalte.
        self.session_commands = list(session_commands or [])
        # Celelalte trei tabele MUTABILE, goale implicit, din acelasi motiv
        # pentru care `mutable` era goala: un test care se uita la `incidents`
        # trebuie sa vada fluxurile astea ca operatii nule, nu ca
        # `AssertionError` despre SQL nerecunoscut.
        self.findings = list(findings or [])
        self.blocklist = list(blocklist or [])
        self.patch_plans = list(patch_plans or [])
        # A cincea tabela mutabila, si prima cu CHEIE TEXT. Goala implicit,
        # ca celelalte: un test care se uita la `incidents` trebuie s-o vada
        # ca operatie nula.
        self.selfcheck = list(selfcheck or [])
        # A saptea tabela mutabila: sesiunile de login. Goala implicit.
        self.login_sessions = list(login_sessions or [])
        # Rularile de scanare: a sasea tabela mutabila. Goala implicit, ca
        # fluxul sa fie operatie nula in testele care nu-l privesc.
        self.scans = list(scans or [])
        # A saptea tabela, si prima cu cursor pe MOMENT. Goala implicit, ca
        # fluxul de agregate sa fie operatie nula in testele care nu-l privesc.
        self.rollup = list(rollup or [])
        self.cursors = dict(cursors or {})
        self.sequence_calls = 0
        self.queries: list[str] = []
        self.mutable = list(mutable or [])
        # numele cursorului -> jumătatea de timp. Ținută separat de `cursors`, ca
        # cursoarele pe `id` să nu capete o jumătate pe care n-o au.
        self.at = dict(at or {})
        self.now = now or NOW
        # Ce spune `pg_trigger`. Fals = migrația nu a ajuns pe gazdă, sau
        # triggerul a fost dezactivat cu mâna.
        self.trigger = trigger
        # numele memo-ului -> (moment, cheie, câte rânduri s-au văzut atunci)
        self.window = dict(window or {})
        self.clock_readable = clock_readable
        # Starea detectorului de înțepenire din `check_ship_lag`: cheia
        # `ship:<flux>:stall` -> {"cursor": ultima valoare, "events_seen": contor}.
        # Ținută separat de `cursors`, ca o cheie de stare a autodiagnosticului
        # să nu se amestece cu cursoarele reale de expediere.
        self.stall: dict[str, dict] = {}

    # -- tabela mutabilă: ce se citește din TEXTUL interogării -----------------
    @staticmethod
    def _operand(token, args):
        """Ce valoare are un operand SCRIS în instrucțiune.

        `$2` înseamnă „al doilea argument"; orice altceva e un literal, și atunci
        argumentul primit nu mai are nicio treabă. Fără pasul ăsta, o interogare
        din care cineva scoate `$2` și pune o constantă s-ar purta aici exact ca
        una corectă — dubla ar filtra după ce i s-a dat, nu după ce s-a cerut.
        """
        token = token.strip().split("::")[0].strip()
        if token.startswith("$"):
            return args[int(token[1:]) - 1]
        return int(token)

    def _after(self, sql, args):
        """Rândurile de deasupra cursorului, filtrate CUM SPUNE instrucțiunea.

        Departajarea pe cheie e a doua jumătate a filigranului. Pierdută din
        `WHERE`, rândurile care împart exact momentul cursorului sunt sărite — iar
        rândurile atinse de aceeași tranzacție au prin construcție același moment
        (`now()` e ora de început a tranzacției). Deci defectul taie restul unei
        schimbări atomice la fiecare margine de lot, tăcut.

        Forma se citește din text ȘI operanzii se rezolvă din text: cele două
        împreună sunt singurul fel în care dubla poate contrazice o interogare
        greșită. Clasa asta de dublă mincinoasă a apărut de patru ori în ciclu.
        """
        import re

        # Coloana de departajare se citeste din TEXT, nu fixata pe `id`:
        # `selfcheck_state` se departajeaza pe `key`, iar un tipar care cere `id`
        # n-ar potrivi deloc si ar cadea pe ramura fara departajare — adica testul
        # ar trece verde peste chiar defectul pe care ramura asta il apara.
        pair = re.search(r"\(updated_at, (\w+)\)\s*>\s*\(([^,]+),\s*([^)]+)\)", sql)
        tie = None
        if pair:
            tie = pair.group(1)
            column = tie
            at = self._operand(pair.group(2), args)
            key = self._operand(pair.group(3), args)

            def keep(r):
                return (r["updated_at"], r[column]) > (at, key)
        else:
            alone = re.search(r"updated_at\s*>\s*(\$\d+[^\s]*)", sql)
            assert alone, f"limita de jos a filigranului nerecunoscută: {sql}"
            at = self._operand(alone.group(1), args)

            def keep(r):
                return r["updated_at"] > at
        # Tabela se alege din TEXT, ca peste tot in falsul asta: `self.mutable`
        # a fost singura cat timp exista un singur flux mutabil, iar acum sunt
        # patru. Fixata, ar fi citit randurile lui `incidents` pentru intrebari
        # despre `findings` - adica exact dubla mincinoasa de care se fereste
        # docstring-ul de mai sus.
        rows = self._mutable_for(sql)
        assert rows is not None, f"tabela mutabila nerecunoscuta in: {sql}"
        # Departajarea la sortare o da coloana din PERECHEA de mai sus, cand
        # exista. Interogarile de NUMARARE folosesc acelasi ajutor si n-au
        # `ORDER BY` deloc — cautata acolo, ar fi o aserțiune care pica pe o
        # instructiune perfect valida.
        if tie is None:
            return sorted((r for r in rows if keep(r)), key=lambda r: r["updated_at"])
        return sorted((r for r in rows if keep(r)),
                      key=lambda r: (r["updated_at"], r[tie]))

    async def fetchval(self, sql, *a):
        self.queries.append(sql)
        if "to_timestamp(0)" in sql:
            return EPOCH
        if sql.startswith("SELECT cursor_at FROM collector_cursors"):
            return self.at.get(a[0])
        if "FROM pg_trigger" in sql:
            # Nu se poate modela un catalog PostgreSQL într-un dicționar, deci
            # condițiile care nu se pot juca se CER ca text.
            for required in ("to_regclass($1)", "NOT tgisinternal",
                             "to_regproc('set_updated_at')", "(tgtype & 19) = 19"):
                assert required in sql, \
                    f"interogarea de trigger nu mai cere {required}: {sql}"
            # `tgenabled` se JOACĂ, nu se cere: are patru valori, iar întrebarea
            # care contează nu e dacă filtrul există, ci pe care le lasă să
            # treacă. Cerut ca text, un `<> 'D'` ar fi arătat identic cu un
            # `IN ('O','A')` — și acceptă în plus `'R'`, care nu se declanșează.
            if self.trigger is None:
                # Nici „lipsește", nici „există": „n-am putut întreba". A treia
                # stare are voie să existe într-un fals care păzește tocmai
                # contopirea ei cu a doua.
                return None
            state = {True: "O", False: None}.get(self.trigger, self.trigger)
            if state is None:
                return 0
            return 1 if state in _accepted_trigger_states(sql) else 0
        if "EXTRACT(EPOCH FROM ($1::timestamptz - now()))" in sql:
            return (a[0] - self.now).total_seconds() if self.clock_readable else None
        if "SELECT now() - make_interval(days =>" in sql:
            return self.now - timedelta(days=a[0])
        if sql.startswith("SELECT cursor_at FROM collector_cursors"):
            return self.at.get(a[0])
        if "collector_cursors.cursor)::bigint + $2::bigint" in sql:
            self.cursors[a[0]] = self.cursors.get(a[0], 0) + a[1]
            return self.cursors[a[0]]
        if "count(*) FROM" in sql and "<= ($3::timestamptz" in sql \
                and self._mutable_for(sql) is not None:
            inside = [r for r in self._after(sql, a)
                      if (r["updated_at"], r["id"]) <= (a[2], a[3])]
            return len(inside)
        if "count(*) FROM" in sql and "<= $1::timestamptz" in sql \
                and self._mutable_for(sql) is not None:
            return len([r for r in self._mutable_for(sql) if r["updated_at"] <= a[0]])
        if "GREATEST" in sql:
            name, watermark, count = a
            self.cursors[name] = max(self.cursors.get(name, 0), watermark)
            return self.cursors[name]
        if "collector_cursors.cursor)::bigint + 1" in sql:
            self.sequence_calls += 1
            self.cursors[a[0]] = self.cursors.get(a[0], 0) + 1
            return self.cursors[a[0]]
        if sql.startswith("SELECT cursor::bigint FROM collector_cursors"):
            return self.cursors.get(a[0])
        if "coalesce(max(id), 0)" in sql:
            cutoff = NOW - timedelta(days=a[0])
            # Coloana de timp se citeste din TEXT: `audit_log` o are `at`,
            # `detections` o are `ts`. Fixata pe una, dubla ar da `KeyError` pe
            # celalalt flux — sau, mai rau, ar citi coloana gresita in tacere.
            when = re.search(r"WHERE (\w+) <", sql)
            assert when, f"nu gasesc coloana de timp in: {sql}"
            column = when.group(1)
            older = [r["id"] for r in self._appendOnly(sql) if r[column] < cutoff]
            return max(older) if older else 0
        if "count(*)" in sql and "id <= $1" in sql:
            return len([r for r in self._appendOnly(sql) if r["id"] <= a[0]])
        raise AssertionError(f"fetchval: SQL nerecunoscut: {sql}")

    async def fetch(self, sql, *a):
        self.queries.append(sql)
        if "date_trunc('hour', now())" in sql and " FROM event_rollup_1h " in sql:
            # Se filtreaza CUM SPUNE instructiunea: perechea `(updated_at,
            # bucket)` strict peste cursor, si strict `<` peste ora curenta. Un
            # fals care ar intoarce tot ar face testul despre intervalul in curs
            # sa treaca degeaba.
            # AMBELE elemente ca `timestamptz`: `bucket` e un moment, iar
            # comparat cu `$2::text` Postgres refuză instrucțiunea întreagă.
            # Testele erau verzi când s-a întâmplat, fiindcă dublul compara
            # valorile în Python — unde un `datetime` și un `str` se compară
            # fără să se plângă. Aici se cere FORMA, nu se joacă semantica.
            # `$2::text::timestamptz`, lanț: parametrul SOSEȘTE text — cursorul
            # e stocat ca text —, iar comparația se face pe momente, fiindcă
            # `bucket` e un moment. Cele două capete au fost, pe rând, greșite:
            # `$2::text` a fost refuzat de Postgres, `$2::timestamptz` de
            # asyncpg. Aici se cere FORMA, nu se joacă semantica.
            assert "($1::timestamptz, $2::text::timestamptz)" in sql, sql
            cursor_at, cursor_key, limit = a
            picked = sorted((r for r in self.rollup
                             if (_rollup_moment(r), str(r["bucket"]))
                             > (cursor_at, str(cursor_key))
                             and r["bucket"] < _hour_floor(self.now)),
                            key=lambda r: (_rollup_moment(r), str(r["bucket"])))
            return picked[:limit]
        if " AS k FROM " in sql and "ORDER BY" in sql and "LIMIT $1" in sql:
            # Lista de reconciliere: mulțimea COMPLETĂ de chei a unui flux din
            # care sursa șterge. Dublul o servește din aceleași rânduri pe care
            # le are, altfel `_prune_keys` ar prinde `AssertionError`-ul de mai
            # jos, l-ar înghiți ca pe o eroare de bază, iar lotul ar pleca tăcut
            # fără listă — cu testele tot verzi.
            column = sql.split("SELECT ", 1)[1].split(" AS k", 1)[0]
            rows = self._mutable_for(sql)
            assert rows is not None, f"tabela mutabila nerecunoscuta in: {sql}"
            return [{"k": r[column]}
                    for r in sorted(rows, key=lambda r: str(r[column]))]
        if self._mutable_for(sql) is not None:
            # Coloana de departajare nu e mereu `id`: `selfcheck_state` o are
            # `key`. Ceruta fixa, aserțiunea ar refuza un flux perfect valid — iar
            # ce trebuie sa ramana verificat e FORMA, adica prezenta perechii.
            assert re.search(r"ORDER BY updated_at, \w+ LIMIT \$4", sql), sql
            cursor_at, cursor_key, lag_s, limit = a
            columns = sql.split("SELECT ", 1)[1].split(" FROM ")[0].split(", ")
            picked = self._after(sql, a)
            # Se taie coada proaspătă doar dacă INTEROGAREA o taie. Un fals care
            # aplică fereastra fiindcă a primit-o ca argument ar trece peste un
            # SQL din care clauza a dispărut — adică testul despre fereastră ar
            # verifica falsul, nu codul. E chiar aserțiunea-pe-numele-variabilei
            # din CLAUDE.md.
            if "make_interval(secs =>" in sql:
                horizon = self.now - timedelta(seconds=lag_s)
                picked = [r for r in picked if r["updated_at"] <= horizon]
            return [{c: r[c] for c in columns} for r in picked[:limit]]
        assert "WHERE id > $1 ORDER BY id LIMIT $2" in sql, sql
        # Tabela se alege prin `_appendOnly`, care ridică singură dacă nu o
        # cunoaște. O listă de nume repetată aici ar trebui editată la fiecare
        # flux nou, iar cine uită s-o editeze primește „SQL nerecunoscut" în loc
        # de un mesaj care spune ce lipsește.
        cursor, limit = a
        columns = sql.split("SELECT ", 1)[1].split(" FROM ")[0].split(", ")
        picked = sorted((r for r in self._appendOnly(sql) if r["id"] > cursor),
                        key=lambda r: r["id"])[:limit]
        return [{c: r[c] for c in columns} for r in picked]

    def _appendOnly(self, sql):
        """Rândurile tabelei append-only NUMITĂ în instrucțiune.

        Alegerea se face din TEXTUL instrucțiunii, ca peste tot în falsul ăsta:
        dacă s-ar face din argumente, un SQL care a rămas pe tabela greșită ar
        primi rândurile corecte și testul ar trece peste chiar defectul lui.

        Căutat pe `FROM <tabelă> `, cu spațiul de la capăt: fără el `detections`
        s-ar potrivi și în interogările lui `detection_events`, iar un flux
        viitor ar citi tăcut rândurile altuia.
        """
        for name, rows in self._append_only_tables().items():
            if f"FROM {name} " in sql:
                return rows
        raise AssertionError(f"tabelă append-only necunoscută în: {sql}")

    def _mutable_tables(self):
        """Tabelele MUTABILE pe care le modeleaza falsul, pe nume.

        Aceeasi forma ca `_append_only_tables`, si acolo e scris de ce: un flux
        adaugat la `STREAMS` si absent de aici face testele sa pice zgomotos, nu
        sa citeasca tacut randurile altei tabele.
        """
        return {
            "incidents": self.mutable,
            "findings": self.findings,
            "blocklist": self.blocklist,
            "patch_plans": self.patch_plans,
            "selfcheck_state": self.selfcheck,
            "scans": self.scans,
            "login_sessions": self.login_sessions,
        }

    def _mutable_for(self, sql):
        """Randurile tabelei mutabile numite in instructiune, sau `None`.

        `None` inseamna „instructiunea nu e despre un flux mutabil", nu „tabela e
        goala" - iar apelantul trateaza cele doua diferit.
        """
        for name, rows in self._mutable_tables().items():
            if "FROM %s " % name in sql:
                return rows
        return None

    def _append_only_tables(self):
        """Tabelele append-only pe care le modelează falsul, pe nume.

        Un flux append-only adăugat la `STREAMS` și absent de aici face testele
        să pice cu „tabelă necunoscută", nu să treacă pe rândurile altei tabele.
        Zgomotos dinadins: alternativa e un prag de backfill calculat din
        rândurile greșite, care se vede ca o avertizare în plus și se caută ore.
        """
        return {
            "audit_log": self.audit,
            "incident_timeline": self.timeline,
            "detections": self.detections,
            "session_commands": self.session_commands,
        }

    async def fetchrow(self, sql, *a):
        self.queries.append(sql)
        if "GREATEST(collector_cursors.cursor_at" in sql:
            name, _iso, moment, rows = a
            # Monoton, ca in SQL: `GREATEST`. Un cursor care merge inapoi ar
            # retrimite intervale deja expediate.
            old_at = self.at.get(name)
            self.at[name] = moment if old_at is None else max(old_at, moment)
            self.cursors[name] = self.at[name].isoformat()
            return {"cursor_at": self.at[name]}
        if "date_trunc('hour', now())" in sql and "count(*) AS pending" in sql:
            after = [r for r in self.rollup
                     if (_rollup_moment(r), str(r["bucket"])) > (a[0], a[1])
                     and r["bucket"] < _hour_floor(self.now)]
            oldest = min((r["bucket"] for r in after), default=None)
            return {"pending": len(after),
                    "oldest_min": None if oldest is None
                    else (self.now - oldest).total_seconds() / 60}
        if sql.startswith("SELECT cursor, events_seen FROM collector_cursors"):
            # Starea detectorului de înțepenire (`ship:<flux>:stall`). Absentă la
            # prima privire: `None`, ca în bază.
            return self.stall.get(a[0])
        if sql.startswith("SELECT cursor, cursor_at, events_seen FROM collector_cursors"):
            memo = self.window.get(a[0])
            if memo is None:
                return None
            return {"cursor": str(memo[1]), "cursor_at": memo[0], "events_seen": memo[2]}
        if sql.startswith("SELECT cursor, cursor_at FROM collector_cursors"):
            if a[0] not in self.cursors:
                return None
            return {"cursor": str(self.cursors[a[0]]), "cursor_at": self.at.get(a[0])}
        if "cursor_at = CASE WHEN" in sql:
            name, position_at, position_key, _rows = a
            old_at, old_key = self.at.get(name), self.cursors.get(name)
            if name not in self.cursors:
                self.cursors[name], self.at[name] = position_key, position_at
            elif old_at is not None and (old_at, old_key) < (position_at, position_key):
                # Se scrie ce scrie SQL-ul: mutarea e monotonă pe PERECHE, iar un
                # `cursor_at` NULL face comparația necunoscută, deci nu mută.
                self.cursors[name], self.at[name] = position_key, position_at
            return {"cursor_at": self.at.get(name), "cursor_key": self.cursors.get(name)}
        if "count(*) AS pending" in sql and "FROM incidents" in sql:
            after = self._after(sql, a)
            oldest = min((r["updated_at"] for r in after), default=None)
            return {"pending": len(after),
                    "oldest_min": None if oldest is None
                    else (self.now - oldest).total_seconds() / 60}
        if "count(*) AS pending" in sql:
            pending = [r for r in self.audit if r["id"] > a[0]]
            oldest = min((r["at"] for r in pending), default=None)
            return {"pending": len(pending),
                    "oldest_min": None if oldest is None
                    else (NOW - oldest).total_seconds() / 60}
        raise AssertionError(f"fetchrow: SQL nerecunoscut: {sql}")

    async def execute(self, sql, *a):
        self.queries.append(sql)
        # ÎNAINTE de ramura generală de mai jos: aia prinde orice instrucțiune
        # care conține „cursor_at", iar semănarea unui cursor de agregat o
        # conține și ea — cu trei argumente, nu patru.
        if "ON CONFLICT (name) DO NOTHING" in sql and len(a) == 3                 and hasattr(a[2], "isoformat"):
            name, _iso, moment = a
            self.at.setdefault(name, moment)
            self.cursors.setdefault(name, moment.isoformat())
            return "INSERT 0 1"
        if "VALUES ($1, $2::timestamptz::text, $2::timestamptz, now())" in sql:
            # Semănatul cursorului unui flux de agregate: UN singur rând, fără
            # prag. Un flux de agregate n-are prag — istoricul lui e chiar ce
            # vrea panoul —, deci nu poate trece prin ramura de mai jos, care
            # seamănă două nume.
            #
            # Cheia se seamănă cu MOMENTUL, nu cu șirul gol: e valoarea cu care
            # se compară prima rundă, iar `''::timestamptz` cade cu «invalid
            # input syntax». A căzut, pe 24 august, în producție.
            assert "ON CONFLICT (name) DO NOTHING" in sql, sql
            name, moment = a
            self.cursors.setdefault(name, str(moment))
            self.at.setdefault(name, moment)
            return "INSERT 0 1"
        if "cursor = $2::text" in sql and "events_seen = $3::bigint" in sql:
            # Upsertul stării detectorului de înțepenire: scrie necondiționat
            # valoarea cursorului văzută și contorul, sub cheia `ship:<flux>:stall`.
            name, cursor_repr, events = a[0], a[1], a[2]
            self.stall[name] = {"cursor": cursor_repr, "events_seen": events}
            return "INSERT 0 1"
        if "cursor_at" in sql:
            if "events_seen = $4::bigint" in sql:
                name, position_at, position_key, rows = a
                self.window[name] = (position_at, position_key, rows)
                return "INSERT 0 1"
            assert "ON CONFLICT (name) DO NOTHING" in sql, sql
            cursor_name, floor_name, floor_at, seed = a
            for name in (cursor_name, floor_name):
                # Se seamănă CE A DAT apelantul, nu un `0` scris aici. Dublul
                # ăsta punea zero până pe 21 august 2026, iar zero e valoarea
                # potrivită doar pentru un flux cu cheie întreagă — deci fluxul
                # cu cheie text trecea prin test și pica în producție.
                self.cursors.setdefault(name, seed)
                self.at.setdefault(name, floor_at)
            return "INSERT 0 2"
        if "ON CONFLICT (name) DO NOTHING" in sql:
            cursor_name, floor_name, floor = a
            # Se scrie ce scrie SQL-ul, nu ce s-a dat ca argumente. O bază falsă
            # care pune ambele rânduri fiindcă a primit ambele nume trece peste
            # o instrucțiune care inserează unul singur — și atunci testul despre
            # pragul persistat n-ar mai verifica nimic.
            written = 0
            if "($1, " in sql:
                self.cursors.setdefault(cursor_name, floor)
                written += 1
            if "($2, " in sql:
                self.cursors.setdefault(floor_name, floor)
                written += 1
            return f"INSERT 0 {written}"
        raise AssertionError(f"execute: SQL nerecunoscut: {sql}")


# Numele sub care își construiesc baza testele care POPULEAZĂ tabela mutabilă. A
# fost o clasă separată cât timp niciun flux mutabil nu era înregistrat: atunci
# `_DB` putea să nu știe nimic despre `pg_trigger`, ceas și `(updated_at, id)`.
# De când `STREAMS` are `incidents`, fiecare rundă a fiecărui test trece pe
# drumul ăla, deci `_DB` trebuie să-i răspundă oricum — iar două dubluri care ar
# implementa aceleași interogări ar putea să nu fie de acord, ceea ce e chiar
# felul în care un test verifică dubla în loc de cod. E același obiect, cu alt
# nume, ca fixtura mutabilă să se citească drept ce e.
_MutableDB = _DB


def unwire(wire: bytes) -> bytes:
    """Octeții SEMNAȚI, scoși din ce a plecat pe sârmă.

    E jumătatea de aici a lui `unwrap()` din `aggregator/lib/envelope.ts`, scrisă
    a doua oară dinadins și cât se poate de prost: dacă ar chema `envelope.py`,
    ar proba că modulul e invers cu el însuși, nu că receptorul îl poate citi.
    Ce nu se poate proba de aici — că exact octeții ăștia trec prin
    implementarea TypeScript — se probează cu un vector comun, în
    `tests/unit/test_transport_envelope.py` și `aggregator/tests/envelope.test.ts`.
    """
    import base64
    import gzip

    if not wire.startswith(b'{"enc":'):
        return wire
    return gzip.decompress(base64.b64decode(json.loads(wire)["body"]))


class _Receiver:
    """Agregator fals. Ține minte DACĂ a fost chemat, nu doar cu ce.

    `body` e ce s-a SEMNAT, `wire` e ce a plecat. Cele două nu mai sunt aceiași
    octeți de când lotul călătorește într-un plic, iar aproape toate probele din
    fișier sunt despre payload — deci `body` rămâne payload-ul, ca o schimbare de
    transport să nu ceară rescrierea a douăzeci de aserțiuni care nu sunt despre
    el. Probele despre transport se uită la `wire`.
    """

    calls: list[dict] = []
    status = 200
    body = '{"ok":true,"accepted":{"audit_log":0}}'
    echo = True     # când e True, corpul se construiește din ce s-a primit

    def __init__(self, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, content=None, headers=None):
        signed = unwire(content)
        _Receiver.calls.append({"url": url, "body": signed, "wire": content,
                                "headers": headers})
        body = _Receiver.body
        if _Receiver.echo:
            sent = json.loads(signed)
            body = json.dumps({"ok": True, "accepted": sent["cursors"]})
        return SimpleNamespace(status_code=_Receiver.status, text=body)


@pytest.fixture
def http(monkeypatch):
    import httpx

    _Receiver.calls = []
    _Receiver.status = 200
    _Receiver.echo = True
    _Receiver.body = '{"ok":true,"accepted":{"audit_log":0}}'
    monkeypatch.setattr(httpx, "AsyncClient", _Receiver)
    return _Receiver


@pytest.fixture(autouse=True)
def _fresh_counters():
    """Contoarele de eșec sunt stare de modul, iar toate testele rulează în
    același proces. Fără curățare, un test care lasă contorul pe 2 mută pragurile
    din următorul și eșecul apare la cine n-a greșit."""
    shipper._identity_failures = 0
    shipper._canonical_failures = 0
    yield
    shipper._identity_failures = 0
    shipper._canonical_failures = 0


@pytest.fixture(autouse=True)
def _identity(monkeypatch, tmp_path):
    """Gazda are o identitate în majoritatea testelor, ca în producție.

    Se repointează CONSTANTA din `sentinel.identity`, nu funcția importată în
    shipper: altfel testele ar trece și peste un cititor complet stricat.
    """
    import sentinel.identity as identity

    target = tmp_path / "instance_id"
    target.write_text(ID_A + "\n", encoding="utf-8")
    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", target)
    return target


def _ship(**over):
    s = SimpleNamespace(enabled=True, url="https://exemplu.test/api/sentinel/sync",
                        interval_s=60, timeout_s=30, max_age_s=300,
                        max_rows_per_batch=2000, max_backfill_days=7,
                        backoff_base_s=30, backoff_max_s=3600,
                        # Aceleași implicite ca `ShipConfig`, nu valori inventate:
                        # o dublă cu alte plafoane ar proba altceva decât ce
                        # rulează pe gazdă.
                        max_children_per_row=1000, max_child_rows_per_batch=6000)
    for k, v in over.items():
        setattr(s, k, v)
    return s


def _detection(id_: int, minutes_ago: float = 1.0, **over):
    """Un rând de detecție ca cel pe care îl întoarce asyncpg.

    `event_ids` e un tablou de întregi, ca în Postgres — nu obiectele de pe
    sârmă. Conversia e chiar ce probează testele care îl folosesc.
    """
    row = {
        "id": id_,
        "ts": NOW - timedelta(minutes=minutes_ago),
        "rule_id": "auth.ssh_bruteforce",
        "rule_family": "auth",
        "severity": "medium",
        "score": None,
        "actor_key": None,
        "asset_id": None,
        "incident_id": None,
        "src_ip": None,
        "dst_port": 22,
        "evidence": "{}",
        "suppressed": False,
        "suppress_reason": None,
        "event_ids": [],
    }
    row.update(over)
    return row


def _cfg(**over):
    return SimpleNamespace(ship=_ship(**over))


# ---------------------------------------------------------------------------
# REGULA: cursorul avansează pe ecou, nu pe 200
# ---------------------------------------------------------------------------
def test_the_cursor_advances_when_the_watermark_comes_back(http):
    """Cazul normal, ca restul fișierului să însemne ceva prin contrast."""
    db = _DB(rows=[_row(91232), _row(91233)], cursors={"ship:audit_log": 91231})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is True
    assert result.advanced == {"audit_log": 91233}
    assert db.cursors["ship:audit_log"] == 91233


def test_a_200_without_an_echo_does_not_advance_the_cursor(http):
    """Un agregator care nu cunoaște fluxul îl ignoră tăcut și răspunde 200.

    Dacă expeditorul crede codul de stare, cursorul trece peste rânduri care
    n-au ajuns nicăieri. Nu se mai întoarce niciodată acolo, iar pe agregator
    lipsa e invizibilă — nimeni nu știe ce trebuia să fie acolo. Pierderea e
    permanentă și n-o raportează nimic.
    """
    http.echo = False
    http.body = '{"ok":true}'
    db = _DB(rows=[_row(91233)], cursors={"ship:audit_log": 91232})

    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert db.cursors["ship:audit_log"] == 91232, "cursorul a avansat pe un 200 fără ecou"

    # Și consecința care contează pentru operator: lotul următor duce aceleași
    # rânduri, în loc să le fi pierdut.
    http.echo = True
    assert run(shipper.ship_once(db, _cfg(), "k")).advanced == {"audit_log": 91233}
    resent = json.loads(http.calls[-1]["body"])["rows"]["audit_log"]
    assert [r["id"] for r in resent] == [91233]


def test_a_cached_cdn_page_that_returns_200_does_not_advance_the_cursor(http):
    """Un edge CDN care servește o pagină din cache răspunde 200 cu HTML.

    E răspunsul cel mai probabil pe o găzduire cu CDN în față și e exact cel
    care arată ca un succes: cod 2xx, corp nenul, nicio excepție.
    """
    http.echo = False
    http.body = "<!doctype html><title>hosting</title>"
    db = _DB(rows=[_row(5)], cursors={"ship:audit_log": 4})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is False
    assert db.cursors["ship:audit_log"] == 4


def test_an_echo_of_the_wrong_watermark_does_not_advance_the_cursor(http):
    """Un filigran care nu e cel trimis înseamnă că nu vorbim despre același lot.

    Cel mai probabil e un răspuns vechi, pus în cache. Avansat până acolo,
    cursorul ar sări peste diferență.
    """
    http.echo = False
    http.body = '{"ok":true,"accepted":{"audit_log":91230}}'
    db = _DB(rows=[_row(91233)], cursors={"ship:audit_log": 91232})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert db.cursors["ship:audit_log"] == 91232
    assert "91230" in result.reason


def test_a_boolean_echo_is_not_a_watermark(http):
    """În Python `True == 1`. Un `{"audit_log": true}` ar confirma filigranul 1
    fără ca nimeni să fi scris asta, iar pe un flux proaspăt (cursor 0, primul
    rând id 1) asta e chiar avansarea peste primul rând."""
    http.echo = False
    http.body = '{"ok":true,"accepted":{"audit_log":true}}'
    db = _DB(rows=[_row(1)], cursors={"ship:audit_log": 0})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is False
    assert db.cursors["ship:audit_log"] == 0


def test_an_echo_AHEAD_of_the_watermark_does_not_advance_the_cursor(http):
    """Direcția care contează, și singura care pierde rânduri.

    Un ecou mai MIC decât filigranul trimis e conservator: cursorul ar rămâne în
    urmă și rândurile s-ar retrimite. Un ecou mai MARE mută cursorul peste
    rânduri care nu au plecat în lotul ăsta — pierdere permanentă și tăcută,
    produsă chiar de mecanismul scris s-o oprească.

    Și e cazul probabil, nu unul teoretic: un edge CDN sau un vhost greșit rutat
    care servește din cache răspunsul unui lot ULTERIOR, reușit, ecouă exact un
    filigran mai mare. `!=`, nu `<`.
    """
    http.echo = False
    http.body = '{"ok":true,"accepted":{"audit_log":91999}}'
    db = _DB(rows=[_row(91233)], cursors={"ship:audit_log": 91232})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert db.cursors["ship:audit_log"] == 91232, \
        "cursorul a sărit peste rânduri pe un ecou din alt lot"
    assert "91999" in result.reason


def test_an_ok_that_is_merely_truthy_is_not_an_ok(http):
    """`ok: 1`, `ok: "true"`, `ok: []` — toate sunt adevărate pentru un `if`, și
    niciuna nu e afirmația pe care o cere protocolul.

    Un receptor care le trimite e unul care a trecut valoarea prin altceva decât
    credem — un proxy care rescrie JSON-ul, un cadru care serializează
    booleenii ca șiruri. „Seamănă cu da" nu e da, și diferența e chiar între a
    ști și a presupune ce s-a întâmplat cu lotul.
    """
    for body in ('{"ok":1,"accepted":{"audit_log":91233}}',
                 '{"ok":"true","accepted":{"audit_log":91233}}',
                 '{"ok":"yes","accepted":{"audit_log":91233}}'):
        confirmed, problem = shipper.accepted_watermarks(body, {"audit_log": 91233})
        assert confirmed == {}, f"{body} a fost acceptat ca ok:true"
        assert "ok" in problem


def test_an_accepted_that_is_not_an_object_is_refused(http):
    """`accepted: null` nu e singura formă greșită, doar cea mai comodă.

    O listă (`accepted: []`), un șir sau un număr trec toate de un
    `accepted is None`, iar apoi `.get` pe ele ridică AttributeError în mijlocul
    rundei — sau, pe o listă, un `in` care nu înseamnă ce pare. Tipul se cere,
    nu se presupune din absența lui `null`.
    """
    for body in ('{"ok":true,"accepted":[]}',
                 '{"ok":true,"accepted":"audit_log"}',
                 '{"ok":true,"accepted":91233}',
                 '{"ok":true,"accepted":[{"audit_log":91233}]}'):
        confirmed, problem = shipper.accepted_watermarks(body, {"audit_log": 91233})
        assert confirmed == {}, f"{body} a fost citit ca obiect `accepted`"
        assert "accepted" in problem


def test_a_string_watermark_is_not_an_integer_watermark(http):
    """Un receptor care ecouă `"91233"` în loc de `91233` e un receptor care a
    trecut valoarea prin altceva decât credem. Nu e o nepotrivire cosmetică: e
    dovada că nu știm ce a făcut cu lotul."""
    http.echo = False
    http.body = '{"ok":true,"accepted":{"audit_log":"91233"}}'
    db = _DB(rows=[_row(91233)], cursors={"ship:audit_log": 91232})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is False
    assert db.cursors["ship:audit_log"] == 91232


def test_ok_false_with_a_correct_echo_does_not_advance(http):
    """Receptorul spune el însuși că n-a preluat. A avansa pe filigranul
    ecouat oricum ar însemna să-l contrazicem pe cel care știe."""
    http.echo = False
    http.body = '{"ok":false,"accepted":{"audit_log":91233}}'
    db = _DB(rows=[_row(91233)], cursors={"ship:audit_log": 91232})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is False
    assert db.cursors["ship:audit_log"] == 91232


def test_a_stream_the_receiver_ignored_is_the_only_one_left_behind():
    """Mecanismul e per FLUX, nu per cerere.

    Un agregator mai vechi decât serverul cunoaște `audit_log` și nu cunoaște
    fluxul următor. Dacă ecoul parțial ar bloca tot, adăugarea unui flux ar opri
    expedierea celor care mergeau; dacă ar confirma tot, fluxul necunoscut s-ar
    pierde tăcut. Fiecare flux își poartă propriul filigran.

    LIMITA testului, scrisă ca să nu fie citit ca mai mult decât e: în faza asta
    `STREAMS` are o singură intrare, deci proprietatea se verifică la nivelul lui
    `accepted_watermarks`, nu cap-coadă printr-o rundă cu două fluxuri. Cine
    adaugă al doilea flux în E3 datorează cazul cap-coadă — că un `accepted`
    parțial avansează cursorul confirmat și îl lasă pe loc pe celălalt.
    """
    other = shipper.Stream(name="detections", table="detections",
                           columns=("id", "at"), time_column="at")
    confirmed, problem = shipper.accepted_watermarks(
        '{"ok":true,"accepted":{"audit_log":7}}',
        {"audit_log": 7, "detections": 42})
    assert confirmed == {"audit_log": 7}
    assert "detections" in problem
    assert other.cursor_name == "ship:detections"


def test_the_watermark_is_the_last_row_of_the_batch_not_the_head_of_the_table(http):
    """Cu 5000 de rânduri în așteptare și un lot de 2000, filigranul trebuie să
    fie al 2000-lea rând.

    Trimis capul tabelei, un răspuns care îl ecouă ar avansa cursorul peste 3000
    de rânduri care n-au plecat — pierderea tăcută, produsă chiar de mecanismul
    care există s-o prevină.
    """
    db = _DB(rows=[_row(i) for i in range(1, 51)], cursors={"ship:audit_log": 0})
    result = run(shipper.ship_once(db, _cfg(max_rows_per_batch=10), "k"))
    sent = json.loads(http.calls[0]["body"])
    assert sent["cursors"]["audit_log"] == 10
    assert len(sent["rows"]["audit_log"]) == 10
    assert result.advanced == {"audit_log": 10}
    assert result.more is True, "lotul plin nu a semnalat că mai sunt rânduri"


def test_a_cursor_that_did_not_move_is_not_reported_as_advanced(http):
    """`UPDATE` care nu potrivește niciun rând iese cu succes.

    Efectul, nu intenția: dacă baza n-a scris filigranul cerut — un cursor mutat
    între timp de altcineva, o migrare care a redenumit rândul — expeditorul nu
    are voie să raporteze o avansare care nu s-a întâmplat, fiindcă atunci
    `ship:lag` ar citi o restanță pe care nimeni n-o explică.
    """
    class _Stuck(_DB):
        async def fetchval(self, sql, *a):
            if "GREATEST" in sql:
                return a[1] - 1        # baza a rămas în urma a ce s-a cerut
            return await super().fetchval(sql, *a)

    db = _Stuck(rows=[_row(9)], cursors={"ship:audit_log": 8})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.advanced == {}
    assert result.ok is False


def test_nothing_to_ship_is_a_successful_round_that_touches_no_network(http):
    """O gazdă liniștită nu trimite loturi goale.

    Un lot gol la fiecare interval e trafic care nu dovedește nimic — dovada că
    gazda trăiește e treaba beaconului — iar „la zi" se citește din cursor, nu
    din faptul că a plecat ceva.
    """
    db = _DB(rows=[_row(3)], cursors={"ship:audit_log": 3})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is True and result.advanced == {}
    assert http.calls == []
    assert db.sequence_calls == 0


# ---------------------------------------------------------------------------
# Protocolul: ce cere receptorul
# ---------------------------------------------------------------------------
def test_the_batch_satisfies_the_three_checks_the_receiver_makes(http):
    """`aggregator/app/api/sentinel/beat/route.ts` verifică în ordine: găsește cheia
    după antet, verifică HMAC peste OCTEȚII BRUȚI, apoi cere
    `payload.instance_id == antet`. E2.4 urmează același contract.

    Fiecare pas ratat se vede de pe server ca tăcere, nu ca eroare de
    configurație: 401 fără cauză, cursor care nu avansează, restanță care crește.
    """
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    assert run(shipper.ship_once(db, _cfg(), "cheie")).ok is True
    sent = http.calls[0]
    body = sent["body"]

    # 1. antetul poartă identitatea gazdei
    assert sent["headers"][shipper.INSTANCE_HEADER] == ID_A
    # 2. semnătura verifică EXACT octeții trimiși
    assert shipper.sign(json.loads(body), "cheie") == sent["headers"][shipper.SIGNATURE_HEADER]
    assert shipper.canonical(json.loads(body)) == body
    # 3. payload.instance_id === antet
    assert json.loads(body)["instance_id"] == sent["headers"][shipper.INSTANCE_HEADER]
    assert sent["headers"]["Cache-Control"] == "no-store"


def test_the_batch_travels_wrapped_and_the_signature_stays_over_the_content(http):
    """Semnat peste PLIC, contractul trans-limbaj se rupe tăcut la prima rundă.

    `sentinel/report/signing.py` și `aggregator/lib/verify.ts` sunt gemeni
    identici la octet peste forma canonică. Plicul comprimă, deci octeții lui
    depind de zlib și de nivelul ales; semnătura pusă peste ei n-ar mai fi
    verificabilă de celălalt capăt, iar simptomul ar fi 401 la fiecare lot —
    adică exact ce arată o cheie greșită sau un secret rotit. S-ar căuta zile
    întregi în locul nepotrivit, timp în care arhiva externă nu primește nimic.

    Proba se uită la CE A PLECAT, nu la ordinea liniilor din `ship_once`: un
    `sign(packet.wire, …)` strecurat oriunde în funcție pică aici.
    """
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    assert run(shipper.ship_once(db, _cfg(), "cheia")).ok is True
    sent = http.calls[0]

    # A plecat împachetat — altfel reparația nu repară nimic.
    assert sent["wire"] != sent["body"], "lotul a plecat neîmpachetat"
    assert sent["wire"].startswith(b'{"enc":"gzip+base64"')
    # Semnătura e peste conținut...
    assert sent["headers"][shipper.SIGNATURE_HEADER] == \
        shipper.sign(json.loads(sent["body"]), "cheia")
    # ...și NU peste ce s-a trimis.
    import hashlib
    import hmac
    assert sent["headers"][shipper.SIGNATURE_HEADER] != \
        hmac.new(b"cheia", sent["wire"], hashlib.sha256).hexdigest()
    # Antetele au rămas în AFARA plicului: identitatea se citește ca să se
    # găsească cheia, adică înainte de a se putea deschide ceva.
    assert sent["headers"][shipper.INSTANCE_HEADER] == ID_A
    assert b"instance_id" not in sent["wire"]
    # Și tipul cererii nu s-a schimbat: plicul e tot JSON. Un corp binar cu alt
    # tip n-a fost probat pe margine, deci nu e o variantă de afirmat.
    assert sent["headers"]["Content-Type"] == "application/json"


def test_the_compression_ratio_reaches_the_operator_log(http, caplog):
    """Fără linia asta, „comprimarea câștigă" e o presupunere, nu o măsurătoare.

    Loturile de comenzi sunt foarte repetitive — `systemctl` și `sleep` de zeci
    de mii de ori — și de-aia plicul e ieftin. Dacă vreodată raportul cade la 1×,
    înseamnă că altceva s-a schimbat în conținut, iar singurul loc din care se
    poate vedea e jurnalul de pe gazdă: operatorul n-are cum să inspecteze corpul
    unei cereri semnate care pleacă spre altă mașină.
    """
    import logging

    db = _DB(rows=[_row(i) for i in range(9, 60)], cursors={"ship:audit_log": 8})
    with caplog.at_level(logging.INFO, logger="sentinel.report.shipper"):
        assert run(shipper.ship_once(db, _cfg(), "k")).ok is True

    lines = [r for r in caplog.records if r.msg == "shipper batch wrapped for transport"]
    assert len(lines) == 1, f"{len(lines)} linii despre împachetare"
    record = lines[0]
    assert record.ratio > 1, f"plicul nu mai câștigă nimic: {record.ratio}"
    assert record.signed_bytes > record.wire_bytes
    assert record.batch_streams.startswith("audit_log×")


def test_the_identity_is_read_once_for_a_batch(http, monkeypatch):
    """Antetul și `payload.instance_id` trebuie să fie ACELAȘI octet.

    Două citiri independente pot să nu fie de acord — o rotire între ele, sau o
    linie mutată mai târziu în alt loc — iar receptorul refuză cu 401, ceea ce de
    pe server se vede ca tăcere.
    """
    import sentinel.identity as identity

    class _Shifting:
        def __init__(self):
            self.reads = 0

        def read_text(self, encoding="utf-8"):
            self.reads += 1
            return (ID_A if self.reads == 1 else "f" * 32) + "\n"

    shifting = _Shifting()
    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", shifting)
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is True
    sent = http.calls[0]
    assert sent["headers"][shipper.INSTANCE_HEADER] == json.loads(sent["body"])["instance_id"]
    assert shifting.reads == 1, f"identitatea s-a citit de {shifting.reads} ori"


def test_the_two_senders_agree_with_the_receiver_on_the_header_names():
    """Numele antetelor sunt scrise în patru locuri, în două limbaje.

    Un antet scris altfel de expeditorul de loturi decât de beacon nu produce o
    eroare: receptorul nu găsește instanța, refuză cu 401, iar de pe server asta
    se vede exact ca o cheie greșită.
    """
    from pathlib import Path

    from sentinel.report import beacon

    assert shipper.INSTANCE_HEADER == beacon.INSTANCE_HEADER
    assert shipper.SIGNATURE_HEADER == beacon.SIGNATURE_HEADER
    lib = Path(__file__).resolve().parents[2] / "aggregator" / "lib"
    instances = (lib / "beat-keys.ts").read_text(encoding="utf-8")
    verify = (lib / "verify.ts").read_text(encoding="utf-8")
    assert f'INSTANCE_HEADER = "{shipper.INSTANCE_HEADER.lower()}"' in instances
    assert f'SIGNATURE_HEADER = "{shipper.SIGNATURE_HEADER.lower()}"' in verify


def test_a_partially_accepted_batch_says_WHY_in_the_log(http, caplog, monkeypatch):
    """Care flux stă pe loc se vede din cursor. DE CE știe numai agregatorul.

    La acceptare parțială, `accepted_watermarks` produce „detections: lipsește
    din `accepted`" — adică exact ce se putea deduce și fără el. Motivul —
    „fluxul nu e cunoscut de agregator, are nevoie de o migrație" — există doar
    în corpul răspunsului, iar `ship_once` scrie corpul în jurnal în două ramuri
    (non-2xx, și `if not confirmed`), dintre care niciuna nu e asta. Fără linia
    de aici, operatorul vede un flux care tace și nicio explicație, pe niciun
    capăt: pe agregator nu se uită, iar aici nu scrie.

    Al doilea flux e fabricat peste aceeași tabelă, fiindcă `STREAMS` are azi o
    singură intrare și acceptarea parțială are nevoie de două. Ce se probează e
    ramura, nu fluxul.
    """
    second = shipper.Stream(name="detections", table="audit_log",
                            columns=shipper.AUDIT_STREAM.columns, time_column="at")
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, second))

    reason = ('fluxul "detections" nu e cunoscut de agregator (cunoscute: '
              "audit_log); are nevoie de o migrație a agregatorului.")
    http.echo = False
    http.body = json.dumps({"ok": True, "accepted": {"audit_log": 91233},
                            "refused": {"detections": reason}})

    db = _DB(rows=[_row(91233)],
             cursors={"ship:audit_log": 91232, "ship:detections": 91232})
    with caplog.at_level("WARNING", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    # Acceptarea parțială chiar s-a întâmplat: unul avansează, celălalt nu.
    assert result.advanced == {"audit_log": 91233}, result
    assert db.cursors["ship:detections"] == 91232

    warnings = [r for r in caplog.records if r.message == "some streams were not confirmed"]
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
    assert "nu e cunoscut" in getattr(warnings[0], "body", ""), (
        "motivul agregatorului nu ajunge în jurnalul de pe gazdă, deci operatorul "
        "află CARE flux stă pe loc și niciodată DE CE")


def test_the_two_ends_agree_on_the_batch_limits(tmp_path):
    """Un lot pe care `config-check` declară legal și agregatorul refuză oprește
    `audit_log` PENTRU TOTDEAUNA.

    `ship_once` face `if response.status_code // 100 != 2: return
    ShipResult(False, ...)` fără să citească vreodată corpul, iar nicăieri nu
    există logică de micșorare a lotului sau a ferestrei. Deci un plafon al
    receptorului mai mic decât ce acceptă `load_config` nu se vede ca o eroare de
    configurație: se vede ca un agregator căzut, la nesfârșit, cu backoff până la
    o oră — în timp ce lanțul de audit nu mai pleacă de pe gazdă.

    Cazul probabil nu e exotic, e chiar cel recomandat de capul lui `shipper.py`:
    operatorul ridică `max_rows_per_batch` ca să recupereze o restanță, și își
    oprește fluxul.

    Testul citește numerele din sursa TypeScript și le probează prin
    `load_config`, ca o mutare de o singură parte să pice aici. Aceeași formă ca
    `test_the_two_senders_agree_with_the_receiver_on_the_header_names`.
    """
    import re
    from pathlib import Path

    from sentinel.config import load_config
    from sentinel.errors import ConfigError

    root = Path(__file__).resolve().parents[2] / "aggregator"
    ingest = (root / "lib" / "ingest.ts").read_text(encoding="utf-8")
    route = (root / "app" / "api" / "sentinel" / "sync" / "route.ts").read_text(encoding="utf-8")

    def number(text: str, name: str) -> int:
        # `finditer` + unicitate, nu `search`: `search` ia PRIMA potrivire, deci
        # un literal de aceeași formă apărut mai devreme în fișier — într-un
        # docstring care explică limita, de pildă — ar umbri constanta reală, iar
        # testul ar compara cele două capete cu un număr dintr-un comentariu.
        found = [m.group(1) for m in re.finditer(rf"^\s*(?:export )?const {name} = ([\d_]+);",
                                                 text, re.MULTILINE)]
        assert len(found) == 1, f"{name}: {len(found)} definiții literale în agregator"
        return int(found[0].replace("_", ""))

    rows_ceiling = number(ingest, "MAX_ROWS_PER_BATCH")
    age_ceiling = number(route, "MAX_AGE_CEILING_S")

    # Plafonul de corp e derivat pe agregator, dar E REPETAT pe gazda asta —
    # `check_ship_lag` îl scrie în mesajul de rămânere în urmă, fiindcă acolo se
    # vede simptomul unui rând care nu încape. Repetat, poate diverge; deci se
    # verifică aici.
    from sentinel.selfcheck.checks import AGGREGATOR_MAX_BODY_BYTES

    assert AGGREGATOR_MAX_BODY_BYTES == rows_ceiling * number(ingest, "MAX_ROW_BYTES"), (
        "numărul din mesajul lui ship:lag nu mai e plafonul de corp al agregatorului")

    def write(body: str) -> Path:
        path = tmp_path / "sentinel.yaml"
        path.write_text(f"telegram:\n  enabled: false\nship:\n{body}", encoding="utf-8")
        return path

    # Exact plafonul receptorului trebuie să fie configurabil...
    cfg = load_config(write(f"  max_rows_per_batch: {rows_ceiling}\n"
                            f"  max_age_s: {age_ceiling}\n"))
    assert cfg.ship.max_rows_per_batch == rows_ceiling
    assert cfg.ship.max_age_s == age_ceiling

    # ...și un pas peste el trebuie să fie refuzat AICI, la încărcare, unde
    # mesajul numește câmpul — nu acolo, unde arată ca o rețea căzută.
    with pytest.raises(ConfigError, match="max_rows_per_batch"):
        load_config(write(f"  max_rows_per_batch: {rows_ceiling + 1}\n"))
    with pytest.raises(ConfigError, match="max_age_s"):
        load_config(write(f"  max_age_s: {age_ceiling + 1}\n"))

    # Sub-rândurile, de pe 20 august 2026. Au ajuns aici din `RECEIVER_ONLY` în
    # ziua în care `detections.event_ids` a devenit primul flux cu copii — vezi
    # nota de acolo. Aceeași formă ca mai sus, și din același motiv: un lot cu
    # prea mulți copii primește 413, iar `ship_once` nu-i citește niciodată
    # corpul, deci se vede ca un agregator căzut.
    children_ceiling = number(ingest, "MAX_CHILDREN_PER_ROW")
    cfg = load_config(write(f"  max_children_per_row: {children_ceiling}\n"))
    assert cfg.ship.max_children_per_row == children_ceiling
    with pytest.raises(ConfigError, match="max_children_per_row"):
        load_config(write(f"  max_children_per_row: {children_ceiling + 1}\n"))

    # Lista de reconciliere. Plafonul receptorului trebuie să fie CEL PUȚIN cât
    # cel al expeditorului: mai mic, expeditorul ar trimite o listă pe care
    # receptorul o refuză mereu, iar reconcilierea n-ar avea loc niciodată —
    # tăcut, fiindcă refuzul unei liste nu oprește lotul. E singurul dintre
    # plafoanele astea al cărui dezacord nu se vede nici măcar ca un flux oprit.
    from sentinel.report.shipper import MAX_PRUNE_KEYS as SENDER_PRUNE_KEYS
    prune = (root / "lib" / "prune.ts").read_text(encoding="utf-8")
    receiver_prune_keys = number(prune, "MAX_PRUNE_KEYS")
    assert receiver_prune_keys >= SENDER_PRUNE_KEYS, (
        f"receptorul acceptă {receiver_prune_keys} chei, expeditorul trimite "
        f"până la {SENDER_PRUNE_KEYS}: listele lungi ar fi refuzate în tăcere")

    # Plafonul pe lot e DERIVAT la receptor (`3 * MAX_ROWS_PER_BATCH`), deci nu e
    # un literal pe care `number` să-l poată citi. Se recalculează aici din
    # factorii lui, ca o schimbare a oricăruia dintre ei să pice.
    batch_ceiling = 3 * rows_ceiling
    cfg = load_config(write(f"  max_child_rows_per_batch: {batch_ceiling}\n"))
    assert cfg.ship.max_child_rows_per_batch == batch_ceiling
    with pytest.raises(ConfigError, match="max_child_rows_per_batch"):
        load_config(write(f"  max_child_rows_per_batch: {batch_ceiling + 1}\n"))

    # Și implicitele trebuie să încapă în plafoane, altfel o instalare curată nu
    # ar putea expedia nimic.
    default = load_config(write("  enabled: false\n"))
    assert default.ship.max_rows_per_batch <= rows_ceiling
    assert default.ship.max_age_s <= age_ceiling
    assert default.ship.max_children_per_row <= children_ceiling
    assert default.ship.max_child_rows_per_batch <= batch_ceiling


# Constantele agregatorului care NU sunt un contract cu expeditorul, fiecare cu
# motivul ei. Lista e o declarație, nu o scutire: dacă una dintre ele ajunge
# vreodată să mărginească ce poate trimite expeditorul, mutarea ei de aici în
# testul de acord e chiar munca pe care testul de mai jos o cere.
RECEIVER_ONLY = {
    # lib/ingest.ts
    "MAX_ROW_BYTES": "factor intern al plafonului de corp; expeditorul nu-l vede "
                     "separat, iar produsul e verificat în testul de acord",
    "MAX_BODY_BYTES": "derivat din MAX_ROWS_PER_BATCH; e repetat în ship:lag și "
                      "verificat în testul de acord",
    "CHUNK": "câte rânduri intră într-o instrucțiune SQL; nu mărginește lotul "
             "primit, doar felul în care se scrie",
    "DELETE_PARAM_BUDGET": "câți parametri se leagă într-un DELETE de curățare a "
                           "sub-rândurilor; taie instrucțiunea în bucăți, nu "
                           "refuză nimic din ce sosește",
    # lib/db.ts — `sql_mode` strict pe sesiune. Niciuna dintre cele trei nu
    # mărginește ce poate trimite expeditorul: ele decid ce REFUZĂ baza după ce
    # lotul a sosit. Expeditorul n-are ce să acorde aici, fiindcă geamăna de pe
    # server vorbește cu PostgreSQL, care e strict prin construcție — n-are un
    # `sql_mode` de potrivit.
    "REQUIRED_SQL_MODES": "lista de moduri cerute pe sesiunea MariaDB; e o "
                          "proprietate a receptorului, iar PostgreSQL n-are "
                          "echivalent de acordat",
    "SET_SESSION_SQL_MODE": "instrucțiunea care adaugă modurile la ce a pus "
                            "gazda; formă SQL, nu plafon pe lot",
    "READ_SESSION_SQL_MODE": "citirea de verificare, ca `SET`-ul să fie dovedit "
                             "prin efect și nu prin cod de retur",
    # `MAX_CHILDREN_PER_ROW` și `MAX_CHILD_ROWS_PER_BATCH` au STAT aici până pe
    # 20 august 2026, cu motivul „niciun flux cu copii nu e declarat la vreun
    # capăt". `detections.event_ids` le-a dat unul, iar testul din
    # `aggregator/tests/subrows.test.ts` s-a înroșit atunci și a cerut mutarea —
    # exact cum era scris că se va întâmpla. Sunt acum în testul de acord de mai
    # sus, verificate prin `load_config`.
    # lib/csp.ts — politica de securitate a conținutului, livrată prin meta-tag
    # fiindcă CDN-ul găzduirii înlocuiește antetul. Niciuna nu atinge protocolul:
    # sunt despre ce are voie să facă BROWSERUL cu o pagină, nu despre ce poate
    # trimite expeditorul. Sunt păzite de `tests/security-headers.test.ts`.
    "CSP_META_DIRECTIVES": "directivele care au efect într-un meta-tag; despre "
                           "browser, nu despre lot",
    "CSP_META": "politica gata compusă; idem",
    "CSP_META_TAG": "elementul pus primul în `<head>`; idem",
    # lib/prune.ts — `MAX_PRUNE_KEYS` NU e aici: el mărginește chiar ce trimite
    # expeditorul, deci e acordat în testul de limite de mai sus.
    "MAX_PRUNE_KEY_BYTES": "lungimea unei chei, egală cu lățimea coloanei de la "
                           "receptor; expeditorul nu poate produce o cheie mai "
                           "lungă decât ce încape în coloana LUI, iar dacă ar "
                           "produce-o, refuzul e purtarea corectă",
    # lib/chain.ts
    "PAGE": "câte rânduri se citesc dintr-o dată la parcurgerea arhivei; nu se "
            "vede din afara agregatorului",
    "CHAINED_STREAM": "numele fluxului cu lanț, scris o dată ca felul cursorului "
                      "și cursorul din bază să fie citite despre ACELAȘI flux; "
                      "expeditorul are propria lui listă de fluxuri și nu "
                      "mărginește nimic din ce poate trimite",
    # lib/purge-automation.ts — curățarea istoricului deja replicat al
    # automatizărilor. Nimic de aici nu ajunge pe sârmă și nimic nu refuză un
    # lot: unealta se rulează de mână, după ce lotul a sosit demult.
    "TABLE": "tabela pe care o curăță unealta de întreținere; expeditorul își "
             "numește singur fluxurile și nu află de constanta asta",
    "REAL_TTY": "tiparul de terminal real, geamăn cu `logins.REAL_TTY_SQL` de pe "
                "server. NU mărginește nimic din ce se trimite — decide ce se "
                "ȘTERGE după. Că cele două tipare acceptă și resping aceleași "
                "valori se ține mecanic, în "
                "`tests/unit/test_purge_automation_commands.py`, care compilează "
                "tiparul CITIT din fișierul TypeScript",
    "SIZE_SQL": "interogarea de mărime a tabelei, pentru raportul dinainte/după; "
                "formă SQL locală, nu plafon pe lot",
    "SESSIONS_TABLE": "tabela de sesiuni, din care unealta CITEȘTE și căreia îi "
                      "aduce `commands_purged` la zi; nu se șterge din ea și nu "
                      "are nicio legătură cu ce poate trimite expeditorul",
    "PURGED_SQL": "instrucțiunea care adună câte rânduri a șters curățarea DE "
                  "AICI. Scrie NUMAI `commands_purged` — `command_count` rămâne "
                  "al gazdei, adus de expediere și rescris la fiecare lot, deci "
                  "o valoare pusă local ar fi oricum înlocuită",
    "COLLATION": "colația sub care se compară `username` și `tty` la ștergere, în "
                 "locul celei CI a coloanei. E o proprietate a MariaDB; "
                 "PostgreSQL n-are ce acorda, fiindcă e sensibil la majuscule "
                 "prin construcție",
    "COLLATION_PROBE_SQL": "întrebarea pusă serverului înainte de orice ștergere, "
                           "ca să se dovedească prin EFECT că marcajul de colație "
                           "chiar se aplică; nu atinge sârma",
    "COLLATION_PROBE_PARAMS": "valorile probei — `PTS0`, `pts0`, `' pts0'` și un "
                              "nume de cont cu majuscule; idem",
    "COLLATION_PROBE_EXPECTED": "ce răspunde GAZDA la aceleași patru întrebări. "
                                "E un acord între cele două motoare, dar unul "
                                "probat pe server la rulare, nu unul care "
                                "mărginește un lot",
    # lib/envelope.ts — plicul de transport. Cele două plafoane și forma
    # plicului SUNT un contract cu expeditorul și sunt mai jos, în
    # CROSS_LANGUAGE; astea două nu sunt.
    "INFLATE_CHUNK": "cât scoate zlib într-o bucată, adică marginea de eroare a "
                     "opririi decomprimării. Nu mărginește nimic din ce poate "
                     "trimite expeditorul: un plic care trece de plafon e "
                     "refuzat la fel oricât de mari ar fi bucățile",
    "BASE64": "alfabetul base64 standard, verificat înainte de decodare fiindcă "
              "`Buffer.from` e îngăduitor. Expeditorul emite base64 standard "
              "prin `base64.b64encode`; nu e un plafon, e forma pe care o "
              "produc amândouă capetele fără să se pună de acord",
    # lib/ship-keys.ts
    "SHIP_SECRET_FIELD": "numele coloanei din care se citește cheia; nu iese pe sârmă",
    # lib/register.ts — instrumentul de înregistrare
    "MIN_SHIP_SECRET_LENGTH": "mărginește o valoare ÎMPĂRȚITĂ cu expeditorul, dar o "
                              "încălcare se vede la înregistrare, cu mesaj, nu ca flux "
                              "oprit peste săptămâni — deci nu e din clasa plafoanelor "
                              "de lot",
    "MAX_SEALED_LENGTH": "lățimea coloanei `ship_secret_enc` din schema "
                         "agregatorului; mărginește TEXTUL CIFRAT, nu ce poate "
                         "trimite expeditorul",
    "LIST_COLUMNS": "coloanele afișate de `list`; nu apare în protocol",
    # lib/finding-groups.ts
    "GROUPS": "cele trei grupe in care panoul imparte starile unei "
              "constatari; e o preferinta de afisare, iar expeditorul nu "
              "stie ca exista",
    # lib/data/selfcheck.ts
    "SEVERITY": "ordinea in care se asaza starile de autodiagnostic pe "
                "ecran; e o preferinta de afisare a panoului, iar "
                "expeditorul nu stie ca exista",
    # lib/panel-page.ts
    "PAGES": "meniul panoului: adresa, numele și fluxul de care atârnă "
             "fiecare pagină. Numele de flux de acolo sunt CITITE, nu impuse "
             "— o pagină care numește un flux inexistent nu refuză nimic, "
             "doar rămâne pe mesajul „nu a sosit niciodată”. Nu mărginește "
             "niciun lot.",
    "USAGE": "textul de ajutor al instrumentului",
    "PRAG_TENDINTA": "sub cate rânduri se scrie diferența brută în loc de "
                     "procent; o alegere de lizibilitate a cartonașelor",
    "BANDA": "lățimea benzii de proporții, în unitățile ei de desen",
    "ORE_IN_GRAFIC": "câte ore se DESENEAZĂ pe pagina de sumar; e o alegere de "
                     "lățime a graficului, nu o limită asupra a ce poate sosi. "
                     "Micșorată, panoul arată mai puțin; expeditorul nu află.",
    # lib/chart.ts — geometrie de desen. Niciuna nu mărginește un lot: sunt
    # coordonate într-un `viewBox`, iar `viewBox`-ul nu ajunge niciodată la
    # expeditor.
    "STACK_SOURCES": "câte surse capătă culoare proprie în graficul stivuit; "
                     "restul se ADUNĂ într-o bandă numită, deci nu se pierde "
                     "nimic și expeditorul n-are de unde afla",
    "ALTELE": "numele benzii în care se adună sursele din coada clasamentului",
    "MIN_SLICE": "lățimea minimă a unei felii din bandă, ca un `critical` "
                 "singur între o mie de `low` să nu dispară sub un pixel",
    "CHART_W": "lățimea sistemului de coordonate al graficului",
    "CHART_H": "înălțimea sistemului de coordonate al graficului",
    "PAD_L": "marginea din stânga a suprafeței de desen, unde încap etichetele "
             "axei verticale",
    "PAD_R": "marginea din dreapta a suprafeței de desen",
    "PAD_T": "marginea de sus a suprafeței de desen",
    "PAD_B": "marginea de jos a suprafeței de desen, unde încap etichetele de oră",
    "MAX_TICKS": "câte gradații se pun pe axa verticală; o alegere de lizibilitate",
    "HOUR_MS": "o oră în milisecunde — o conversie de unități, nu o limită",
    # lib/data/overview.ts — ferestre de INTEROGARE ale panoului.
    "WINDOW_HOURS": "peste câte ore se însumează cifrele de pe cartonașele de "
                    "sumar; panoul alege ce ARATĂ din ce a sosit, iar "
                    "expeditorul nu e mărginit de fereastra asta",
    "SERIES_HOURS": "câte ore intră în seria orară citită pentru grafic; idem",
    "RANK_LIMIT": "câte rânduri se citesc pentru un clasament; o tăiere la "
                  "afișare, nu o limită de lot",
    "ACTIVITY_LIMIT": "câte intrări se arată în firul de activitate recentă",
    "EMPTY": "sumarul gol servit când o instanță n-a trimis încă nimic; e o "
             "valoare implicită de afișare",
    "FINDING_OPEN": "ce stări ale unei constatări mai cer ceva de la operator; "
                    "e o citire a datelor sosite, nu o limită asupra lor",
    "BARE_DATETIME": "forma în care MariaDB scrie un `DATETIME(6)` ca text; e "
                     "un fapt despre DRIVER, nu un număr pe care expeditorul "
                     "l-ar putea încălca",
    "SEVERITY_ORDER": "ordinea în care se așază severitățile pe ecran; o "
                      "preferință de afișare, ca `SEVERITY` de mai sus",
    # lib/streams.ts
    "INCIDENTS": "declarația fluxului `incidents` la receptor; coloanele lui sunt "
                 "ținute în acord cu expeditorul de "
                 "test_aggregator_stream_columns.py, nu de o limită numerică",
    "STREAMS": "registrul fluxurilor cunoscute; un flux necunoscut nu e o limită, "
               "e o absență — și e raportat prin lipsa din `accepted`",
    "LINK_PARENTS": "ce tabelă de legătură atârnă de care părinte; e un fapt "
                    "despre schema REPLICII, nu un număr pe care expeditorul "
                    "l-ar putea încălca",
    "AUDIT_LOG": "definiția unui flux din registru, nu o limită",
    "FINDINGS": "declarația fluxului `findings` la receptor; o declarație "
                "nu mărginește niciun lot",
    "BLOCKLIST": "declarația fluxului `blocklist` la receptor; idem",
    "PATCH_PLANS": "declarația fluxului `patch_plans` la receptor; idem",
    # lib/retention.ts — ce TAIE replica din ea însăși. Niciuna nu mărginește
    # ce poate trimite expeditorul: sunt despre ce se șterge după ce a sosit.
    "BATCH": "câte rânduri șterge o singură instrucțiune de retenție; ține "
             "lock-ul InnoDB scurt, ca ingestia să nu expire în timpul tăierii",
    "AUTOMATION_DAYS": "câte zile trăiesc pe replică comenzile unei sesiuni "
                       "fără terminal. Măsurat: 405 777 de comenzi pentru un "
                       "singur deploy. E o politică de ȘTERGERE, nu o limită "
                       "asupra a ce poate sosi",
    "MAX_BATCHES": "câte tranșe face o rulare de retenție, ca un cron să nu "
                   "rămână ore într-o buclă la prima trecere de după o restanță",
    "POLICIES": "ce tabele se taie și după câte zile. Ce nu e în listă nu se "
                "atinge — `audit_entries` e o arhivă înlănțuită prin hash",
    "SESSIONS_SHOWN": "câte sesiuni încap pe pagina de sesiuni; e o tăiere la "
                      "AFIȘARE, iar restul rămân în bază, netăiate",
    "COMMANDS_SHOWN": "câte comenzi se arată pentru o sesiune. Un deploy rulează "
                      "~17 000; pagina arată primele și SPUNE că a tăiat. Nu "
                      "mărginește nimic din ce poate trimite expeditorul — "
                      "plafonul lui e `max_rows_per_batch`",
    "LOGIN_SESSIONS": "declarația fluxului `login_sessions` la receptor; o "
                      "declarație nu mărginește niciun lot",
    "SESSION_COMMANDS": "declarația fluxului `session_commands` la receptor — "
                        "cel cu cel mai mare volum din toate zece, dar tot o "
                        "declarație: ce poate trimite expeditorul e mărginit de "
                        "`max_rows_per_batch`, nu de forma de aici",
    "SELFCHECK_STATE": "declarația fluxului `selfcheck_state` la receptor, "
                       "primul cu filigran text; tot o declarație, nu o limită",
    "EVENT_ROLLUP_1H": "declarația fluxului `event_rollup_1h` la receptor, primul "
                       "cu filigran de MOMENT; tot o declarație, nu o limită",
    "SCANS": "declarația fluxului `scans` la receptor; el dă paginii de "
             "vulnerabilități vârsta cifrei și faptul că ultima măsurătoare a "
             "eșuat. Tot o declarație, nu o limită",
    # lib/data/rollups.ts — cât se ARATĂ pe pagina Rapoarte, nu cât se poate
    # primi. Niciuna nu poate opri un flux: un lot sosește întreg oricare ar fi
    # ele, iar dacă pagina ar arăta prea puțin, asta se vede pe ecran.
    "HOURS_SHOWN": "câte ore se arată pe pagină; o limită de afișare, nu de "
                   "ingestie — lotul intră întreg oricum",
    "TOP_PER_HOUR": "câte surse se numesc într-o oră înainte de restul; pur "
                    "cosmetică",
    "MAX_ROWS_READ": "câte rânduri CITEȘTE pagina din arhiva deja scrisă; "
                     "mărginește o interogare a panoului, nu un lot primit",
    "DETECTIONS": "declarația fluxului `detections` la receptor; coloanele îi "
                  "sunt ținute în acord de test_aggregator_stream_columns.py, "
                  "iar o declarație nu mărginește niciun lot",
    "INCIDENT_TIMELINE": "declarația fluxului `incident_timeline` la receptor; "
                         "ca și celelalte două, coloanele îi sunt ținute în "
                         "acord de test_aggregator_stream_columns.py, iar o "
                         "declarație nu mărginește niciun lot",
    "CURSOR_KINDS": "mulțimea felurilor de cursor ale REPLICII; decide forma "
                    "scrierii la ingestie, nu ce poate trimite expeditorul",
    "TEXT": "marginea tipului MariaDB, nu o limită de protocol",
    "MEDIUMTEXT": "marginea tipului MariaDB",
    "LONGTEXT": "marginea tipului MariaDB",
    # lib/crypto.ts — cifrare în repaus, invizibilă expeditorului
    "MIN_MASTER_LENGTH": "lungimea secretului principal AL AGREGATORULUI",
    "SHIP_SECRET_INFO": "eticheta HKDF a agregatorului; nu apare în protocol",
    "VERSION": "prefixul jetonului cifrat în repaus",
    "IV_BYTES": "parametru AES-GCM al cifrării în repaus",
    "TAG_BYTES": "parametru AES-GCM al cifrării în repaus",
    "KEY_BYTES": "parametru AES-GCM al cifrării în repaus",
    # lib/env.ts, lib/db.ts — configurația agregatorului
    "REQUIRED_REASONS": "de ce e obligatorie fiecare variabilă de mediu A "
                        "AGREGATORULUI; text pentru operator, nu o limită pe "
                        "care o vede expeditorul",
    "DEFAULT_POOL_SIZE": "dimensiunea pool-ului agregatorului",
    "MAX_POOL_SIZE": "dimensiunea pool-ului agregatorului",
    "POOL_KEY": "cheia sub care stă pool-ul pe globalThis",
    # lib/migrate.ts, lib/sql-statements.ts, lib/syntax-check.ts — migrațiile,
    # care nu ating protocolul de sincronizare
    "MIGRATIONS_DIR": "cale locală a agregatorului",
    "BOOTSTRAP_FILE": "nume de fișier de migrație",
    "LOCK_NAME": "numele lacătului de migrație",
    "LOCK_TIMEOUT_S": "cât se așteaptă lacătul de migrație",
    "NAME_RE": "forma numelui unui fișier de migrație",
    "IDENT": "formă de identificator SQL în parserul de migrații",
    "ER_UNSUPPORTED_PS": "cod de eroare MariaDB la verificarea de sintaxă",
    "PROBE_NAME": "numele instrucțiunii pregătite la verificarea de sintaxă",
    "PROBE_VAR": "numele variabilei de sesiune la verificarea de sintaxă",
    # app/api/sentinel/sync/route.ts
    "DEFAULT_MAX_AGE_S": "implicit folosit DOAR când expeditorul nu trimite câmpul; "
                         "nu poate refuza nimic din ce a configurat cineva",
    "NO_STORE": "antet de răspuns, nu o limită",
    "REFUSED": "corpul unui refuz, nu o limită",
    "STREAM_STATUS": "harta cod-de-stare, nu o limită",
    "STREAM_RANK": "ordinea gravității, nu o limită",
    # lib/auth/ — autentificarea PANOULUI agregator. Expeditorul nu vede nimic
    # din ea: nu se autentifică prin ea (are cheia lui de instanță) și nu-i
    # trimite niciodată date. Ce e totuși în acord cu serverul e în
    # CROSS_LANGUAGE, pinuit de test_aggregator_auth_parity.py.
    "TOTP_SECRET_BYTES": "lungimea unui secret TOTP nou al panoului; secretele "
                         "agregatorului sunt ale lui, nu circulă spre server",
    "TOTP_SECRET_INFO": "eticheta HKDF a cheii de TOTP a panoului; nu apare "
                        "nicăieri în afara agregatorului",
    "TOTP_SECRET_FIELD": "numele coloanei care intră în AAD; nu iese pe sârmă",
    "BASE32_ALPHABET": "alfabetul RFC 4648 al secretelor TOTP; e o constantă a "
                       "standardului, nu o limită pe care ar putea-o încălca "
                       "expeditorul",
    "SESSION_ID_BYTES": "lungimea id-ului opac de rând al unei sesiuni a "
                        "panoului; nu e credențialul și nu pleacă nicăieri",
    "MAX_CONCURRENT_ARGON2": "câte verificări de parolă ale PANOULUI pot fi în "
                             "zbor deodată; plafonează memoria procesului de pe "
                             "găzduire, nu ce poate trimite expeditorul — el nu "
                             "trece prin autentificarea panoului, are cheia lui "
                             "de instanță",
    "MAX_QUEUED_ARGON2": "câte cereri de autentificare ale panoului așteaptă la "
                         "semafor înainte de refuz; e o limită a rutei de login, "
                         "invizibilă expeditorului",
    "COLUMNS": "coloanele citite din `sessions` de panou; nu apare în protocol",
    # lib/auth/ — piesa 2: rutele, CSRF, limitarea de rată, antetele.
    #
    # Niciuna nu mărginește ce poate trimite expeditorul, și motivul e același
    # pentru toate: `POST /api/sentinel/sync` nu trece prin nimic de aici. Se
    # autentifică prin semnătura HMAC a cheii de instanță, are propria rută,
    # propriile plafoane (`MAX_BODY_BYTES`, `MAX_ROWS_PER_BATCH`) și propriul
    # cod de răspuns. Un plafon de formular de login atins de un lot de
    # sincronizare ar însemna că lotul a nimerit ruta greșită.
    #
    # Câteva dintre ele OGLINDESC valori de pe server (`security.py`), dar
    # oglindirea aia nu e un contract pe sârmă: panoul serverului și panoul
    # agregatorului sunt două aplicații separate, cu utilizatori separați și cu
    # sesiuni separate. Ce chiar TREBUIE să fie identic — parametrii Argon2id,
    # fereastra TOTP, forma jetonului — e în CROSS_LANGUAGE_AUTH, unde
    # apartenența se verifică prin efect.
    "CLIENT_IP_HEADER_ENV": "numele variabilei prin care operatorul declară "
                            "antetul de adresă măsurat pe găzduire; e "
                            "configurația agregatorului, nu ceva ce vede "
                            "expeditorul",
    "CLAIMED_HEADERS": "antetele citite DOAR pentru urma de audit când nu există "
                       "unul de încredere; nimic nu se decide din ele",
    "CLAIMED_MAX_CHARS": "cât din adresa pretinsă încape în `login_attempts."
                         "detail`; mărginește un text de diagnostic al panoului",
    "PREAUTH_CSRF_COOKIE": "numele cookie-ului CSRF al formularului de login; nu "
                           "iese pe sârmă spre nicio instanță",
    "PREAUTH_CSRF_TTL_S": "cât trăiește jetonul CSRF pre-autentificare al "
                          "panoului; expeditorul nu are formulare",
    "PREAUTH_CSRF_INFO": "eticheta HKDF a cheii cu care se semnează jetonul "
                         "pre-auth; locală agregatorului",
    "NONCE_BYTES": "lungimea nonce-ului CSRF pre-auth al panoului",
    "CONTENT_SECURITY_POLICY": "antet de răspuns al PANOULUI; acordul lui e cu "
                               "vhostul nginx al serverului, ținut de "
                               "test_aggregator_csp_parity.py, nu cu expeditorul",
    "SESSION_COOKIE": "numele cookie-ului de sesiune al panoului",
    "MAX_FORM_BYTES": "cât are voie să aibă un formular de autentificare; ruta de "
                      "sincronizare are propriul plafon (`MAX_BODY_BYTES`), "
                      "verificat în testul de acord",
    "FORM_CONTENT_TYPE": "tipul de conținut acceptat de formularele panoului; "
                         "lotul de sincronizare e JSON pe altă rută",
    "SESSION_TTL_S": "cât trăiește o sesiune a panoului; nu atinge nicio cerere "
                     "de sincronizare",
    "BUSY_RETRY_AFTER_S": "cât i se spune să aștepte celui care a picat pe coada "
                          "de Argon2 a panoului",
    "ARGON2ID_PHC": "forma unui hash pe care panoul îl poate citi; deosebește un "
                    "rând stricat de o parolă greșită, nu mărginește nimic",
    "BAD_CREDENTIALS": "textul unic al refuzului de credențiale; un mesaj, nu o "
                       "limită",
    "FAILURE_WINDOW_MINUTES": "fereastra numărătorilor de limitare a PANOULUI",
    "IP_FAILURE_LIMIT": "câte eșecuri de autentificare acceptă panoul de la o "
                        "sursă; expeditorul nu se autentifică prin panou",
    "GLOBAL_FAILURE_LIMIT": "plafonul global de eșecuri de autentificare ale "
                            "panoului; apără memoria procesului de pe găzduire, "
                            "nu refuză niciun lot",
    "MAX_FAILED_LOGINS_WITH_TRUSTED_IP": "pragul per cont, pe fereastra "
                                         "alunecătoare, când adresa sursei e "
                                         "de încredere",
    "MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP": "pragul per cont, mai strict, când nu "
                                            "există o sursă de încredere",
    "THROTTLE_RETRY_AFTER_S": "cât i se spune să aștepte celui limitat de panou",
    "ESCAPES": "tabela de escapare HTML a paginilor panoului",
    "MAX_USERNAME_LENGTH": "lățimea coloanei `users.username` a agregatorului; "
                           "taie ce se tastează în formular, nu ce sosește prin "
                           "sincronizare",
    "MAX_DETAIL_LENGTH": "lățimea coloanei `login_attempts.detail` a agregatorului",
    "MAX_USER_AGENT_LENGTH": "lățimea coloanei `user_agent` a agregatorului",
    "USER_COLUMNS": "coloanele citite din `users` de panou; nu apare în protocol",
    "ATTEMPT_RESULTS": "vocabularul impus de `ck_login_attempts_result`; e o "
                       "constrângere a schemei agregatorului",
    "ATTEMPT_STAGES": "vocabularul impus de `ck_login_attempts_stage`",
    # lib/auth/, lib/data/ — piesa 3: autorizarea multi-instanță și unealta de
    # conturi.
    #
    # Niciuna nu mărginește ce poate trimite expeditorul, și motivul e din nou
    # același: `POST /api/sentinel/sync` nu trece prin autorizarea panoului. Ea
    # răspunde la „ce vede OMUL ăsta"; expeditorul nu e un om, are cheia
    # instanței lui și scrie doar în propria ei partiție.
    #
    # `MAX_PAGE` merită numit separat, fiindcă e singura de aici care ar putea fi
    # citită greșit ca plafon de protocol: mărginește câte rânduri IES spre panou
    # la o cerere de citire, nu câte INTRĂ într-un lot. Plafonul de intrare e
    # `MAX_ROWS_PER_BATCH`, e în CROSS_LANGUAGE, și e verificat la ambele capete.
    "INSTANCE_ROLES": "vocabularul impus de `ck_user_instances_role` și "
                      "`ck_users_role`; e o constrângere a schemei agregatorului, "
                      "iar expeditorul n-are roluri",
    "MAX_PAGE": "câte incidente întoarce cel mult o citire a PANOULUI; nu are "
                "nicio legătură cu câte rânduri poate trimite expeditorul "
                "într-un lot (vezi MAX_ROWS_PER_BATCH)",
    "DEFAULT_PAGE": "câte incidente întoarce o citire a panoului fără `?limit=`",
    "MAX_TIMELINE": "câte rânduri de cronologie citește PANOUL sub un incident, cu "
                    "tăierea raportată prin `timelineTruncated`; ca MAX_PAGE, "
                    "mărginește ce IESE spre un cont autentificat, nu ce poate "
                    "INTRA într-un lot (vezi MAX_ROWS_PER_BATCH)",
    "SUMMARY_COLUMNS": "coloanele citite din `incident_entries` pentru lista "
                       "panoului; o proiecție locală, nu ceva ce apare pe sârmă",
    "DETAIL_COLUMNS": "coloanele citite pentru pagina unui incident",
    "INSTANCE_COLUMNS": "coloanele citite din `instances` pentru panou; "
                        "`ship_secret_enc` NU e printre ele, dinadins",
    "TOTP_ISSUER": "ce scrie în aplicația de autentificare lângă numele contului "
                   "de panou; nu apare nicăieri în protocol",
    "GRANTED_BY": "cine a dat un drept, scris în `user_instances.granted_by` de "
                  "unealta de linie de comandă; urmă de audit locală",
    "FORBIDDEN_ARGS": "argumentele de linie de comandă pe care unealta de conturi "
                      "le REFUZĂ fiindcă ar purta o parolă prin `argv`; o regulă "
                      "a uneltei, nu o limită pe sârmă",
    "UNAUTHENTICATED": "corpul unic al refuzului rutelor de date ale panoului; un "
                       "mesaj, nu o limită",
    # lib/beat-keys.ts, lib/store.ts, lib/telegram.ts, lib/verify.ts,
    # lib/witness-page.ts — martorul, mutat în aplicația asta pe 18 august 2026.
    #
    # Niciuna nu mărginește ce poate trimite expeditorul de LOTURI: martorul e
    # celălalt receptor, cel de heartbeat, iar plafoanele lui de protocol
    # (`MAX_AGE_CEILING_S`, `DEFAULT_MAX_AGE_S`, `MAX_BODY_BYTES`) stau în
    # `app/api/sentinel/beat/route.ts`, pe care censusul de mai jos NU îl citește
    # — vezi nota de la `sources`.
    "DEFAULT_INSTANCE": "identitatea sub care intră un beat fără antet; e o "
                        "toleranță a receptorului pentru expeditorul vechi, nu o "
                        "limită pe care cineva o poate încălca",
    "PAIR_SEPARATORS": "ce desparte două perechi `<id>:<cheie>` în variabila de "
                       "mediu a găzduirii; o formă de configurație citită local, "
                       "care nu ajunge niciodată pe sârmă",
    "SECRET_CHARS": "alfabetul închis dintr-o cheie de heartbeat citită din "
                    "variabila de mediu; refuză un separator neanticipat, nu un "
                    "lot",
    "ID_FIELD": "cheia sub care un fișier de stare al martorului își scrie propria "
                "identitate; e o convenție pe disc, nu ceva ce se vede din afară",
    "RENAME_RETRY_CODES": "codurile de eroare pentru care redenumirea unui fișier "
                          "de stare se mai încearcă o dată; o purtare de sistem "
                          "de fișiere, nu de protocol",
    "RENAME_ATTEMPTS": "de câte ori se reîncearcă redenumirea aceea",
    "PREFIX": "textul cu care se deschid mesajele martorului pe Telegram, ca o "
              "confuzie deliberată cu ale serverului să se vadă; nu apare în "
              "protocol",
    "OK": "verdictul „nimic de raportat” al judecății martorului; o valoare "
          "internă a lui `judge()`",
    "MISSED_BEATS_BEFORE_ALARM": "câte intervale ratate consecutiv înseamnă "
                                 "alarmă; e o decizie a receptorului despre CÂND "
                                 "sună telefonul, iar expeditorul nu o poate "
                                 "încălca — el doar tace sau nu",
    "STALL_SECONDS": "cât pot sta contoarele pe loc cu semnalul sosind normal, "
                     "tot o decizie a receptorului despre când sună telefonul",
    "SUPPRESSIBLE_KINDS": "pentru care verdicte ale receptorului există un mesaj "
                          "gemene pe principal, deci martorul tace dacă acela a "
                          "livrat. Nu mărginește ce poate trimite expeditorul: "
                          "`readAlertedKinds` din beat/route.ts acceptă orice "
                          "cheie boolean în `alerted_kinds`, fără să verifice "
                          "apartenența la lista asta — un beacon poate trimite "
                          "`{\"orice\": true}` fără să fie refuzat. E o decizie a "
                          "receptorului despre CE verdict al LUI poate tăcea, nu "
                          "un plafon pe corp: o valoare greșită aici nu oprește "
                          "fluxul, cel mult pierde o suprimare legitimă — o "
                          "alertă în plus pe Telegram, nu un lot respins. Dacă "
                          "numele cheii diverge de la `beacon.py` (`selfcheck`), "
                          "`principalAlreadyDelivered` nu găsește cheia și cade "
                          "pe implicitul `false` — spre alertă, direcția sigură, "
                          "nu spre tăcere",
    "EXPLAIN": "textele care explică fiecare verdict pe pagina publică a "
               "martorului; interfață, nu protocol",
    "HEADLINE": "titlul arătat pentru fiecare verdict pe aceeași pagină",
}

# Constantele autentificării panoului, ținute SEPARAT de restul acordului
# trans-limbaj fiindcă apartenența la mulțimea asta e singura care se verifică
# MECANIC: `tests/unit/test_aggregator_auth_parity.py` cere ca puntea spre
# TypeScript să poarte exact numele de aici, și cere prin efect ca fiecare dintre
# ele să fie chiar comparat cu geamănul lui de pe server.
#
# Separarea are un motiv scris cu cerneală: până pe 17 august 2026, o constantă
# nouă în `lib/auth/session.ts` trecea censusul de mai jos doar scriindu-i numele
# aici. Un nume într-o mulțime Python era tratat drept dovadă că alt test îl
# verifică — adică jumătatea asta a censusului era pe cuvânt, iar cealaltă
# (`RECEIVER_ONLY`, unde intrările moarte pică) era mecanică.
#
# Fiecare valoare e cerută de la AMBELE capete acolo: parametrii Argon2id și
# marginile de parolă prin efect (hashul unuia verificat de celălalt), fereastra
# TOTP prin coduri identice, forma jetonului de sesiune prin `sessions.py`.
CROSS_LANGUAGE_AUTH = {
    "ARGON2_TIME_COST", "ARGON2_MEMORY_KIB", "ARGON2_PARALLELISM",
    "ARGON2_HASH_BYTES", "ARGON2_SALT_BYTES",
    "MIN_PASSWORD_LENGTH", "MAX_PASSWORD_LENGTH",
    "TOTP_DIGITS", "TOTP_INTERVAL_S", "TOTP_VALID_WINDOW",
    "SESSION_TOKEN_BYTES", "CSRF_TOKEN_BYTES", "PENDING_TOTP_TTL_S",
}

# Constantele care SUNT un contract cu expeditorul, deci trebuie verificate
# împotriva celuilalt capăt.
CROSS_LANGUAGE = CROSS_LANGUAGE_AUTH | {
    # test_the_two_ends_agree_on_the_batch_limits
    "MAX_ROWS_PER_BATCH", "MAX_AGE_CEILING_S",
    # Aceleași, pentru sub-rânduri. Au venit din `RECEIVER_ONLY` pe 20 august
    # 2026, când `detections.event_ids` a devenit primul flux cu copii.
    "MAX_CHILDREN_PER_ROW", "MAX_CHILD_ROWS_PER_BATCH",
    # Lista de reconciliere, de pe 21 august 2026. Receptorul trebuie să accepte
    # cel puțin cât trimite expeditorul — dezacordul aici nu se vede nici măcar
    # ca un flux oprit, fiindcă refuzul unei liste nu oprește lotul.
    "MAX_PRUNE_KEYS",
    # tests/unit/test_transport_envelope.py — plicul de transport, de pe
    # 25 august 2026. Forma lui e citită de receptor ÎNAINTE de semnătură: un
    # prefix, o etichetă de codare sau o versiune pe care cele două capete le
    # scriu diferit înseamnă că receptorul citește plicul ca JSON în clar, iar
    # semnătura pică — 401 la fiecare lot, adică exact ce arată o cheie greșită.
    # Plafoanele de decomprimare mărginesc chiar ce poate trimite expeditorul:
    # sub ele, fluxul se oprește cu 413 la fiecare rundă, iar `ship_once` nu
    # deosebește un non-2xx de altul.
    "ENVELOPE_ENCODING", "ENVELOPE_VERSION", "ENVELOPE_PREFIX",
    "MAX_INFLATED_BYTES", "MAX_INFLATE_RATIO", "MAX_WIRE_BYTES",
    # test_the_two_senders_agree_with_the_receiver_on_the_header_names
    "INSTANCE_HEADER", "SIGNATURE_HEADER",
    # test_the_identifier_shape_is_the_same_at_both_ends
    "ID_PATTERN",
    # test_the_shipper_has_its_own_key
    "SHIP_SECRET_ENV",
    # tests/unit/test_aggregator_chain.py — `prev_hash`-ul primului rând, scris
    # în două limbaje. Dacă diferă, începutul dovedit al lanțului nu se mai
    # recunoaște, iar o instalare curată rămâne veșnic cu capătul de jos
    # neverificat.
    "GENESIS_HASH",
    # tests/unit/test_aggregator_secret_form.py — modele ale parserului de
    # secrete al serverului, scrise în TypeScript. Sunt contracte cu alt limbaj,
    # nu limite ale receptorului: dacă se rup, instrumentul sigilează alți octeți
    # decât semnează serverul, iar simptomul e 401 la fiecare lot.
    "PY_SPACE_CLASS", "PY_EDGE", "LINE_BREAK_CHARS",
    # tests/unit/test_signing.py și aggregator/tests/canonical.test.ts —
    # marginile formei canonice peste care se semnează. Sunt scrise în ambele
    # limbaje și pinuite de corpusul comun de vectori: dacă diverg, cele două
    # capete produc octeți diferiți din același payload, iar simptomul e 401 la
    # fiecare bătaie — adică exact ce arată o cheie greșită.
    "MAX_DEPTH", "MAX_SAFE_INT",
    # Autentificarea panoului e mai sus, în CROSS_LANGUAGE_AUTH, fiindcă acolo
    # apartenența se verifică prin efect, nu se declară.
}


def test_the_identifier_shape_is_the_same_at_both_ends():
    """Un identificator pe care agregatorul îl consideră malformat e un 401.

    De pe server arată exact ca o cheie greșită: `ship_once` nu citește corpul,
    deci nu vede „identificator malformat". Iar identitatea nu se poate schimba
    — e scrisă în `/etc/sentinel/instance_id` —, deci fluxul acelei gazde e
    oprit permanent.

    Regula agregatorului trebuie deci să accepte ORICE identitate pe care o
    poate produce `sentinel/identity.py`, și să fie aceeași cu a martorului: o
    instanță acceptată de unul și refuzată de celălalt se vede ca „merge
    heartbeat-ul, nu merge sincronizarea".
    """
    import os
    import re
    from pathlib import Path

    from sentinel import identity

    root = Path(__file__).resolve().parents[2]
    ship = (root / "aggregator" / "lib" / "ship-keys.ts").read_text(encoding="utf-8")
    beat = (root / "aggregator" / "lib" / "beat-keys.ts").read_text(encoding="utf-8")

    def pattern(text: str) -> str:
        found = re.findall(r"^const ID_PATTERN = (.+);$", text, re.MULTILINE)
        assert len(found) == 1, f"{len(found)} definiții ID_PATTERN"
        return found[0]

    assert pattern(ship) == pattern(beat), (
        "ruta de loturi și cea de heartbeat acceptă forme diferite de identificator")

    # Și forma chiar acceptă TOT ce poate exista pe o gazdă. Identitatea e
    # produsă de `openssl rand -hex 16` în install.sh și validată aici de
    # `_INSTANCE_ID_RE`; deci candidații se generează din gramatica AIA, nu din
    # ce pare plauzibil. Regexul JavaScript e transcris în Python — aceeași
    # clasă de caractere, aceleași limite —, iar transcrierea e legată de textul
    # de mai sus printr-o aserțiune, ca o schimbare a formei să nu treacă
    # neobservată pe lângă ea.
    js = pattern(ship)
    assert js == "/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/", (
        f"forma s-a schimbat ({js}); transcrierea de mai jos nu mai e echivalentă")
    equivalent = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")

    candidates = ["0" * 32, "f" * 32, "0123456789abcdef" * 2]
    candidates += [os.urandom(16).hex() for _ in range(20)]
    for candidate in candidates:
        assert identity._INSTANCE_ID_RE.fullmatch(candidate), candidate
        assert equivalent.fullmatch(candidate), (
            f"identitatea {candidate} e validă pe gazdă și refuzată de agregator — "
            f"401 permanent, imposibil de reparat de acolo")


def test_every_receiver_constant_is_either_agreed_or_declared_receiver_only():
    """Întrebarea „expeditorul cunoaște numărul ăsta?" nu are voie să depindă de
    cine revizuiește.

    Trei runde la rând, aceeași clasă de defect a apărut pe altă constantă:
    receptorul mărginea ceva ce expeditorul nu putea descoperi, iar simptomul —
    orice non-2xx arată ca un agregator căzut, fiindcă `ship_once` nu citește
    niciodată corpul — e un flux oprit definitiv, nu o eroare de configurație.

    Deci întrebarea se pune AICI, mecanic: orice constantă a agregatorului ori e
    în testul de acord trans-limbaj, ori e pe lista de mai sus cu un motiv scris.
    O constantă nouă care nu e în niciuna dintre ele pică suita — pe mașina celui
    care o adaugă, nu peste trei runde.

    **Cât de tare e fiecare jumătate**, fiindcă nu sunt la fel de tari:

      * `RECEIVER_ONLY` e mecanică în amândouă direcțiile — o intrare pentru o
        constantă care nu mai există pică aici;
      * `CROSS_LANGUAGE_AUTH` e mecanică din 17 august 2026:
        `test_aggregator_auth_parity.py` cere ca puntea spre TypeScript să poarte
        exact numele astea (un nume inventat nu se poate importa, deci puntea nu
        pornește) ȘI, prin efect, ca fiecare să fie comparat cu geamănul lui de
        pe server. Înainte era pe cuvânt: numele scris aici era tratat drept
        dovadă că îl verifică altcineva;
      * restul lui `CROSS_LANGUAGE` — `MAX_ROWS_PER_BATCH`, `GENESIS_HASH`,
        formele parserului de secrete — e ÎNCĂ pe cuvânt: numele e scris aici, iar
        testul care îl pinuiește e numit într-un comentariu. Fiecare CHIAR e
        pinuit azi (verificat una câte una), dar nimic nu leagă mecanic cele două
        capete, iar mecanismul care ar face-o e cel de la autentificare: testul
        care pinuiește trebuie să EXPORTE ce a comparat. Scris aici ca lipsă
        cunoscută, nu ca lucru rezolvat.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "aggregator"
    # `rglob`, nu `glob`: `lib/auth/` e primul subdirector al lui `lib`, iar cu
    # tiparul plat recensământul nu l-ar fi văzut deloc — adică fix „constanta
    # următoare scapă", modul de eșec pentru care există regula. Un director nou
    # sub `lib` nu are voie să fie o poartă de ieșire din verificarea asta.
    sources = sorted((root / "lib").rglob("*.ts"))
    sources.append(root / "app" / "api" / "sentinel" / "sync" / "route.ts")
    assert len(sources) >= 7, f"prea puține fișiere găsite: {sources}"
    assert any(path.parent.name == "auth" for path in sources), (
        "recensământul nu vede `lib/auth/`; un subdirector nescanat e o listă de "
        "scutiri fără nume")

    found: dict[str, str] = {}
    for path in sources:
        # Adnotarea de tip e opțională în tipar: `const X: readonly T[] = …` e
        # tot o constantă, iar fără partea asta recensământul o rata — adică fix
        # „constanta următoare scapă", modul de eșec pentru care există.
        for match in re.finditer(r"^(?:export )?const ([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=",
                                 path.read_text(encoding="utf-8"), re.MULTILINE):
            found[match.group(1)] = path.name

    # Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
    assert len(found) >= 12, f"doar {len(found)} constante găsite: {found}"

    unclassified = {n: f for n, f in found.items()
                    if n not in RECEIVER_ONLY and n not in CROSS_LANGUAGE}
    assert not unclassified, (
        f"constante ale agregatorului neclasificate: {unclassified}. Fiecare "
        f"trebuie ori verificată în test_the_two_ends_agree_on_the_batch_limits "
        f"(dacă mărginește ce poate trimite expeditorul), ori pusă în "
        f"RECEIVER_ONLY cu motivul pentru care nu-l mărginește.")

    # Și lista nu are voie să adune intrări moarte: o scutire pentru o constantă
    # care nu mai există e o scutire care într-o zi acoperă altceva cu același nume.
    stale = sorted(set(RECEIVER_ONLY) - set(found))
    assert not stale, f"RECEIVER_ONLY conține constante care nu mai există: {stale}"
    assert CROSS_LANGUAGE <= set(found), sorted(CROSS_LANGUAGE - set(found))


def test_the_shipper_has_its_own_key(http):
    """O cheie comună cu beaconul înseamnă că root pe gazda A poate fabrica
    loturi în numele lui B — și invers, că o rotire a cheii de heartbeat oprește
    tăcut expedierea."""
    from pathlib import Path

    from sentinel.report import beacon

    assert shipper.SECRET_NAME != beacon.SECRET_NAME
    assert shipper.SECRET_NAME == "SENTINEL_SHIP_SECRET"

    # Și instrumentul care sigilează cheia pe agregator cere ACEEAȘI variabilă.
    # Un al doilea nume pentru aceeași valoare e un al doilea loc din care poate
    # lipsi: operatorul ar exporta ce scrie procedura, instrumentul n-ar găsi
    # nimic, iar mesajul l-ar trimite să caute o variabilă pe care tocmai a pus-o.
    tool = (Path(__file__).resolve().parents[2] / "aggregator" / "lib"
            / "secret-input.ts").read_text(encoding="utf-8")
    assert f'SHIP_SECRET_ENV = "{shipper.SECRET_NAME}"' in tool


# ---------------------------------------------------------------------------
# Identitatea, și ce nu are voie să lase în urmă o rundă care n-a trimis
# ---------------------------------------------------------------------------
def test_a_batch_without_an_identity_never_reaches_the_network(http, _identity):
    """Rândurile de audit ale două gazde fără identitate ar ajunge în aceeași
    găleată `default`, într-un singur lanț de hash-uri — care ar arăta rupt în
    permanență, la ambele capete, fără ca nimic să fie rupt."""
    _identity.unlink()
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is False
    assert http.calls == []
    assert db.sequence_calls == 0
    assert db.cursors["ship:audit_log"] == 8


def test_a_permanently_missing_identity_stops_looking_like_a_blip(caplog, http, _identity):
    """În jurnal, prima rundă ratată arată identic cu a suta. La al treilea eșec
    consecutiv linia trebuie să spună că nu e o clipire — și să poarte comanda
    care repară."""
    _identity.unlink()
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    with caplog.at_level("INFO", logger="sentinel.report.shipper"):
        for _ in range(3):
            run(shipper.ship_once(db, _cfg(), "k"))
        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, [r.getMessage() for r in caplog.records]
        assert errors[0].consecutive == 3
        assert "deploy.sh" in errors[0].action

        caplog.clear()
        _identity.write_text(ID_A, encoding="utf-8")
        run(shipper.ship_once(db, _cfg(), "k"))
        assert shipper._identity_failures == 0
        assert any(r.getMessage() == "shipper has an instance identity again"
                   for r in caplog.records)


def test_an_unsignable_batch_consumes_no_batch_number(http):
    """Numărul de lot e strict crescător și e verificat la celălalt capăt ca
    protecție la reluare. Consumat de o rundă care n-a trimis nimic, ar arăta
    acolo ca un lot pierdut — adică exact semnalul pe care îl căutăm."""
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    # Un float în configurație: Python îl scrie `300.0`, JavaScript `300`, deci
    # cele două capete nu pot calcula aceeași semnătură.
    assert run(shipper.ship_once(db, _cfg(max_age_s=300.0), "k")).ok is False
    assert http.calls == []
    assert db.sequence_calls == 0
    assert db.cursors["ship:audit_log"] == 8


# ---------------------------------------------------------------------------
# Pragul de backfill: o singură dată, la prima rundă, și niciodată tăcut
# ---------------------------------------------------------------------------
def test_the_first_round_starts_above_the_backfill_floor(http, caplog):
    """Pornită pe o gazdă cu un an de audit, expedierea nu urcă un an de rânduri.

    Ce nu are voie să facă e s-o facă tăcut: rândurile de sub prag nu vor pleca
    NICIODATĂ, deci faptul se scrie în jurnal atunci ȘI rămâne citibil, ca prag
    persistat, pentru operatorul care se uită luni mai târziu.
    """
    old = [_row(i, minutes_ago=60 * 24 * 30) for i in range(1, 6)]
    fresh = [_row(i, minutes_ago=5) for i in range(6, 9)]
    db = _DB(rows=old + fresh)
    with caplog.at_level("WARNING", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    sent = json.loads(http.calls[0]["body"])
    assert [r["id"] for r in sent["rows"]["audit_log"]] == [6, 7, 8]
    assert result.advanced == {"audit_log": 8}
    # Pragul e persistat, nu doar jurnalizat.
    assert db.cursors["ship:audit_log:floor"] == 5
    warned = [r for r in caplog.records if r.getMessage()
              == "shipper starts above a backfill floor"]
    assert len(warned) == 1
    assert warned[0].skipped_rows == 5


def test_a_backlog_that_grew_past_the_bound_is_not_skipped(http):
    """Odată ce cursorul există, vechimea nu mai sare peste nimic.

    O pană de o lună a agregatorului lasă în urmă rânduri mai vechi de
    `max_backfill_days`. A le sări atunci ar fi chiar pierderea permanentă și
    tăcută pe care o previne tot modulul — declanșată, ironic, de o pană a
    celuilalt capăt. Se recuperează integral, lot cu lot.
    """
    stale = [_row(i, minutes_ago=60 * 24 * 30) for i in range(1, 6)]
    db = _DB(rows=stale, cursors={"ship:audit_log": 0, "ship:audit_log:floor": 0})
    result = run(shipper.ship_once(db, _cfg(max_backfill_days=7), "k"))
    sent = json.loads(http.calls[0]["body"])
    assert [r["id"] for r in sent["rows"]["audit_log"]] == [1, 2, 3, 4, 5]
    assert result.advanced == {"audit_log": 5}


def test_the_floor_is_computed_once_and_not_at_every_round(http):
    """Recalculat la fiecare rundă, pragul ar urca odată cu ceasul și ar sări
    peste rândurile pe care agregatorul nu apucă să le primească într-o pană mai
    lungă de `max_backfill_days` — aceeași pierdere, cu altă cauză."""
    db = _DB(rows=[_row(i, minutes_ago=5) for i in range(1, 4)])

    # Numărat PE FLUX, nu global: de când `STREAMS` are mai mult de un flux
    # append-only, fiecare își așază propriul prag, iar un total ar crește cu
    # fiecare flux adăugat și ar trebui rescris — adică testul s-ar schimba
    # dintr-un motiv care n-are legătură cu proprietatea pe care o apără.
    def floors(table):
        return [q for q in db.queries
                if "coalesce(max(id), 0)" in q and f"FROM {table} " in q]

    run(shipper.ship_once(db, _cfg(), "k"))
    assert len(floors("audit_log")) == 1
    assert len(floors("incident_timeline")) == 1, (
        "un flux append-only adăugat nu și-a așezat pragul deloc")

    db.audit.append(_row(4, minutes_ago=1))
    run(shipper.ship_once(db, _cfg(), "k"))
    assert len(floors("audit_log")) == 1, "pragul s-a recalculat la a doua rundă"
    assert len(floors("incident_timeline")) == 1


# ---------------------------------------------------------------------------
# Codificarea rândurilor
# ---------------------------------------------------------------------------
def test_a_row_carries_the_columns_the_chain_is_built_from(http):
    """Fără `prev_hash` și `entry_hash` neatinse, agregatorul nu poate verifica
    înlănțuirea — proprietatea pe care docs/PLAN-arhitectura-distribuita.md §5 o
    declară azi imposibilă și care e chiar motivul pentru care fluxul ăsta e
    primul."""
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    run(shipper.ship_once(db, _cfg(), "k"))
    row = json.loads(http.calls[0]["body"])["rows"]["audit_log"][0]
    assert {"id", "prev_hash", "entry_hash", "params", "at"} <= set(row)
    assert row["prev_hash"] == f"{8:064d}" and row["entry_hash"] == f"{9:064d}"
    # `at` pleacă drept șir ISO: un datetime nu are formă canonică comună.
    assert row["at"].startswith(str(NOW.year))


def test_a_jsonb_column_travels_as_text():
    """Despachetat într-un dicționar, `params` ar putea conține un float — un
    scor, o durată — iar contractul de semnare refuză float-urile fără excepție.
    Fluxul s-ar bloca definitiv pe un rând perfect valid."""
    assert shipper.encode_value('{"a":1.5}', "x") == '{"a":1.5}'
    with pytest.raises(shipper.ShipEncodingError):
        shipper.encode_value({"a": 1.5}, "audit_log[9].params")


def test_a_column_type_nobody_taught_it_is_refused_by_name():
    """Un `str(x)` peste orice tip necunoscut e un al doilea serializator,
    ascuns, pe care celălalt capăt nu-l cunoaște. Refuzul numește coloana, ca
    operatorul să nu caute într-un rând cu unsprezece câmpuri.

    Exemplul era `Decimal`; acum e `float`, fiindcă `Decimal` a fost ÎNVĂȚAT
    dinadins (are formă canonică de șir, iar drumul dus-întors e exact — vezi
    `encode_value`). `float` rămâne refuzat tocmai pentru că nu are proprietatea
    aia: `0.1` n-are reprezentare exactă, iar două implementări pot scrie șiruri
    diferite. Regula n-a slăbit, doar a fost spusă mai precis."""
    with pytest.raises(shipper.ShipEncodingError) as exc:
        shipper.encode_value(1.5, "audit_log[9].cost")
    assert "audit_log[9].cost" in str(exc.value)


def test_an_ip_address_ships_as_its_canonical_string() -> None:
    """Eșecul pe care îl previne: fluxul `detections` moare MUT la primul rând
    cu `src_ip`.

    `asyncpg` întoarce o coloană `inet` ca obiect de adresă, nu ca text. Fără
    ramura din `encode_value`, rândul e refuzat, fluxul stă pe loc — izolat de
    celelalte, fiindcă fiecare are `try`-ul lui — și singurul semn e restanța
    raportată de `ship:lag` ore mai târziu.

    Conversia e permisă din același motiv ca la `Decimal`, și testul cere exact
    proprietatea aia: forma de șir e canonică, iar drumul dus-întors e EXACT.
    Un `str()` care ar pierde ceva n-ar trece de a doua aserțiune.

    Receptorul are un fel de coloană `inet` care cere un șir și îi verifică
    forma canonică (`aggregator/lib/ingest.ts`), deci ce pleacă de aici trebuie
    să fie chiar aia — nu o formă „apropiată".
    """
    for text in ("203.0.113.9", "2001:db8::1", "::1", "0.0.0.0"):
        encoded = shipper.encode_value(ip_address(text), "detections[7].src_ip")
        assert isinstance(encoded, str), "adresa nu a plecat ca text"
        assert ip_address(encoded) == ip_address(text), (
            f"drumul dus-intors nu e exact pentru {text}: a iesit {encoded}")

    # Forma NEcanonica se canonizeaza la fel la ambele capete: `ip_address` o
    # normalizeaza, iar receptorul cere canonicul. Daca vreodata una dintre
    # parti ar accepta forma lunga, aici s-ar vedea.
    assert shipper.encode_value(ip_address("2001:0db8:0000:0000:0000:0000:0000:0001"),
                                "detections[7].src_ip") == "2001:db8::1"


def test_an_array_column_ships_as_objects_not_bare_integers() -> None:
    """Forma sub-randurilor pe sarma, ceruta de contractul receptorului.

    Elementul e un OBIECT cu un singur camp, nu un intreg gol. Nu e stil: unele
    tabele de legatura au doua campuri per element (`actor_attrs` are `kind` si
    `value`), iar doua forme de element ar fi fost doua cai de validare — inca un
    loc in care capetele pot sa nu fie de acord.

    Un intreg gol ar fi refuzat de receptor ca element malformat, lotul ar primi
    400, iar `ship_once` nu-i citeste niciodata corpul: se vede ca agregator
    cazut, la nesfarsit.
    """
    record = {"id": 7, "event_ids": [11, 12]}
    for column in shipper.DETECTION_STREAM.columns:
        record.setdefault(column, None)
    record["id"] = 7

    row, carried = shipper.encode_row(shipper.DETECTION_STREAM, record, 7, 1000)
    assert carried == 2
    assert row["event_ids"] == [{"event_id": 11}, {"event_id": 12}], (
        "sub-randurile nu au forma de obiecte pe care o cere receptorul")

    # Tabloul gol e o valoare valida — o detectie fara dovezi — si trebuie sa
    # plece ca tablou gol, nu sa lipseasca: un flux cu copii cere FIECARUI rand
    # sa poarte campul.
    record["event_ids"] = None
    row, carried = shipper.encode_row(shipper.DETECTION_STREAM, record, 7, 1000)
    assert row["event_ids"] == [] and carried == 0


def test_a_parent_over_the_child_ceiling_stalls_instead_of_being_trimmed() -> None:
    """Un rand cu prea multi copii nu se taie si nu se sare: opreste fluxul.

    Taiat, s-ar scrie o detectie cu jumatate din dovezile ei si nimic n-ar spune
    care jumatate. Sarit, rândul n-ar mai reveni niciodata — ce trece de cursor nu
    se retrimite. Oprit, se vede in `ship:lag` si mesajul numeste coloana.
    """
    record = {"id": 9, "event_ids": list(range(5))}
    for column in shipper.DETECTION_STREAM.columns:
        record.setdefault(column, None)
    record["id"] = 9

    with pytest.raises(shipper.ShipEncodingError) as exc:
        shipper.encode_row(shipper.DETECTION_STREAM, record, 9, 4)
    assert "event_ids" in str(exc.value)
    assert "5 sub-rânduri" in str(exc.value)


def test_the_batch_is_cut_short_when_the_child_budget_runs_out(http) -> None:
    """Bugetul de sub-randuri taie lotul; nu-l face refuzat.

    2000 de detectii cu cate cinci evenimente inseamna 10000 de copii, peste
    plafonul receptorului. Un lot refuzat nu se micsoreaza nicaieri — se
    retrimite identic, la nesfarsit. Taiat, cursorul avanseaza si restul pleaca
    runda urmatoare.

    Se probeaza prin EFECT: cate randuri au plecat chiar pe sarma, si ca lotul
    se declara `full` ca sa continue drenajul.
    """
    rows = [_detection(i, event_ids=[1, 2, 3]) for i in range(1, 6)]
    db = _DB(detections=rows, cursors={"ship:detections": 0})
    cfg = _cfg(max_child_rows_per_batch=7)

    batch = run(shipper.collect_stream(db, cfg, shipper.DETECTION_STREAM))
    assert len(batch.rows) == 2, (
        f"{len(batch.rows)} randuri pentru un buget de 7 copii cu 3 pe rand; "
        "al treilea ar fi dus totalul la 9")
    assert batch.full is True, (
        "lotul taiat nu s-a declarat plin, deci drenajul se opreste si restanta "
        "se recupereaza la cadenta de regim stationar")
    assert batch.watermark == 2, "filigranul nu e id-ul ultimului rand INCLUS"


def test_an_unencodable_row_stalls_visibly_instead_of_being_skipped(http, caplog):
    """A sări peste rândul pe care nu-l înțelege ar fi chiar pierderea tăcută.
    Fluxul stă pe loc, zgomotos, iar `ship:lag` raportează restanța."""
    db = _DB(rows=[_row(9, detail=1.5)], cursors={"ship:audit_log": 8})
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert http.calls == []
    assert db.cursors["ship:audit_log"] == 8
    assert any("cannot encode" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Programul de reîncercare
# ---------------------------------------------------------------------------
def test_the_retry_schedule_is_exponential_capped_and_computable():
    """Un `random()` chemat din buclă face programul imposibil de afirmat, iar
    atunci singurul lucru testat despre backoff e că există.

    Fără plafon, o pană lungă a agregatorului duce pauza la ore și restanța nu
    se mai recuperează după ce revine; fără creștere, un agregator căzut e
    lovit la fiecare 60 de secunde la nesfârșit.
    """
    ship = _ship(interval_s=60, backoff_base_s=30, backoff_max_s=3600)
    no_jitter = lambda: 0.0  # noqa: E731

    assert shipper.next_delay(0, ship, no_jitter) == 60.0
    assert shipper.next_delay(1, ship, no_jitter) == 30.0
    assert shipper.next_delay(2, ship, no_jitter) == 60.0
    assert shipper.next_delay(3, ship, no_jitter) == 120.0
    assert shipper.next_delay(10, ship, no_jitter) == 3600.0
    # Și nu explodează pe un contor care a crescut zile la rând.
    assert shipper.next_delay(100_000, ship, no_jitter) == 3600.0


def test_the_jitter_only_ever_shortens_the_wait():
    """Un jitter în sus face ca plafonul să nu mai fie plafon — iar plafonul e
    singura proprietate a backoff-ului care se poate afirma simplu și verifica."""
    ship = _ship(backoff_base_s=30, backoff_max_s=3600)
    for failures in (1, 5, 50):
        full = shipper.next_delay(failures, ship, lambda: 0.0)
        most = shipper.next_delay(failures, ship, lambda: 1.0)
        assert most < full
        assert most == pytest.approx(full * (1 - shipper.JITTER_RATIO))
        assert full <= ship.backoff_max_s


# ---------------------------------------------------------------------------
# Bucla
# ---------------------------------------------------------------------------
@pytest.fixture
def no_sleeping(monkeypatch):
    """O intrare neașteptată în buclă PICĂ, nu atârnă.

    Fără asta, un expeditor care intră în buclă când n-ar trebui nu produce un
    test roșu: produce `asyncio.sleep(60)` la nesfârșit. Testul nu se termină
    niciodată, iar suita nu spune „FAILED", spune nimic — exact ce s-a văzut aici
    când poarta de pornire avea `and` în loc de `or` și rularea completă a stat
    până a oprit-o cineva cu mâna. Un test care prinde bug-ul atârnând e un test
    pe care nimeni nu-l vede picând.
    """
    async def _never(seconds):
        raise AssertionError(
            f"expeditorul a intrat în buclă și a cerut o pauză de {seconds}s")

    monkeypatch.setattr(shipper.asyncio, "sleep", _never)


def test_a_disabled_shipper_exits_instead_of_looping(monkeypatch, no_sleeping):
    """Fără agregator configurat, serviciul spune o dată în jurnal și iese.
    Unitatea are Restart=on-failure tocmai ca ieșirea asta să nu devină buclă.

    Cele trei condiții sunt alternative, nu cumulative: `enabled: false` peste un
    `url` și o cheie rămase în fișier de la o probă trebuie să oprească
    expedierea. Cu `and`, gazda ar trimite rânduri în timp ce configurația spune
    că nu trimite, iar `check_ship_lag` ar raporta liniștit „oprită".
    """
    from sentinel import config as config_module

    monkeypatch.setattr(config_module, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: "k"))
    monkeypatch.setattr(shipper, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: "k"))
    run(shipper.run_forever(_DB(), _cfg(enabled=False)))
    run(shipper.run_forever(_DB(), _cfg(url="")))


def test_a_shipper_without_a_key_exits_rather_than_signing_with_nothing(
        monkeypatch, no_sleeping):
    """Cu o cheie goală, HMAC-ul se calculează fără să se plângă nimeni și
    receptorul refuză cu 401 la fiecare lot — de pe server, tăcere."""
    monkeypatch.setattr(shipper, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: ""))
    run(shipper.run_forever(_DB(), _cfg()))


def _fake_clock(monkeypatch, stop_after: int) -> tuple[list[float], list[float]]:
    """Ceas care înaintează exact cu pauzele dormite. Întoarce (ceasul, pauzele).

    Fără el, un test al buclei nu poate spune NIMIC despre cadență: `asyncio.sleep`
    e falsificat, deci timpul real nu se mișcă, iar termenul fiecărui flux rămâne
    în viitor la nesfârșit — bucla ar reface la infinit aceeași așteptare și
    fiecare pauză ar ieși egală cu prima. Un test care măsoară asta ar afirma
    „backoff-ul nu crește" despre un backoff care crește.

    Se oprește prin `KeyboardInterrupt` după `stop_after` pauze: o buclă fără
    ieșire nu produce un test roșu, produce o suită care atârnă.
    """
    clock = [0.0]
    delays: list[float] = []

    async def _sleep(seconds):
        delays.append(seconds)
        clock[0] += seconds
        if len(delays) >= stop_after:
            raise KeyboardInterrupt

    monkeypatch.setattr(shipper, "monotonic", lambda: clock[0])
    monkeypatch.setattr(shipper.asyncio, "sleep", _sleep)
    return clock, delays


def test_the_loop_survives_a_round_that_failed(monkeypatch, http):
    """Dacă o rundă eșuată ar urca excepția, serviciul ar muri, iar
    `Restart=on-failure` cu `StartLimitBurst=10` l-ar opri definitiv — expedierea
    ar rămâne oprită până când observă cineva.

    Un singur flux înregistrat, dinadins: de când contorul de eșecuri e al
    FLUXULUI și nu al buclei, pauza dintre două runde e cel mai apropiat termen
    peste fluxuri, deci cu două fluxuri șirul pauzelor nu mai e exponențiala
    niciunuia. Ce se probează aici e că un flux care eșuează la rând nu e lovit
    la aceeași cadență; cadența LUI e ce se citește. Împletirea a două fluxuri e
    întrebarea testului de mai jos.
    """
    monkeypatch.setattr(shipper, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: "cheie"))
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM,))
    http.echo = False
    http.body = '{"ok":true}'
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})

    _, delays = _fake_clock(monkeypatch, stop_after=3)
    with pytest.raises(KeyboardInterrupt):
        run(shipper.run_forever(db, _cfg()))

    assert len(delays) == 3, "bucla s-a oprit la prima rundă eșuată"
    # Pauzele cresc, deci un agregator căzut nu e lovit la aceeași cadență.
    # Intervalele nu se suprapun nici cu jitterul întreg (30·[0.75,1],
    # 60·[0.75,1], 120·[0.75,1]), deci comparația e o afirmație, nu un noroc.
    assert delays[1] > delays[0]
    assert delays[2] > delays[1]
    assert db.cursors["ship:audit_log"] == 8


def test_a_stalled_stream_does_not_drag_the_healthy_one_into_its_backoff(
        monkeypatch, http):
    """Eșecul pe care îl previne: `audit_log` pleacă o dată pe oră fiindcă
    `incidents` s-a poticnit pe un rând necodificabil.

    Măsurat pe codul dinaintea reparației, cu `incidents` blocat și `audit_log`
    cu restanță: runda întorcea un singur `ok=False` pentru amândouă, bucla îl
    număra ca eșec GLOBAL, iar pauza urca 30s, 60s, 120s… până la `backoff_max_s`.
    Adică `audit_log` — singura copie verificabilă a lanțului de audit din afara
    gazdei — expediat o dată pe oră în loc de o dată pe minut, și o restanță
    recuperată de `backoff_max_s / DRAIN_PAUSE_S` ori mai încet, din cauza unui
    rând din ALTĂ tabelă. Apoi `check_ship_lag` arăta cheia roșie pe `audit_log`,
    cu remedii despre CDN și `HTTP 413`, în timp ce cauza era în `incidents`.

    De ce testul se întinde pe mai multe runde, și nu poate altfel: pe O RUNDĂ,
    reparat și nereparat arată identic — în ambele cazuri `audit_log` pleacă și
    `incidents` nu. Diferența e ce se întâmplă la runda a doua și a treia, adică
    exact ce nu putea vedea testul dinainte.
    """
    monkeypatch.setattr(shipper, "get_secrets",
                        lambda *a, **k: SimpleNamespace(get=lambda *_: "cheie"))
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))

    db = _MutableDB(rows=[_row(i) for i in range(1, 6)],
                    # `title` float: rândul pe care `encode_value` îl refuză, deci
                    # `incidents` se oprește la fiecare rundă, la nesfârșit.
                    mutable=[_mrow(1, 5) | {"title": 1.5}],
                    cursors={"ship:audit_log": 0, "ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})

    # Cine a fost strâns în fiecare rundă, și la ce moment al ceasului. Cadența
    # unui flux nu se poate citi din șirul pauzelor buclei — aia e minimul peste
    # fluxuri —, deci se citește de unde chiar e: din rundele fluxului.
    rounds: list[tuple[float, tuple[str, ...]]] = []
    real_ship_once = shipper.ship_once

    async def spy(db_, cfg_, secret_, streams=None):
        rounds.append((clock[0], tuple(s.name for s in (streams or shipper.STREAMS))))
        return await real_ship_once(db_, cfg_, secret_, streams)

    monkeypatch.setattr(shipper, "ship_once", spy)
    clock, _delays = _fake_clock(monkeypatch, stop_after=6)
    with pytest.raises(KeyboardInterrupt):
        run(shipper.run_forever(db, _cfg(max_rows_per_batch=2)))

    audit_at = [t for t, names in rounds if "audit_log" in names]
    stuck_at = [t for t, names in rounds if "incidents" in names]
    audit_gaps = [b - a for a, b in zip(audit_at, audit_at[1:])]
    stuck_gaps = [b - a for a, b in zip(stuck_at, stuck_at[1:])]

    # Cinci rânduri, loturi de două: două runde pline (deci `DRAIN_PAUSE_S`) și
    # una parțială. Nici drenarea, nici regimul staționar nu văd exponențiala.
    assert audit_gaps[:2] == [shipper.DRAIN_PAUSE_S, shipper.DRAIN_PAUSE_S], \
        f"fluxul sănătos a fost pus în backoff-ul celui oprit: {rounds}"
    assert audit_gaps[2] == 60.0, \
        f"după drenare, cadența nu a revenit la interval_s: {rounds}"
    assert max(audit_gaps) <= 60.0, \
        f"o pauză a fluxului sănătos a trecut de interval_s: {audit_gaps}"
    assert db.cursors["ship:audit_log"] == 5, "restanța nu s-a drenat"

    # …iar fluxul oprit chiar intră în exponențială, singur. Fără partea asta,
    # testul ar trece și peste un cod care a scos backoff-ul cu totul.
    # Benzile sunt exponențiala lui `next_delay` cu jitterul întreg
    # (`backoff_base_s`·2ⁿ·[1−JITTER_RATIO, 1]) și NU se suprapun, deci creșterea
    # e o afirmație, nu norocul unei rulări.
    assert len(stuck_gaps) >= 2, f"prea puține runde ale fluxului oprit: {rounds}"
    for step, gap in zip((30.0, 60.0), stuck_gaps):
        assert step * (1 - shipper.JITTER_RATIO) <= gap <= step, \
            f"fluxul oprit nu și-a urcat propria pauză la {step}s: {stuck_gaps}"
    assert stuck_gaps[1] > stuck_gaps[0]
    assert db.cursors["ship:incidents"] == 0, "fluxul oprit a avansat peste rând"


# ---------------------------------------------------------------------------
# Ce depinde de altcineva
# ---------------------------------------------------------------------------
def test_the_id_cursor_is_safe_only_because_the_writer_serialises():
    """Cursorul pe `id` presupune că `id`-urile devin vizibile în ordine.

    `audit.record` ia `... ORDER BY id DESC LIMIT 1 FOR UPDATE` înainte de
    INSERT, deci al doilea scriitor așteaptă commit-ul primului. Scos lacătul —
    sau adăugat un al doilea scriitor fără el — o tranzacție care a luat id-ul
    100 și comite după ce s-a expediat 101 e sărită PENTRU TOTDEAUNA, fără ca
    nimic să raporteze lipsa. Testul păzește dependența, fiindcă ea trăiește în
    alt fișier decât cel care se sprijină pe ea.
    """
    import inspect

    from sentinel.db.repo import audit

    source = inspect.getsource(audit.record)
    assert "FOR UPDATE" in source, \
        "audit.record nu mai serializează scriitorii — cursorul pe id devine lossy"
    assert source.index("FOR UPDATE") < source.index("INSERT INTO audit_log")


def test_the_service_and_its_unit_are_registered():
    """O componentă scrisă și neînregistrată nu rulează niciodată, iar tăcerea ei
    arată identic cu „nimic de trimis"."""
    from pathlib import Path

    from sentinel.__main__ import SERVICES

    assert "ship" in SERVICES
    unit = (Path(__file__).resolve().parents[2] / "deploy" / "systemd"
            / "sentinel-shipper.service").read_text(encoding="utf-8")
    assert "ExecStart=/opt/sentinel/bin/sentinel ship" in unit
    # on-failure, nu always: un expeditor neconfigurat iese cu 0.
    assert "Restart=on-failure" in unit
    # Serviciu propriu, nu inclus în beacon: un bug aici nu are voie să fie o
    # pană de heartbeat.
    assert "sentinel-beacon" not in unit.replace("sentinel-beacon.", "")


def test_config_check_names_the_missing_key_instead_of_just_failing(monkeypatch, capsys):
    """`config-check` e diagnosticul, deci trebuie să NUMEASCĂ cheia lipsă.

    Refuzul propriu-zis e în altă parte și e probat în altă parte: fără cheie
    `run_forever` iese cu 0. Problema e că ieșirea aia arată identic cu
    „neconfigurat", iar operatorul care tocmai a pus `ship.enabled: true` nu are
    de unde ști care din cele trei condiții lipsește. Diferența e între o
    reparație de cinci secunde și o seară pierdută.
    """
    from types import SimpleNamespace as NS

    from sentinel import __main__ as cli
    from sentinel.config import Config

    cfg = Config()
    cfg.ship.enabled = True
    cfg.ship.url = "https://exemplu.test/api/sentinel/sync"
    monkeypatch.setattr("sentinel.config.get_config", lambda *a, **k: cfg)
    monkeypatch.setattr("sentinel.config.get_secrets",
                        lambda *a, **k: NS(has=lambda key: key != "SENTINEL_SHIP_SECRET"))

    rc = cli._config_check(NS(verbose=False))
    out = capsys.readouterr().out
    assert rc == 1, "config-check a raportat OK peste o cheie lipsă"
    assert "SENTINEL_SHIP_SECRET" in out, out

    # Și celălalt capăt: cu expedierea oprită, cheia nu e cerută. Un
    # config-check care se plânge pe fiecare gazdă de o cheie de care nu are
    # nevoie e unul peste care operatorul învață să treacă.
    cfg.ship.enabled = False
    assert cli._config_check(NS(verbose=False)) == 0
    assert "SENTINEL_SHIP_SECRET" not in capsys.readouterr().out


def test_the_service_module_exists_under_the_name_the_dispatcher_builds():
    """`__main__._run_service` importă `sentinel.services.<nume>_service`. Un
    nume care nu se potrivește iese cu 78 și scrie „not implemented yet in this
    build" — o unitate care pare instalată și nu rulează niciodată."""
    import importlib

    module = importlib.import_module("sentinel.services.ship_service")
    assert callable(module.main)


# ---------------------------------------------------------------------------
# Escaladarea: `ship:lag` în autodiagnostic
#
# Expeditorul nu are cale proprie de alarmare, dinadins. Ce se testează aici e
# că cele patru stări — neconfigurat, la zi, în urmă, nu pot spune — ajung la
# operator DIFERITE. Contopite, oricare pereche transformă unealta într-una care
# minte: „nu pot citi" raportat ca „la zi" e tăcere în formă de sănătate.
# ---------------------------------------------------------------------------
def _secrets(monkeypatch, present=True):
    from sentinel import config as config_module

    monkeypatch.setattr(config_module, "get_secrets",
                        lambda *a, **k: SimpleNamespace(has=lambda key: present))


def _lag_cfg(**over):
    return SimpleNamespace(ship=_ship(**over))


def _lag(db, cfg):
    from sentinel.selfcheck import checks

    return run(checks.check_ship_lag(db, cfg))


def test_shipping_that_is_switched_off_is_not_a_fault(monkeypatch):
    """Agregatorul nu există încă, iar `ship.enabled` e false pe fiecare gazdă.

    `unknown` ar ține permanent titlul lui /selfcheck pe „nu tot s-a putut
    verifica", pe fiecare instalare, pentru o stare normală — iar un avertisment
    care nu se stinge niciodată e unul pe care nimeni nu-l mai citește când chiar
    apare. Se spune cu voce tare, nu prin omiterea cheii.
    """
    results = _lag(_DB(), _lag_cfg(enabled=False))
    assert [r.key for r in results] == ["ship:lag"]
    assert results[0].status == "ok"
    assert results[0].facts["configured"] is False
    assert "oprită" in results[0].detail


def test_shipping_that_is_on_with_nowhere_to_send_is_a_finding(monkeypatch):
    """`enabled: true` cu `url` gol e invizibil din afară: serviciul spune o dată
    în jurnal și iese cu 0, deci unitatea e `inactive` și arată exact ca una pe
    care nimeni n-a pornit-o. Operatorul crede că expediază."""
    results = _lag(_DB(), _lag_cfg(url=""))
    assert results[0].status == "degraded"
    assert "ship.url" in results[0].detail


def test_shipping_that_is_on_without_a_key_is_a_finding(monkeypatch):
    """Aceeași tăcere, altă cauză. Fără `SENTINEL_SHIP_SECRET` expeditorul iese
    curat, iar diferența dintre „neconfigurat" și „configurat pe jumătate" e
    exact ce trebuie să citească operatorul."""
    _secrets(monkeypatch, present=False)
    results = _lag(_DB(), _lag_cfg())
    assert results[0].status == "degraded"
    assert "SENTINEL_SHIP_SECRET" in results[0].detail


def test_a_configured_shipper_that_never_ran_is_not_current(monkeypatch):
    """Cursorul lipsă nu e „la zi" — e „coada n-a fost citită niciodată".

    E și starea în care rămâne o gazdă pe care unitatea nu a fost pornită după
    ce operatorul a pus `enabled: true`, iar aia trebuie să se vadă: altfel
    configurația spune că expediază și nu pleacă nimic, la nesfârșit.
    """
    _secrets(monkeypatch)
    results = _lag(_DB(rows=[_row(1)]), _lag_cfg())
    assert results[0].status == "degraded"
    assert results[0].facts["cursor"] is None
    assert "sentinel-shipper" in results[0].action


def test_a_stream_that_is_up_to_date_is_ok(monkeypatch):
    """Și, odată cu asta: fiecare flux ÎNREGISTRAT își primește propria cheie.

    Nu e o aserțiune despre numărare. `_reconcile_state` șterge, la o rulare
    completă, fiecare rând pe care rularea nu l-a emis — deci un flux care nu-și
    emite cheia nu apare roșu, DISPARE din /selfcheck, iar un panou fără el arată
    exact ca o instalare pe care expedierea n-a fost pornită niciodată. Scrisă ca
    listă fixă, aserțiunea ar fi devenit falsă la al doilea flux fără să spună
    nimic despre proprietate; scrisă din `STREAMS`, rămâne despre ea.
    """
    _secrets(monkeypatch)
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 9})
    results = _lag(db, _lag_cfg())
    assert [r.key for r in results] == [f"ship:lag:{s.name}" for s in shipper.STREAMS], \
        "verificarea nu emite exact o cheie pentru fiecare flux înregistrat"
    audit = next(r for r in results if r.key == "ship:lag:audit_log")
    assert audit.status == "ok"
    assert audit.facts["pending"] == 0


def test_rows_written_a_moment_ago_are_not_a_backlog(monkeypatch):
    """Între două runde există mereu rânduri netrimise. Raportate ca defect, ar
    aprinde cheia la fiecare minut ocupat — iar o cheie care e roșie tot timpul
    e una peste care operatorul învață să treacă."""
    _secrets(monkeypatch)
    db = _DB(rows=[_row(9, minutes_ago=0.5)], cursors={"ship:audit_log": 8})
    assert _lag(db, _lag_cfg())[0].status == "ok"


def test_a_stream_that_stopped_moving_is_reported(monkeypatch):
    """Restanța veche e singurul simptom al unui cursor care nu avansează —
    adică al unui agregator care răspunde 200 fără ecou. Pe gazdă nu se oprește
    nimic, deci nimic altceva nu o arată."""
    _secrets(monkeypatch)
    db = _DB(rows=[_row(i, minutes_ago=200) for i in (9, 10)],
             cursors={"ship:audit_log": 8})
    result = _lag(db, _lag_cfg())[0]
    assert result.status == "degraded"
    assert result.facts["pending"] == 2
    assert "ecou" in result.action


def test_the_backlog_message_sends_the_operator_to_a_log_field_that_exists(
        monkeypatch, http, caplog):
    """Eșecul pe care îl previne: cheia roșie e pe `audit_log`, iar cauza e în
    `incidents` — și remediul îl trimite pe operator să caute un `params` uriaș
    într-o tabelă care n-are nicio vină.

    Cheia e a fluxului rămas în urmă, adică a EFECTULUI. Fluxurile scadente
    pleacă într-un LOT COMUN, deci un `HTTP 413` produs de rândurile unui flux
    oprește și fluxurile care încăpeau lejer. Singurul fapt care spune al cui
    rând a produs refuzul e compoziția lotului — și ea trebuie să existe chiar în
    linia de jurnal la care trimite `action`.

    De-aia testul are DOUĂ jumătăți, și separat n-ar dovedi nimic: că mesajul
    numește câmpul, și că expeditorul chiar îl scrie. Un remediu care trimite la
    un tipar inexistent e „grep după un tipar care n-a potrivit niciodată" din
    CLAUDE.md, adică o verificare care raportează „nimic în neregulă" pe vecie.

    Aceeași regulă pentru a doua cauză pe care mesajul o numea deloc: un rând
    necodificabil blochează fluxul LUI, n-are nicio treabă cu agregatorul, iar
    dinainte operatorul era trimis să caute un CDN și un `HTTP 413`.
    """
    # (1) Ce citește operatorul.
    _secrets(monkeypatch)
    db = _DB(rows=[_row(i, minutes_ago=200) for i in (9, 10)],
             cursors={"ship:audit_log": 8})
    behind = _lag(db, _lag_cfg())[0]
    assert behind.status == "degraded"
    assert "batch_streams" in behind.action, behind.action
    assert "altui flux" in behind.action, behind.action
    assert "cannot encode a row" in behind.action, behind.action

    # (2) Ce scrie expeditorul, cu ambele fluxuri în același lot refuzat.
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))
    http.status = 413
    shipped = _MutableDB(rows=[_row(91233)],
                         mutable=[_mrow(1, 5), _mrow(2, 6)],
                         cursors={"ship:audit_log": 91232, "ship:incidents": 0},
                         at={"ship:incidents": NOW - timedelta(hours=2)})
    with caplog.at_level("WARNING", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(shipped, _cfg(), "k"))

    rejected = [r for r in caplog.records
                if "rejected the batch" in r.getMessage()]
    assert len(rejected) == 1, [r.getMessage() for r in caplog.records]
    # Numele fluxurilor ȘI câte rânduri a dus fiecare: „incidents e în lot" nu
    # separă un flux care a trimis două rânduri de unul care a trimis două mii.
    assert rejected[0].batch_streams == "audit_log×1, incidents×2", \
        rejected[0].batch_streams
    # Și niciun flux din lot nu iese cu verdict de succes: refuzul e al lotului,
    # deci amândouă intră în exponențială, amândouă cu numele celuilalt în motiv.
    assert result.streams["audit_log"].ok is False
    assert result.streams["incidents"].ok is False
    assert "incidents×2" in result.streams["audit_log"].reason

    # (3) Și al doilea tipar la care trimite mesajul chiar e emis, cuvânt cu
    # cuvânt. Cerut aici, nu presupus din faptul că există o linie de `log.error`
    # undeva: textul din `action` e ce tastează operatorul.
    caplog.clear()
    unencodable = _MutableDB(rows=[_row(91234)],
                             mutable=[_mrow(3, 5) | {"title": 1.5}],
                             cursors={"ship:audit_log": 91233, "ship:incidents": 0},
                             at={"ship:incidents": NOW - timedelta(hours=2)})
    http.status = 200
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        run(shipper.ship_once(unencodable, _cfg(), "k"))
    assert any("cannot encode a row" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


def test_the_grace_window_follows_a_long_interval(monkeypatch):
    """Cu `interval_s` mare, o fereastră fixă de 15 minute ar raporta defect
    pentru un flux care e pur și simplu între două trimiteri."""
    _secrets(monkeypatch)
    db = _DB(rows=[_row(9, minutes_ago=40)], cursors={"ship:audit_log": 8})
    assert _lag(db, _lag_cfg(interval_s=3600))[0].status == "ok"
    assert _lag(db, _lag_cfg(interval_s=60))[0].status == "degraded"


def test_a_backlog_is_never_reported_as_a_dead_agent(monkeypatch):
    """`down` face titlul „SENTINEL NU FUNCȚIONEAZĂ COMPLET", care trebuie să
    însemne un singur lucru: nu se mai uită nimeni la server. O expediere rămasă
    în urmă nu oprește nici colectarea, nici detecția, nici blocarea — copia din
    afara gazdei e cea incompletă."""
    _secrets(monkeypatch)
    db = _DB(rows=[_row(i, minutes_ago=60 * 24 * 30) for i in range(9, 40)],
             cursors={"ship:audit_log": 8})
    assert _lag(db, _lag_cfg())[0].status == "degraded"


def test_a_check_that_cannot_look_says_so_instead_of_saying_ok(monkeypatch):
    """Contopit cu „la zi", un cursor imposibil de citit devine tăcere în formă
    de sănătate — și, fiindcă runner-ul reconciliază starea după cheile emise, ar
    șterge o restanță reală și nereparată, arătând operatorului o revenire care
    nu s-a întâmplat.

    Cheia e a FLUXULUI și e alta decât cea care poartă verdictul de restanță:
    `bad` e fals pentru `unknown`, deci sub aceeași cheie o restanță devenită
    necitibilă s-ar anunța ca revenire. Proprietatea aia are testul ei
    (`test_a_backlog_that_becomes_unreadable_is_not_announced_as_a_recovery`);
    aici se păzește forma din care ea decurge.
    """
    _secrets(monkeypatch)

    class _Broken(_DB):
        async def fetchval(self, sql, *a):
            raise RuntimeError("relatia collector_cursors nu exista")

    results = _lag(_Broken(), _lag_cfg())
    assert results, "verificarea nu a emis nicio cheie"
    assert {r.status for r in results} == {"unknown"}, results
    for r in results:
        assert r.key.endswith(":unreadable"), r
        assert r.key != f"ship:lag:{r.facts['stream']}", \
            "starea „nu pot spune” împarte cheia cu verdictul de restanță"
        assert "nu s-a putut citi" in r.detail


def test_the_check_emits_a_key_even_when_there_is_no_stream_to_report(monkeypatch):
    """O listă goală de rezultate nu e „nimic în neregulă", e „nicio cheie".

    `runner._reconcile_state` șterge, la o rulare completă, fiecare rând pe care
    rularea nu l-a emis. O ramură care întoarce `[]` își șterge deci propriul
    rând, iar verificarea DISPARE din /selfcheck în loc să se facă roșie —
    operatorul vede un panou fără `ship:lag`, ceea ce arată identic cu o
    instalare pe care expedierea n-a fost pornită niciodată. Azi `STREAMS` are o
    intrare fixă; ramura devine accesibilă când E3 leagă fluxurile de
    configurație, iar atunci eșecul e tăcut prin construcție.
    """
    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "lag", _no_streams)
    results = _lag(_DB(), _lag_cfg())
    assert len(results) == 1, "verificarea nu a emis nicio cheie"
    assert results[0].key == "ship:lag"
    assert results[0].status == "unknown"


async def _no_streams(db, streams=()):
    return []


class _StateDB:
    """Cât din `selfcheck_state` trebuie ca runner-ul să poată clasifica.

    Reimplementează în Python semantica instrucțiunilor SQL, deci dovedește
    clasificarea, nu SQL-ul. Ce nu poate arăta: dacă PostgreSQL acceptă
    `NOT (key = ANY($1::text[]))`.
    """

    def __init__(self):
        self.state: dict[str, dict] = {}
        self.notifications: list[str] = []

    async def fetch(self, sql, *a):
        assert "FROM selfcheck_state" in sql, sql
        return [dict(v) for v in self.state.values()]

    async def execute(self, sql, *a):
        if "INSERT INTO selfcheck_state" in sql:
            key, status, title, detail, _facts, keep_since = a
            old = self.state.get(key)
            self.state[key] = {
                "key": key, "status": status, "title": title, "detail": detail,
                "since": old["since"] if (old and keep_since) else NOW,
                "stale": False,
                "last_alert_at": old["last_alert_at"] if old else None,
            }
        elif "DELETE FROM selfcheck_state" in sql:
            keep = set(a[0])
            for key in [k for k in self.state if k not in keep]:
                del self.state[key]
        elif "UPDATE selfcheck_state SET last_alert_at" in sql:
            for key in a[0]:
                if key in self.state:
                    self.state[key]["last_alert_at"] = NOW
        elif "INSERT INTO notifications" in sql:
            self.notifications.append(a[-1])


def test_a_backlog_that_becomes_unreadable_is_not_announced_as_a_recovery(monkeypatch):
    """Restanță reală, apoi baza devine necitibilă. Operatorul NU are voie să
    citească „🟢 Revenit la normal”.

    E consecința care leagă cele două jumătăți ale regulii. `CheckResult.bad` e
    fals pentru `unknown`, iar runner-ul numește „revenit" orice cheie care era
    `degraded` și nu mai e `bad`. Deci dacă „în urmă" și „nu pot spune" ar sta
    sub ACEEAȘI cheie, un `collector_cursors` picat ar stinge o restanță
    nereparată cu un mesaj verde — și restanța ar rămâne acolo, nevăzută, cât
    timp baza nu se repară. Cheile diferite (`ship:lag:<flux>` față de
    `ship:lag`) fac ca dispariția să se anunțe ca retragere, nu ca revenire, iar
    testul ăsta păzește proprietatea la nivelul mesajului, nu al aserțiunii
    despre nume.
    """
    from sentinel.selfcheck import runner

    _secrets(monkeypatch)
    cfg = _lag_cfg()

    class _Broken(_DB):
        async def fetchval(self, sql, *a):
            raise RuntimeError("relatia collector_cursors nu exista")

    behind = _lag(_DB(rows=[_row(9, minutes_ago=500)],
                      cursors={"ship:audit_log": 8}), cfg)
    unclear = _lag(_Broken(), cfg)
    assert behind[0].status == "degraded" and unclear[0].status == "unknown"

    db = _StateDB()

    def _emit(results):
        async def _run_groups(_db, _cfg):
            from sentinel.selfcheck.checks import RunOutcome

            return RunOutcome(list(results), ())
        return _run_groups

    monkeypatch.setattr(runner, "run_groups", _emit(behind))
    run(runner.run_and_alert(db, cfg))
    assert "rămas în urmă" in db.notifications[-1]

    monkeypatch.setattr(runner, "run_groups", _emit(unclear))
    summary = run(runner.run_and_alert(db, cfg))
    assert summary["recovered"] == [], summary
    assert "Revenit la normal" not in db.notifications[-1], db.notifications[-1]
    assert "Nu se mai raportează" in db.notifications[-1]


def test_unreadable_secrets_are_not_reported_as_a_missing_key(monkeypatch):
    """`load_secrets` ridică dacă secrets.env e citibil de toată lumea. „N-am
    putut citi fișierul" și „cheia nu e acolo" cer lucruri diferite de la
    operator, iar prima nu are voie să treacă drept a doua."""
    from sentinel import config as config_module

    def _boom(*a, **k):
        raise RuntimeError("secrets.env is world-readable")

    monkeypatch.setattr(config_module, "get_secrets", _boom)
    result = _lag(_DB(), _lag_cfg())[0]
    assert result.status == "unknown"
    assert "secrets.env" in result.action


def test_the_floor_stays_visible_long_after_the_log_line_scrolled(monkeypatch):
    """Rândurile de sub pragul de backfill nu vor pleca NICIODATĂ. Faptul ăsta
    într-o singură linie de jurnal, scrisă la prima rundă, e un fapt pierdut —
    operatorul care se uită peste trei luni nu are de unde să-l afle."""
    _secrets(monkeypatch)
    db = _DB(rows=[_row(9)],
             cursors={"ship:audit_log": 9, "ship:audit_log:floor": 5})
    result = _lag(db, _lag_cfg())[0]
    assert result.status == "ok"
    assert "id 5" in result.detail and "niciodată" in result.detail


def test_the_four_states_are_actually_distinguishable(monkeypatch):
    """Aserțiunea de ansamblu, fiindcă fiecare test de mai sus privește o singură
    stare și contopirea a două se vede doar comparându-le."""
    _secrets(monkeypatch)
    off = _lag(_DB(), _lag_cfg(enabled=False))[0]
    current = _lag(_DB(rows=[_row(9)], cursors={"ship:audit_log": 9}), _lag_cfg())[0]
    behind = _lag(_DB(rows=[_row(9, minutes_ago=500)],
                      cursors={"ship:audit_log": 8}), _lag_cfg())[0]

    class _Broken(_DB):
        async def fetchval(self, sql, *a):
            raise RuntimeError("nu")

    unclear = _lag(_Broken(), _lag_cfg())[0]

    assert off.status == "ok" and current.status == "ok"
    assert off.detail != current.detail, "«oprit» si «la zi» arata la fel"
    assert behind.status == "degraded"
    assert unclear.status == "unknown"


def test_the_check_is_wired_into_the_run():
    """O verificare scrisă și neînregistrată nu rulează niciodată, iar tăcerea ei
    arată identic cu „nimic în neregulă"."""
    from sentinel.selfcheck import checks

    assert ("ship", checks.check_ship_lag) in checks.CHECKS


def test_the_check_asks_only_for_what_the_runner_can_give():
    """`run_groups` injectează argumentele după NUME (`db`, `cfg`). Un parametru
    numit altfel nu se completează, apelul cade cu TypeError, iar grupul se
    raportează stricat la fiecare rulare."""
    from sentinel.selfcheck import checks

    fn = checks.check_ship_lag
    names = fn.__code__.co_varnames[:fn.__code__.co_argcount]
    assert set(names) <= {"db", "cfg"}, names


def test_the_check_reads_config_fields_that_exist_on_the_real_dataclass():
    """Un câmp citit de verificare și absent de pe `Config` face verificarea să
    crape la fiecare rulare — sau, cu `getattr(..., default)`, să nu ruleze
    niciodată și să treacă verde peste cod mort. Ambele s-au întâmplat aici."""
    from sentinel.config import Config, ShipConfig

    ship = Config().ship
    assert isinstance(ship, ShipConfig)
    for attr in ("enabled", "url", "interval_s", "timeout_s", "max_age_s",
                 "max_rows_per_batch", "max_backfill_days",
                 "backoff_base_s", "backoff_max_s"):
        assert hasattr(ship, attr), f"ShipConfig nu are {attr}"
    assert ship.enabled is False, "expedierea trebuie sa fie oprita implicit"


def test_the_cursor_names_are_not_written_a_second_time_in_the_check():
    """O verificare care întreabă de un cursor pe care nu-l scrie nimeni
    raportează „la zi" pentru totdeauna. Numele vin dintr-un singur loc."""
    import inspect

    from sentinel.selfcheck import checks

    source = inspect.getsource(checks.check_ship_lag)
    assert "ship:audit_log" not in source
    assert shipper.AUDIT_STREAM.cursor_name == "ship:audit_log"

# ---------------------------------------------------------------------------
# Fluxurile mutabile: cursorul `(updated_at, id)` și prețul lui
#
# Un cursor pe `id` nu vede un rând care se schimbă, iar unul pe timp se încrede
# în ceas. Ce se probează aici e că a doua proprietate e PLĂTITĂ: un ceas care a
# sărit nu are voie să arate ca o gazdă liniștită, nici în rezultatul rundei,
# nici în /selfcheck.
# ---------------------------------------------------------------------------
# Fluxul REAL e `shipper.INCIDENT_STREAM`, cu toate cele 24 de coloane ale
# tabelei. Aici e o formă scurtată dinadins: ce se probează în secțiunea asta e
# MECANICA cursorului pe timp — ceas, trigger, fereastră, departajare pe cheie —,
# iar aia nu se schimbă cu numărul de coloane, în timp ce douăzeci și patru de
# câmpuri în fiecare fixtură ar ascunde rândul care contează. Acordul dintre
# coloanele declarate și cele pe care le cunoaște receptorul e altă întrebare, și
# se verifică pe declarația reală, în
# `tests/unit/test_aggregator_stream_columns.py`.
INCIDENTS = shipper.Stream(
    name="incidents", table="incidents",
    columns=("id", "updated_at", "status", "title"),
    time_column="updated_at", cursor_kind=shipper.MUTABLE)


def _mrow(id_: int, updated_min_ago: float, status: str = "open"):
    """Un rând de incident ca cel pe care îl întoarce asyncpg."""
    return {"id": id_, "updated_at": NOW - timedelta(minutes=updated_min_ago),
            "status": status, "title": f"incident {id_}"}


def _only_incidents(monkeypatch):
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))


def test_the_registry_carries_the_mutable_stream_the_receiver_expects():
    """Eșecul pe care îl previne: agregatorul așteaptă un flux care nu pleacă.

    Receptorul are `incidents` înregistrat, cu upsert și identitate
    `(instance_id, source_id)`. Nedeclarat aici, nimic nu se plânge nicăieri:
    expeditorul trimite mai departe doar `audit_log`, agregatorul răspunde vesel
    200, iar panoul rămâne gol la nesfârșit — o lipsă pe care n-o vede niciun
    capăt, fiindcă niciunul nu știe ce trebuia să fie acolo. Egalitatea
    COLOANELOR cu ale receptorului e verificată separat, chemând amândouă sursele
    reale (`tests/unit/test_aggregator_stream_columns.py`).
    """
    registered = {s.name: s for s in shipper.STREAMS}
    assert "incidents" in registered, "fluxul mutabil nu e înregistrat la expeditor"
    stream = registered["incidents"]
    assert stream is shipper.INCIDENT_STREAM
    assert stream.cursor_kind == shipper.MUTABLE
    assert stream.table == "incidents"
    assert (stream.time_column, stream.key_column) == ("updated_at", "id")
    assert stream.cursor_name == "ship:incidents"


def _incident_row(id_: int = 4211, updated_min_ago: float = 5.0) -> dict:
    """Un rând `incidents` în forma pe care o întoarce asyncpg, cu toate cele 24.

    Tipurile sunt cele ale coloanelor din `0001_core.sql` plus 0011 și 0023, nu
    unele comode: `ai_verdict` e `jsonb`, deci sosește TEXT; `ai_confidence` e
    `numeric(3,2)`, deci sosește `Decimal`; timpii sosesc cu fus. Fixtura scurtată
    de mai sus (`INCIDENTS`, patru coloane) probează mecanica cursorului pe timp
    și nu atinge niciunul dintre tipurile astea.
    """
    at = NOW - timedelta(minutes=updated_min_ago)
    return {
        "id": id_,
        "fingerprint": "ssh_bruteforce|198.51.100.7|4211",
        "status": "open",
        "severity": "high",
        "ai_severity": "medium",
        # jsonb: din asyncpg vine text, și așa trebuie să plece.
        "ai_verdict": '{"verdict":"probabil scanare automată","confidence":0.85}',
        # numeric(3,2): singurul Decimal din flux.
        "ai_confidence": Decimal("0.85"),
        "ai_analyzed_at": at - timedelta(minutes=1),
        "title": "Autentificări SSH eșuate repetate",
        "summary": "17 eșecuri în 4 minute pentru contul „deploy”",
        "actor_key": "ip:198.51.100.7",
        "asset_id": 12,
        "detection_count": 17,
        "created_at": at - timedelta(minutes=30),
        "first_detection_at": at - timedelta(minutes=30),
        "last_detection_at": at - timedelta(minutes=6),
        "acknowledged_by": "telegram:1",
        "acknowledged_at": at - timedelta(minutes=2),
        "resolved_at": None,
        "resolution_note": None,
        "notified_at": at - timedelta(minutes=29),
        "auto_action": "observe",
        "auto_action_at": at - timedelta(minutes=29),
        "updated_at": at,
    }


def test_the_real_incident_row_reaches_the_signed_body_with_its_own_types(
        http, monkeypatch):
    """Eșecul pe care îl previne: fluxul REAL nu trece niciodată prin
    `collect_stream` în suita asta, deci nimic nu leagă `ai_confidence` de felul
    de coloană `decimal` al receptorului decât NUMELE coloanei.

    Restul secțiunii merge pe o fixtură de patru coloane, dinadins — mecanica
    cursorului pe timp nu se schimbă cu numărul de coloane. Prețul e că
    `encode_value` nu e chemat niciodată pe un `Decimal` în contextul fluxului
    `incidents`: dacă ramura lui ar dispărea, sau dacă un `::text` ar fi mutat în
    interogare, aici n-ar pica nimic, iar defectul s-ar vedea abia pe agregator
    ca „numeric refuzat de MariaDB" — un mesaj despre tipuri în loc de unul
    despre date, la o săptămână după.

    Ce se probează, până la capăt și pe declarația reală: toate cele 24 de
    coloane pleacă, `Decimal` pleacă drept șir exact, `jsonb` pleacă neatins ca
    text, timpii pleacă cu fus — și lotul e semnabil cu tipurile astea, adică
    trece contractul din `signing.py`, nu doar `json.dumps`.
    """
    from sentinel.report.signing import sign

    monkeypatch.setattr(shipper, "STREAMS", (shipper.INCIDENT_STREAM,))
    row = _incident_row()
    db = _MutableDB(mutable=[row], cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.ok is True, result
    assert len(http.calls) == 1, "rândul real nu a ajuns pe sârmă"
    body = json.loads(http.calls[0]["body"])
    sent = body["rows"]["incidents"][0]

    assert set(sent) == set(shipper.INCIDENT_STREAM.columns), \
        "corpul nu poartă exact coloanele declarate"
    assert len(sent) == 24
    # `Decimal` → ȘIR, exact, fiindcă `Decimal(str(x)) == x`. Un `float(x)` aici
    # ar fi refuzat de contract; un `0.85` scris ca `0.8500000000000001` ar ajunge
    # într-o coloană `DECIMAL` a receptorului și ar fi refuzat abia de MariaDB.
    assert sent["ai_confidence"] == "0.85"
    assert isinstance(sent["ai_confidence"], str)
    # `jsonb` călătorește TEXT și neatins: despachetat, `confidence: 0.85` ar
    # deveni un `float` pe care contractul îl refuză, iar fluxul s-ar bloca pe un
    # rând perfect valid.
    assert sent["ai_verdict"] == row["ai_verdict"]
    # Timpii duc fusul. Fără el, receptorul citește o oră locală ca UTC.
    assert sent["updated_at"] == row["updated_at"].isoformat()
    assert sent["updated_at"].endswith("+00:00")
    assert sent["resolved_at"] is None and sent["detection_count"] == 17

    # Pe sârmă pleacă cel mai mare `id` din lot, iar corpul semnat e chiar ăsta:
    # semnătura se recalculează din ce s-a trimis, nu se presupune.
    assert body["cursors"]["incidents"] == row["id"]
    assert http.calls[0]["headers"][shipper.SIGNATURE_HEADER] == sign(body, "k")
    assert db.cursors["ship:incidents"] == row["id"]


def test_the_mutable_stream_is_a_no_op_when_nothing_changed_not_an_unasked_one(http):
    """Eșecul pe care îl previne: al doilea flux pare cuminte fiindcă nimeni nu-l
    întreabă.

    Pe o gazdă pe care niciun incident nu s-a schimbat, runda trebuie să iasă
    exact ca înainte de înregistrarea fluxului: `audit_log` pleacă, nimic altceva
    nu se trimite, iar rezultatul e succes. Diferența dintre asta și „fluxul e
    sărit" nu se vede în rezultat — se vede numai în interogările PUSE, de-aia se
    citesc ele: un flux care n-a întrebat `pg_trigger` și n-a citit `(updated_at,
    id)` nu e la zi, e neinterogat, iar cele două arată identic de afară.

    E și proba că dubla răspunde neutru pe drumul mutabil: dacă n-ar face-o,
    fiecare test din fișierul ăsta ar cădea pe SQL nerecunoscut.
    """
    db = _DB(rows=[_row(9)], cursors={"ship:audit_log": 8})
    result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.ok is True and result.advanced == {"audit_log": 9}, result
    body = json.loads(http.calls[0]["body"])
    assert set(body["rows"]) == {"audit_log"}, "s-a trimis un flux fără rânduri"
    asked = "\n".join(db.queries)
    assert "FROM pg_trigger" in asked, \
        "fluxul mutabil nu a fost interogat deloc: „la zi” aici e o presupunere"
    assert "ORDER BY updated_at, id" in asked, \
        "fluxul mutabil nu și-a citit rândurile pe perechea lui de cursor"


# ---------------------------------------------------------------------------
# Ce poate cursorul nou și nu putea cel vechi
# ---------------------------------------------------------------------------
def test_a_mutable_stream_ships_a_row_an_id_cursor_would_never_have_seen(http, monkeypatch):
    """Eșecul pe care îl previne: operatorul închide un incident vechi din
    Telegram, iar panoul agregatorului îl arată deschis pentru totdeauna.

    Rândul are cel mai mic `id` din tabelă și nu și-l schimbă când se închide,
    deci `WHERE id > cursor` nu-l atinge niciodată — indiferent de câte ori
    rulează expedierea. Pe `(updated_at, id)` trece, fiindcă momentul lui s-a
    mutat.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 2, status="resolved"), _mrow(7, 600)],
                    cursors={"ship:incidents": 7},
                    at={"ship:incidents": NOW - timedelta(minutes=300)})
    result = run(shipper.ship_once(db, _cfg(), "k"))

    sent = json.loads(http.calls[0]["body"])["rows"]["incidents"]
    assert [r["id"] for r in sent] == [1], "rândul schimbat nu a plecat"
    assert result.ok is True
    assert db.cursors["ship:incidents"] == 1
    assert db.at["ship:incidents"] == NOW - timedelta(minutes=2)


def test_the_local_watermark_is_the_last_row_in_shipping_order_not_the_biggest_id(
        http, monkeypatch):
    """Filigranul de pe sârmă și cel local sunt numere diferite, iar confundarea
    lor pierde rânduri.

    Receptorul cere `cursors.<flux>` = cel mai mare `id` din lot. Pe un flux
    ordonat după `(updated_at, id)` ultimul rând NU e cel cu `id`-ul cel mai
    mare: aici lotul e [id 9, id 3], deci pe sârmă pleacă 9, iar cursorul local
    trebuie să rămână pe perechea lui 3. Mutat pe 9, rândurile cu `id` între 3 și
    9 atinse mai târziu ar cădea sub filigran și nu s-ar mai expedia niciodată.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(9, 10), _mrow(3, 5)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    result = run(shipper.ship_once(db, _cfg(), "k"))

    sent = json.loads(http.calls[0]["body"])
    assert [r["id"] for r in sent["rows"]["incidents"]] == [9, 3]
    assert sent["cursors"]["incidents"] == 9, "pe sârmă nu a plecat cel mai mare id"
    assert result.ok is True
    assert db.cursors["ship:incidents"] == 3, "cursorul local a sărit peste rânduri"
    assert db.at["ship:incidents"] == NOW - timedelta(minutes=5)


def test_rows_younger_than_the_commit_safety_lag_stay_for_the_next_round(
        http, monkeypatch):
    """`now()` e ora de ÎNCEPUT a tranzacției, iar commit-urile nu vin în ordinea
    începuturilor.

    Fără fereastra de siguranță, un rând atins de o tranzacție lungă devine
    vizibil după ce cursorul a trecut de momentul lui și nu mai e selectat
    NICIODATĂ — aceeași pierdere permanentă și tăcută pe care lacătul din
    `audit.record` o închide pentru cursorul pe `id`, și pentru care aici nu
    există lacăt.
    """
    _only_incidents(monkeypatch)
    fresh = shipper.COMMIT_SAFETY_LAG_S / 2 / 60
    db = _MutableDB(mutable=[_mrow(1, 10), _mrow(2, fresh)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    run(shipper.ship_once(db, _cfg(), "k"))

    sent = json.loads(http.calls[0]["body"])["rows"]["incidents"]
    assert [r["id"] for r in sent] == [1], \
        "un rând mai proaspăt decât fereastra de siguranță a plecat"


# ---------------------------------------------------------------------------
# Derapajul de ceas
# ---------------------------------------------------------------------------
def test_a_clock_that_went_backwards_does_not_look_like_nothing_to_ship(
        http, monkeypatch, caplog):
    """Eșecul pe care îl previne: expedierea se oprește definitiv și raportează
    succes la fiecare rundă.

    Ceasul merge înapoi o oră. Rândurile atinse de acum încolo primesc un
    `updated_at` mai mic decât filigranul și nu mai sunt selectate niciodată.
    Interogarea rămâne validă și întoarce ZERO rânduri — adică exact ce întoarce
    o gazdă pe care nu s-a schimbat nimic. Dacă cele două ies la fel, operatorul
    citește „la zi” în timp ce tot ce se schimbă se pierde definitiv.

    Rândul e atins DUPĂ saltul înapoi, deci `updated_at` e ceasul de acum, adică
    SUB filigran. Nu e un amănunt de fixtură: e chiar forma pierderii, și e
    motivul pentru care numărătoarea de restanță iese zero.
    """
    _only_incidents(monkeypatch)
    after_the_jump = NOW - timedelta(hours=1)
    db = _MutableDB(mutable=[{"id": 1, "updated_at": after_the_jump,
                              "status": "open", "title": "incident 1"}],
                    cursors={"ship:incidents": 9},
                    at={"ship:incidents": NOW},
                    now=after_the_jump)
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.ok is False, "o expediere oprită de ceas a raportat succes"
    assert "ceas" in result.reason, result.reason
    assert http.calls == [], "s-a trimis un lot peste un filigran rămas în viitor"
    assert db.cursors["ship:incidents"] == 9, "cursorul s-a mutat pe un ceas nesigur"

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1, [r.getMessage() for r in caplog.records]
    assert "timedatectl" in errors[0].action


def test_a_quiet_host_and_a_jumped_clock_do_not_produce_the_same_result(
        http, monkeypatch):
    """Aserțiunea de ansamblu, fiindcă fiecare test de mai sus privește o singură
    stare, iar contopirea a două se vede doar comparându-le.

    E proprietatea cerută cuvânt cu cuvânt: „n-am expediat nimic fiindcă nu s-a
    schimbat nimic” și „n-am expediat nimic fiindcă ceasul a sărit” nu au voie să
    arate la fel.
    """
    _only_incidents(monkeypatch)
    quiet = _MutableDB(mutable=[_mrow(1, 600)],
                       cursors={"ship:incidents": 1},
                       at={"ship:incidents": NOW - timedelta(minutes=600)})
    jumped = _MutableDB(mutable=[_mrow(1, 600)],
                        cursors={"ship:incidents": 1},
                        at={"ship:incidents": NOW},
                        now=NOW - timedelta(hours=1))

    calm = run(shipper.ship_once(quiet, _cfg(), "k"))
    broken = run(shipper.ship_once(jumped, _cfg(), "k"))

    assert calm.ok is True and broken.ok is False
    assert calm.reason != broken.reason
    assert calm.advanced == broken.advanced == {}


def test_a_forward_jump_that_was_corrected_does_not_lose_rows_silently(
        http, monkeypatch):
    """Saltul înainte nu oprește nimic în clipa lui — pierde mai târziu, la
    corecție, și aia e partea tăcută.

    Ceasul o ia înainte cu o oră, un rând pleacă și urcă filigranul în viitor.
    Când ceasul e pus la loc, tot ce se atinge până când timpul real ajunge din
    urmă filigranul are un `updated_at` sub el și nu va fi expediat NICIODATĂ.
    Codul nu poate întoarce rândurile alea — o retragere a filigranului e o
    decizie de operator, vezi capul lui shipper.py. Ce poate, și ce se probează
    aici, e să nu ascundă: runda de după corecție nu are voie să iasă „ok, nimic
    de expediat”.
    """
    _only_incidents(monkeypatch)
    ahead = NOW + timedelta(hours=1)
    db = _MutableDB(mutable=[{"id": 5, "updated_at": ahead - timedelta(minutes=5),
                              "status": "open", "title": "incident 5"}],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    now=ahead)

    assert run(shipper.ship_once(db, _cfg(), "k")).ok is True
    assert db.at["ship:incidents"] == ahead - timedelta(minutes=5)

    # Ceasul e corectat, și apare un rând nou sub filigranul rămas în viitor.
    db.now = NOW
    db.mutable.append(_mrow(6, 1))
    result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.ok is False, "pierderea de după corecția ceasului a trecut ca succes"
    assert "ceas" in result.reason
    assert len(http.calls) == 1, "s-a mai trimis un lot peste filigranul din viitor"


def test_a_stalled_clock_in_one_stream_does_not_stop_the_streams_on_id(
        http, monkeypatch):
    """Un ceas care sare e o proprietate a cursoarelor pe TIMP.

    Oprit tot lotul, un `incidents` poticnit ar opri și `audit_log` — singura
    copie a lanțului de audit din afara gazdei, și un flux pe care ceasul nu-l
    atinge deloc. Cauza ar fi atunci în alt flux decât efectul, iar asta se caută
    prost: exact tiparul pe care capul lui `collect_stream` cere să nu-l
    reintroducem.

    Izolarea vine din DOUĂ locuri, și amândouă se probează aici, fiindcă o
    mutație a arătat că un singur caz le confundă: derapajul propriu-zis
    ÎNTOARCE un lot oprit, iar un filigran pe jumătate scris RIDICĂ
    `ShipClockError`, prinsă per flux în `ship_once`. Ruptura celei de-a doua nu
    se vede probând-o doar pe prima — excepția ar urca la handlerul de „bază
    indisponibilă” și ar rata toată runda, tăcut.
    """
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))

    # (1) ceasul a mers înapoi: lotul oprit se ÎNTOARCE
    drifted = _MutableDB(rows=[_row(91233)],
                         mutable=[_mrow(1, 5)],
                         cursors={"ship:audit_log": 91232, "ship:incidents": 3},
                         at={"ship:incidents": NOW},
                         now=NOW - timedelta(hours=1))
    result = run(shipper.ship_once(drifted, _cfg(), "k"))
    assert result.advanced == {"audit_log": 91233}, result
    assert drifted.cursors["ship:audit_log"] == 91233
    # ...și runda tot NU e un succes, fiindcă un flux s-a oprit.
    assert result.ok is False and "incidents" in result.reason

    # (2) filigran pe jumătate scris: se RIDICĂ, și tot nu are voie să ducă
    # `audit_log` cu el.
    half = _MutableDB(rows=[_row(91233)],
                      mutable=[_mrow(1, 5)],
                      cursors={"ship:audit_log": 91232, "ship:incidents": 3},
                      at={"ship:incidents": None})
    second = run(shipper.ship_once(half, _cfg(), "k"))
    assert second.advanced == {"audit_log": 91233}, second
    assert half.cursors["ship:audit_log"] == 91233
    assert second.ok is False and "cursor_at" in second.reason


def test_an_unencodable_row_in_one_stream_does_not_stop_the_audit_chain(
        http, monkeypatch, caplog):
    """Eșecul pe care îl previne: lanțul de audit nu mai iese de pe gazdă fiindcă
    o ALTĂ tabelă a crescut o coloană cu un tip necunoscut.

    `encode_value` refuză ce nu are formă canonică de șir — și trebuie s-o facă;
    a sări peste rând ar fi pierderea tăcută. Dar strânse toate fluxurile într-un
    singur `try`, refuzul unuia oprea runda ÎNTREAGĂ: `audit_log`, adică singura
    copie verificabilă a lanțului din afara gazdei, ar fi tăcut din cauza lui
    `incidents`. Cauza într-un flux, efectul în altul, și amândouă arătând ca
    „expedierea a rămas în urmă" — se caută prost și se găsește târziu.

    Ce trebuie să rămână adevărat în același timp: fluxul stricat NU avansează și
    runda NU e un succes, altfel bucla ar reveni la `interval_s` și singurul semn
    ar fi o linie de jurnal care se derulează.
    """
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))
    db = _MutableDB(rows=[_row(91233)],
                    # `title` float: exact tipul pe care `encode_value` îl refuză
                    # fiindcă `0.1` n-are reprezentare exactă și două
                    # implementări pot scrie șiruri diferite.
                    mutable=[_mrow(1, 5) | {"title": 1.5}],
                    cursors={"ship:audit_log": 91232, "ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.advanced == {"audit_log": 91233}, \
        f"lanțul de audit a fost oprit de un rând din alt flux: {result}"
    assert db.cursors["ship:audit_log"] == 91233
    assert db.cursors["ship:incidents"] == 0, "fluxul stricat a avansat peste rând"
    assert result.ok is False and "incidents" in result.reason, result
    assert any("cannot encode" in r.getMessage() for r in caplog.records)
    # ...și NU pe drumul ceasului: acolo mesajul îl trimite pe operator la
    # `timedatectl`, care n-are nicio treabă cu un rând necodificabil.
    assert not any("time cursor" in r.getMessage() for r in caplog.records), \
        [r.getMessage() for r in caplog.records]


def test_a_time_cursor_without_its_time_half_is_not_read_as_the_beginning(
        http, monkeypatch):
    """`cursor_at` NULL nu e „de la început” și nu e „de acum”.

    Citit ca zero, ar retrimite toată tabela; citit ca `now()`, ar sări tot ce e
    în urmă. E starea „nu știu unde am rămas”, iar singurul răspuns onest e să se
    oprească și s-o spună.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 3},
                    at={"ship:incidents": None})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert "cursor_at" in result.reason
    assert http.calls == []


def test_a_mutable_stream_with_a_text_key_stalls_instead_of_inventing_a_watermark(
        http, monkeypatch):
    """Filigranul de pe sârmă e un întreg pozitiv, cerut așa de receptor.

    Un flux cu cheie text — `actors.actor_key`, `selfcheck_state.key` — n-are ce
    pune acolo. Un `str()` sau un `hash()` ar fi un filigran inventat, pe care
    ecoul l-ar confirma fără să însemne nimic, iar cursorul ar avansa peste
    rânduri care n-au ajuns nicăieri. Refuzul numește coloana.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[{"id": "cluster:abc",
                              "updated_at": NOW - timedelta(minutes=5),
                              "status": "open", "title": "x"}],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False
    assert "incidents.id" in result.reason
    assert http.calls == []


def test_the_backfill_floor_of_a_mutable_stream_is_a_moment_and_is_persisted(
        http, monkeypatch, caplog):
    """Pragul unui flux mutabil nu e un `id`, e un MOMENT — rândurile neatinse de
    mai mult de `max_backfill_days` nu pleacă niciodată.

    Faptul trăiește doar într-o linie de jurnal dacă nu e persistat, iar un fapt
    dintr-o linie de jurnal e un fapt pierdut: operatorul care se uită peste trei
    luni nu are de unde să-l afle.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 60 * 24 * 30), _mrow(2, 5)])
    with caplog.at_level("WARNING", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(max_backfill_days=7), "k"))

    sent = json.loads(http.calls[0]["body"])["rows"]["incidents"]
    assert [r["id"] for r in sent] == [2]
    assert result.advanced == {"incidents": 2}
    assert db.at["ship:incidents:floor"] == NOW - timedelta(days=7)
    warned = [r for r in caplog.records
              if r.getMessage() == "shipper starts above a backfill floor"]
    assert len(warned) == 1 and warned[0].skipped_rows == 1


# ---------------------------------------------------------------------------
# Declarația fluxului
# ---------------------------------------------------------------------------
def test_a_stream_kind_nobody_taught_it_is_refused_at_declaration():
    """Un `cursor_kind` scris greșit nu are voie să devină tăcut un flux pe `id`.

    `Stream(..., cursor_kind="mutabil")` interpretat ca implicit ar expedia o
    tabelă mutabilă cu un cursor pe `id`, adică ar trimite o dată rândurile și
    n-ar mai vedea niciodată o schimbare — fără ca nimic să raporteze ceva.
    """
    with pytest.raises(ValueError, match="cursor_kind"):
        shipper.Stream(name="x", table="x", columns=("id", "updated_at"),
                       time_column="updated_at", cursor_kind="mutabil")


def test_a_mutable_stream_must_carry_the_columns_its_cursor_is_built_from():
    """Filigranul unui flux mutabil se citește din RÂNDUL expediat.

    Fără coloana de timp sau fără cheie în `columns`, `collect_stream` ar cădea cu
    KeyError la fiecare rundă — adică fluxul ar tăcea din prima zi, iar cauza ar
    fi într-o urmă de excepție, nu în declarația greșită.
    """
    with pytest.raises(ValueError, match="updated_at"):
        shipper.Stream(name="x", table="x", columns=("id", "status"),
                       time_column="updated_at", cursor_kind=shipper.MUTABLE)
    with pytest.raises(ValueError, match="'id'"):
        shipper.Stream(name="x", table="x", columns=("updated_at", "status"),
                       time_column="updated_at", cursor_kind=shipper.MUTABLE)


def test_the_audit_stream_stays_on_the_id_cursor():
    """`audit_log` e append-only, impus de un trigger care ridică excepție la
    UPDATE (`sentinel/db/migrations/0002_response.sql`). Mutat pe un cursor pe
    timp, ar căpăta dependența de ceas fără să câștige nimic — nu are ce
    actualiza, iar `0023_ship_watermarks.sql` explică de ce nici nu poate primi
    triggerul care ar întreține `updated_at`: al doilea trigger BEFORE UPDATE pe
    o tabelă unde orice UPDATE moare ar fi cod care nu rulează niciodată.

    Se cere fluxul ÎNREGISTRAT sub numele ăsta, nu constanta din modul: numai
    ce e în `STREAMS` se expediază, iar o constantă corectă lăsată pe dinafară,
    sau înlocuită în registru cu una mutabilă, ar trece de o aserțiune care se
    uită doar la `AUDIT_STREAM`. Cât timp `STREAMS` avea o singură intrare,
    „toate fluxurile sunt pe `id`" spunea același lucru; de la al doilea flux
    încolo spune altceva — că nu are voie să existe niciun flux mutabil — și
    aia nu e proprietatea de aici.
    """
    assert shipper.AUDIT_STREAM.cursor_kind == shipper.APPEND_ONLY
    registered = {s.name: s for s in shipper.STREAMS}
    assert "audit_log" in registered, "fluxul de audit nu mai e înregistrat"
    assert registered["audit_log"].cursor_kind == shipper.APPEND_ONLY
    assert registered["audit_log"] is shipper.AUDIT_STREAM


# ---------------------------------------------------------------------------
# Ce ajunge la operator
# ---------------------------------------------------------------------------
def test_a_stream_stopped_by_the_clock_is_not_shown_as_up_to_date(monkeypatch):
    """Eșecul pe care îl previne: /selfcheck verde peste o expediere moartă.

    Sub un filigran rămas în viitor, interogarea de restanță numără ZERO — nimic
    nu e „după” cursor. Judecată pe `pending`, verificarea ar spune „la zi” la
    fiecare rulare, la nesfârșit. De-aia ramura ceasului stă ÎNAINTEA celei de
    restanță.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    after_the_jump = NOW - timedelta(hours=1)
    db = _MutableDB(mutable=[{"id": 1, "updated_at": after_the_jump,
                              "status": "open", "title": "incident 1"}],
                    cursors={"ship:incidents": 9},
                    at={"ship:incidents": NOW},
                    now=after_the_jump)
    # Numărătoarea chiar iese zero: fără asta, testul ar trece și cu ramura
    # ceasului așezată DUPĂ cea de restanță, adică exact bug-ul.
    assert run(shipper.lag(db, (INCIDENTS,)))[0].pending == 0

    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]

    assert result.status == "degraded", result
    assert result.key == "ship:lag:incidents"
    assert "ceasul" in result.title or "ceasul" in result.detail
    assert "timedatectl" in result.action
    assert result.facts["clock_ahead_s"] >= 3600


def test_a_mutable_stream_with_a_healthy_clock_is_still_reported_normally(monkeypatch):
    """Contrastul, ca testul de mai sus să însemne ceva.

    O ramură de ceas care s-ar aprinde și pe un ceas bun ar ține cheia roșie
    permanent, iar o cheie roșie tot timpul e una peste care operatorul învață să
    treacă — exact cum s-a întâmplat cu titlul lui /selfcheck.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    db = _MutableDB(mutable=[_mrow(1, 600)],
                    cursors={"ship:incidents": 1},
                    at={"ship:incidents": NOW - timedelta(minutes=600)})
    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.status == "ok"
    assert result.facts["pending"] == 0


def test_a_half_written_time_cursor_is_unknown_not_current(monkeypatch):
    """`cursor_at` lipsă e „nu pot spune”, nu „la zi”.

    Contopit cu „la zi”, ar fi tăcere în formă de sănătate; și fiindcă runner-ul
    reconciliază starea după cheile emise, ar șterge o restanță reală și
    nereparată, arătând operatorului o revenire care nu s-a întâmplat.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 3},
                    at={"ship:incidents": None})
    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.status == "unknown"
    # Cheia e a fluxului, și nu cea care poartă restanța: vezi
    # `test_a_check_that_cannot_look_says_so_instead_of_saying_ok`.
    assert result.key == "ship:lag:incidents:unreadable"
    assert "cursor_at" in result.detail


def test_the_procedure_the_operator_is_sent_to_actually_exists(http, monkeypatch, caplog):
    """Eșecul pe care îl previne: o trimitere către un capitol care nu e acolo.

    Și expeditorul, și autodiagnosticul îl trimit pe operator la „Expedierea s-a
    oprit din cauza ceasului" din `docs/OPERARE.md`, fiindcă decizia de a retrage
    sau nu filigranul nu se ia dintr-un mesaj de trei rânduri. O trimitere moartă
    e mai rea decât niciuna: cine o urmează pierde timp căutând, la 3 dimineața,
    exact când fluxul deja nu mai pleacă.

    Se compară titlul din MESAJELE PRODUSE cu titlurile din document — nu textul
    sursei, care e rupt pe rânduri de formatare, și nu prezența fișierului, care
    există oricum și ar face aserțiunea verde peste orice.
    """
    from pathlib import Path

    from sentinel.selfcheck import checks

    title = "Expedierea s-a oprit din cauza ceasului"
    doc = Path(__file__).resolve().parents[2] / "docs" / "OPERARE.md"
    headings = [line.lstrip("# ").strip() for line in
                doc.read_text(encoding="utf-8").splitlines() if line.startswith("#")]
    assert any(h.endswith(title) for h in headings),         f"{title!r} nu e un titlu în docs/OPERARE.md; ultimele: {headings[-6:]}"

    _secrets(monkeypatch)
    _only_incidents(monkeypatch)
    after_the_jump = NOW - timedelta(hours=1)

    def _drifted():
        return _MutableDB(mutable=[{"id": 1, "updated_at": after_the_jump,
                                    "status": "open", "title": "incident 1"}],
                          cursors={"ship:incidents": 9},
                          at={"ship:incidents": NOW},
                          now=after_the_jump)

    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        run(shipper.ship_once(_drifted(), _cfg(), "k"))
    logged = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(logged) == 1
    assert title in getattr(logged[0], "action", "")

    finding = run(checks.check_ship_lag(_drifted(), _lag_cfg()))[0]
    assert title in finding.action


def test_the_loss_report_points_at_a_procedure_that_exists(http, monkeypatch, caplog):
    """Aceeași pază, pentru a doua trimitere: „Rânduri apărute sub filigran".

    Linia de ERROR care anunță pierderea e singurul moment în care operatorul
    poate afla că rândurile se pot recupera retrăgând filigranul. O trimitere
    moartă acolo înseamnă că informația nu ajunge niciodată, iar rândurile rămân
    pierdute fiindcă nimeni n-a știut că se putea altfel.
    """
    from pathlib import Path

    title = "Rânduri apărute sub filigran"
    doc = Path(__file__).resolve().parents[2] / "docs" / "OPERARE.md"
    headings = [line.lstrip("# ").strip() for line in
                doc.read_text(encoding="utf-8").splitlines() if line.startswith("#")]
    assert any(h.endswith(title) for h in headings),         f"{title!r} nu e un titlu în docs/OPERARE.md; ultimele: {headings[-6:]}"

    _only_incidents(monkeypatch)
    early, late = NOW - timedelta(minutes=20), NOW - timedelta(minutes=10)
    db = _MutableDB(mutable=[{"id": 1, "updated_at": late, "status": "open",
                              "title": "incident 1"}],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    run(shipper.ship_once(db, _cfg(), "k"))
    db.mutable.append({"id": 2, "updated_at": early, "status": "open",
                       "title": "incident 2"})
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        run(shipper.ship_once(db, _cfg(), "k"))

    lost = [r for r in caplog.records if r.getMessage().startswith("rows appeared below")]
    assert len(lost) == 1
    assert title in lost[0].action


# ---------------------------------------------------------------------------
# Ce a scăpat în runda 1, prins de mutații
# ---------------------------------------------------------------------------
def test_two_rows_that_share_a_moment_are_not_split_by_a_batch_edge(http, monkeypatch):
    """Eșecul pe care îl previne: jumătate dintr-o schimbare atomică ajunge pe
    agregator, cealaltă jumătate niciodată.

    `updated_at` e `now()`, adică ora de ÎNCEPUT a tranzacției — deci două rânduri
    atinse împreună primesc EXACT același moment. E o alegere scrisă în
    `0023_ship_watermarks.sql`, tocmai ca ele să plece împreună.

    Departajarea pe cheie e a doua jumătate a filigranului și singura care face
    asta să țină la marginea unui lot. Cu un `WHERE updated_at > $1` simplu,
    rândul care împarte momentul cu cursorul nu mai e selectat NICIODATĂ: e sub
    prag pentru totdeauna, iar interogarea rămâne validă și tăcută.

    Lotul e mărginit la un rând, ca marginea să cadă chiar între cele două.
    """
    _only_incidents(monkeypatch)
    moment = NOW - timedelta(minutes=10)
    together = [{"id": i, "updated_at": moment, "status": "open",
                 "title": f"incident {i}"} for i in (4, 5)]
    db = _MutableDB(mutable=together,
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})

    first = run(shipper.ship_once(db, _cfg(max_rows_per_batch=1), "k"))
    second = run(shipper.ship_once(db, _cfg(max_rows_per_batch=1), "k"))

    assert first.ok is True and second.ok is True
    shipped = [r["id"] for call in http.calls
               for r in json.loads(call["body"])["rows"]["incidents"]]
    assert shipped == [4, 5], \
        f"rândul care împarte momentul cu filigranul a fost sărit: {shipped}"


def test_a_clock_comparison_that_returns_nothing_is_not_read_as_a_good_clock(
        http, monkeypatch):
    """Eșecul pe care îl previne: „n-am putut compara" raportat ca „ceasul e bun".

    Cu `0.0` în loc de excepție, `ahead > 0` e fals, ramura de derapaj nu se
    aprinde, iar fluxul citește mai departe cu un filigran pe care nu l-a validat
    nimeni. E aceeași clasă cu un `Number(null)` care iese 0: valoarea absentă
    capătă tăcut înțelesul cel mai favorabil.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    clock_readable=False)
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False, "un ceas necitibil a trecut drept ceas bun"
    assert http.calls == []


def test_rows_that_appear_below_the_cursor_are_counted_and_kept(http, monkeypatch, caplog):
    """Eșecul pe care îl previne: pierderea pe care fereastra de siguranță o
    mărginește, dar nu o elimină — și care altfel n-ar produce niciun semnal.

    `COMMIT_SAFETY_LAG_S` presupune că nicio tranzacție de scriere nu ține mai
    mult de atât. Măsurat pe codul de azi, presupunerea e adevărată cu multe
    ordine de mărime. În ziua în care cineva înfășoară două `UPDATE`-uri pe
    `incidents` într-o tranzacție care ține o cerere HTTP, devine falsă — iar
    pierderea e SUB cursor, deci `ship:lag`, care numără deasupra, nu o vede.

    Măsurătoarea nu presupune nimic: fereastra citită runda trecută e închisă
    (orice atingere nouă pune `updated_at = now()`, care e deasupra cursorului),
    deci orice rând în plus găsit acolo acum a fost comis cu întârziere.
    """
    _only_incidents(monkeypatch)
    early, late = NOW - timedelta(minutes=20), NOW - timedelta(minutes=10)
    db = _MutableDB(mutable=[{"id": 1, "updated_at": late, "status": "open",
                              "title": "incident 1"}],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    assert run(shipper.ship_once(db, _cfg(), "k")).ok is True

    # Tranzacția lungă comite acum un rând al cărui moment e deja sub filigran.
    db.mutable.append({"id": 2, "updated_at": early, "status": "open",
                       "title": "incident 2"})
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        run(shipper.ship_once(db, _cfg(), "k"))

    lost = [r for r in caplog.records
            if r.getMessage() == "rows appeared below the shipping cursor "
                                 "and will never be shipped"]
    assert len(lost) == 1, [r.getMessage() for r in caplog.records]
    assert lost[0].rows == 1
    # ...și rămâne citibil după ce linia de jurnal se derulează.
    assert db.cursors["ship:incidents:lost"] == 1


def test_a_quiet_window_is_not_reported_as_a_loss(http, monkeypatch, caplog):
    """Contrastul. Un detector care se aprinde pe funcționarea normală e unul
    peste care operatorul învață să treacă, iar aici ar fi la fiecare rundă."""
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 10)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)})
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        run(shipper.ship_once(db, _cfg(), "k"))
        db.mutable.append(_mrow(2, 5))
        run(shipper.ship_once(db, _cfg(), "k"))
    assert [r.getMessage() for r in caplog.records] == []
    assert "ship:incidents:lost" not in db.cursors


# ---------------------------------------------------------------------------
# Triggerul: întrebat, nu presupus
# ---------------------------------------------------------------------------
def test_a_stream_whose_updated_at_is_not_maintained_refuses_to_ship(
        http, monkeypatch, caplog):
    """Eșecul pe care îl previne: fluxul cel mai tăcut cu putință.

    Fără triggerul din 0023, `updated_at` rămâne valoarea pusă de `DEFAULT now()`
    la INSERT. Rândul se schimbă, momentul lui nu. Cursorul trece o dată peste el
    și nu-l mai vede niciodată — iar de pe gazdă totul arată sănătos: interogarea
    întoarce zero rânduri, ceasul e bun, restanța e zero, unitatea e `active`.

    Un fișier de migrație pe disc nu e dovadă că nucleul l-a acceptat, iar
    `schema_version` spune doar că instrucțiunile au rulat. Singurul fapt e
    `pg_trigger`, întrebat la rulare.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    trigger=False)
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    assert result.ok is False, "un flux fără filigran întreținut a raportat succes"
    assert "trigger" in result.reason
    assert http.calls == [], "s-a expediat dintr-o tabelă al cărei moment nu se mișcă"


def test_a_missing_trigger_stops_only_its_own_stream(http, monkeypatch):
    """`audit_log` nu are și nu poate avea triggerul ăsta — e append-only, cu un
    trigger care ridică excepție la UPDATE. Oprit din cauza lui `incidents`, ar
    însemna că lanțul de audit nu mai iese de pe gazdă fiindcă altă tabelă are o
    migrație lipsă."""
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))
    db = _MutableDB(rows=[_row(91233)],
                    mutable=[_mrow(1, 5)],
                    cursors={"ship:audit_log": 91232, "ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    trigger=False)
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.advanced == {"audit_log": 91233}, result
    assert result.ok is False and "incidents" in result.reason


def test_a_stream_without_its_trigger_is_not_shown_as_up_to_date(monkeypatch):
    """Perechea din autodiagnostic, și motivul pentru care verificarea întreabă
    și ea, în loc să se sprijine pe expeditor.

    Expeditorul se oprește — dar el nu are cale către operator, dinadins. Dacă
    verificarea n-ar întreba `pg_trigger`, ar citi cursorul, ar găsi restanța
    ZERO (niciun moment nu se mai mișcă) și ar raporta „la zi", verde, pentru
    totdeauna. Singurul semn ar fi o unitate care rulează și nu trimite nimic.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 1},
                    at={"ship:incidents": NOW - timedelta(minutes=5)},
                    trigger=False)
    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.status == "degraded", result
    assert result.key == "ship:lag:incidents"
    assert result.facts["updated_at_trigger"] is False
    assert "sentinel migrate" in result.action


class _NoCursorAtColumn(_DB):
    """`collector_cursors` fără coloana `cursor_at`.

    Nu e o ipoteză: e gazda de producție pe 16 august 2026, cu
    `schema_version=22` și migrația 0023 neaplicată. Orice interogare care
    numește coloana cade cu mesajul de mai jos, exact ca în Postgres.
    """

    async def fetchrow(self, sql, *a):
        if "cursor_at" in sql:
            raise RuntimeError('column "cursor_at" does not exist')
        return await super().fetchrow(sql, *a)

    async def fetchval(self, sql, *a):
        if "cursor_at" in sql:
            raise RuntimeError('column "cursor_at" does not exist')
        return await super().fetchval(sql, *a)


def test_the_append_only_stream_still_reports_when_the_mutable_one_cannot_be_read(
        monkeypatch):
    """Eșecul pe care îl previne, și e viu pe gazdă: fluxul care MERGE dispare
    din panou fiindcă vecinul lui nu s-a putut citi.

    `shipper.lag` ridica din prima interogare care cădea, `check_ship_lag` prindea
    și întorcea O SINGURĂ cheie — `ship:lag | unknown` —, iar runner-ul șterge, la
    o rulare completă, fiecare cheie pe care rularea n-a emis-o. Deci
    `ship:lag:audit_log`, cu restanța lui reală și nereparată, era reconciliat
    afară din `/selfcheck`: fluxul append-only, care n-are nevoie nici de trigger
    nici de `cursor_at`, devenea invizibil fiindcă cel mutabil nu se putea citi. O
    gardă care ascunde altă gardă.

    Cheia fluxului necitibil e alta decât cea a restanței, dinadins — vezi
    `test_a_check_that_cannot_look_says_so_instead_of_saying_ok`.
    """
    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))
    db = _NoCursorAtColumn(rows=[_row(9, minutes_ago=500)],
                           cursors={"ship:audit_log": 8})

    results = {r.key: r for r in _lag(db, _lag_cfg())}

    assert "ship:lag:audit_log" in results, \
        f"fluxul append-only a dispărut din panou: {sorted(results)}"
    assert results["ship:lag:audit_log"].status == "degraded"
    assert results["ship:lag:audit_log"].facts["pending"] == 1
    assert results["ship:lag:incidents:unreadable"].status == "unknown"
    assert "cursor_at" in results["ship:lag:incidents:unreadable"].detail


def test_a_host_without_the_watermark_migration_is_told_which_migration_is_missing(
        monkeypatch):
    """Eșecul pe care îl previne: simptomul migrației lipsă în locul cauzei ei.

    Pe gazda de azi (`schema_version=22`), fluxul mutabil n-are nici triggerul
    din 0023, nici coloana `cursor_at`. Măsurătoarea întreabă întâi
    `pg_trigger` — dar cât timp mergea mai departe după răspuns, cădea pe
    `cursor_at`, iar operatorul primea „nu pot spune: column cursor_at does not
    exist" cu remediul „journalctl". Cauza e alta și are alt remediu: coloana
    care ține filigranul nu e întreținută de nimeni, deci fluxul e oprit — și
    asta se repară cu `sentinel migrate`, verificat în `pg_trigger`, nu în
    jurnal.
    """
    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (shipper.AUDIT_STREAM, INCIDENTS))
    db = _NoCursorAtColumn(rows=[_row(9, minutes_ago=500)],
                           cursors={"ship:audit_log": 8},
                           trigger=False)

    results = {r.key: r for r in _lag(db, _lag_cfg())}

    assert "ship:lag:incidents" in results, \
        f"cauza s-a pierdut în simptom: {sorted(results)}"
    assert not [k for k in results if k.endswith(":unreadable")], \
        f"întrebarea a trecut de verdictul care o făcea fără obiect: {sorted(results)}"
    finding = results["ship:lag:incidents"]
    assert finding.status == "degraded"
    assert finding.facts["updated_at_trigger"] is False
    assert "sentinel migrate" in finding.action
    assert "pg_trigger" in finding.action
    # …iar fluxul care merge își raportează starea lui, nu pe a vecinului.
    assert results["ship:lag:audit_log"].status == "degraded"
    assert results["ship:lag:audit_log"].facts["pending"] == 1


@pytest.mark.parametrize("state,ships", [("O", True), ("A", True),
                                        ("D", False), ("R", False)])
def test_only_the_trigger_states_that_actually_fire_count_as_installed(
        http, monkeypatch, state, ships):
    """Eșecul pe care îl previne: un trigger prezent în catalog care nu rulează.

    `tgenabled` are PATRU valori, nu două. `'D'` e dezactivat; `'R'` se
    declanșează DOAR pe o sesiune cu `session_replication_role = 'replica'`, deci
    pentru expeditor nu se declanșează deloc. Un filtru scris ca `<> 'D'` lasă
    `'R'` să treacă — adică raportează „întreținut" peste o coloană care nu se
    mai mișcă, exact starea pe care verificarea există s-o rupă.

    Se enumeră ce se ACCEPTĂ, nu ce se respinge: o listă de respinsuri e greșită
    de fiecare dată când apare o valoare nouă.

    Ce NU poate arăta testul: că PostgreSQL scrie chiar literele astea. Ele vin
    din documentația lui `pg_trigger`; efectul se confirmă numai pe gazdă.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    trigger=state)
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is ships, f"tgenabled={state!r}: ok={result.ok}, aşteptat {ships}"
    assert bool(http.calls) is ships


def test_the_trigger_type_mask_is_still_asked_for():
    """`tgtype` nu se poate juca într-un dicționar, deci se cere ca text.

    Biții: 1 ROW, 2 BEFORE, 16 UPDATE. Un `AFTER` nu mai poate schimba `NEW`, iar
    un `FOR EACH STATEMENT` ratează un `UPDATE … WHERE status = 'open'` peste
    patruzeci de rânduri — amândouă sunt „prezent și fără efect". E test de
    submulțime, deci un `BEFORE INSERT OR UPDATE ROW` (23) trece, cum trebuie.
    """
    import inspect

    source = inspect.getsource(shipper.updated_at_trigger_installed)
    assert "(tgtype & 19) = 19" in source
    assert "to_regproc('set_updated_at')" in source


def test_the_clock_message_says_the_rows_are_gone_for_good(http, monkeypatch, caplog):
    """Eșecul pe care îl previne: operatorul repară ceasul și crede că a terminat.

    „Nu pleacă nimic până se ajunge din urmă" descrie o întârziere. Ce s-a
    întâmplat e o pierdere: rândurile atinse în răstimp rămân sub filigran și după
    ce ceasul e corect. Fără propoziția asta, decizia de a resincroniza nu se
    poate lua — nici măcar nu se știe că există.
    """
    _only_incidents(monkeypatch)
    after_the_jump = NOW - timedelta(hours=1)
    db = _MutableDB(mutable=[{"id": 1, "updated_at": after_the_jump,
                              "status": "open", "title": "incident 1"}],
                    cursors={"ship:incidents": 9},
                    at={"ship:incidents": NOW},
                    now=after_the_jump)
    with caplog.at_level("ERROR", logger="sentinel.report.shipper"):
        result = run(shipper.ship_once(db, _cfg(), "k"))

    stall = [r for r in caplog.records
             if r.getMessage() == "shipper stream cannot advance its time cursor"]
    assert len(stall) == 1
    said = stall[0].detail + " " + stall[0].action + " " + result.reason
    assert "NICIODATĂ" in said, said
    assert "resincronizare" in said or "retrăgând" in said, said


def test_a_backlog_that_shares_the_cursor_moment_is_still_counted(monkeypatch):
    """Eșecul pe care îl previne: restanță reală raportată ca „la zi".

    Numărătoarea de restanță are aceeași limită de jos ca interogarea de
    expediere, și trebuie s-o aibă pe aceeași pereche. Pierdută departajarea pe
    cheie, rândurile care împart EXACT momentul filigranului ies din numărătoare —
    iar rândurile atinse de aceeași tranzacție au prin construcție același moment.

    Consecința nu e cosmetică: cu agregatorul căzut, cursorul stă pe loc, iar
    `/selfcheck` ar arăta 0 rânduri în așteptare peste o coadă care chiar există.
    „Nu e nimic de trimis" și „nu se poate trimite" se contopesc din nou.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    moment = NOW - timedelta(hours=3)
    db = _MutableDB(mutable=[{"id": i, "updated_at": moment, "status": "open",
                              "title": f"incident {i}"} for i in (1, 2, 3)],
                    cursors={"ship:incidents": 1},
                    at={"ship:incidents": moment})

    measured = run(shipper.lag(db, (INCIDENTS,)))[0]
    assert measured.pending == 2,         f"rândurile care împart momentul filigranului nu se numără: {measured}"

    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.status == "degraded", result
    assert result.facts["pending"] == 2


def test_a_trigger_question_that_returns_nothing_is_not_read_as_installed(
        http, monkeypatch):
    """Eșecul pe care îl previne: „n-am putut întreba" citit ca „e instalat".

    `count(*)` nu întoarce NULL — până în ziua în care întoarce, fiindcă cineva a
    schimbat interogarea, a mutat-o pe altă conexiune, sau a pus-o pe o cale care
    răspunde gol. Direcția implicită contează: „instalat" lasă fluxul să meargă
    mai departe peste o tabelă al cărei moment poate să nu se miște deloc, adică
    exact tăcerea pe care verificarea există s-o rupă.

    E aceeași clasă cu ceasul necitibil de mai sus, și e aceeași alegere: absența
    unui răspuns nu capătă înțelesul cel mai favorabil.
    """
    _only_incidents(monkeypatch)
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 0},
                    at={"ship:incidents": NOW - timedelta(hours=2)},
                    trigger=None)
    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert result.ok is False, "un pg_trigger necitibil a trecut drept trigger instalat"
    assert "pg_trigger" in result.reason
    assert http.calls == []

# ---------------------------------------------------------------------------
# Ciclul de închidere
# ---------------------------------------------------------------------------
def test_a_cursor_that_landed_inside_a_shared_moment_resumes_inside_it(
        http, monkeypatch):
    """Eșecul pe care îl previne: restul unei schimbări atomice nu pleacă
    niciodată.

    Fixtura e chiar cazul: două rânduri cu EXACT același `updated_at` — ceea ce
    `0023_ship_watermarks.sql` face deliberat pentru rândurile atinse de aceeași
    tranzacție, ca „fie pleacă amândouă, fie niciunul" — și cursorul aterizat
    între ele, pe primul.

    Cu filigranul pe pereche, al doilea e deasupra cursorului și pleacă. Cu un
    `WHERE updated_at > $1` simplu, `moment > moment` e fals: rândul rămâne sub
    prag pentru totdeauna, interogarea rămâne validă, iar runda raportează
    liniștită „nimic de expediat".

    Se probează CONSECINȚA, într-o singură rundă, nu ortografia interogării:
    aceeași clasă de defect a trecut de patru ori în ciclul ăsta pentru că a fost
    verificată ca text.
    """
    _only_incidents(monkeypatch)
    moment = NOW - timedelta(minutes=10)
    db = _MutableDB(mutable=[{"id": i, "updated_at": moment, "status": "open",
                              "title": f"incident {i}"} for i in (4, 5)],
                    cursors={"ship:incidents": 4},
                    at={"ship:incidents": moment})

    result = run(shipper.ship_once(db, _cfg(), "k"))

    assert http.calls, "rândul care împarte momentul cu filigranul nu a plecat deloc"
    sent = [r["id"] for r in json.loads(http.calls[0]["body"])["rows"]["incidents"]]
    assert sent == [5], f"aşteptat [5], trimis {sent}"
    assert result.advanced == {"incidents": 5}
    assert db.cursors["ship:incidents"] == 5


def test_a_past_loss_stays_in_the_message_on_runs_where_it_did_not_grow(monkeypatch):
    """Eșecul pe care îl previne: operatorul ratează ziua și nu mai află niciodată.

    Pierderea e ireversibilă, iar singurul moment în care se anunță zgomotos e
    runda în care CREȘTE. Dacă detaliul verificării ar purta contorul numai
    atunci, cine se uită a doua zi vede un flux verde peste rânduri care nu vor
    ajunge niciodată pe agregator.

    Aceeași alegere ca la pragul de backfill, și din același motiv: un fapt care
    trăiește doar într-o linie de jurnal e un fapt pierdut. Cheia rămâne verde —
    o cheie roșie care nu se mai stinge e una peste care se învață să se treacă —
    dar faptul rămâne citibil la fiecare rulare.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    # Nimic nu se schimbă acum: fluxul e la zi, iar contorul e de acum trei luni.
    db = _MutableDB(mutable=[_mrow(1, 600)],
                    cursors={"ship:incidents": 1, "ship:incidents:lost": 3},
                    at={"ship:incidents": NOW - timedelta(minutes=600)})

    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.status == "ok", result
    assert "3 rânduri" in result.detail, result.detail
    assert "niciodată" in result.detail
    assert result.facts["lost_below_cursor"] == 3


def test_a_missing_trigger_is_reported_before_the_clock(monkeypatch):
    """Când ambele sunt stricate, operatorul trebuie trimis la cauză.

    Fără trigger, `updated_at` nu se mai mișcă deloc — deci starea ceasului nu mai
    poate schimba nimic pentru fluxul ăsta, iar `timedatectl` ar fi o oră pierdută
    pe simptomul greșit. Ordinea ramurilor e informația, nu un amănunt de stil.

    De la 16 august 2026 măsurătoarea se și OPREȘTE pe trigger, nu doar îl
    judecă întâi: pe o gazdă unde 0023 n-a ajuns, `collector_cursors` n-are
    coloana `cursor_at`, deci interogarea de după ar fi ridicat, iar fluxul ar fi
    ieșit „nu pot spune: column cursor_at does not exist" — simptomul migrației
    lipsă în locul cauzei ei. De-aia ceasul se probează aici direct, nu prin
    `lag`: prin `lag` nu se mai măsoară, ceea ce e chiar reparația.
    """
    from sentinel.selfcheck import checks

    _secrets(monkeypatch)
    monkeypatch.setattr(shipper, "STREAMS", (INCIDENTS,))
    db = _MutableDB(mutable=[_mrow(1, 5)],
                    cursors={"ship:incidents": 9},
                    at={"ship:incidents": NOW},
                    now=NOW - timedelta(hours=1),
                    trigger=False)

    # Amândouă chiar sunt stricate în fixtura asta.
    measured = run(shipper.lag(db, (INCIDENTS,)))[0]
    assert measured.updated_at_trigger is False
    assert measured.error == "", measured
    assert run(shipper.clock_ahead_s(db, NOW)) > 0, \
        "fixtura nu mai are ceasul stricat, deci testul nu mai probează ordinea"

    result = run(checks.check_ship_lag(db, _lag_cfg()))[0]
    assert result.facts["updated_at_trigger"] is False, result
    assert "sentinel migrate" in result.action
    assert "timedatectl" not in result.action


# ---------------------------------------------------------------------------
# TAXONOMIA: fiecare cale de ieșire care scrie un verdict per flux
#
# Clasificarea din `ship_once` nu e o colecție de ramuri, e o taxonomie: fiecare
# cauză de eșec are un domeniu (LOTUL, FLUXUL, sau RUNDA) și un text propriu, iar
# din domeniu se construiește programul de reîncercare al fiecărui flux. Testată
# ramură cu ramură, taxonomia se verifică pe cazurile la care s-a gândit cineva,
# și tocmai asta a lăsat să treacă patru mutații prin 454 de teste, pe 16 august
# 2026:
#
#   * `batch_failed` doborând TOATE fluxurile cerute, nu doar pe cele din lot;
#   * un flux fără verdict citit ca succes în loc de eșec;
#   * un flux refuzat la ecou parțial păstrându-și `True`-ul provizoriu;
#   * un cursor pe care baza a refuzat să-l mute, raportat ca livrare.
#
# A treia e cea mai gravă și e chiar scenariul în jurul căruia capul modulului
# construiește toată regula ecoului: un agregator care cunoaște `audit_log` și nu
# `incidents`. Cu ea, fluxul refuzat e programat sănătos la nesfârșit — nu intră
# în backoff, deci nu ajunge la `_PROBE_ALARM_AT`, deci linia
# `ERROR shipper stream has been failing | stream=incidents` nu se emite
# NICIODATĂ. `ship:lag` ajunge degradat fiindcă restanța chiar crește, dar
# singura linie care numește ȘI fluxul ȘI cauza a dispărut.
#
# Deci un TABEL, și o gardă care NUMĂRĂ în loc să recunoască. Prima ei formă
# număra apelurile scrise literal `StreamOutcome(...)`, adică tot un
# recunoscător, doar cu alt tipar — și a fost evadată de două ori în aceeași zi,
# amândouă cu ramuri noi puse chiar în `ship_once`:
#
#   * `return ShipResult(False, x, streams=batch_failed(x))` — idiomul propriu al
#     modulului, calea pe care ies patru din rândurile tabelului de mai jos;
#   * `outcomes[s.name] = _V(False, …)`, cu `_V = StreamOutcome` ca alias.
#
# Amândouă treceau verde prin suita întreagă: garda se uita la CE se cheamă,
# adică la o ortografie pe care orice ramură nouă o poate scrie altfel.
#
# Ce se numără acum sunt IEȘIRILE, nu constructorii (`_round_verdict_sites`):
# fiecare `return` cu valoare și fiecare instrucțiune care scrie în
# `outcomes`/`outcome`, din `ship_once`, `run_forever`, `_round_failed` și din
# funcțiile cuibărite în ele. Cum se construiește verdictul înăuntru nu mai
# contează deloc — un `return` nou e un sit nou oricum ar arăta corpul lui.
#
# Ce NU poate arăta, și se scrie aici fiindcă o gardă care se declară completă e
# chiar pana pe care fișierul ăsta o tot plătește. Garda e pe LINIE și pe
# ACOPERIRE: dovedește că fiecare INSTRUCȚIUNE de ieșire e executată de vreun rând,
# NU că fiecare DECIZIE dinăuntrul uneia e asertată de vreun rând. O ramură nouă
# pusă într-o instrucțiune deja executată e invizibilă pentru ea — oricum ar fi
# scrisă, oriunde ar fi definit ce cheamă. Nu e un amănunt de implementare, e
# forma pe care au avut-o toate evadările de până acum:
#
#   * `isinstance(exc, _OUR_DEFECT)` — ambele laturi scriu verdictul prin aceeași
#     instrucțiune, deci ștergerea rândului `_setup_our_own_defect` NU lasă niciun
#     sit neatins; ce înroșește e chiar rândul lui din tabel (falsificat cu
#     `if False:` în locul condiției);
#   * `more=batch.full and len(advanced) < 2` pe linia care scrie verdictul unui
#     flux confirmat — aceeași instrucțiune, alt efect, gardă verde, iar fluxul cu
#     restanță revine peste `interval_s` în loc de `DRAIN_PAUSE_S`;
#   * un verdict scris de un ajutor definit ÎN AFARA celor trei funcții și chemat
#     dintr-o instrucțiune deja executată. Măsurat, nu presupus:
#     `test_the_guard_does_not_see_a_verdict_written_outside_the_three_functions`
#     rulează exact evadarea asta și o arată verde.
#
# Predicatul lucrează pe SINTAXĂ, iar proprietatea e SEMANTICĂ — deci nu i se mai
# cere unei gărzi structurale să dovedească acoperire comportamentală. Aia o cere
# a doua gardă, `test_the_taxonomy_produces_the_situations_a_round_is_judged_on`,
# care nu se uită deloc la textul modulului: numai la ce s-a întâmplat cu adevărat
# în rundele pe care le produce tabelul.
# ---------------------------------------------------------------------------
_SHIPPER_FILE = shipper.__file__

# Funcțiile din care iese verdictul unei runde. Scrise cu mâna fiindcă mecanismul
# nu le poate găsi singur: cine mută clasificarea în afara lor mută și lista de
# aici. E o margine a mulțimii, nu limita gărzii — limita e mai sus, și e faptul
# că se numără INSTRUCȚIUNI, nu decizii.
_EXITS = ("ship_once", "run_forever", "_round_failed")

# Numele sub care `ship_once` și `run_forever` țin verdictele.
_VERDICT_NAMES = ("outcomes", "outcome")


def _root_name(node) -> str | None:
    """Numele de la baza unei ținte: `outcomes[x]` și `outcomes` dau „outcomes”."""
    while isinstance(node, (ast.Subscript, ast.Attribute, ast.Starred)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _writes_a_verdict(statement) -> bool:
    """Instrucțiunea scrie în harta de verdicte? Prin ORICE formă de scriere.

    Atribuire simplă, cu adnotare, augmentată, țintă de `for`, walrus, sau un apel
    de metodă pe hartă (`outcomes.update(...)`, `outcomes.setdefault(...)`). Nu se
    caută `StreamOutcome`: ce se construiește înăuntru e liber, ce se cere e ca
    instrucțiunea să fie ATINSĂ de un rând al tabelului.
    """
    targets: list = []
    if isinstance(statement, ast.Assign):
        targets += statement.targets
    elif isinstance(statement, (ast.AnnAssign, ast.AugAssign, ast.For,
                                ast.AsyncFor)):
        targets.append(statement.target)
    for node in ast.walk(statement):
        if isinstance(node, ast.NamedExpr):
            targets.append(node.target)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and _root_name(node.func.value) in _VERDICT_NAMES):
            return True
    return any(_root_name(t) in _VERDICT_NAMES for t in targets)


def _round_verdict_sites() -> dict[str, tuple[int, int]]:
    """Fiecare loc din `shipper.py` de unde iese un verdict, citit din COD.

    Derivat, nu enumerat cu mâna: o listă scrisă de mână e completă în ziua în
    care a fost scrisă și tace pentru totdeauna după. Cheia e `funcție:fel:linie`,
    valoarea e intervalul instrucțiunii — adică exact ce se compară cu liniile
    chiar executate de tabelul de mai jos.
    """
    tree = ast.parse(inspect.getsource(shipper))
    functions = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def _owner(line: int) -> str:
        holding = [n for n in functions
                   if n.lineno <= line <= (n.end_lineno or n.lineno)]
        assert holding, f"linia {line} nu e în nicio funcție"
        return min(holding,
                   key=lambda n: (n.end_lineno or n.lineno) - n.lineno).name

    sites: dict[str, tuple[int, int]] = {}
    for function in functions:
        if function.name not in _EXITS:
            continue
        # `walk`, nu doar corpul: `batch_failed` e cuibărit în `ship_once`, iar o
        # evadare a folosit exact asta — ajutorul din casă, chemat dintr-o ramură
        # nouă. Cuibărit înseamnă înăuntru, deci intră în mulțime.
        for node in ast.walk(function):
            if not isinstance(node, ast.stmt):
                continue
            if isinstance(node, ast.Return) and node.value is not None:
                kind = "return"
            elif _writes_a_verdict(node):
                kind = "verdict"
            else:
                continue
            sites[f"{_owner(node.lineno)}:{kind}:{node.lineno}"] = (
                node.lineno, node.end_lineno or node.lineno)
    assert len(sites) >= 20, (
        f"garda vede {len(sites)} situri de verdict, sub prag:\n  "
        + "\n  ".join(sorted(sites))
        + "\nDouă citiri, și se aleg CITIND lista de mai sus, nu coborând pragul "
        "din reflex: ori predicatul nu mai găsește ieșirile — și atunci o ieșire "
        "nedeclarată n-ar mai fi raportată de nimeni —, ori o ieșire chiar a fost "
        "scoasă pe bună dreptate, ceea ce se întâmplă la o curățenie legitimă "
        "(cele patru `return`-uri de eșec din `if not pending:` strânse într-un "
        "ajutor sunt trei situri mai puține fără să fie acoperire mai puțină). "
        "Pragul se mută abia după ce lista arată că mulțimea e încă întreagă.")
    return sites


def _lines_of_shipper_executed_by(work) -> set[int]:
    """Ce linii din `shipper.py` a executat `work`. MĂSURAT, nu presupus.

    Traseul dinainte se pune la loc, nu se șterge: un `settrace(None)` ar opri
    tăcut orice unealtă de acoperire sub care ar rula suita.
    """
    seen: set[int] = set()

    def _line(frame, event, arg):
        if event == "line":
            seen.add(frame.f_lineno)
        return _line

    def _call(frame, event, arg):
        if frame.f_code.co_filename == _SHIPPER_FILE:
            seen.add(frame.f_lineno)
            return _line
        return None

    previous = sys.gettrace()
    sys.settrace(_call)
    try:
        work()
    finally:
        sys.settrace(previous)
    return seen


@dataclass(frozen=True)
class Verdict:
    """Ce trebuie să spună runda despre UN flux. `because` gol cere motiv gol."""

    ok: bool
    because: str = ""
    more: bool = False


@dataclass(frozen=True)
class _Case:
    """Un rând al taxonomiei: defectul, fluxurile cerute, verdictele cerute.

    `round_ok` / `round_says` sunt verdictul RUNDEI, nu al fluxurilor, și sunt
    obligatorii pentru cazurile care chiar produc un `ShipResult`. Fără ele,
    aceeași cauză poate ieși cu verdicte corecte per flux și cu o rundă care
    raportează `ok=True` și nu numește nimic — trei mutații de-astea au trecut
    prin toată suita pe 16 august 2026. `round_says` gol NU înseamnă „nu se
    verifică": înseamnă „motivul rundei trebuie să fie exact gol".

    `cause` se declară doar când două rânduri probează ACEEAȘI cauză în două forme
    de rundă — de pildă un ceas sărit cu lot și fără lot. Atunci cele două trebuie
    să ajungă la operator cu aceleași cuvinte, iar cauze diferite tot nu au voie
    să le împartă. Ce nu poate dovedi eticheta: că două rânduri care o împart chiar
    sunt aceeași cauză. Se scrie cu mâna, deci se citește la revizuire.
    """

    defect: str
    streams: tuple
    setup: Any
    expected: dict
    round_ok: bool | None = None
    round_says: str = ""
    driver: str = "round"
    cause: str = ""

    @property
    def failure_cause(self) -> str:
        return self.cause or self.setup.__name__


# -- ce se strică în fiecare caz --------------------------------------------
def _pair(**over):
    """Baza obișnuită: `audit_log` cu un rând restant, `incidents` cu cursor."""
    base = dict(rows=[_row(92001)],
                cursors={"ship:audit_log": 92000, "ship:incidents": 0},
                at={"ship:incidents": NOW - timedelta(hours=2)})
    base.update(over)
    return base


def _setup_healthy(monkeypatch, http, tmp_path):
    return _DB(**_pair()), _cfg()


def _setup_draining(monkeypatch, http, tmp_path):
    return (_DB(**_pair(rows=[_row(92001), _row(92002), _row(92003)])),
            _cfg(max_rows_per_batch=2))


def _setup_both_streams_advance(monkeypatch, http, tmp_path):
    """Starea NORMALĂ a unei gazde: amândouă fluxurile au ce trimite, și pleacă.

    `_pair()` singur lasă `incidents` fără rânduri, deci `advanced` iese cu un
    singur nume — și atunci orice ramură care se uită la CÂTE fluxuri au plecat
    e invizibilă. Rândurile mutabile sunt mai vechi decât `COMMIT_SAFETY_LAG_S`,
    altfel fereastra de siguranță le-ar tăia și fluxul ar părea liniștit.
    """
    return _DB(**_pair(mutable=[_mrow(1, 5)])), _cfg()


def _setup_both_streams_draining(monkeypatch, http, tmp_path):
    """Amândouă fluxurile ies cu lotul plin: amândouă mai au de drenat."""
    return (_DB(**_pair(rows=[_row(92001), _row(92002), _row(92003)],
                        mutable=[_mrow(1, 8), _mrow(2, 7), _mrow(3, 6)])),
            _cfg(max_rows_per_batch=2))


def _setup_only_one_stream_is_due(monkeypatch, http, tmp_path):
    """Un singur flux cerut rundei — ce cere bucla când celălalt e în backoff."""
    return (_DB(**_pair(rows=[_row(92001), _row(92002), _row(92003)])),
            _cfg(max_rows_per_batch=2))


def _setup_quiet(monkeypatch, http, tmp_path):
    return _DB(**_pair(rows=[])), _cfg()


def _setup_no_identity(monkeypatch, http, tmp_path):
    import sentinel.identity as identity

    monkeypatch.setattr(identity, "INSTANCE_ID_PATH", tmp_path / "nu-exista")
    return _DB(**_pair()), _cfg()


def _setup_database_error(monkeypatch, http, tmp_path):
    class _SchemaDrift(_DB):
        async def fetch(self, sql, *a):
            if "FROM incidents" in sql:
                raise RuntimeError('column "auto_action" does not exist')
            return await super().fetch(sql, *a)

    return _SchemaDrift(**_pair(mutable=[_mrow(1, 5)])), _cfg()


def _setup_our_own_defect(monkeypatch, http, tmp_path):
    """Un `AttributeError` din codul NOSTRU, nu o eroare a bazei."""
    class _Buggy(_DB):
        async def fetch(self, sql, *a):
            if "FROM incidents" in sql:
                raise AttributeError(
                    "'NoneType' object has no attribute 'isoformat'")
            return await super().fetch(sql, *a)

    return _Buggy(**_pair(mutable=[_mrow(1, 5)])), _cfg()


def _setup_every_stream_unreadable(monkeypatch, http, tmp_path):
    """Niciun flux nu se poate citi, deci nu e nimic de expediat — și nici bine."""
    class _Closed(_DB):
        async def fetch(self, sql, *a):
            raise RuntimeError("connection was closed in the middle of operation")

    return _Closed(**_pair(mutable=[_mrow(1, 5)])), _cfg()


def _setup_unencodable_row_with_nothing_pending(monkeypatch, http, tmp_path):
    return (_DB(**_pair(rows=[], mutable=[_mrow(1, 5) | {"title": 1.5}])),
            _cfg())


def _setup_clock_went_back_with_nothing_pending(monkeypatch, http, tmp_path):
    jumped = NOW - timedelta(hours=1)
    return _DB(**_pair(rows=[], mutable=[_mrow(1, 5)],
                       at={"ship:incidents": NOW}, now=jumped)), _cfg()


def _setup_clock_went_back(monkeypatch, http, tmp_path):
    jumped = NOW - timedelta(hours=1)
    return _DB(**_pair(mutable=[_mrow(1, 5)],
                       at={"ship:incidents": NOW}, now=jumped)), _cfg()


def _setup_missing_trigger(monkeypatch, http, tmp_path):
    return _DB(**_pair(mutable=[_mrow(1, 5)], trigger=False)), _cfg()


def _setup_unencodable_row(monkeypatch, http, tmp_path):
    return _DB(**_pair(mutable=[_mrow(1, 5) | {"title": 1.5}])), _cfg()


def _setup_unsignable_batch(monkeypatch, http, tmp_path):
    # `max_age_s` float: iese din contractul din signing.py, deci lotul chiar nu
    # se poate semna. Real, nu un `canonical` falsificat.
    return _DB(**_pair()), _cfg(max_age_s=300.5)


def _setup_unwrappable_batch(monkeypatch, http, tmp_path):
    """Împachetarea pentru transport pică.

    Spre deosebire de rândul de mai sus, aici defectul se PUNE, fiindcă nu există
    payload care să-l producă: `envelope.wrap` umple plicul până când inegalitatea
    receptorului e adevărată, deci pentru orice corp pe care expeditorul îl poate
    produce ea E adevărată prin construcție. Ramura există pentru ziua în care
    umplutura aia e calculată greșit, iar atunci trebuie să iasă ca VERDICT: o
    excepție scăpată din `ship_once` ar fi prinsă de bucla din `run_forever` ca
    orice altceva, iar fluxurile ar intra în exponențială cu un motiv care
    numește rețeaua.
    """
    def _broken(body):
        raise shipper.EnvelopeError("umplutură calculată greșit")

    monkeypatch.setattr(shipper, "wrap", _broken)
    return _DB(**_pair()), _cfg()


def _setup_network_down(monkeypatch, http, tmp_path):
    import httpx

    class _Dead(_Receiver):
        async def post(self, url, content=None, headers=None):
            raise OSError("conexiune refuzata")

    monkeypatch.setattr(httpx, "AsyncClient", _Dead)
    return _DB(**_pair()), _cfg()


def _setup_rejected_batch(monkeypatch, http, tmp_path):
    http.status = 413
    http.echo = False
    http.body = "Payload Too Large"
    return _DB(**_pair()), _cfg()


def _setup_no_echo(monkeypatch, http, tmp_path):
    http.echo = False
    http.body = '{"ok":true}'
    return _DB(**_pair()), _cfg()


def _setup_partial_echo(monkeypatch, http, tmp_path):
    import httpx

    class _KnowsOnlyAudit(_Receiver):
        """Agregatorul din capul modulului: știe `audit_log`, nu și `incidents`."""

        async def post(self, url, content=None, headers=None):
            signed = unwire(content)
            _Receiver.calls.append({"url": url, "body": signed, "wire": content,
                                    "headers": headers})
            sent = json.loads(signed)["cursors"]
            body = json.dumps({"ok": True,
                               "accepted": {"audit_log": sent["audit_log"]}})
            return SimpleNamespace(status_code=200, text=body)

    monkeypatch.setattr(httpx, "AsyncClient", _KnowsOnlyAudit)
    return _DB(**_pair(mutable=[_mrow(1, 5)])), _cfg()


def _setup_cursor_that_would_not_move(monkeypatch, http, tmp_path):
    class _Stuck(_DB):
        async def fetchval(self, sql, *a):
            if "GREATEST" in sql:
                return a[1] - 1     # baza a scris altceva decât s-a cerut
            return await super().fetchval(sql, *a)

    return _Stuck(**_pair()), _cfg()


def _setup_round_without_a_verdict(monkeypatch, http, tmp_path):
    async def _silent(db, cfg, secret, streams=None):
        return shipper.ShipResult(False, "o ramură care iese fără să scrie `streams`")

    monkeypatch.setattr(shipper, "ship_once", _silent)
    return _DB(**_pair()), _cfg()


TAXONOMY = (
    _Case(
        defect="o rundă curată raportată ca eșec ar pune fluxul sănătos în "
               "exponențială fără să fie nimic stricat",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_healthy,
        expected={"audit_log": Verdict(True), "incidents": Verdict(True)},
        round_ok=True, round_says=""),
    _Case(
        defect="o restanță drenată la cadența de regim staționar se recuperează "
               "de `interval_s / DRAIN_PAUSE_S` ori mai încet",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_draining,
        expected={"audit_log": Verdict(True, more=True),
                  "incidents": Verdict(True)},
        round_ok=True, round_says=""),
    _Case(
        defect="cât timp niciun rând nu expedia DOUĂ fluxuri cu succes în același "
               "lot, orice ramură care se uită la câte au plecat era invizibilă — "
               "iar proprietatea de titlu a modulului („un flux oprit nu are voie "
               "să încetinească fluxul sănătos”) nu era probată în starea ei "
               "normală, cu amândouă în mișcare",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_both_streams_advance,
        expected={"audit_log": Verdict(True), "incidents": Verdict(True)},
        round_ok=True, round_says=""),
    _Case(
        defect="două fluxuri cu restanță în aceeași rundă: dacă unul dintre ele "
               "iese cu `more=False`, restanța lui se recuperează de "
               "`interval_s / DRAIN_PAUSE_S` — de 60 de ori — mai încet, și nimic "
               "nu se plânge, fiindcă fluxul chiar livrează la fiecare rundă",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_both_streams_draining,
        expected={"audit_log": Verdict(True, more=True),
                  "incidents": Verdict(True, more=True)},
        round_ok=True, round_says=""),
    _Case(
        defect="runda cerută pentru UN singur flux — ce se întâmplă la fiecare "
               "rundă în care celălalt e în exponențială — nu era produsă de "
               "niciun rând, deci o ramură care se uită la câte fluxuri s-au "
               "cerut ar fi trecut nevăzută prin toată suita",
        streams=(shipper.AUDIT_STREAM,),
        setup=_setup_only_one_stream_is_due,
        expected={"audit_log": Verdict(True, more=True)},
        round_ok=True, round_says=""),
    _Case(
        defect="o gazdă liniștită raportată ca eșec ar urca pauza tuturor "
               "fluxurilor fără ca ceva să nu meargă",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_quiet,
        expected={"audit_log": Verdict(True), "incidents": Verdict(True)},
        round_ok=True, round_says="nimic de expediat"),
    _Case(
        defect="fără identitate rândurile ar ajunge în istoria instanței "
               "`default`, amestecate cu ale altei gazde — cauza e a RUNDEI, "
               "deci cad toate fluxurile cerute",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_no_identity,
        expected={"audit_log": Verdict(False, "fără identitate"),
                  "incidents": Verdict(False, "fără identitate")},
        round_ok=False, round_says="fără identitate"),
    _Case(
        defect="o derivă de schemă pe `incidents` doboară și `audit_log`, deși "
               "acela se strânsese deja — cauza într-un flux, efectul în două",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_database_error,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "baza locală")},
        round_ok=False, round_says="baza locală",
        cause="fluxul nu se poate citi din baza locală"),
    _Case(
        defect="un defect al codului NOSTRU raportat drept „baza locală” îl "
               "trimite pe operator în Postgres după o cauză care e în Python — "
               "o oră pierdută în casa altuia, la fiecare rundă",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_our_own_defect,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "defect în expeditor")},
        round_ok=False, round_says="defect în expeditor"),
    _Case(
        defect="o rundă în care NICIUN flux nu s-a putut citi iese „nimic de "
               "expediat”, adică tăcerea din cauza unei baze inaccesibile arată "
               "exact ca o gazdă liniștită — contopirea pe care capul modulului "
               "o interzice",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_every_stream_unreadable,
        expected={"audit_log": Verdict(False, "baza locală"),
                  "incidents": Verdict(False, "baza locală")},
        round_ok=False, round_says="baza locală",
        cause="fluxul nu se poate citi din baza locală"),
    _Case(
        defect="un ceas dat înapoi oprește fluxul mutabil, iar `audit_log` — "
               "care nu se uită la ceas — nu are de ce să tacă odată cu el",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_clock_went_back,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "ceasul bazei")},
        round_ok=False, round_says="ceasul bazei",
        cause="ceasul bazei a sărit înapoia filigranului"),
    _Case(
        defect="ceasul sărit pe o rundă fără niciun rând de trimis: „n-am "
               "expediat fiindcă nu s-a schimbat nimic” și „n-am expediat "
               "fiindcă ceasul a sărit” ar arăta identic, iar cursorul oprit "
               "n-ar mai fi numit de nimeni",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_clock_went_back_with_nothing_pending,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "ceasul bazei")},
        round_ok=False, round_says="cursor pe timp oprit",
        cause="ceasul bazei a sărit înapoia filigranului"),
    _Case(
        defect="triggerul lipsă face fluxul mutabil să pară la zi; oprit, n-are "
               "voie să oprească și lanțul de audit",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_missing_trigger,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False,
                                       "niciun trigger BEFORE UPDATE activ")},
        round_ok=False, round_says="niciun trigger BEFORE UPDATE activ"),
    _Case(
        defect="un rând necodificabil din `incidents` oprea și singura copie "
               "verificabilă a lanțului de audit din afara gazdei",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_unencodable_row,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "rând necodificabil")},
        round_ok=False, round_says="rând necodificabil",
        cause="rând pe care `encode_value` nu-l poate expedia"),
    _Case(
        defect="rândul necodificabil pe o rundă fără nimic de trimis: runda ar "
               "ieși „nimic de expediat”, adică un flux blocat pentru totdeauna "
               "raportat ca gazdă liniștită",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_unencodable_row_with_nothing_pending,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "rând necodificabil")},
        round_ok=False, round_says="rând necodificabil",
        cause="rând pe care `encode_value` nu-l poate expedia"),
    _Case(
        defect="un lot nesemnabil e un refuz al LOTULUI: cade cine era în el, "
               "iar fluxul care n-avea nimic de trimis nu e cu nimic mai rău",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_unsignable_batch,
        expected={"audit_log": Verdict(False, "lot nesemnabil"),
                  "incidents": Verdict(True)},
        round_ok=False, round_says="lot nesemnabil"),
    _Case(
        defect="un defect al împachetării pentru transport ar ieși din rundă ca "
               "excepție, nu ca verdict: bucla ar opri toate fluxurile cu un "
               "motiv care numește rețeaua, în timp ce cauza e în expeditor",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_unwrappable_batch,
        expected={"audit_log": Verdict(False, "lot neîmpachetabil"),
                  "incidents": Verdict(True)},
        round_ok=False, round_says="lot neîmpachetabil"),
    _Case(
        defect="o rețea căzută ar pune în exponențială și un flux care n-a "
               "trimis nimic, deci o gazdă liniștită pe `incidents` ar expedia "
               "`audit_log` din oră în oră",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_network_down,
        expected={"audit_log": Verdict(False, "agregator inaccesibil"),
                  "incidents": Verdict(True)},
        round_ok=False, round_says="agregator inaccesibil"),
    _Case(
        defect="un `HTTP 413` produs de rândurile unui flux n-are voie să "
               "încetinească fluxul care nici măcar nu era în lot",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_rejected_batch,
        expected={"audit_log": Verdict(False, "HTTP 413"),
                  "incidents": Verdict(True)},
        round_ok=False, round_says="HTTP 413 pe lotul comun"),
    _Case(
        defect="un 200 fără ecou — CDN, vhost greșit rutat — ar avansa cursorul "
               "și ar pierde rândurile definitiv și în tăcere",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_no_echo,
        expected={"audit_log": Verdict(False, "200 fără ecou"),
                  "incidents": Verdict(True)},
        round_ok=False, round_says="200 fără ecou"),
    _Case(
        defect="un agregator care cunoaște `audit_log` și nu `incidents`: fluxul "
               "refuzat rămâne programat sănătos la nesfârșit, deci nu intră în "
               "backoff, deci ERROR-ul care îl numește nu se emite niciodată, "
               "deși cursorul lui nu mai avansează",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_partial_echo,
        expected={"audit_log": Verdict(True),
                  "incidents": Verdict(False, "neconfirmat de agregator")},
        round_ok=False, round_says="incidents: lipsește din `accepted`"),
    _Case(
        defect="un cursor pe care baza a refuzat să-l mute, raportat ca flux "
               "livrat: `ship:lag` ar arăta o restanță pe care nimeni n-o explică",
        streams=(shipper.AUDIT_STREAM, INCIDENTS),
        setup=_setup_cursor_that_would_not_move,
        expected={"audit_log": Verdict(False, "cursorul nu s-a mutat"),
                  "incidents": Verdict(True)},
        # Gol dinadins, și e o constatare, nu o cerință: azi runda iese
        # `ok=False` cu motivul GOL, fiindcă `reason` se construiește doar din
        # ecou, ceas, codificare și bază — un cursor refuzat de bază nu apare în
        # niciuna. Fluxul își duce cauza în `streams`, deci nu se pierde nimic
        # pentru buclă; ce nu se poate citi e `ShipResult.reason` singur. Scris
        # aici ca să se vadă, nu reparat în aceeași trecere.
        round_ok=False, round_says=""),
    _Case(
        defect="un flux despre care runda n-a spus nimic, citit ca succes: ar "
               "reveni la `interval_s` la nesfârșit, fără nicio urmă — „nu știu” "
               "și „a plecat” nu au voie să arate la fel",
        streams=(shipper.AUDIT_STREAM,),
        setup=_setup_round_without_a_verdict,
        driver="loop",
        expected={"audit_log": Verdict(False,
                                       "runda nu a raportat niciun verdict")}),
)


def _drive(case, monkeypatch, http, tmp_path) -> tuple[dict, Any]:
    """Rulează un caz. Întoarce (verdictele per flux, rezultatul RUNDEI).

    Rezultatul rundei e `None` pentru cazurile pe buclă: acolo `ship_once` e
    falsificat, deci `ShipResult`-ul e al fixturii, iar o aserțiune pe el ar
    verifica fixtura în loc de cod.
    """
    if case.driver == "loop":
        monkeypatch.setattr(shipper, "get_secrets",
                            lambda *a, **k: SimpleNamespace(get=lambda *_: "cheie"))
        monkeypatch.setattr(shipper, "STREAMS", case.streams)
        db, cfg = case.setup(monkeypatch, http, tmp_path)
        # Verdictul cu care bucla chiar PROGRAMEAZĂ fluxul, nu cel întors de
        # rundă: între cele două stă exact ramura care completează un flux rămas
        # fără verdict, iar ea e una dintre căile de măsurat.
        recorded: dict = {}
        real_record = shipper.ShipSchedule.record

        def _spy(self, name, outcome, *a, **kw):
            recorded[name] = outcome
            return real_record(self, name, outcome, *a, **kw)

        monkeypatch.setattr(shipper.ShipSchedule, "record", _spy)
        _fake_clock(monkeypatch, stop_after=1)
        with pytest.raises(KeyboardInterrupt):
            run(shipper.run_forever(db, cfg))
        return recorded, None

    db, cfg = case.setup(monkeypatch, http, tmp_path)
    result = run(shipper.ship_once(db, cfg, "k", case.streams))
    return result.streams, result


def _for_each_case(work) -> list:
    """Rulează FIECARE rând al tabelului într-o fixtură curată. `work(case, patch, folder)`.

    Aceeași pregătire pentru amândouă gărzile, dinadins: două copii ale ei ar
    putea să nu fie de acord, iar atunci una dintre gărzi ar măsura o rundă pe
    care cealaltă n-o vede — exact felul de dezacord tăcut pe care tabelul există
    să-l scoată. Contoarele de eșec sunt stare de modul și se pun pe zero înainte
    de fiecare caz: pornite de la 2, un rând ar muta pragurile din următorul.
    """
    produced: list = []
    for case in TAXONOMY:
        with pytest.MonkeyPatch.context() as patch:
            import httpx

            import sentinel.identity as identity_module

            _Receiver.calls, _Receiver.status = [], 200
            _Receiver.echo, _Receiver.body = True, ""
            patch.setattr(httpx, "AsyncClient", _Receiver)
            with tempfile.TemporaryDirectory() as folder:
                target = Path(folder) / "instance_id"
                target.write_text(ID_A + "\n", encoding="utf-8")
                patch.setattr(identity_module, "INSTANCE_ID_PATH", target)
                shipper._identity_failures = 0
                shipper._canonical_failures = 0
                produced.append(work(case, patch, Path(folder)))
    shipper._identity_failures = 0
    shipper._canonical_failures = 0
    assert len(produced) == len(TAXONOMY), \
        f"{len(produced)} runde pentru {len(TAXONOMY)} rânduri — un rând s-a sărit"
    return produced


@pytest.mark.parametrize("case", TAXONOMY, ids=[
    f"{i:02d}-{c.setup.__name__[len('_setup_'):]}"
    for i, c in enumerate(TAXONOMY)])
def test_ship_once_gives_every_stream_the_verdict_its_own_cause_earned(
        case, monkeypatch, http, tmp_path):
    """Fiecare cale de ieșire își clasifică fluxurile cum spune tabelul.

    Eșecul pe care îl previne, în termenii operatorului: un flux clasificat
    greșit e ori unul pus în exponențială fără vină — și atunci o copie care
    funcționează pleacă de zeci de ori mai rar —, ori unul programat sănătos
    deși nu livrează, și atunci nu ajunge niciodată la pragul care scrie
    `ERROR shipper stream has been failing | stream=<flux>`. A doua e tăcută:
    `ship:lag` se face degradat fiindcă restanța chiar crește, dar singura linie
    care numește ȘI fluxul ȘI cauza nu se scrie niciodată.

    Se cere ȘI verdictul RUNDEI, nu doar cele per flux. Cele două se pot
    contrazice tăcut: cu verdictele per flux corecte, `ShipResult.ok` poate ieși
    `True` peste un flux ilizibil și `reason` poate să nu-l numească deloc — două
    mutații care au trecut prin toată suita, fiindcă nimic nu se uita la rezultatul
    rundei decât în cazurile fericite. `ok` al rundei e ce ajunge în jurnalul
    buclei; un `True` acolo e ultima linie care putea spune că runda n-a fost
    curată.

    `case.defect` spune, pentru fiecare rând, ce anume s-ar strica.
    """
    produced, round_result = _drive(case, monkeypatch, http, tmp_path)

    assert set(produced) == set(case.expected), (
        f"{case.defect}\n  fluxuri cu verdict: {sorted(produced)}\n"
        f"  fluxuri cerute:     {sorted(case.expected)}")
    for name, want in case.expected.items():
        got = produced[name]
        assert got.ok is want.ok, (
            f"{case.defect}\n  {name}: ok={got.ok}, așteptat {want.ok} "
            f"(motiv: {got.reason!r})")
        assert got.more is want.more, (
            f"{case.defect}\n  {name}: more={got.more}, așteptat {want.more}")
        if want.ok:
            assert got.reason == "", (
                f"{case.defect}\n  {name}: flux reușit cu motiv: {got.reason!r}")
        else:
            assert want.because in got.reason, (
                f"{case.defect}\n  {name}: motivul nu numește cauza\n"
                f"  cerut:  {want.because!r}\n  produs: {got.reason!r}")

    if round_result is None:
        assert case.round_ok is None, (
            f"{case.defect}\n  cazul e pe buclă, deci `ShipResult`-ul e al "
            f"fixturii: o cerință pe el ar verifica fixtura")
        return
    assert case.round_ok is not None, (
        f"{case.defect}\n  rândul nu declară verdictul RUNDEI (`round_ok`). "
        f"Runda a ieșit ok={round_result.ok}, motiv {round_result.reason!r}")
    assert round_result.ok is case.round_ok, (
        f"{case.defect}\n  runda: ok={round_result.ok}, așteptat "
        f"{case.round_ok} (motiv: {round_result.reason!r})")
    if case.round_says:
        assert case.round_says in round_result.reason, (
            f"{case.defect}\n  motivul RUNDEI nu numește cauza\n"
            f"  cerut:  {case.round_says!r}\n  produs: {round_result.reason!r}")
    else:
        # Gol cerut înseamnă gol măsurat. Un `"" in reason` ar fi adevărat mereu,
        # adică rândul ar declara ceva și n-ar verifica nimic — chiar aserțiunea
        # care nu verifică nimic din CLAUDE.md.
        assert round_result.reason == "", (
            f"{case.defect}\n  rândul cere motiv gol pentru rundă, s-a produs "
            f"{round_result.reason!r}")


def test_the_taxonomy_covers_every_exit_that_writes_a_stream_verdict():
    """Eșecul pe care îl previne: o cale de ieșire nouă, pe care n-o măsoară nimeni.

    Patru mutații ale clasificării au trecut prin 454 de teste fiindcă garda de
    atunci recunoștea cazuri în loc să numere căi. A doua ei formă număra apelurile
    scrise `StreamOutcome(...)`, adică tot o ortografie, și a fost evadată de două
    ori în aceeași zi: o ramură nouă care refolosea `batch_failed`, și una care
    chema constructorul printr-un alias. Amândouă verzi pe suita întreagă.

    Aici se numără IEȘIRILE: fiecare `return` cu valoare și fiecare instrucțiune
    care scrie în `outcomes`/`outcome`, din `ship_once`, `run_forever`,
    `_round_failed` și din funcțiile cuibărite în ele. Cum e construit verdictul
    înăuntru nu mai contează — o ieșire pe care niciun rând al tabelului n-o
    execută face testul roșu, cu numele funcției și linia.

    Ce NU vede garda e măsurat separat, nu presupus, în
    `test_the_guard_does_not_see_a_verdict_written_outside_the_three_functions`.

    A doua jumătate păzește un eșec pe care fișierul ăsta l-a mai avut de trei
    ori: o listă parametrizată ieșită goală, deci sărită tăcut, deci verde.
    """
    assert len(TAXONOMY) >= 19, \
        f"tabelul taxonomiei s-a golit sau s-a scurtat: {len(TAXONOMY)} cazuri"
    names = [c.setup.__name__ for c in TAXONOMY]
    assert len(set(names)) == len(names), f"cazuri care se suprascriu: {names}"
    missing = [c.setup.__name__ for c in TAXONOMY
               if c.driver == "round" and c.round_ok is None]
    assert not missing, (
        f"rânduri care nu declară verdictul RUNDEI: {missing}. Un rând fără "
        f"`round_ok` verifică fluxurile și lasă runda nemăsurată.")

    sites = _round_verdict_sites()
    executed: set[int] = set()
    for lines in _for_each_case(
            lambda case, patch, folder: _lines_of_shipper_executed_by(
                lambda: _drive(case, patch, _Receiver, folder))):
        executed |= lines

    untouched = sorted(
        name for name, (start, end) in sites.items()
        if not any(line in executed for line in range(start, end + 1)))
    assert not untouched, (
        "căi de ieșire care scriu un verdict și pe care niciun rând al "
        f"taxonomiei nu le atinge: {untouched}. Fiecare ramură nouă își declară "
        "cazul în TAXONOMY, altfel n-o măsoară nimic.")


# ---------------------------------------------------------------------------
# A DOUA GARDĂ: situațiile pe care tabelul trebuie să le PRODUCĂ
#
# Garda de mai sus citește `shipper.py` ca text și stabilește exact un lucru:
# fiecare instrucțiune de ieșire e executată de vreun rând. A fost evadată de trei
# ori, de fiecare dată mutând decizia înăuntrul unei instrucțiuni pe care tabelul
# deja o executa — deci într-un loc unde citirea textului nu mai răspunde.
#
# Ce le lega pe toate trei nu era o slăbiciune a predicatului, era o gaură în
# TABEL. Instrumentat pe 16 august 2026, peste 2198 de teste, `advanced` din
# `ship_once` a ieșit așa:
#
#     37 ['audit_log']      15 ['incidents']      3 []
#
# Niciodată două fluxuri. Adică starea normală a unei gazde cu `audit_log` și
# `incidents` amândouă în mișcare — exact starea despre care e proprietatea de
# titlu a modulului — nu era produsă de niciun test din repository, iar o ramură
# care se uita la `len(advanced)` se ascundea în gaura aia fără să atingă nimic.
#
# Deci a doua gardă nu se uită deloc la textul modulului. Se uită la ce s-a
# ÎNTÂMPLAT în rundele pe care le produce tabelul, și cere ca situațiile de mai
# jos să apară măcar o dată fiecare. Ea ar fi prins toate trei evadările fără să
# știe cum se scrie un verdict sau unde e definit un ajutor: o mutație care face
# ca două fluxuri să nu mai dreneze niciodată în aceeași rundă stinge situația, iar
# situația stinsă e roșu.
#
# **Unde se termină și ea**, măsurat pe o a cincea evadare, nu presupus:
#
#     if written != asked and batch.stream.cursor_kind != MUTABLE:
#
# Un cursor pe care baza a refuzat să-l mute e raportat ca livrare — dar numai pe
# fluxul mutabil. Amândouă gărzile rămân verzi: instrucțiunea e aceeași (deci
# prima n-o vede), iar toate situațiile de mai jos continuă să apară (deci nici a
# doua). Cauza e că tabelul probează „cursorul nu s-a mutat" o singură dată, pe
# fluxul pe `id`. O listă de situații e o alegere, nu o demonstrație de
# completitudine; ce se cere de la ea e să fie citită, nu crezută. Închiderea
# evadării ăsteia cere un rând nou (cursor refuzat pe fluxul mutabil), și e scrisă
# aici ca să fie decisă, nu strecurată în aceeași trecere.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _Observation:
    """Ce s-a întâmplat CU ADEVĂRAT într-o rundă a tabelului.

    Nimic din asta nu se declară în `_Case`: se măsoară din rundă. Un câmp
    declarat de rând ar face garda să verifice tabelul, nu expeditorul.
    """

    case: str
    requested: frozenset        # fluxurile cerute rundei
    in_batch: frozenset         # fluxurile care chiar au ajuns în lotul comun
    verdicts: dict              # nume -> StreamOutcome, ce a produs runda
    advanced: frozenset         # fluxurile al căror cursor a avansat
    round_ok: bool | None       # `None` = cazul e pe buclă, runda e a fixturii


def _observe(case, patch, folder) -> _Observation:
    """Rulează un rând și strânge faptele. `in_batch` e SPIONAT, nu dedus.

    Cine a fost în lot nu se poate citi din corpul cererii: pe cazul cu rețeaua
    căzută nu se trimite nicio cerere, iar lotul chiar exista. Se ia deci din ce
    întoarce `collect_stream` — adică din chiar ce `ship_once` numește `pending`.
    """
    in_batch: set = set()
    collect = shipper.collect_stream

    async def _spy(db, cfg, stream):
        batch = await collect(db, cfg, stream)
        if batch.rows:
            in_batch.add(batch.stream.name)
        return batch

    patch.setattr(shipper, "collect_stream", _spy)
    verdicts, result = _drive(case, patch, _Receiver, folder)
    return _Observation(
        case=case.setup.__name__,
        requested=frozenset(s.name for s in case.streams),
        in_batch=frozenset(in_batch),
        verdicts=dict(verdicts),
        advanced=frozenset(result.advanced if result else ()),
        round_ok=None if result is None else result.ok)


def _delivered(o: _Observation) -> set:
    return {name for name, v in o.verdicts.items() if v.ok}


def _failed(o: _Observation) -> set:
    return {name for name, v in o.verdicts.items() if not v.ok}


def _draining(o: _Observation) -> set:
    return {name for name, v in o.verdicts.items() if v.ok and v.more}


@dataclass(frozen=True)
class _Situation:
    """O situație pe care tabelul trebuie s-o producă, și ce rămâne nemăsurat fără ea."""

    what: str
    harm: str
    holds: Any


SITUATIONS = (
    _Situation(
        what="două fluxuri își avansează cursorul în aceeași rundă, amândouă la zi",
        harm="starea normală a gazdei nu e produsă de nimeni, deci o ramură care "
             "se uită la `len(advanced)` nu are unde să se vadă",
        holds=lambda o: len(o.advanced) >= 2 and not _draining(o)),
    _Situation(
        what="două fluxuri mai au de drenat în aceeași rundă",
        harm="un flux cu restanță poate fi pus înapoi pe `interval_s` în loc de "
             "`DRAIN_PAUSE_S` — recuperare de 60 de ori mai lentă — fără ca nimic "
             "să se plângă, fiindcă fluxul chiar livrează la fiecare rundă",
        holds=lambda o: len(_draining(o)) >= 2),
    _Situation(
        what="un flux drenează, iar celălalt e în regim staționar",
        harm="cele două cadențe s-ar putea contopi — amândouă pe `interval_s` sau "
             "amândouă pe `DRAIN_PAUSE_S` — fără să se vadă diferența",
        holds=lambda o: bool(_draining(o)) and bool(_delivered(o) - _draining(o))),
    _Situation(
        what="două fluxuri în același lot comun",
        harm="un lot cu un singur flux nu probează nici compunerea lui, nici "
             "ecoul cerut pe fiecare flux în parte",
        holds=lambda o: len(o.in_batch) >= 2),
    _Situation(
        what="un flux e în lotul comun, altul e cerut rundei dar în afara lui",
        harm="fără ea nu se poate vedea deloc dacă un refuz al lotului cade pe "
             "cine era în el sau pe toate fluxurile cerute",
        holds=lambda o: bool(o.in_batch) and bool(o.requested - o.in_batch)),
    _Situation(
        what="lotul comun cade, iar fluxul din afara lui rămâne bun",
        harm="`batch_failed` întins tăcut peste toate fluxurile cerute — chiar "
             "cuplajul de reparat: o gazdă liniștită pe `incidents` ar expedia "
             "`audit_log` din oră în oră fiindcă lotul a fost refuzat o dată",
        holds=lambda o: bool(o.in_batch & _failed(o))
        and bool((o.requested - o.in_batch) & _delivered(o))),
    _Situation(
        what="un flux pleacă și altul cade în aceeași rundă",
        harm="dacă orice rundă e ori toată bună ori toată rea, un verdict copiat "
             "de la vecin arată exact ca unul câștigat",
        holds=lambda o: bool(_delivered(o)) and bool(_failed(o))),
    _Situation(
        what="o rundă fără niciun rând de trimis, care totuși nu e curată",
        harm="tăcerea unui flux blocat ar arăta ca o gazdă liniștită — contopirea "
             "pe care capul modulului o interzice",
        holds=lambda o: o.round_ok is False and not o.in_batch),
    _Situation(
        what="o rundă fără niciun rând de trimis și fără nimic stricat",
        harm="fără contrastul ăsta, „nimic de expediat” nu mai înseamnă nimic",
        holds=lambda o: o.round_ok is True and not o.in_batch),
    _Situation(
        what="toate fluxurile cerute cad în aceeași rundă",
        harm="o cauză a RUNDEI care ar lăsa un flux fără verdict n-ar avea unde "
             "să se vadă",
        holds=lambda o: len(o.requested) >= 2 and _failed(o) == set(o.requested)),
    _Situation(
        what="o rundă cerută pentru un singur flux",
        harm="e chiar ce cere bucla cât timp celălalt flux e în exponențială; "
             "nefiind produsă, o ramură care se uită la câte fluxuri s-au cerut "
             "trece nevăzută prin toată suita",
        holds=lambda o: o.round_ok is not None and len(o.requested) == 1),
)


def test_the_taxonomy_produces_the_situations_a_round_is_judged_on():
    """Eșecul pe care îl previne: o situație de producție pe care n-o rulează nimeni.

    În termenii operatorului: o gazdă cu amândouă fluxurile în mișcare e starea
    NORMALĂ, iar până azi niciun test din repository nu expedia două fluxuri cu
    succes în același lot. Orice defect care se manifestă numai acolo — un flux cu
    restanță pus înapoi pe `interval_s` în loc de `DRAIN_PAUSE_S`, deci de 60 de
    ori mai încet, în timp ce el chiar livrează la fiecare rundă și deci nu ajunge
    niciodată la `ERROR shipper stream has been failing` — trecea verde prin toată
    suita. Restanța crește, `ship:lag` se degradează, și nimic nu numește cauza.

    Garda de deasupra nu putea vedea așa ceva și nici nu i se mai cere: ea lucrează
    pe sintaxă, iar proprietatea e semantică. Asta nu se uită deloc la textul
    modulului. Rulează tabelul, MĂSOARĂ ce s-a întâmplat în fiecare rundă, și cere
    ca fiecare situație din `SITUATIONS` să apară măcar o dată. O mutație care
    stinge o situație — care face ca două fluxuri să nu mai dreneze niciodată în
    aceeași rundă, de pildă — o înroșește, oriunde ar fi scrisă.

    Ce NU dovedește: că lista e completă. E o alegere de situații, iar unde se
    termină e scris, măsurat, în comentariul de deasupra.
    """
    assert len(SITUATIONS) >= 11, (
        f"lista de situații s-a scurtat la {len(SITUATIONS)}:\n  "
        + "\n  ".join(s.what for s in SITUATIONS)
        + "\nSe citește lista înainte de a coborî pragul: ori o situație a fost "
        "scoasă din greșeală — și atunci nimeni nu mai cere tabelului s-o "
        "producă —, ori două au fost contopite pe bună dreptate. A doua se vede "
        "din lista de sus; prima nu se vede din numărul de aici.")

    observations = _observe_the_taxonomy()
    unseen = [s for s in SITUATIONS
              if not any(s.holds(o) for o in observations)]
    assert not unseen, (
        "situații pe care niciun rând al tabelului nu le mai produce:\n"
        + "\n".join(f"  * {s.what}\n    ce rămâne nemăsurat: {s.harm}"
                    for s in unseen)
        + "\nOri s-a șters rândul care le producea — și atunci se pune la loc —, "
          "ori o schimbare din `ship_once` a făcut situația imposibilă, și atunci "
          "cauza e acolo, nu aici.")


def _observe_the_taxonomy() -> list:
    """Rundele tabelului, măsurate. Scoasă din test ca s-o poată folosi și martorul."""
    observations = _for_each_case(_observe)
    assert observations, "tabelul s-a golit: nu s-a măsurat nicio rundă"
    return observations


def test_no_situation_is_produced_by_every_round_of_the_taxonomy():
    """Eșecul pe care îl previne: o situație scrisă atât de larg încât nu cere nimic.

    O cerință adevărată în FIECARE rundă nu poate fi încălcată de nicio ștergere
    și de nicio mutație — adică e un rând în listă și zero apărare, exact
    aserțiunea care trece verde fără să verifice nimic din CLAUDE.md. Un
    `holds=lambda o: True` scris din grabă e cazul limită; unul scris din
    neatenție (`len(o.requested) >= 1`) arată la fel de bine în listă și e la fel
    de gol.

    Ce NU cere: ca martorul să fie unic. Mai multe rânduri care produc aceeași
    situație e redundanță utilă.
    """
    assert SITUATIONS, "lista de situații e goală; testul ăsta n-ar verifica nimic"
    observations = _observe_the_taxonomy()
    always = [s.what for s in SITUATIONS
              if all(s.holds(o) for o in observations)]
    assert not always, (
        f"situații adevărate în toate cele {len(observations)} runde ale "
        f"tabelului, deci pe care nu le ține niciun rând: {always}. Se "
        "restrânge predicatul până când numește o situație anume.")


def test_the_guard_does_not_see_a_verdict_written_outside_the_three_functions():
    """Limita gărzii, MĂSURATĂ. O gardă care se declară completă e o pană.

    `ship_once` are docstringul care spune ce ține garda și ce nu. Propoziția aia
    a fost odată o promisiune („o ramură nouă care scrie un verdict și nu-și
    declară cazul face testul roșu") care nu era adevărată, iar din ea s-au scris
    două evadări. Deci limita nu se mai afirmă, se probează: se compilează o formă
    a modulului cu un verdict scris de un ajutor definit ÎN AFARA celor trei
    funcții și chemat dintr-o instrucțiune care oricum se execută, și se arată că
    mulțimea derivată nu se schimbă.

    Roșu aici înseamnă că garda a devenit mai puternică decât spune comentariul
    de deasupra taxonomiei — se lărgește propoziția, nu se șterge testul.
    """
    source = inspect.getsource(shipper)
    escape = source.replace(
        "        return ShipResult(True, \"nimic de expediat\", streams=outcomes)",
        "        return ShipResult(True, \"nimic de expediat\",\n"
        "                          streams=_quietly_pass(outcomes))")
    assert escape != source, \
        "ancora evadării nu mai există în shipper.py; testul nu mai probează nimic"
    escape += (
        "\n\ndef _quietly_pass(outcomes):\n"
        "    return {name: StreamOutcome(True) for name in outcomes}\n")

    def _sites(text: str) -> set[str]:
        tree = ast.parse(text)
        found = set()
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if function.name not in _EXITS:
                continue
            for node in ast.walk(function):
                if not isinstance(node, ast.stmt):
                    continue
                if ((isinstance(node, ast.Return) and node.value is not None)
                        or _writes_a_verdict(node)):
                    found.add(f"{node.lineno}")
        return found

    assert len(_sites(escape)) == len(_sites(source)), (
        "garda a prins un verdict scris în afara celor trei funcții — ceea ce e "
        "bine, dar comentariul de deasupra taxonomiei îl dă ca exemplu de ce NU "
        "poate. Se lărgește propoziția.")


def test_two_different_causes_never_reach_the_operator_with_the_same_words():
    """Eșecul pe care îl previne: două cauze cu remedii diferite, un singur text.

    S-a mai întâmplat exact aici — un rând necodificabil ieșea prin `stall`,
    adică operatorul era trimis la `timedatectl` pentru o valoare pe care
    `encode_value` n-o cunoaște. Motivul e singurul lucru pe care verdictul îl
    duce mai departe, în `ERROR … | detail=`, deci dacă două rânduri ale
    taxonomiei l-ar împărți, unul dintre ele l-ar trimite pe operator în altă
    parte decât la cauza lui.

    Se grupează pe CAUZĂ, nu pe fixtură, de când tabelul are aceeași cauză probată
    în două forme de rundă — cu lot și fără. Gruparea taie în două direcții: cauze
    diferite tot nu au voie să împartă un text, iar două forme ale aceleiași cauze
    trebuie să ajungă la operator cu ACELAȘI text, ceea ce înainte nu cerea nimeni.
    """
    failing: dict = {}
    for case in TAXONOMY:
        for want in case.expected.values():
            if not want.ok:
                failing.setdefault(case.failure_cause, set()).add(want.because)

    assert len(failing) >= 13, \
        f"prea puține cauze de eșec în tabel: {sorted(failing)}"
    words: dict = {}
    for defect, fragments in failing.items():
        assert len(fragments) == 1, \
            f"{defect} cere două texte diferite: {fragments}"
        fragment = fragments.pop()
        assert fragment not in words, (
            f"{defect} și {words[fragment]} ajung la operator cu același text "
            f"({fragment!r}), deși cer lucruri diferite de la el")
        words[fragment] = defect


def test_the_batch_carries_the_full_key_set_for_a_stream_whose_source_deletes(http):
    """Capăt la capăt: lista de reconciliere ajunge în lotul SEMNAT.

    Eșecul pe care îl previne e unul pe care testele unitare ale lui
    `_prune_keys` nu-l pot vedea: funcția e învelită într-un `except` larg, ca o
    eroare de igienă să nu pice lotul. Cu dublul care nu cunoaște interogarea,
    excepția ar fi înghițită, lista n-ar pleca niciodată, și totul ar fi verde.
    Aserțiunea de aici se uită la corpul cererii, adică la fapt.
    """
    def _srow(key: str):
        # Îmbătrânit dinadins: interogarea taie coada proaspătă cu
        # `COMMIT_SAFETY_LAG_S`, iar un rând la `NOW` n-ar fi strâns deloc.
        moment = NOW - timedelta(minutes=5)
        return {"key": key, "status": "ok", "title": "t", "detail": "",
                "facts": "{}", "since": moment, "last_seen": moment,
                "last_alert_at": None, "stale": False, "updated_at": moment}

    db = _DB(selfcheck=[_srow("alert:telegram"), _srow("db:reachable")],
             at={"ship:selfcheck_state": NOW - timedelta(days=1)},
             cursors={"ship:selfcheck_state": ""})

    result = run(shipper.ship_once(db, _cfg(), "k"))
    assert http.calls, f"nimic nu a plecat: {result.reason!r}"
    sent = json.loads(http.calls[0]["body"])
    assert sent["prune"] == {"selfcheck_state": ["alert:telegram", "db:reachable"]}, (
        f"lista de reconciliere nu a ajuns în lot: {sent.get('prune')!r}")


def test_no_prune_list_is_sent_for_streams_whose_source_never_deletes(http):
    """`audit_log` nu primește listă, deci receptorul nu poate șterge din el.

    O listă apărută aici din greșeală ar face ca fiecare intrare de audit absentă
    dintr-un lot să fie ștearsă de pe agregator — adică exact arhiva pe care
    sistemul o ține ca să nu poată fi ștearsă.
    """
    db = _DB(rows=[_row(7)], cursors={"ship:audit_log": 6})
    run(shipper.ship_once(db, _cfg(), "k"))
    sent = json.loads(http.calls[0]["body"])
    assert "prune" not in sent, f"listă trimisă pentru un flux append-only: {sent['prune']!r}"
