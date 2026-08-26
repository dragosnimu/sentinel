/**
 * Verificarea lanțului de hash-uri: ce e ruptură, ce e doar gol, ce nu se știe.
 *
 * ## Ce se strică pentru operator dacă modulul ăsta greșește
 *
 * În ambele direcții, și amândouă sunt scumpe:
 *
 *   * **gol raportat ca ruptură** — fiecare recuperare de restanță dă o alarmă
 *     falsă („cineva ți-a rescris jurnalul de audit"), iar după a treia oară
 *     operatorul oprește alarma. Atunci ruptura adevărată sosește într-un canal
 *     pe care nu se mai uită nimeni;
 *   * **ruptură raportată ca gol** — o rescriere reală de istorie trece tăcut,
 *     iar singura copie pe care root pe mașina monitorizată n-o poate atinge
 *     confirmă liniștit o istorie falsificată. Aia e chiar proprietatea pentru
 *     care există tot proiectul.
 *
 * A treia stare, la fel de importantă: **„n-am verificat niciodată" nu are voie
 * să arate ca „am verificat și e bine"**.
 *
 * ## CE AFIRMĂ DUBLUL, ȘI CE NU
 *
 * Nu există MariaDB aici. `FakeChainDb` **citește instrucțiunea** — clauza
 * `WHERE`, ordinea, limita — în loc să presupună ce a vrut apelantul, ca în
 * `tests/register.test.ts`. Fără asta, o interogare fără `instance_id = ?` ar
 * amesteca lanțurile a două instanțe și niciun test n-ar putea vedea.
 *
 * Ce NU se dovedește de aici, și trebuie verificat pe gazdă: că
 * `ON DUPLICATE KEY UPDATE` cu `COALESCE` scrie ce credem în
 * `audit_chain_state`, că `UTC_TIMESTAMP(6)` e acceptat, și că `LIMIT` pe o
 * arhivă mare are costul presupus.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { queryableDb } from "../lib/db";
import {
  GENESIS_HASH, chainReadable, positionIsKnowable, readState, recordVerdict,
  verifyAfterIngest,
  verifyIngestedWindow, verifyLinks, verifyStoredChain,
} from "../lib/chain";
import { streamFor } from "../lib/streams";
import type { Stream } from "../lib/streams";
import type { Link } from "../lib/chain";
import { applyUpsert } from "./sql-reading";
import type { Row } from "./sql-reading";
import type { Pool } from "../lib/db";

const A = "a1b2c3d4e5f60718";
const B = "b2c3d4e5f6071829";

/** Hash-uri de probă, scurte de citit și evident false. */
const h = (n: number) => String(n).padStart(64, "h");

/**
 * Verigi care continuă lanțul de după `lastId`, cu un gol de numerotare înaintea
 * lor — cazul obișnuit al unui lot nou.
 */
function linkedAfter(lastId: number, n: number): Link[] {
  const links: Link[] = [];
  let prev = h(lastId);
  for (let i = 0; i < n; i++) {
    const id = lastId + 1 + i;
    links.push({ sourceId: id, prevHash: prev, entryHash: h(id) });
    prev = h(id);
  }
  return links;
}

/**
 * Un lanț de `n` verigi începând de la `from`, legate corect.
 *
 * `id`-urile nu sunt neapărat consecutive: `audit_log.id` e o secvență Postgres,
 * iar o tranzacție anulată consumă un număr fără să lase un rând. Lanțul se
 * leagă prin hash, nu prin numerotare — vezi testul despre goluri.
 */
function chain(from: number, n: number, step = 1): Link[] {
  const links: Link[] = [];
  for (let i = 0; i < n; i++) {
    const id = from + i * step;
    links.push({
      sourceId: id,
      prevHash: i === 0 ? GENESIS_HASH : h(from + (i - 1) * step),
      entryHash: h(id),
    });
  }
  return links;
}

// ---------------------------------------------------------------------------
// Dublul
// ---------------------------------------------------------------------------
class FakeChainDb implements Pool {
  readonly entries = new Map<string, Link[]>();
  /** Tabela pentru care e semănat depozitul de verigi. */
  chainedTable = "audit_entries";
  readonly cursors = new Map<string, number | null>();
  readonly state = new Map<string, Row>();
  readonly asked: string[] = [];
  /** Prima interogare care începe cu prefixul ăsta aruncă. */
  failOn?: string;

  async end(): Promise<void> { /* nimic */ }

  /** Dublul ăsta nu trece prin `getPool`, deci nimeni nu-i cheamă cârligul.
   *  E aici fiindcă `Pool` îl cere — vezi `lib/db.ts`. */
  on(): unknown { return this; }

  async query(sql: string, params: unknown[] = []): Promise<[unknown, unknown]> {
    this.asked.push(sql);
    if (this.failOn && sql.startsWith(this.failOn)) {
      throw new Error("Connection lost: The server closed the connection");
    }

    if (sql.startsWith("SELECT last_source_id FROM sync_cursors")) {
      assert.ok(sql.includes("WHERE instance_id = ? AND stream = ?"), sql);
      const key = `${String(params[0])}|${String(params[1])}`;
      if (!this.cursors.has(key)) return [[], []];
      const value = this.cursors.get(key);
      // Rândul POATE exista cu coloana NULL — altă stare decât rândul lipsă, și
      // singura în care `Number(...)` ar produce un zero care pare o citire.
      // Șir, ca `bigNumberStrings`.
      return [[{ last_source_id: value === null ? null : String(value) }], []];
    }

    const links = /^SELECT source_id, prev_hash, entry_hash FROM (\w+) /.exec(sql);
    if (links) {
      // Tabela se CITEȘTE din instrucțiune, și trebuie să fie a fluxului cu lanț.
      // Cu numele fixat în dublu, o interogare îndreptată spre altă tabelă ar fi
      // fost servită din același depozit — adică verigi citite de undeva și
      // filigran de altundeva, tocmai perechea greșită pe care garda o previne.
      assert.equal(links[1], this.chainedTable,
                   `verigi cerute din ${links[1]}, dar depozitul e al lui ${this.chainedTable}`);
      // Filtrul de instanță se CITEȘTE din instrucțiune: fără el, lanțurile a
      // două instanțe s-ar amesteca, iar un dublu care presupune filtrul n-ar
      // putea arăta niciodată asta.
      const filtered = sql.includes("WHERE instance_id = ?");
      const instance = filtered ? String(params[0]) : null;
      const stored = instance === null
        ? [...this.entries.values()].flat()
        : (this.entries.get(instance) ?? []);
      let rows = [...stored].sort((x, y) => x.sourceId - y.sourceId);

      const rest = filtered ? params.slice(1) : params;
      if (sql.includes("source_id > ?")) {
        rows = rows.filter((r) => r.sourceId > Number(rest[0]));
      } else if (sql.includes("source_id < ?")) {
        rows = rows.filter((r) => r.sourceId < Number(rest[0]));
      }
      // Ordinea se CITEȘTE din instrucțiune. Un dublu care sortează oricum ar
      // face un `ORDER BY` șters să treacă neobservat, iar parcurgerea lanțului
      // ar depinde de ordinea în care baza nimerește să întoarcă rândurile.
      if (sql.includes("ORDER BY source_id DESC")) rows = [...rows].reverse();
      else if (!sql.includes("ORDER BY source_id")) rows = this.insertionOrder(rows);

      const limit = /LIMIT (\d+)/.exec(sql);
      assert.ok(limit, `interogare fără LIMIT pe o arhivă: ${sql}`);
      rows = rows.slice(0, Number(limit[1]));

      return [rows.map((r) => ({
        source_id: String(r.sourceId),
        prev_hash: r.prevHash,
        entry_hash: r.entryHash,
      })), []];
    }

    if (sql.startsWith("SELECT status,") && sql.includes("FROM audit_chain_state")) {
      assert.ok(sql.includes("WHERE instance_id = ?"), sql);
      const row = this.state.get(String(params[0]));
      return [row ? [row] : [], []];
    }

    if (sql.startsWith("INSERT INTO audit_chain_state")) {
      // Coloanele, valorile ȘI clauza de actualizare se iau din INSTRUCȚIUNE —
      // vezi `tests/sql-reading.ts`. Sunt trei instrucțiuni diferite, alese după
      // autoritatea verdictului (`lib/chain.ts::recordVerdict`); un dublu care
      // ar aplica mereu aceleași câmpuri ar face tocmai distincția dintre ele —
      // cine are voie să scrie `status` — imposibil de probat.
      const id = String(params[0]);
      this.state.set(id, applyUpsert(sql, params, this.state.get(id)));
      return [{ affectedRows: this.state.has(id) ? 2 : 1 }, []];
    }

    if (sql.startsWith("SELECT instance_id FROM instances")) {
      return [[...this.entries.keys()].sort().map((id) => ({ instance_id: id })), []];
    }

    throw new Error(`FakeChainDb: interogare neprevăzută: ${sql}`);
  }

  /** Rândurile în ordinea în care au fost puse, nu în cea a numerelor. */
  private insertionOrder(rows: Link[]): Link[] {
    const stored = [...this.entries.values()].flat();
    return [...rows].sort((a, b) => stored.indexOf(a) - stored.indexOf(b));
  }

  give(instance: string, links: Link[], cursor?: number): void {
    this.entries.set(instance, links);
    this.cursors.set(`${instance}|audit_log`,
                     cursor ?? links[links.length - 1].sourceId);
  }
}





const dbOf = (server: FakeChainDb) => queryableDb(server);

// ---------------------------------------------------------------------------
// Regula, fără bază de date
// ---------------------------------------------------------------------------
test("un lanț legat e „ok”, și se spune până unde", () => {
  const verdict = verifyLinks(chain(100, 5), null, 104);
  assert.equal(verdict.status, "ok");
  assert.equal(verdict.checkedLinks, 4);
  assert.equal(verdict.verifiedThrough, 104);
  assert.equal(verdict.breakSourceId, null);
});

test("o RUPTURĂ sub filigran e raportată, cu rândul la care se rupe", () => {
  // Cineva a șters rândul 102 din arhivă. 103 arată spre el, iar 101 nu duce
  // acolo. Ambele sunt sub filigran, deci ce lipsește NU mai poate sosi.
  const links = chain(100, 5);
  const broken = links.filter((l) => l.sourceId !== 102);
  const verdict = verifyLinks(broken, null, 104);
  assert.equal(verdict.status, "broken");
  assert.equal(verdict.breakSourceId, 103);
  assert.match(String(verdict.detail), /NU mai poate sosi|nu mai e/);
});

test("un GOL peste filigran NU e o ruptură", () => {
  // Aceeași formă exact — o verigă lipsă —, dar rândurile sunt peste filigranul
  // confirmat, deci predecesorul poate fi încă pe drum. Dacă testul ăsta și cel
  // de dinainte n-ar da rezultate DIFERITE, mecanismul ar fi ori alarmă falsă la
  // fiecare restanță, ori tăcere pe o rescriere reală.
  const links = chain(100, 5);
  const withHole = links.filter((l) => l.sourceId !== 102);
  const verdict = verifyLinks(withHole, null, 101);
  assert.equal(verdict.status, "unknown");
  assert.equal(verdict.breakSourceId, null);
  assert.match(String(verdict.detail), /filigran/);
  // Și ce s-a putut verifica sub filigran rămâne verificat.
  assert.equal(verdict.verifiedThrough, 101);
});

test("golurile de NUMEROTARE nu contează: lanțul se leagă prin hash", () => {
  // O tranzacție anulată consumă un `id` din secvență fără să lase un rând, deci
  // `audit_log.id` POATE avea goluri. O verificare construită pe „id-urile
  // trebuie să fie consecutive" ar fi dat alarme false pe purtarea normală a
  // bazei.
  const verdict = verifyLinks(chain(100, 5, 7), null, 128);
  assert.equal(verdict.status, "ok");
  assert.equal(verdict.checkedLinks, 4);
});

test("primul rând cu `prev_hash` NULL nu e o ruptură, dar nici o dovadă", () => {
  // Capătul de jos al copiei: predecesorul poate fi sub pragul de backfill, deci
  // nu va ajunge NICIODATĂ. Nu e o ruptură. Nu e nici un început dovedit — de-aia
  // `verifiedThrough` începe de la a doua verigă.
  const links = chain(100, 3);
  links[0] = { ...links[0], prevHash: null };
  const verdict = verifyLinks(links, null, 102);
  assert.equal(verdict.status, "ok");
  assert.equal(verdict.firstSourceId, 100);
  assert.equal(verdict.firstPrevHash, null);
  assert.equal(verdict.checkedLinks, 2);
});

test("`prev_hash` NULL în MIJLOC, sub filigran, E o ruptură", () => {
  // Serverul scrie GENESIS_HASH la primul rând, niciodată NULL
  // (`sentinel/db/repo/audit.py`), deci un NULL după un rând existent înseamnă
  // că rândul a fost fabricat sau că lanțul a fost tăiat acolo.
  const links = chain(100, 4);
  links[2] = { ...links[2], prevHash: null };
  const verdict = verifyLinks(links, null, 103);
  assert.equal(verdict.status, "broken");
  assert.equal(verdict.breakSourceId, 102);
});

test("un capăt de jos cu GENESIS e un început DOVEDIT", () => {
  const verdict = verifyLinks(chain(1, 3), null, 3);
  assert.equal(verdict.status, "ok");
  assert.equal(verdict.firstPrevHash, GENESIS_HASH);
  assert.equal(verdict.verifiedThrough, 3);
});

test("capătul de jos FIXAT nu se mai poate muta: e o trunchiere", () => {
  // Fără fixare, ștergerea primelor rânduri ar arăta pentru totdeauna ca un prag
  // de backfill — ambele lasă un `prev_hash` care nu se poate verifica. Pragul se
  // așază o singură dată, înaintea primei runde; capătul care se MUTĂ e altceva.
  const links = chain(100, 3);
  const known = { firstSourceId: 90, firstPrevHash: h(89) };
  const verdict = verifyLinks(links, null, 102, known);
  assert.equal(verdict.status, "broken");
  assert.equal(verdict.breakSourceId, 100);
  assert.match(String(verdict.detail), /ȘTERSE|capătul de jos/);
});

// ---------------------------------------------------------------------------
// Peste ce e stocat
// ---------------------------------------------------------------------------
test("verificarea programată parcurge tot ce e stocat", async () => {
  const server = new FakeChainDb();
  server.give(A, chain(1, 2500));
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 2499);
  assert.equal(verdict.verifiedThrough, 2500);
  // Chiar a fost nevoie de mai multe pagini — altfel testul n-ar spune nimic
  // despre parcurgerea în pagini.
  const pages = server.asked.filter((s) => s.startsWith("SELECT source_id"));
  assert.ok(pages.length >= 3, `doar ${pages.length} pagini`);
});

test("lanțurile a două instanțe NU se amestecă", async () => {
  // `source_id` e unic doar în cadrul instanței (`migrations/0001_core.sql`),
  // deci două servere pornite în aceeași zi au aceleași numere. O interogare
  // fără `instance_id = ?` ar lipi lanțul lui B de al lui A și ar raporta o
  // ruptură pe două arhive perfect sănătoase — sau, mai rău, ar declara „ok" o
  // arhivă ruptă fiindcă verigile celeilalte instanțe umplu golul.
  const server = new FakeChainDb();
  server.give(A, chain(100, 4));
  // B are aceleași numere, alt lanț.
  const other = chain(100, 4).map((l) => ({
    sourceId: l.sourceId,
    prevHash: l.prevHash === null || l.prevHash === GENESIS_HASH
      ? l.prevHash : `b${l.prevHash.slice(1)}`,
    entryHash: `b${l.entryHash.slice(1)}`,
  }));
  server.give(B, other);

  assert.equal((await verifyStoredChain(dbOf(server), A)).status, "ok");
  assert.equal((await verifyStoredChain(dbOf(server), B)).status, "ok");

  // Și o ruptură la A nu se poate „repara" cu verigile lui B.
  server.give(A, chain(100, 4).filter((l) => l.sourceId !== 102));
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "broken");
  assert.equal(verdict.breakSourceId, 103);
});

test("lanțurile a două instanțe nu se amestecă NICI dincolo de o pagină", async () => {
  // Testul de mai sus are patru rânduri, deci se termină în prima pagină — iar
  // prima pagină folosește ALTĂ interogare (fără `source_id > ?`) decât restul.
  // Un filtru de instanță pierdut doar în interogarea de continuare ar fi trecut
  // neobservat, și s-ar fi văzut abia pe o arhivă reală, care are mai mult de o
  // pagină.
  const server = new FakeChainDb();
  server.give(A, chain(1, 1200));
  const other = chain(1, 1200).map((l) => ({
    sourceId: l.sourceId,
    prevHash: l.prevHash === null || l.prevHash === GENESIS_HASH
      ? l.prevHash : `b${l.prevHash.slice(1)}`,
    entryHash: `b${l.entryHash.slice(1)}`,
  }));
  server.give(B, other);

  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 1199);
  const pages = server.asked.filter((s) => s.includes("source_id > ?"));
  assert.ok(pages.length >= 1, "nu s-a cerut nicio pagină de continuare");
});

test("joncțiunea se caută în ACEEAȘI instanță, nu în oricare", async () => {
  // `verifyAfterIngest` cere predecesorul lotului printr-o interogare separată.
  // Fără filtrul de instanță, predecesorul lotului lui A ar putea fi un rând al
  // lui B — `source_id` e unic doar în cadrul instanței —, iar rezultatul ar fi
  // o ruptură raportată pe două arhive perfect sănătoase.
  const server = new FakeChainDb();
  const links = chain(100, 5);
  server.give(A, links, 104);
  // B se pune DUPĂ A și cu hash-uri diferite. Amândouă contează: cu aceleași
  // hash-uri, rândul lui B s-ar lega întâmplător de lanțul lui A și proba n-ar
  // arăta nimic; pus înaintea lui A, o căutare fără filtru ar nimeri tot rândul
  // lui A, iar proba ar trece verde peste exact greșeala pe care o caută.
  server.give(B, chain(100, 5).map((l) => ({
    sourceId: l.sourceId,
    prevHash: l.prevHash === null || l.prevHash === GENESIS_HASH
      ? l.prevHash : `b${l.prevHash.slice(1)}`,
    entryHash: `b${l.entryHash.slice(1)}`,
  })));

  const verdict = await verifyAfterIngest(dbOf(server), A, 102);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
});

test("parcurgerea nu depinde de ordinea în care baza întoarce rândurile", async () => {
  // Lanțul se citește în ordinea `source_id`, cerută explicit. Dacă `ORDER BY`
  // ar dispărea din interogare, verificarea ar compara verigi în ordinea în care
  // se nimeresc pe disc — uneori verde, uneori ruptură, pe aceleași date.
  const server = new FakeChainDb();
  const links = chain(100, 6);
  // Puse în hartă amestecat: dublul le întoarce în ordinea asta dacă
  // instrucțiunea nu cere alta.
  server.give(A, [links[3], links[0], links[5], links[1], links[4], links[2]], 105);
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 5);
});

test("fără filigran citibil, verdictul e „nu știu”, nu „ok”", async () => {
  // Fără el nu se poate deosebi un gol de o ruptură, iar „nu pot deosebi" nu e
  // „e în regulă".
  const server = new FakeChainDb();
  server.entries.set(A, chain(100, 3));
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "unknown");
  assert.match(String(verdict.detail), /filigran/);

  // Și cazul mai subtil: rândul de cursor EXISTĂ, dar coloana e NULL. Aici
  // `Number(null)` ar da 0 — un filigran care pare citit și spune „nimic nu e
  // confirmat", adică transformă orice gol în ruptură.
  const nullCursor = new FakeChainDb();
  nullCursor.entries.set(A, chain(100, 3));
  nullCursor.cursors.set(`${A}|audit_log`, null);
  const second = await verifyStoredChain(dbOf(nullCursor), A);
  assert.equal(second.status, "unknown", JSON.stringify(second));
  assert.match(String(second.detail), /filigran/);
});

test("îndreptată spre un flux MUTABIL, verificarea spune „nu știu”, nu „ruptură”", async () => {
  // Filigranul confirmat e `sync_cursors.last_source_id`, scris cu `GREATEST`:
  // maximul istoric al filigranelor primite. Pe un flux append-only maximul CHIAR
  // e poziția. Pe unul mutabil nu — filigranul e maximul DIN LOT, iar loturile
  // succesive pot scădea (măsurat: 12 după 900).
  //
  // Ce s-ar întâmpla fără garda asta: verigile de sub un maxim istoric prea mare
  // ar fi citite ca „au fost confirmate și au dispărut", adică `broken` pe un
  // lanț perfect sănătos — cea mai scumpă formă de minciună de aici, fiindcă
  // exact asta e alarma pentru care există tot mecanismul.
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));

  const asAppendOnly = await verifyStoredChain(dbOf(server), A);
  assert.equal(asAppendOnly.status, "ok", JSON.stringify(asAppendOnly));

  const mutable = { ...streamFor("audit_log")!, cursor: "mutable" as const };
  const verdict = await verifyStoredChain(dbOf(server), A, undefined, mutable);
  assert.equal(verdict.status, "unknown", JSON.stringify(verdict));
  assert.match(String(verdict.detail), /filigran/);

  // Cazul „flux necunoscut" NU se poate cere prin parametru: un `undefined` dat
  // explicit alege valoarea IMPLICITĂ a parametrului, adică tocmai fluxul real.
  // (Măsurat aici: prima formă a testului trecea prin default și primea `ok`.)
  // El se probează pe regula însăși, în testul de mai jos.
});

test("verificarea citește filigranul FLUXULUI dat, nu pe al lui `audit_log`", async () => {
  // Gaura pe care o închide, măsurată: paza cerea doar `cursor === "append-only"`,
  // iar interogarea folosea numele fixat al modulului. Deci un AL DOILEA flux cu
  // lanț — prevăzut în `lib/streams.ts` pentru dovezile din E4 — ar fi trecut de
  // pază și ar fi primit filigranul lui `audit_log`.
  //
  // Ce se strică atunci: dacă `audit_log` e mai avansat, verigile fluxului nou
  // aflate încă în zbor cad SUB filigranul citit, iar „lipsesc verigi sub
  // filigranul confirmat" înseamnă `broken`. Adică alarmă de falsificare pe un
  // lanț perfect sănătos — exact eșecul pentru care există toată proiectarea.
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));            // cursor și verigi pentru `audit_log`

  const other: Stream = {
    ...streamFor("audit_log")!, name: "alt_flux_cu_lanț", table: "audit_entries",
  };

  // 1. Fluxul nou n-are încă niciun cursor. Răspunsul corect e „nu pot ști", NU
  //    filigranul altcuiva.
  const borrowed = await verifyStoredChain(dbOf(server), A, undefined, other);
  assert.equal(borrowed.status, "unknown", JSON.stringify(borrowed));

  // 2. Iar când fluxul nou ÎȘI are cursorul, e citit al lui și verificarea merge.
  //    Asta deosebește reparația aleasă de cealaltă: cu numele cerut în pază, un
  //    al doilea flux cu lanț n-ar putea fi verificat NICIODATĂ.
  server.cursors.set(`${A}|alt_flux_cu_lanț`, 102);
  const own = await verifyStoredChain(dbOf(server), A, undefined, other);
  assert.equal(own.status, "ok", JSON.stringify(own));
  assert.equal(own.verifiedThrough, 102);

  // 3. Și VERIGILE se citesc din tabela fluxului dat, nu dintr-una fixată.
  //    Jumătatea asta e aceeași greșeală ca filigranul: dacă numai una dintre
  //    cele două urmează parametrul, perechea rămâne greșită — verigi de la unul,
  //    filigran de la celălalt. Numele tabelei e ipotetic (E4 n-a fost scris);
  //    dublul cere doar ca interogarea să numească tabela fluxului.
  const elsewhere = new FakeChainDb();
  elsewhere.chainedTable = "evidence_entries";
  elsewhere.give(A, chain(100, 3));
  elsewhere.cursors.set(`${A}|dovezi`, 102);
  const other_table: Stream = {
    ...streamFor("audit_log")!, name: "dovezi", table: "evidence_entries",
  };
  const verdict = await verifyStoredChain(dbOf(elsewhere), A, undefined, other_table);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
});

test("fereastra de după ingestie citește tot din tabela FLUXULUI dat", async () => {
  // A doua intrare are aceeași pereche de întrebări — care filigran, care verigi
  // — și aceeași capcană. Măsurat: fixată numai în `verifyStoredChain`, tabela
  // rămânea nepinuită aici, iar mutația trecea neobservată.
  const elsewhere = new FakeChainDb();
  elsewhere.chainedTable = "evidence_entries";
  elsewhere.give(A, chain(100, 3));
  elsewhere.cursors.set(`${A}|dovezi`, 102);
  const stream: Stream = {
    ...streamFor("audit_log")!, name: "dovezi", table: "evidence_entries",
  };

  const verdict = await verifyIngestedWindow(dbOf(elsewhere), A, 101, undefined, stream);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
});

test("un flux FĂRĂ lanț nu se verifică deloc", async () => {
  // `chained` și `append-only` sunt condiții diferite: a doua spune că filigranul
  // e o poziție, prima că există `prev_hash`/`entry_hash` de citit. Un flux
  // append-only fără lanț ar trece de prima și ar cere coloane care nu există în
  // tabela lui — o eroare SQL în loc de un verdict.
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));
  const plain: Stream = { ...streamFor("audit_log")!, chained: false };
  const verdict = await verifyStoredChain(dbOf(server), A, undefined, plain);
  assert.equal(verdict.status, "unknown", JSON.stringify(verdict));
});

test("regula „pot ști o poziție?” se declanșează singură, pe fiecare formă", () => {
  // Regula, probată fără bază de date, ca declanșarea ei să nu depindă de restul
  // conductei — la fel ca `assertRegistrable` din `tests/ingest.test.ts`.
  const audit = streamFor("audit_log")!;
  assert.equal(positionIsKnowable(audit), true, "fluxul append-only a fost refuzat");
  assert.equal(positionIsKnowable({ ...audit, cursor: "mutable" }), false,
               "un flux mutabil a primit o poziție confirmată");
  assert.equal(positionIsKnowable(undefined), false,
               "un flux necunoscut a primit o poziție confirmată");

  // Și contractul funcției EXPORTATE de deasupra ei. Azi `chained + mutable` e
  // imposibil prin construcție (`tests/ingest.test.ts` îl interzice la
  // declarare), deci mutația care scoate `positionIsKnowable` din `chainReadable`
  // rămâne verde — apărarea e dublă. Aserțiunea nu repară nimic: spune ce
  // promite funcția pentru un `Stream` OARECARE, fiindcă asta primește.
  assert.equal(chainReadable(audit), true, "fluxul cu lanț a fost refuzat");
  assert.equal(chainReadable({ ...audit, cursor: "mutable" }), false,
               "un flux mutabil cu lanț ar fi verificat pe un maxim istoric");
  assert.equal(chainReadable({ ...audit, chained: false }), false,
               "un flux fără lanț ar fi verificat");
  assert.equal(chainReadable(undefined), false);
});

test("o instanță fără niciun rând e „nu știu”, nu „ok”", async () => {
  const server = new FakeChainDb();
  server.cursors.set(`${A}|audit_log`, 0);
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "unknown");
});

// ---------------------------------------------------------------------------
// Joncțiunea dintre două loturi
// ---------------------------------------------------------------------------
test("o ruptură EXACT la joncțiunea a două loturi e prinsă", async () => {
  // Locul în care ar tăia cineva: o verificare care se uită doar în interiorul
  // lotului găsește un lot perfect legat și nu vede nimic.
  const server = new FakeChainDb();
  // Lotul 1: 100–102. Lotul 2: 200–202, cu un `prev_hash` care NU duce la 102.
  const first = chain(100, 3);
  const second = chain(200, 3);
  server.give(A, [...first, ...second], 202);

  const verdict = await verifyAfterIngest(dbOf(server), A, 200);
  assert.equal(verdict.status, "broken", JSON.stringify(verdict));
  assert.equal(verdict.breakSourceId, 200);

  // Iar dacă al doilea lot se leagă corect, aceeași verificare spune „ok".
  const linked = chain(200, 3);
  linked[0] = { ...linked[0], prevHash: h(102) };
  const clean = new FakeChainDb();
  clean.give(A, [...first, ...linked], 202);
  assert.equal((await verifyAfterIngest(dbOf(clean), A, 200)).status, "ok");
});

test("primul lot al unei instanțe nu raportează ruptură la joncțiune", async () => {
  // Nu există lot anterior. Predecesorul primului rând e sub pragul de backfill
  // și nu va veni niciodată.
  const server = new FakeChainDb();
  const links = chain(5000, 3);
  links[0] = { ...links[0], prevHash: h(4999) };
  server.give(A, links, 5002);
  const verdict = await verifyAfterIngest(dbOf(server), A, 5000);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.firstSourceId, 5000);
});

// ---------------------------------------------------------------------------
// Consemnarea
// ---------------------------------------------------------------------------
test("un SINGUR rând, cu un predecesor necunoscut, nu dovedește nimic", async () => {
  // Zero legături comparate și niciun capăt dovedit. `ok` aici ar fi o bifă
  // verde care nu s-a uitat la nimic — iar bifa aia ar sta în `audit_chain_state`
  // exact ca una câștigată, pe o instanță despre care nu se știe nimic.
  const server = new FakeChainDb();
  const only = chain(5000, 1);
  only[0] = { ...only[0], prevHash: h(4999) };
  server.give(A, only, 5000);

  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "unknown", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 0);
  assert.equal(verdict.verifiedThrough, null);

  // Iar dacă rândul e chiar începutul lanțului serverului, atunci DA: capătul e
  // dovedit, și cele două cazuri trebuie să se deosebească.
  const genesis = new FakeChainDb();
  genesis.give(A, chain(1, 1), 1);
  const proven = await verifyStoredChain(dbOf(genesis), A);
  assert.equal(proven.status, "ok", JSON.stringify(proven));
  assert.equal(proven.verifiedThrough, 1);
});

test("o ruptură într-o pagină care NU e ultima oprește parcurgerea acolo", async () => {
  // Cu peste o pagină de rânduri, o ruptură devreme trebuie să oprească
  // verdictul. Dacă parcurgerea ar continua, verdictul ultimei pagini — care se
  // leagă perfect — ar acoperi ruptura, iar arhiva ruptă ar ieși `ok`.
  const server = new FakeChainDb();
  server.give(A, chain(1, 1500).filter((l) => l.sourceId !== 400));
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "broken", JSON.stringify(verdict));
  assert.equal(verdict.breakSourceId, 401);
});

test("continuarea pe pagini nu depinde nici ea de ordinea rândurilor", async () => {
  // Testul de mai sus despre ordine se termină în prima pagină, care folosește
  // ALTĂ interogare. Un `ORDER BY` pierdut doar în interogarea de continuare s-ar
  // fi văzut abia pe o arhivă reală.
  const server = new FakeChainDb();
  const links = chain(1, 1500);
  const shuffled = [...links];
  for (let i = shuffled.length - 1; i > 0; i--) {
    // Amestec determinist: aceleași date la fiecare rulare, altă ordine decât a
    // numerelor.
    const j = (i * 7919) % (i + 1);
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  server.give(A, shuffled, 1500);
  const verdict = await verifyStoredChain(dbOf(server), A);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 1499);
});

test("verificarea de la ingestie pornește de la predecesorul IMEDIAT", async () => {
  // Joncțiunea e „locul în care ar tăia cineva", iar predecesorul imediat e
  // singurul rând cu care se compară primul rând al lotului. O căutare care
  // întoarce alt rând de dedesubt (cel mai vechi, sau unul la întâmplare fiindcă
  // nu s-a cerut nicio ordine) ar compara altceva decât joncțiunea — uneori
  // corect din întâmplare, iar asta e mai rău decât greșit mereu.
  //
  // Ce se observă: câte legături a comparat. De la predecesorul imediat sunt
  // exact cele trei ale lotului; de la capătul de jos ar fi toate.
  const server = new FakeChainDb();
  server.give(A, chain(100, 10), 109);
  const verdict = await verifyAfterIngest(dbOf(server), A, 107);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));
  assert.equal(verdict.checkedLinks, 3,
               "fereastra n-a pornit de la predecesorul imediat");
  assert.equal(verdict.fromLowEnd, false);
});

// ---------------------------------------------------------------------------
// Cine are dreptul să scrie `status`
// ---------------------------------------------------------------------------
test("o ruptură consemnată NU e ștearsă de lotul următor", async () => {
  // Defectul care a picat runda: `verifyAfterIngest` pornește deasupra rupturii,
  // n-are cum s-o vadă, iese `ok` — și scria necondiționat. Loturile sosesc la
  // `ship.interval_s` (implicit 60 s), deci o ruptură reală rămânea consemnată
  // cel mult un minut, apoi arhiva ruptă arăta `ok`.
  //
  // Regula: `status` e o propoziție despre TOT lanțul. O fereastră care n-a
  // citit nimic sub ruptură nu are autoritatea s-o contrazică.
  const server = new FakeChainDb();
  server.give(A, chain(1, 8).filter((l) => l.sourceId !== 3), 8);

  const full = await verifyStoredChain(dbOf(server), A);
  await recordVerdict(dbOf(server), A, full, "scheduled");
  assert.equal(server.state.get(A)?.status, "broken");
  assert.equal(Number(server.state.get(A)?.break_source_id), 4);

  // Sosește un lot NOU, deasupra rupturii.
  server.give(A, [...chain(1, 8).filter((l) => l.sourceId !== 3), ...linkedAfter(8, 3)], 11);
  const window = await verifyAfterIngest(dbOf(server), A, 9);
  assert.equal(window.status, "ok", "fereastra nouă chiar se leagă");
  assert.equal(window.fromLowEnd, false);

  const state = server.state.get(A);
  assert.equal(state?.status, "broken", "ruptura consemnată a fost ștearsă");
  assert.equal(Number(state?.break_source_id), 4, "pointerul rupturii s-a pierdut");
});

test("numai o trecere COMPLETĂ poate spune „ok”, iar `broken_at` rămâne", async () => {
  // Vindecarea există, dar are un singur drum: o parcurgere de la capătul de jos
  // care nu mai găsește ruptura. Ce nu se șterge niciodată e momentul primei
  // observații — „copia asta a fost văzută ruptă odată" e un fapt permanent
  // despre ea, iar o arhivă care a fost ruptă nu are voie să arate din nou nouă.
  const server = new FakeChainDb();
  server.give(A, chain(1, 8).filter((l) => l.sourceId !== 3), 8);
  await recordVerdict(dbOf(server), A, await verifyStoredChain(dbOf(server), A), "scheduled");
  const brokenAt = server.state.get(A)?.broken_at;
  assert.ok(brokenAt);

  // Rândul lipsă e refăcut dintr-o copie: acum lanțul se leagă.
  server.give(A, chain(1, 8), 8);
  const healed = await verifyStoredChain(dbOf(server), A);
  await recordVerdict(dbOf(server), A, healed, "scheduled");

  const state = server.state.get(A);
  assert.equal(state?.status, "ok");
  assert.equal(state?.break_source_id, null, "pointerul rupturii nu s-a curățat");
  assert.equal(state?.broken_at, brokenAt, "momentul primei rupturi a fost șters");
});

test("o trecere completă pe MAI MULTE pagini își păstrează autoritatea", async () => {
  // Autoritatea de a spune `ok` e a parcurgerii care a pornit de la capătul de
  // jos — și trebuie să supraviețuiască agregării dintre pagini. Dacă
  // `merge` ar lua `fromLowEnd` de la ULTIMA pagină, o trecere completă peste o
  // arhivă mai mare de o pagină și-ar pierde autoritatea pe drum: n-ar mai putea
  // scrie `ok`, deci o ruptură VINDECATĂ ar rămâne consemnată `broken` pentru
  // totdeauna — o alarmă care nu se poate opri, adică exact modul de eșec pe
  // care tot mecanismul îl evită.
  //
  // Și nu e un caz exotic: orice arhivă reală are peste o pagină, deci ăsta e
  // drumul normal.
  const server = new FakeChainDb();
  server.give(A, chain(1, 2500).filter((l) => l.sourceId !== 400), 2500);
  await recordVerdict(dbOf(server), A, await verifyStoredChain(dbOf(server), A), "scheduled");
  assert.equal(server.state.get(A)?.status, "broken", "prima trecere n-a văzut ruptura");

  // Rândul lipsă e refăcut dintr-o copie.
  server.give(A, chain(1, 2500), 2500);
  const healed = await verifyStoredChain(dbOf(server), A);
  assert.equal(healed.fromLowEnd, true,
               "parcurgerea a pornit de jos, dar verdictul nu mai spune asta");
  assert.equal(healed.checkedLinks, 2499);

  await recordVerdict(dbOf(server), A, healed, "scheduled");
  assert.equal(server.state.get(A)?.status, "ok",
               "o trecere completă n-a putut vindeca starea: autoritatea s-a " +
               "pierdut între pagini");
});

test("`verified_through` nu regresează, nici dintr-o fereastră", async () => {
  // Câmp de diagnostic, nu de decizie — dar „până unde am ajuns" citit mai mic
  // decât data trecută înseamnă ori că verificarea a luat-o înapoi, ori că
  // altcineva scrie peste ea. Niciuna nu e adevărată, deci nu are voie să apară.
  const server = new FakeChainDb();
  server.give(A, chain(1, 500), 500);
  await recordVerdict(dbOf(server), A, await verifyStoredChain(dbOf(server), A), "scheduled");
  assert.equal(Number(server.state.get(A)?.verified_through), 500);

  // O fereastră care a verificat mai puțin — un lot vechi reluat, de pildă. Nu
  // are autoritate pe `status` și nu are voie să tragă înapoi nici cifra asta.
  await recordVerdict(dbOf(server), A, {
    status: "ok", checkedLinks: 2, verifiedThrough: 42,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null,
    detail: null, fromLowEnd: false,
  }, "ingest");

  assert.equal(Number(server.state.get(A)?.verified_through), 500,
               "cifra „până unde am verificat” a mers înapoi");
  // Iar în sus se mișcă, altfel aserțiunea de mai sus ar fi trecut și peste un
  // câmp care nu se scrie deloc.
  await recordVerdict(dbOf(server), A, {
    status: "ok", checkedLinks: 2, verifiedThrough: 600,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null,
    detail: null, fromLowEnd: false,
  }, "ingest");
  assert.equal(Number(server.state.get(A)?.verified_through), 600);
});

test("istorie mai VECHE sosită nu e o trunchiere", async () => {
  // Capătul de jos care COBOARĂ înseamnă că au sosit rânduri de sub el — o cale
  // pe care serverul o recomandă singur: linia de WARNING din
  // `shipper.py::_cursor_of` îi spune operatorului să mărească
  // `ship.max_backfill_days` și să șteargă cursoarele `ship:*`. Raportată ca
  // ștergere, ar fi o alarmă falsă exact la procedura din mesajul de ajutor.
  const server = new FakeChainDb();
  server.give(A, chain(5, 4), 8);
  await recordVerdict(dbOf(server), A, await verifyStoredChain(dbOf(server), A), "scheduled");
  assert.equal(Number(server.state.get(A)?.first_source_id), 5);

  // Sosesc rândurile 2,3,4 — de SUB capăt.
  server.give(A, chain(2, 7), 8);
  const verdict = await verifyStoredChain(
    dbOf(server), A, await readState(dbOf(server), A) ?? undefined);
  assert.equal(verdict.status, "ok", JSON.stringify(verdict));

  await recordVerdict(dbOf(server), A, verdict, "scheduled");
  assert.equal(Number(server.state.get(A)?.first_source_id), 2,
               "capătul de jos nu a coborât odată cu istoria sosită");
});

test("același capăt de jos, alt `prev_hash`, e o rescriere", async () => {
  // A treia direcție: rândul e tot acolo, dar arată acum spre altceva în urmă.
  // Nu e o sosire de istorie mai veche, e o modificare.
  const links = chain(100, 3);
  const known = { firstSourceId: 100, firstPrevHash: h(99) };
  const verdict = verifyLinks(links, null, 102, known);
  assert.equal(verdict.status, "broken");
  assert.match(String(verdict.detail), /rescriere/);
});

test("„niciodată verificat” nu arată ca „verificat și e bine”", async () => {
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));

  // Înainte de orice rulare: NICIUN rând. Absența e starea, nu o valoare
  // implicită care seamănă cu „ok".
  assert.equal(await readState(dbOf(server), A), null);

  await verifyAfterIngest(dbOf(server), A, 100);
  const state = await readState(dbOf(server), A);
  assert.equal(state?.status, "ok");
  assert.equal(state?.verifiedThrough, 102);
  assert.equal(state?.lastRunAt !== null, true);
});

test("momentul rupturii e cel de la PRIMA observație", async () => {
  // O rulare ulterioară nu are voie să împingă momentul înainte: prima
  // observație e cea care spune ce interval trebuie cercetat. Cu ea rescrisă la
  // fiecare rulare de cron, „ruptă de ieri" ar deveni „ruptă acum un minut", iar
  // fereastra în care s-a întâmplat s-ar pierde.
  const server = new FakeChainDb();
  server.give(A, chain(100, 4).filter((l) => l.sourceId !== 102));

  await verifyAfterIngest(dbOf(server), A, 100);
  assert.ok(server.state.get(A)?.broken_at, "ruptura nu a fost consemnată cu un moment");

  // Momentul se pune pe o valoare distinctă înainte de a doua rulare: două
  // rulări una după alta produc același șir de timp la milisecundă, deci o
  // comparație „înainte/după" ar fi trecut și peste o rescriere.
  const seen = "2026-01-01 00:00:00.000000";
  server.state.set(A, { ...server.state.get(A)!, broken_at: seen });

  await verifyAfterIngest(dbOf(server), A, 100);
  assert.equal(server.state.get(A)?.broken_at, seen, "momentul a fost rescris");
  assert.equal(server.state.get(A)?.status, "broken");
  assert.equal(Number(server.state.get(A)?.break_source_id), 103);
});

test("capătul de jos NU se pierde la o verificare care începe din mijloc", async () => {
  // Verificarea de la ingestie pornește de la joncțiunea lotului, deci nu vede
  // capătul de jos și nu are ce raporta despre el. Fără `COALESCE`, ar scrie
  // NULL peste ce fixase prima verificare — iar de atunci o trunchiere de la
  // început n-ar mai avea cu ce fi comparată.
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));
  await verifyAfterIngest(dbOf(server), A, 100);
  assert.equal(Number(server.state.get(A)?.first_source_id), 100);
  const pinned = server.state.get(A)?.first_prev_hash;

  // Al doilea lot: 103–105, verificat de la joncțiune.
  const more = chain(100, 6);
  server.give(A, more, 105);
  await verifyAfterIngest(dbOf(server), A, 103);

  assert.equal(Number(server.state.get(A)?.first_source_id), 100,
               "capătul de jos a fost șters de o verificare care nu-l vedea");
  assert.equal(server.state.get(A)?.first_prev_hash, pinned);
});

test("capătul de jos se fixează o dată și se compară de atunci", async () => {
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));
  await verifyAfterIngest(dbOf(server), A, 100);
  assert.equal(Number(server.state.get(A)?.first_source_id), 100);

  // Cineva șterge primele două rânduri. Fără capătul fixat, ce rămâne arată ca
  // o instanță care tocmai a început să expedieze.
  server.give(A, chain(100, 3).filter((l) => l.sourceId === 102), 102);
  const verdict = await verifyAfterIngest(dbOf(server), A, 102);
  assert.equal(verdict.status, "broken");
  assert.match(String(verdict.detail), /capătul de jos/);
  // Iar capătul consemnat rămâne cel vechi: e dovada a ce era.
  assert.equal(Number(server.state.get(A)?.first_source_id), 100);
});

test("o bază care nu răspunde dă „nu știu”, nu „ok”", async () => {
  const server = new FakeChainDb();
  server.give(A, chain(100, 3));
  server.failOn = "SELECT source_id, prev_hash, entry_hash";
  await assert.rejects(verifyStoredChain(dbOf(server), A));

  // Iar un rând care nu se poate citi ca verigă nu se sare — sărit, lanțul ar
  // părea legat peste el.
  const broken = new FakeChainDb();
  broken.entries.set(A, chain(100, 3));
  broken.cursors.set(`${A}|audit_log`, 102);
  const rows = broken.entries.get(A)!;
  rows[1] = { ...rows[1], entryHash: undefined as unknown as string };
  const verdict = await verifyStoredChain(dbOf(broken), A);
  assert.equal(verdict.status, "unknown");
  assert.match(String(verdict.detail), /verigă/);
});
