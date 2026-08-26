/**
 * Schela testelor de ingestie.
 *
 * ## CE AFIRMĂ DUBLUL DE MAI JOS, ȘI CE NU POATE AFIRMA — de citit înainte
 *
 * Pe mașina pe care s-au scris testele nu există MariaDB, iar găzduirea nu are
 * conexiune la distanță configurată. Deci se folosește aceeași abordare ca în
 * `tests/migrate.test.ts` și `tests/db.test.ts`: un dublu care **răspunde** la
 * interogări și **ține minte** ce a primit. Diferența față de dublul de acolo e
 * că ăsta ține și un pic de STARE — trei tabele, ca hărți —, fiindcă
 * proprietatea de probat e idempotența, iar idempotența nu se poate afirma
 * despre un dublu fără memorie.
 *
 * Dublul **nu modelează MariaDB** și nu se pretinde echivalent cu ea. Ce
 * imită, exact:
 *
 *   * `INSERT IGNORE` = primul scris câștigă, restul se sar în tăcere;
 *   * `UNIQUE (instance_id, source_id)` = cheia hărții;
 *   * `COUNT(*) … WHERE instance_id = ? AND source_id IN (…)` = câte chei sunt
 *     acolo. **Filtrul de instanță se citește din instrucțiune, nu se
 *     presupune**: o versiune anterioară a dublului filtra pe `params[0]`
 *     indiferent ce scria în clauză, deci un `countSql` fără
 *     `WHERE instance_id = ?` — adică numărând rândurile ALTEI instanțe cu
 *     aceleași `source_id` — nu putea fi observat de nicio probă. Aia e singura
 *     dovadă de efect din tot sistemul;
 *   * `ON DUPLICATE KEY UPDATE` pe `sync_cursors`, cu `GREATEST` **doar dacă
 *     instrucțiunea îl conține**. Fără citirea asta, o scriere care mută
 *     cursorul înapoi arăta identic cu una monotonă;
 *   * `BIGINT` întors ca ȘIR, fiindcă driverul chiar face asta
 *     (`bigNumberStrings` în `lib/db.ts`), iar codul nu are voie să se bazeze pe
 *     tip;
 *   * valorile BINARE se compară pe OCTEȚI (`cell` din `tests/sql-reading.ts`),
 *     nu prin `String(...)`. `actor_attrs.value_hash` e `BINARY(32)` și e
 *     MEMBRU al cheii unice, iar decodarea UTF-8 a unor octeți oarecare poate
 *     face doi digești distincți să arate la fel — adică ar declara idempotență
 *     exact acolo unde MariaDB ar vedea două rânduri.
 *
 * Ce se dovedește cu el e purtarea CODULUI NOSTRU: că nu ecouă un filigran
 * nedovedit, că un lot reluat nu schimbă nimic, că un flux necunoscut nu produce
 * un 200. Toate sunt decizii scrise în `lib/ingest.ts` și în rută.
 *
 * Ce NU se dovedește, și trebuie verificat pe gazdă:
 *
 *   * că `INSERT IGNORE` chiar sare peste un duplicat în loc să declanșeze
 *     triggerul de append-only (motivul pentru care nu e `ON DUPLICATE KEY
 *     UPDATE` — vezi `migrations/0001_core.sql`);
 *   * că `UTC_TIMESTAMP(6)` și `GREATEST(COALESCE(...))` sunt acceptate acolo.
 *     Ce se poate verifica de aici e doar că instrucțiunea TRIMISĂ le conține —
 *     `UTC_TIMESTAMP(6)` față de `CURRENT_TIMESTAMP(6)` e diferența dintre UTC
 *     și fusul sesiunii, iar un dublu n-are fus. Vezi testul care se uită la
 *     `asked`, și nota din `tests/migrate.test.ts` despre aserțiuni pe
 *     interogarea trimisă;
 *   * că un `DATETIME(6)` primit ca șir e stocat neatins;
 *   * că un `params` care nu e JSON valid chiar cade pe `CHECK (json_valid(...))`;
 *   * că `INSERT IGNORE` TRUNCHIAZĂ un șir prea lung în loc să sară rândul —
 *     premisa pentru care `lib/streams.ts` poartă marginile coloanelor;
 *   * că `BINARY(32)` chiar stochează cei 32 de octeți neatinși, și că un
 *     parametru mai scurt sau mai lung ar fi completat sau tăiat în loc să fie
 *     refuzat — premisa pentru care `prepareRows` verifică lățimea digestului
 *     ÎNAINTE de bază. Dublul ține octeții exact cum îi primește, deci nu poate
 *     arăta nici potrivirea, nici tăierea.
 *
 * Dublul se pune ÎN LOCUL DRIVERULUI, nu al stratului nostru: `getPool` îl
 * primește ca fabrică, deci cererea trece prin `queryableDb` și prin toată ruta,
 * cod real. Un dublu pus mai sus (peste `lib/ingest.ts`) ar fi confirmat că am
 * apelat propria noastră imitație.
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import zlib from "node:zlib";

import { SecretBox } from "../lib/crypto";
import { closePool, getPool } from "../lib/db";
import { SHIP_SECRET_FIELD } from "../lib/ship-keys";
import { streamFor } from "../lib/streams";
import {
  applyUpsert, cell, evaluate, readDelete, readMultiRowInsert, tableColumns,
  uniqueKeyColumns,
} from "./sql-reading";
import { discover } from "../lib/migrate";
import type { Row } from "./sql-reading";
import type { Pool, PooledConnection } from "../lib/db";

/** Secretul principal de test: 64 de caractere, evident false. */
export const MASTER = "0".repeat(32) + "abcdefabcdefabcdefabcdefabcdef12";

/** Identitatea de test. Nu seamănă cu niciuna reală și nu e citită de nicăieri. */
export const INSTANCE = "a1b2c3d4e5f60718";

/** Cheia de expediere a instanței de test. */
export const SHIP_KEY = "cheie-de-expediere-test";

/**
 * Ce cere `readDbConfig`. Valorile nu ajung nicăieri: pool-ul e înlocuit, deci
 * nimic nu se conectează. Sunt totuși obligatorii, fiindcă `getPool` citește
 * configurația ÎNAINTE de a chema fabrica.
 */
const DB_ENV = {
  AGGREGATOR_DB_USER: "u",
  AGGREGATOR_DB_PASSWORD: "p",
  AGGREGATOR_DB_NAME: "d",
};

export function setEnv(vars: Record<string, string | undefined>): void {
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

/** Mediul de bază: secretul principal, atât. */
export function baseEnv(): void {
  setEnv({ SENTINEL_AGGREGATOR_SECRET: MASTER });
}

export function sealedShipKey(
  secret: string = SHIP_KEY, instanceId: string = INSTANCE, master: string = MASTER,
): string {
  return new SecretBox(master).seal(secret, { owner: instanceId, field: SHIP_SECRET_FIELD });
}

export type InstanceRow = {
  instance_id: string;
  enabled: number;
  ship_secret_enc: string | null;
};

export type FakeOptions = {
  /** Rândurile din `instances`. Implicit: instanța de test, activă, cu cheie. */
  instances?: InstanceRow[];
  /**
   * `source_id`-uri pe care `INSERT` le înghite în TĂCERE.
   *
   * Ăsta e chiar comportamentul lui `INSERT IGNORE` pe o eroare care nu e o
   * cheie duplicată — un CHECK picat, o coloană prea scurtă. Serverul nu
   * aruncă, rândul nu e acolo, iar singurul mod de a afla e să numeri.
   */
  swallow?: Set<number>;
  /**
   * `INSERT` înghite în tăcere rândurile pentru care predicatul e adevărat.
   *
   * `swallow` de mai sus alege după `source_id`, deci nu poate pierde UN rând
   * dintr-un flux cu cheie compusă, unde mai multe rânduri au același
   * `source_id`. Iar exact ăla e cazul în care o numărătoare scrisă pe
   * `source_id` minte: rândul lipsă are un frate prezent cu același `source_id`.
   */
  swallowWhere?: (row: Row) => boolean;
  /** `COUNT(*)` nu întoarce niciun rând: „nu știu", nu „zero". */
  blindCount?: boolean;
  /**
   * `COUNT(*)` întoarce o valoare care nu e număr.
   *
   * Se întâmplă: o coloană citită din alt rând, un driver care întoarce
   * `Buffer`, o interogare care a selectat altceva decât credea apelantul. Nu se
   * poate produce numărând, deci trebuie să poată fi cerut.
   */
  countValue?: unknown;
  /** Cursorul nu se mișcă, oricât i s-ar cere. */
  frozenCursor?: boolean;
  /**
   * Rândul de cursor EXISTĂ, dar `last_source_id` nu e un număr.
   *
   * Nu se poate produce mutând cursorul, deci trebuie să poată fi cerut — la
   * fel ca `countValue`. `null` de aici e cazul care contează: `Number(null)`
   * e 0, adică „cursorul e la început", care e o afirmație, nu o citire.
   */
  cursorValue?: unknown;
  /**
   * ORICE interogare care începe cu prefixul ăsta aruncă, nu doar prima.
   *
   * Scris aici fiindcă e o capcană măsurată: un lot împărțit în bucăți trimite
   * mai multe instrucțiuni cu același prefix, iar cine vrea să pice DOAR a doua
   * bucată n-o poate face de aici — i-ar trebui un predicat, ca la
   * `swallowWhere`. Niciun test nu se sprijină azi pe „prima".
   */
  failOn?: string;
  /**
   * Curățarea sub-rândurilor nu face NIMIC, și nu se plânge.
   *
   * Nu se poate produce trimițând date: e forma pe care o ia un `DELETE` scos
   * din cod, un predicat care nu potrivește nimic, sau o versiune care ar
   * face upsert pe copii în loc să înlocuiască mulțimea. Toate arată identic —
   * mulțimile se CONTOPESC, tăcut.
   */
  skipDelete?: boolean;
};

type CursorRow = {
  /** Filigranul stocat. Numar pentru fluxurile cu `source_id`, SIR pentru
   *  cele cu cheie text — coloana difera, iar dublul o alege din
   *  instructiune, nu din tipul valorii. */
  last_source_id: number | string;
  rows_ingested: number;
  last_batch_seq: number;
};

/**
 * Cheile unice ale tabelelor, citite din migrațiile LIVRATE.
 *
 * Dublul ține rândurile pe cheia din SCHEMĂ, nu pe cea pe care o declară fluxul.
 * Diferența e tot ce contează: dacă cele două nu sunt de acord, un flux cu
 * identitate greșită scrie peste rânduri distincte (sau nu-și găsește propriile
 * rânduri) chiar aici, în suită, în loc să facă asta pe gazdă. Acordul e cerut
 * separat de `tests/schema.test.ts`; dublul îl PROBEAZĂ, nu îl presupune.
 */
const UNIQUE_KEYS = new Map<string, string[]>(
  discover().flatMap((migration) => migration.statements.flatMap((stmt) => {
    const found = /^CREATE TABLE (\w+)/.exec(stmt.sql);
    return found ? [[found[1], uniqueKeyColumns(stmt.sql)] as [string, string[]]] : [];
  })));

/**
 * Coloanele fiecărei tabele, tot din migrațiile LIVRATE.
 *
 * Dublul refuză un `INSERT` care numește o coloană pe care tabela nu o are. E
 * garda care lipsea la #62: `writeSql` emitea `received_at` și `batch_seq`
 * necondiționat, iar cele patru tabele de legătură din `0003_entities.sql` nu le
 * au. Pe MariaDB aia e `Unknown column 'received_at' in 'field list'` la primul
 * lot; aici, până acum, era tăcere — dublul lega parametrii după text și nu se
 * întreba niciodată dacă tabela chiar are coloanele alea.
 */
const TABLE_COLUMNS = (() => {
  const out = new Map<string, string[]>();
  for (const migration of discover()) {
    for (const stmt of migration.statements) {
      const created = /^CREATE TABLE (\w+)/.exec(stmt.sql);
      if (created) {
        out.set(created[1], tableColumns(stmt.sql));
        continue;
      }
      // `ALTER TABLE … ADD COLUMN` e a doua cale prin care o tabelă capătă o
      // coloană, și e folosită: `updated_at` și `auto_action` din
      // `incident_entries` vin din `0006`/`0007`. Citit doar din `CREATE TABLE`,
      // dublul ar fi refuzat instrucțiuni PERFECT valide — o gardă care se
      // înșală în direcția „sigură" tot se înșală.
      const added = /^ALTER TABLE (\w+) ADD COLUMN (\w+)\b/.exec(stmt.sql);
      if (added) out.set(added[1], [...(out.get(added[1]) ?? []), added[2]]);
    }
  }
  return out;
})();

/**
 * Cheia sub care stă un rând în depozit: valorile cheii unice, în ordinea din
 * schemă. Pentru `audit_entries` iese „instanță|source_id", exact forma de
 * dinainte, deci probele care se uită direct în depozit rămân valabile.
 */
function identityKey(table: string, row: Row): string {
  const columns = UNIQUE_KEYS.get(table);
  assert.ok(columns && columns.length,
            `dublul nu știe cheia unică a tabelei ${table}: nu e în nicio migrație livrată`);
  return (columns as string[]).map((column) => cell(row[column])).join("|");
}

/** Coloanele după care numără un `COUNT`, citite din predicatul lui. */
function countedColumns(sql: string): string[] {
  const tuple = /AND \(([\w, ]+)\) IN \(/.exec(sql);
  if (tuple) return tuple[1].split(",").map((c) => c.trim());
  const single = /AND (\w+) IN \(/.exec(sql);
  assert.ok(single, `nu pot citi coloanele după care numără: ${sql}`);
  return [(single as RegExpExecArray)[1]];
}

export class FakeServer implements Pool {
  /**
   * Depozitul, pe tabelă: „tabelă" → („instanță|source_id" → rând).
   *
   * Rândurile se țin ca OBIECTE cu numele coloanelor, nu ca tupluri de
   * parametri: numele vin din instrucțiune, deci o coloană mutată se vede, iar
   * un test care se uită la ce s-a scris nu numără poziții.
   */
  readonly tables = new Map<string, Map<string, Row>>();
  /** Scurtătură pentru `audit_entries`, tabela cu care lucrează majoritatea probelor. */
  get audit(): Map<string, Row> { return this.tableRows("audit_entries"); }
  /** Cheie „instanță|flux" → rândul din `sync_cursors`. */
  readonly cursors = new Map<string, CursorRow>();
  /** Ce s-a scris în `instances` prin `noteBatch`. */
  readonly instanceUpdates: unknown[][] = [];
  /** Ce s-a consemnat despre lanț. Cheie „instanță" → rândul din
   *  `audit_chain_state`. Lipsa cheii înseamnă NICIODATĂ verificat. */
  readonly chainState = new Map<string, Record<string, unknown>>();
  readonly asked: string[] = [];
  private readonly opts: FakeOptions;
  private readonly instances: InstanceRow[];

  constructor(opts: FakeOptions = {}) {
    this.opts = opts;
    this.instances = opts.instances ?? [
      { instance_id: INSTANCE, enabled: 1, ship_secret_enc: sealedShipKey() },
    ];
  }

  async end(): Promise<void> { /* nimic de închis */ }

  /**
   * Cârligul per conexiune al pool-ului. Dublul nu deschide nicio sesiune
   * MariaDB, deci n-are ce pune în mod strict — dar ȚINE tratantul, ca
   * `useFakeServer` să poată cere ca `getPool` chiar să-l fi înregistrat. Ce
   * TRIMITE tratantul se probează în `tests/db-strict-mode.test.ts`.
   */
  connectionHandler: ((connection: PooledConnection) => void) | null = null;

  on(_event: "connection", handler: (connection: PooledConnection) => void): unknown {
    this.connectionHandler = handler;
    return this;
  }

  async query(sql: string, params: unknown[] = []): Promise<[unknown, unknown]> {
    this.asked.push(sql);
    if (this.opts.failOn && sql.startsWith(this.opts.failOn)) {
      throw new Error("serverul a refuzat interogarea");
    }

    if (sql.startsWith("SELECT enabled, ship_secret_enc FROM instances")) {
      const found = this.instances.filter((i) => i.instance_id === params[0]);
      return [found.map((i) => ({ enabled: i.enabled, ship_secret_enc: i.ship_secret_enc })), []];
    }

    if (/^INSERT (?:IGNORE )?INTO \w+ \(/.test(sql)
        && !sql.startsWith("INSERT INTO audit_chain_state")
        && !sql.startsWith("INSERT INTO sync_cursors")) {
      // Scrierea unui flux, în oricare dintre cele două forme. Instrucțiunea se
      // CITEȘTE (`tests/sql-reading.ts`): coloanele, tuplurile și clauza de
      // actualizare vin din text, nu dintr-o ordine presupusă.
      const insert = readMultiRowInsert(sql, params);
      // Coloanele emise trebuie să EXISTE în tabelă. Vezi `TABLE_COLUMNS`.
      const declared = TABLE_COLUMNS.get(insert.table);
      assert.ok(declared && declared.length,
                `dublul nu știe coloanele tabelei ${insert.table}: nu e în nicio ` +
                "migrație livrată");
      for (const column of insert.columns) {
        assert.ok((declared as string[]).includes(column),
                  `${insert.table} nu declară coloana ${column}; pe MariaDB ` +
                  `instrucțiunea asta ar fi „Unknown column '${column}' in 'field list'”`);
      }
      const store = this.tableRows(insert.table);

      // Triggerul de append-only, modelat. `migrations/0001_core.sql` scrie de ce
      // ingestia lui `audit_entries` NU poate fi `ON DUPLICATE KEY UPDATE`:
      // ramura de UPDATE declanșează `audit_entries_no_update`, deci lotul moare
      // la primul rând deja prezent — adică la fiecare retrimitere. Dublul ridică
      // aceeași eroare, ca o întoarcere viitoare la forma greșită să pice aici,
      // nu pe gazdă, la a doua rundă de expediere.
      const appendOnlyTable = insert.table === "audit_entries";

      for (const row of insert.rows) {
        const id = Number(row.source_id);
        const key = identityKey(insert.table, row);
        const existing = store.get(key);

        if (existing && appendOnlyTable && !insert.ignore) {
          throw new Error(
            "ERROR 1644 (45000): audit_entries is append-only (UPDATE refused)");
        }
        // `INSERT IGNORE`: primul scris câștigă, iar ce e „înghițit" nu ajunge în
        // tabelă și nu produce nicio eroare.
        if (this.opts.swallow?.has(id) || this.opts.swallowWhere?.(row)) continue;
        if (existing && insert.ignore) continue;
        if (!existing) { store.set(key, { ...row }); continue; }

        // `ON DUPLICATE KEY UPDATE`: se aplică EXACT atribuirile din clauză.
        // Dacă o coloană lipsește de acolo, rândul stocat își păstrează valoarea
        // veche — chiar defectul pe care testele îl caută.
        const patch: Row = {};
        for (const [column, expression] of insert.updates) {
          patch[column] = evaluate(expression, existing,
                                   () => { throw new Error("parametru neașteptat"); }, row);
        }
        store.set(key, { ...existing, ...patch });
      }
      return [{ affectedRows: insert.rows.length }, []];
    }

    const counting = /^SELECT COUNT\(\*\) AS n FROM (\w+) /.exec(sql);
    if (counting) {
      if (this.opts.blindCount) return [[], []];
      if (this.opts.countValue !== undefined) return [[{ n: this.opts.countValue }], []];
      // Filtrul de instanță și COLOANELE după care se numără se CITESC din
      // instrucțiune. Fără filtru, `COUNT` ar număra rândurile oricărei instanțe
      // cu aceleași chei — scurgerea pe care un dublu care presupune filtrul
      // n-o poate arăta. Iar coloanele contează la fel de mult: o numărătoare
      // scrisă pe `source_id` acolo unde identitatea e `(source_id, tag)` ar
      // răspunde „prezent" pentru un rând care nu e acolo.
      const instance = /WHERE instance_id = \? AND /.test(sql) ? String(params[0]) : null;
      const columns = countedColumns(sql);
      const store = this.tableRows(counting[1]);
      const rest = instance === null ? params : params.slice(1);
      const wanted = new Set<string>();
      for (let i = 0; i + columns.length <= rest.length; i += columns.length) {
        wanted.add(JSON.stringify(rest.slice(i, i + columns.length).map(cell)));
      }
      // Semantica lui `IN`, nu o căutare pe cheie: se numără RÂNDURI, o dată
      // fiecare, pe coloanele NUMITE în predicat. Diferența e tot ce contează —
      // `source_id IN (7, 7)` chiar potrivește ambele rânduri cu `source_id = 7`
      // (fratele rămas de la un lot dinainte, plus cel nou), iar o numărătoare
      // scrisă pe coloana greșită trebuie să iasă GREȘIT în dublu, nu „zero".
      //
      // Aceeași formă răspunde și la a doua întrebare a sub-rândurilor — „câte
      // sunt sub părinții ăștia?" —, unde coloanele din predicat sunt legătura,
      // nu cheia.
      let n = 0;
      for (const row of store.values()) {
        if (instance !== null && String(row.instance_id) !== instance) continue;
        if (wanted.has(JSON.stringify(columns.map((column) => cell(row[column]))))) n++;
      }
      // Șir, ca `bigNumberStrings`.
      return [[{ n: String(n) }], []];
    }

    if (sql.startsWith("DELETE FROM ")) {
      // Curățarea sub-rândurilor. `skipDelete` o face o OPERAȚIE NULĂ tăcută —
      // exact ce se întâmplă dacă cineva scoate pasul, sau dacă predicatul iese
      // gol: nicio eroare, nicio urmă, și mulțimile se contopesc. Numărătoarea
      // de sub părinți e singurul lucru care poate să vadă asta.
      const parsed = readDelete(sql, params);
      if (this.opts.skipDelete) return [{ affectedRows: 0 }, []];
      const store = this.tableRows(parsed.table);
      for (const [key, row] of [...store.entries()]) {
        // Filtrul de instanță se CITEȘTE, nu se presupune. Vezi `readDelete`.
        if (parsed.instance !== null && String(row.instance_id) !== String(parsed.instance)) {
          continue;
        }
        const hit = parsed.filters.every((filter) => {
          const value = JSON.stringify(filter.columns.map((c) => cell(row[c])));
          const listed = filter.tuples
            .some((tuple) => JSON.stringify(tuple.map(cell)) === value);
          return filter.negated ? !listed : listed;
        });
        if (hit) store.delete(key);
      }
      return [{ affectedRows: 1 }, []];
    }

    if (sql.startsWith("INSERT INTO sync_cursors")) {
      if (!this.opts.frozenCursor) {
        const [instance, stream, watermark, inserted, batchSeq] = params as
          [string, string, number | string, number, number];
        const key = `${instance}|${stream}`;
        const existing = this.cursors.get(key);
        // Coloana se CITEȘTE din instrucțiune, nu din tipul valorii: aleasă din
        // valoare, dublul ar accepta un flux întreg căruia i-ar sosi un șir, iar
        // testul ar trece verde peste chiar defectul care mută filigranul în
        // coloana greșită.
        const textual = sql.includes("(instance_id, stream, last_source_key,");
        // `GREATEST` se citește tot din instrucțiune: o scriere care mută
        // cursorul ÎNAPOI (un lot reluat, sau două expeditoare) e altceva decât
        // una monotonă, iar dublul trebuie să le poată deosebi.
        const monotonic = sql.includes("GREATEST(last_source_key, ?)")
          || sql.includes("GREATEST(last_source_id, ?)");
        // Maximul se ia cu ordinea FELULUI, ca `GREATEST` pe coloana reală:
        // numeric pentru întregi, pe octeți pentru text. `Math.max` peste șiruri
        // ar da `NaN`, adică un cursor care arată ca o valoare și nu e.
        const greatest = (a: number | string, b: number | string) =>
          textual ? (String(a) > String(b) ? a : b) : Math.max(Number(a), Number(b));
        this.cursors.set(key, existing
          ? {
            last_source_id: monotonic
              ? greatest(existing.last_source_id, watermark) : watermark,
            rows_ingested: existing.rows_ingested + inserted,
            last_batch_seq: Math.max(existing.last_batch_seq, batchSeq),
          }
          : { last_source_id: watermark, rows_ingested: inserted, last_batch_seq: batchSeq });
      }
      return [{ affectedRows: 1 }, []];
    }

    if (sql.startsWith("SELECT last_source_id FROM sync_cursors")
        || sql.startsWith("SELECT last_source_key FROM sync_cursors")) {
      const column = sql.startsWith("SELECT last_source_key")
        ? "last_source_key" : "last_source_id";
      const row = this.cursors.get(`${String(params[0])}|${String(params[1])}`);
      if (row && "cursorValue" in this.opts) {
        return [[{ [column]: this.opts.cursorValue }], []];
      }
      // Șir, ca `bigNumberStrings`. Lipsa rândului e un set gol, nu un zero.
      return [row ? [{ [column]: String(row.last_source_id) }] : [], []];
    }

    if (sql.startsWith("UPDATE instances SET")) {
      this.instanceUpdates.push(params);
      return [{ affectedRows: 1 }, []];
    }

    // --- verificarea lanțului (`lib/chain.ts`) ------------------------------
    if (sql.startsWith("SELECT source_id, prev_hash, entry_hash FROM audit_entries")) {
      // Filtrul de instanță se CITEȘTE din instrucțiune, ca peste tot în
      // dublurile astea: fără el, lanțurile a două instanțe s-ar amesteca.
      const filtered = sql.includes("WHERE instance_id = ?");
      const instance = filtered ? String(params[0]) : null;
      const rest = filtered ? params.slice(1) : params;
      let rows = [...this.audit.entries()]
        .filter(([key]) => instance === null || key.startsWith(`${instance}|`))
        .map(([, row]) => ({
          source_id: String(row.source_id),
          prev_hash: row.prev_hash,
          entry_hash: row.entry_hash,
          n: Number(row.source_id),
        }))
        .sort((a, b) => a.n - b.n);
      if (sql.includes("source_id > ?")) rows = rows.filter((r) => r.n > Number(rest[0]));
      else if (sql.includes("source_id < ?")) rows = rows.filter((r) => r.n < Number(rest[0]));
      if (sql.includes("ORDER BY source_id DESC")) rows = [...rows].reverse();
      const limit = /LIMIT (\d+)/.exec(sql);
      if (!limit) throw new Error(`interogare fără LIMIT pe arhivă: ${sql}`);
      return [rows.slice(0, Number(limit[1]))
        .map(({ source_id, prev_hash, entry_hash }) => ({ source_id, prev_hash, entry_hash })), []];
    }

    if (sql.startsWith("SELECT status,") && sql.includes("FROM audit_chain_state")) {
      const row = this.chainState.get(String(params[0]));
      return [row ? [row] : [], []];
    }

    if (sql.startsWith("INSERT INTO audit_chain_state")) {
      // Citită din instrucțiune, ca peste tot: `lib/chain.ts` emite TREI forme,
      // după cine are autoritatea să scrie `status`. Vezi `tests/sql-reading.ts`.
      const id = String(params[0]);
      this.chainState.set(id, applyUpsert(sql, params, this.chainState.get(id)));
      return [{ affectedRows: 1 }, []];
    }

    throw new Error(`FakeServer: interogare neprevăzută: ${sql}`);
  }

  /** Câte rânduri sunt în arhivă pentru o instanță. Echivalentul lui
   *  `SELECT count(*)` din criteriul de acceptanță 2 al planului. */
  tableRows(table: string): Map<string, Row> {
    if (!this.tables.has(table)) this.tables.set(table, new Map());
    return this.tables.get(table) as Map<string, Row>;
  }

  countFor(instanceId: string = INSTANCE): number {
    let n = 0;
    for (const key of this.audit.keys()) if (key.startsWith(`${instanceId}|`)) n++;
    return n;
  }

  storedRow(id: number, instanceId: string = INSTANCE, table = "audit_entries"): Row | undefined {
    return this.tableRows(table).get(`${instanceId}|${id}`);
  }
}

/** Lățimea unui tuplu de `audit_entries`: instanța + coloanele fluxului +
 *  `batch_seq`. `received_at` nu e parametru — se scrie cu `UTC_TIMESTAMP(6)`. */
export function auditRowWidth(): number {
  const stream = streamFor("audit_log");
  if (!stream) throw new Error("fluxul audit_log a dispărut din lib/streams.ts");
  return stream.columns.length + 2;
}

/** Poziția unei coloane în tuplul de parametri, ca testele să se poată uita la
 *  ce s-a scris fără să numere de mână. */
export function columnAt(name: string): number {
  const stream = streamFor("audit_log");
  if (!stream) throw new Error("fluxul audit_log a dispărut din lib/streams.ts");
  const index = stream.columns.findIndex((c) => c.source === name);
  if (index < 0) throw new Error(`coloana ${name} nu e în fluxul audit_log`);
  return index + 1;
}

/** Pune dublul în locul driverului și dă mediul de bază. */
export async function useFakeServer(opts: FakeOptions = {}): Promise<FakeServer> {
  await closePool();
  baseEnv();
  const server = new FakeServer(opts);
  getPool(() => server, DB_ENV);
  // Nu e decor: dacă `getPool` încetează să înregistreze cârligul, toate
  // conexiunile de producție rămân pe `sql_mode`-ul gazdei — nestrict, măsurat —
  // și fiecare rând prea lung intră TĂIAT și numărat drept prezent. Fără
  // aserțiunea asta, singurul test care ar fi observat e cel dedicat; aici o
  // observă fiecare test de ingestie.
  assert.ok(server.connectionHandler,
            "getPool nu a înregistrat cârligul `connection`, deci nicio " +
            "conexiune nu mai primește sql_mode strict — vezi lib/db.ts");
  return server;
}

export async function forgetServer(): Promise<void> {
  await closePool();
}

let nextId = 91_000;

/** Hash-ul de probă al unui rând, derivat din `id`. Evident fals, dar
 *  înlănțuibil: `auditHash(n)` e `entry_hash`-ul lui `n` și `prev_hash`-ul lui
 *  `n + 1`. */
export function auditHash(id: number): string {
  // Hexa, fiindcă `lib/ingest.ts` cere 64 de caractere hexa pentru coloanele de
  // hash — coloana e `VARCHAR(64) ascii`, iar orice altceva ar fi tăiat tăcut la
  // scriere. O fixtură care nu respectă forma ar fi refuzată la validare, nu la
  // verificarea lanțului, iar testul ar pica din alt motiv decât cel numit.
  return id.toString(16).padStart(64, "0");
}

/** Un rând de `audit_log` cu forma pe care o trimite `shipper.py`. */
export function auditRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  // `id`-ul EFECTIV, nu cel generat: `over.id` e chiar felul în care testele
  // aleg numerele, iar hash-urile trebuie să urmeze rândul, altfel un lot
  // „valid" ar fi de fapt un lanț rupt și verificarea ar raporta corect ceva ce
  // testul n-a vrut să spună.
  const id = over.id === undefined ? nextId++ : Number(over.id);
  return {
    id,
    at: "2026-08-15T09:13:58.104211+00:00",
    actor: "telegram:operator",
    source: "telegram",
    operation: "incident.close",
    target: "incident:8812",
    params: '{"reason": "fals pozitiv"}',
    result: "ok",
    detail: null,
    // Înlănțuite ca la sursă: `prev_hash` al unui rând e `entry_hash`-ul celui
    // dinainte. Un lot real E un lanț, iar o fixtură care nu e ar face
    // verificarea din `lib/chain.ts` să raporteze o ruptură la fiecare test.
    prev_hash: auditHash(id - 1),
    entry_hash: auditHash(id),
    ...over,
  };
}

/**
 * Un lot valid, proaspăt.
 *
 * `cursors` se calculează din rânduri, nu se scrie de mână: la fel face
 * `shipper.py` (`watermark = rows[-1].id`), iar un test care le-ar putea
 * dezacorda din neatenție ar pica din alt motiv decât cel probat.
 */
export function syncPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  const rows = over.rows ?? { audit_log: [auditRow()] };
  const cursors: Record<string, number> = {};
  // Defensiv: unele teste trimit dinadins un `rows` malformat, iar schela n-are
  // voie să cadă înaintea rutei — altfel testul ar pica din alt motiv.
  if (rows !== null && typeof rows === "object" && !Array.isArray(rows)) {
    for (const [name, list] of Object.entries(rows as Record<string, unknown>)) {
      if (!Array.isArray(list)) continue;
      const ids = list.map((r) => Number((r as Record<string, unknown>)?.id));
      cursors[name] = ids.length ? Math.max(...ids) : 0;
    }
  }
  return {
    instance_id: INSTANCE,
    batch_seq: 4471,
    sent_at: new Date().toISOString(),
    max_age_s: 300,
    cursors,
    rows,
    ...over,
  };
}

/**
 * Cererea POST către /sync, semnată corect.
 *
 * Corpul e serializat cu `JSON.stringify`, NU cu forma canonică — dinadins.
 * Agregatorul verifică semnătura peste octeții primiți și nu recalculează
 * niciodată forma canonică; un test care ar folosi-o ar ascunde tocmai
 * proprietatea asta. Că octeții produși de capătul Python sunt acceptați se
 * dovedește separat, cu un vector de aur, în `tests/signature.test.ts`.
 */
export function syncRequest(opts: {
  payload?: unknown;
  raw?: string | Buffer;
  key?: string;
  instance?: string | null;
  signature?: string;
  /** Împachetează corpul pentru transport, ca `sentinel/report/envelope.py`.
   *  Semnătura rămâne peste octeții DINĂUNTRU — dacă schela ar semna plicul,
   *  fiecare probă cu `wrapped: true` ar trece din alt motiv decât cel scris. */
  wrapped?: boolean;
} = {}): Request {
  const body = opts.raw !== undefined
    ? Buffer.from(opts.raw as string)
    : Buffer.from(JSON.stringify(opts.payload ?? syncPayload()), "utf8");
  const key = opts.key ?? SHIP_KEY;
  const signature = opts.signature
    ?? crypto.createHmac("sha256", key).update(body).digest("hex");
  const wire = opts.wrapped ? wireOf(body) : body;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Sentinel-Signature": signature,
  };
  const instance = opts.instance === undefined ? INSTANCE : opts.instance;
  if (instance) headers["X-Sentinel-Instance"] = instance;

  return new Request("https://exemplu.invalid/api/sentinel/sync", {
    method: "POST",
    body: wire,
    headers,
  });
}

/**
 * Plicul, scris cu mâna după aceleași reguli ca `envelope.py:wrap`.
 *
 * Nu cheamă `lib/envelope.ts`: schela ar proba atunci că modulul e invers cu el
 * însuși. Că exact octeții produși de partea Python sunt citiți de partea asta
 * se probează cu vectorul comun, în `tests/envelope.test.ts`.
 */
export function wireOf(signed: Buffer): Buffer {
  const packed = zlib.gzipSync(signed, { level: 6 });
  const encoded = packed.toString("base64");
  const head = '{"enc":"gzip+base64","v":1,"pad":"';
  const tail = `","body":"${encoded}"}`;
  const needed = Math.ceil(signed.length / 64);
  const pad = "0".repeat(Math.max(0, needed - (head.length + tail.length)));
  return Buffer.from(head + pad + tail, "ascii");
}

/** Adună `console.warn` — refuzurile. Vezi nota din `tests/witness-harness.ts`. */
export function captureWarn(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.warn = original; } };
}

/** Adună `console.error` — configurația și efectele neconfirmate. */
export function captureError(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.error = original; } };
}
