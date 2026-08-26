/**
 * Ingestia unui flux: ce se scrie, ce se refuză, și ce dovedește ecoul.
 *
 * ## Ce se strică pentru operator dacă modulul ăsta greșește
 *
 * Un filigran ecouat face expeditorul să avanseze cursorul, iar un cursor nu se
 * întoarce niciodată. Deci fiecare eșec de mai jos are aceeași formă:
 * agregatorul spune „le am" despre rânduri pe care nu le are, expeditorul trece
 * mai departe, iar rândurile lipsesc pentru totdeauna din singura copie pe care
 * n-o poate șterge cineva cu root pe mașina monitorizată. Pe agregator lipsa nu
 * se vede — nimeni nu știe ce trebuia să fie acolo.
 *
 * A doua formă, mai puțin evidentă: rândul e ACOLO, dar altul decât cel trimis.
 * `INSERT IGNORE` taie un șir prea lung și pune valoarea implicită peste un
 * `NULL` nepermis, cu un avertisment pe care nu-l citește nimeni. Numărătoarea
 * nu prinde asta — numai refuzul dinainte o prinde. Iar un rând tăiat arată
 * identic cu unul falsificat când se verifică lanțul.
 *
 * Vezi `tests/sync-harness.ts` pentru ce afirmă dublul și ce nu poate afirma.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { queryableDb } from "../lib/db";
import {
  MAX_BODY_BYTES, MAX_ROWS_PER_BATCH, MAX_ROW_BYTES,
  ingestStream, parentTarget, prepareRows, toUtcDatetime, writeSql,
} from "../lib/ingest";
import { CURSOR_KINDS, allStreams, streamFor } from "../lib/streams";
import type { Stream } from "../lib/streams";
import { FakeServer, INSTANCE, auditRow, columnAt } from "./sync-harness";
import { readMultiRowInsert } from "./sql-reading";

const AUDIT = streamFor("audit_log")!;

function dbOf(server: FakeServer) {
  return queryableDb(server);
}

/** Ingestia unui lot, cu filigranul calculat ca la expeditor. */
async function ingest(server: FakeServer, rows: Record<string, unknown>[], batchSeq = 1) {
  const watermark = Math.max(...rows.map((r) => Number(r.id)));
  return await ingestStream(dbOf(server), INSTANCE, AUDIT, rows, watermark, batchSeq);
}

// ---------------------------------------------------------------------------
// Timpul
// ---------------------------------------------------------------------------
test("timpul se convertește la UTC și PĂSTREAZĂ microsecundele", () => {
  // Prin `new Date(...)` s-ar fi pierdut ultimele trei cifre, tăcut. Coloana e o
  // replică a unui `timestamptz` cu precizie de microsecundă, iar regula din
  // capul lui `migrations/0001_core.sql` e că nimic nu se trunchiază aici.
  const converted = toUtcDatetime("2026-08-15T12:13:58.104211+03:00");
  assert.equal(converted.ok && converted.value, "2026-08-15 09:13:58.104211");

  // Fracțiune scurtă: se completează cu zerouri, nu se lasă parțială.
  const short = toUtcDatetime("2026-08-15T09:13:58.1Z");
  assert.equal(short.ok && short.value, "2026-08-15 09:13:58.100000");

  // Fără fracțiune deloc.
  const none = toUtcDatetime("2026-08-15T09:13:58+00:00");
  assert.equal(none.ok && none.value, "2026-08-15 09:13:58.000000");

  // Decalaj negativ care trece peste miezul nopții: ziua se schimbă.
  const across = toUtcDatetime("2026-08-14T23:30:00-05:00");
  assert.equal(across.ok && across.value, "2026-08-15 04:30:00.000000");
});

test("un timp FĂRĂ decalaj e refuzat, nu presupus UTC", () => {
  // „Nu se știe în ce fus" și „e UTC" sunt lucruri diferite. Presupunerea mută
  // tăcut istoricul cu câteva ore, iar un istoric de securitate mutat e chiar
  // felul în care o corelare de incident iese greșită.
  assert.equal(toUtcDatetime("2026-08-15T09:13:58.104211").ok, false);
  assert.equal(toUtcDatetime("2026-08-15 09:13:58").ok, false);
});

test("o dată inexistentă în calendar e refuzată, nu normalizată", () => {
  // `Date.UTC(2026, 1, 30)` întoarce 2 martie fără să se plângă. Fără
  // verificarea de după, rândul ar intra în arhivă cu ALT moment decât cel
  // trimis — o falsificare produsă de replică, nu de atacator.
  assert.equal(toUtcDatetime("2026-02-30T09:00:00+00:00").ok, false);
  assert.equal(toUtcDatetime("2026-13-01T09:00:00+00:00").ok, false);
  assert.equal(toUtcDatetime("2026-08-15T24:00:00+00:00").ok, false);
});

test("mai multă precizie decât ține coloana e refuz, nu tăiere", () => {
  assert.equal(toUtcDatetime("2026-08-15T09:13:58.1042117+00:00").ok, false);
});

// ---------------------------------------------------------------------------
// Rândurile
// ---------------------------------------------------------------------------
test("un rând valid iese cu parametrii în ordinea coloanelor", () => {
  const prepared = prepareRows(AUDIT, [auditRow({ id: 5 })], INSTANCE, 42);
  assert.ok(prepared.ok);
  assert.deepEqual(prepared.keys, [5]);
  const tuple = prepared.values[0];
  assert.equal(tuple[0], INSTANCE, "instanța nu e primul parametru");
  assert.equal(tuple[columnAt("id")], 5);
  assert.equal(tuple[columnAt("at")], "2026-08-15 09:13:58.104211");
  assert.equal(tuple[tuple.length - 1], 42, "batch_seq nu e ultimul parametru");
});

test("un câmp NECUNOSCUT în rând oprește fluxul, nu se aruncă tăcut", () => {
  // Sursa a crescut o coloană pe care replica nu o are. Ignorată, s-ar pierde
  // DEFINITIV: cursorul trece peste rând, iar rândul nu se mai retrimite
  // niciodată. Refuzul ține fluxul pe loc, vizibil în `ship:lag`, până când
  // agregatorul primește migrația.
  const prepared = prepareRows(AUDIT, [auditRow({ severity: "high" })], INSTANCE, 1);
  assert.equal(prepared.ok, false);
  assert.match((prepared as { detail: string }).detail, /severity/);
});

test("un câmp care lipsește e o eroare, nu un NULL", () => {
  const row = auditRow();
  delete row.entry_hash;
  const prepared = prepareRows(AUDIT, [row], INSTANCE, 1);
  assert.equal(prepared.ok, false);
  // Mesajul, nu doar refuzul: un câmp absent e prins și de verificarea de tip
  // („aștept 64 de caractere hexa"), deci o aserțiune doar pe `ok === false` ar
  // fi trecut și fără ramura care spune CE lipsește. Cine citește jurnalul
  // expeditorului trebuie să afle numele câmpului, nu forma lui.
  assert.match((prepared as { detail: string }).detail, /lipsește câmpul "entry_hash"/);
});

test("NULL într-o coloană care nu-l acceptă e refuzat", () => {
  // `INSERT IGNORE` ar fi pus valoarea implicită (`''`) și ar fi avertizat.
  // Rândul ar fi fost PREZENT, deci numărat ca bun, și GREȘIT.
  for (const column of ["actor", "source", "operation", "params", "result", "entry_hash"]) {
    const prepared = prepareRows(AUDIT, [auditRow({ [column]: null })], INSTANCE, 1);
    assert.equal(prepared.ok, false, `${column}: NULL a fost acceptat`);
  }
  // Iar cele care CHIAR acceptă NULL trec — altfel testul de mai sus ar fi
  // verde și pe o implementare care refuză orice.
  for (const column of ["target", "detail", "prev_hash"]) {
    assert.equal(prepareRows(AUDIT, [auditRow({ [column]: null })], INSTANCE, 1).ok, true,
                 `${column}: NULL legitim a fost refuzat`);
  }
});

test("un șir mai lung decât coloana e REFUZAT, nu tăiat", () => {
  // `INSERT IGNORE` taie la 65535 de octeți cu un avertisment. Rândul rezultat
  // e prezent, deci numărătoarea îl declară bun, iar conținutul lui nu mai e cel
  // peste care s-a calculat `entry_hash` la sursă.
  const prepared = prepareRows(AUDIT, [auditRow({ actor: "a".repeat(65_536) })], INSTANCE, 1);
  assert.equal(prepared.ok, false);
  assert.match((prepared as { detail: string }).detail, /nu se trunchiază/);

  // Marginea se măsoară în OCTEȚI, nu în caractere: 65535 de „ă" sunt 131070 de
  // octeți, iar o verificare pe lungimea șirului i-ar fi lăsat să treacă.
  const diacritics = prepareRows(AUDIT, [auditRow({ actor: "ă".repeat(40_000) })], INSTANCE, 1);
  assert.equal(diacritics.ok, false, "marginea a fost măsurată în caractere, nu în octeți");

  // Și exact la margine trece, ca refuzul de mai sus să însemne ceva.
  assert.equal(prepareRows(AUDIT, [auditRow({ actor: "a".repeat(65_535) })], INSTANCE, 1).ok,
               true);
});

test("`params` care nu e JSON valid e refuzat cu numele câmpului", () => {
  // Coloana e `JSON`, adică `LONGTEXT` + `CHECK (json_valid(...))`. Sub `INSERT
  // IGNORE`, un CHECK picat face rândul să DISPARĂ, fără eroare. Numărătoarea de
  // după l-ar prinde, dar mesajul ar fi „lipsesc rânduri" — refuzul de aici
  // spune care câmp, al cărui rând.
  const prepared = prepareRows(AUDIT, [auditRow({ params: "{nu e json" })], INSTANCE, 1);
  assert.equal(prepared.ok, false);
  assert.match((prepared as { detail: string }).detail, /params.*JSON/s);
});

test("un `entry_hash` care nu e 64 hexa e refuzat", () => {
  // Coloana e `VARCHAR(64) CHARACTER SET ascii`. Un șir mai lung ar fi tăiat, iar
  // unul cu caractere din afara ASCII ar fi stricat de conversia de set de
  // caractere — în ambele cazuri tăcut, cu rândul prezent și hash-ul altul.
  for (const bad of ["", "c".repeat(63), "c".repeat(65), "z".repeat(64), 5]) {
    assert.equal(prepareRows(AUDIT, [auditRow({ entry_hash: bad })], INSTANCE, 1).ok, false,
                 `entry_hash=${JSON.stringify(bad)} a fost acceptat`);
  }
});

test("un `id` care nu e întreg pozitiv exact e refuzat", () => {
  for (const bad of [0, -1, 1.5, "5", Number.MAX_SAFE_INTEGER + 2, null]) {
    assert.equal(prepareRows(AUDIT, [auditRow({ id: bad })], INSTANCE, 1).ok, false,
                 `id=${JSON.stringify(bad)} a fost acceptat`);
  }
});

test("același id de două ori în același lot e refuzat", () => {
  // `INSERT IGNORE` ar fi păstrat primul rând și l-ar fi aruncat pe al doilea,
  // iar numărătoarea ar fi ieșit corectă — adică un rând pierdut cu filigranul
  // ecouat.
  const prepared = prepareRows(
    AUDIT, [auditRow({ id: 7 }), auditRow({ id: 7, actor: "altcineva" })], INSTANCE, 1);
  assert.equal(prepared.ok, false);
  assert.match((prepared as { detail: string }).detail, /de două ori/);
});

test("un lot gol nu e o operație nulă, e o eroare", () => {
  // Un flux fără rânduri dar cu filigran ar cere avansarea cursorului peste un
  // gol. Expeditorul nu trimite așa ceva; dacă vine, ceva e rupt.
  assert.equal(prepareRows(AUDIT, [], INSTANCE, 1).ok, false);
});

test("un lot peste plafon se refuză, dar EXACT plafonul trece", () => {
  // Plafonul e cel pe care `sentinel/config.py` îl declară legal, nu implicitul
  // de 2000: un `max_rows_per_batch` acceptat de config-check și refuzat aici ar
  // opri `audit_log` definitiv, fiindcă `ship_once` nu citește corpul refuzului
  // și nimic nu micșorează lotul. Perechea e ținută de
  // `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`.
  const rows = Array.from({ length: MAX_ROWS_PER_BATCH + 1 }, (_, i) => auditRow({ id: i + 1 }));
  const prepared = prepareRows(AUDIT, rows, INSTANCE, 1);
  assert.equal(prepared.ok, false);
  assert.match((prepared as { detail: string }).detail, new RegExp(String(MAX_ROWS_PER_BATCH + 1)));
  assert.equal(prepareRows(AUDIT, rows.slice(0, MAX_ROWS_PER_BATCH), INSTANCE, 1).ok, true);
});

test("un surogat neîmperecheat e refuzat, nu scris schimbat", () => {
  // `JSON.parse('"\\ud800"')` îl produce fără să se plângă, iar driverul îl
  // codifică cu un caracter de înlocuire — deci rândul ar ajunge în arhivă ALTUL
  // decât cel peste care s-a calculat `entry_hash` la sursă, tăcut. La celălalt
  // capăt `signing.py` îl refuză deja; refuzul de aici acoperă cazul în care
  // corpul nu vine de acolo.
  let probed = 0;
  for (const bad of ["\ud800", "a\udc00b", "sfârșit\ud83d"]) {
    const prepared = prepareRows(AUDIT, [auditRow({ actor: bad })], INSTANCE, 1);
    assert.equal(prepared.ok, false, `${JSON.stringify(bad)} a fost acceptat`);
    assert.match((prepared as { detail: string }).detail, /surogat/);
    probed++;
  }
  assert.equal(probed, 3, "nu s-au probat toate formele");
  // Și o pereche VALIDĂ trece — altfel testul de mai sus ar fi verde și pe o
  // implementare care refuză orice caracter din afara BMP.
  assert.equal(prepareRows(AUDIT, [auditRow({ actor: "emoji \u{1F600}" })], INSTANCE, 1).ok,
               true, "o pereche de surogați validă a fost refuzată");
});

// ---------------------------------------------------------------------------
// Efectul
// ---------------------------------------------------------------------------
test("un lot bun intră, iar cursorul ajunge la filigran", async () => {
  const server = new FakeServer();
  const rows = [auditRow({ id: 10 }), auditRow({ id: 11 })];
  const result = await ingest(server, rows);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.ok && result.watermark, 11);
  assert.equal(result.ok && result.inserted, 2);
  assert.equal(server.countFor(), 2);
  assert.equal(server.cursors.get(`${INSTANCE}|audit_log`)?.last_source_id, 11);
});

test("ACELAȘI lot de două ori: numărul de rânduri nu se schimbă", async () => {
  // Criteriul de acceptanță 2 din plan. Reluarea trebuie să fie o operație nulă
  // — altfel „nu știu ce s-a întâmplat" n-ar putea fi tratat prin retrimitere,
  // iar tratamentul ăla e ce ține regula cursorului în picioare.
  const server = new FakeServer();
  const rows = [auditRow({ id: 20 }), auditRow({ id: 21 })];

  const first = await ingest(server, rows, 1);
  assert.equal(first.ok && first.inserted, 2);
  const after = server.countFor();

  const second = await ingest(server, rows, 2);
  assert.equal(second.ok, true, "reluarea a fost refuzată");
  assert.equal(second.ok && second.watermark, 21, "reluarea nu a mai ecouat filigranul");
  assert.equal(second.ok && second.inserted, 0, "reluarea a raportat rânduri noi");
  assert.equal(server.countFor(), after, "reluarea a schimbat numărul de rânduri");
});

test("un rând înghițit tăcut de INSERT IGNORE NU produce filigran ecouat", async () => {
  // ESTE eșecul pentru care ingestia numără în loc să creadă driverul.
  //
  // `INSERT IGNORE` nu aruncă atunci când un rând e respins din alt motiv decât
  // cheia duplicată — un `CHECK (json_valid(...))` picat, o coloană prea scurtă,
  // o conversie de set de caractere. `affectedRows` nu deosebește „era deja
  // acolo" de „a fost aruncat", deci un ecou emis pe baza lui e o promisiune
  // făcută despre un rând care nu există. Expeditorul avansează cursorul, iar
  // rândul nu se mai întoarce NICIODATĂ.
  const server = new FakeServer({ swallow: new Set([31]) });
  const result = await ingest(server, [auditRow({ id: 30 }), auditRow({ id: 31 })]);

  assert.equal(result.ok, false, "un lot incomplet a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail, /am trimis 2 rânduri, în tabelă sunt 1/);
  // Și cursorul NU s-a mișcat: un filigran neecouat n-are voie să lase în urmă
  // un registru care spune altceva.
  assert.equal(server.cursors.get(`${INSTANCE}|audit_log`), undefined);
});

test("dacă numărătoarea nu se poate citi, nu se confirmă nimic", async () => {
  // „Nu pot număra" și „lipsesc rânduri" opresc amândouă, dar operatorul trebuie
  // să știe pe care o are: prima cere o bază care răspunde, a doua cere o
  // căutare în ce s-a scris.
  const server = new FakeServer({ blindCount: true });
  const result = await ingest(server, [auditRow({ id: 40 })]);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "unavailable");
});

test("un COUNT care nu e număr e „nu știu”, nu zero și nu adevărat", async () => {
  // Un rând citit din altă coloană, un `Buffer` de la driver, o interogare care
  // a selectat altceva decât credea apelantul. `Number(x) || 0` l-ar fi
  // transformat în „zero rânduri prezente" — care e o AFIRMAȚIE, făcută pe o
  // valoare pe care nimeni n-a înțeles-o.
  // `undefined` nu e în listă fiindcă schela îl folosește ca „nu s-a cerut
  // nimic"; drumul ăla e acoperit de `Number(undefined)` din aceeași ramură.
  let probed = 0;
  for (const value of ["nu-e-număr", null, {}, NaN]) {
    const server = new FakeServer({ countValue: value });
    const result = await ingest(server, [auditRow({ id: 41 })]);
    assert.equal(result.ok, false, `n=${JSON.stringify(value)} a fost confirmat`);
    assert.equal(result.ok === false && result.kind, "unavailable",
                 `n=${JSON.stringify(value)}`);
    probed++;
  }
  assert.equal(probed, 4, "nu s-au probat toate formele");
});

test("numărătoarea e a INSTANȚEI, nu a tuturor instanțelor cu același id", async () => {
  // `countPresent` e singura dovadă de efect din tot sistemul. Fără
  // `WHERE instance_id = ?`, numără rândurile ALTEI instanțe cu aceleași
  // `source_id` — adică un filigran ecouat peste rânduri care nu sunt ale
  // instanței care le-a trimis. `source_id` e unic doar în cadrul instanței
  // (`migrations/0001_core.sql`), deci ciocnirea nu e exotică: două servere
  // pornite în aceeași zi au aceleași id-uri de audit.
  // Instanța A are deja rândul 42. Scris direct în hartă, nu prin ingestie: ce
  // contează aici e doar că EXISTĂ sub altă instanță.
  //
  // B trimite rândul 42, iar serverul îl înghite (un CHECK picat, o coloană prea
  // scurtă). Numărat corect, B are zero rânduri; numărat fără filtru, are unul —
  // al lui A.
  const server = new FakeServer({ swallow: new Set([42]) });
  server.audit.set("aaaa1111|42", { instance_id: "aaaa1111", source_id: 42 });
  const result = await ingestStream(
    dbOf(server), INSTANCE, AUDIT, [auditRow({ id: 42 })], 42, 1);
  assert.equal(result.ok, false, "rândul altei instanțe a fost numărat ca al nostru");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.equal(server.countFor(INSTANCE), 0);
});

test("cursorul nu se întoarce: un lot mai vechi, reluat, nu-l trage înapoi", async () => {
  // Fără `GREATEST`, o reluare — sau două expeditoare pe aceeași identitate —
  // ar rescrie `last_source_id` cu o valoare mai mică. `sync_cursors` e locul
  // din care se citește mai târziu cine a rămas în urmă, deci un cursor căzut
  // înapoi e o restanță inventată; iar dacă vreodată ceva citește de acolo ca să
  // decidă ce se retrimite, e o retrimitere fără capăt.
  const server = new FakeServer();
  const ten = Array.from({ length: 10 }, (_, i) => auditRow({ id: i + 1 }));
  assert.equal((await ingest(server, ten, 1)).ok, true);
  assert.equal(server.cursors.get(`${INSTANCE}|audit_log`)?.last_source_id, 10);

  // Același lot, dar doar primele cinci rânduri: filigranul e 5, iar toate cinci
  // sunt deja acolo.
  const older = await ingest(server, ten.slice(0, 5), 2);
  assert.equal(older.ok, true);
  assert.equal(server.cursors.get(`${INSTANCE}|audit_log`)?.last_source_id, 10,
               "cursorul a fost tras înapoi de un lot mai vechi");
});

test("timpii se scriu cu UTC_TIMESTAMP(6), nu cu ora sesiunii", async () => {
  // `CURRENT_TIMESTAMP(6)` dă ora LOCALĂ a sesiunii, iar coloanele sunt
  // documentate ca UTC (`migrations/0001_core.sql`). Pe o gazdă pornită în alt
  // fus, `received_at` ar fi mutat cu câteva ore, iar diferența dintre `at` și
  // `received_at` — chiar restanța expeditorului, motivul pentru care coloana
  // există — s-ar citi greșit.
  //
  // E o aserțiune pe interogarea TRIMISĂ, nu pe efectul ei: un dublu n-are fus
  // orar, deci diferența nu se poate arăta altfel decât pe gazdă. Aceeași clasă
  // ca aserțiunea despre `DATABASE()` din `tests/migrate.test.ts`.
  const server = new FakeServer();
  await ingest(server, [auditRow({ id: 60 })]);
  const inserts = server.asked.filter((s) => s.startsWith("INSERT IGNORE INTO audit_entries"));
  assert.ok(inserts.length > 0, "nu s-a trimis niciun INSERT");
  for (const sql of inserts) {
    assert.ok(sql.includes("UTC_TIMESTAMP(6)"), sql.slice(0, 200));
    assert.ok(!/[^_]CURRENT_TIMESTAMP/.test(sql), `folosește ora sesiunii: ${sql.slice(0, 200)}`);
  }
});

test("dacă cursorul nu se mișcă, filigranul nu se ecouă", async () => {
  // Rândurile sunt în arhivă, dar `sync_cursors` e locul din care se citește mai
  // târziu cine a rămas în urmă. Un registru care spune altceva decât ce s-a
  // promis e chiar felul în care o restanță devine invizibilă.
  //
  // Două forme, fiindcă cer mesaje diferite: rândul care nu apare deloc e „nu
  // pot citi", iar rândul care e acolo și a rămas în urmă e „se știe și e
  // greșit". Ce nu au voie să facă nici una, nici alta, e să confirme.
  const missing = new FakeServer({ frozenCursor: true });
  const first = await ingest(missing, [auditRow({ id: 50 })]);
  assert.equal(first.ok, false);
  assert.equal(first.ok === false && first.kind, "unavailable");

  const stuck = new FakeServer({ frozenCursor: true });
  stuck.cursors.set(`${INSTANCE}|audit_log`,
                    { last_source_id: 3, rows_ingested: 0, last_batch_seq: 0 });
  const second = await ingest(stuck, [auditRow({ id: 51 })]);
  assert.equal(second.ok, false);
  assert.equal(second.ok === false && second.kind, "incomplete");
  assert.match((second as { detail: string }).detail, /cursorul a rămas la 3/);
});

// ---------------------------------------------------------------------------
// Forma de scriere, per tip de cursor
// ---------------------------------------------------------------------------
/**
 * Un flux mutabil de probă, peste o tabelă din `0003_entities.sql`.
 *
 * Fabricat aici, nu înregistrat în `lib/streams.ts`: înregistrarea fluxurilor e
 * partea următoare, iar forma de scriere trebuie să existe ÎNAINTE — altfel
 * primul flux mutabil înregistrat ar pierde actualizări tăcut.
 */
const MUTABLE: Stream = {
  name: "incidents",
  table: "incident_entries",
  cursor: "mutable",
  chained: false,
  // `uk_incident_entries_source (instance_id, source_id)`, `0003_entities.sql`.
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: 65_535 },
    { source: "title", target: "title", kind: "text", nullable: false, maxBytes: 65_535 },
  ],
};

/**
 * Fluxul care poartă un ROLLUP — și care e, la receptor, un flux mutabil obișnuit.
 *
 * Nu mai există un fel de cursor `rollup`: bucketul curent retrimis cu cifre noi
 * ESTE cazul mutabil (aceeași identitate, valori noi, trebuie să se suprascrie),
 * iar ingestia nu se uita niciodată la diferență. Vezi `lib/streams.ts` pentru ce
 * s-a respins odată cu felul.
 *
 * De ce fixtura NU arată spre `availability_rollup_entries`, deși tabela există.
 * Nu fiindcă i-ar lipsi coloanele întregi — are nouă, între care `asset_source_id`.
 * Constrângerea e în IDENTITATE: cheia e `(instance_id, asset_source_id, day)`,
 * `day` e `DATE`, iar `asset_source_id` se repetă la fiecare zi, deci `max()`
 * peste el nu spune nimic despre progres. Identitatea n-are niciun membru întreg
 * care să CREASCĂ, deci fluxul n-are ce trimite ca filigran — întrebare deschisă,
 * nu ceva de ascuns într-o fixtură care pretinde că e rezolvată.
 */
const ROLLUP: Stream = { ...MUTABLE, name: "rollup_probe" };

/**
 * Un flux cu cheie de TEXT, modelat pe `actors` din `0003_entities.sql`:
 * `(instance_id, actor_key)`, unde `actor_key` e un text (o adresă, sau
 * `cluster:<hash>`).
 *
 * E cazul lui #61, nu unul construit: fluxul n-are NICIO coloană întreagă, deci
 * n-are ce trimite ca filigran — protocolul poartă un întreg, iar `shipper.py`
 * refuză deja cazul cu `ShipEncodingError`. `assertRegistrable` e refuzul geamăn,
 * ca înregistrarea să nu treacă de o parte și să moară de cealaltă.
 */
const TEXT_KEYED: Stream = {
  name: "actors_probe",
  table: "actor_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "actor_key"],
  watermark: "actor_key",
  columns: [
    { source: "actor_key", target: "actor_key", kind: "text", nullable: false, maxBytes: 190 },
    { source: "kind", target: "kind", kind: "text", nullable: false, maxBytes: 32 },
  ],
};

/** Un rând pentru fluxurile de mai sus. */
function entityRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { id: 7, status: "open", title: "acces refuzat", ...over };
}

async function ingestInto(server: FakeServer, stream: Stream,
                          rows: Record<string, unknown>[], batchSeq = 1) {
  const watermark = Math.max(...rows.map((r) => Number(r.id)));
  return await ingestStream(dbOf(server), INSTANCE, stream, rows, watermark, batchSeq);
}

test("un flux MUTABIL suprascrie rândul; nu pierde actualizarea", async () => {
  // Eșecul pe care îl previne, și motivul pentru care forma de scriere se alege
  // după tipul cursorului: cu `INSERT IGNORE`, un incident închis pe server ar
  // sosi, ar fi ignorat fiindcă identitatea există deja, iar ruta ar ecoua
  // filigranul. Panoul ar arăta la nesfârșit un incident deschis care pe server
  // e rezolvat, expeditorul ar trece peste rând și nu l-ar mai retrimite
  // NICIODATĂ — iar nimic, nicăieri, n-ar spune de ce.
  const server = new FakeServer();

  const opened = await ingestInto(server, MUTABLE, [entityRow()]);
  assert.equal(opened.ok, true, JSON.stringify(opened));
  assert.equal(server.storedRow(7, INSTANCE, MUTABLE.table)?.status, "open");

  const closed = await ingestInto(
    server, MUTABLE, [entityRow({ status: "resolved", title: "acces refuzat" })], 2);
  assert.equal(closed.ok, true, JSON.stringify(closed));
  assert.equal(server.storedRow(7, INSTANCE, MUTABLE.table)?.status, "resolved",
               "actualizarea s-a pierdut: rândul a rămas la versiunea veche");
  // Și rămâne UN singur rând: upsertul actualizează, nu adaugă.
  assert.equal(server.tableRows(MUTABLE.table).size, 1);
});

test("un rând retrimis IDENTIC e un succes, nu un lot incomplet", async () => {
  // Întrebarea pe care `audit_log` n-o punea: la un flux mutabil, ce înseamnă „am
  // scris"? Un rând identic cu cel stocat nu schimbă nimic, și e corect că nu
  // schimbă — MariaDB întoarce `affectedRows = 0` pentru el. Dacă verificarea ar
  // număra rânduri ATINSE, lotul ar ieși `incomplete`, filigranul n-ar fi ecouat,
  // iar expeditorul ar retrimite la nesfârșit un lot perfect valid.
  //
  // De-aia se numără PREZENȚA. Aceeași alegere face gratuită retrimiterea
  // bucketului de rollup, care e proiectată să se repete la fiecare rundă.
  const server = new FakeServer();
  await ingestInto(server, MUTABLE, [entityRow()]);

  const again = await ingestInto(server, MUTABLE, [entityRow()], 2);
  assert.equal(again.ok, true, JSON.stringify(again));
  assert.equal(again.ok && again.watermark, 7);
  assert.equal(server.tableRows(MUTABLE.table).size, 1);
});

test("un bucket de rollup retrimis, cu cifre noi, îl înlocuiește pe cel vechi", async () => {
  // Bucketul curent e incomplet prin construcție și se retrimite la fiecare
  // rundă, cu cifre mai mari. Cu `INSERT IGNORE`, prima versiune — cea mai
  // săracă — ar rămâne pentru totdeauna, iar panoul ar arăta o oră în care nu
  // s-a întâmplat aproape nimic.
  //
  // Cazul e probat cu un flux MUTABIL, fiindcă la receptor asta e: nu există un
  // fel de cursor separat pentru rollup-uri, și nici nu ar schimba nimic.
  const server = new FakeServer();
  await ingestInto(server, ROLLUP, [entityRow({ id: 3, status: "12", title: "ora 09" })]);
  const later = await ingestInto(
    server, ROLLUP, [entityRow({ id: 3, status: "480", title: "ora 09" })], 2);

  assert.equal(later.ok, true, JSON.stringify(later));
  assert.equal(server.storedRow(3, INSTANCE, ROLLUP.table)?.status, "480",
               "bucketul retrimis nu a înlocuit versiunea incompletă");
});

/**
 * Coloanele pe care un upsert TREBUIE să le atribuie, derivate din specificație.
 *
 * Tot ce nu e identitate, plus contabilitatea sosirii. Derivarea e chiar miezul
 * testului de mai jos: o listă de nume scrisă de mână ar fi rămas verde pentru
 * fiecare coloană adăugată după ce a fost scrisă, iar partea următoare aduce zece
 * tabele.
 */
function mustBeUpdated(stream: Stream): Set<string> {
  const identity = new Set(stream.identity);
  return new Set([
    ...stream.columns.map((c) => c.target).filter((target) => !identity.has(target)),
    "received_at", "batch_seq",
  ]);
}

/** Ce atribuie chiar instrucțiunea emisă, citită din text. */
function updatedColumns(stream: Stream): Set<string> {
  const sql = writeSql(parentTarget(stream), 1);
  const params = Array.from({ length: stream.columns.length + 2 }, () => 0);
  return new Set(readMultiRowInsert(sql, params).updates.map(([column]) => column));
}

/**
 * Un flux cu cheie COMPUSĂ care chiar se poate expedia: `availability_rollup`,
 * cheia `(instance_id, asset_source_id, day)`, cu `asset_source_id` întreg.
 *
 * E cazul care despărțea cele două noțiuni: `asset_source_id` se REPETĂ prin
 * construcție (un activ are câte un rând pe zi), deci nu e identitate — dar e
 * singura coloană întreagă, adică singurul candidat de filigran. Cu numărătoarea
 * și dedublarea scrise pe el, un lot valid era refuzat, iar unul cu rânduri
 * pierdute ar fi trecut.
 *
 * ## De ce NU mai e `asset_tags`, cum era
 *
 * Fiindcă `asset_tags` nu mai poate fi un flux de sine stătător (#62): e o tabelă
 * de LEGĂTURĂ, fără `received_at` și `batch_seq`, iar rândurile ei sunt
 * sub-rânduri ale activului. Un `Stream` peste ea ar emite coloane pe care tabela
 * nu le are — chiar defectul reparat —, iar dublul îl refuză acum.
 *
 * Proprietatea probată mai jos e neschimbată, doar mutată pe o tabelă care CHIAR
 * poate fi părinte. Cazul `asset_tags` e probat ca sub-rând, în
 * `tests/subrows.test.ts`.
 */
const COMPOSITE_PARENT: Stream = {
  name: "availability_rollup",
  table: "availability_rollup_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "asset_source_id", "day"],
  watermark: "asset_source_id",
  columns: [
    { source: "asset_id", target: "asset_source_id", kind: "id", nullable: false },
    { source: "day", target: "day", kind: "text", nullable: false, maxBytes: 10 },
  ],
};

test("un lot cu cheie compusă intră; filigranul repetat NU e un duplicat", async () => {
  // Eșecul pe care îl previne, măsurat înainte de reparație:
  // «rows[1]: id-ul 5 apare de două ori în același lot» — un lot perfect valid,
  // refuzat cu 400, fiindcă dedublarea se făcea pe filigran în loc de
  // identitate. Fluxul s-ar fi oprit la primul activ cu două zile, adică
  // imediat, și mesajul ar fi arătat spre expeditor.
  const server = new FakeServer();
  const rows = [{ asset_id: 5, day: "2026-08-01" }, { asset_id: 5, day: "2026-08-02" },
                { asset_id: 9, day: "2026-08-01" }];
  const result = await ingestStream(dbOf(server), INSTANCE, COMPOSITE_PARENT, rows, 9, 1);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(server.tableRows(COMPOSITE_PARENT.table).size, 3, "trei zile, trei rânduri");
  // Și numărătoarea a întrebat despre TUPLURI, nu despre filigran.
  const counting = server.asked.filter((s) => s.startsWith("SELECT COUNT(*)"));
  assert.ok(counting.every((s) => s.includes("(asset_source_id, day) IN ((?, ?)")),
            `numărătoarea nu e pe identitate: ${counting[0]}`);
});

test("un rând pierdut e PRINS, deși filigranul lui e prezent în tabelă", async () => {
  // Cazul pe care o numărătoare scrisă pe coloana de filigran nu-l poate vedea
  // NICIODATĂ, construit exact:
  //
  //   * activul 7 are deja ziua `2026-08-01` în tabelă, dintr-un lot dinainte;
  //   * lotul nou trimite `(7, 08-02)` și `(7, 08-03)`, iar `(7, 08-03)` e
  //     înghițit;
  //   * `COUNT(*) WHERE asset_source_id IN (7, 7)` numără RÂNDURI cu
  //     `asset_source_id = 7`, adică `08-01` și `08-02` — DOUĂ. Exact cât s-a
  //     trimis. Lotul ar fi ieșit complet, filigranul s-ar fi ecouat, iar
  //     `(7, 08-03)` s-ar fi pierdut definitiv, fiindcă un cursor nu se întoarce.
  //
  // Numărând pe identitate, întrebarea devine „sunt `(7, 08-02)` și `(7, 08-03)`
  // acolo?" — și răspunsul e nu.
  const server = new FakeServer({ swallowWhere: (row) => row.day === "2026-08-03" });
  const seeded = await ingestStream(dbOf(server), INSTANCE, COMPOSITE_PARENT,
                                    [{ asset_id: 7, day: "2026-08-01" }], 7, 1);
  assert.equal(seeded.ok, true, JSON.stringify(seeded));

  const rows = [{ asset_id: 7, day: "2026-08-02" }, { asset_id: 7, day: "2026-08-03" }];
  const result = await ingestStream(dbOf(server), INSTANCE, COMPOSITE_PARENT, rows, 7, 2);

  assert.equal(result.ok, false, "un lot cu un rând lipsă a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail, /am trimis 2 rânduri, în tabelă sunt 1/);
  // Și fratele cu același filigran chiar e acolo — altfel proba n-ar fi despre
  // ce pretinde că e.
  assert.equal(server.tableRows(COMPOSITE_PARENT.table).size, 2);
});

test("filigranul se ia din coloana DECLARATĂ, nu din prima coloană", async () => {
  // Ordinea coloanelor unui flux e liberă: sursa trimite un obiect, iar
  // `lib/streams.ts` decide în ce ordine se leagă parametrii. Că prima coloană a
  // fost `source_id` peste tot e o obișnuință, nu o regulă — iar un flux care o
  // rupe (aici: eticheta întâi) ar fi luat filigranul dintr-un TEXT.
  //
  // Ce s-ar fi întâmplat: `Math.max` peste texte dă `NaN`, iar lotul ar fi ieșit
  // `invalid` cu un mesaj despre filigran — pentru un lot perfect bun. Măsurat:
  // fără proba asta, mutarea filigranului înapoi pe „prima coloană" nu pica
  // nimic, fiindcă toate fixturile aveau `source_id` primul.
  const reordered: Stream = {
    ...COMPOSITE_PARENT,
    columns: [
      { source: "day", target: "day", kind: "text", nullable: false, maxBytes: 10 },
      { source: "asset_id", target: "asset_source_id", kind: "id", nullable: false },
    ],
  };
  const server = new FakeServer();
  const result = await ingestStream(
    dbOf(server), INSTANCE, reordered,
    [{ asset_id: 4, day: "2026-08-01" }, { asset_id: 8, day: "2026-08-01" }], 8, 1);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.ok && result.watermark, 8, "filigranul nu vine din coloana declarată");
  assert.equal(server.tableRows(COMPOSITE_PARENT.table).size, 2);
});

test("filigranul se citește după NUME: nici din identitate, nici din poziție", () => {
  // Testul de deasupra a închis „citit pozițional din lista de coloane". Rămăsese
  // o variantă alături, invizibilă fiindcă în toate fixturile coloana de filigran
  // se NIMEREA să fie și membru al identității: citit din TUPLUL DE IDENTITATE.
  // Măsurat, `byTarget.get(stream.watermark)` → `byTarget.get(stream.identity[1])`
  // nu pica nimic, nici în TypeScript, nici la capătul Python.
  //
  // Ce s-ar strica: filigranul ecouat ar fi calculat din altă coloană decât cea
  // declarată. Dacă iese tot întreg, agregatorul ecouă un număr pe care
  // `accepted_watermarks` nu-l recunoaște, deci fluxul nu avansează NICIODATĂ;
  // dacă valorile se nimeresc egale, cursorul avansează pe o coincidență. În
  // ambele cazuri testul cu două capete tace, deși există exact pentru asta.
  //
  // Se probează pe `prepareRows`, stratul unde se face citirea, cu două forme pe
  // care nicio fixtură de mai sus nu le are:
  const cases: { why: string; stream: Stream; rows: Record<string, unknown>[]; keys: number[] }[] = [
    {
      // 1. Filigranul e ULTIMUL membru al identității, nu primul. Orice citire de
      //    la începutul tuplului dă `plan_source_id`, care e alt număr.
      why: "identitatea începe cu altă coloană",
      stream: {
        name: "patch_plan_findings", table: "patch_plan_findings",
        cursor: "append-only", chained: false,
        identity: ["instance_id", "plan_source_id", "finding_source_id"],
        watermark: "finding_source_id",
        columns: [
          { source: "plan_id", target: "plan_source_id", kind: "id", nullable: false },
          { source: "finding_id", target: "finding_source_id", kind: "id", nullable: false },
        ],
      },
      rows: [{ plan_id: 3, finding_id: 71 }, { plan_id: 3, finding_id: 72 }],
      keys: [71, 72],
    },
    {
      // 2. Filigranul NU e deloc membru al identității. Atunci orice citire din
      //    identitate iese diferită, indiferent de poziție — forma care închide
      //    clasa întreagă, nu încă un caz de lângă.
      //
      //    E și forma de care are nevoie piesa 2: pentru rollup-uri, identitatea
      //    `(instance_id, asset_source_id, day)` n-are niciun membru întreg care
      //    să crească, deci filigranul lor va trebui să vină din AFARA
      //    identității. Fixtura probează citirea, nu propune fluxul.
      why: "filigranul e în afara identității",
      stream: {
        name: "sondă_rollup", table: "availability_rollup_entries",
        cursor: "mutable", chained: false,
        identity: ["instance_id", "asset_source_id", "day"],
        watermark: "samples",
        columns: [
          { source: "asset_id", target: "asset_source_id", kind: "id", nullable: false },
          { source: "day", target: "day", kind: "text", nullable: false, maxBytes: 10 },
          { source: "samples", target: "samples", kind: "id", nullable: false },
        ],
      },
      rows: [{ asset_id: 4, day: "2026-08-16", samples: 240 }],
      keys: [240],
    },
  ];

  for (const { why, stream, rows, keys } of cases) {
    const prepared = prepareRows(stream, rows, INSTANCE, 1);
    assert.ok(prepared.ok, `${why}: ${(prepared as { detail?: string }).detail}`);
    assert.deepEqual(prepared.keys, keys,
                     `${why}: filigranul nu vine din coloana "${stream.watermark}"`);
    // Și identitatea rămâne a ei: cele două citiri nu se pot contopi „din
    // greșeală, dar corect".
    assert.notDeepEqual(prepared.identities[0], [keys[0]],
                        `${why}: identitatea a ieșit egală cu filigranul, deci ` +
                        "fixtura nu deosebește nimic");
  }
});

test("aceeași identitate de două ori în același lot rămâne o eroare", async () => {
  // Dedublarea nu s-a pierdut odată cu mutarea ei pe identitate: două rânduri
  // identice ca identitate ar fi însemnat unul scris și unul aruncat de
  // `INSERT IGNORE`, cu numărătoarea ieșind corectă — un rând pierdut cu
  // filigranul ecouat.
  const server = new FakeServer();
  const rows = [{ asset_id: 5, day: "2026-08-01" }, { asset_id: 5, day: "2026-08-01" }];
  const result = await ingestStream(dbOf(server), INSTANCE, COMPOSITE_PARENT, rows, 5, 1);

  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "invalid");
  assert.match((result as { detail: string }).detail,
               /identitatea \(5, 2026-08-01\) apare de două ori/);
});

test("filigranul unui flux mutabil NU trebuie să crească de la un lot la altul", async () => {
  // Proprietatea care se pierde ușor dacă cineva confundă filigranul cu poziția.
  // Pe un flux mutabil, ordinea de expediere e `(updated_at, id)`, deci un rând
  // vechi atins acum sosește într-un lot al cărui `max(id)` e mai mic decât al
  // lotului dinainte. `sentinel/report/shipper.py` chiar asta trimite
  // (`watermark=max(keys)`), iar receptorul trebuie să-l accepte — altfel
  // fiecare modificare a unui rând vechi ar fi respinsă cu 400, la nesfârșit.
  const server = new FakeServer();
  const first = await ingestInto(
    server, MUTABLE, [entityRow({ id: 5 }), entityRow({ id: 900 })], 1);
  assert.equal(first.ok, true, JSON.stringify(first));

  const older = await ingestInto(
    server, MUTABLE, [entityRow({ id: 12, status: "resolved" })], 2);
  assert.equal(older.ok, true, JSON.stringify(older));
  assert.equal(older.ok && older.watermark, 12, "filigranul ecouat nu e cel trimis");
  assert.equal(server.storedRow(12, INSTANCE, MUTABLE.table)?.status, "resolved");
});

test("filigranul rămâne cel mai mare id DIN LOT, oricât de vechi ar fi lotul", async () => {
  // Cealaltă jumătate a regulii, care NU se relaxează: în interiorul unui lot,
  // filigranul e `max(id)`. Unul mai mare ar cere expeditorului să treacă peste
  // rânduri care n-au fost trimise, iar ecoul l-ar confirma.
  const server = new FakeServer();
  const result = await ingestStream(
    dbOf(server), INSTANCE, MUTABLE, [entityRow({ id: 5 }), entityRow({ id: 12 })], 5, 1);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "invalid");
  assert.match((result as { detail: string }).detail, /nu e cel mai mare id/);
});

test("clauza de actualizare e DERIVATĂ din specificație", async () => {
  // O coloană uitată din `ON DUPLICATE KEY UPDATE` ar rămâne înghețată la prima
  // sosire, iar numărătoarea de după N-AR VEDEA: rândul e prezent, deci lotul e
  // „bun", filigranul se ecouă și cursorul avansează. Măsurat, cu
  // `title = VALUES(title)` scos: prima sosire scrie „acces refuzat", a doua
  // schimbă statusul și lasă titlul vechi — pentru totdeauna, tăcut.
  //
  // De-aia mulțimea așteptată se derivă din SPECIFICAȚIE, nu se enumeră. Forma
  // dinainte enumera `["status", "title", "batch_seq", "received_at"]` — exact
  // coloanele fixturii de atunci —, deci orice coloană adăugată ulterior ar fi
  // fost neapărată din prima zi.
  //
  // Egalitatea se cere în AMÂNDOUĂ direcțiile: ce lipsește e o actualizare
  // pierdută, iar ce e în plus nu poate fi decât o coloană de identitate, adică
  // o cheie rescrisă în propriul `SET`.
  for (const stream of [MUTABLE, ROLLUP, COMPOSITE_PARENT]) {
    assert.deepEqual([...updatedColumns(stream)].sort(), [...mustBeUpdated(stream)].sort(),
                     `${stream.name}: clauza de actualizare emisă nu e cea derivată din spec`);
  }

  // Și instrucțiunea chiar pleacă în forma asta prin ingestie, nu doar din
  // `writeSql` chemat direct.
  const server = new FakeServer();
  await ingestInto(server, MUTABLE, [entityRow()]);
  const written = server.asked.filter((s) => s.startsWith("INSERT INTO incident_entries"));
  assert.equal(written.length, 1, "instrucțiunea nu e un upsert");
  assert.deepEqual(
    [...new Set(readMultiRowInsert(written[0], [INSTANCE, 7, "open", "acces refuzat", 1])
      .updates.map(([column]) => column))].sort(),
    [...mustBeUpdated(MUTABLE)].sort());
});

test("o cheie compusă rămâne în afara lui SET", async () => {
  // Cazul pe care identitatea DEDUSĂ îl rata: identitatea e
  // `(instance_id, asset_source_id, day)`, iar `day` nu e un `id`. Cu deducția
  // „instance_id + coloana cu kind id", `writeSql` emitea `day = VALUES(day)` —
  // chiar lucrul despre care modulul scrie că nu are voie să se întâmple.
  //
  // Pe MariaDB asta nu corupe date (la o potrivire, `VALUES()` pe o coloană de
  // cheie e valoarea stocată), dar face invariantul declarat tăcut fals — iar
  // testul care îl păzea căuta `source_id`, care nu apare deloc aici.
  //
  // Forma cea mai grea a cazului — o cheie de patru coloane, cu ENUM și
  // `BINARY(32)`, adică `actor_attrs` — e probată în `tests/subrows.test.ts`,
  // unde tabela aia trăiește acum ca sub-rând.
  const emitted = updatedColumns(COMPOSITE_PARENT);
  for (const key of COMPOSITE_PARENT.identity) {
    assert.ok(!emitted.has(key),
              `${key} e coloană de cheie și a ajuns în SET: ${[...emitted].join(", ")}`);
  }
  assert.equal(COMPOSITE_PARENT.identity.length, 3);
});

test("dublul aplică EXACT clauza citită, nu rândul întreg", async () => {
  // Testul de deasupra citește TEXTUL clauzei; ăsta ține onest dublul care o
  // execută. Un dublu care ar înlocui rândul întreg, în loc să aplice
  // atribuirile citite, ar arăta o coloană uitată din `SET` ca actualizată —
  // adică ar ascunde exact defectul pe care prezența nu-l poate prinde, și ar
  // face verde orice probă de mai jos care se uită la ce s-a stocat.
  const server = new FakeServer();
  const head = "INSERT INTO incident_entries " +
    "(instance_id, source_id, status, title, received_at, batch_seq) " +
    "VALUES (?, ?, ?, ?, UTC_TIMESTAMP(6), ?)";
  await server.query(
    `${head} ON DUPLICATE KEY UPDATE status = VALUES(status), title = VALUES(title), ` +
    "batch_seq = VALUES(batch_seq)", [INSTANCE, 7, "open", "acces refuzat", 1]);
  // A doua oară, `title` LIPSEȘTE din clauză: rândul rămâne cu titlul vechi.
  await server.query(
    `${head} ON DUPLICATE KEY UPDATE status = VALUES(status), batch_seq = VALUES(batch_seq)`,
    [INSTANCE, 7, "resolved", "alt titlu", 2]);

  const stored = server.storedRow(7, INSTANCE, "incident_entries");
  assert.equal(stored?.status, "resolved", "coloana din clauză nu s-a actualizat");
  assert.equal(stored?.title, "acces refuzat",
               "dublul a scris o coloană care NU era în clauza de actualizare");
});

test("fluxul append-only NU folosește upsert — triggerul l-ar omorî", async () => {
  // Dublul ridică `ERROR 1644 (45000)` dacă un `INSERT` fără `IGNORE` atinge un
  // rând existent din `audit_entries`, exact ca triggerul de append-only din
  // `0001_core.sql`. Deci o alegere greșită de formă pentru fluxul cu lanț se
  // vede AICI, nu pe gazdă la a doua rundă de expediere.
  const server = new FakeServer();
  await ingest(server, [auditRow({ id: 900 })]);
  const again = await ingest(server, [auditRow({ id: 900 })], 2);
  assert.equal(again.ok, true, "retrimiterea unui rând append-only a murit");
  const inserts = server.asked.filter((s) => s.includes("INTO audit_entries"));
  assert.ok(inserts.every((s) => s.startsWith("INSERT IGNORE")),
            "fluxul append-only a fost scris cu altă formă decât INSERT IGNORE");
});

test("filigranul nu se ecouă pe `affectedRows`, nici la upsert", async () => {
  // `affectedRows` e și mai înșelător pe un upsert: 2 pentru o actualizare, 1
  // pentru o inserare, 0 pentru un rând identic. Dublul raportează un
  // `affectedRows` care spune „am scris tot", în timp ce rândul e înghițit —
  // dacă verdictul s-ar sprijini pe el, lotul ar ieși confirmat.
  const server = new FakeServer({ swallow: new Set([7]) });
  const result = await ingestInto(server, MUTABLE, [entityRow()]);
  assert.equal(result.ok, false, "un rând absent a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.equal(server.tableRows(MUTABLE.table).size, 0);
});

/**
 * Regula de înregistrare a unui flux, ca FUNCȚIE.
 *
 * Scoasă din bucla de mai jos ca să poată fi declanșată direct, pe o fixtură.
 * Motivul e o gaură de probă, nu eleganță: singurul fel în care se văzuse
 * refuzul era stricând fluxul înregistrat, iar aia pică ÎNTÂI la validarea de
 * date — deci ce se observa era eșecul colateral, nu regula. O regulă a cărei
 * declanșare n-a fost văzută izolat e o regulă despre care nu se știe pe ce pică.
 */
function assertRegistrable(stream: Stream): void {
  assert.equal(stream.identity[0], "instance_id",
               `${stream.name}: identitatea nu începe cu instance_id`);
  assert.ok(stream.identity.length >= 2,
            `${stream.name}: identitatea e doar instance_id, deci o singură ` +
            "instanță ar avea un singur rând");
  const targets = new Set(stream.columns.map((c) => c.target));
  for (const key of stream.identity.slice(1)) {
    assert.ok(targets.has(key),
              `${stream.name}: coloana de cheie ${key} nu e trimisă de flux`);
  }

  // RESTRICȚIE TEMPORARĂ. CE S-A DEBLOCAT, ȘI CE NU.
  //
  // DEBLOCAT, și dovedit: entitățile mutabile cu cheie ÎNTREAGĂ. `incidents` e
  // înregistrat la amândouă capetele, cu cursor `(updated_at, id)` la expeditor
  // și upsert la receptor, iar testul „fluxul MUTABIL înregistrat nu pierde o
  // actualizare" îl duce pe drumul complet. Clasa asta nu mai e blocată de nimic.
  //
  // Ce ține garda mai departe, neatins de runda asta:
  //
  //   * #61 — fluxurile cu cheie TEXT (`actors` prin `actor_key`,
  //     `selfcheck_state` prin `check_key`) n-au ce trimite ca filigran, oricât
  //     de mutabile ar fi. Amândouă au primit `updated_at` în `0023`, și tot nu
  //     se pot expedia: protocolul poartă un întreg. `shipper.py` refuză deja
  //     cazul (`ShipEncodingError`), iar regula de aici e refuzul geamăn, ca
  //     înregistrarea să nu treacă de o parte și să moară de cealaltă.
  //   * #62 — REZOLVAT ca mecanism, nu ca înregistrare. Cele cinci tabele de
  //     legătură sunt acum SUB-RÂNDURI ale părintelui: n-au contabilitate proprie
  //     fiindcă n-au sosire proprie, `writeSql` nu le mai emite `received_at` și
  //     `batch_seq`, iar `ingestStream` le scrie, le curăță și le NUMĂRĂ (vezi
  //     `tests/subrows.test.ts`). Ce ține înregistrarea lui `actors` mai departe
  //     e capătul celălalt: expeditorul nu declară încă un flux cu sub-rânduri,
  //     `actor_attrs.value_hash` se calculează la ingestie și nimeni n-a decis
  //     unde, iar plafoanele de sub-rânduri n-au încă perechea lor în
  //     `sentinel/config.py`.
  //
  // Se ridică atunci, nu acum: ridicarea ei e ce permite înregistrarea, iar
  // înregistrarea are nevoie de răspunsurile de mai sus.
  // #61 s-a ÎNCHIS pe 20 august 2026: filigranul nu mai trebuie să fie un
  // întreg. E un jeton de ecou, iar felul lui se declară pe flux
  // (`watermarkKind`), deci un flux cu cheie text — `selfcheck_state`, `actors`,
  // rollup-urile — poate trimite cheia maximă pe octeți.
  //
  // Regula nu s-a slăbit, s-a MUTAT: fiecare flux trebuie să aibă o coloană de
  // filigran de felul pe care îl declară. Un flux întreg fără coloană `id` n-are
  // ce ecoua; unul text al cărui filigran arată spre o coloană numerică ar
  // trimite un întreg pe care receptorul îl refuză ca fel greșit.
  const carrier = stream.columns.find((c) => c.target === stream.watermark);
  assert.ok(carrier,
            `${stream.name}: coloana de filigran "${stream.watermark}" nu e ` +
            "printre coloanele fluxului, deci n-are ce trimite înapoi");
  const wantsText = stream.watermarkKind === "text";
  // A treia formă acceptată, de pe 21 august 2026: un MOMENT purtat ca text.
  //
  // Obiecția din care s-a născut regula rămâne valabilă — două momente scrise cu
  // fusuri diferite sunt egale și sortează diferit, iar atunci ecoul n-ar mai
  // potrivi niciodată. Ce s-a schimbat e că presupunerea a devenit fapt impus,
  // în două locuri: expeditorul scrie fiecare moment cu fus UTC explicit (probat
  // de `tests/unit/test_ship_rollup.py`, „momentele pleacă toate cu același
  // fus"), iar receptorul calculează filigranul din valoarea SOSITĂ, nu din cea
  // convertită — altfel `2026-08-21T13:00:00+00:00` ar deveni
  // `2026-08-21 13:00:00.000000` și ecoul ar cere altceva decât s-a trimis.
  //
  // Cu fus fix și lățime fixă, ordinea pe octeți e chiar cea cronologică.
  const allowed = wantsText ? ["text", "timestamp"] : ["id"];
  assert.ok(allowed.includes(carrier.kind),
            `${stream.name}: filigranul e declarat ${wantsText ? "text" : "întreg"} ` +
            `dar coloana lui e de tip ${carrier.kind}. Cele două capete ar ` +
            "calcula maximul cu ordini diferite, iar ecoul n-ar mai potrivi " +
            "niciodată — pe un lot perfect valid");
}

test("regula de înregistrare se declanșează SINGURĂ, pe fiecare formă greșită", () => {
  // Fiecare caz de aici e o formă care ar trece azi tăcut de tot restul suitei.
  assert.doesNotThrow(() => assertRegistrable(MUTABLE), "un flux valid e refuzat");

  // Un flux cu cheie TEXT e valid de pe 20 august 2026 — dar numai dacă își
  // declară felul. `TEXT_KEYED` fără declarație e chiar greșeala de prins: ar
  // trimite un șir pe care receptorul îl cere întreg.
  assert.throws(() => assertRegistrable(TEXT_KEYED), /coloana lui e de tip text/,
                "un flux cu cheie text și filigran întreg a trecut de regulă");
  assert.doesNotThrow(
    () => assertRegistrable({ ...TEXT_KEYED, watermarkKind: "text" }),
    "un flux cu cheie text care ÎȘI DECLARĂ felul a fost refuzat");

  // Și invers: un flux întreg care se declară text ar calcula maximul cu altă
  // ordine decât receptorul.
  assert.throws(
    () => assertRegistrable({ ...MUTABLE, watermarkKind: "text" }),
    /coloana lui e de tip id/, "un flux întreg declarat text a trecut");

  // Coloana de filigran trebuie să fie printre cele trimise. Fără cazul ăsta,
  // verificarea se putea slăbi la „dacă există" fără ca nimic să pice.
  assert.throws(
    () => assertRegistrable({ ...MUTABLE, watermark: "nu_exista" }),
    /nu e printre coloanele fluxului/, "un filigran fără coloană a trecut");

  assert.throws(
    () => assertRegistrable({ ...MUTABLE, identity: ["source_id"] }),
    /nu începe cu instance_id/, "o cheie fără instanță a trecut");
  // Identitatea GOALĂ, nu doar cea greșită: `identity: []` e ce scrie cineva
  // care completează câmpul ca să treacă de compilator. Fără cazul ăsta,
  // verificarea de mai sus se putea slăbi la „primul element, dacă există"
  // fără ca nimic să pice — măsurat.
  assert.throws(() => assertRegistrable({ ...MUTABLE, identity: [] }),
                /nu începe cu instance_id/, "o identitate goală a trecut");
  assert.throws(
    () => assertRegistrable({ ...MUTABLE, identity: ["instance_id", "fingerprint"] }),
    /fingerprint nu e trimisă de flux/, "o cheie peste o coloană netrimisă a trecut");
});

test("identitatea unui flux e formată din coloane pe care fluxul chiar le scrie", () => {
  // Identitatea nu mai e dedusă, e declarată — deci trebuie să fie declarată
  // COERENT. Două feluri de a greși, amândouă tăcute:
  //
  //   * o cheie care nu începe cu `instance_id` — atunci potrivirea upsertului
  //     traversează instanțe, iar rândul unei mașini îl rescrie pe al alteia;
  //   * o coloană de cheie pe care fluxul n-o trimite — atunci `writeSql` nici
  //     n-o inserează, deci rândul intră cu o cheie pe care nimeni n-a scris-o,
  //     iar excluderea ei din `SET` nu apără nimic.
  //
  // Acordul cu schema e altă întrebare și se pune în `tests/schema.test.ts`;
  // aici se verifică doar că declarația se poate scrie cu coloanele fluxului.
  //
  // Ciocnirea care va veni, scrisă acum ca să nu pară o surpriză: `actor_attrs`
  // are `value_hash` în cheie, iar pe server acela se CALCULEAZĂ la ingestie. Cu
  // regula asta, fluxul nu se poate înregistra fără o decizie explicită despre
  // cum ajunge coloana aia scrisă — și e chiar ce trebuie să se întâmple.
  // Regula e `assertRegistrable`, probată izolat de testul de deasupra. Aici se
  // aplică pe ce e ÎNREGISTRAT: cele două întrebări sunt diferite, iar înainte
  // se putea răspunde doar la a doua.
  const streams = allStreams();
  assert.ok(streams.length >= 1, "nicio înregistrare de flux: bucla ar trece goală");
  for (const stream of streams) assertRegistrable(stream);
});

test("un flux cu LANȚ e append-only, și asta e impus, nu nimerit", () => {
  // Verificarea lanțului deosebește un GOL de o RUPTURĂ folosind
  // `sync_cursors.last_source_id` ca filigran confirmat. Numărul ăla e maximul
  // istoric al filigranelor primite (`GREATEST` în `advanceCursor`), iar pe un
  // flux append-only maximul CHIAR e poziția, fiindcă filigranele cresc.
  //
  // Pe un flux mutabil nu mai e: filigranul e maximul DIN LOT, iar loturile
  // succesive pot scădea. Verigile de sub un maxim istoric prea mare ar fi
  // citite ca „au fost confirmate și au dispărut" — `broken` pe un lanț sănătos.
  //
  // Până acum echivalența era o coincidență: `audit_log` se nimerea append-only.
  // Regula de aici o face constrângere, iar `lib/chain.ts` o verifică și la
  // fiecare citire.
  const chained = allStreams().filter((s) => s.chained);
  assert.ok(chained.length >= 1, "niciun flux cu lanț: regula n-ar atinge nimic");
  for (const stream of chained) {
    assert.equal(stream.cursor, "append-only",
                 `fluxul ${stream.name} poartă un lanț, dar cursorul lui e ` +
                 `${stream.cursor}: filigranul confirmat n-ar mai fi o poziție, ` +
                 "iar verificarea de lanț ar numi ruptură o restanță");
  }
});

test("felurile de cursor sunt EXACT două, ca la expeditor", () => {
  // Un al treilea fel a existat — `rollup` — și nu deosebea nimic: aceeași
  // ramură de scriere, aceeași numărătoare, iar felul nu circulă pe sârmă, deci
  // nimic nu punea vreodată cele două vocabulare față în față. O etichetă care
  // arată ca o gardă e chiar tiparul pe care depozitul ăsta îl plătește.
  //
  // Aserțiunea e pe CONȚINUT: cine adaugă un al treilea fel editează testul, iar
  // aia e declarația că felul cel nou chiar schimbă ceva în ingestie.
  assert.deepEqual([...CURSOR_KINDS], ["append-only", "mutable"],
                   "lista felurilor de cursor s-a schimbat; `CURSOR_KINDS` din " +
                   "`sentinel/report/shipper.py` are tot două, iar un fel în plus " +
                   "aici ar fi o etichetă sau o divergență");
});

test("fiecare flux declară CUM înaintează cursorul lui", () => {
  // Tipul cursorului nu e o etichetă descriptivă: decide FORMA SCRIERII. Un flux
  // `mutable` ingerat cu `INSERT IGNORE` ar păstra tăcut versiunea veche a
  // rândului — un incident închis pe server ar rămâne deschis în panou, iar
  // nimic n-ar spune de ce. Un flux `append-only` ingerat cu
  // `ON DUPLICATE KEY UPDATE` ar muri pe triggerul de append-only la prima
  // retrimitere.
  //
  // Deci un flux fără tip declarat n-are voie să existe: fără el, ingestia ar
  // alege singură, iar alegerea aia se vede abia în date.
  const streams = allStreams();
  assert.ok(streams.length >= 1, "registrul de fluxuri e gol");
  for (const stream of streams) {
    assert.ok(CURSOR_KINDS.includes(stream.cursor),
              `fluxul ${stream.name} declară cursorul „${String(stream.cursor)}”, ` +
              `care nu e unul dintre ${CURSOR_KINDS.join(", ")}`);
  }
  // Fluxul cu lanț de hash-uri e append-only prin construcție: pe el, sursa are
  // un trigger care refuză UPDATE, iar replica la fel.
  for (const stream of streams) {
    if (!stream.chained) continue;
    assert.equal(stream.cursor, "append-only",
                 `${stream.name} poartă un lanț de hash-uri dar e declarat ` +
                 `${stream.cursor}: un rând care se poate schimba nu poate fi înlănțuit`);
  }
});

test("un cursor citit ca NULL e „nu pot citi”, nu „cursorul e la zero”", async () => {
  // Aceeași formă ca la `COUNT`: `Number(null)` e 0, iar 0 e o afirmație —
  // „cursorul e la început" — făcută pe o valoare pe care n-am citit-o.
  // Direcția e sigură oricum (0 e sub filigran, deci nu se ecouă nimic), dar
  // mesajul ar trimite operatorul să caute un cursor căzut la zero în loc de o
  // coloană care nu se poate citi.
  let probed = 0;
  for (const value of [null, "nu-e-număr", {}]) {
    const server = new FakeServer({ cursorValue: value });
    const result = await ingest(server, [auditRow({ id: 55 })]);
    assert.equal(result.ok, false, `last_source_id=${JSON.stringify(value)} a fost acceptat`);
    assert.equal(result.ok === false && result.kind, "unavailable",
                 `last_source_id=${JSON.stringify(value)}`);
    probed++;
  }
  assert.equal(probed, 3, "nu s-au probat toate formele");
});

test("plafonul de corp e DERIVAT din limita de rânduri, nu scris de mână", () => {
  // Argumentul scris în `lib/ingest.ts` e că plafonul de corp rămâne legat de
  // numărul de rânduri, ca să nu devină a treia limită pe care cele două capete
  // o văd diferit.
  //
  // Valoarea singură NU poate apăra asta, și e important de spus de ce: un
  // literal scris de mână care se NIMEREȘTE egal cu produsul de azi trece de
  // orice aserțiune pe valoare, iar legătura e deja ruptă — se vede abia în ziua
  // în care se mișcă limita de rânduri și plafonul de corp rămâne în urmă.
  // Măsurat: cu `MAX_BODY_BYTES = 8_192_000` scris literal, aserțiunea de mai
  // jos pe valoare a rămas verde.
  //
  // Deci se verifică ȘI textul definiției. E o aserțiune pe sursă, adică chiar
  // clasa pe care `CLAUDE.md` o numește slabă — se scrie aici de ce e totuși
  // singura posibilă: „derivat" și „egal din întâmplare" nu au NICIO diferență
  // observabilă la execuție.
  assert.equal(MAX_BODY_BYTES, MAX_ROWS_PER_BATCH * MAX_ROW_BYTES);

  const source = readFileSync(new URL("../lib/ingest.ts", import.meta.url), "utf8");
  const definition = /^export const MAX_BODY_BYTES = (.+);$/m.exec(source);
  assert.ok(definition, "MAX_BODY_BYTES nu mai e o constantă exportată la nivel de modul");
  assert.match(definition[1], /\bMAX_ROWS_PER_BATCH\b/,
               `plafonul de corp nu mai e derivat din limita de rânduri: ${definition[1]}`);

  // Și derivarea trebuie să lase loc unui lot maxim de rânduri realiste: sub
  // câteva sute de octeți pe rând, plafonul ar refuza loturi pe care ambele
  // capete le declară legale.
  assert.ok(MAX_ROW_BYTES >= 1024, `${MAX_ROW_BYTES} octeți pe rând e sub orice rând real`);
});

test("un filigran care nu e cel mai mare id din lot e refuzat", async () => {
  // Mai mare: expeditorul ar trece peste rânduri pe care nu le-a trimis nimeni.
  // Mai mic: ar retrimite la nesfârșit ce e deja aici.
  const server = new FakeServer();
  const rows = [auditRow({ id: 60 }), auditRow({ id: 61 })];
  for (const watermark of [62, 60]) {
    const result = await ingestStream(dbOf(server), INSTANCE, AUDIT, rows, watermark, 1);
    assert.equal(result.ok, false, `filigranul ${watermark} a fost acceptat`);
    assert.equal(result.ok === false && result.kind, "invalid");
  }
  assert.equal(server.countFor(), 0, "s-a scris ceva pe un lot refuzat");
});

test("o bază care aruncă e „nu știu”, nu „lot invalid”", async () => {
  const server = new FakeServer({ failOn: "INSERT IGNORE INTO audit_entries" });
  const result = await ingest(server, [auditRow({ id: 70 })]);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "unavailable");
});

test("un lot mare intră în bucăți, dar rămâne un singur lot", async () => {
  // Bucățile există ca să nu se lovească `max_allowed_packet`. Ce nu au voie să
  // schimbe e verdictul: 2000 de rânduri trimise, 2000 prezente, un filigran.
  const server = new FakeServer();
  const rows = Array.from({ length: 2000 }, (_, i) => auditRow({ id: 1000 + i }));
  const result = await ingest(server, rows);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.ok && result.watermark, 2999);
  assert.equal(server.countFor(), 2000);
  const inserts = server.asked.filter((s) => s.startsWith("INSERT IGNORE INTO audit_entries"));
  assert.ok(inserts.length > 1, "lotul nu a fost împărțit deloc");
});

test("primul scris câștigă: un rând retrimis cu alt conținut nu rescrie arhiva", async () => {
  // `audit_entries` e append-only, impus prin trigger. „Replica își corectează
  // istoria după ce i-o rescrie sursa" ar fi chiar proprietatea pe care
  // agregatorul o are ca să nu o piardă.
  const server = new FakeServer();
  await ingest(server, [auditRow({ id: 80, actor: "primul" })], 1);
  await ingest(server, [auditRow({ id: 80, actor: "al doilea" })], 2);
  assert.equal(server.storedRow(80)?.actor, "primul");
  assert.equal(server.countFor(), 1);
});

// ---------------------------------------------------------------------------
// Fluxul mutabil ÎNREGISTRAT, pe drumul complet
// ---------------------------------------------------------------------------
const INCIDENTS = streamFor("incidents")!;

/** Un incident, cu toate câmpurile pe care le cere fluxul înregistrat. */
function incidentRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 7, fingerprint: "f7", status: "open", severity: "high",
    ai_severity: null, ai_verdict: null, ai_confidence: "0.85", ai_analyzed_at: null,
    title: "acces refuzat repetat", summary: null, actor_key: "203.0.113.10",
    asset_id: 4, detection_count: 3,
    created_at: "2026-08-16T09:00:00.000000+00:00",
    first_detection_at: "2026-08-16T09:00:00.000000+00:00",
    last_detection_at: "2026-08-16T09:05:00.000000+00:00",
    acknowledged_by: null, acknowledged_at: null, resolved_at: null,
    resolution_note: null, notified_at: null, auto_action: null, auto_action_at: null,
    updated_at: "2026-08-16T09:05:00.000000+00:00",
    ...over,
  };
}

test("fluxul MUTABIL înregistrat nu pierde o actualizare, pe drumul complet", async () => {
  // Falsificarea care contează, pe fluxul REAL, nu pe o fixtură: `incidents`,
  // așa cum e declarat la amândouă capetele.
  //
  // Eșecul pe care îl previne, pas cu pas: incidentul se închide pe server,
  // rândul sosește actualizat, se SCRIE, numărătoarea îl GĂSEȘTE (identitatea e
  // acolo, indiferent de versiune), filigranul se ECOUĂ, cursorul AVANSEAZĂ — și
  // versiunea din agregator rămâne cea veche. Panoul arată la nesfârșit un
  // incident deschis care pe server e rezolvat, iar expeditorul nu-l mai
  // retrimite NICIODATĂ, fiindcă un cursor nu se întoarce.
  //
  // Toate cele patru piese trebuie să țină împreună ca proba să treacă: forma de
  // scriere aleasă după felul cursorului, identitatea declarată, numărătoarea pe
  // ea, și ecoul emis abia după numărătoare.
  const server = new FakeServer();
  const opened = await ingestStream(dbOf(server), INSTANCE, INCIDENTS,
                                    [incidentRow()], 7, 1);
  assert.equal(opened.ok, true, JSON.stringify(opened));
  assert.equal(server.storedRow(7, INSTANCE, INCIDENTS.table)?.status, "open");

  const closed = await ingestStream(
    dbOf(server), INSTANCE, INCIDENTS,
    [incidentRow({
      status: "resolved", resolved_at: "2026-08-16T10:00:00.000000+00:00",
      resolution_note: "adresa blocată", auto_action: "block_ip",
      auto_action_at: "2026-08-16T09:06:00.000000+00:00",
      updated_at: "2026-08-16T10:00:00.000000+00:00",
    })], 7, 2);

  assert.equal(closed.ok, true, JSON.stringify(closed));
  assert.equal(closed.ok && closed.watermark, 7, "filigranul ecouat nu e cel trimis");

  const stored = server.storedRow(7, INSTANCE, INCIDENTS.table);
  assert.equal(stored?.status, "resolved",
               "ACTUALIZAREA S-A PIERDUT: agregatorul ține versiunea veche, iar " +
               "expeditorul a primit filigranul ecouat, deci n-o mai retrimite");
  assert.equal(stored?.resolution_note, "adresa blocată");
  assert.equal(stored?.auto_action, "block_ip", "coloana din 0007 nu s-a scris");
  assert.equal(server.tableRows(INCIDENTS.table).size, 1, "s-a adăugat un rând, nu s-a actualizat");
});

test("un incident cu `ai_confidence` stricat e refuzat AICI, cu numele câmpului", async () => {
  // `numeric(3,2)` sosește ca text (`encode_value` îl trece prin `str()`), deci
  // forma se verifică la noi. Lăsat drept `text`, un șir stricat ar fi ajuns
  // într-o coloană `DECIMAL` și ar fi fost refuzat abia de MariaDB — cu un mesaj
  // despre tipuri, la miezul nopții, în loc de unul care numește câmpul.
  const server = new FakeServer();
  const bad = await ingestStream(dbOf(server), INSTANCE, INCIDENTS,
                                 [incidentRow({ ai_confidence: "0,85" })], 7, 1);
  assert.equal(bad.ok, false);
  assert.equal(bad.ok === false && bad.kind, "invalid");
  assert.match((bad as { detail: string }).detail, /ai_confidence: aștept un zecimal canonic/);

  // Iar un număr NU e acceptat: ar însemna că valoarea a trecut printr-un float
  // pe drum, adică tocmai pierderea pe care forma de text o evită.
  const asNumber = await ingestStream(dbOf(server), INSTANCE, INCIDENTS,
                                      [incidentRow({ ai_confidence: 0.85 })], 7, 1);
  assert.equal(asNumber.ok, false);
});

// ---------------------------------------------------------------------------
// `inet`: al DOILEA tip care pleacă drept șir și se validează la sosire
// ---------------------------------------------------------------------------
/**
 * Un flux cu o coloană `inet`, modelat pe `actor_ips` din `0003_entities.sql`
 * (`ip INET6 NOT NULL`).
 *
 * Fabricat aici, ca `MUTABLE`: niciun flux ÎNREGISTRAT nu poartă azi o adresă —
 * `incidents` n-are coloană `inet`, iar `actor_ips` are cheie compusă și nu se
 * poate încă înregistra (#62). Felul de coloană există dinaintea primului flux
 * care îl folosește, din același motiv pentru care exista forma de scriere
 * mutabilă înaintea primului flux mutabil: altfel primul care ajunge acolo
 * descoperă lipsa în producție, iar aici lipsa înseamnă o adresă care nu e
 * adresă scrisă tăcut într-o coloană `INET6`.
 */
const WITH_INET: Stream = {
  name: "actor_ips_probe",
  table: "incident_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "ip", target: "ip", kind: "inet", nullable: false },
  ],
};

test("o adresă IP validă trece, IPv4 și IPv6, în formele pe care le scrie sursa", () => {
  // Contrastul, ca refuzurile de mai jos să însemne ceva: o verificare prea
  // strictă nu se vede ca „valoare refuzată", se vede ca un flux care s-a oprit
  // definitiv pe un rând perfect valid — și nu se poate repara de pe gazdă.
  const accepted = [
    "203.0.113.10", "0.0.0.0", "255.255.255.255",
    "2001:db8::1", "::", "::1", "fe80::1",
    "2001:0db8:0000:0000:0000:0000:0000:0001",
    "2001:db8:0:0:1:0:0:1",
    // IPv4 în coadă: forma pe care o scriu adresele mapate.
    "::ffff:192.0.2.128",
  ];
  for (const value of accepted) {
    const prepared = prepareRows(WITH_INET, [{ id: 1, ip: value }], INSTANCE, 1);
    assert.equal(prepared.ok, true,
                 `${value} a fost refuzată: ${(prepared as { detail?: string }).detail}`);
  }
});

test("ce nu e o adresă e refuzat AICI, cu numele coloanei", () => {
  // Eșecul pe care îl previne: coloana e `INET6`, iar sub `INSERT IGNORE` o
  // valoare care nu e adresă nu se oprește la o eroare pe care s-o citească
  // cineva — ori dispare rândul, ori intră altceva decât s-a trimis. Ambele
  // arată de la expeditor exact la fel: un ecou, sau un non-2xx fără corp citit.
  //
  // A doua oară aceeași formă, după `decimal`: tipul pleacă de pe server ca șir,
  // deci verificarea lui e AICI.
  const refused = [
    ["nu-e-o-adresă", "text oarecare"],
    ["", "șirul gol; „nu se știe” se trimite ca null"],
    [" 203.0.113.10", "spații în jur"],
    ["203.0.113.10 ", "spații în jur"],
    ["203.0.113.256", "octet peste 255"],
    ["203.0.113", "trei octeți"],
    ["203.0.113.10.5", "cinci octeți"],
    ["010.0.0.1", "zerouri în față: opt sau zece, după parser"],
    ["203.0.113.0/24", "prefix: e o plajă, nu o adresă"],
    ["fe80::1%eth0", "zonă: are înțeles doar pe mașina care a scris-o"],
    ["2001:db8::1::2", "două `::`, deci ambiguă"],
    ["1:2:3:4:5:6:7:8:9", "nouă grupuri"],
    ["1:2:3:4:5:6:7", "șapte grupuri fără `::`"],
    ["2001:db8::g", "cifră care nu e hexa"],
    ["12345::1", "grup de cinci cifre"],
    ["::ffff:192.0.2.300", "coadă IPv4 invalidă"],
    [":1:2:3:4:5:6:7", "început cu un singur `:`"],
  ];
  for (const [value, why] of refused) {
    const prepared = prepareRows(WITH_INET, [{ id: 1, ip: value }], INSTANCE, 1);
    assert.equal(prepared.ok, false, `${JSON.stringify(value)} (${why}) a fost acceptată`);
    // Numele coloanei, nu doar refuzul: cine citește un 400 la miezul nopții
    // trebuie să afle CE câmp, nu că „un rând e greșit".
    assert.match((prepared as { detail: string }).detail,
                 /rows\.actor_ips_probe\[0\]\.ip: aștept o adresă IP/,
                 `refuzul lui ${JSON.stringify(value)} nu numește coloana`);
  }

  // Și un NUMĂR nu e o adresă, chiar dacă ar putea fi convertit: conversia ar fi
  // al doilea codificator, pe care celălalt capăt nu-l cunoaște.
  const asNumber = prepareRows(WITH_INET, [{ id: 1, ip: 3405803786 }], INSTANCE, 1);
  assert.equal(asNumber.ok, false);
  assert.match((asNumber as { detail: string }).detail, /am number/);
});

test("`null` într-o coloană `inet` urmează nullable, ca orice alt fel", () => {
  // Fără cazul ăsta, verificarea de formă ar fi putut fi scrisă ÎNAINTEA celei
  // de `null` și ar fi refuzat o coloană care acceptă „nu se știe".
  const notNull = prepareRows(WITH_INET, [{ id: 1, ip: null }], INSTANCE, 1);
  assert.equal(notNull.ok, false);
  assert.match((notNull as { detail: string }).detail, /NULL într-o coloană care nu-l acceptă/);

  const nullable: Stream = {
    ...WITH_INET,
    columns: [WITH_INET.columns[0], { ...WITH_INET.columns[1], nullable: true }],
  };
  assert.equal(prepareRows(nullable, [{ id: 1, ip: null }], INSTANCE, 1).ok, true);
});

// ---------------------------------------------------------------------------
// `bool` și `inet` — cele două feluri pe care `detections` le folosește primul
// ---------------------------------------------------------------------------
function detectionRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 11, ts: "2026-08-20T06:00:00.000000+00:00",
    rule_id: "auth.ssh_bruteforce", rule_family: "auth", severity: "medium",
    score: "3.50", actor_key: "203.0.113.10", asset_id: 4, incident_id: 9,
    src_ip: "203.0.113.10", dst_port: 22, evidence: "{}",
    suppressed: false, suppress_reason: null,
    // Obligatoriu de când fluxul declară un copil: un flux cu sub-rânduri cere
    // FIECĂRUI rând să poarte câmpul, iar un rând fără el e refuzat. Tabloul gol
    // e o valoare validă — o detecție fără dovezi —, absența nu.
    event_ids: [],
    ...over,
  };
}

test("`suppressed` acceptă DOAR adevărat sau fals, niciodată 1 sau «true»",
     async () => {
  // Eșecul pe care îl previne: `Boolean("0")` e ADEVĂRAT în JavaScript, iar
  // coloana e `TINYINT(1)`, pe care MariaDB o umple bucuroasă din orice se
  // poate converti. O detecție suprimată ar ajunge nesuprimată, sau invers, iar
  // pe panou diferența e între „am văzut asta și am hotărât s-o ignor" și „asta
  // e nouă". Nimic nu ar semnala conversia.
  //
  // Expeditorul trimite un boolean adevărat — `encode_value` lasă `bool` să
  // treacă neatins —, deci orice altceva înseamnă o conversie pe drum, iar o
  // conversie pe drum e chiar ce fluxul interzice.
  const stream = streamFor("detections") as Stream;
  const server = new FakeServer();

  const bun = await ingestStream(dbOf(server), INSTANCE, stream,
                                 [detectionRow({ suppressed: true })], 11, 1);
  assert.equal(bun.ok, true, "un boolean adevărat a fost refuzat");

  for (const gresit of [1, 0, "true", "false", "1", null]) {
    const res = await ingestStream(dbOf(new FakeServer()), INSTANCE, stream,
                                   [detectionRow({ suppressed: gresit })], 11, 1);
    assert.equal(res.ok, false,
                 `valoarea ${JSON.stringify(gresit)} a fost acceptată pentru o coloană bool`);
    assert.equal(res.ok === false && res.kind, "invalid");
  }
});

test("`src_ip` cere o adresă canonică, nu orice șir", async () => {
  // Geamăna acestei verificări e ramura pentru adrese din `encode_value`, care
  // trimite exact forma canonică. Dacă unul dintre capete ar accepta forma
  // lungă și celălalt nu, rândul ar fi refuzat abia de MariaDB — cu un mesaj
  // despre tipuri, nu despre câmp.
  const stream = streamFor("detections") as Stream;

  const bun = await ingestStream(dbOf(new FakeServer()), INSTANCE, stream,
                                 [detectionRow({ src_ip: "2001:db8::1" })], 11, 1);
  assert.equal(bun.ok, true, "o adresă IPv6 canonică a fost refuzată");

  const gol = await ingestStream(dbOf(new FakeServer()), INSTANCE, stream,
                                 [detectionRow({ src_ip: null })], 11, 1);
  assert.equal(gol.ok, true, "`src_ip` e nullable la sursă; null trebuie acceptat");

  for (const gresit of ["203.0.113.10/32", "nu-e-adresa", "203.0.113.10 ", 3232235530]) {
    const res = await ingestStream(dbOf(new FakeServer()), INSTANCE, stream,
                                   [detectionRow({ src_ip: gresit })], 11, 1);
    assert.equal(res.ok, false,
                 `valoarea ${JSON.stringify(gresit)} a trecut drept adresă`);
  }
});
