/**
 * Sub-rândurile: tabelele de legătură scrise ca parte a rândului părinte (#62).
 *
 * ## Ce se strică pentru operator dacă mecanismul ăsta greșește
 *
 * Cinci tabele din schemă — `asset_tags`, `actor_ips`, `actor_attrs`,
 * `detection_events`, `patch_plan_findings` — n-au `received_at` și `batch_seq`,
 * fiindcă n-au sosire proprie: sunt tablouri de pe rândul părinte. Trei feluri de
 * a greși, toate cu același rezultat vizibil (niciunul):
 *
 *   1. **coloane emise care nu există** — `Unknown column 'received_at' in 'field
 *      list'`. Fluxul se oprește la primul lot, iar mesajul arată spre o coloană,
 *      nu spre decizia care lipsește. Ăsta era chiar defectul.
 *   2. **contopire în loc de înlocuire** — un IP scos din `member_ips` rămâne pe
 *      veci în `actor_ips`. Panoul arată un actor care folosește o adresă pe care
 *      serverul nu i-o mai atribuie, iar gunoiul nu se mai vizitează niciodată.
 *   3. **copii pierduți tăcut** — `INSERT IGNORE` înghite un sub-rând, ecoul se
 *      emite pe numărătoarea părinților, iar expeditorul trece mai departe.
 *      Cursorul nu se întoarce, deci adresa aia nu mai ajunge NICIODATĂ aici.
 *
 * Regula ecoului se aplică sub-rândurilor la fel ca rândurilor: nu se confirmă
 * nimic decât după ce se NUMĂRĂ ce a aterizat — și, pentru o mulțime, „ce a
 * aterizat" înseamnă două numere, nu unul. Vezi capul lui `lib/ingest.ts`.
 *
 * Fixturile de aici NU sunt înregistrări și nu pretind să fie: niciun flux cu
 * sub-rânduri nu e declarat în `lib/streams.ts`, fiindcă asta cere și capătul
 * celălalt — expeditorul nu trimite încă tablouri.
 *
 * Ce NU mai e un motiv, de la #66: `actor_attrs.value_hash`. „Cine o calculează"
 * s-a decis, și e receptorul, la ingestie, prin `HashedColumn` din
 * `lib/streams.ts` — coloana nu mai ține pe loc nicio înregistrare. Ce se
 * probează mai jos e MECANISMUL, peste tabelele reale din migrațiile livrate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { queryableDb } from "../lib/db";
import {
  MAX_CHILDREN_PER_ROW, MAX_CHILD_ROWS_PER_BATCH,
  childTarget, ingestStream, prepareRows, writeSql,
} from "../lib/ingest";
import { allStreams, linkParentTable, linkTables } from "../lib/streams";
import type { ChildStream, Stream } from "../lib/streams";
import { discover } from "../lib/migrate";
import { FakeServer, INSTANCE } from "./sync-harness";
import type { FakeOptions } from "./sync-harness";
import { cell, columnType, readMultiRowInsert, uniqueKeyColumns } from "./sql-reading";

/**
 * Textul `CREATE TABLE` al unei tabele, din migrațiile LIVRATE.
 *
 * Aceeași citire ca în `tests/schema.test.ts` și în dublu, și dinadins tot pe
 * text: fișierul livrat E sursa, iar ce se compară cu el trebuie citit din el.
 */
function createSqlOf(table: string): string {
  for (const migration of discover()) {
    for (const stmt of migration.statements) {
      if (new RegExp(`^CREATE TABLE ${table}\\b`).test(stmt.sql)) return stmt.sql;
    }
  }
  throw new Error(`nu găsesc tabela ${table} în nicio migrație livrată`);
}

/** Cheia unică a unei tabele, citită din migrațiile LIVRATE. */
function uniqueKeyOf(table: string): string[] {
  return uniqueKeyColumns(createSqlOf(table));
}

function dbOf(server: FakeServer) {
  return queryableDb(server);
}

// ---------------------------------------------------------------------------
// Fixturi, peste tabelele REALE din migrațiile livrate
// ---------------------------------------------------------------------------
/**
 * `assets` cu tablomul lui de etichete.
 *
 * Cel mai simplu caz cu putință: un copil, o singură coloană proprie, iar tabela
 * de legătură e NUMAI identitate — `(instance_id, source_id, tag)` și atât.
 */
const ASSETS: Stream = {
  name: "assets_probe",
  table: "asset_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "name", target: "name", kind: "text", nullable: false, maxBytes: 65_535 },
  ],
  children: [
    {
      source: "tags",
      table: "asset_tags",
      link: [{ child: "source_id", parent: "source_id" }],
      identity: ["instance_id", "source_id", "tag"],
      columns: [
        { source: "tag", target: "tag", kind: "text", nullable: false, maxBytes: 190 },
      ],
    },
  ],
};

/**
 * `actors` cu DOUĂ tablouri: adresele și atributele.
 *
 * Cazul greu, și e cazul real:
 *
 *   * `actor_ips` are o coloană `INET6`, deci sub-rândurile trec prin aceeași
 *     validare de adresă ca rândurile;
 *   * `actor_attrs` are cheie de PATRU coloane — text, ENUM, `BINARY(32)` — plus
 *     o coloană de date (`value`), deci e singurul copil care are ce actualiza;
 *   * filigranul (`event_count`) e în AFARA identității, fiindcă `actor_key` e
 *     text. Fluxul ăsta nu se poate încă înregistra (#61), dar mecanismul de
 *     sub-rânduri nu depinde de asta.
 *
 * `value_hash` NU e o coloană de pe sârmă: e `BINARY(32)`, iar octeții n-au
 * formă de sârmă. Se CALCULEAZĂ aici, din `value`, prin `hashed` (#66) — exact
 * ce scrie `migrations/0003_entities.sql`: „SHA-256 peste value; calculat la
 * ingestie". Declarat `hash`, cum era, cele 64 de caractere ar fi ajuns 64 de
 * octeți într-o coloană de 32: trunchiate tăcut, apoi `incomplete` la nesfârșit
 * fiindcă numărătoarea compară ce s-a stocat cu ce s-a trimis.
 */
const ACTORS: Stream = {
  name: "actors_probe",
  table: "actor_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "actor_key"],
  watermark: "event_count",
  columns: [
    { source: "actor_key", target: "actor_key", kind: "text", nullable: false, maxBytes: 190 },
    { source: "event_count", target: "event_count", kind: "id", nullable: false },
  ],
  children: [
    {
      source: "member_ips",
      table: "actor_ips",
      link: [{ child: "actor_key", parent: "actor_key" }],
      identity: ["instance_id", "actor_key", "ip"],
      columns: [{ source: "ip", target: "ip", kind: "inet", nullable: false }],
    },
    {
      source: "attrs",
      table: "actor_attrs",
      link: [{ child: "actor_key", parent: "actor_key" }],
      identity: ["instance_id", "actor_key", "kind", "value_hash"],
      columns: [
        { source: "kind", target: "kind", kind: "text", nullable: false, maxBytes: 32 },
        { source: "value", target: "value", kind: "text", nullable: false, maxBytes: 65_535 },
      ],
      hashed: [{ target: "value_hash", from: "value", byteLength: 32 }],
    },
  ],
};

const TAGS = (ASSETS.children as ChildStream[])[0];
const IPS = (ACTORS.children as ChildStream[])[0];
const ATTRS = (ACTORS.children as ChildStream[])[1];

/**
 * Un hash de probă în forma pe care o cerea coloana pe vremea când era declarată
 * `hash`: 64 de caractere HEXA, ca ȘIR.
 *
 * Exact valoarea pe care felul `bytes` trebuie s-o refuze: 64 de octeți către o
 * coloană de 32. Nu se calculează nimic din ea — e forma greșită, ținută vie ca
 * refuzul să aibă ce refuza.
 */
function hash(seed: number): string {
  return seed.toString(16).padStart(64, "0");
}

/**
 * Digestul pe care îl AȘTEPTĂM de la receptor, calculat independent de el.
 *
 * Rețeta se rescrie aici, nu se importă din `lib/`: un test care ar chema
 * aceeași funcție ca implementarea ar fi verde și dacă amândouă hash-uiesc
 * altceva. Ce se probează e chiar rețeta — SHA-256 peste octeții UTF-8 ai lui
 * `value`, fără nicio normalizare.
 */
function expectedDigest(value: string): string {
  return createHash("sha256").update(Buffer.from(value, "utf8")).digest("hex");
}

function assetRow(id: number, tags: string[], name = "vhost"): Record<string, unknown> {
  return { id, name, tags: tags.map((tag) => ({ tag })) };
}

/**
 * Un rând de actor. Atributele poartă DOAR `kind` și `value`.
 *
 * `value_hash` lipsește dinadins: nu e un câmp de pe sârmă, iar un element care
 * l-ar purta e refuzat ca necunoscut (probat mai jos). Cine adaugă aici un
 * `value_hash` „ca să fie" rupe fix proprietatea pentru care există #66.
 */
function actorRow(
  key: string, ips: string[], attrs: { kind: string; value: string }[] = [],
  eventCount = 10,
): Record<string, unknown> {
  return {
    actor_key: key,
    event_count: eventCount,
    member_ips: ips.map((ip) => ({ ip })),
    attrs: attrs.map((a) => ({ kind: a.kind, value: a.value })),
  };
}

/** Ce e CHIAR ACUM într-o tabelă de legătură, ca mulțime de valori. */
function storedValues(server: FakeServer, table: string, column: string): string[] {
  return [...server.tableRows(table).values()].map((row) => cell(row[column])).sort();
}

/** Octeții unei coloane binare, în hexa, ca să se poată compara și tipări. */
function storedDigest(server: FakeServer, table: string, column: string): string[] {
  return [...server.tableRows(table).values()].map((row) => {
    const value = row[column];
    assert.ok(Buffer.isBuffer(value),
              `${table}.${column} nu s-a scris ca octeți, ci ca ${typeof value}: ` +
              `${String(value)}. Într-o coloană BINARY(32) un ȘIR de 64 de ` +
              "caractere se trunchiază tăcut");
    return (value as Buffer).toString("hex");
  }).sort();
}

// ---------------------------------------------------------------------------
// Drumul complet
// ---------------------------------------------------------------------------
test("părintele și sub-rândurile lui aterizează din aceeași sosire", async () => {
  // Eșecul pe care îl previne: fluxul nu pleacă deloc. `writeSql` emitea
  // `received_at` și `batch_seq` pentru orice tabelă, iar cele de legătură nu le
  // au — deci primul lot murea cu „Unknown column 'received_at' in 'field list'",
  // un mesaj care arată spre o coloană în loc de spre decizia care lipsea.
  const server = new FakeServer();
  const result = await ingestStream(
    dbOf(server), INSTANCE, ASSETS,
    [assetRow(5, ["prod", "web"]), assetRow(9, ["staging"])], 9, 1);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.ok && result.watermark, 9);
  assert.equal(server.tableRows("asset_entries").size, 2, "părinții nu sunt acolo");
  assert.deepEqual(storedValues(server, "asset_tags", "tag"), ["prod", "staging", "web"]);
});

test("tabela de legătură primește EXACT coloanele pe care le are", async () => {
  // Aserțiunea pe instrucțiune, în plus față de efect: dublul refuză deja o
  // coloană inexistentă, dar refuzul ăla ar putea fi îndepărtat de cineva care
  // „repară" un test. Ce se cere aici e forma pozitivă — contabilitatea sosirii
  // NU apare, fiindcă un sub-rând nu are sosire proprie.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ASSETS, [assetRow(5, ["prod"])], 5, 1);

  const written = server.asked.filter((s) => s.includes("INTO asset_tags"));
  assert.equal(written.length, 1, `instrucțiuni pentru asset_tags: ${written.length}`);
  const parsed = readMultiRowInsert(written[0], [INSTANCE, 5, "prod"]);
  assert.deepEqual(parsed.columns, ["instance_id", "source_id", "tag"]);
  for (const forbidden of ["received_at", "batch_seq"]) {
    assert.ok(!parsed.columns.includes(forbidden),
              `${forbidden} emis într-o tabelă care nu-l are`);
  }
  // Iar rândul PĂRINTE le are, altfel aserțiunea de deasupra ar fi verde și pe o
  // implementare care a încetat să le mai scrie nicăieri.
  const parent = server.asked.filter((s) => s.includes("INTO asset_entries"));
  assert.equal(parent.length, 1);
  assert.ok(parent[0].includes("received_at") && parent[0].includes("batch_seq"),
            `rândul părinte a rămas fără contabilitatea sosirii: ${parent[0]}`);
});

test("un sub-rând care e NUMAI identitate se scrie cu INSERT IGNORE", () => {
  // `ON DUPLICATE KEY UPDATE` cu clauza goală nu e SQL valid, iar `asset_tags`
  // n-are nicio coloană în afara cheii. Forma se alege din ce ARE de actualizat,
  // nu din felul cursorului părintelui — altfel un părinte mutabil ar produce o
  // instrucțiune pe care serverul o respinge, la fiecare lot.
  const tags = writeSql(childTarget(TAGS), 1);
  assert.ok(tags.startsWith("INSERT IGNORE INTO asset_tags "), tags);
  assert.ok(!tags.includes("ON DUPLICATE KEY UPDATE"), tags);

  // Iar copilul care ARE o coloană de date o actualizează.
  const attrs = writeSql(childTarget(ATTRS), 1);
  assert.ok(attrs.includes("ON DUPLICATE KEY UPDATE value = VALUES(value)"), attrs);
});

test("o cheie compusă de text, ENUM și BINARY rămâne în afara lui SET", () => {
  // `actor_attrs` e identificată de `(instance_id, actor_key, kind, value_hash)`,
  // iar niciuna dintre cele trei nu e un `id`. O deducție „instance_id + coloana
  // cu kind id" ar fi pus toate trei în `SET` — pe MariaDB nu corupe date, dar
  // face invariantul declarat tăcut fals.
  const sql = writeSql(childTarget(ATTRS), 1);
  // Parametrii în ORDINEA coloanelor emise: legătura, coloanele sosite, apoi
  // cele CALCULATE. Digestul e ultimul fiindcă `childTarget` îl pune ultimul.
  const params = [INSTANCE, "cluster:ab", "country", "RO", Buffer.alloc(32, 7)];
  const updates = new Set(readMultiRowInsert(sql, params).updates.map(([column]) => column));
  for (const key of ATTRS.identity) {
    assert.ok(!updates.has(key), `${key} e coloană de cheie și a ajuns în SET`);
  }
  assert.deepEqual([...updates], ["value"], "coloana de date a rămas fără actualizare");
  assert.equal(ATTRS.identity.length, 4);
});

// ---------------------------------------------------------------------------
// Înlocuire, nu contopire — dovedit prin ce e în tabelă
// ---------------------------------------------------------------------------
test("un actor care pierde un IP chiar nu-l mai are la receptor", async () => {
  // EȘECUL CENTRAL al lui #62 pe partea de date. Cu un upsert simplu pe copii,
  // mulțimile se CONTOPESC: `203.0.113.10` scos din `member_ips` pe server rămâne
  // în `actor_ips` pentru totdeauna, fiindcă nimic nu-l mai vizitează. Panoul ar
  // arăta un actor care folosește o adresă pe care serverul nu i-o mai atribuie,
  // iar operatorul ar bloca sau ar căuta pe baza ei.
  //
  // Proba e prin EFECT — ce e în tabelă —, nu prin forma instrucțiunii emise: un
  // `DELETE` corect scris care nu potrivește nimic arată identic în text.
  const server = new FakeServer();
  const first = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:ab", ["203.0.113.10", "203.0.113.11"])], 10, 1);
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["203.0.113.10", "203.0.113.11"]);

  const second = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:ab", ["203.0.113.11", "203.0.113.12"], [], 20)], 20, 2);

  assert.equal(second.ok, true, JSON.stringify(second));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["203.0.113.11", "203.0.113.12"],
                   "mulțimile s-au CONTOPIT: adresa scoasă e încă la receptor");
});

test("un actor care rămâne fără nicio adresă chiar rămâne fără ele", async () => {
  // Tabloul GOL e o mulțime, nu o lipsă de informație. Tratat ca „n-am ce scrie",
  // ultimele adrese ale unui actor ar rămâne acolo pentru totdeauna — cazul în
  // care contopirea e cea mai vizibilă, fiindcă serverul spune explicit „niciuna".
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);
  assert.equal(server.tableRows("actor_ips").size, 1);

  const emptied = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                     [actorRow("cluster:ab", [], [], 20)], 20, 2);
  assert.equal(emptied.ok, true, JSON.stringify(emptied));
  assert.equal(server.tableRows("actor_ips").size, 0,
               "actorul a rămas cu adrese pe care serverul nu i le mai atribuie");
  // Și părintele e tot acolo: s-au șters copiii, nu rândul.
  assert.equal(server.tableRows("actor_entries").size, 1);
});

test("curățarea atinge DOAR părinții din lot", async () => {
  // Un `DELETE` fără filtrul de părinte — sau cu unul prea larg — ar șterge
  // adresele altor actori la fiecare lot. Rândurile alea n-ar fi retrimise
  // niciodată: cursorul lor a trecut deja peste ele.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"]),
                      actorRow("cluster:cd", ["198.51.100.7"])], 10, 1);
  assert.equal(server.tableRows("actor_ips").size, 2);

  const only = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                  [actorRow("cluster:ab", ["203.0.113.99"], [], 20)], 20, 2);
  assert.equal(only.ok, true, JSON.stringify(only));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["198.51.100.7", "203.0.113.99"],
                   "curățarea a atins un actor care nu era în lot");
});

test("curățarea nu iese din instanță", async () => {
  // `source_id` și `actor_key` sunt unice DOAR în cadrul unei instanțe. Un
  // `DELETE` fără `instance_id = ?` ar șterge etichetele activului 5 al altui
  // server la fiecare lot al nostru — pierdere tăcută, pe o mașină care n-a
  // trimis nimic.
  const server = new FakeServer();
  server.tableRows("asset_tags").set("aaaa1111|5|prod",
                                     { instance_id: "aaaa1111", source_id: 5, tag: "prod" });

  const result = await ingestStream(dbOf(server), INSTANCE, ASSETS,
                                    [assetRow(5, ["web"])], 5, 1);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.ok(server.tableRows("asset_tags").has("aaaa1111|5|prod"),
            "eticheta altei instanțe a fost ștearsă");
  assert.equal(server.tableRows("asset_tags").size, 2);
});

// ---------------------------------------------------------------------------
// Regula ecoului, aplicată sub-rândurilor
// ---------------------------------------------------------------------------
test("un sub-rând înghițit tăcut NU produce filigran ecouat", async () => {
  // Regula ecoului, la sub-rânduri. `INSERT IGNORE` nu aruncă atunci când un rând
  // e respins din alt motiv decât cheia duplicată — un șir prea lung, o conversie
  // de set de caractere. Numărată doar pe părinți, mulțimea incompletă arată
  // identic cu una completă: expeditorul primește ecoul, avansează cursorul, iar
  // adresa aia nu mai ajunge NICIODATĂ aici.
  const server = new FakeServer({ swallowWhere: (row) => row.ip === "203.0.113.11" });
  const result = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:ab", ["203.0.113.10", "203.0.113.11"])], 10, 1);

  assert.equal(result.ok, false, "un lot cu un sub-rând lipsă a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail,
               /am trimis 2 sub-rânduri, în actor_ips sunt 1/);
  // Și cursorul NU s-a mișcat.
  assert.equal(server.cursors.get(`${INSTANCE}|actors_probe`), undefined);
});

test("o curățare care nu se face NU produce filigran ecouat", async () => {
  // Cealaltă jumătate a dovezii, și cea pe care prezența nu o poate da: toate
  // sub-rândurile TRIMISE sunt acolo, dar sub părinte a mai rămas unul vechi.
  // Numărând doar prezența, lotul ar ieși complet, filigranul s-ar ecoua, iar
  // adresa scoasă ar rămâne la receptor pentru totdeauna — contopirea raportată
  // ca succes.
  //
  // `skipDelete` e forma pe care o ia un `DELETE` scos din cod sau un predicat
  // care nu potrivește nimic: nicio eroare, nicio urmă.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);

  const merging = new FakeServer({ skipDelete: true });
  await ingestStream(dbOf(merging), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);
  const result = await ingestStream(dbOf(merging), INSTANCE, ACTORS,
                                    [actorRow("cluster:ab", ["203.0.113.11"], [], 20)], 20, 2);

  assert.equal(result.ok, false, "o mulțime contopită a fost confirmată");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail,
               /sub părinții din lot sunt 2 sub-rânduri în actor_ips, iar lotul a trimis 1/);
  // Iar cu ștergerea la locul ei, ACELAȘI lot trece — altfel proba de mai sus ar
  // fi verde și pe o implementare care refuză orice.
  const healthy = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                     [actorRow("cluster:ab", ["203.0.113.11"], [], 20)], 20, 2);
  assert.equal(healthy.ok, true, JSON.stringify(healthy));
});

// ---------------------------------------------------------------------------
// Cele TREI ferestre de eșec CU EXCEPȚIE ale scrierii
//
// Aici se injectează `failOn`, adică o instrucțiune care ARUNCĂ. Fereastra a
// patra — respingerea TĂCUTĂ, în care nu aruncă nimeni — e mai jos, cu
// `swallowWhere`, fiindcă ordinea singură n-o închide.
// ---------------------------------------------------------------------------
/**
 * Sub-rândurile atârnate de un părinte care NU e în tabela lui.
 *
 * Starea asta nu se vede din niciun verdict și din nicio numărătoare a lotului:
 * un copil orfan nu e sub niciun părinte din vreun lot, deci nici curățarea, nici
 * cele două numărători nu ajung vreodată la el. Se citește direct din depozit,
 * fiindcă e singurul loc unde există.
 */
function orphanChildren(server: FakeServer, parentTable: string, child: ChildStream): string[] {
  const parentKey = (row: Record<string, unknown>, side: "child" | "parent") =>
    JSON.stringify([String(row.instance_id),
                    ...child.link.map((link) => String(row[link[side]]))]);
  const present = new Set([...server.tableRows(parentTable).values()]
    .map((row) => parentKey(row, "parent")));
  return [...server.tableRows(child.table).values()]
    .filter((row) => !present.has(parentKey(row, "child")))
    .map((row) => child.identity.slice(1).map((column) => String(row[column])).join("|"))
    .sort();
}

test("o cădere ÎNAINTE de părinte nu lasă sub-rânduri atârnate de nimic", async () => {
  // FEREASTRA 1: scrierea părintelui aruncă. E fereastra pentru care ordinea
  // celor trei pași a fost INVERSATĂ (părintele înaintea copiilor), și singura
  // care nu se repară singură dacă e greșită.
  //
  // Cu copiii primii, aici rămâneau două rânduri în `actor_ips` sub
  // `cluster:nou`, un actor care nu există în replică. Nu e o mulțime învechită —
  // sursa n-a avut niciodată starea asta —, iar singurul `DELETE` din agregator
  // se face pe părinții DINTR-UN LOT, deci nimic nu le mai vizitează niciodată.
  // Dacă rândul dispare de la sursă înainte ca o reluare să treacă (expeditorul
  // recitește pe cursor, nu retrimite un lot memorat), rămân acolo definitiv.
  const broken = new FakeServer({ failOn: "INSERT INTO actor_entries" });
  const result = await ingestStream(
    dbOf(broken), INSTANCE, ACTORS,
    [actorRow("cluster:nou", ["203.0.113.10", "203.0.113.11"])], 10, 1);

  assert.equal(result.ok, false, "un lot care a picat pe părinte a fost confirmat");
  assert.equal(result.ok === false && result.kind, "unavailable");
  assert.deepEqual(orphanChildren(broken, "actor_entries", IPS), [],
                   "sub-rânduri atârnate de un părinte care nu e în replică");
  assert.equal(broken.tableRows("actor_ips").size, 0,
               "s-au scris copii deși părintele nu a intrat");
  assert.equal(broken.cursors.get(`${INSTANCE}|actors_probe`), undefined);
});

test("o cădere pe copii lasă un părinte ANCORAT, pe care reluarea îl repară", async () => {
  // FEREASTRA 2: părintele a intrat, scrierea copiilor aruncă. Asta e ce
  // PLĂTEȘTE ordinea, și se scrie aici ca să nu fie o surpriză: un părinte NOU
  // rămâne cu mulțimea goală, iar un actor fără adrese arată exact ca un actor
  // care n-are adrese.
  //
  // Ce face starea asta acceptabilă nu e că ar fi mai puțin falsă, ci că e
  // ANCORATĂ: părintele EXISTĂ, filigranul nu s-a ecouat, cursorul n-a avansat,
  // deci lotul se retrimite și îl vizitează din nou. Proba e chiar reluarea —
  // fără ea, „se repară singur" ar fi o intenție, nu un fapt.
  const opts: FakeOptions = { failOn: "INSERT IGNORE INTO actor_ips" };
  const server = new FakeServer(opts);
  const failed = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:nou", ["203.0.113.10", "203.0.113.11"])], 10, 1);

  assert.equal(failed.ok, false);
  assert.equal(failed.ok === false && failed.kind, "unavailable");
  assert.equal(server.tableRows("actor_entries").size, 1, "părintele nu a intrat");
  assert.equal(server.tableRows("actor_ips").size, 0);
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), []);

  // Defectul dispare (o bucată prea mare, o pană de rețea), iar expeditorul
  // retrimite ACELAȘI lot, fiindcă n-a primit ecoul.
  opts.failOn = undefined;
  const again = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:nou", ["203.0.113.10", "203.0.113.11"])], 10, 1);
  assert.equal(again.ok, true, JSON.stringify(again));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["203.0.113.10", "203.0.113.11"],
                   "reluarea nu a pus mulțimea la loc: părintele NU era ancorat");
});

test("o cădere pe copii lasă mulțimea VECHE a unui părinte care era deja acolo", async () => {
  // Aceeași fereastră, pe un părinte EXISTENT: scrierea e aditivă, ștergerea vine
  // după ea, deci ce era rămâne. Ordinea „evidentă" — ștergi întâi, apoi inserezi
  // — ar fi lăsat aici zero adrese, adică o afirmație falsă în locul uneia
  // învechite, și de-aia curățarea e ultima.
  const opts: FakeOptions = {};
  const server = new FakeServer(opts);
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);
  assert.deepEqual(storedValues(server, "actor_ips", "ip"), ["203.0.113.10"]);

  opts.failOn = "INSERT IGNORE INTO actor_ips";
  const result = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                    [actorRow("cluster:ab", ["203.0.113.11"], [], 20)], 20, 2);
  assert.equal(result.ok, false, "un lot care a picat la mijloc a fost confirmat");
  assert.equal(result.ok === false && result.kind, "unavailable");
  assert.deepEqual(storedValues(server, "actor_ips", "ip"), ["203.0.113.10"],
                   "actorul a rămas FĂRĂ adrese: ștergerea s-a făcut înaintea scrierii");
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), []);
});

test("o cădere pe CURĂȚARE lasă o supramulțime, iar reluarea o taie", async () => {
  // FEREASTRA 3: părintele și copiii au intrat, `DELETE`-ul aruncă. Aici — și
  // numai aici — chiar rămâne o SUPRAMULȚIME: adresa veche plus cea nouă, sub un
  // părinte care există. Numărătoarea „câte sunt sub părinții ăștia" o vede, deci
  // nu se ecouă nimic, iar reluarea taie ce a rămas.
  const opts: FakeOptions = {};
  const server = new FakeServer(opts);
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);

  opts.failOn = "DELETE FROM actor_ips";
  const result = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                    [actorRow("cluster:ab", ["203.0.113.11"], [], 20)], 20, 2);
  assert.equal(result.ok, false, "un lot cu curățarea nefăcută a fost confirmat");
  assert.equal(result.ok === false && result.kind, "unavailable");
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["203.0.113.10", "203.0.113.11"],
                   "curățarea a picat, dar mulțimea nu e supramulțimea celor două");
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), []);

  opts.failOn = undefined;
  const again = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                   [actorRow("cluster:ab", ["203.0.113.11"], [], 20)], 20, 2);
  assert.equal(again.ok, true, JSON.stringify(again));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"), ["203.0.113.11"],
                   "reluarea nu a curățat adresa veche");
});

test("ordinea celor trei SCRIERI e cea declarată: părintele, copiii, curățarea", async () => {
  // Ordinea ține locul tranzacției pe care `Db` n-o are: `Db` are două metode,
  // `all` și `run`, iar conexiunea vine din pool, deci un `BEGIN`/`COMMIT` s-ar
  // deschide pe o conexiune și ar scrie pe alta.
  //
  // Aserțiunea e pe instrucțiunile TRIMISE, în plus față de probele de efect de
  // mai sus: ele arată ce rămâne după fiecare fereastră, asta arată că ferestrele
  // sunt chiar alea trei, în ordinea asta.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);

  const order = server.asked
    .filter((s) => /^(INSERT (IGNORE )?INTO (actor_ips|actor_entries)|DELETE FROM actor_ips)/
      .test(s))
    .map((s) => s.startsWith("DELETE") ? "sterge"
      : s.includes("actor_ips") ? "copii" : "parinte");
  assert.deepEqual(order, ["parinte", "copii", "sterge"], order.join(" → "));
});

test("numărătoarea părinților se face ÎNAINTE de prima scriere de sub-rânduri", async () => {
  // Cealaltă jumătate a ordinii, și cea pe care aserțiunea de deasupra n-o poate
  // da: nu doar CINE se scrie primul, ci UNDE se numără. Numărătoarea părinților
  // e singurul lucru care vede o respingere TĂCUTĂ, iar dacă rulează după copii,
  // îi descoperă când sunt deja pe disc (vezi testele de mai jos).
  //
  // Aserțiunea e pe poziția instrucțiunii, nu pe efect, fiindcă pe un lot SĂNĂTOS
  // rezultatul e același oriunde ar sta numărătoarea — exact motivul pentru care
  // greșeala a putut trece.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);

  const steps = server.asked
    .filter((s) => /^(INSERT (IGNORE )?INTO (actor_ips|actor_entries)|DELETE FROM actor_ips|SELECT COUNT\(\*\) AS n FROM actor_entries)/
      .test(s))
    .map((s) => s.startsWith("SELECT") ? "numara-parinti"
      : s.startsWith("DELETE") ? "sterge"
      : s.includes("actor_ips") ? "copii" : "parinte");
  // Prima numărătoare e cea de dinaintea scrierii (`before`); a doua e dovada.
  assert.deepEqual(steps,
                   ["numara-parinti", "parinte", "numara-parinti", "copii", "sterge"],
                   steps.join(" → "));
});

// ---------------------------------------------------------------------------
// Respingerea TĂCUTĂ a unui părinte — fereastra pe care ORDINEA n-o închide
// ---------------------------------------------------------------------------
test("un părinte înghițit tăcut nu lasă niciun sub-rând scris sub el", async () => {
  // Fereastra pe care ordinea pașilor NU o acoperă, fiindcă ordinea
  // oprește doar căderile cu EXCEPȚIE. `INSERT IGNORE` — și un upsert care cade
  // pe un CHECK — nu aruncă atunci când rândul e respins din alt motiv decât
  // cheia duplicată: nicio eroare, niciun rând. Pasul copiilor pornește liniștit,
  // fiindcă n-a aruncat nimeni.
  //
  // Ce vede operatorul dacă asta trece: în ziua în care se înregistrează
  // `actors`, `actor_ips` capătă rânduri sub un `actor_key` care nu există în
  // replică. Singurul `DELETE` din tot agregatorul curăță pe părinții DINTR-UN
  // LOT, deci copiii unui părinte care n-a aterizat niciodată sunt în afara razei
  // oricărei curățări, acum și pe viitor. Nu se vede din niciun verdict, din
  // nicio numărătoare de lot și din niciun panou — un actor inexistent nu se
  // desenează nicăieri.
  //
  // Verdictul era corect și fără reparație (numărătoarea de la capăt prinde
  // părintele lipsă), iar filigranul NU se ecoua — dar orfanii erau deja pe disc
  // când îi descoperea. De-aia proba se uită în DEPOZIT, nu în verdict.
  const server = new FakeServer({ swallowWhere: (row) => row.event_count !== undefined });
  const result = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:nou", ["203.0.113.10", "203.0.113.11"])], 10, 1);

  assert.equal(result.ok, false, "un lot cu părintele lipsă a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail,
               /am trimis 1 rânduri, în tabelă sunt 0/);
  assert.equal(server.tableRows("actor_entries").size, 0, "părintele a aterizat totuși");
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), [],
                   "sub-rânduri atârnate de un părinte care nu e în replică");
  assert.equal(server.tableRows("actor_ips").size, 0,
               "s-au scris copii sub un părinte care nu e în replică");
  assert.equal(server.cursors.get(`${INSTANCE}|actors_probe`), undefined);
});

test("un părinte înghițit dintre mai mulți nu-i ia pe ceilalți cu el, dar oprește lotul", async () => {
  // A doua formă a aceleiași respingeri tăcute, și cea care ascunde orfanul cel
  // mai bine: lotul NU e refuzat pe de-a-ntregul — un părinte chiar aterizează,
  // cu mulțimea lui corectă —, iar rândurile atârnate de celălalt stau lângă
  // rânduri perfect legitime, în aceeași tabelă.
  //
  // Ce plătește oprirea, spus pe față: `cluster:ab` rămâne cu mulțimea VECHE,
  // deși lotul îi trimitea una nouă. E o afirmație învechită, dar ANCORATĂ —
  // părintele există, filigranul nu s-a ecouat, cursorul n-a avansat, deci
  // reluarea o pune la loc. Proba e chiar reluarea, la sfârșit; fără ea „se
  // repară singur" ar fi o intenție, nu un fapt.
  const opts: FakeOptions = {};
  const server = new FakeServer(opts);
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);
  assert.deepEqual(storedValues(server, "actor_ips", "ip"), ["203.0.113.10"]);

  // Numai rândul PĂRINTE al lui `cluster:nou`: sub-rândurile lui trec, exact ca
  // pe un server care a respins tăcut un singur rând.
  opts.swallowWhere = (row) => row.actor_key === "cluster:nou" && row.event_count !== undefined;
  const batch = [actorRow("cluster:ab", ["203.0.113.20"], [], 20),
                 actorRow("cluster:nou", ["198.51.100.5"], [], 21)];
  const result = await ingestStream(dbOf(server), INSTANCE, ACTORS, batch, 21, 2);

  assert.equal(result.ok, false, "un lot cu un părinte lipsă a fost confirmat");
  assert.equal(result.ok === false && result.kind, "incomplete");
  assert.match((result as { detail: string }).detail,
               /am trimis 2 rânduri, în tabelă sunt 1/);
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), [],
                   "sub-rânduri atârnate de un părinte care nu e în replică");
  assert.deepEqual(storedValues(server, "actor_ips", "ip"), ["203.0.113.10"],
                   "s-au scris sau s-au șters sub-rânduri pentru un lot deja refuzat");
  // Cursorul a rămas la filigranul primului lot: al doilea nu s-a ecouat.
  assert.equal(server.cursors.get(`${INSTANCE}|actors_probe`)?.last_source_id, 10);

  // Respingerea încetează (o migrație ajunsă, o coloană lărgită), iar expeditorul
  // retrimite ACELAȘI lot, fiindcă n-a primit ecoul.
  opts.swallowWhere = undefined;
  const again = await ingestStream(dbOf(server), INSTANCE, ACTORS, batch, 21, 2);
  assert.equal(again.ok, true, JSON.stringify(again));
  assert.deepEqual(storedValues(server, "actor_ips", "ip"),
                   ["198.51.100.5", "203.0.113.20"],
                   "reluarea nu a pus mulțimile la loc");
  assert.deepEqual(orphanChildren(server, "actor_entries", IPS), []);
});

test("dacă sub-rândurile nu se pot număra, nu se confirmă nimic", async () => {
  // „Nu pot număra" și „lipsesc rânduri" opresc amândouă, dar operatorul trebuie
  // să știe pe care o are. Fără ramura asta, o bază care nu răspunde ar fi citită
  // ca un lot stricat, iar expeditorul ar fi învinuit pentru o pană de bază.
  const server = new FakeServer({ blindCount: true });
  const result = await ingestStream(dbOf(server), INSTANCE, ASSETS,
                                    [assetRow(5, ["prod"])], 5, 1);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "unavailable");
});

// ---------------------------------------------------------------------------
// Loturi malformate: părinte fără copii, copii fără părinte
// ---------------------------------------------------------------------------
test("un părinte care nu-și trimite tabloul e REFUZAT, cu numele câmpului", () => {
  // Câmpul ABSENT și tabloul GOL sunt lucruri diferite, iar confundate ar produce
  // exact ștergerea greșită: „nu ți-am spus ce etichete are" citit ca „n-are
  // niciuna" ar șterge etichetele activului la fiecare lot al unui expeditor
  // vechi, care nu trimite încă tablouri.
  const row = assetRow(5, []);
  delete row.tags;
  const missing = prepareRows(ASSETS, [row], INSTANCE, 1);
  assert.equal(missing.ok, false);
  assert.match((missing as { detail: string }).detail, /lipsește câmpul "tags"/);

  // Iar tabloul gol trece, și e o mulțime: zero sub-rânduri, un grup de părinte.
  const empty = prepareRows(ASSETS, [assetRow(5, [])], INSTANCE, 1);
  assert.ok(empty.ok, (empty as { detail?: string }).detail);
  assert.equal(empty.children.length, 1);
  assert.equal(empty.children[0].identities.length, 0);
  assert.equal(empty.children[0].groups.length, 1, "părintele fără copii n-a lăsat niciun grup");
});

test("un sub-rând nu-și poate aduce singur părintele", () => {
  // Legătura vine din LOCUL în care stă sub-rândul, nu dintr-un câmp pe care îl
  // poartă. Un copil care și-ar numi părintele l-ar putea numi greșit, iar
  // rezultatul — eticheta activului 5 atârnată de activul 9 — nu se vede de
  // nicăieri: rândul e prezent, numărătoarea iese, ecoul se emite.
  const orphan = prepareRows(
    ASSETS, [{ id: 5, name: "vhost", tags: [{ source_id: 9, tag: "prod" }] }], INSTANCE, 1);
  assert.equal(orphan.ok, false);
  assert.match((orphan as { detail: string }).detail,
               /rows\.assets_probe\[0\]\.tags\[0\]: câmpul necunoscut "source_id"/);
});

test("un tablou trimis unui flux fără copii e câmp NECUNOSCUT, nu gunoi aruncat", () => {
  // Cealaltă direcție a aceleiași greșeli: sursa a crescut un tablou pe care
  // replica nu-l desfășoară nicăieri. Ignorat, s-ar pierde DEFINITIV — cursorul
  // trece peste rând, iar rândul nu se mai retrimite. Refuzul ține fluxul pe loc,
  // vizibil în `ship:lag`, până când agregatorul primește migrația.
  const childless: Stream = { ...ASSETS, children: undefined };
  const result = prepareRows(childless, [assetRow(5, ["prod"])], INSTANCE, 1);
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /câmpul necunoscut "tags"/);
});

test("un tablou care nu e tablou e refuzat cu numele câmpului", () => {
  for (const bad of [{ tag: "prod" }, "prod", 5, null]) {
    const result = prepareRows(
      ASSETS, [{ id: 5, name: "vhost", tags: bad }], INSTANCE, 1);
    assert.equal(result.ok, false, `tags=${JSON.stringify(bad)} a fost acceptat`);
    assert.match((result as { detail: string }).detail, /\.tags: aștept un tablou/);
  }
  // Și un element care nu e obiect: sub-rândurile sunt obiecte, fiindcă
  // `actor_attrs` are nevoie de două câmpuri per element.
  const scalar = prepareRows(ASSETS, [{ id: 5, name: "vhost", tags: ["prod"] }], INSTANCE, 1);
  assert.equal(scalar.ok, false);
  assert.match((scalar as { detail: string }).detail, /tags\[0\]: aștept un obiect/);
});

test("același sub-rând de două ori în același lot e o eroare", () => {
  // `INSERT IGNORE` l-ar păstra pe primul și l-ar arunca pe al doilea, iar
  // numărătoarea ar ieși corectă — un sub-rând pierdut cu filigranul ecouat.
  const result = prepareRows(
    ASSETS, [{ id: 5, name: "vhost", tags: [{ tag: "prod" }, { tag: "prod" }] }], INSTANCE, 1);
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /sub-rândul \(5, prod\) apare de două ori/);

  // Aceeași etichetă pe DOI părinți nu e un duplicat: identitatea conține
  // legătura. Fără cazul ăsta, dedublarea s-ar fi putut scrie pe eticheta
  // singură, iar un lot perfect valid ar fi fost refuzat.
  const twoParents = prepareRows(
    ASSETS, [assetRow(5, ["prod"]), assetRow(9, ["prod"])], INSTANCE, 1);
  assert.ok(twoParents.ok, (twoParents as { detail?: string }).detail);
  assert.equal(twoParents.children[0].identities.length, 2);
});

test("un sub-rând stricat e refuzat AICI, cu numele câmpului", () => {
  // Aceeași regulă ca la rânduri: marginile se verifică ÎNAINTE, pe valori.
  // `INSERT IGNORE` ar fi TRUNCHIAT eticheta de 191 de octeți la 190, cu un
  // avertisment pe care nu-l citește nimeni — iar rândul rezultat e prezent, deci
  // numărat ca bun, și altul decât cel trimis.
  const long = prepareRows(
    ASSETS, [{ id: 5, name: "vhost", tags: [{ tag: "t".repeat(191) }] }], INSTANCE, 1);
  assert.equal(long.ok, false);
  assert.match((long as { detail: string }).detail, /tags\[0\]\.tag: 191 octeți/);

  // Și o adresă care nu e adresă, în coloana `INET6` a lui `actor_ips`.
  const notAnIp = prepareRows(
    ACTORS, [actorRow("cluster:ab", ["203.0.113.0/24"])], INSTANCE, 1);
  assert.equal(notAnIp.ok, false);
  assert.match((notAnIp as { detail: string }).detail,
               /member_ips\[0\]\.ip: aștept o adresă IP/);
});

/**
 * `value_hash` declarat GREȘIT: ca o coloană care sosește de pe sârmă.
 *
 * Forma pe care o ia mâna care „completează" declarația, și singura pentru care
 * felul `bytes` mai există. Ținută ca fixtură separată, nu ca abatere a lui
 * `ACTORS`: declarația bună trebuie să rămână cea folosită de restul suitei.
 */
const BINARY_ON_THE_WIRE: Stream = {
  ...ACTORS,
  children: [IPS, {
    ...ATTRS,
    columns: [...ATTRS.columns,
              { source: "value_hash", target: "value_hash", kind: "bytes",
                byteLength: 32, nullable: false }],
    hashed: undefined,
  }],
};

test("o coloană BINARĂ declarată pe sârmă e refuzată, iar refuzul vine înaintea bazei",
     async () => {
  // `actor_attrs.value_hash` e `BINARY(32)`. Declarat `hash` — cum era —,
  // validarea cerea 64 de caractere hexa și le trecea mai departe ca ȘIR: 64 de
  // octeți într-o coloană de 32. `INSERT IGNORE` TRUNCHIAZĂ cu un avertisment,
  // deci rândul e PREZENT și altul decât cel trimis, iar numărătoarea de
  // identitate compară apoi cei 32 de octeți stocați cu parametrul de 64 și nu
  // potrivește NICIODATĂ. Lotul iese `incomplete` la fiecare reluare, cu un mesaj
  // care numără rânduri în loc să arate spre coloană — adică fluxul oprit
  // definitiv, cu cauza ascunsă.
  //
  // De la #66 refuzul nu mai înseamnă „nu s-a decis cine calculează": valoarea se
  // calculează AICI, din `value` (vezi testele de mai jos). Ce refuză felul
  // `bytes` e o DECLARAȚIE greșită — octeți ceruți de pe sârmă, unde
  // `encode_value` din `shipper.py` n-are cum să-i producă.
  const row = {
    actor_key: "cluster:ab", event_count: 10, member_ips: [],
    attrs: [{ kind: "country", value: "RO", value_hash: hash(1) }],
  };
  const prepared = prepareRows(BINARY_ON_THE_WIRE, [row], INSTANCE, 1);
  assert.equal(prepared.ok, false, "un value_hash de 64 de caractere a fost acceptat");
  assert.match((prepared as { detail: string }).detail,
               /attrs\[0\]\.value_hash: coloana e binară \(32 octeți\)/);

  // Și nimic nu ajunge la bază: refuzul e `invalid`, nu un lot pe jumătate scris.
  const server = new FakeServer();
  const result = await ingestStream(dbOf(server), INSTANCE, BINARY_ON_THE_WIRE, [row], 10, 1);
  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "invalid");
  assert.equal(server.tableRows("actor_attrs").size, 0, "s-a scris în actor_attrs");
  assert.equal(server.tableRows("actor_entries").size, 0);
  assert.deepEqual(server.asked, [], "s-a trimis o instrucțiune pentru un lot refuzat");

  // Iar tabloul GOL trece mai departe: refuzul e al VALORII, nu al tabelei.
  // Altfel proba de deasupra ar fi verde și pe o implementare care a încetat să
  // mai scrie `actor_attrs` cu totul.
  const empty = await ingestStream(dbOf(new FakeServer()), INSTANCE, ACTORS,
                                   [actorRow("cluster:ab", ["203.0.113.10"])], 10, 1);
  assert.equal(empty.ok, true, JSON.stringify(empty));
});

// ---------------------------------------------------------------------------
// Coloana CALCULATĂ la ingestie (#66)
// ---------------------------------------------------------------------------
test("un value_hash venit pe sârmă e REFUZAT, nu preferat celui calculat", () => {
  // Eșecul pe care îl previne: două capete care calculează aceeași cheie. Dacă
  // un digest trimis de sursă ar fi acceptat, identitatea unui atribut la
  // receptor ar depinde de ce a socotit gazda monitorizată — adică exact locul
  // în care cele două pot să nu fie de acord, iar dezacordul nu se vede de
  // nicăieri: rândul e prezent, cu altă cheie decât ar fi avut.
  //
  // Refuzul iese din regula câmpurilor necunoscute, deci e zgomotos: lotul se
  // oprește, nu se completează tăcut.
  const row = {
    actor_key: "cluster:ab", event_count: 10, member_ips: [],
    attrs: [{ kind: "country", value: "RO", value_hash: hash(1) }],
  };
  const prepared = prepareRows(ACTORS, [row], INSTANCE, 1);
  assert.equal(prepared.ok, false, "un value_hash de pe sârmă a fost acceptat");
  assert.match((prepared as { detail: string }).detail,
               /attrs\[0\]: câmpul necunoscut "value_hash"/);
});

test("dublul deosebește doi octeți diferiți, altfel probele de mai jos nu spun nimic", () => {
  // Ce previne: probele despre `value_hash` care sunt verzi fiindcă dublul nu
  // vede diferența. `String(buffer)` DECODEAZĂ octeții ca UTF-8, iar orice
  // secvență invalidă devine același caracter de înlocuire — deci doi digești
  // distincți pot ieși ca același text, iar un depozit ținut pe textul ăla ar
  // declara idempotență acolo unde MariaDB ar vedea două rânduri.
  //
  // Cazul nu e ipotetic pentru un `BINARY(32)`: octeții unui digest sunt
  // oarecare, nu text. Perechea de mai jos e cea mai scurtă formă a lui.
  const a = Buffer.from([0xff]);
  const b = Buffer.from([0xfe]);
  assert.equal(String(a), String(b),
               "premisa testului a căzut: `String` chiar deosebește octeții ăștia");
  assert.notEqual(cell(a), cell(b),
                  "dublul compară doi octeți distincți ca fiind egali; orice probă " +
                  "despre value_hash devine astfel vacuă");
  // Și forma obișnuită rămâne neatinsă: un număr și șirul lui se compară la fel
  // ca înainte, altfel toate celelalte probe s-ar muta pe altă semantică.
  assert.equal(cell(5), cell("5"));
});

test("același atribut retrimis nu adaugă niciun rând la receptor", async () => {
  // Eșecul pe care îl previne: un digest care nu e o funcție a valorii —
  // sărat, cu un ceas în el, ori normalizat cu ceva ce se schimbă între rulări.
  // Cheia unică e pe `value_hash`, deci un digest care se mișcă face din fiecare
  // retrimitere (cazul NORMAL, nu cel excepțional) un rând nou. Ce vede
  // operatorul: `actor_attrs` crește la fiecare rundă de expediere, cu aceleași
  // valori sub chei diferite.
  //
  // Curățarea sub-rândurilor ar ascunde jumătate din asta — ștergând rândurile
  // vechi ale aceluiași părinte —, deci proba se face și cu ea SCOASĂ
  // (`skipDelete`). Ce rămâne atunci e chiar întrebarea: al doilea lot a inserat
  // ceva sau nu?
  const attrs = [{ kind: "country", value: "RO" },
                 { kind: "user_agent", value: "curl/8.5.0" }];

  const server = new FakeServer();
  const first = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                   [actorRow("cluster:ab", [], attrs)], 10, 1);
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(server.tableRows("actor_attrs").size, 2);
  const digests = storedDigest(server, "actor_attrs", "value_hash");

  const again = await ingestStream(dbOf(server), INSTANCE, ACTORS,
                                   [actorRow("cluster:ab", [], attrs)], 10, 2);
  assert.equal(again.ok, true, JSON.stringify(again));
  assert.deepEqual(storedDigest(server, "actor_attrs", "value_hash"), digests,
                   "aceeași valoare a produs alt value_hash la al doilea lot");

  // Fără curățare, un digest care se mișcă ar lăsa în urmă rândurile vechi:
  // patru în loc de două, iar numărătoarea de sub părinți ar ieși `incomplete`.
  const noDelete = new FakeServer({ skipDelete: true });
  const one = await ingestStream(dbOf(noDelete), INSTANCE, ACTORS,
                                 [actorRow("cluster:ab", [], attrs)], 10, 1);
  assert.equal(one.ok, true, JSON.stringify(one));
  const two = await ingestStream(dbOf(noDelete), INSTANCE, ACTORS,
                                 [actorRow("cluster:ab", [], attrs)], 10, 2);
  assert.equal(two.ok, true, JSON.stringify(two));
  assert.equal(noDelete.tableRows("actor_attrs").size, 2,
               "retrimiterea aceluiași lot a inserat rânduri noi: digestul nu e o " +
               "funcție a valorii");
});

test("două valori diferite dau chei diferite, iar digestul e al OCTEȚILOR trimiși",
     async () => {
  // Două eșecuri, amândouă tăcute la receptor:
  //
  //   1. un digest care nu depinde de valoare (constant, ori al unei alte
  //      coloane) — cheia e `(instanță, actor, kind, value_hash)`, deci două
  //      atribute de același fel s-ar CONTOPI: al doilea ar fi înghițit, iar
  //      panoul ar arăta un singur user-agent acolo unde serverul are două;
  //   2. o NORMALIZARE strecurată în rețetă (registru, trim, NFC). Aceeași
  //      contopire, dar numai pe valorile care diferă prin ce s-a normalizat —
  //      adică descoperită târziu, pe date reale.
  //
  // `HashedColumn` interzice trei normalizări — registru, trim, NFC —, iar
  // fiecare trebuie să aibă aici valoarea ei. Nu e zel: cu o singură pereche, cea
  // de registru, cum a fost testul ăsta la prima scriere, `normalize("NFC")` și
  // `trim()` strecurate în `digestOf` treceau prin TOATĂ suita, măsurat. Singura
  // pereche Unicode din suită era deja NFC și deja fără spații — deci pata oarbă
  // era în DATE, nu în aserțiuni, și de-aia se repară cu valori.
  //
  // A patra valoare nu e pe lista aia și nu e o pereche: rețeta nu spune „fără
  // cele trei", ci fără NICIO curățare, iar o afirmație de felul ăla nu se
  // probează adăugând o valoare per curățare — enumerarea nu se termină. Prima
  // formă a ei purta un singur caracter de control, deci era punct fix pentru
  // orice curățare care nu-l atinge: `value.split("\u0000")[0]` și
  // `value.replace(/\u00a0/g, " ")` strecurate în `digestOf` treceau prin TOATĂ
  // suita, măsurat, 541/541. Amândouă sunt atingibile — `checkString` refuză
  // doar surogatul neîmperecheat, iar un NBSP lipit de un proxy chiar sosește
  // într-un `user_agent`.
  //
  // Deci valoarea aia poartă câte un caracter din clasele NUMITE mai jos, iar
  // oracolul (`expectedDigest`, calculat independent) le înroșește pe acelea.
  //
  // NU le înroșește pe toate, și asta e măsurat, nu bănuit. Trei curățări trec
  // în continuare pe suita întreagă (541/541, august 2026):
  //
  //     colapsarea liniilor noi (CR si LF inlocuite cu spatiu)
  //     tabul inlocuit cu spatiu
  //     un plafon de lungime (toate cele sase valori au sub 30 de
  //     caractere, deci orice plafon plauzibil e operatie nula peste fixtura)
  //
  // Toate trei sunt atingibile: `checkString` refuza doar surogatul
  // neimperecheat si depasirea de octeti — nu atinge liniile noi, returul
  // de car sau tabul.
  //
  // Cauza nu e o valoare care lipseste, e ABORDAREA: acoperirea depinde
  // exclusiv de date, iar enumerarea nu se termina. Fixtura a fost largita de
  // trei ori — o pereche, apoi clase, apoi caractere — si de fiecare data a
  // ramas altceva afara. Ce ar inchide clasa e esantionarea in locul
  // enumerarii: un corpus fix, cu samanta, prin acelasi oracol, cu o singura
  // aserttiune si fara lista de clase. Tiparul exista deja in depozit, la
  // `tests/fixtures/canonical-corpus.json`. Decizie de operator, nu a mea.
  //
  // Aserțiunile de mai jos leagă fiecare CARACTER numit de garda lui, deci o
  // clasă ștearsă din valoare se vede ca test roșu — dar numai dintre cele
  // numite.
  //
  // Ce se strică dacă lipsește una: nimic vizibil azi, fiindcă `actors` nu e încă
  // înregistrat — dar odată înregistrat, o curățare strecurată în rețetă schimbă
  // identitatea tuturor rândurilor din arhivă deodată, iar de atunci fiecare lot
  // inserează rânduri noi și curățarea le șterge pe cele vechi, la nesfârșit.

  // Perechea NFC/NFD. Scrisă cu escape-uri fiindcă cele două se tipăresc
  // IDENTIC: un literal „café" nu spune care formă e în fișier, iar un editor
  // sau un filtru de git care normalizează la salvare le-ar face egale fără să
  // se vadă nimic în diff.
  const nfc = "caf\u00e9";   // é precompus, U+00E9
  const nfd = "cafe\u0301";  // e + accent combinat, U+0065 U+0301
  // Spațiile SUNT valoarea: unul în față, unul în coadă, doi înăuntru. Un
  // user-agent chiar sosește așa când un proxy lipește antete.
  const spaced = " curl/8.5.0  (compatible) ";
  // Valoarea COMPUSĂ: câte un caracter din fiecare clasă pe care o curățare pe
  // clase de caractere le ia de obicei pe toate deodată. Toate trec de
  // `checkString` — el refuză doar surogatul neîmperecheat și depășirea de
  // octeți —, iar `value` se scrie neatins. Scrisă tot cu escape-uri, și cu
  // atât mai mult: NUL, NBSP și spațiul de lățime zero sunt INVIZIBILE în
  // editor, deci un literal le-ar lăsa să dispară la prima reformatare fără
  // nicio urmă în diff. O „curățare" care ar scoate oricare dintre ele din
  // digest rupe motivul #3 din `HashedColumn` — digestul n-ar mai putea fi
  // recalculat din ce e stocat.
  const composed =
    " curl/8.5.0" +  // spații la capete: trim / trimStart / trimEnd
    "\u0007" +       // BEL — control C0
    "\u0000" +       // NUL — orice tăiere „până la octetul nul"
    "\u00a0" +       // NBSP — ce lipește un proxy între antete
    "\u200b" +       // spațiu de lățime zero — „scoate invizibilele"
    "e\u0301" +      // e + accent combinat — NFC îl compune
    "\u00e9" +       // é precompus — NFD îl desface
    "\uff11" +       // cifra 1 în lățime întreagă — NFKC/NFKD o pliază la „1"
    "Aa ";           // ambele registre — toLowerCase ȘI toUpperCase
  const upper = "Mozilla/5.0 Ünïcode";
  const lower = "mozilla/5.0 ünïcode";

  // Fixtura se apără singură. O pereche care încetează să difere prin ce trebuie
  // — un editor care normalizează Unicode, o reformatare care înghite spațiile —
  // ar lăsa testul verde fără să mai probeze nimic; chiar tiparul din CLAUDE.md.
  assert.notEqual(upper, lower, "perechea de registru s-a contopit în fixtură");
  assert.equal(upper.toLowerCase(), lower, "cele două nu mai diferă DOAR prin registru");
  assert.notEqual(nfc, nfd, "perechea NFC/NFD s-a contopit în fixtură");
  assert.equal(nfd.normalize("NFC"), nfc, "a doua valoare nu mai e forma NFD a primei");
  assert.notEqual(spaced.trim(), spaced, "valoarea nu mai are spații în jur");
  assert.notEqual(spaced.replace(/\s+/g, " "), spaced,
                  "valoarea nu mai are spații dublate înăuntru");

  // Câte o aserțiune per CARACTER, cu curățarea care l-ar atinge pe el. Nu pe
  // clasă: două clase se suprapun aici — NUL e și el un control C0, NBSP se
  // pliază și el sub NFKC —, iar o gardă scrisă pe clasă rămâne verde cu
  // reprezentantul celeilalte încă în literal. Măsurat, pe fișierul ăsta: cu
  // "\u0007" scos din valoare, garda pe [\u0000-\u001f] trecea; cu "\uff11" scos,
  // garda pe NFKC trecea — și odată cu ea se pierdea tăcut chiar clasa pentru
  // care fusese pus caracterul. Deci fiecare caracter își are garda lui, și
  // fiecare spune ce a dispărut din literal.
  assert.notEqual(composed.trim(), composed,
                  "valoarea compusă nu mai are spații la capete");
  assert.notEqual(composed.replace(/\u0007/g, ""), composed,
                  "valoarea compusă nu mai poartă BEL (control C0)");
  assert.notEqual(composed.split("\u0000")[0], composed,
                  "valoarea compusă nu mai poartă NUL");
  assert.notEqual(composed.replace(/\u00a0/g, " "), composed,
                  "valoarea compusă nu mai poartă NBSP");
  assert.notEqual(composed.replace(/\u200b/g, ""), composed,
                  "valoarea compusă nu mai poartă un spațiu de lățime zero");
  assert.notEqual(composed.replace(/\u0301/g, ""), composed,
                  "valoarea compusă nu mai poartă o marcă combinată");
  assert.notEqual(composed.replace(/\u00e9/g, "e"), composed,
                  "valoarea compusă nu mai poartă o formă precompusă");
  assert.notEqual(composed.replace(/\uff11/g, "1"), composed,
                  "valoarea compusă nu mai poartă un caracter de compatibilitate");
  assert.notEqual(composed.toLowerCase(), composed,
                  "valoarea compusă nu mai poartă o literă mare");
  assert.notEqual(composed.toUpperCase(), composed,
                  "valoarea compusă nu mai poartă o literă mică");

  // Și afirmația de clasă, care e chiar ce spune rețeta: niciuna dintre cele
  // trei forme de normalizare nu lasă valoarea neatinsă. Aserțiunile de mai sus
  // păzesc caracterele; astea trei păzesc concluzia care se trage din ele.
  assert.notEqual(composed.normalize("NFC"), composed, "valoarea compusă e punct fix pentru NFC");
  assert.notEqual(composed.normalize("NFD"), composed, "valoarea compusă e punct fix pentru NFD");
  assert.notEqual(composed.normalize("NFKC"), composed, "valoarea compusă e punct fix pentru NFKC");

  // `kind` face parte din cheie, deci perechile stau pe feluri diferite ca
  // fiecare să se ciocnească doar cu perechea ei — altfel un digest constant ar
  // fi refuzat de dedublare înainte să se poată compara vreun digest.
  const attrs = [
    { kind: "user_agent", value: upper },
    { kind: "user_agent", value: lower },
    { kind: "user_agent", value: spaced },
    { kind: "user_agent", value: composed },
    { kind: "targeted_asset", value: nfc },
    { kind: "targeted_asset", value: nfd },
  ];

  // Și ACUM gărzile de mai sus sunt legate de tabloul pe care lucrează
  // aserțiunile. Până aici păzeau șase variabile LOCALE: cu `attrs` golit de
  // tot, testul trecea — `size === attrs.length === 0`, `deepEqual([], [])` de
  // două ori —, iar gărzile rămâneau verzi lângă el. Măsurat, pe toată suita:
  // 541/541. La fel scoțând o singură valoare din tablou, ceea ce e chiar felul
  // în care se pierde acoperirea: nu se șterge o aserțiune, se „simplifică"
  // fixtura.
  assert.equal(attrs.length, 6, "lotul nu mai are cele șase valori păzite mai sus");
  assert.deepEqual(attrs.map((a) => a.value).sort(),
                   [upper, lower, spaced, composed, nfc, nfd].sort(),
                   "mulțimea trimisă nu mai e cea pe care o păzesc aserțiunile " +
                   "de mai sus");
  const server = new FakeServer();
  const result = await ingestStream(
    dbOf(server), INSTANCE, ACTORS, [actorRow("cluster:ab", [], attrs)], 10, 1);

  // Un refuz „apare de două ori în același lot" ÎNSEAMNĂ contopire: două valori
  // pe care sursa le ține distincte au dat același digest. Dedublarea din
  // `prepareRows` o prinde înainte de bază, deci normalizarea se vede ca lot
  // oprit, nu ca rând pierdut.
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(server.tableRows("actor_attrs").size, attrs.length,
               "două valori distincte s-au contopit într-un singur rând");
  assert.deepEqual(storedValues(server, "actor_attrs", "value"),
                   attrs.map((a) => a.value).sort());
  assert.deepEqual(storedDigest(server, "actor_attrs", "value_hash"),
                   attrs.map((a) => expectedDigest(a.value)).sort(),
                   "digestul stocat nu e SHA-256 peste octeții UTF-8 ai lui value");
});

test("două atribute cu aceeași cheie într-un lot se refuză, iar mesajul le NUMEȘTE", () => {
  // Jumătatea care se poate apăra din presupunerea scrisă la `HashedColumn`:
  // rezistența la coliziuni a lui SHA-256 nu se poate proba, dar drumul pe care
  // o coliziune ar pierde un rând TĂCUT e închis. Două sub-rânduri cu aceeași
  // identitate — fie două valori egale, fie (teoretic) două valori care se
  // hash-uiesc la fel — opresc lotul aici, înainte de orice scriere. `INSERT
  // IGNORE` l-ar fi păstrat pe primul, iar numărătoarea ar fi ieșit corectă:
  // exact un rând pierdut cu filigranul ecouat.
  //
  // Iar mesajul trebuie să spună CARE: identitatea conține un digest, deci
  // scrisă cu `String()` ar ieși ca octeți bruți în jurnalul operatorului.
  const row = actorRow("cluster:ab", [], [{ kind: "country", value: "RO" },
                                          { kind: "country", value: "RO" }]);
  const result = prepareRows(ACTORS, [row], INSTANCE, 1);
  assert.equal(result.ok, false, "două sub-rânduri cu aceeași cheie au trecut");
  assert.match((result as { detail: string }).detail,
               new RegExp(`sub-rândul \\(cluster:ab, country, ${expectedDigest("RO")}\\) ` +
                          "apare de două ori"));
});

test("un atribut scos de la sursă chiar dispare de la receptor", async () => {
  // Aceeași proprietate ca la adrese, dar pe cheia care conține o coloană
  // CALCULATĂ: clauza `NOT IN` a curățării compară tupluri `(kind, value_hash)`,
  // deci un digest nedeterminist sau prost legat ar face ștergerea să nu
  // potrivească nimic. Ce rămâne atunci la receptor e un atribut pe care
  // serverul nu-l mai atribuie actorului — un user-agent vechi, un ASN de la
  // care nu mai vine nimic —, iar operatorul citește din el.
  const server = new FakeServer();
  await ingestStream(dbOf(server), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", [], [{ kind: "country", value: "RO" },
                                                  { kind: "user_agent", value: "curl/8.5.0" }])],
                     10, 1);
  assert.equal(server.tableRows("actor_attrs").size, 2);

  const shrunk = await ingestStream(
    dbOf(server), INSTANCE, ACTORS,
    [actorRow("cluster:ab", [], [{ kind: "country", value: "RO" }], 20)], 20, 2);
  assert.equal(shrunk.ok, true, JSON.stringify(shrunk));
  assert.deepEqual(storedValues(server, "actor_attrs", "value"), ["RO"],
                   "atributul scos de la sursă e încă la receptor");
  assert.deepEqual(storedDigest(server, "actor_attrs", "value_hash"),
                   [expectedDigest("RO")]);

  // Iar dacă ștergerea nu face nimic, lotul NU se declară complet: mulțimea de
  // la receptor n-ar fi cea de la sursă.
  const merged = new FakeServer({ skipDelete: true });
  await ingestStream(dbOf(merged), INSTANCE, ACTORS,
                     [actorRow("cluster:ab", [], [{ kind: "country", value: "RO" },
                                                  { kind: "user_agent", value: "curl/8.5.0" }])],
                     10, 1);
  const stale = await ingestStream(
    dbOf(merged), INSTANCE, ACTORS,
    [actorRow("cluster:ab", [], [{ kind: "country", value: "RO" }], 20)], 20, 2);
  assert.equal(stale.ok, false, "un lot cu mulțimea contopită s-a declarat complet");
  assert.equal(stale.ok === false && stale.kind, "incomplete");
  assert.match((stale as { detail: string }).detail,
               /sub părinții din lot sunt 2 sub-rânduri în actor_attrs/);
});

test("un digest care n-ar încăpea în coloană e refuzat ÎNAINTE de bază", async () => {
  // `BINARY(n)` nu refuză: completează cu zerouri ce e mai scurt și TAIE ce e mai
  // lung, tăcut. Deci dacă `byteLength` din declarație și lățimea reală a
  // coloanei se despart — o migrație care schimbă `BINARY(32)` în `BINARY(64)`,
  // o declarație copiată de la altă coloană —, rândul ar ajunge în arhivă
  // completat cu zerouri, iar numărătoarea de identitate ar compara ce s-a
  // stocat cu parametrul trimis și n-ar potrivi NICIODATĂ: `incomplete` la
  // fiecare reluare, cu un mesaj care numără rânduri.
  //
  // SHA-256 dă întotdeauna 32 de octeți, deci ce se probează aici e acordul
  // dintre DECLARAȚIE și digest, nu neîncrederea în bibliotecă.
  const narrow: Stream = {
    ...ACTORS,
    children: [IPS, { ...ATTRS,
                      hashed: [{ target: "value_hash", from: "value", byteLength: 16 }] }],
  };
  const row = actorRow("cluster:ab", [], [{ kind: "country", value: "RO" }]);
  const server = new FakeServer();
  const result = await ingestStream(dbOf(server), INSTANCE, narrow, [row], 10, 1);

  assert.equal(result.ok, false, "un digest de 32 de octeți a intrat într-un BINARY(16)");
  assert.equal(result.ok === false && result.kind, "invalid");
  assert.match((result as { detail: string }).detail,
               /attrs\[0\]: value_hash a ieșit 32 octeți, iar coloana e declarată BINARY\(16\)/);
  assert.deepEqual(server.asked, [], "s-a trimis o instrucțiune pentru un lot refuzat");

  // Și coloana din care se calculează trebuie să existe: o declarație care arată
  // spre un câmp inexistent ar hash-ui `undefined` — un digest perfect valid, al
  // nimicului, identic pentru toate rândurile.
  const orphan: Stream = {
    ...ACTORS,
    children: [IPS, { ...ATTRS,
                      hashed: [{ target: "value_hash", from: "valoare", byteLength: 32 }] }],
  };
  const missing = prepareRows(orphan, [row], INSTANCE, 1);
  assert.equal(missing.ok, false, "un digest s-a calculat dintr-o coloană inexistentă");
  assert.match((missing as { detail: string }).detail,
               /value_hash se calculează din "valoare", care nu e o coloană a sub-rândului/);
});

// ---------------------------------------------------------------------------
// Plafoanele
// ---------------------------------------------------------------------------
test("un rând cu mai multe sub-rânduri decât încape dă un refuz LIZIBIL", async () => {
  // Fără plafon, un actor cu zeci de mii de adrese ar produce ori un corp peste
  // `MAX_BODY_BYTES` (413, fără să spună care rând), ori o eroare de driver
  // despre numărul de parametri. Refuzul de aici numește fluxul, rândul, câmpul
  // și numărul — adică exact ce trebuie ca operatorul să poată mări plafonul în
  // cunoștință de cauză.
  const many = Array.from({ length: MAX_CHILDREN_PER_ROW + 1 }, (_, i) => ({ tag: `t${i}` }));
  const server = new FakeServer();
  const result = await ingestStream(
    dbOf(server), INSTANCE, ASSETS, [{ id: 5, name: "vhost", tags: many }], 5, 1);

  assert.equal(result.ok, false);
  assert.equal(result.ok === false && result.kind, "invalid");
  assert.match((result as { detail: string }).detail,
               new RegExp(`tags: ${MAX_CHILDREN_PER_ROW + 1} sub-rânduri, limita e ` +
                          `${MAX_CHILDREN_PER_ROW}`));
  assert.equal(server.tableRows("asset_tags").size, 0, "s-a scris ceva pe un lot refuzat");
  assert.equal(server.tableRows("asset_entries").size, 0);

  // Și EXACT plafonul trece, ca refuzul să însemne ceva.
  const exact = prepareRows(
    ASSETS, [{ id: 5, name: "vhost", tags: many.slice(0, MAX_CHILDREN_PER_ROW) }], INSTANCE, 1);
  assert.ok(exact.ok, (exact as { detail?: string }).detail);
});

test("plafonul pe lot al sub-rândurilor se refuză, nu se taie", () => {
  // Plafonul de rânduri părinte nu mai mărginește singur munca unui lot. Ce
  // apără numărul ăsta sunt dus-întorsurile: fiecare bucată de sub-rânduri e o
  // scriere plus două numărători, iar un lot nemărginit le-ar face pe toate
  // înăuntrul unui singur `ship.timeout_s`.
  const perRow = 500;
  const rows = Array.from(
    { length: Math.ceil(MAX_CHILD_ROWS_PER_BATCH / perRow) + 1 },
    (_, i) => assetRow(i + 1, Array.from({ length: perRow }, (_, j) => `t${j}`)));
  const result = prepareRows(ASSETS, rows, INSTANCE, 1);
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail,
               new RegExp(`peste ${MAX_CHILD_ROWS_PER_BATCH} sub-rânduri`));
});

test("plafoanele lasă să treacă mulțimile pe care le putem numi", () => {
  // O margine e o unealtă doar dacă lasă normalul să treacă. Cea mai mare
  // mulțime pe care o știm e `actors.member_ips` al unui cluster pe /24 — 254 de
  // adrese —, iar un plafon sub ea ar opri fluxul pe un actor perfect obișnuit,
  // fără cale de reparare de pe gazdă.
  assert.ok(MAX_CHILDREN_PER_ROW >= 254,
            `${MAX_CHILDREN_PER_ROW} e sub un cluster /24, adică sub normal`);
  assert.ok(MAX_CHILD_ROWS_PER_BATCH >= MAX_CHILDREN_PER_ROW,
            "un singur rând la plafon n-ar încăpea într-un lot");
});

test("un lot cu multe sub-rânduri intră în bucăți, dar rămâne un singur lot", async () => {
  // Bucățile există ca să nu se lovească `max_allowed_packet`. Ce nu au voie să
  // schimbe e verdictul — iar la sub-rânduri e mai ușor de greșit: numărătoarea
  // de sub părinți și ștergerea se taie după alte criterii decât scrierea.
  const tags = Array.from({ length: 450 }, (_, i) => `t${i}`);
  const server = new FakeServer();
  const result = await ingestStream(dbOf(server), INSTANCE, ASSETS,
                                    [assetRow(5, tags)], 5, 1);

  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(server.tableRows("asset_tags").size, 450);
  const writes = server.asked.filter((s) => s.includes("INTO asset_tags"));
  assert.ok(writes.length > 1, "lotul de sub-rânduri nu a fost împărțit deloc");
});

// ---------------------------------------------------------------------------
// Regula de declarare a unui copil
// ---------------------------------------------------------------------------
/**
 * Ce trebuie să fie adevărat despre un copil ca să poată fi scris.
 *
 * Scoasă ca funcție, ca `assertRegistrable` din `tests/ingest.test.ts`, și din
 * același motiv: o regulă a cărei declanșare n-a fost văzută izolat e o regulă
 * despre care nu se știe pe ce pică.
 */
function assertChildDeclarable(parent: Stream, child: ChildStream): void {
  assert.equal(child.identity[0], "instance_id",
               `${child.table}: identitatea nu începe cu instance_id`);

  // Tabela e declarată ca fiind de LEGĂTURĂ, iar părintele declarat acolo e chiar
  // ăsta. Fără potrivirea asta, un copil s-ar putea atârna de altă tabelă decât
  // cea din registru, iar garda de recensământ n-ar avea ce să compare.
  assert.equal(linkParentTable(child.table), parent.table,
               `${child.table}: registrul tabelelor de legătură nu-l dă drept copil ` +
               `al lui ${parent.table}`);

  // Identitatea DECLARATĂ e chiar cheia unică din migrație. Dacă cele două
  // diferă, `INSERT` se potrivește după alte coloane decât cele pe care le
  // numără verificarea de efect, iar `DELETE`-ul de curățare exclude altceva
  // decât ce s-a scris — adică șterge sub-rânduri care tocmai au sosit. Testul
  // fluxurilor din `tests/schema.test.ts` se uită doar la `Stream.identity`.
  assert.deepEqual([...child.identity], uniqueKeyOf(child.table),
                   `${child.table}: identitatea declarată nu e cheia unică din migrație`);

  const written = new Set([...child.link.map((l) => l.child),
                           ...child.columns.map((c) => c.target),
                           ...(child.hashed ?? []).map((h) => h.target)]);
  for (const key of child.identity.slice(1)) {
    assert.ok(written.has(key),
              `${child.table}: coloana de cheie ${key} nu e scrisă de sub-rând`);
  }

  // Coloanele CALCULATE (#66). Trei lucruri, fiecare cu o cădere tăcută în
  // spate:
  //
  //   * o coloană scrisă de două ori — o dată de pe sârmă, o dată calculată —
  //     ar apărea de două ori în `INSERT`, iar valorile s-ar lega la coloane
  //     greșite dacă serverul ar accepta forma;
  //   * `from` trebuie să fie o coloană SOSITĂ a aceluiași sub-rând. Arătând
  //     spre altceva, digestul s-ar lua peste ce nu există;
  //   * `byteLength` trebuie să fie EXACT lățimea din migrație. Numărul ăla
  //     decide dacă digestul intră întreg, iar `BINARY(n)` nu refuză nimic:
  //     completează sau taie, tăcut. Până acum nimic din suită nu se uita la
  //     tipul coloanei — pata oarbă scrisă în `lib/streams.ts` —, deci `32` era
  //     o intenție. Aici devine un fapt citit din fișierul livrat.
  //
  // ## CE anume ține `32`, fiindcă NU e aserțiunea de mai jos singură
  //
  // `createSqlOf` citește `CREATE TABLE`, atât. O migrație de mâine care lărgește
  // coloana cu `ALTER TABLE actor_attrs MODIFY COLUMN value_hash BINARY(64) …`
  // n-ar atinge textul ăla, deci aserțiunea de mai jos ar rămâne VERDE peste o
  // coloană care nu mai are 32 de octeți — măsurat, chiar așa: fișierul ăsta
  // rămâne 41/0. Ce se înroșește atunci sunt două gărzi din
  // `tests/schema.test.ts`, niciuna despre coloane calculate:
  //
  //   * „un `MODIFY COLUMN` repetă definiția întreagă" — cere ca definiția
  //     rescrisă să ÎNCEAPĂ cu tipul din `CREATE TABLE`, deci `BINARY(64)` peste
  //     un `BINARY(32)` pică acolo;
  //   * recensământul gărzilor (`objectOf` + `ATTRIBUTE_ONLY`) — orice formă de
  //     instrucțiune nerecunoscută, inclusiv ortografia `CHANGE COLUMN` care
  //     ocolește tiparul de mai sus, e roșie până când cineva o declară anume.
  //
  // Scris fiindcă altfel următorul citește aserțiunea de mai jos ca pe o gardă
  // completă și, la prima lărgire de coloană, o „repară" acolo unde e verde.
  const arrived = new Set(child.columns.map((c) => c.target));
  for (const derived of child.hashed ?? []) {
    assert.ok(!arrived.has(derived.target) && !child.link.some((l) => l.child === derived.target),
              `${child.table}.${derived.target} e și calculată, și scrisă din lot`);
    assert.ok(arrived.has(derived.from),
              `${child.table}.${derived.target} se calculează din "${derived.from}", ` +
              "care nu e o coloană sosită a sub-rândului");
    assert.equal(columnType(createSqlOf(child.table), derived.target),
                 `BINARY(${derived.byteLength})`,
                 `${child.table}.${derived.target}: lățimea declarată nu e cea din ` +
                 "migrație; BINARY(n) nu refuză un digest de altă lungime, îl " +
                 "completează cu zerouri sau îl taie");
  }

  // Legătura trebuie să fie PARTE din cheia copilului. Fără regula asta, cheia
  // nu mai deosebește sub-rândurile a doi părinți: același element sub alt
  // părinte e ACELAȘI rând, deci scrierea celui de-al doilea e înghițită de
  // `INSERT IGNORE`, iar curățarea unei bucăți de părinți poate șterge un rând
  // pe care tocmai l-a revendicat altă bucată — `deleteChunks` taie ÎNTRE
  // grupuri, iar clauza `NOT IN` a unei bucăți e scrisă pe cheie, deci nu spune
  // nimic despre ce s-a scris în alta. Ce vede operatorul: fluxul se oprește
  // DEFINITIV, cu `incomplete` la fiecare reluare, fiindcă lotul se repetă
  // identic. Cele cinci tabele de azi respectă regula, dar din întâmplare.
  const keyColumns = new Set(child.identity);
  for (const link of child.link) {
    assert.ok(keyColumns.has(link.child),
              `${child.table}: coloana de legătură ${link.child} nu e în cheia unică, ` +
              "deci curățarea unei bucăți de părinți ar putea șterge sub-rândurile alteia");
  }

  // `NOT IN` cu un `NULL` în listă e UNKNOWN, deci curățarea n-ar șterge NIMIC —
  // tăcut, și exact în forma care arată ca o contopire.
  for (const column of child.columns) {
    if (!child.identity.includes(column.target)) continue;
    assert.equal(column.nullable, false,
                 `${child.table}.${column.target} e în cheie și acceptă NULL; ` +
                 "curățarea s-ar opri fără să șteargă nimic");
  }

  // Legătura trebuie să cuprindă identitatea părintelui. Altfel doi părinți
  // distincți pot avea aceleași valori de legătură, iar sub-rândurile unuia le-ar
  // rescrie — sau le-ar ȘTERGE — pe ale celuilalt.
  const linked = new Set(child.link.map((l) => l.parent));
  for (const key of parent.identity.slice(1)) {
    assert.ok(linked.has(key),
              `${child.table}: legătura nu cuprinde ${key} din identitatea lui ` +
              `${parent.name}, deci doi părinți s-ar putea ciocni`);
  }

  // Câmpul tabloului nu are voie să fie și o coloană a părintelui: unul dintre
  // ele ar fi citit, celălalt ignorat, și nu se poate spune care.
  assert.ok(!parent.columns.some((c) => c.source === child.source),
            `${parent.name}: "${child.source}" e și coloană, și tablou`);
}

test("regula de declarare a unui copil se declanșează SINGURĂ, pe fiecare formă greșită", () => {
  assert.doesNotThrow(() => assertChildDeclarable(ASSETS, TAGS), "un copil valid e refuzat");
  assert.doesNotThrow(() => assertChildDeclarable(ACTORS, ATTRS));

  assert.throws(
    () => assertChildDeclarable(ASSETS, { ...TAGS, identity: ["source_id", "tag"] }),
    /nu începe cu instance_id/, "o cheie fără instanță a trecut");
  assert.throws(
    () => assertChildDeclarable(ASSETS, { ...TAGS, identity: ["instance_id", "source_id"] }),
    /nu e cheia unică din migrație/, "o identitate mai îngustă decât cheia a trecut");
  assert.throws(
    () => assertChildDeclarable(ASSETS, { ...TAGS, table: "asset_entries" }),
    /registrul tabelelor de legătură/, "o tabelă care nu e de legătură a trecut");
  assert.throws(
    () => assertChildDeclarable(ACTORS, TAGS),
    /registrul tabelelor de legătură/, "un copil atârnat de alt părinte a trecut");
  assert.throws(
    () => assertChildDeclarable(ASSETS, { ...TAGS, columns: [] }),
    /coloana de cheie tag nu e scrisă/, "o cheie peste o coloană nescrisă a trecut");
  assert.throws(
    () => assertChildDeclarable(ASSETS, {
      ...TAGS,
      columns: [{ ...TAGS.columns[0], nullable: true }],
    }), /acceptă NULL/, "o coloană de cheie care acceptă NULL a trecut");
  assert.throws(
    () => assertChildDeclarable(ASSETS, { ...TAGS, link: [{ child: "source_id", parent: "name" }] }),
    /legătura nu cuprinde source_id/, "o legătură care nu prinde identitatea a trecut");
  // O coloană de legătură în AFARA cheii copilului. `id` chiar e o coloană a lui
  // `asset_tags` (cheia primară auto), deci cazul nu e construit: e forma pe care
  // o ia o legătură pusă pe altceva decât pe cheia unică. Legătura pe `source_id`
  // rămâne, ca aserțiunile dinainte să fie satisfăcute și să pice DOAR asta.
  assert.throws(
    () => assertChildDeclarable(ASSETS, {
      ...TAGS,
      link: [{ child: "source_id", parent: "source_id" }, { child: "id", parent: "source_id" }],
    }), /coloana de legătură id nu e în cheia unică/,
    "o legătură în afara cheii copilului a trecut");
  assert.throws(
    () => assertChildDeclarable({ ...ASSETS, columns: [
      ...ASSETS.columns, { source: "tags", target: "tags", kind: "text", nullable: false },
    ] }, TAGS), /e și coloană, și tablou/, "un câmp dublu declarat a trecut");

  // Coloanele calculate (#66), fiecare formă greșită separat.
  assert.throws(
    () => assertChildDeclarable(ACTORS, {
      ...ATTRS,
      columns: [...ATTRS.columns,
                { source: "value_hash", target: "value_hash", kind: "bytes",
                  byteLength: 32, nullable: false }],
    }), /e și calculată, și scrisă din lot/, "o coloană scrisă de două ori a trecut");
  assert.throws(
    () => assertChildDeclarable(ACTORS, {
      ...ATTRS, hashed: [{ target: "value_hash", from: "valoare", byteLength: 32 }],
    }), /care nu e o coloană sosită/, "un digest peste o coloană inexistentă a trecut");
  assert.throws(
    () => assertChildDeclarable(ACTORS, {
      ...ATTRS, hashed: [{ target: "value_hash", from: "value", byteLength: 64 }],
    }), /lățimea declarată nu e cea din migrație/,
    "o lățime care nu e cea din BINARY(n) a trecut");
});

test("fiecare copil DECLARAT respectă regula, iar mulțimea verificată nu e goală", () => {
  // Se aplică pe tot ce e declarat: fixturile de aici plus copiii fluxurilor
  // ÎNREGISTRATE. Azi niciun flux înregistrat n-are copii, deci bucla ar trece
  // goală — iar o buclă goală care raportează verde e chiar tiparul din
  // `CLAUDE.md`. De-aia numărul se afirmă.
  const declared: [Stream, ChildStream][] = [
    ...[ASSETS, ACTORS].flatMap((s) => (s.children ?? []).map((c) => [s, c] as [Stream, ChildStream])),
    ...allStreams().flatMap((s) => (s.children ?? []).map((c) => [s, c] as [Stream, ChildStream])),
  ];
  assert.ok(declared.length >= 3, `doar ${declared.length} copii declarați`);
  for (const [parent, child] of declared) assertChildDeclarable(parent, child);
});

test("plafoanele de sub-rânduri sunt în acord cu expeditorul", () => {
  // Testul ăsta a avut până pe 20 august 2026 forma INVERSĂ: cerea ca NICIUN
  // flux să nu aibă copii, tocmai ca să se înroșească în ziua înregistrării.
  // `detections.event_ids` a fost ziua aia. Ce apăra atunci — că plafoanele nu
  // pot rămâne un contract nescris — se apără acum în sens pozitiv.
  //
  // Ce se strică dacă cineva le mută înapoi în `RECEIVER_ONLY`: `sentinel/config.py`
  // ar declara legal un lot pe care agregatorul îl refuză cu 413, `ship_once` nu
  // citește niciodată corpul refuzului, iar fluxul se oprește DEFINITIV, cu
  // backoff până la o oră. Simptomul e „agregatorul e căzut", cauza e o listă.
  const withChildren = allStreams().filter((stream) => (stream.children ?? []).length);
  assert.ok(withChildren.length > 0,
            "niciun flux cu sub-rânduri: mecanismul n-are apelant, iar acordul de " +
            "mai jos n-ar proba nimic");

  // Sursa de adevăr e chiar testul de la celălalt capăt, citit ca text: numele
  // trebuie să fie în lista trans-limbaj, nu în cea de scutiri.
  const census = readFileSync(
    new URL("../../tests/unit/test_shipper.py", import.meta.url), "utf8");
  const crossStart = census.indexOf("CROSS_LANGUAGE = CROSS_LANGUAGE_AUTH");
  assert.ok(crossStart > 0, "n-am găsit lista trans-limbaj în test_shipper.py");
  const crossBlock = census.slice(crossStart, census.indexOf("\n}", crossStart));

  for (const name of ["MAX_CHILDREN_PER_ROW", "MAX_CHILD_ROWS_PER_BATCH"]) {
    assert.ok(crossBlock.includes(`"${name}"`),
              `${name} nu e în lista trans-limbaj din tests/unit/test_shipper.py. ` +
              "Un flux cu sub-rânduri e înregistrat, deci plafonul ĂSTA mărginește " +
              "ce poate trimite expeditorul — iar un lot peste el se vede ca " +
              "agregator căzut, nu ca eroare de configurație");
  }

  // Și plafoanele chiar sunt cele pe care le poartă configurația serverului.
  // Citit din sursă, nu presupus: o valoare schimbată la un singur capăt e exact
  // defectul pe care testul îl previne.
  const config = readFileSync(
    new URL("../../sentinel/config.py", import.meta.url), "utf8");
  assert.match(config, new RegExp(`max_children_per_row: int = ${MAX_CHILDREN_PER_ROW}\\b`),
               "implicitul din config.py nu e plafonul receptorului");
  assert.match(config,
               new RegExp(`max_child_rows_per_batch: int = ${MAX_CHILD_ROWS_PER_BATCH}\\b`),
               "implicitul din config.py nu e plafonul receptorului");
});

test("registrul tabelelor de legătură nu e gol și nu se contrazice", () => {
  // Recensământul propriu-zis — „câte tabele de legătură are schema, și sunt
  // toate declarate?" — e în `tests/schema.test.ts`, unde se poate citi schema.
  // Aici se cere doar ca registrul să existe: gol, garda de acolo ar compara două
  // mulțimi vide și ar trece verde.
  const tables = linkTables();
  assert.ok(tables.length >= 5, `doar ${tables.length} tabele de legătură declarate`);
  for (const [child, parent] of tables) {
    assert.notEqual(child, parent, `${child}: e propriul ei părinte`);
    assert.equal(linkParentTable(child), parent);
  }
  assert.equal(linkParentTable("audit_entries"), undefined,
               "o tabelă cu contabilitate proprie e dată drept tabelă de legătură");
});
