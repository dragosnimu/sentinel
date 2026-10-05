/**
 * Comenzile replicate își găsesc sesiunea, chiar dacă au sosit înaintea ei.
 *
 * Eșecul, măsurat pe 5 octombrie 2026: **265 220 din 502 242** de rânduri din
 * `session_command_entries` (53 %) aveau `session_source_id` NULL, pe 8 645 de
 * chei de sesiune și pe toată perioada. Detaliul unei sesiuni caută comenzile
 * după coloana aia, deci pentru jumătate din sesiuni nu putea arăta nimic —
 * deși toate rândurile erau în tabelă.
 *
 * Cauza: gazda scrie `session_id` NULL pe o comandă care sosește înaintea
 * sesiunii ei și îl completează mai târziu, dar fluxul de comenzi e append-only
 * și expediază un rând o singură dată. Vezi `lib/session-links.ts`.
 *
 * Dublul (`tests/session-links-double.ts`) evaluează condițiile din textul
 * instrucțiunilor. Ce NU dovedește: că MariaDB le acceptă și cât durează pe
 * 500 000 de rânduri.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  MARGIN_MS, backfill, formatDatetime, parseDatetime, planLinks, relinkAfterIngest,
} from "../lib/session-links";
import type { SessionWindow } from "../lib/session-links";
import { POST } from "../app/api/sentinel/sync/route";
import {
  FakeServer, INSTANCE, captureError, forgetServer, syncPayload, syncRequest,
  useFakeServer,
} from "./sync-harness";
import { LinkDouble } from "./session-links-double";
import type { Row } from "./session-links-double";

const A = "inst-A";
const B = "inst-B";

function session(over: Partial<SessionWindow> & { sourceId: number }): SessionWindow {
  return {
    sessionKey: "455", openedAt: "2026-10-05 06:52:54.000000",
    closedAt: "2026-10-05 09:59:06.000000", interactive: true, ...over,
  };
}

// ---------------------------------------------------------------------------
// Regula, pe cazuri scrise de mână
// ---------------------------------------------------------------------------
test("data se citește și se scrie fără să se piardă milisecunda", () => {
  const ms = parseDatetime("2026-10-05 06:52:54.123456");
  assert.equal(ms, Date.UTC(2026, 9, 5, 6, 52, 54, 123));
  assert.equal(formatDatetime(ms as number), "2026-10-05 06:52:54.123");
  assert.equal(parseDatetime("2026-10-05T06:52:54Z"), Date.UTC(2026, 9, 5, 6, 52, 54));
  assert.equal(parseDatetime("nu e o dată"), null);
  assert.equal(parseDatetime(null), null);
  assert.equal(parseDatetime(12345), null);
});

test("o sesiune închisă are intervalul [deschidere − 1 min, închidere + 1 min]", () => {
  const plan = planLinks([session({ sourceId: 46797 })]);
  assert.equal(plan.link.length, 1);
  const open = Date.UTC(2026, 9, 5, 6, 52, 54);
  const close = Date.UTC(2026, 9, 5, 9, 59, 6);
  assert.equal(plan.link[0].lo, open - MARGIN_MS);
  assert.equal(plan.link[0].hi, close + MARGIN_MS,
               "marginea de un minut e cea de pe gazdă (`_attach_orphans`)");
});

test("o sesiune deschisă n-are margine superioară", () => {
  const plan = planLinks([session({ sourceId: 1, closedAt: null })]);
  assert.equal(plan.link[0].hi, Number.POSITIVE_INFINITY);
});

test("aceeași cheie după o repornire NU se confundă: intervalele sunt la luni distanță", () => {
  // `ses` se renumerotează la fiecare pornire a gazdei: cheia 455 din august și
  // cea din octombrie sunt sesiuni diferite. Cheia SINGURĂ n-ar lega nimic corect.
  const plan = planLinks([
    session({ sourceId: 10, openedAt: "2026-08-24 13:48:50.000000",
              closedAt: "2026-08-24 13:48:52.000000" }),
    session({ sourceId: 46797 }),
  ]);
  assert.equal(plan.link.length, 2);
  assert.deepEqual(plan.ambiguous, []);
});

test("două sesiuni cu aceeași cheie și intervale suprapuse NU se leagă nici una", () => {
  // Cele 6 perechi măsurate pe gazdă (24 august): duplicate la o secundă. O
  // comandă din suprapunere ar putea fi a oricăreia, iar replica nu ghicește.
  const plan = planLinks([
    session({ sourceId: 2482, sessionKey: "458", openedAt: "2026-08-24 13:54:50.000000",
              closedAt: "2026-08-24 13:54:51.000000" }),
    session({ sourceId: 2483, sessionKey: "458", openedAt: "2026-08-24 13:54:51.000000",
              closedAt: "2026-08-24 13:54:51.000000" }),
  ]);
  assert.deepEqual(plan.link, []);
  assert.deepEqual(plan.ambiguous.map((s) => s.sourceId), [2482, 2483]);
});

test("chei DIFERITE în același minut nu se încurcă", () => {
  const plan = planLinks([
    session({ sourceId: 1, sessionKey: "10" }),
    session({ sourceId: 2, sessionKey: "11" }),
  ]);
  assert.equal(plan.link.length, 2);
  assert.deepEqual(plan.ambiguous, []);
});

test("o dată necitibilă e raportată, nu tratată ca «fără comenzi»", () => {
  const plan = planLinks([session({ sourceId: 9, openedAt: "ieri seara" }),
                          session({ sourceId: 8, closedAt: "mâine" })]);
  assert.deepEqual(plan.link, []);
  assert.deepEqual(plan.unreadable.map((s) => s.sourceId).sort(), [8, 9]);
});

// ---------------------------------------------------------------------------
// Pe date: dublul evaluează condițiile
// ---------------------------------------------------------------------------
let sessions: Row[];
let commands: Row[];
let db: LinkDouble;

beforeEach(() => {
  sessions = [];
  commands = [];
  db = new LinkDouble(() => sessions, () => commands);
});

function addSession(over: Row = {}): Row {
  const row: Row = {
    instance_id: A, source_id: 46797, session_key: "455", interactive: 1,
    opened_at: "2026-10-05 06:52:54.000000", closed_at: "2026-10-05 09:59:06.000000",
    ...over,
  };
  sessions.push(row);
  return row;
}

let nextCommand = 1;
function addCommand(over: Row = {}): Row {
  const row: Row = {
    instance_id: A, source_id: nextCommand++, session_source_id: null,
    session_key: "455", ts: "2026-10-05 07:10:00.000000", ...over,
  };
  commands.push(row);
  return row;
}

const linked = (r: Row) => r.session_source_id;

test("comenzile sosite ÎNAINTEA sesiunii sunt legate când sesiunea sosește", async () => {
  // Plângerea, în cea mai scurtă formă a ei. Comenzile au plecat de pe gazdă cu
  // `session_id` NULL; sesiunea ajunge după. Înainte, rândurile rămâneau NULL
  // pentru totdeauna și detaliul sesiunii era gol.
  const c1 = addCommand({ ts: "2026-10-05 06:52:55.000000" });
  const c2 = addCommand({ ts: "2026-10-05 08:00:00.000000" });
  addSession();

  const report = await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [] });

  assert.equal(linked(c1), 46797);
  assert.equal(linked(c2), 46797);
  assert.equal(report.windows, 1);
});

test("o comandă nouă din lot își găsește sesiunea deja existentă", async () => {
  addSession();
  const c = addCommand();
  const report = await relinkAfterIngest(db, A, { sessionIds: [], commandIds: [c.source_id as number] });
  assert.equal(linked(c), 46797);
  assert.equal(report.linked, 1);
  assert.equal(report.stillUnlinked, 0);
});

test("o comandă fără nicio sesiune rămâne NULL și raportul o numără", async () => {
  // Orfanele reale ale gazdei (151 661 azi): nu există sesiune căreia să-i
  // aparțină, iar „nu știu" nu devine o legătură inventată.
  const c = addCommand({ session_key: "485", ts: "2026-08-24 14:36:41.000000" });
  addSession();
  const report = await relinkAfterIngest(db, A, { sessionIds: [], commandIds: [c.source_id as number] });
  assert.equal(linked(c), null);
  assert.equal(report.linked, 0);
  assert.equal(report.stillUnlinked, 1);
});

test("aceeași cheie dar în afara intervalului NU se leagă (cheia singură nu ajunge)", async () => {
  // Comanda de azi cu cheia 455, sesiunea 455 din august. Legată doar pe cheie,
  // fapta de azi a unei persoane ar ajunge în cronologia alteia.
  addSession({ source_id: 10, opened_at: "2026-08-24 13:48:50.000000",
               closed_at: "2026-08-24 13:48:52.000000" });
  const c = addCommand({ ts: "2026-10-05 07:10:00.000000" });
  await relinkAfterIngest(db, A, { sessionIds: [10], commandIds: [c.source_id as number] });
  assert.equal(linked(c), null);
});

test("marginea de un minut cuprinde comanda ajunsă puțin înaintea logării", async () => {
  addSession();
  const before = addCommand({ ts: "2026-10-05 06:51:55.000000" });   // −59 s
  const tooEarly = addCommand({ ts: "2026-10-05 06:51:53.000000" }); // −61 s
  const after = addCommand({ ts: "2026-10-05 10:00:05.000000" });    // +59 s
  const tooLate = addCommand({ ts: "2026-10-05 10:00:07.000000" });  // +61 s
  await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [] });
  assert.deepEqual([before, tooEarly, after, tooLate].map(linked),
                   [46797, null, 46797, null]);
});

test("un rând deja legat de gazdă NU se atinge", async () => {
  // Gazda știe mai bine decât orice derivare de aici. `IS NULL` din instrucțiune
  // e ce apără legătura ei — și ce face rularea repetabilă.
  addSession();
  const owned = addCommand({ session_source_id: 99 });
  await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [] });
  assert.equal(linked(owned), 99);
});

test("o altă instanță cu aceeași cheie și aceeași oră nu e atinsă", async () => {
  // `source_id` și `session_key` se repetă între gazde. Fără `instance_id` în
  // instrucțiune, comenzile unui server ar intra în sesiunea altuia.
  addSession();
  const theirs = addCommand({ instance_id: B });
  await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [] });
  assert.equal(linked(theirs), null);
  assert.ok(db.updates.every((u) => u.params.includes(A) && !u.params.includes(B)));
});

test("suprapunerea nu se rezolvă prin alegere: comenzile rămân NULL și se raportează", async () => {
  addSession({ source_id: 2482, session_key: "458",
               opened_at: "2026-08-24 13:54:50.000000", closed_at: "2026-08-24 13:54:51.000000" });
  addSession({ source_id: 2483, session_key: "458",
               opened_at: "2026-08-24 13:54:51.000000", closed_at: "2026-08-24 13:54:51.000000" });
  const c = addCommand({ session_key: "458", ts: "2026-08-24 13:54:50.500000" });
  const report = await relinkAfterIngest(db, A, { sessionIds: [2482, 2483],
                                                   commandIds: [c.source_id as number] });
  assert.equal(linked(c), null);
  assert.deepEqual(report.ambiguous.sort(), [2482, 2483]);
  assert.equal(db.updates.length, 0);
});

test("o sesiune încă deschisă leagă și comenzile de după, fără margine superioară", async () => {
  addSession({ closed_at: null });
  const late = addCommand({ ts: "2026-10-05 20:00:00.000000" });
  await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [] });
  assert.equal(linked(late), 46797);
  assert.ok(!db.updates[0].sql.includes("ts <="),
            "o sesiune deschisă nu are margine superioară");
});

test("un lot de comenzi nu reciteste tot intervalul unei sesiuni pe care n-a atins-o", async () => {
  // Fiecare lot dintr-o sesiune lungă ar rescana, pentru aceeași cheie, tot
  // intervalul ei. Sesiunea găsită doar prin comenzi se leagă numai în fereastra
  // lotului.
  addSession();
  const inBatch = addCommand({ ts: "2026-10-05 07:00:00.000000" });
  await relinkAfterIngest(db, A, { sessionIds: [], commandIds: [inBatch.source_id as number] });
  const [update] = db.updates;
  assert.equal(update.params[3], "2026-10-05 07:00:00.000");
  assert.equal(update.params[4], "2026-10-05 07:00:00.000");
});

test("un lot gol nu scrie nimic", async () => {
  addSession();
  addCommand();
  const report = await relinkAfterIngest(db, A, { sessionIds: [], commandIds: [] });
  assert.equal(db.updates.length, 0);
  assert.equal(report.keys, 0);
});

test("o a doua trecere peste aceleași rânduri nu schimbă nimic", async () => {
  addSession();
  const c = addCommand();
  await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [c.source_id as number] });
  const first = linked(c);
  const again = await relinkAfterIngest(db, A, { sessionIds: [46797], commandIds: [c.source_id as number] });
  assert.equal(linked(c), first);
  assert.equal(again.linked, 0);
});

// ---------------------------------------------------------------------------
// Istoricul
// ---------------------------------------------------------------------------
const NOW = Date.UTC(2026, 9, 5, 12, 0, 0);

test("uscat: numără ce ar lega și nu scrie nimic", async () => {
  addSession();
  addCommand({ ts: "2026-10-05 07:00:00.000000" });
  addCommand({ ts: "2026-10-05 08:00:00.000000" });
  addCommand({ session_key: "999" });

  const [r] = await backfill(db, { instanceId: A, apply: false, automationDays: 14, now: () => NOW });
  assert.equal(r.wouldLink, 2);
  assert.equal(r.unlinkedBefore, 3);
  assert.equal(r.unlinkedAfter, 3, "uscat înseamnă că baza n-are cum să se fi schimbat");
  assert.equal(db.updates.length, 0);
  assert.ok(commands.every((c) => c.session_source_id === null));
});

test("cu apply: ce s-a numărat e ce s-a legat, verificat prin recitirea bazei", async () => {
  addSession();
  addCommand({ ts: "2026-10-05 07:00:00.000000" });
  addCommand({ ts: "2026-10-05 08:00:00.000000" });
  addCommand({ session_key: "999" });

  const [r] = await backfill(db, { instanceId: A, apply: true, automationDays: 14, now: () => NOW });
  assert.equal(r.unlinkedBefore - r.unlinkedAfter, r.wouldLink);
  assert.equal(r.wouldLink, 2);
  assert.equal(r.unlinkedAfter, 1, "orfana fără sesiune rămâne orfană");
});

test("a doua rulare nu are nimic de legat", async () => {
  addSession();
  addCommand();
  await backfill(db, { apply: true, automationDays: 14, now: () => NOW });
  const [again] = await backfill(db, { apply: true, automationDays: 14, now: () => NOW });
  assert.equal(again.wouldLink, 0);
  assert.equal(again.unlinkedBefore, again.unlinkedAfter);
});

test("spune ce va tăia retenția după legare: sesiunile fără terminal mai vechi de 14 zile", async () => {
  // Rândurile NULL nu intră sub politica de 14 zile (`session_source_id IN
  // (… interactive = 0)` nu le prinde). Legate, intră. Operatorul trebuie să
  // știe ÎNAINTE să apese `--apply`.
  addSession({ source_id: 1, session_key: "20", interactive: 0,
               opened_at: "2026-09-01 10:00:00.000000", closed_at: "2026-09-01 10:00:05.000000" });
  addCommand({ session_key: "20", ts: "2026-09-01 10:00:02.000000" });
  addCommand({ session_key: "20", ts: "2026-09-01 10:00:03.000000" });
  addSession({ source_id: 2, session_key: "21", interactive: 1,
               opened_at: "2026-09-01 11:00:00.000000", closed_at: "2026-09-01 11:00:05.000000" });
  addCommand({ session_key: "21", ts: "2026-09-01 11:00:02.000000" });
  addSession({ source_id: 3, session_key: "22", interactive: 0,
               opened_at: "2026-10-05 11:00:00.000000", closed_at: "2026-10-05 11:00:05.000000" });
  addCommand({ session_key: "22", ts: "2026-10-05 11:00:02.000000" });

  const [r] = await backfill(db, { instanceId: A, apply: false, automationDays: 14, now: () => NOW });
  assert.equal(r.wouldLink, 4);
  assert.equal(r.prunableByRetention, 2,
               "doar cele 2 ale sesiunii fără terminal de acum o lună");
});

test("fără --instance se parcurg toate instanțele, fiecare cu ale ei", async () => {
  addSession();
  addSession({ instance_id: B, source_id: 7 });
  const a = addCommand();
  const b = addCommand({ instance_id: B });
  const reports = await backfill(db, { apply: true, automationDays: 14, now: () => NOW });
  assert.deepEqual(reports.map((r) => r.instanceId).sort(), [A, B]);
  assert.equal(linked(a), 46797);
  assert.equal(linked(b), 7, "comanda lui B s-a legat de sesiunea lui B, nu de a lui A");
});

// ---------------------------------------------------------------------------
// Prin rută: pasul chiar e cuplat la ingestie
// ---------------------------------------------------------------------------
/**
 * `FakeServer` + instrucțiunile din `lib/session-links.ts`, evaluate de
 * `LinkDouble` peste ACELEAȘI rânduri pe care le-a scris ingestia. Fără asta,
 * ruta ar cădea pe „interogare neprevăzută" la primul lot cu sesiuni.
 */
class LinkingServer extends FakeServer {
  failUpdate = false;
  readonly links: LinkDouble;

  constructor() {
    super();
    this.links = new LinkDouble(
      () => [...this.tableRows("login_session_entries").values()],
      () => [...this.tableRows("session_command_entries").values()]);
  }

  override async query(sql: string, params: unknown[] = []): Promise<[unknown, unknown]> {
    const mine = sql.startsWith("UPDATE session_command_entries SET session_source_id")
      || sql.includes("session_source_id IS NULL")
      || sql.startsWith("SELECT source_id, session_key FROM login_session_entries")
      || sql.startsWith("SELECT source_id, session_key, interactive");
    if (!mine) return super.query(sql, params);
    this.asked.push(sql);
    if (sql.startsWith("UPDATE")) {
      if (this.failUpdate) throw new Error("serverul a refuzat interogarea");
      await this.links.run(sql, params);
      return [{ affectedRows: 1 }, []];
    }
    return [await this.links.all(sql, params), []];
  }
}

let server: LinkingServer;

async function withLinkingServer(): Promise<void> {
  await forgetServer();
  server = new LinkingServer();
  const { getPool } = await import("../lib/db");
  const { baseEnv } = await import("./sync-harness");
  baseEnv();
  getPool(() => server, {
    AGGREGATOR_DB_USER: "u", AGGREGATOR_DB_PASSWORD: "p", AGGREGATOR_DB_NAME: "d",
  });
}

afterEach(async () => { await forgetServer(); });

function sessionRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 46797, session_key: "455", username: "operator", auid: "1000",
    src_ip: "198.51.100.7", terminal: "pts0", interactive: true,
    opened_at: "2026-10-05T06:52:54+00:00", closed_at: "2026-10-05T09:59:06+00:00",
    closed_inferred: false, command_count: 2, sudo_count: 0,
    updated_at: "2026-10-05T09:59:07+00:00", ...over,
  };
}

function commandRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 1, session_id: null, session_key: "455", ts: "2026-10-05T07:10:00+00:00",
    username: "operator", exe: "/usr/bin/ls", argv: "ls -la", cwd: "/home",
    tty: "pts0", pid: 100, ppid: 99, success: true, ...over,
  };
}

test("prin rută: comenzile expediate cu NULL și sesiunea sosită după ele ajung legate", async () => {
  await withLinkingServer();

  // 1. Lotul de comenzi pleacă primul, cu `session_id` NULL — cum a plecat de pe
  //    gazdă pentru jumătate din rânduri. Sesiunea nu e încă în replică.
  const first = await POST(syncRequest({ payload: syncPayload({
    rows: { session_commands: [commandRow({ id: 1 }), commandRow({ id: 2, ts: "2026-10-05T08:00:00+00:00" })] } }) }));
  assert.equal(first.status, 200);
  const stored = () => [...server.tableRows("session_command_entries").values()];
  assert.deepEqual(stored().map((r) => r.session_source_id), [null, null],
                   "înainte de sesiune nu există nimic de care să se lege");

  // 2. Sesiunea sosește. Gazda a legat deja comenzile ei local, dar rândurile
  //    nu mai pleacă a doua oară — legătura trebuie făcută AICI.
  const second = await POST(syncRequest({ payload: syncPayload({
    batch_seq: 4472, rows: { login_sessions: [sessionRow()] } }) }));
  assert.equal(second.status, 200);
  assert.deepEqual(stored().map((r) => Number(r.session_source_id)), [46797, 46797],
                   "comenzile au rămas fără sesiune — exact defectul de 53 %");
  assert.ok(server.links.updates.length >= 1);
  assert.ok(server.links.updates.every((u) => u.params.includes(INSTANCE)));
});

test("prin rută: un lot de comenzi pentru o sesiune deja cunoscută le leagă pe loc", async () => {
  await withLinkingServer();
  await POST(syncRequest({ payload: syncPayload({ rows: { login_sessions: [sessionRow()] } }) }));
  const res = await POST(syncRequest({ payload: syncPayload({
    batch_seq: 4472, rows: { session_commands: [commandRow({ id: 5 })] } }) }));
  assert.equal(res.status, 200);
  const [row] = [...server.tableRows("session_command_entries").values()];
  assert.equal(Number(row.session_source_id), 46797);
});

test("prin rută: o legare care eșuează nu anulează ecoul unui lot valid, dar se scrie", async () => {
  // Rândurile sunt deja în arhivă, iar legătura se poate reface cu
  // `relink-session-commands`. Un `UPDATE` căzut n-are voie să facă expeditorul
  // să retrimită la nesfârșit un lot bun — dar nici să treacă fără urmă.
  await withLinkingServer();
  server.failUpdate = true;
  await POST(syncRequest({ payload: syncPayload({ rows: { session_commands: [commandRow({ id: 1 })] } }) }));

  const spy = captureError();
  try {
    const res = await POST(syncRequest({ payload: syncPayload({
      batch_seq: 4472, rows: { login_sessions: [sessionRow()] } }) }));
    assert.equal(res.status, 200);
    assert.deepEqual((await res.json() as { accepted: Record<string, number> }).accepted,
                     { login_sessions: 46797 });
  } finally {
    spy.restore();
  }
  assert.ok(spy.lines.some((l) => l.join(" ").includes("n-au putut fi legate")),
            "eșecul legării a trecut fără nicio urmă în jurnal");
});

test("prin rută: un lot fără sesiuni sau comenzi nu declanșează nicio legare", async () => {
  await withLinkingServer();
  const res = await POST(syncRequest());
  assert.equal(res.status, 200);
  assert.equal(server.links.asked.length, 0);
});
