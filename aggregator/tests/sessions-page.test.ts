/**
 * Pagina de sesiuni: lista duce la detaliu, iar detaliul arată TOATE comenzile.
 *
 * Plângerile operatorului, 5 octombrie 2026: «comenzile nu apar în sesiuni pe
 * panoul de pe agregator · nu mai am posibilitatea să văd detaliat toate
 * comenzile dintr-o sesiune».
 *
 * Două cauze separate, ambele în ce a văzut operatorul:
 *
 *   * jumătate din comenzi n-aveau legătura cu sesiunea lor — vezi
 *     `tests/session-links.test.ts`;
 *   * și cele care aveau-o se arătau numai primele 500. O sesiune cu 22 368 de
 *     comenzi trimitea restul «în baza de pe gazdă», adică nicăieri.
 *
 * Testele de aici prind a doua cauză și felul în care pagina spune ce NU arată.
 * Trec prin rută, cu un cont autentificat de-adevăratelea; dublul de bază nu e
 * MariaDB (vezi nota din `tests/auth-harness.ts`), deci ce se dovedește e
 * purtarea codului nostru, nu sintaxa `LIMIT … OFFSET …` pe server.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as sesiuniGet } from "../app/panel/sesiuni/route";
import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { COMMANDS_SHOWN, sessionDetail } from "../lib/data/logins";
import {
  PASSWORD, USERNAME, captureError, captureWarn, completeLogin,
  forgetAuthServer, getRequest, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture } from "./auth-routes-harness";

const HANDLERS = { loginGet, loginPost, totpGet, totpPost };
const INSTANCE_A = "prod-a";
const INSTANCE_B = "prod-b";

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
  fixture.db.addInstance(INSTANCE_A, { label: "Serverul A" });
  fixture.db.addInstance(INSTANCE_B, { label: "Serverul B" });
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

async function signIn(): Promise<Record<string, string>> {
  const token = await completeLogin(HANDLERS, {
    username: USERNAME, password: PASSWORD, totpSecret: fixture.totpSecret,
  });
  return { sentinel_session: token };
}

async function grant(instanceId: string): Promise<void> {
  assert.equal((await grantInstance(fixture.db, USERNAME, instanceId, "owner")).ok, true);
}

/** O sesiune cu `n` comenzi LEGATE de ea, numerotate `cmd-0001` … */
function seedSession(n: number, over: Record<string, unknown> = {}): void {
  fixture.db.addLoginSession(INSTANCE_A, {
    source_id: 46797, session_key: "455", username: "operator",
    command_count: n, ...over,
  });
  for (let i = 1; i <= n; i++) {
    fixture.db.addSessionCommand(INSTANCE_A, {
      source_id: i, session_source_id: 46797,
      argv: `cmd-${String(i).padStart(5, "0")}`,
    });
  }
}

async function page(query: string, cookies: Record<string, string>): Promise<string> {
  const res = await sesiuniGet(getRequest(`/panel/sesiuni?${query}`, { cookies }));
  assert.equal(res.status, 200);
  return await res.text();
}

const argvsOf = (html: string): string[] =>
  [...html.matchAll(/cmd-\d{5}/g)].map((m) => m[0]);

// ---------------------------------------------------------------------------
// Lista duce la detaliu
// ---------------------------------------------------------------------------
test("în listă, numărul de comenzi e o legătură spre comenzile sesiunii", async () => {
  // Până acum numărul era text, iar singura cale spre detaliu era data
  // deschiderii — pe care nimic n-o arăta ca pe un buton. Operatorul vedea
  // «22368» și nu avea pe ce să apese.
  await grant(INSTANCE_A);
  seedSession(3);
  const html = await page("instanta=prod-a", await signIn());
  assert.match(html, /<td class="nr"><a href="[^"]*sesiune=46797[^"]*"[^>]*>3<\/a><\/td>/,
               "numărul de comenzi nu duce la detaliul sesiunii");
});

// ---------------------------------------------------------------------------
// Toate comenzile, pe pagini
// ---------------------------------------------------------------------------
test("o sesiune mai lungă decât o pagină se citește COMPLET, pe pagini", async () => {
  // Cu plafonul vechi (primele 500) o sesiune de 1 203 comenzi arăta 500 și
  // restul nu era nicăieri. Acum unirea paginilor e exact mulțimea comenzilor:
  // nici una pierdută, nici una arătată de două ori.
  await grant(INSTANCE_A);
  const total = COMMANDS_SHOWN * 2 + 203;
  seedSession(total);
  const cookies = await signIn();

  const seen: string[] = [];
  const pages = Math.ceil(total / COMMANDS_SHOWN);
  for (let p = 1; p <= pages; p++) {
    const html = await page(`instanta=prod-a&sesiune=46797&pagina=${p}`, cookies);
    const here = [...new Set(argvsOf(html))];
    assert.ok(here.length <= COMMANDS_SHOWN, `pagina ${p} a depășit ${COMMANDS_SHOWN}`);
    assert.ok(html.includes(`Pagina <strong>${p}</strong> din ${pages}`),
              `pagina ${p} nu spune unde e din ${pages}`);
    seen.push(...here);
  }
  const expected = Array.from({ length: total },
    (_v, i) => `cmd-${String(i + 1).padStart(5, "0")}`);
  assert.deepEqual(seen, expected,
                   "paginile, puse cap la cap, nu dau exact comenzile sesiunii");
});

test("pagina spune ce parte din total arată", async () => {
  await grant(INSTANCE_A);
  seedSession(COMMANDS_SHOWN + 7);
  const html = await page("instanta=prod-a&sesiune=46797&pagina=2", await signIn());
  assert.ok(html.includes(`comenzile ${COMMANDS_SHOWN + 1}–${COMMANDS_SHOWN + 7} din ${COMMANDS_SHOWN + 7}`),
            "pagina a doua nu spune ce interval de comenzi arată");
  assert.equal(argvsOf(html).length, 7, "pagina a doua trebuia să aibă exact cele 7 comenzi rămase");
});

test("legăturile dintre pagini păstrează serverul ales și comutatorul «toate»", async () => {
  // O legătură care pierde `instanta` te mută pe alt server în mijlocul unei
  // sesiuni; una care pierde `toate=1` face sesiunea de automatizare să dispară
  // din listă la prima pagină următoare.
  await grant(INSTANCE_A);
  seedSession(COMMANDS_SHOWN + 1, { terminal: "ssh", interactive: 0 });
  const html = await page("instanta=prod-a&sesiune=46797&toate=1", await signIn());
  const next = /<a href="([^"]*pagina=2[^"]*)">înainte ›<\/a>/.exec(html);
  assert.ok(next, "nu există legătura spre pagina următoare");
  const href = next![1].replace(/&amp;/g, "&");
  assert.ok(href.includes("instanta=prod-a"), `legătura a pierdut serverul: ${href}`);
  assert.ok(href.includes("sesiune=46797"), `legătura a pierdut sesiunea: ${href}`);
  assert.ok(href.includes("toate=1"), `legătura a pierdut «toate»: ${href}`);
});

test("o sesiune cu exact o pagină nu arată cârlige de paginare", async () => {
  await grant(INSTANCE_A);
  seedSession(COMMANDS_SHOWN);
  const html = await page("instanta=prod-a&sesiune=46797", await signIn());
  assert.ok(!html.includes("înainte ›"), "paginare pe o singură pagină");
  assert.equal(new Set(argvsOf(html)).size, COMMANDS_SHOWN);
});

test("o pagină inventată în URL duce la una care există, nu la un ecran gol", async () => {
  // O legătură pusă la favorite pe pagina 45 a unei sesiuni care între timp s-a
  // scurtat trebuie să ducă undeva. Ecranul gol ar spune «sesiunea n-a rulat
  // nimic» despre una care a rulat.
  await grant(INSTANCE_A);
  seedSession(COMMANDS_SHOWN + 3);
  const cookies = await signIn();

  const last = await page("instanta=prod-a&sesiune=46797&pagina=999", cookies);
  assert.deepEqual([...new Set(argvsOf(last))],
                   ["cmd-00501", "cmd-00502", "cmd-00503"]);
  for (const garbage of ["abc", "0", "-3", ""]) {
    const first = await page(`instanta=prod-a&sesiune=46797&pagina=${garbage}`, cookies);
    assert.ok(first.includes("cmd-00001"), `pagina «${garbage}» n-a dus la prima pagină`);
  }
});

// ---------------------------------------------------------------------------
// Ce lipsește, spus
// ---------------------------------------------------------------------------
test("gazda a numărat mai multe comenzi decât are replica: pagina spune câte lipsesc", async () => {
  // `command_count` e câte rânduri are GAZDA. Un tabel mai scurt, fără nicio
  // explicație, arată ca «atât s-a rulat».
  await grant(INSTANCE_A);
  seedSession(10, { command_count: 310 });
  const html = await page("instanta=prod-a&sesiune=46797", await signIn());
  assert.ok(html.includes("300 din 310 comenzi nu sunt în arhiva asta"),
            "diferența dintre gazdă și replică nu e spusă");
});

test("o sesiune completă nu capătă nicio notă de lipsă", async () => {
  await grant(INSTANCE_A);
  seedSession(10);
  const html = await page("instanta=prod-a&sesiune=46797", await signIn());
  assert.ok(!html.includes("nu sunt în arhiva asta"),
            "nota de lipsă pe o sesiune la care nu lipsește nimic e zgomot");
});

test("ce a șters curățarea nu se numără a doua oară ca lipsă", async () => {
  // 10 stocate + 300 curățate = 310 la gazdă: nu lipsește nimic neexplicat.
  await grant(INSTANCE_A);
  seedSession(10, { command_count: 310, commands_purged: 300 });
  const html = await page("instanta=prod-a&sesiune=46797", await signIn());
  assert.ok(html.includes("300 comenzi ale sesiunii au fost șterse"));
  assert.ok(!html.includes("nu sunt în arhiva asta"));
});

async function detailAt(now: number, over: Record<string, unknown>) {
  await grant(INSTANCE_A);
  seedSession(5, { command_count: 50, ...over });
  const scope = await scopeForUser(fixture.db, fixture.user.id);
  return await sessionDetail(fixture.db, scope, INSTANCE_A, 46797, 1, () => now);
}

const DAY = 86_400_000;
const T0 = Date.UTC(2026, 9, 5, 12, 0, 0);

test("o sesiune mai veche decât retenția: lipsa se pune pe seama retenției, cu zilele ei", async () => {
  // Interactivă: fereastra de 180 de zile, citită din `lib/retention.ts`.
  const old = await detailAt(T0, {
    opened_at: T0 - 200 * DAY, closed_at: T0 - 200 * DAY + 1000, interactive: 1 });
  assert.equal(old.missing, 45);
  assert.equal(old.missingWhy, "retention");
  assert.equal(old.retentionDays, 180);
});

test("fără terminal, fereastra e cea scurtă de 14 zile", async () => {
  const detail = await detailAt(T0, {
    opened_at: T0 - 20 * DAY, closed_at: T0 - 20 * DAY + 1000, interactive: 0 });
  assert.equal(detail.missingWhy, "retention");
  assert.equal(detail.retentionDays, 14);
});

test("o sesiune NOUĂ cu comenzi lipsă: «nu știu», nu o cauză inventată", async () => {
  // Poate fi curățarea, poate comenzi care n-au ajuns încă, poate legătura.
  // De aici nu se poate alege — și pagina nu pretinde că se poate.
  const fresh = await detailAt(T0, {
    opened_at: T0 - 2 * DAY, closed_at: T0 - 2 * DAY + 1000, interactive: 1 });
  assert.equal(fresh.missing, 45);
  assert.equal(fresh.missingWhy, "unknown");
  assert.equal(fresh.retentionDays, null);
});

test("o sesiune veche dar fără nicio comandă lipsă nu e explicată prin nimic", async () => {
  const done = await detailAt(T0, {
    command_count: 5, opened_at: T0 - 400 * DAY, closed_at: T0 - 400 * DAY + 1000 });
  assert.equal(done.missing, 0);
  assert.equal(done.missingWhy, null);
});

test("detaliul unei sesiuni a altei instanțe nu arată comenzile ei", async () => {
  await grant(INSTANCE_A);
  fixture.db.addLoginSession(INSTANCE_B, { source_id: 46797, command_count: 1 });
  fixture.db.addSessionCommand(INSTANCE_B, { source_id: 1, session_source_id: 46797,
                                             argv: "cmd-SECRET-al-lui-B" });
  const html = await page("instanta=prod-a&sesiune=46797", await signIn());
  assert.ok(!html.includes("cmd-SECRET-al-lui-B"));
});

test("totalul se numără ÎNAINTE de pagină: pagina cere LIMIT și OFFSET, nu toate rândurile", async () => {
  // O pagină care citește toate rândurile și le taie în JavaScript ar aduce
  // 405 000 de rânduri pentru a arăta 500.
  await grant(INSTANCE_A);
  seedSession(COMMANDS_SHOWN + 5);
  fixture.db.statements.length = 0;
  await page("instanta=prod-a&sesiune=46797&pagina=2", await signIn());
  const read = fixture.db.statements.find((s) => /FROM session_command_entries/.test(s.sql)
    && /ORDER BY source_id/.test(s.sql));
  assert.ok(read, "nu s-a citit pagina de comenzi");
  assert.match(read!.sql, /LIMIT \? OFFSET \?/);
  assert.deepEqual(read!.params.slice(-2), [COMMANDS_SHOWN, COMMANDS_SHOWN]);
});
