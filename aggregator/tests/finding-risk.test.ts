/**
 * Semaforul unei constatări, pe agregator: ce arată pagina și ce NU are voie să
 * arate.
 *
 * Eșecurile pe care le previne, în termenii operatorului:
 *
 *   * un rând fără date (sosit înainte de migrație, sau cu o culoare pe care
 *     vocabularul nu o cunoaște) afișat VERDE — „în regulă" despre ceva ce
 *     nimeni n-a evaluat;
 *   * un rând roșu de pe un server care apare pe pagina altuia, sau o pastilă
 *     „🔴 2" care adună roșul ambelor — două gazde nu se amestecă;
 *   * ordinea listei după altceva decât banda semaforului: un verde cu EPSS mare
 *     deasupra unui roșu.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as vulnGet } from "../app/panel/vulnerabilitati/route";
import { GET as panelGet } from "../app/panel/route";
import { grantInstance } from "../lib/auth/accounts";
import {
  COLOR_ORDER, COLORS, countColors, fmtCvss, fmtEpss, greyReason, headline,
  oneLiner, parseRisk, riskView, toColor,
} from "../lib/finding-risk";
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
  const result = await grantInstance(fixture.db, USERNAME, instanceId, "owner");
  assert.equal(result.ok, true);
}

const RISK_RED = JSON.stringify({
  v: 1, decision: "act", cve: "CVE-2026-0001",
  points: { exploitation: { value: "active", basis: "vulnrichment", as_of: "2026-09-18" },
            automatable: { value: "yes", basis: "cvss_vector" },
            technical_impact: { value: "total", basis: "cvss_vector" },
            mission: { value: "medium", basis: "asset_criticality" } },
  cvss: { source: "trivy", score: 9.1 }, epss: { p: 0.99225, percentile: 0.99936 },
});
const RISK_GREY = JSON.stringify({
  v: 1, decision: null, missing: ["vulnrichment"], possible: ["track", "attend"],
});

// ---------------------------------------------------------------------------
// Pur: ce se citește dintr-un rând
// ---------------------------------------------------------------------------
test("o culoare necunoscută sau lipsă e GRI, niciodată verde", () => {
  for (const bad of [undefined, null, "", "purple", "GREEN", 3, {}, "green "]) {
    assert.equal(toColor(bad), "grey", `culoare ${String(bad)} nu a căzut pe gri`);
  }
  for (const ok of COLORS) assert.equal(toColor(ok), ok);
});

test("un rând fără `risk` (sosit înainte de migrație) e gri și spune că n-a fost evaluat", () => {
  const v = riskView({ risk_color: "grey", risk_decision: null, risk: null });
  assert.equal(v.color, "grey");
  assert.equal(v.greyReason, "încă neevaluată");
  assert.equal(v.headline, "⚪ fără date");
});

test("culoarea și decizia care nu se potrivesc strică rândul în GRI, nu în ce crede una din ele", () => {
  // `risk_color=green` cu `risk_decision=act` nu există pe server (CHECK), deci
  // ajunge aici doar prin coruperea unui rând. Citit după culoare ar fi verde.
  const v = riskView({ risk_color: "green", risk_decision: "act", risk: RISK_RED });
  assert.equal(v.color, "grey");
  assert.equal(v.decision, null);
});

test("decizia lipsă la o culoare cu decizie e tot gri", () => {
  assert.equal(riskView({ risk_color: "red", risk_decision: null, risk: RISK_RED }).color, "grey");
  assert.equal(riskView({ risk_color: "green", risk_decision: "bogus", risk: RISK_RED }).color, "grey");
});

test("un `risk` care nu e JSON nu aruncă și nu se afișează", () => {
  for (const raw of ["{not json", "[]", "5", "null", "\"x\""]) {
    const v = riskView({ risk_color: "grey", risk_decision: null, risk: raw });
    assert.equal(v.color, "grey");
    assert.equal(typeof v.oneLiner, "string");
  }
  assert.equal(parseRisk("{not json"), null);
});

test("headline, motivul scurt și motivul griului spun ce spune și serverul", () => {
  assert.equal(headline("red", "act"), "🔴 Act — acum");
  assert.equal(headline("amber", "attend"), "🟡 Attend — accelerat");
  assert.equal(headline("green", "track_star"), "🟢 Track* — de urmărit");
  assert.equal(headline("green", "track"), "🟢 Track — ciclul obișnuit");
  assert.equal(headline("grey", null), "⚪ fără date");
  assert.equal(greyReason(parseRisk(RISK_GREY)),
    "lipsește punctele CISA (CVE-ul nu a fost încă întrebat); ar putea fi între Track și Attend");
  assert.equal(oneLiner("grey", parseRisk(RISK_GREY)), "fără date CISA");
  // Motivul unui rând roșu: cine a spus că se exploatează, nu probabilitatea.
  assert.equal(oneLiner("red", parseRisk(RISK_RED)), "CISA: exploatat");
  // Un CVE pe care CISA l-a evaluat `none` nu are motiv de exploatare: arată EPSS,
  // informativ, ca până acum.
  const none = JSON.stringify({ points: { exploitation: { value: "none", basis: "vulnrichment" } },
                                epss: { p: 0.99225 } });
  assert.equal(oneLiner("green", parseRisk(none)), "EPSS 99,2%");
  assert.equal(oneLiner("grey", { missing: ["exploitation_unpublished"] }), "CISA n-a evaluat");
});

const RISK_OVERLAY = JSON.stringify({
  v: 1, decision: "attend",
  points: { exploitation: { value: "none", basis: "vulnrichment", as_of: "2025-04-08" } },
  epss: { p: 0.99225, percentile: 0.99936 },
  overlay: { basis: "epss_overlay", floor: "attend", ssvc_decision: "track", epss: 0.99225,
             observation_as_of: "2025-04-08", observation_age_days: 542,
             min_epss: 0.5, min_age_days: 180 },
});

test("un galben urcat de regula Sentinel nu trece drept decizie SSVC pe agregator", () => {
  // Eșecul: un 🟡 pe care arborele nu l-a dat, afișat ca orice Attend. Eticheta și
  // motivul poartă numele Sentinel, iar o înregistrare rămasă pe o culoare care nu
  // e galbenă nu pune eticheta pe un verde sau pe un roșu.
  const v = riskView({ risk_color: "amber", risk_decision: "attend", risk: RISK_OVERLAY });
  assert.equal(v.color, "amber");
  assert.equal(v.headline, "🟡 Attend — accelerat (regula Sentinel, nu SSVC)");
  assert.equal(v.oneLiner, "regula Sentinel (EPSS)");
  const plain = riskView({ risk_color: "amber", risk_decision: "attend",
                           risk: JSON.stringify({ points: { exploitation: { value: "active", basis: "kev" } } }) });
  assert.equal(plain.headline, "🟡 Attend — accelerat");
  assert.equal(plain.oneLiner, "KEV");
  const stray = riskView({ risk_color: "green", risk_decision: "track", risk: RISK_OVERLAY });
  assert.ok(!stray.headline.includes("Sentinel"), stray.headline);
  assert.notEqual(stray.oneLiner, "regula Sentinel (EPSS)");
  assert.equal(headline("amber", "attend", { overlay: { basis: "altceva" } }), "🟡 Attend — accelerat");
});

test("pagina agregatorului spune pe rând și în notă că un galben e al regulii Sentinel", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-REGULA", priority: 77,
    risk_color: "amber", risk_decision: "attend", risk: RISK_OVERLAY, risk_score: 0.9 });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-OBISNUIT", priority: 60,
    risk_color: "amber", risk_decision: "attend", risk_score: 0.5 });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  // Celula „Risc" stă înaintea celulei CVE: rândul se taie de la `<tr` care îl deschide.
  const row = (cve: string) => {
    const at = html.indexOf(`>${cve}<`);
    assert.ok(at > 0, `${cve} lipsește din pagină`);
    return html.slice(html.lastIndexOf("<tr", at), html.indexOf("</tr>", at));
  };
  assert.ok(row("CVE-REGULA").includes("regula Sentinel, nu SSVC"), "rândul nu poartă eticheta");
  assert.ok(row("CVE-REGULA").includes("regula Sentinel (EPSS)"));
  assert.ok(!row("CVE-OBISNUIT").includes("Sentinel"), "eticheta a trecut pe un Attend obișnuit");
  assert.ok(html.includes("Singura excepție, a Sentinel și nu a SSVC"), "nota paginii nu spune excepția");
});

test("EPSS: probabilitatea întreagă cu percentilă, niciodată rotunjită la zero", () => {
  assert.equal(fmtEpss("0.0045", "0.3682"), "0,45% (percentila 37)");
  assert.equal(fmtEpss(0.153, 0.92), "15,3% (percentila 92)");
  assert.equal(fmtEpss(0.0005), "0,05%");
  assert.equal(fmtEpss(0.00004), "<0,01%");
  assert.equal(fmtEpss(null), "fără EPSS");
  assert.equal(fmtEpss("garbage"), "fără EPSS");
  // Jumătățile exacte se rotunjesc în sus, ca în Python (`risk_view._half_up`).
  assert.equal(fmtEpss(0.1225), "12,3%");
  assert.equal(fmtEpss(0.00125), "0,13%");
  // Decimal ties a binary `toFixed` rounds the other way (0.145 -> "0.14").
  assert.equal(fmtEpss(0.00145), "0,15%");
  assert.equal(fmtEpss(0.00405), "0,41%");
  assert.equal(fmtEpss(0.00615), "0,62%");
});

test("CVSS: numește sursa care a decis", () => {
  assert.equal(fmtCvss({ score: 3.1, source: "redhat" }), "CVSS 3,1 (Red Hat)");
  assert.equal(fmtCvss({ score: 7.5, source: "trivy" }), "CVSS 7,5 (trivy)");
  assert.equal(fmtCvss(null), "fără CVSS");
});

test("culorile se numără toate, cu zero unde nu e nimic, iar necunoscutul cade pe gri", () => {
  const c = countColors([{ risk_color: "red" }, { risk_color: "weird" }, { risk_color: null }]);
  assert.deepEqual(c, { red: 1, amber: 0, green: 0, grey: 2 });
  assert.ok(COLOR_ORDER.red < COLOR_ORDER.amber && COLOR_ORDER.amber < COLOR_ORDER.grey
            && COLOR_ORDER.grey < COLOR_ORDER.green, "gri trebuie să stea deasupra lui verde");
});

// ---------------------------------------------------------------------------
// Pagina
// ---------------------------------------------------------------------------
test("lista e ordonată după banda semaforului, apoi după scor, indiferent de ordinea sosirii",
     async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-VERDE", priority: 12,
    risk_color: "green", risk_decision: "track", epss: "0.9", risk_score: 0.9 });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-GRI", priority: 45,
    risk_color: "grey", risk_decision: null, risk: RISK_GREY });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, cve: "CVE-ROSU", priority: 95,
    risk_color: "red", risk_decision: "act", risk: RISK_RED, risk_score: 0.9 });
  fixture.db.addFinding(INSTANCE_A, { source_id: 4, cve: "CVE-GALBEN-MARE", priority: 70,
    risk_color: "amber", risk_decision: "attend", risk_score: 0.5 });
  fixture.db.addFinding(INSTANCE_A, { source_id: 5, cve: "CVE-GALBEN-MIC", priority: 70,
    risk_color: "amber", risk_decision: "attend", risk_score: 0.1 });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const at = (cve: string) => html.indexOf(cve);
  const order = ["CVE-ROSU", "CVE-GALBEN-MARE", "CVE-GALBEN-MIC", "CVE-GRI", "CVE-VERDE"];
  for (const cve of order) assert.ok(at(cve) > 0, `${cve} lipsește`);
  const positions = order.map(at);
  assert.deepEqual([...positions].sort((a, b) => a - b), positions,
    `ordinea nu e roșu, galben (scor mare întâi), gri, verde: ${order.join(" < ")}`);
});

test("vederea implicită nu poate fi 200 de rânduri rezolvate cât timp există rânduri deschise",
     async () => {
  // O constatare rezolvată nu mai e reexpediată, deci își păstrează pe veci
  // `priority`-ul vechi: pe producție, 6.684 de rânduri rezolvate au ≥ 40 și
  // 4.499 au ≥ 80, iar un rând deschis verde are 0–20. Ordonată doar după
  // `priority`, pagina „Toate" (limita e 200) arăta 200 de rezolvate și nicio
  // constatare care cere ceva — operatorul ar fi citit „nimic de făcut".
  await grant(INSTANCE_A);
  for (let i = 1; i <= 205; i++) {
    fixture.db.addFinding(INSTANCE_A, { source_id: i, cve: `CVE-INCHIS-${i}`,
      priority: 80 + (i % 20), status: "resolved", risk_color: "grey" });
  }
  fixture.db.addFinding(INSTANCE_A, { source_id: 1001, cve: "CVE-DESCHIS-VERDE",
    priority: 0, status: "open", risk_color: "green", risk_decision: "track",
    risk_score: 0.01 });
  fixture.db.addFinding(INSTANCE_A, { source_id: 1002, cve: "CVE-DESCHIS-GRI",
    priority: 40, status: "open", risk_color: "grey", risk: RISK_GREY });
  fixture.db.addFinding(INSTANCE_A, { source_id: 1003, cve: "CVE-AMANAT",
    priority: 10, status: "deferred", risk_color: "green", risk_decision: "track" });
  const cookies = await signIn();

  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati", { cookies }))).text();
  const firstClosed = html.indexOf("CVE-INCHIS-");
  assert.ok(firstClosed > 0, "pagina implicită n-are niciun rând rezolvat: testul n-a pus presiune");
  for (const cve of ["CVE-DESCHIS-VERDE", "CVE-DESCHIS-GRI", "CVE-AMANAT"]) {
    const at = html.indexOf(cve);
    assert.ok(at > 0, `${cve} (deschis) lipsește din pagina implicită, deși sunt 205 rezolvate`);
    assert.ok(at < firstClosed, `${cve} stă după un rând rezolvat`);
  }
  // Neaplicatele își păstrează ordinea dintre ele: gri (40) înaintea verdelui (0).
  assert.ok(html.indexOf("CVE-DESCHIS-GRI") < html.indexOf("CVE-DESCHIS-VERDE"));

  // Grupa „rezolvate" rămâne ce era: doar rezolvate.
  const closed = await (await vulnGet(getRequest(
    "/panel/vulnerabilitati?grupa=rezolvate", { cookies }))).text();
  assert.ok(closed.includes("CVE-INCHIS-") && !closed.includes("CVE-DESCHIS-VERDE"));
});

test("pastilele de culoare numără ce e în tabel, gri apare mereu, iar `?culoare=` filtrează",
     async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-R", priority: 90,
    risk_color: "red", risk_decision: "act", risk: RISK_RED });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-V1", priority: 10,
    risk_color: "green", risk_decision: "track" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, cve: "CVE-V2", priority: 10,
    risk_color: "green", risk_decision: "track" });
  const cookies = await signIn();

  const all = await (await vulnGet(getRequest("/panel/vulnerabilitati", { cookies }))).text();
  assert.match(all, /🔴 roșu <span class="nr">1<\/span>/);
  assert.match(all, /⚪ gri <span class="nr">0<\/span>/, "gri trebuie să apară chiar și cu zero");
  assert.match(all, /🟢 verde <span class="nr">2<\/span>/);

  const red = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=red", { cookies }))).text();
  assert.ok(red.includes("CVE-R") && !red.includes("CVE-V1"), "filtrul pe roșu arată și verzi");
  const green = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=green", { cookies }))).text();
  assert.ok(green.includes("CVE-V1") && !green.includes("CVE-R"));

  const nonsense = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=purple", { cookies }))).text();
  assert.ok(nonsense.includes("CVE-R") && nonsense.includes("CVE-V1"),
    "o culoare inventată trebuie să arate tot, nu un ecran gol");
});

test("un rând cu culoare necunoscută sau fără evaluare apare GRI și cu motivul, nu verde", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-NECUNOSCUT", priority: 50,
    risk_color: "purple", risk_decision: null });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-NEEVALUAT", priority: 40 });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  assert.ok(!html.includes("🟢 Track"), "un rând fără date apare ca Track verde");
  assert.equal((html.match(/⚪ fără date/g) ?? []).length, 2);
  assert.ok(html.includes("încă neevaluată"));
  assert.match(html, /⚪ gri <span class="nr">2<\/span>/);
});

test("două gazde care nu sunt de acord asupra aceluiași CVE: fiecare pagină arată verdictul gazdei ei",
     async () => {
  // A: CVE-X deschis și roșu. B: același CVE, reparat. Nicio pagină nu o ia pe
  // cealaltă drept adevăr: pe pagina lui B nu apare roșul lui A, pe a lui A nu
  // apare reparația lui B, iar pastila „🔴" a unuia nu adună roșul celuilalt.
  await grant(INSTANCE_A);
  await grant(INSTANCE_B);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-X", priority: 90,
    status: "open", risk_color: "red", risk_decision: "act", risk: RISK_RED });
  fixture.db.addFinding(INSTANCE_B, { source_id: 1, cve: "CVE-X", priority: 90,
    status: "resolved", risk_color: "red", risk_decision: "act", risk: RISK_RED });
  fixture.db.addFinding(INSTANCE_B, { source_id: 2, cve: "CVE-Y", priority: 10,
    status: "open", risk_color: "green", risk_decision: "track" });
  const cookies = await signIn();

  const a = await (await vulnGet(getRequest(
    `/panel/vulnerabilitati?instanta=${INSTANCE_A}&grupa=neaplicate`, { cookies }))).text();
  const b = await (await vulnGet(getRequest(
    `/panel/vulnerabilitati?instanta=${INSTANCE_B}&grupa=neaplicate`, { cookies }))).text();
  assert.match(a, /🔴 roșu <span class="nr">1<\/span>/);
  assert.ok(a.includes("CVE-X") && !a.includes("CVE-Y"));
  assert.match(b, /🔴 roșu <span class="nr">0<\/span>/,
    "reparația de pe B nu poate lăsa roșul lui A pe pagina lui B");
  assert.ok(!b.includes("CVE-X"), "CVE-X rezolvat pe B apare ca neaplicat");
  assert.ok(b.includes("CVE-Y"));
  // Rezolvat e rezolvat, cu rândul lui, la gazda lui — nu e „vindecat" de A.
  const bAll = await (await vulnGet(getRequest(
    `/panel/vulnerabilitati?instanta=${INSTANCE_B}&grupa=rezolvate`, { cookies }))).text();
  assert.ok(bAll.includes("CVE-X") && bAll.includes("resolved"));
});

test("textul din `risk` care ar fi marcaj nu ajunge ca marcaj", async () => {
  await grant(INSTANCE_A);
  const hostile = JSON.stringify({
    v: 1, decision: null, missing: ["<img src=x onerror=alert(1)>"],
    possible: ["<script>", "track"],
  });
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-H", priority: 40,
    risk_color: "grey", risk_decision: null, risk: hostile });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  assert.ok(!html.includes("<img src=x"), "marcajul din `risk` a ajuns în pagină");
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;img"));
});

test("cardul de pe prima pagină spune câte sunt roșii, galbene și FĂRĂ DATE", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, status: "open", priority: 90,
    risk_color: "red", risk_decision: "act" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, status: "open", priority: 40,
    risk_color: "grey" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, status: "resolved", priority: 90,
    risk_color: "red", risk_decision: "act" });   // închis: nu se numără
  const html = await (await panelGet(getRequest("/panel", { cookies: await signIn() }))).text();
  assert.ok(html.includes("1 roșii · 0 galbene · 1 fără date"),
    "cardul nu spune culorile constatărilor deschise");
});

test("un rând închis nu e desenat „fără date”, iar pastilele nu numără rezolvatele", async () => {
  // Serverul nu mai evaluează o constatare rezolvată: ea rămâne cu culoarea
  // implicită (gri). Pe producție sunt ~6.700 de rânduri `dnf` rezolvate — numărate
  // la „fără date”, ar îngropa cele câteva zeci de gri care contează.
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-DESCHIS", priority: 90,
    status: "open", risk_color: "red", risk_decision: "act", risk: RISK_RED });
  for (let i = 2; i < 8; i++) {
    fixture.db.addFinding(INSTANCE_A, { source_id: i, cve: `CVE-INCHIS-${i}`, priority: 83,
      status: "resolved", risk_color: "grey" });
  }
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  assert.match(html, /⚪ gri <span class="nr">0<\/span>/,
    "rezolvatele au fost numărate ca „fără date”");
  assert.match(html, /🔴 roșu <span class="nr">1<\/span>/);
  assert.equal((html.match(/— \(resolved\)/g) ?? []).length, 6,
    "un rând rezolvat nu spune că e rezolvat");
  const risky = html.split("<tr").filter((r) => r.includes("CVE-INCHIS-2"))[0];
  assert.ok(!risky.includes("⚪ fără date"), "un rând rezolvat apare ca fără date");
});

test("o constatare în curs de patch-uire sau amânată e încă a semaforului", async () => {
  // Cele patru stări „neaplicate” (`GROUPS.neaplicate`) sunt evaluate pe server;
  // doar rezolvatele și cele închise fără reparație nu mai sunt.
  await grant(INSTANCE_A);
  for (const [i, status] of ["patch_planned", "patching", "deferred"].entries()) {
    fixture.db.addFinding(INSTANCE_A, { source_id: i + 1, cve: `CVE-${status}`, priority: 95,
      status, risk_color: "red", risk_decision: "act", risk: RISK_RED });
  }
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  assert.equal((html.match(/🔴 Act — acum/g) ?? []).length, 3,
    "o stare neaplicată a fost tratată ca închisă");
  assert.match(html, /🔴 roșu <span class="nr">3<\/span>/);
});

test("a cere o culoare restrânge lista la neaplicate, peste orice `?grupa=`", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-GRI-DESCHIS", priority: 45,
    status: "open", risk_color: "grey", risk: RISK_GREY });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-GRI-INCHIS", priority: 83,
    status: "resolved", risk_color: "grey" });
  const html = await (await vulnGet(getRequest(
    "/panel/vulnerabilitati?culoare=grey&grupa=rezolvate", { cookies: await signIn() }))).text();
  assert.ok(html.includes("CVE-GRI-DESCHIS"));
  assert.ok(!html.includes("CVE-GRI-INCHIS"),
    "filtrul pe culoare a lăsat să treacă un rând rezolvat");
});
