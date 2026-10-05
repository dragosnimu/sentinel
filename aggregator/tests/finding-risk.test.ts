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
  COLOR_ORDER, COLOR_STATE_RO, COLORS, DECISION_LABEL_RO, KEV_UNKNOWN_NOTE_RO, countColors, fmtCvss,
  fmtEpss, fmtKev, greyDetail, greyReason, headline, legendStates, parseRisk, pillTitle, reasonLine, riskView,
  ssvcName, toColor,
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
  assert.equal(v.headline, "⚪ Nedecis");
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
    assert.ok(v.reason === null || typeof v.reason === "string");
  }
  assert.equal(parseRisk("{not json"), null);
});

test("headline, motivul și motivul griului spun ce spune și serverul", () => {
  assert.equal(headline("red", "act"), "🔴 Acum");
  assert.equal(headline("amber", "attend"), "🟡 Curând");
  assert.equal(headline("green", "track_star"), "🟢 De urmărit*");
  assert.equal(headline("green", "track"), "🟢 Ciclul obișnuit");
  assert.equal(headline("grey", null), "⚪ Nedecis");
  // Celula spune doar ce lipsește; fraza lungă e în tooltip (`greyDetail`).
  assert.equal(greyReason(parseRisk(RISK_GREY)), "fără date CISA");
  assert.equal(greyDetail(parseRisk(RISK_GREY)),
    "lipsește punctele CISA (CVE-ul nu a fost încă întrebat); ar putea fi între Track și Attend");
  assert.equal(reasonLine("grey", parseRisk(RISK_GREY)), "fără date CISA");
  assert.equal(reasonLine("grey", { missing: ["exploitation_unpublished"] }), "CISA n-a evaluat");
  // Motivul unui rând roșu: cine a spus că se exploatează, nu probabilitatea.
  assert.equal(reasonLine("red", parseRisk(RISK_RED)), "exploatat activ (CISA)");
  // Un CVE pe care CISA l-a evaluat `none`, cu un EPSS de la pragul regulii în sus:
  // tensiunea rămâne vizibilă. Sub prag, cifra e deja în coloana EPSS, deci nicio linie.
  const none = (p: number) => JSON.stringify({
    points: { exploitation: { value: "none", basis: "vulnrichment" } }, epss: { p } });
  assert.equal(reasonLine("green", parseRisk(none(0.99225))), "EPSS 99,2%");
  assert.equal(reasonLine("green", parseRisk(none(0.5))), "EPSS 50,0%");
  assert.equal(reasonLine("green", parseRisk(none(0.4999))), null);
  assert.equal(reasonLine("green", parseRisk(none(0.0024))), null);
  // La galben și roșu, EPSS-ul e chiar motivul: rămâne oricât ar fi.
  assert.equal(reasonLine("amber", parseRisk(none(0.0024))), "EPSS 0,24%");
});

test("numele SSVC rămân urmăribile, iar un cod necunoscut nu devine funcția lui Object", () => {
  assert.equal(ssvcName("attend"), "Attend");
  assert.equal(ssvcName("track_star"), "Track*");
  assert.equal(ssvcName(null), null);
  // `MAP["constructor"]` e `Object`, nu `undefined`: fără gardă, textul funcției ar fi
  // ajuns în celulă ca „ce lipsește".
  for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
    assert.equal(ssvcName(name), null, name);
    assert.equal(greyReason({ decision: null, missing: [name] }), name);
    assert.equal(greyDetail({ decision: null, missing: [name], possible: [name, "track"] }),
      `lipsește ${name}; ar putea fi între ${name} și Track`);
  }
});

test("KEV spune „nu” doar când s-a căutat", () => {
  const evaluated = { decision: "track", missing: [] };
  assert.equal(fmtKev(true, "2026-10-12", evaluated), "da — 2026-10-12");
  assert.equal(fmtKev(true, null, evaluated), "da");
  assert.equal(fmtKev(true, "", null), "da");
  assert.equal(fmtKev(false, null, evaluated), "nu");
  for (const unknown of [null, {}, { decision: null, missing: ["cve"] },
                         { decision: null, missing: ["epss", "kev_mirror"] },
                         // Ce scrie `risk._unassessable` când evaluarea cade.
                         { v: 1, missing: ["assessment_error"], error: "KeyError: x" }]) {
    assert.equal(fmtKev(false, null, unknown), "nu se știe", JSON.stringify(unknown));
  }
});

test("KEV venit ca TEXT din coloană: „0” nu devine „da”, „1” rămâne „da”", () => {
  // `kev` e `TINYINT(1)`, iar un driver sau o replică îl poate da ca text. `Boolean("0")`
  // e ADEVĂRAT: un rând care nu e în catalog ar fi apărut ca exploatat activ, cu ziua-limită
  // lipsă. Niciun alt test nu hrănește un șir, deci `Number(row.kev) === 1` din `riskView`
  // era păzit doar de comentariul de lângă el.
  const evaluated = JSON.stringify({ decision: "track", missing: [] });
  const kevOf = (kev: unknown) => riskView({
    risk_color: "green", risk_decision: "track", risk: evaluated, kev,
    kev_due_date: "2026-10-12" }).kev;
  assert.equal(kevOf("0"), "nu", "„0” citit ca adevărat");
  assert.equal(kevOf(""), "nu");
  assert.equal(kevOf(0), "nu");
  assert.equal(kevOf(false), "nu");
  assert.equal(kevOf(null), "nu");
  assert.equal(kevOf("1"), "da — 2026-10-12");
  assert.equal(kevOf(1), "da — 2026-10-12");
  assert.equal(kevOf(true), "da — 2026-10-12");
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
  assert.equal(v.headline, "🟡 Curând · regula Sentinel");
  assert.equal(v.reason, "EPSS 99,2%, CISA veche");
  // Numele din arbore NU stă lângă marcaj: „Attend" ar spune că arborele a decis ce n-a decis.
  assert.ok(!v.headline.includes("Attend"));
  assert.ok(v.detail !== null && v.detail.includes("nu decis de CISA SSVC")
            && v.detail.endsWith("ar fi dat Track"), String(v.detail));
  const plain = riskView({ risk_color: "amber", risk_decision: "attend",
                           risk: JSON.stringify({ points: { exploitation: { value: "active", basis: "kev" } } }) });
  assert.equal(plain.headline, "🟡 Curând");
  assert.equal(plain.reason, "exploatat activ (KEV)");
  assert.equal(plain.detail, "Decizie CISA SSVC: Attend");
  const stray = riskView({ risk_color: "green", risk_decision: "track", risk: RISK_OVERLAY });
  assert.ok(!stray.headline.includes("Sentinel"), stray.headline);
  assert.ok(!(stray.reason ?? "").includes("CISA veche"), String(stray.reason));
  assert.equal(headline("amber", "attend", { overlay: { basis: "altceva" } }), "🟡 Curând");
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
  assert.ok(row("CVE-REGULA").includes("🟡 Curând · regula Sentinel"), "rândul nu poartă marcajul");
  assert.ok(row("CVE-REGULA").includes("EPSS 99,2%, CISA veche"));
  assert.ok(row("CVE-REGULA").includes("nu decis de CISA SSVC"), "tooltip-ul a pierdut explicația");
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
  assert.match(all, /🔴 Acum <span class="nr">1<\/span>/);
  assert.match(all, /⚪ Nedecis <span class="nr">0<\/span>/, "gri trebuie să apară chiar și cu zero");
  assert.ok(all.includes('🟢 Ciclul obișnuit / De urmărit* <span class="nr">2</span>'),
    "pastila verde poartă etichetele ambelor decizii ale grupei");

  const red = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=red", { cookies }))).text();
  assert.ok(red.includes("CVE-R") && !red.includes("CVE-V1"), "filtrul pe roșu arată și verzi");
  const green = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=green", { cookies }))).text();
  assert.ok(green.includes("CVE-V1") && !green.includes("CVE-R"));

  const nonsense = await (await vulnGet(getRequest("/panel/vulnerabilitati?culoare=purple", { cookies }))).text();
  assert.ok(nonsense.includes("CVE-R") && nonsense.includes("CVE-V1"),
    "o culoare inventată trebuie să arate tot, nu un ecran gol");
});

test("legenda paginii e făcută din etichetele rândurilor, iar pastilele poartă numele stării", async () => {
  // O legendă scrisă de mână se abate de la etichete fără ca ceva să pară stricat: pe Telegram a
  // spus „🟢 De urmărit (Track)" când rândul spunea „Ciclul obișnuit". Aici se citește din
  // sursa etichetelor, iar pastila cu cuvântul culorii („gri") nu mai e numele stării.
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-L", priority: 90,
    risk_color: "red", risk_decision: "act", risk: RISK_RED });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const text = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
  assert.ok(text.includes(legendStates()), "legenda nu e cea construită din etichete");
  assert.ok(text.includes("🟢 Ciclul obișnuit (Track) · 🟢 De urmărit* (Track*)"));
  assert.ok(!text.includes("De urmărit (Track)"), "maparea greșită a reapărut");
  // Propozițiile din jurul legendei numesc starea tot printr-un literal în `panel-page.ts`: dacă
  // eticheta se schimbă în `finding-risk.ts`, legenda o urmează (e generată), iar propoziția ar
  // rămâne să numească o stare pe care niciun rând n-o mai poartă. De aceea sunt citite din
  // etichete, nu scrise încă o dată aici.
  assert.ok(text.includes(`${headline("grey", null)} înseamnă că lipsesc date`) &&
    !text.includes("Gri înseamnă"));
  assert.ok(text.includes(
    `„${DECISION_LABEL_RO.track_star}” e ${DECISION_LABEL_RO.track.toLowerCase()}, dar cu o privire mai deasă`),
    "propoziția despre starea «De urmărit*» nu mai e cea a etichetelor");
  for (const cause of ["lista KEV n-a putut fi citită", "rândul n-are CVE",
                       "evaluarea lui s-a oprit cu o eroare", "încă n-a fost făcută"]) {
    assert.ok(text.includes(cause), `legenda KEV nu spune: ${cause}`);
  }
  assert.ok(text.includes(KEV_UNKNOWN_NOTE_RO));
  for (const color of COLORS) {
    // Eticheta vizibilă a pastilei e numele stării; cuvântul culorii stă doar în `title`.
    const pill = new RegExp(`<a href="[^"]*culoare=${color}" title="([^"]*)"[^>]*>([^<]*)<span`);
    const m = html.match(pill);
    assert.ok(m, `pastila ${color} lipsește`);
    assert.equal(m[1], pillTitle(color));
    assert.ok(m[2].includes(COLOR_STATE_RO[color]), `pastila ${color}: ${m[2]}`);
    assert.ok(!/\b(roșu|galben|gri|verde)\b/.test(m[2]), `pastila ${color} poartă cuvântul culorii`);
  }
});

test("un rând cu culoare necunoscută sau fără evaluare apare GRI și cu motivul, nu verde", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-NECUNOSCUT", priority: 50,
    risk_color: "purple", risk_decision: null });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-NEEVALUAT", priority: 40 });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  // Legenda paginii pomenește etichetele verzi („🟢 Ciclul obișnuit = Track"); un rând
  // desenat verde ar avea eticheta lipită de sfârșitul celulei.
  assert.ok(!/🟢 (Ciclul obișnuit|De urmărit\*?)</.test(html), "un rând fără date apare ca verde");
  assert.equal((html.match(/⚪ Nedecis</g) ?? []).length, 2);
  assert.ok(html.includes("încă neevaluată"));
  assert.match(html, /⚪ Nedecis <span class="nr">2<\/span>/);
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
  assert.match(a, /🔴 Acum <span class="nr">1<\/span>/);
  assert.ok(a.includes("CVE-X") && !a.includes("CVE-Y"));
  assert.match(b, /🔴 Acum <span class="nr">0<\/span>/,
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

test("cardul de pe prima pagină spune câte sunt Acum, Curând și Nedecis, cu numele stărilor", async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, status: "open", priority: 90,
    risk_color: "red", risk_decision: "act" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, status: "open", priority: 40,
    risk_color: "grey" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, status: "resolved", priority: 90,
    risk_color: "red", risk_decision: "act" });   // închis: nu se numără
  const html = await (await panelGet(getRequest("/panel", { cookies: await signIn() }))).text();
  assert.ok(html.includes("Acum 1 · Curând 0 · Nedecis 1"),
    "cardul nu spune stările constatărilor deschise");
  // Un singur nume pentru starea aceea: cel al rândului și al pastilei, nu „fără date” sau „gri”.
  assert.ok(!html.includes("fără date") && !html.includes("roșii"),
    "cardul a revenit la un al doilea nume pentru aceeași stare");
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
  assert.match(html, /⚪ Nedecis <span class="nr">0<\/span>/,
    "rezolvatele au fost numărate ca „fără date”");
  assert.match(html, /🔴 Acum <span class="nr">1<\/span>/);
  assert.equal((html.match(/— \(resolved\)/g) ?? []).length, 6,
    "un rând rezolvat nu spune că e rezolvat");
  const risky = html.split("<tr").filter((r) => r.includes("CVE-INCHIS-2"))[0];
  assert.ok(!risky.includes("⚪ Nedecis"), "un rând rezolvat apare ca nedecis");
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
  assert.equal((html.match(/🔴 Acum</g) ?? []).length, 3,
    "o stare neaplicată a fost tratată ca închisă");
  assert.match(html, /🔴 Acum <span class="nr">3<\/span>/);
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

// ---------------------------------------------------------------------------
// Coloanele și celula „Risc"
// ---------------------------------------------------------------------------
test("CVSS, EPSS și KEV stau una lângă alta, sub numele lor, în ordinea panoului serverului",
     async () => {
  // Operatorul n-a găsit CVSS-ul: stătea sub „Importanță". Cele trei semnale se citesc
  // împreună, iar panoul serverului (`findings.html`) are aceeași ordine — o verifică
  // `tests/unit/test_findings_columns_agree.py`, care citește ambele fișiere sursă.
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-1", priority: 50 });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const headers = [...html.matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]);
  const at = headers.indexOf("CVSS");
  assert.ok(at >= 0, `fără coloana CVSS: ${headers.join("|")}`);
  assert.deepEqual(headers.slice(at, at + 3), ["CVSS", "EPSS", "KEV"]);
  assert.ok(!headers.includes("Importanță"));
});

test("celula KEV: da cu ziua-limită, nu, sau „nu se știe”; un rând închis nu primește „nu se știe”",
     async () => {
  await grant(INSTANCE_A);
  const evaluated = JSON.stringify({ decision: "track", missing: [] });
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-K-DA", priority: 90, kev: 1,
    kev_due_date: "2026-10-12", risk_color: "red", risk_decision: "act", risk: RISK_RED });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-K-NU", priority: 50,
    risk_color: "green", risk_decision: "track", risk: evaluated });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, cve: "CVE-K-NESTIU", priority: 45,
    risk_color: "grey", risk: JSON.stringify({ decision: null, missing: ["kev_mirror"] }) });
  fixture.db.addFinding(INSTANCE_A, { source_id: 4, cve: "CVE-K-INCHIS", priority: 10,
    status: "resolved", risk_color: "grey" });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const headers = [...html.matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]);
  const kevOf = (cve: string) => {
    const at = html.indexOf(`>${cve}<`);
    assert.ok(at > 0, `${cve} lipsește`);
    const row = html.slice(html.lastIndexOf("<tr", at), html.indexOf("</tr>", at));
    const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
    return cells[headers.indexOf("KEV")].replace(/<[^>]+>/g, "").trim();
  };
  assert.equal(kevOf("CVE-K-DA"), "da — 2026-10-12");
  assert.equal(kevOf("CVE-K-NU"), "nu");
  assert.equal(kevOf("CVE-K-NESTIU"), "nu se știe");
  assert.equal(kevOf("CVE-K-INCHIS"), "—");
});

test("fiecare celulă stă sub antetul care o numește (nu doar antetele sunt în ordine)", async () => {
  // Comparația antetelor dovedește că cele două pagini se numesc la fel, nu că celula de sub
  // „CVSS” arată CVSS. O celulă „CVSS” care ar scrie EPSS-ul (antetele neatinse) trecea toată
  // suita: o probabilitate citită ca scor de severitate. Fiecare celulă se citește prin
  // indicele ANTETULUI ei, cu valori pe care nicio altă celulă nu le poate împărți.
  await grant(INSTANCE_A);
  const risk = JSON.stringify({
    decision: "act", missing: [], cvss: { source: "redhat", score: 7.5 },
    epss: { p: 0.0045, percentile: 0.3682 },
    points: { exploitation: { value: "active", basis: "kev" } } });
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-CELULE-7", priority: 90,
    severity: "critical", epss: "0.0045", epss_percentile: "0.3682", kev: 1,
    kev_due_date: "2026-10-12", package: "pkg-seven", installed_version: "1.0.0-inst",
    fixed_version: "9.9.9-fix", risk_color: "red", risk_decision: "act", risk });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const headers = [...html.matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]);
  const at = html.indexOf("CVE-CELULE-7");
  assert.ok(at > 0, "rândul lipsește");
  const row = html.slice(html.lastIndexOf("<tr", at), html.indexOf("</tr>", at));
  const cells = [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)]
    .map((m) => m[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
  assert.equal(cells.length, headers.length, `${headers.join("|")} față de ${cells.join("|")}`);
  const cell = (name: string) => {
    const i = headers.indexOf(name);
    assert.ok(i >= 0, `fără antetul ${name}`);
    return cells[i];
  };
  assert.ok(cell("Risc").includes("🔴 Acum"), cell("Risc"));
  assert.ok(cell("Severitate").includes("critical"), cell("Severitate"));
  assert.ok(cell("CVE").includes("CVE-CELULE-7"), cell("CVE"));
  assert.equal(cell("CVSS"), "CVSS 7,5 (Red Hat)");
  assert.equal(cell("EPSS"), "0,45% (percentila 37)");
  assert.equal(cell("KEV"), "da — 2026-10-12");
  assert.ok(cell("Pachet").includes("pkg-seven"), cell("Pachet"));
  assert.equal(cell("Fix"), "9.9.9-fix");
});

test("un verde fără nimic de spus n-are a doua linie, un gri o are mereu, iar 🔁 vine din semn",
     async () => {
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, cve: "CVE-LINISTIT", priority: 10,
    epss: "0.0024", risk_color: "green", risk_decision: "track",
    risk: JSON.stringify({ decision: "track", missing: [], epss: { p: 0.0024 },
                           reboot_pending: true }) });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, cve: "CVE-GRI", priority: 45,
    risk_color: "grey", risk: RISK_GREY });
  const html = await (await vulnGet(getRequest("/panel/vulnerabilitati",
    { cookies: await signIn() }))).text();
  const riskCell = (cve: string) => {
    const at = html.indexOf(`>${cve}<`);
    assert.ok(at > 0, `${cve} lipsește`);
    const row = html.slice(html.lastIndexOf("<tr", at), html.indexOf("</tr>", at));
    return row.slice(row.indexOf("<td"), row.indexOf("</td>"));
  };
  const quiet = riskCell("CVE-LINISTIT");
  assert.ok(!quiet.includes("<br>"), "un verde fără motiv are totuși a doua linie");
  assert.ok(quiet.includes("🔁"), "repornirea în așteptare a dispărut odată cu motivul");
  const grey = riskCell("CVE-GRI");
  assert.ok(grey.includes("fără date CISA"), "griul nu spune ce lipsește");
  // Fraza lungă stă în tooltip, nu în celulă.
  const visible = grey.slice(grey.indexOf(">") + 1);
  assert.ok(!visible.includes("ar putea fi"), "fraza lungă a rămas în celulă");
  assert.ok(grey.slice(0, grey.indexOf(">")).includes("ar putea fi între Track și Attend"),
    "fraza lungă nu mai e nicăieri");
  assert.ok(grey.includes('class="risc"') && grey.includes("risc-eticheta"));
});
