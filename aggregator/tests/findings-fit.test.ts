/**
 * Tabelul vulnerabilităților ÎNCAPE și nu rupe identificatorii.
 *
 * Eșecul pe care îl previne, în termenii operatorului: coloana CVE — prima pe care o
 * citește — se rupea la cratimă pe 177 din 200 de rânduri reale (`CVE-2026-` / `53362`),
 * data din KEV pe amândouă rândurile KEV (`da — 2026-` / `08-30`), iar o versiune de la
 * Fix la cratimă (`15.6.0-` / `canary.59`) se citește ca altă versiune. Un identificator
 * rupt nu se poate nici copia.
 *
 * Panoul serverului a primit aceeași reparație în `c73db4a` (`<span class="nowrap">` pe
 * fiecare versiune, `<wbr>` între segmentele pachetului). AICI e altă problemă: un
 * identificator nerupt nu cedează, deci tabelul are nevoie de 1240–1500 px, iar
 * `main { max-width: 72rem }` dă 1112. Pagina cere `<main class="wide">` (100rem), iar
 * celelalte pagini nu — vezi comentariul din `panel.css`.
 *
 * Ce NU poate proba un test: pixelii. Un test care ar pretinde că măsoară lățimea unui
 * tabel fără browser ar măsura propria intenție. Aici stă forma marcajului (inclusiv ce pagini
 * cer `wide`); regulile din foaie le judecă, prin cascadă, `tests/unit/test_aggregator_findings_fit.py`
 * (rulează și fără node); lățimile (0 depășire, 0 identificatori rupți) sunt MĂSURĂTORI, scrise
 * în foaie și în raportul schimbării.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { findingsPage, incidentsPage, pendingPage } from "../lib/panel-page";
import { riskView } from "../lib/finding-risk";
import type { FindingSummary } from "../lib/data/findings";

const CSS = readFileSync(join(import.meta.dirname, "..", "public", "panel.css"), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "");

/** Cea mai lungă `fixed_version` de pe producție: 135 de caractere, 19 versiuni (symfony/mime). */
const WORST_FIX = "3.0.0, 5.0.0, 6.3.0, 6.4.0, 7.1.0, 7.3.0, 7.4.12, 6.2.0, 5.1.0, 5.4.52, 6.1.0, "
  + "7.4.0, 8.0.12, 4.0.0, 5.2.0, 5.3.0, 5.4.0, 6.4.40, 7.2.0";

const GREEN = riskView({ risk_color: "green", risk_decision: "track",
                         risk: JSON.stringify({ decision: "track", missing: [] }) });
const AMBER_KEV = (due: string | null) => riskView({
  risk_color: "amber", risk_decision: "attend", kev: 1, kev_due_date: due,
  risk: JSON.stringify({ decision: "attend", missing: [] }),
});

function row(over: Partial<FindingSummary> & { id: number }): FindingSummary {
  return {
    sourceId: over.id, scanner: "trivy_image", cve: `CVE-2026-${50000 + over.id}`, title: "t",
    severity: "high", cvss: null, epss: null, epssPercentile: null, kev: false, kevDueDate: null,
    packageName: "next", installedVersion: "13.4.19", fixedVersion: "15.2.3", priority: 50,
    risk: GREEN, riskScore: null, status: "open",
    firstSeen: "2026-09-01 00:00", lastSeen: "2026-10-05 03:00",
    ...over,
  };
}

function render(findings: FindingSummary[]): string {
  return findingsPage({
    username: "operator", csrfToken: "x", instances: [], selected: "prod-a",
    active: "/panel/vulnerabilitati", arrivals: new Map(), findings, group: null, color: null,
    colors: { red: 0, amber: 0, green: findings.length, grey: 0 },
    counts: { neaplicate: findings.length, rezolvate: 0, inchise: 0, total: findings.length },
    scan: { lastGood: null, latest: null },
  } as never);
}

/** Antetele, în ordine, ca o celulă să se citească după NUMELE coloanei ei. */
function headers(html: string): string[] {
  return [...html.matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]);
}

/** Rândul `<tr>` al constatării `id` (CVE-ul se deduce din id; cu `cve: null` rândul se află după `id`). */
function rowOf(html: string, id: number): string {
  const rows = html.split("<tr>").filter((r) => r.includes("<td"));
  const at = rows.findIndex((r) => r.includes(`>CVE-2026-${50000 + id}<`));
  assert.ok(at >= 0, `rândul ${id} lipsește`);
  return rows[at];
}

/** Interiorul celulei `name` din rândul constatării `id`. */
function cell(html: string, id: number, name: string): string {
  const cells = [...rowOf(html, id).matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1]);
  const at = headers(html).indexOf(name);
  assert.ok(at >= 0, `fără antetul ${name}`);
  assert.equal(cells.length, headers(html).length, "rândul n-are tot atâtea celule cât antetul");
  return cells[at];
}

const SPAN = /<span class="nowrap">(.*?)<\/span>/g;
const spans = (s: string): string[] => [...s.matchAll(SPAN)].map((m) => m[1]);

test("CVE: identificatorul e un singur `nowrap`, scanerul rămâne dedesubt", () => {
  const html = render([row({ id: 1, cve: "CVE-2026-50001" })]);
  assert.equal(cell(html, 1, "CVE"),
               '<span class="nowrap">CVE-2026-50001</span><br><span class="id">trivy_image</span>');
});

test("CVE: fără CVE se scrie o liniuță, nu o celulă goală", () => {
  const html = render([row({ id: 1, cve: null }), row({ id: 2 })]);
  const first = html.split("<tr>").filter((r) => r.includes("<td"))[0];
  assert.ok(first.includes('<td><span class="nowrap">—</span><br><span class="id">trivy_image</span></td>'),
            first);
});

test("KEV: data e un `nowrap`, „da —” rămâne liber; „nu” și „nu se știe” nu poartă niciunul", () => {
  const inKev = AMBER_KEV("2026-08-30");
  const html = render([
    row({ id: 1, kev: true, kevDueDate: "2026-08-30", risk: inKev }),
    row({ id: 2 }),                                    // „nu”: evaluat, în afara listei
    row({ id: 3, risk: riskView({ risk_color: "grey",
                                  risk: JSON.stringify({ decision: null, missing: ["cve"] }) }) }),
  ]);
  const da = cell(html, 1, "KEV");
  assert.equal(da, '<strong>da — <span class="nowrap">2026-08-30</span></strong>');
  // Textul vizibil rămâne EXACT cel din `risk.kev` (aceeași sursă ca pe celelalte ecrane).
  assert.equal(da.replace(/<[^>]+>/g, ""), inKev.kev);
  assert.equal(cell(html, 2, "KEV"), "nu");
  assert.equal(cell(html, 3, "KEV"), "nu se știe");
});

test("KEV: o dată cu marcaj iese escapată într-un singur `nowrap`, iar fără dată nu e nimic de ținut", () => {
  const html = render([
    row({ id: 1, kev: true, kevDueDate: "<b>x</b> 2026", risk: AMBER_KEV("<b>x</b> 2026") }),
    row({ id: 2, kev: true, kevDueDate: null, risk: AMBER_KEV(null) }),
  ]);
  assert.equal(cell(html, 1, "KEV"),
               '<strong>da — <span class="nowrap">&lt;b&gt;x&lt;/b&gt; 2026</span></strong>');
  assert.ok(!html.includes("<b>x"), "o dată a devenit marcaj viu");
  assert.equal(cell(html, 2, "KEV"), "<strong>da</strong>");
});

test("Fix: fiecare versiune e un `nowrap`, între ele doar „, ”", () => {
  const html = render([
    row({ id: 1, fixedVersion: WORST_FIX }),
    row({ id: 2, fixedVersion: "15.6.0-canary.59, 16.0.10" }),
    row({ id: 3, fixedVersion: "3.0.13-0ubuntu3.11" }),
    row({ id: 4, fixedVersion: "1.0,2.0" }),
    row({ id: 5, fixedVersion: "<b>1</b>, 2" }),
    row({ id: 6, fixedVersion: null }), row({ id: 7, fixedVersion: "" }),
    row({ id: 8, fixedVersion: " , ," }),
  ]);
  const want: Record<number, string[]> = {
    1: WORST_FIX.split(", "), 2: ["15.6.0-canary.59", "16.0.10"], 3: ["3.0.13-0ubuntu3.11"],
    4: ["1.0", "2.0"], 5: ["&lt;b&gt;1&lt;/b&gt;", "2"],
  };
  assert.equal(want[1].length, 19, "controlul pozitiv: cea mai lungă formă are 19 versiuni");
  for (const [id, versions] of Object.entries(want)) {
    const c = cell(html, Number(id), "Fix");
    assert.deepEqual(spans(c), versions, `rândul ${id}: ${c}`);
    // Între span-uri stă „, ” și nimic altceva: virgula rămâne lipită de versiunea ei,
    // spațiul de după e singurul loc unde se rupe rândul.
    assert.equal(c.replace(SPAN, "#"), versions.map(() => "#").join(", "), `rândul ${id}`);
  }
  assert.ok(!html.includes("<b>1"), "o versiune a devenit marcaj viu");
  for (const id of [6, 7, 8]) assert.equal(cell(html, id, "Fix"), "—", `rândul ${id}`);
});

test("Pachet: fiecare segment dintre „/” e un `nowrap` cu `<wbr>` între ele; versiunea instalată nu se rupe", () => {
  const html = render([
    row({ id: 1, packageName: "symfony/http-foundation", installedVersion: "5.4.0-1" }),
    row({ id: 2, packageName: "mtdowling/jmespath.php" }),
    row({ id: 3, packageName: "http-cache-semantics", installedVersion: "5.14.0-687.52.1.el9_8" }),
    row({ id: 4, packageName: "@t/node/<img src=x onerror=1>" }),
    row({ id: 5, packageName: null, installedVersion: null }),
  ]);
  const want: Record<number, string[]> = {
    1: ["symfony/", "http-foundation"], 2: ["mtdowling/", "jmespath.php"],
    3: ["http-cache-semantics"], 4: ["@t/", "node/", "&lt;img src=x onerror=1&gt;"],
  };
  for (const [id, parts] of Object.entries(want)) {
    const name = cell(html, Number(id), "Pachet").split("<br>")[0];
    assert.deepEqual(spans(name), parts, `rândul ${id}: ${name}`);
    assert.equal(name.replace(SPAN, "#"), parts.map(() => "#").join("<wbr>"), `rândul ${id}`);
  }
  // „5.14.0-687.52.1.el9_8” tăiat la cratimă se citește ca altă versiune, ca la Fix.
  assert.ok(cell(html, 3, "Pachet").endsWith('<br><span class="id nowrap">5.14.0-687.52.1.el9_8</span>'));
  assert.ok(!html.includes("<img"), "un nume de pachet a devenit marcaj viu");
  assert.equal(cell(html, 5, "Pachet"), '—<br><span class="id nowrap">—</span>');
});

test("Stare: se poate rupe după „_”, textul rămâne cel din bază", () => {
  const html = render([row({ id: 1, status: "patch_planned" }), row({ id: 2, status: "open" })]);
  const c = cell(html, 1, "Stare");
  assert.equal(c, "patch_<wbr>planned");
  assert.equal(c.replace(/<wbr>/g, ""), "patch_planned");
  assert.equal(cell(html, 2, "Stare"), "open");
});

test("tabelul poartă clasa `findings`, iar foaia are regulile pe care marcajul le cere", () => {
  const html = render([row({ id: 1 })]);
  assert.ok(html.includes('<table class="findings">'), "fără clasa care scopează regulile");
  // Fiecare clasă pe care o scrie pagina trebuie să aibă o regulă ÎN FOAIA SERVITĂ: un
  // `<span class="nowrap">` fără regulă e un span oarecare, iar identificatorii se rup la loc.
  assert.match(CSS, /\.nowrap\s*\{[^}]*white-space:\s*nowrap/);
  // Celulele întregi NU sunt `nowrap`: Fix e coloana care dă înapoi (se rupe între versiuni), iar
  // un `nowrap` pe tot `<td>` ar face-o cât cea mai lungă valoare (135 de caractere, 19 versiuni).
  assert.ok(!html.includes('<td class="nowrap">'), "o celulă întreagă nu se mai poate rupe");
});

test("`wide`: pagina vulnerabilităților își cere lățimea, iar nicio altă pagină nu", () => {
  // Fără clasă, `main` rămâne la 72rem și tabelul iese din încăpere (n8n: 94 px peste, măsurat).
  const html = render([row({ id: 1 })]);
  assert.equal(html.split('<main class="wide">').length - 1, 1, "pagina cere `wide` exact o dată");
  assert.ok(!/<main>/.test(html), "a rămas un `<main>` fără clasă");
  // Pagina goală (o vedere fără rânduri) are tot lățimea ei: titlul și filtrele nu sar între vederi.
  assert.ok(render([]).includes('<main class="wide">'), "pagina fără rânduri nu cere `wide`");
  // Celelalte pagini: marcaj identic cu cel de dinainte. O lățime luată de la proză se ia de la toate.
  const chrome = { username: "operator", csrfToken: "x", instances: [], selected: "prod-a",
                   active: "/panel/x", arrivals: new Map() } as never;
  for (const [nume, other] of [
    ["pendingPage", pendingPage(chrome, "T", "findings", "explicație")],
    ["incidentsPage", incidentsPage({ ...(chrome as object), incidents: [] } as never)],
  ] as const) {
    assert.ok(other.includes("<main>\n"), `${nume}: a pierdut \`<main>\` simplu`);
    assert.ok(!other.includes("wide"), `${nume}: a primit clasa \`wide\``);
  }
});
