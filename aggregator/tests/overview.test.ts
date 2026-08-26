/**
 * Rezumatul: cifrele, seria orară, clasamentele și cronologia.
 *
 * Eșecurile pe care le previne — toate arată ca o pagină care funcționează:
 *
 *   * **tendința inversată**: „acum" și „înainte" schimbate între ele. Un panou
 *     care spune „−80%" într-o zi în care atacurile s-au dublat e mai rău decât
 *     unul fără tendință deloc;
 *   * **evenimentele concatenate**: driverul întoarce `n` ca ȘIR, iar `"10"+"5"`
 *     e `"105"`. Un cartonaș cu un număr de zece ori mai mare nu pică nimic;
 *   * **fereastra desenată mai lungă decât cea numărată**: seria orară și
 *     cartonașele au ferestre diferite prin proiectare (48 vs 24 de ore), iar
 *     confundate, graficul ar arăta ore care nu intră în niciun contor;
 *   * **plafonul tăcut**: o citire tăiată la `MAX_ROWS_READ` arată exact ca
 *     „atât a fost". Aici se cere să fie SPUSĂ;
 *   * **cronologia în ordine greșită**: detecțiile și blocările vin din două
 *     citiri; lipite fără sortare, se citesc ca altă poveste, nu ca o eroare;
 *   * **două ceasuri**: fereastra tăiată de bază și despărțirea făcută pe ceasul
 *     procesului. Un derapaj între gazde ar da „−100%" pe trafic neschimbat.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import {
  ACTIVITY_LIMIT, MAX_ROWS_READ, RANK_LIMIT, SERIES_HOURS, WINDOW_HOURS, summary,
} from "../lib/data/overview";
import {
  USERNAME, captureError, captureWarn, forgetAuthServer, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture } from "./auth-routes-harness";
import type { InstanceScope } from "../lib/auth/scope";

const INSTANCE = "prod-a";
const HOUR = 3_600_000;

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };
let scope: InstanceScope;

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
  fixture.db.addInstance(INSTANCE, { label: "A" });
  const granted = await grantInstance(fixture.db, USERNAME, INSTANCE, "owner");
  assert.equal(granted.ok, true);
  scope = await scopeForUser(fixture.db, fixture.user.id);
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

/** Cu câte ore în urmă față de ceasul ÎNGHEȚAT al dublului. */
function agoMs(hours: number): number {
  return fixture.db.nowMs - hours * HOUR;
}

function run() {
  return summary(fixture.db, scope, INSTANCE);
}

// ---------------------------------------------------------------------------
// Tendința: două ferestre egale
// ---------------------------------------------------------------------------
test("detecțiile de acum și cele de dinainte nu se amestecă", async () => {
  // Trei în fereastra curentă, una în cea dinainte. Cu ferestrele schimbate
  // între ele, panoul ar raporta o scădere de două treimi într-o zi în care
  // atacurile s-au triplat.
  for (const h of [1, 2, 3]) {
    fixture.db.addDetection(INSTANCE, { ts: agoMs(h), src_ip: `203.0.113.${h}` });
  }
  fixture.db.addDetection(INSTANCE, { ts: agoMs(30), src_ip: "198.51.100.1" });

  const s = await run();
  assert.equal(s.overview.detections.now, 3);
  assert.equal(s.overview.detections.before, 1);
  assert.equal(s.overview.attackers.now, 3, "adresele distincte din fereastră");
  assert.equal(s.overview.attackers.before, 1);
});

test("o detecție mai veche decât AMBELE ferestre nu se numără nicăieri", async () => {
  // `WINDOW_HOURS * 2` e chiar marginea citirii. Fără ea, „înainte" ar crește
  // la nesfârșit pe măsură ce baza se umple, iar tendința ar tinde spre −100%
  // fără ca nimic să se fi întâmplat.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1) });
  fixture.db.addDetection(INSTANCE, { ts: agoMs(WINDOW_HOURS * 2 + 5) });

  const s = await run();
  assert.equal(s.overview.detections.now, 1);
  assert.equal(s.overview.detections.before, 0,
               "o detecție de dinainte de fereastra dublă a fost numărată");
});

test("detecțiile suprimate nu intră în niciun contor", async () => {
  // Suprimarea e o decizie luată pe server: „am văzut, e zgomot". Numărată
  // aici, panoul ar raporta un atac pe care motorul l-a respins deja.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1), suppressed: 1 });
  const s = await run();
  assert.equal(s.overview.detections.now, 0);
  assert.equal(s.activity.length, 0, "o detecție suprimată a ajuns în cronologie");
});

test("evenimentele orei se ADUNĂ, nu se concatenează", async () => {
  // Driverul întoarce `n` ca șir. `"10" + "5"` e `"105"` — un vârf de zece ori
  // mai mare pe grafic, fără nimic care să pice.
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "nginx", n: "10" });
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "sshd", n: "5" });

  const s = await run();
  assert.equal(s.overview.events.now, 15);
  assert.equal(typeof s.overview.events.now, "number");
});

// ---------------------------------------------------------------------------
// Seria orară: fereastra desenată e mai lungă decât cea numărată
// ---------------------------------------------------------------------------
test("seria acoperă mai multe ore decât cartonașele, dinadins", async () => {
  // 48 de ore desenate, 24 numărate. Confundate, graficul ar arăta ore care nu
  // intră în niciun contor de sus, iar cine compară cele două ar crede că unul
  // dintre ele minte.
  assert.ok(SERIES_HOURS > WINDOW_HOURS,
            "seria nu mai e mai lungă decât fereastra, deci testul nu deosebește nimic");
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "nginx", n: "10" });
  fixture.db.addRollupHour(INSTANCE,
    { bucket: agoMs(WINDOW_HOURS + 5), source: "nginx", n: "7" });

  const s = await run();
  assert.equal(s.series.length, 2, "ora dintre cele două ferestre lipsește din serie");
  assert.equal(s.overview.events.now, 10,
               "ora din afara ferestrei de 24 a fost numărată pe cartonaș");
  assert.equal(s.overview.events.before, 7);
});

test("seria e în ordine crescătoare, ca timpul", async () => {
  // Citirea e `ORDER BY bucket DESC` — cea mai nouă întâi, ca plafonul să taie
  // vechimea, nu prospețimea. Desenată în ordinea aia, seria ar merge înapoi.
  for (const h of [3, 1, 2]) {
    fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(h), source: "nginx" });
  }
  const s = await run();
  const buckets = s.series.map((x) => x.bucket);
  assert.deepEqual(buckets, [...buckets].sort((a, b) => a - b),
                   "seria merge înapoi în timp");
});

test("o oră poartă fiecare sursă separat", async () => {
  // Despărțirea pe sursă E rostul graficului stivuit: un total spune „a fost
  // trafic", stivuit spune CINE l-a produs — iar `sshd` care ia locul lui
  // `nginx` fără ca totalul să se miște e chiar ce trebuie văzut.
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "nginx", n: "10" });
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "sshd", n: "5" });

  const s = await run();
  assert.equal(s.series.length, 1);
  assert.deepEqual(s.series[0].bySource, { nginx: 10, sshd: 5 });
});

// ---------------------------------------------------------------------------
// Clasamente
// ---------------------------------------------------------------------------
test("clasamentul e ordonat descrescător și tăiat la RANK_LIMIT", async () => {
  for (let i = 0; i < RANK_LIMIT + 3; i += 1) {
    for (let k = 0; k <= i; k += 1) {
      fixture.db.addDetection(INSTANCE,
        { ts: agoMs(1), src_ip: `203.0.113.${i}`, rule_id: `regula.${i}` });
    }
  }
  const s = await run();
  assert.equal(s.rankings.attackers.length, RANK_LIMIT);
  const counts = s.rankings.attackers.map((x) => x.count);
  assert.deepEqual(counts, [...counts].sort((a, b) => b - a),
                   "clasamentul nu e ordonat descrescător");
  assert.equal(counts[0], RANK_LIMIT + 3,
               "prima intrare nu e cea mai mare, deci tăierea s-a făcut înainte " +
               "de ordonare — adică s-au păstrat primele găsite, nu primele");
});

test("clasamentul de atacatori numără REGULI distincte, nu detecții", async () => {
  // O adresă care lovește o singură regulă de o sută de ori și una care încearcă
  // zece reguli nu sunt același lucru; a doua caută, prima insistă.
  for (let i = 0; i < 3; i += 1) {
    fixture.db.addDetection(INSTANCE,
      { ts: agoMs(1), src_ip: "203.0.113.1", rule_id: "aceeași" });
  }
  fixture.db.addDetection(INSTANCE,
    { ts: agoMs(1), src_ip: "203.0.113.1", rule_id: "alta" });

  const s = await run();
  assert.equal(s.rankings.attackers[0].count, 4);
  assert.equal(s.rankings.attackers[0].extra, "2 reguli",
               "s-au numărat detecțiile, nu regulile distincte");
});

test("o detecție fără adresă nu inventează un atacator", async () => {
  // `src_ip` e NULL pentru regulile care nu privesc rețeaua. Trecută prin
  // `String()`, ar apărea în clasament o intrare „null" care arată ca o adresă.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1), src_ip: null });
  const s = await run();
  assert.deepEqual(s.rankings.attackers, []);
  assert.equal(s.overview.attackers.now, 0);
  assert.equal(s.rankings.rules[0].extra, "0 IP");
});

test("clasamentul de surse numără ORE distincte, nu rânduri", async () => {
  // 900 de evenimente într-o oră și 900 pe douăzeci de ore nu sunt același
  // lucru: primul e un vârf, al doilea e fundal.
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), source: "nginx", n: "100" });
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(2), source: "nginx", n: "100" });

  const s = await run();
  assert.equal(s.rankings.sources[0].count, 200);
  assert.equal(s.rankings.sources[0].extra, "2 ore");
});

// ---------------------------------------------------------------------------
// Cronologia
// ---------------------------------------------------------------------------
test("cronologia amestecă detecțiile și blocările în ordinea timpului", async () => {
  // Din două citiri, lipite. Fără sortare, ar ieși mai întâi toate detecțiile,
  // apoi toate blocările — iar legătura „am fost atacat de X, am blocat X" e
  // chiar ce vrea să vadă cineva.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(3), rule_id: "veche" });
  fixture.db.addBlock(INSTANCE, { blocked_at: agoMs(2), ip: "203.0.113.9" });
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1), rule_id: "noua" });

  const s = await run();
  assert.deepEqual(s.activity.map((x) => x.kind), ["detection", "block", "detection"]);
  assert.deepEqual(s.activity.map((x) => x.title), ["noua", "IP blocat", "veche"]);
});

test("cronologia e tăiată la ACTIVITY_LIMIT, nu la de două ori atât", async () => {
  // Două citiri de câte `ACTIVITY_LIMIT`, lipite: fără tăierea de la sfârșit,
  // pagina ar arăta de două ori mai multe rânduri decât spune constanta.
  for (let i = 0; i < ACTIVITY_LIMIT; i += 1) {
    fixture.db.addDetection(INSTANCE, { ts: agoMs(1) });
    fixture.db.addBlock(INSTANCE, { blocked_at: agoMs(1) });
  }
  const s = await run();
  assert.equal(s.activity.length, ACTIVITY_LIMIT);
});

// ---------------------------------------------------------------------------
// Contoarele de stare
// ---------------------------------------------------------------------------
test("numai constatările care mai cer ceva sunt numărate deschise", async () => {
  for (const status of ["open", "patch_planned", "patching", "deferred"]) {
    fixture.db.addFinding(INSTANCE, { status });
  }
  for (const status of ["fixed", "not_affected", "wont_fix"]) {
    fixture.db.addFinding(INSTANCE, { status });
  }
  const s = await run();
  assert.equal(s.overview.findingsOpen, 4,
               "o constatare rezolvată e numărată ca deschisă, sau invers");
});

test("numai blocările ACTIVE sunt numărate active", async () => {
  // `active` vine ca `TINYINT(1)`. Citit cu `Boolean(x)`, `"0"` e `true` —
  // fiecare blocare ridicată vreodată ar apărea ca fiind încă în vigoare.
  fixture.db.addBlock(INSTANCE, { active: 1 });
  fixture.db.addBlock(INSTANCE, { active: 0 });
  fixture.db.addBlock(INSTANCE, { active: "0" });

  const s = await run();
  assert.equal(s.overview.blocksActive, 1,
               "o blocare ridicată e numărată activă — probabil `Boolean(\"0\")`");
});

test("severitățile deschise vin cu cele grave întâi, iar necunoscutul la coadă", async () => {
  for (const severity of ["low", "critical", "nascocita", "high"]) {
    fixture.db.addIncident(INSTANCE, { severity, status: "open" });
  }
  fixture.db.addIncident(INSTANCE, { severity: "critical", status: "resolved" });

  const s = await run();
  assert.deepEqual(s.overview.bySeverity.map((x) => x.severity),
                   ["critical", "high", "low", "nascocita"],
                   "o severitate inventată de o versiune viitoare s-a așezat " +
                   "în fața celor grave");
  assert.equal(s.overview.incidentsOpen, 4, "un incident rezolvat e numărat deschis");
  assert.equal(s.overview.incidentsSevere, 2);
});

// ---------------------------------------------------------------------------
// Plafonul, și ceasul
// ---------------------------------------------------------------------------
test("o citire tăiată de plafon o SPUNE", async () => {
  // Eșecul: un panou care arată jumătate din date și niciun semn. Plafonul e
  // necesar — baza e partajată —, dar tăcut e mai rău decât absent.
  for (let i = 0; i < MAX_ROWS_READ; i += 1) {
    fixture.db.addDetection(INSTANCE, { ts: agoMs(1) });
  }
  const s = await run();
  assert.deepEqual(s.truncated, ["detecții"]);
});

test("o zi liniștită NU raportează nicio tăiere", async () => {
  // Garda celuilalt sens: un `>=` scris `>` sau un plafon greșit ar pune
  // avertismentul pe fiecare pagină, iar un avertisment permanent nu se mai
  // citește.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1) });
  const s = await run();
  assert.deepEqual(s.truncated, []);
});

test("despărțirea ferestrelor merge pe ceasul BAZEI, nu pe al procesului", async () => {
  // Dublul îngheață ceasul la 16 august 2026. Un cod care ar despărți pe
  // `Date.now()` ar pune fiecare rând în „înainte" — și ar fi trecut testele în
  // ziua în care a fost scris.
  fixture.db.addDetection(INSTANCE, { ts: agoMs(1) });
  fixture.db.addRollupHour(INSTANCE, { bucket: agoMs(1), n: "10" });

  const s = await run();
  assert.equal(s.overview.detections.now, 1,
               "detecția de acum o oră a căzut în fereastra dinainte");
  assert.equal(s.overview.events.now, 10,
               "ora de acum o oră a căzut în fereastra dinainte");
  assert.equal(s.series.length, 1, "ora de acum o oră a căzut din seria desenată");
});

test("un cont fără nicio instanță primește un rezumat gol, nu tot", async () => {
  const gol = await scopeForUser(fixture.db, 999_999);
  // Golit DUPĂ citirea domeniului: `scopeForUser` interoghează și el, iar
  // instrucțiunile lui n-au nicio legătură cu întrebarea de aici.
  fixture.db.statements.length = 0;
  const s = await summary(fixture.db, gol, INSTANCE);
  assert.equal(s.overview.incidentsOpen, 0);
  assert.deepEqual(s.series, []);
  assert.deepEqual(s.activity, []);
  assert.equal(fixture.db.statements.length, 0,
               "un domeniu gol a plecat spre bază; un domeniu gol nu se lărgește");
});


test("un moment scris de MariaDB ca text fără fus se citește ca UTC", async () => {
  // Driverul întoarce `DATETIME(6)` ca `"2026-08-16 10:00:00.000"` — fără fus.
  // `new Date(...)` pe forma asta citește ora ca LOCALĂ. Pe o gazdă pe fusul
  // României, fiecare moment ar aluneca cu două-trei ore: cronologia rămâne în
  // ordine, doar cu ore greșite, iar rândurile de la marginea ferestrei trec
  // dintr-o jumătate în alta.
  //
  // Testul e scris ca o COMPARAȚIE între două coloane care descriu același
  // moment: blocarea și detecția sunt puse la aceeași milisecundă, deci orice
  // deplasare le desparte.
  const cand = agoMs(2);
  fixture.db.addDetection(INSTANCE, { ts: cand, rule_id: "regula" });
  fixture.db.addBlock(INSTANCE, { blocked_at: cand, ip: "203.0.113.9" });

  const s = await run();
  const det = s.activity.find((x) => x.kind === "detection");
  const blk = s.activity.find((x) => x.kind === "block");
  assert.ok(det !== undefined && blk !== undefined);
  assert.equal(blk.at, det.at,
               "aceeași milisecundă, citită diferit din două coloane — una " +
               "dintre ele a fost interpretată ca oră locală");
  assert.equal(blk.at, cand, "momentul citit nu e cel scris");
});
