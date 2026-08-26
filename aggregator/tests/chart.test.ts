/**
 * Graficele panoului: ce desenează, și ce refuză să deseneze.
 *
 * Trei feluri în care un grafic minte fără să scrie nimic fals, și fiecare are
 * testul lui aici:
 *
 *   * **o oră fără măsurătoare desenată ca zero.** Cele două arată identic pe
 *     ecran și înseamnă lucruri opuse: „n-a fost trafic" și „nu știu dacă a
 *     fost". Pe un panou de securitate, a doua e chiar întrebarea;
 *   * **o oră lipsă sărită cu totul.** Barele se închid peste ea și o pană de
 *     șase ore devine o linie continuă;
 *   * **axa tăiată.** O creștere de trei procente devine un munte.
 *
 * Plus constrângerea care le guvernează pe toate: sub CSP-ul paginii nu există
 * nici `<script>`, nici `style=`. Un grafic desenat cu ele nu se vede — și ce
 * rămâne pe ecran arată exact ca „nu s-a întâmplat nimic".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  barGeometry, hourEpoch, hourLabel, hourSeries, niceCeiling, rankGeometry,
  shortNumber,
} from "../lib/chart";
import type { Point } from "../lib/chart";

const eticheta = (p: Point) => hourLabel(Number(p.bucket));

function ore(...valori: (number | null)[]): Point[] {
  const T0 = Date.UTC(2026, 7, 21, 0);
  return valori.map((v, i) => ({
    bucket: String(T0 + i * 3_600_000),
    value: v,
    title: v === null ? "nu s-a măsurat" : `${v} evenimente`,
  }));
}

// ---------------------------------------------------------------------------
// Axa
// ---------------------------------------------------------------------------

test("axa pleacă de la zero: o bară de jumătate din vârf are jumătate din înălțime",
     () => {
  const g = barGeometry(ore(100, 50), eticheta);
  const [plina, jumatate] = g.bars;
  assert.ok(Math.abs(jumatate.h - plina.h / 2) < 0.01,
            `bara de 50 are ${jumatate.h}, cea de 100 are ${plina.h}: axa e tăiată, ` +
            "deci o creștere mică arată ca un munte");
});

test("capătul de sus se rotunjește la ceva ce se poate citi", () => {
  assert.equal(niceCeiling(1743), 2000);
  assert.equal(niceCeiling(3), 5);
  assert.equal(niceCeiling(11), 20);
  assert.equal(niceCeiling(100), 100);
  // Marginea care contează: o serie numai de zerouri nu are voie să producă
  // împărțire la zero — `NaN` într-un atribut SVG e o bară care nu se desenează.
  assert.equal(niceCeiling(0), 1);
  assert.equal(niceCeiling(-5), 1);
  assert.equal(niceCeiling(NaN), 1);
});

test("geometria FOLOSEȘTE capătul rotunjit, nu maximul brut", () => {
  // `niceCeiling` corect și nechemat lasă axa să se termine la 1743, iar
  // cititorul face împărțiri în cap. Verificat prin falsificare: fără linia
  // asta, scoaterea apelului trecea neobservată.
  const g = barGeometry(ore(1743, 100), eticheta);
  assert.equal(g.peak, 2000, `vârful e ${g.peak}, deci axa se termină pe o cifră ` +
                             "care nu se citește dintr-o privire");
  // Și bara maximă nu mai atinge tavanul, fiindcă tavanul e mai sus decât ea.
  assert.ok(g.bars[0].h < g.height, "bara atinge marginea de sus a graficului");
});


test("o serie numai de zerouri desenează bare de zero, nu `NaN`", () => {
  const g = barGeometry(ore(0, 0, 0), eticheta);
  for (const b of g.bars) {
    assert.ok(Number.isFinite(b.h), `înălțime ${b.h}: bara n-ar fi desenată deloc`);
    assert.equal(b.h, 0);
    assert.equal(b.missing, false, "zero nu e «nu s-a măsurat»");
  }
});

// ---------------------------------------------------------------------------
// Golurile — proprietatea care contează cel mai mult
// ---------------------------------------------------------------------------

test("o oră fără măsurătoare NU e o bară de zero", () => {
  const g = barGeometry(ore(100, null, 100), eticheta);
  const gol = g.bars[1];
  assert.equal(gol.missing, true);
  assert.ok(gol.h > 0, (
    "ora fără măsurătoare a fost desenată ca zero, deci arată identic cu o oră " +
    "în care chiar n-a fost trafic — două lucruri opuse, același desen"));
  assert.match(gol.title, /nu s-a măsurat/);
});

test("orele lipsă nu se sar: seria rămâne continuă", () => {
  // 10:00 și 14:00 primite; 11, 12, 13 lipsesc. Sărite, cele două bare ar sta
  // alături și o pană de trei ore ar dispărea din grafic.
  const puncte = hourSeries([
    { bucket: "2026-08-21 10:00:00", value: 5, title: "a" },
    { bucket: "2026-08-21 14:00:00", value: 7, title: "b" },
  ], 48);
  assert.equal(puncte.length, 5, "seria s-a închis peste orele lipsă");
  assert.deepEqual(puncte.map((p) => p.value), [5, null, null, null, 7]);
});

test("seria se ancorează în ultima oră PRIMITĂ, nu în ceasul agregatorului", () => {
  // Două ceasuri: al gazdei monitorizate și al agregatorului. Ancorat în `now()`,
  // un decalaj între ele ar produce o coadă de goluri care nu există — și care
  // s-ar citi ca o pană a serverului.
  const puncte = hourSeries([
    { bucket: "2020-01-01 00:00:00", value: 1, title: "vechi" },
    { bucket: "2020-01-01 01:00:00", value: 2, title: "vechi" },
  ], 48);
  assert.equal(puncte.length, 2);
  assert.equal(puncte[puncte.length - 1].value, 2,
               "ultima oră primită nu e ultima din serie");
});

test("fereastra nu inventează goluri dinaintea primei măsurători", () => {
  // O gazdă instalată ieri n-are voie să arate 46 de ore de «nu s-a măsurat»:
  // golul acela ar spune ceva despre ore în care fluxul nici nu exista.
  const puncte = hourSeries([
    { bucket: "2026-08-21 10:00:00", value: 5, title: "a" },
    { bucket: "2026-08-21 11:00:00", value: 6, title: "b" },
  ], 48);
  assert.equal(puncte.length, 2);
});

test("fereastra se oprește la lungimea cerută", () => {
  const multe = Array.from({ length: 100 }, (_, i) => ({
    bucket: `2026-08-21 ${String(i % 24).padStart(2, "0")}:00:00`,
    value: i, title: String(i),
  }));
  assert.ok(hourSeries(multe, 12).length <= 12);
});

// ---------------------------------------------------------------------------
// Timpul
// ---------------------------------------------------------------------------

test("momentele se citesc ca UTC, nu ca oră locală", () => {
  // `new Date("2026-08-21 13:00:00")` e ora LOCALĂ în Node. Pe o mașină din
  // București, tot graficul s-ar muta cu trei ore — iar barele ar arăta perfect
  // normale, deci nimic n-ar semnala mutarea.
  assert.equal(hourEpoch("2026-08-21 13:00:00"), Date.UTC(2026, 7, 21, 13));
  assert.equal(hourEpoch("2026-08-21T13:00:00.000Z"), Date.UTC(2026, 7, 21, 13));
  assert.equal(hourEpoch("nu e un moment"), null);
});

test("eticheta de pe axă e citibilă și în UTC", () => {
  assert.equal(hourLabel(Date.UTC(2026, 7, 21, 9)), "21.08 09");
});

test("axa nu se aglomerează: etichetele sunt rărite", () => {
  const g = barGeometry(ore(...Array.from({ length: 48 }, (_, i) => i)), eticheta);
  assert.equal(g.bars.length, 48);
  assert.ok(g.ticks.length <= 8, `${g.ticks.length} etichete pe 48 de bare`);
  assert.ok(g.ticks.length >= 4, "prea puține etichete ca să se citească axa");
});

// ---------------------------------------------------------------------------
// Seria goală
// ---------------------------------------------------------------------------

test("o serie fără nicio măsurătoare se declară goală", () => {
  // Ca pagina să poată spune «n-a sosit nimic» în loc să deseneze un grafic gol,
  // care arată ca zero trafic.
  const g = barGeometry(ore(null, null), eticheta);
  assert.equal(g.empty, true);
  assert.equal(hourSeries([], 48).length, 0);
});

test("o serie cu măsurători nu se declară goală", () => {
  assert.equal(barGeometry(ore(0, 1), eticheta).empty, false);
});

// ---------------------------------------------------------------------------
// Clasamentul
// ---------------------------------------------------------------------------

test("barele clasamentului se compară cu cea mai mare, nu cu totalul", () => {
  const g = rankGeometry([
    { label: "nginx", value: 100, title: "a" },
    { label: "sshd", value: 50, title: "b" },
  ]);
  assert.equal(g.rows[0].pct, 100);
  assert.equal(g.rows[1].pct, 50, (
    "procentele sunt din total, deci cu douăzeci de surse toate barele devin " +
    "invizibile și nu se compară nimic cu nimic"));
  assert.equal(g.total, 150);
});

test("o sursă foarte mică rămâne vizibilă", () => {
  const g = rankGeometry([
    { label: "mult", value: 100_000, title: "a" },
    { label: "putin", value: 1, title: "b" },
  ]);
  assert.ok(g.rows[1].pct >= 1, (
    "bara a coborât la zero, deci o intrare care EXISTĂ nu se vede — mai rău " +
    "decât una absentă, fiindcă pare că n-ai date"));
});

test("un clasament gol nu împarte la zero", () => {
  assert.deepEqual(rankGeometry([]), { rows: [], total: 0 });
});

test("numerele mari se scurtează, cele mici nu", () => {
  assert.equal(shortNumber(1700), "1.7k");
  assert.equal(shortNumber(23_000), "23k");
  assert.equal(shortNumber(2_300_000), "2.3M");
  assert.equal(shortNumber(42), "42");
  assert.equal(shortNumber(0), "0");
});

// ---------------------------------------------------------------------------
// Ce ajunge în pagină
// ---------------------------------------------------------------------------

type Ora = { bucket: number; bySource: Record<string, number> };

const H = 3_600_000;
const ORA0 = Date.UTC(2026, 7, 21, 10);

function sumar(over: Record<string, unknown> = {}) {
  return {
    overview: {
      attackers: { now: 0, before: 0 }, detections: { now: 0, before: 0 },
      events: { now: 0, before: 0 }, incidentsOpen: 0, incidentsSevere: 0,
      findingsOpen: 0, blocksActive: 0, bySeverity: [],
    },
    series: [] as Ora[],
    rankings: { attackers: [], rules: [], sources: [] },
    activity: [], truncated: [] as string[],
    ...over,
  };
}

async function randeaza(over: Record<string, unknown> = {}): Promise<string> {
  const { summaryPage } = await import("../lib/panel-page");
  return summaryPage({
    username: "operator", csrfToken: "x",
    instances: [{ instanceId: "prod-a", label: "A", role: "owner",
                  enabled: true, lastBatchAt: null } as never],
    selected: "prod-a", active: "/panel", arrivals: new Map(),
    incidents: [], sumar: sumar(over),
  } as never);
}

test("graficul stivuit ajunge în pagină, cu geometria în ATRIBUTE", async () => {
  const html = await randeaza({
    series: [{ bucket: ORA0, bySource: { nginx: 1700, sshd: 12 } }],
    rankings: {
      attackers: [{ key: "203.0.113.9", count: 40, extra: "3 reguli" }],
      rules: [{ key: "auth.ssh_bruteforce", count: 40, extra: "1 IP" }],
      sources: [{ key: "nginx", count: 1700, extra: "1 ore" }],
    },
  });

  assert.match(html, /<svg class="grafic"/, "niciun grafic în pagină");
  assert.match(html, /<rect class="g-s0"[^>]*height="/, "benzile n-au înălțime");
  assert.match(html, /<rect class="g-s1"[^>]*height="/, (
    "a doua sursă n-a fost desenată — un grafic stivuit cu o singură bandă e " +
    "un grafic simplu care pretinde că e stivuit"));
  assert.match(html, /1700/, "valoarea nu apare nicăieri");
  assert.match(html, /nginx/, "clasamentul nu apare");
  assert.match(html, /203\.0\.113\.9/, "clasamentul de adrese nu apare");
});

test("legenda numește fiecare bandă desenată", async () => {
  // Fără legendă, un grafic stivuit e un teanc de culori. Cu una care nu se
  // potrivește cu clasele desenate, e mai rău: spune cine a produs traficul, și
  // greșit.
  const html = await randeaza({
    series: [{ bucket: ORA0, bySource: { nginx: 10, sshd: 5 } }],
  });
  assert.match(html, /<span class="leg-pata g-s0"><\/span>nginx/);
  assert.match(html, /<span class="leg-pata g-s1"><\/span>sshd/);
});

test("cartonașele de sus arată cifrele și tendința lor", async () => {
  const html = await randeaza({
    overview: {
      attackers: { now: 12, before: 30 }, detections: { now: 300, before: 100 },
      events: { now: 1700, before: 1700 }, incidentsOpen: 3, incidentsSevere: 1,
      findingsOpen: 31, blocksActive: 7,
      bySeverity: [{ severity: "critical", count: 1 }, { severity: "low", count: 2 }],
    },
  });
  assert.match(html, /class="card-nr">12</, "numărul de adrese nu apare");
  assert.match(html, /class="card-nr">31</, "numărul de vulnerabilități nu apare");
  assert.match(html, /class="card-nr">7</, "numărul de blocări nu apare");
  assert.match(html, /t-jos">−60%/, "scăderea de 60% nu e arătată ca scădere");
  assert.match(html, /t-sus">\+200%/, "creșterea de 200% nu e arătată ca creștere");
  assert.match(html, /t-egal">la fel/, "egalitatea e arătată ca o schimbare");
  assert.match(html, /card-alarma/, "un incident grav nu se deosebește de restul");
});

test("pe numere mici se scrie diferența, nu procentul", async () => {
  // 1 → 3 e «+200%» și nu înseamnă nimic. Un panou care spune asta învață
  // cititorul să nu se uite la tendințe.
  const html = await randeaza({
    overview: {
      ...sumar().overview,
      detections: { now: 3, before: 1 },
    },
  });
  assert.match(html, /\+2 fata de ieri/, "s-a scris un procent pe numere mici");
  assert.ok(!/\+200%/.test(html), "procentul de pe numere mici a rămas în pagină");
});

test("banda de severități desenează fiecare severitate deschisă", async () => {
  const html = await randeaza({
    overview: {
      ...sumar().overview, incidentsOpen: 101, incidentsSevere: 1,
      bySeverity: [{ severity: "critical", count: 1 }, { severity: "low", count: 100 }],
    },
  });
  assert.match(html, /<rect class="banda-sev-critical"[^>]*width="/, (
    "un `critical` singur, între o sută de `low`, a dispărut din bandă — exact " +
    "felia care n-are voie să dispară"));
  assert.match(html, /<rect class="banda-sev-low"/);
});

test("cronologia amestecă detecțiile și blocările, în ordine", async () => {
  const html = await randeaza({
    activity: [
      { at: ORA0 + H, kind: "detection", title: "auth.ssh_bruteforce",
        detail: "203.0.113.9", severity: "high" },
      { at: ORA0, kind: "block", title: "IP blocat", detail: "203.0.113.9",
        severity: "brute-force" },
    ],
  });
  const i = html.indexOf("auth.ssh_bruteforce");
  const j = html.indexOf("IP blocat");
  assert.ok(i > 0 && j > 0, "cronologia nu apare în pagină");
  assert.ok(i < j, "cronologia e desenată în ordine inversă");
  assert.match(html, /cron-blocare/, "blocarea nu se deosebește de o detecție");
});

test("pagina nu conține NIMIC din ce ar refuza politica", async () => {
  const html = await randeaza({
    series: [{ bucket: ORA0, bySource: { nginx: 5 } }],
    overview: { ...sumar().overview, bySeverity: [{ severity: "high", count: 2 }] },
    activity: [{ at: ORA0, kind: "block", title: "IP blocat",
                 detail: "203.0.113.9", severity: "brute-force" }],
  });

  assert.ok(!/<script/i.test(html), "un `<script>` în pagină — politica îl blochează");
  assert.ok(!/\sstyle="/i.test(html), (
    "un atribut `style=` — browserul îl aruncă sub `style-src 'self'`, iar " +
    "graficul desenat cu el nu se vede deloc"));
});

test("fiecare bandă poartă un `<title>`, ca să se poată citi fără mouse",
     async () => {
  const html = await randeaza({ series: [{ bucket: ORA0, bySource: { nginx: 5 } }] });
  assert.match(html, /<rect class="g-s0"[^>]*><title>/);
  assert.match(html, /role="img"/, "graficul n-are rol accesibil");
  assert.match(html, /aria-label="/, "graficul n-are descriere");
});

test("o oră fără măsurătoare se desenează ALTFEL decât una cu zero", async () => {
  // Într-o pană de șase ore, orele lipsă desenate ca bare de zero spun «n-a
  // fost trafic». Sunt lucruri diferite, iar diferența e chiar ce se caută.
  const html = await randeaza({
    series: [
      { bucket: ORA0, bySource: { nginx: 10 } },
      { bucket: ORA0 + 3 * H, bySource: { nginx: 10 } },
    ],
  });
  assert.match(html, /<rect class="g-lipsa"[^>]*><title>[^<]*nu s-a masurat/,
               "golul dintre cele două ore nu e marcat ca nemăsurat");
});

test("fără contoare, pagina SPUNE asta în loc să deseneze un grafic gol",
     async () => {
  const html = await randeaza();
  assert.ok(!/<svg class="grafic"/.test(html),
            "s-a desenat un grafic gol, care arată ca zero trafic");
  assert.match(html, /n-are ce fi desenat|nu.*desenat/i,
               "pagina tace despre lipsa contoarelor");
});

test("o citire tăiată de plafon se SPUNE în pagină", async () => {
  const html = await randeaza({ truncated: ["detecții"] });
  assert.match(html, /taiata de plafon/i,
               "plafonul atins nu apare nicăieri; cifrele arată ca un total");
  assert.match(html, /detecții/);
});

// ---------------------------------------------------------------------------
// Geometria stivuita: cele trei proprietati pe care nimic nu le atingea
// ---------------------------------------------------------------------------
test("sursele din coada se ADUNA intr-o banda, nu se arunca", async () => {
  // Eșecul: înălțimea stivei mai mică decât totalul orei. Cine compară graficul
  // cu cartonașul de sus găsește o diferență pe care nimic n-o explică — și e
  // mai rău decât un grafic lipsă, fiindcă arată corect.
  const { stackSeries, STACK_SOURCES, ALTELE } = await import("../lib/chart");
  const bySource: Record<string, number> = {};
  for (let i = 0; i < STACK_SOURCES + 3; i += 1) bySource[`sursa${i}`] = 10;

  const { columns, sources } = stackSeries([{ epoch: ORA0, bySource }], 48);
  assert.equal(sources.length, STACK_SOURCES + 1,
               "coada n-a devenit o bandă proprie");
  assert.equal(sources[sources.length - 1], ALTELE);

  const total = Object.values(columns[0].bySource).reduce((a, n) => a + n, 0);
  assert.equal(total, (STACK_SOURCES + 3) * 10,
               "totalul orei s-a micșorat: sursele din coadă au fost aruncate, " +
               "nu adunate, iar stiva nu mai e totalul orei");
  assert.equal(columns[0].bySource[ALTELE], 30);
});

test("banda `g-sN` e a sursei numărul N din legendă", async () => {
  // Eșecul: legenda spune „albastru = nginx" iar banda albastră e a lui sshd.
  // Un grafic care spune CINE a produs traficul, și greșit, e mai rău decât unul
  // care nu spune. Prima falsificare l-a prins: benzile inversate lăsau ambele
  // clase în pagină, deci testul care le căuta pe rând trecea.
  const html = await randeaza({
    series: [{ bucket: ORA0, bySource: { nginx: 100, sshd: 1 } }],
  });
  const s0 = /<rect class="g-s0"[^>]*><title>([^<]*)<\/title>/.exec(html);
  const s1 = /<rect class="g-s1"[^>]*><title>([^<]*)<\/title>/.exec(html);
  assert.ok(s0 !== null && s1 !== null, "benzile n-au titluri de citit");
  assert.match(s0[1], /nginx/,
               "prima bandă din legendă nu e desenată cu prima clasă de culoare");
  assert.match(s1[1], /sshd/,
               "a doua bandă din legendă nu e desenată cu a doua clasă");
});

test("o felie minusculă din bandă rămâne VIZIBILĂ", async () => {
  // Un `critical` singur, între zece mii de `low`: 1/10001 din 720 e sub o
  // zecime de pixel. Desenată proporțional, felia dispare — exact felia care nu
  // are voie să dispară de pe un panou de securitate.
  const { shareBar, MIN_SLICE } = await import("../lib/chart");
  const felii = shareBar([{ key: "critical", value: 1 },
                          { key: "low", value: 10_000 }], 720);
  assert.equal(felii.length, 2, "felia mică a fost scoasă din bandă");
  assert.ok(felii[0].w >= MIN_SLICE,
            `felia de 1 la 10000 are lățimea ${felii[0].w}, sub pragul vizibil`);
  const suma = felii.reduce((a, f) => a + f.w, 0);
  assert.ok(Math.abs(suma - 720) < 0.001,
            `benzile însumează ${suma}, nu lățimea întreagă — banda are o ` +
            "gaură sau iese din cadru");
  assert.ok(felii[1].x >= felii[0].x + felii[0].w - 0.001,
            "feliile se suprapun");
});

test("o bandă cu o singură categorie o umple întreagă", async () => {
  // Garda celuilalt sens: pragul minim nu are voie să lase spațiu gol când nu e
  // nimic de comprimat.
  const { shareBar } = await import("../lib/chart");
  const felii = shareBar([{ key: "high", value: 5 }], 720);
  assert.equal(felii.length, 1);
  assert.equal(Math.round(felii[0].w), 720);
});
