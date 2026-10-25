/**
 * Vârsta cifrei de pe pagina de vulnerabilități, și eșecul care o îngheață.
 *
 * Eșecul pe care îl previne, măsurat pe 21 august 2026 și trăit de operator:
 * pagina arăta 31 de vulnerabilități neaplicate, iar pe server `dnf update` nu
 * găsea nimic. Numărul nu era greșit — fusese măsurat la 03:23, iar pachetele
 * fuseseră reparate la 09:14. Între cele două a mai rulat o scanare și A EȘUAT
 * cu `timeout`; reușită, ar fi închis toate cele 31.
 *
 * Nimic din asta nu era vizibil. Pagina nu spunea nici când măsurase, nici că
 * încercarea de reîmprospătare căzuse. Operatorul a văzut două surse care nu
 * erau de acord și n-avea de unde ști care minte.
 *
 * De aceea testele de aici cer DOUĂ lucruri deosebite: momentul ultimei
 * măsurători bune, și faptul că ultima încercare a eșuat. Contopite într-unul,
 * un eșec ar ascunde momentul măsurătorii bune — sau invers.
 *
 * Al treilea caz, adăugat pe 25 octombrie 2026: o scanare ÎNCHEIATĂ cu bine dar
 * cu avertisment de acoperire în `error` (`trivy_image` și imaginile sărite).
 * Pagina confirma doar „Masurat la <ora>", deci o cifră proaspătă și incompletă
 * arăta ca una întreagă.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { scanHealth, scanHealthAll } from "../lib/data/scans";
import type { ScanHealth, ScannerHealth } from "../lib/data/scans";
import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as vulnGet } from "../app/panel/vulnerabilitati/route";
import {
  PASSWORD, USERNAME, captureError, captureWarn, completeLogin, forgetAuthServer,
  getRequest, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture } from "./auth-routes-harness";
import type { InstanceScope } from "../lib/auth/scope";

const INSTANCE = "prod-a";

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };
let scope: InstanceScope;

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
  fixture.db.addInstance(INSTANCE, { label: "A" });
  assert.equal((await grantInstance(fixture.db, USERNAME, INSTANCE, "owner")).ok, true);
  scope = await scopeForUser(fixture.db, fixture.user.id);
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

const T0 = 1_780_000_000_000;
const ora = (n: number) => T0 + n * 3_600_000;

test("un eșec NU ascunde momentul ultimei măsurători bune", async () => {
  // Chiar secvența din 21 august: o scanare bună, apoi una care cade.
  fixture.db.addScan(INSTANCE, {
    source_id: 25, status: "completed", started_at: ora(0), finished_at: ora(0),
    findings_count: "31",
  });
  fixture.db.addScan(INSTANCE, {
    source_id: 26, status: "failed", started_at: ora(7), finished_at: ora(7),
    error: "timeout",
  });

  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.equal(h.latest?.sourceId, 26, "ultima rulare nu e cea mai recentă");
  assert.equal(h.latest?.status, "failed");
  assert.equal(h.latest?.error, "timeout");
  assert.equal(h.lastGood?.sourceId, 25,
               "momentul ultimei măsurători bune s-a pierdut sub eșec — atunci " +
               "pagina n-ar putea spune cât de veche e cifra");
});

test("fără nicio scanare încheiată bine, vârsta e NECUNOSCUTĂ, nu recentă", async () => {
  // „N-am măsurat niciodată cu succes" și „am măsurat adineauri" nu au voie să
  // arate la fel: prima e o pagină în care nu poți avea încredere.
  fixture.db.addScan(INSTANCE, {
    source_id: 1, status: "failed", started_at: ora(0), error: "timeout",
  });
  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.equal(h.lastGood, null);
  assert.equal(h.latest?.status, "failed");
});

test("o scanare care RULEAZĂ acum nu se numără ca măsurătoare bună", async () => {
  fixture.db.addScan(INSTANCE, {
    source_id: 1, status: "completed", started_at: ora(0), finished_at: ora(0),
  });
  fixture.db.addScan(INSTANCE, {
    source_id: 2, status: "running", started_at: ora(9), finished_at: null,
  });

  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.equal(h.latest?.status, "running");
  assert.equal(h.lastGood?.sourceId, 1,
               "o rulare neîncheiată a fost luată drept măsurătoare");
});

test("se alege scanerul cerut, nu prima rulare care se nimerește", async () => {
  // Pagina de vulnerabilități e alimentată de `dnf` pe AlmaLinux. O rulare de
  // `trivy` mai recentă nu spune nimic despre vârstea cifrelor de acolo.
  fixture.db.addScan(INSTANCE, {
    source_id: 1, scanner: "dnf", status: "completed",
    started_at: ora(0), finished_at: ora(0),
  });
  fixture.db.addScan(INSTANCE, {
    source_id: 2, scanner: "trivy_fs", status: "completed",
    started_at: ora(9), finished_at: ora(9),
  });

  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.equal(h.lastGood?.scanner, "dnf");
  assert.equal(h.lastGood?.sourceId, 1);
});

test("scanările altui server nu dau vârsta cifrelor tale", async () => {
  fixture.db.addInstance("prod-b", { label: "B" });
  fixture.db.addScan("prod-b", {
    source_id: 99, status: "completed", started_at: ora(9), finished_at: ora(9),
  });
  fixture.db.addScan(INSTANCE, {
    source_id: 1, status: "completed", started_at: ora(0), finished_at: ora(0),
  });

  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.equal(h.lastGood?.sourceId, 1,
               "vârsta măsurătorii altui server a fost arătată ca fiind a ta");
  assert.equal(h.latest?.sourceId, 1);
});

test("fără nicio scanare, ambele sunt `null` — nu se inventează un moment", async () => {
  const h = await scanHealth(fixture.db, scope, INSTANCE);
  assert.deepEqual(h, { lastGood: null, latest: null });
});

// ---------------------------------------------------------------------------
// Ce ajunge pe ECRAN. O funcție de date corectă și un șablon care n-o folosește
// arată împreună exact ca pagina de dinainte.
// ---------------------------------------------------------------------------

/**
 * Starea unui singur scaner, în forma veche `{ lastGood, latest }`, sau lista
 * pe scaner pe care o dă ruta acum. Forma veche se învelește cu numele
 * scanerului luat din rândurile ei; `null`/`null` e „nicio scanare".
 */
async function render(
  scan: Awaited<ReturnType<typeof scanHealth>> | ScannerHealth[],
): Promise<string> {
  const { findingsPage } = await import("../lib/panel-page");
  const own = (scan as ScanHealth).lastGood ?? (scan as ScanHealth).latest;
  const scans: ScannerHealth[] = Array.isArray(scan) ? scan
    : own === null ? [] : [{ scanner: own.scanner, ...scan }];
  return findingsPage({
    username: "operator", csrfToken: "x", instances: [], selected: INSTANCE,
    active: "/panel/vulnerabilitati", arrivals: new Map(),
    findings: [], group: null, color: null,
    colors: { red: 0, amber: 0, green: 0, grey: 0 },
    counts: { neaplicate: 31, rezolvate: 0, inchise: 0, total: 31 },
    scans,
  } as never);
}

test("pagina spune CÂND a fost măsurat", async () => {
  const html = await render({
    lastGood: {
      sourceId: 25, scanner: "dnf", status: "completed",
      startedAt: "2026-08-21 00:21:07", finishedAt: "2026-08-21 00:23:06",
      findings: 31, resolved: 0, error: null, triggeredBy: "schedule",
    },
    latest: null,
  });
  // Data SINGURĂ nu e de ajuns: fără eticheta care spune ce e, cifra aia poate
  // fi orice. Verificat prin falsificare — scoasă eticheta, testul trecea în
  // continuare fiindcă data rămânea în pagină.
  assert.match(html, /Masurat la <strong>2026-08-21 00:23/,
               "momentul măsurătorii apare fără să spună CE e");
  assert.match(html, /<code>dnf<\/code>/,
               "pagina nu spune care scaner a măsurat");
});

test("pagina strigă când ultima scanare a EȘUAT", async () => {
  const html = await render({
    lastGood: {
      sourceId: 25, scanner: "dnf", status: "completed",
      startedAt: "2026-08-21 00:21:07", finishedAt: "2026-08-21 00:23:06",
      findings: 31, resolved: 0, error: null, triggeredBy: "schedule",
    },
    latest: {
      sourceId: 26, scanner: "dnf", status: "failed",
      startedAt: "2026-08-21 07:33:33", finishedAt: "2026-08-21 07:35:34",
      findings: 0, resolved: 0, error: "timeout", triggeredBy: "schedule",
    },
  });
  assert.match(html, /a esuat|a eșuat/i, "eșecul nu e anunțat");
  assert.match(html, /timeout/, "motivul eșecului nu apare");
  assert.match(html, /2026-08-21 00:23/,
               "eșecul a ascuns momentul ultimei măsurători bune");
});

test("pagina nu inventează un moment când n-a măsurat niciodată", async () => {
  const html = await render({ lastGood: null, latest: null });
  assert.match(html, /varsta|vârst/i,
               "pagina tace despre faptul că cifrele n-au vârstă cunoscută");
});

test("o scanare care rulează acum nu e anunțată ca eșec", async () => {
  // `running` nu e o problemă; anunțat ca eșec, ar fi o alarmă la fiecare
  // scanare, iar o alarmă permanentă e la fel de invizibilă ca tăcerea.
  const html = await render({
    lastGood: {
      sourceId: 25, scanner: "dnf", status: "completed",
      startedAt: "2026-08-21 00:21:07", finishedAt: "2026-08-21 00:23:06",
      findings: 31, resolved: 0, error: null, triggeredBy: "schedule",
    },
    latest: {
      sourceId: 27, scanner: "dnf", status: "running",
      startedAt: "2026-08-21 11:36:40", finishedAt: null,
      findings: 0, resolved: 0, error: null, triggeredBy: "manual",
    },
  });
  assert.doesNotMatch(html, /a esuat|a eșuat/i,
                      "o scanare în curs a fost anunțată ca eșec");
});

// ---------------------------------------------------------------------------
// Al treilea caz: scanarea a REUSIT, dar nu pe tot. `trivy_image` scrie in
// `scans.error` al unui rand `completed` imaginile pe care le-a sarit. Fara
// teste aici, pagina confirma ca s-a masurat, nu CE s-a masurat.
// ---------------------------------------------------------------------------

const AVERTISMENT =
  "2 imagini din 11 NU au fost ingerate — depășesc singure tot plafonul de " +
  "3000: registry.example.invalid/mare:1 (4100 constatări: 37 CRITICAL), " +
  "registry.example.invalid/alta:2 (3300 constatări: 9 CRITICAL).";

type Run = Awaited<ReturnType<typeof scanHealth>>["lastGood"] & object;

function run(over: Partial<Run>): Run {
  return {
    sourceId: 40, scanner: "trivy_image", status: "completed",
    startedAt: "2026-10-26 02:00:00", finishedAt: "2026-10-26 02:41:00",
    findings: 812, resolved: 0, error: null, triggeredBy: "schedule", ...over,
  };
}

test("o scanare încheiată cu avertisment NU arată ca una cu acoperire întreagă", async () => {
  // Operatorul vede 812 constatări și crede că sunt toate. În realitate două
  // imagini cu 37 + 9 CRITICAL au fost sărite: cifra e proaspătă și incompletă,
  // iar pagina de dinainte confirma doar „Masurat la <ora>".
  const rulare = run({ error: AVERTISMENT });
  const html = await render({ lastGood: rulare, latest: rulare });

  assert.match(html, /Acoperire partiala/,
               "acoperirea partială nu e spusă — cifra pare întreagă");
  assert.match(html, /registry\.example\.invalid\/mare:1/,
               "avertismentul nu numește imaginile sărite — operatorul nu știe " +
               "pe ce să se uite");
  assert.match(html, /37 CRITICAL/,
               "numărul de CRITICAL nearătate lipsește din pagină");
  assert.match(html, /Masurat la <strong>2026-10-26 02:41/,
               "avertismentul a ascuns momentul măsurătorii");
  assert.doesNotMatch(html, /a esuat|a eșuat/i,
                      "o scanare reușită cu avertisment a fost anunțată ca ESEC — " +
                      "remediul e altul, iar alarma devine zgomot");
});

test("avertismentul de acoperire nu depinde de ce scaner l-a scris", async () => {
  // `completed` + `error` nenul poate veni de la orice scaner, nu doar de la
  // `trivy_image`. Legat de un nume de scaner, următorul care folosește aceeași
  // coloană ar reveni la o pagină care tace.
  for (const scanner of ["dnf", "trivy_image", "un_scaner_nou"]) {
    const rulare = run({ scanner, error: AVERTISMENT });
    const html = await render({ lastGood: rulare, latest: rulare });
    assert.match(html, /Acoperire partiala/,
                 `avertismentul scanerului ${scanner} nu ajunge pe pagină`);
  }
});

test("avertismentul vine din baza de date și trece prin escapeHtml", async () => {
  // Numele unei imagini e text ales de cine a publicat-o. Interpolat crud într-o
  // pagină văzută de operator, ar rula în sesiunea lui.
  const rulare = run({ error: 'x <img src=x onerror="alert(1)"> y' });
  const html = await render({ lastGood: rulare, latest: rulare });

  assert.match(html, /Acoperire partiala/, "avertismentul nu s-a randat deloc");
  assert.doesNotMatch(html, /<img src=x/,
                      "textul avertismentului a ajuns în pagină ca marcaj");
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/,
               "textul nu apare în pagină nici măcar escapat");
});

test("o scanare curată nu poartă avertisment — altfel avertismentul devine zgomot", async () => {
  // O casetă care apare mereu e la fel de invizibilă ca tăcerea. `null`, șirul
  // gol și spațiile sunt aceeași stare: nu s-a sărit nimic.
  for (const error of [null, "", "   \n "]) {
    const rulare = run({ error });
    const html = await render({ lastGood: rulare, latest: rulare });
    assert.doesNotMatch(html, /Acoperire partiala/,
                        `eroarea ${JSON.stringify(error)} a desenat un avertisment`);
    assert.match(html, /Masurat la <strong>2026-10-26 02:41/,
                 "fără avertisment, momentul măsurătorii a dispărut");
  }
});

test("avertismentul rămâne cât timp cifra incompletă e cea de pe ecran", async () => {
  // Noaptea la 02:00 scanarea încheie cu avertisment; la 02:05 pornește alta.
  // Cifrele de pe ecran sunt TOT ale primeia, deci avertismentul nu are voie să
  // dispară cu `running` — legat de ultima rulare, ar dispărea tocmai atunci.
  const html = await render({
    lastGood: run({ error: AVERTISMENT }),
    latest: run({
      sourceId: 41, status: "running", finishedAt: null, error: null,
      startedAt: "2026-10-26 02:45:00",
    }),
  });
  assert.match(html, /Acoperire partiala/,
               "avertismentul a dispărut când a pornit o scanare nouă, deși " +
               "cifrele de pe ecran sunt tot cele incomplete");
  assert.doesNotMatch(html, /a esuat|a eșuat/i);
});

test("eșecul rămâne primul, avertismentul al doilea, vârsta ultima", async () => {
  // Ierarhia din docstring-ul lui `scanAge`: eșecul strigă mai tare decât
  // vârsta, iar acoperirea partială stă între ele. Dacă ordinea se inversează,
  // operatorul citește „Masurat la" ca pe concluzie și avertismentul ca pe o
  // notă de subsol.
  const html = await render({
    lastGood: run({ error: AVERTISMENT }),
    latest: run({
      sourceId: 41, status: "failed", error: "timeout",
      startedAt: "2026-10-27 02:00:00", finishedAt: "2026-10-27 02:30:00",
    }),
  });
  const esec = html.search(/Ultima scanare a esuat/);
  const partial = html.search(/Acoperire partiala/);
  const varsta = html.search(/Masurat la/);
  assert.ok(esec >= 0, "eșecul nu e anunțat");
  assert.ok(partial >= 0, "avertismentul lipsește când ultima rulare a eșuat");
  assert.ok(varsta >= 0, "vârsta lipsește");
  assert.ok(esec < partial && partial < varsta,
            `ordinea e greșită: eșec@${esec}, acoperire@${partial}, vârstă@${varsta}`);
  assert.match(html, /timeout/, "motivul eșecului a dispărut sub avertisment");
});

test("un eșec fără avertisment în cifra bună nu inventează acoperire partială", async () => {
  // Cazul din 21 august, neschimbat: eșecul vorbește singur. Un avertisment
  // pus pe lângă el ar face doi alarmiști din una.
  const html = await render({
    lastGood: run({ scanner: "dnf", error: null }),
    latest: run({
      scanner: "dnf", sourceId: 41, status: "failed", error: "timeout",
      startedAt: "2026-10-27 02:00:00",
    }),
  });
  assert.match(html, /Ultima scanare a esuat/);
  assert.doesNotMatch(html, /Acoperire partiala/,
                      "eșecul a fost însoțit de un avertisment de acoperire inventat");
});

// ---------------------------------------------------------------------------
// Mai mulți scaneri pe aceeași pagină. `listFindings` nu filtrează după scaner,
// deci „Măsurat la <ora lui dnf>" stătea deasupra unei liste în care o parte din
// rânduri veneau de la `trivy_image`, cu altă oră, alt eșec sau alt avertisment.
// ---------------------------------------------------------------------------

function entry(scanner: string, good: Partial<Run> | null,
               latest: Partial<Run> | "same" | null = "same"): ScannerHealth {
  const lastGood = good === null ? null : run({ scanner, ...good });
  return {
    scanner, lastGood,
    latest: latest === "same" ? lastGood
      : latest === null ? null : run({ scanner, ...latest }),
  };
}

/** Pagina reală, prin rută: sesiune, domeniu, bază — nu doar șablonul. */
async function pageThroughRoute(): Promise<string> {
  const token = await completeLogin(
    { loginGet, loginPost, totpGet, totpPost },
    { username: USERNAME, password: PASSWORD, totpSecret: fixture.totpSecret });
  return await (await vulnGet(getRequest(
    `/panel/vulnerabilitati?instanta=${INSTANCE}`,
    { cookies: { sentinel_session: token } }))).text();
}

test("scanerele se citesc din rulări: unul nou nu rămâne invizibil", async () => {
  // Cu o listă scrisă în cod (`dnf`, `trivy_fs`, `trivy_image`), scanerul de
  // mâine ar rula, ar produce constatări pe pagină și n-ar apărea nicăieri în
  // starea ei — fără ca ceva să devină roșu. Inserate NEALFABETIC, ca ordinea
  // de la ieșire să fie a codului, nu a bazei.
  for (const scanner of ["trivy_image", "un_scaner_nou", "dnf", "trivy_fs"]) {
    fixture.db.addScan(INSTANCE, { scanner, started_at: ora(1), finished_at: ora(1) });
  }
  const all = await scanHealthAll(fixture.db, scope, INSTANCE);
  assert.deepEqual(all.map((s) => s.scanner),
                   ["dnf", "trivy_fs", "trivy_image", "un_scaner_nou"],
                   "lista scanerelor nu e cea din rulări, în ordine alfabetică");
});

test("fiecare scaner are starea LUI: un eșec nu se amestecă cu alt scaner", async () => {
  // `dnf` a reușit la 00:00; `trivy_image` a reușit la 02:00 și a eșuat la 09:00.
  // Contopite, „ultima rulare" ar fi eșecul lui `trivy_image` și ar acoperi
  // reușita lui `dnf` (sau invers: `dnf` ar șterge eșecul).
  fixture.db.addScan(INSTANCE, { source_id: 1, scanner: "dnf",
    started_at: ora(0), finished_at: ora(0) });
  fixture.db.addScan(INSTANCE, { source_id: 2, scanner: "trivy_image",
    started_at: ora(2), finished_at: ora(2) });
  fixture.db.addScan(INSTANCE, { source_id: 3, scanner: "trivy_image", status: "failed",
    started_at: ora(9), finished_at: ora(9), error: "timeout" });

  const by = new Map((await scanHealthAll(fixture.db, scope, INSTANCE))
    .map((s) => [s.scanner, s]));
  assert.equal(by.get("dnf")?.latest?.status, "completed");
  assert.equal(by.get("trivy_image")?.latest?.status, "failed");
  assert.equal(by.get("trivy_image")?.lastGood?.sourceId, 2,
               "momentul ultimei măsurători bune a lui trivy_image s-a pierdut");
});

test("scanerele altui server nu apar pe pagina ta", async () => {
  // Prin rută, cu un cont care vede amândouă serverele: B rulează `nuclei`, A
  // nu. Un filtru de instanță căzut din lista scanerelor ar scrie pe pagina lui
  // A „nuclei n-a încheiat nicio scanare cu bine" — adică ce caută cineva pe
  // serverul celuilalt.
  fixture.db.addInstance("prod-b", { label: "B" });
  assert.equal((await grantInstance(fixture.db, USERNAME, "prod-b", "owner")).ok, true);
  fixture.db.addScan(INSTANCE, { source_id: 1, scanner: "dnf",
    started_at: ora(0), finished_at: ora(0) });
  fixture.db.addScan("prod-b", { source_id: 1, scanner: "nuclei", status: "failed",
    started_at: ora(5), error: "al-lui-B" });

  const html = await pageThroughRoute();
  assert.match(html, /Masurat la <strong>/, "pagina lui A nu are vârsta propriei scanări");
  assert.doesNotMatch(html, /nuclei|al-lui-B/,
                      "pagina lui A numește scanerul sau eșecul serverului B");
  assert.doesNotMatch(html, /a esuat/, "eșecul lui B a ajuns ca eșec al lui A");
});

test("ruta duce la pagină avertismentul unui scaner pe care nu l-a numit nimeni", async () => {
  // Cap-coadă, prin rută și bază: `dnf` e curat, iar `trivy_image` încheie cu
  // avertisment. Pagina de dinainte citea numai `dnf` și arăta „Masurat la",
  // fără nicio urmă că o parte din imagini nu fuseseră ingerate.
  fixture.db.addScan(INSTANCE, { source_id: 1, scanner: "dnf",
    started_at: ora(0), finished_at: ora(0) });
  fixture.db.addScan(INSTANCE, { source_id: 2, scanner: "trivy_image",
    started_at: ora(2), finished_at: ora(2), error: AVERTISMENT });

  const html = await pageThroughRoute();
  assert.match(html, /Acoperire partiala<\/strong> \(scanerul <code>trivy_image<\/code>\)/,
               "avertismentul lui trivy_image nu ajunge pe pagină");
  assert.match(html, /registry\.example\.invalid\/mare:1/);
});

test("vârsta e a celui mai VECHI scaner, nu a primului și nu a celui mai nou", async () => {
  // O listă e atât de proaspătă cât cel mai rămas în urmă dintre scanerele ei.
  // Cel vechi stă la mijloc, dinadins: `dnf` (primul) e proaspăt, `trivy_image`
  // (ultimul) și mai proaspăt. Scris „Masurat la <ora lui dnf>", operatorul ar
  // crede lista de o oră când o parte din ea e de ieri.
  const html = await render([
    entry("dnf", { finishedAt: "2026-10-26 08:00:00" }),
    entry("trivy_fs", { finishedAt: "2026-10-25 02:10:00" }),
    entry("trivy_image", { finishedAt: "2026-10-26 09:00:00" }),
  ]);
  assert.match(html, /Masurat la <strong>2026-10-25 02:10 UTC<\/strong>, de scanerul <code>trivy_fs<\/code>/,
               "vârsta arătată nu e a scanerului celui mai vechi");
  for (const scanner of ["dnf", "trivy_fs", "trivy_image"]) {
    assert.match(html, new RegExp(`<li><code>${scanner}</code>: 2026`),
                 `ora scanerului ${scanner} lipsește din lista pe scaner`);
  }
});

test("starea mixtă: dnf curat, trivy_image cu avertisment — avertismentul poartă numele lui", async () => {
  // Cazul pe care operatorul îl va vedea de fapt. Avertismentul trebuie atribuit
  // scanerului care l-a scris: pus pe „dnf", ar trimite operatorul să caute
  // pachetele de sistem acolo unde sunt imaginile.
  const html = await render([
    entry("dnf", { finishedAt: "2026-10-26 08:00:00" }),
    entry("trivy_image", { finishedAt: "2026-10-26 02:41:00", error: AVERTISMENT }),
  ]);
  assert.match(html, /Acoperire partiala<\/strong> \(scanerul <code>trivy_image<\/code>\)/);
  assert.doesNotMatch(html, /Acoperire partiala<\/strong> \(scanerul <code>dnf<\/code>/,
                      "avertismentul a fost pus pe scanerul curat");
  assert.equal(html.split("Acoperire partiala").length - 1, 1,
               "avertismentul apare de mai multe ori");
  assert.doesNotMatch(html, /a esuat/);
});

test("eșecul unui scaner nu se pierde sub un altul care a mers", async () => {
  // `dnf` a mers la 08:00; `trivy_fs` a eșuat la 09:00. Cu „ultima rulare" luată
  // dintr-un singur scaner, pagina zicea „Masurat la 08:00" și tăcea despre
  // `trivy_fs`, ale cărui constatări rămâneau în listă ca deschise la nesfârșit.
  const html = await render([
    entry("dnf", { finishedAt: "2026-10-26 08:00:00" }),
    entry("trivy_fs", { finishedAt: "2026-10-25 02:10:00" },
          { status: "failed", error: "timeout", startedAt: "2026-10-26 09:00:00" }),
  ]);
  assert.match(html, /Ultima scanare a esuat<\/strong> \(scanerul <code>trivy_fs<\/code>, 2026-10-26 09:00 UTC, timeout\)/,
               "eșecul lui trivy_fs nu e numit");
  assert.doesNotMatch(html, /esuat<\/strong> \(scanerul <code>dnf/,
                      "eșecul a fost atribuit scanerului care a mers");
});

test("un scaner fără nicio scanare bună e numit, nu înghițit de vârsta celorlalți", async () => {
  // „Masurat la <ora lui dnf>" peste o listă cu rânduri de la un scaner care n-a
  // reușit niciodată ar afirma o vârstă pe care o parte din ea n-o are.
  const html = await render([
    entry("dnf", { finishedAt: "2026-10-26 08:00:00" }),
    entry("trivy_image", null, { status: "failed", error: "timeout" }),
  ]);
  assert.match(html, /Scanerul <code>trivy_image<\/code> n-a incheiat nicio scanare cu bine/,
               "scanerul fără nicio măsurătoare bună nu e numit");
  assert.match(html, /Masurat la <strong>2026-10-26 08:00/);
});

test("ordinea cu mai mulți scaneri: eșec, apoi acoperire, apoi vârstă", async () => {
  // Ierarhia din docstring-ul lui `scanAge`, acum între scaneri diferiți: eșecul
  // lui `dnf` strigă mai tare decât avertismentul lui `trivy_image`, care strigă
  // mai tare decât orice notă de vârstă.
  const html = await render([
    entry("dnf", { finishedAt: "2026-10-26 08:00:00" },
          { status: "failed", error: "timeout", startedAt: "2026-10-26 09:00:00" }),
    entry("trivy_image", { finishedAt: "2026-10-26 02:41:00", error: AVERTISMENT }),
  ]);
  const esec = html.search(/Ultima scanare a esuat/);
  const partial = html.search(/Acoperire partiala/);
  const varsta = html.search(/Masurat la/);
  assert.ok(esec >= 0 && partial >= 0 && varsta >= 0, "lipsește unul din cele trei");
  assert.ok(esec < partial && partial < varsta,
            `ordinea e greșită: eșec@${esec}, acoperire@${partial}, vârstă@${varsta}`);
});
