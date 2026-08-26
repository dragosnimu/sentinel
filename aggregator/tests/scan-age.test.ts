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
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { scanHealth } from "../lib/data/scans";
import {
  USERNAME, captureError, captureWarn, forgetAuthServer, useAuthServer,
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

async function render(scan: Awaited<ReturnType<typeof scanHealth>>): Promise<string> {
  const { findingsPage } = await import("../lib/panel-page");
  return findingsPage({
    username: "operator", csrfToken: "x", instances: [], selected: INSTANCE,
    active: "/panel/vulnerabilitati", arrivals: new Map(),
    findings: [], group: null,
    counts: { neaplicate: 31, rezolvate: 0, inchise: 0, total: 31 },
    scan,
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
