/**
 * `TINYINT(1)` citit ca boolean — capcana care se repetă în tot depozitul.
 *
 * `Boolean("0") === true` în JavaScript, iar driverul MariaDB întoarce coloanele
 * întregi ca ȘIRURI când sunt mari (`bigNumberStrings`) sau când o versiune
 * viitoare hotărăște altfel. Fiecare loc care citește un `TINYINT(1)` face de
 * aceea `Number(x) === 1`, iar comentariile o spun — `pending_totp`, `disabled`,
 * `enabled`, `suppressed`, `kev`, `active`, `requires_reboot`, `reversible`.
 *
 * Comentariile nu sunt o probă. Testul ăsta e: seamănă valoarea ca ȘIR, forma în
 * care capcana chiar mușcă, și cere valoarea logică. Recensământul din
 * `data-scope-coverage` nu-l acoperă — el probează granița dintre instanțe, iar
 * dublul lui seamănă numere, unde `Boolean(0)` se nimerește fals.
 *
 * Ce se strică dacă cade, pe rând:
 *
 *   * `kev` — o constatare oarecare urcă în capul listei ca „se exploatează
 *     acum", iar una reală e îngropată sub ea;
 *   * `active` — o blocare expirată apare ca apărare activă;
 *   * `requires_reboot` — un patch aplicat în plin trafic în loc de noaptea;
 *   * `reversible` — cineva aprobă ceva ce crede că poate anula.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { listBlocks } from "../lib/data/blocklist";
import { listFindings } from "../lib/data/findings";
import { listPlans } from "../lib/data/patch-plans";
import { listDetections } from "../lib/data/detections";
import { listChecks } from "../lib/data/selfcheck";
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
  const granted = await grantInstance(fixture.db, USERNAME, INSTANCE, "owner");
  assert.equal(granted.ok, true);
  scope = await scopeForUser(fixture.db, fixture.user.id);
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

test("`kev` venit ca ȘIRUL «0» e FALS, nu adevărat", async () => {
  fixture.db.addFinding(INSTANCE, { source_id: 11, kev: "0" });
  fixture.db.addFinding(INSTANCE, { source_id: 12, kev: "1" });

  const rows = await listFindings(fixture.db, scope, INSTANCE);
  const byId = new Map(rows.map((r) => [r.sourceId, r]));
  assert.equal(byId.get(11)?.kev, false,
               "`Boolean(\"0\")` e adevărat: o constatare oarecare a fost marcată " +
               "ca exploatată activ");
  assert.equal(byId.get(12)?.kev, true);
});

test("`active` venit ca ȘIRUL «0» e o blocare EXPIRATĂ, nu una activă", async () => {
  fixture.db.addBlock(INSTANCE, { source_id: 11, active: "0" });
  fixture.db.addBlock(INSTANCE, { source_id: 12, active: "1" });

  const rows = await listBlocks(fixture.db, scope, INSTANCE);
  const byId = new Map(rows.map((r) => [r.sourceId, r]));
  assert.equal(byId.get(11)?.active, false,
               "o blocare expirată apare ca apărare activă");
  assert.equal(byId.get(12)?.active, true);
});

test("`requires_reboot` și `reversible` ca ȘIRURI se citesc corect", async () => {
  fixture.db.addPlan(INSTANCE, {
    source_id: 11, requires_reboot: "0", reversible: "0",
  });
  fixture.db.addPlan(INSTANCE, {
    source_id: 12, requires_reboot: "1", reversible: "1",
  });

  const rows = await listPlans(fixture.db, scope, INSTANCE);
  const byId = new Map(rows.map((r) => [r.sourceId, r]));
  assert.equal(byId.get(11)?.requiresReboot, false);
  assert.equal(byId.get(11)?.reversible, false,
               "un plan IREVERSIBIL a fost arătat ca reversibil — cineva ar " +
               "aproba ceva ce crede că poate anula");
  assert.equal(byId.get(12)?.requiresReboot, true);
  assert.equal(byId.get(12)?.reversible, true);
});

test("`suppressed` ca ȘIRUL «0» e o detecție ACTIVĂ", async () => {
  fixture.db.addDetection(INSTANCE, { source_id: 11, suppressed: "0" });
  fixture.db.addDetection(INSTANCE, { source_id: 12, suppressed: "1" });

  const rows = await listDetections(fixture.db, scope, INSTANCE);
  const byId = new Map(rows.map((r) => [r.sourceId, r]));
  assert.equal(byId.get(11)?.suppressed, false,
               "o detecție activă a fost ascunsă ca suprimată");
  assert.equal(byId.get(12)?.suppressed, true);
});

test("`stale` ca ȘIRUL «0» înseamnă o verificare care CHIAR a rulat", async () => {
  // Diferența pe ecran: „verificarea spune ok" și „verificarea n-a putut rula și
  // îți arăt ce știam data trecută" nu sunt același lucru. A doua citită ca
  // prima e un raport care minte liniștit — chiar clasa după care e numit
  // depozitul.
  fixture.db.addCheck(INSTANCE, { check_key: "web", stale: "0" });
  fixture.db.addCheck(INSTANCE, { check_key: "db", stale: "1" });

  const rows = await listChecks(fixture.db, scope, INSTANCE);
  const byKey = new Map(rows.map((r) => [r.checkKey, r]));
  assert.equal(byKey.get("web")?.stale, false,
               "o verificare care a rulat a fost marcată ca veche");
  assert.equal(byKey.get("db")?.stale, true,
               "o verificare care NU a rulat a fost arătată ca proaspătă");
});
