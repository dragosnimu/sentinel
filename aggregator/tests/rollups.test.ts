/**
 * Contorul orar: însumarea care umple pagina „Rapoarte".
 *
 * Eșecul pe care îl previne, în trei forme care arată toate ca o pagină care
 * funcționează:
 *
 *   * totalul unei ore concatenat în loc de adunat — driverul întoarce coloanele
 *     întregi ca ȘIRURI, iar `"10" + "5"` e `"105"`. Un grafic cu un vârf de zece
 *     ori mai mare decât realitatea nu pică nimic;
 *   * `uniq_src` adunat — valoarea de pe server e deja un MAXIM peste minute, iar
 *     suma unor maxime nu răspunde la nicio întrebare;
 *   * ora de la marginea plafonului de citire arătată pe jumătate, cu un total
 *     mai mic decât cel real. E un raport care minte liniștit, spre deosebire de
 *     o oră lipsă, care se vede.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { HOURS_SHOWN, MAX_ROWS_READ, TOP_PER_HOUR, listHours } from "../lib/data/rollups";
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

/** Un moment de oră, ca număr — dublul ține timpul în milisecunde. */
function hourAt(offset: number): number {
  return 1_780_000_000_000 + offset * 3_600_000;
}

test("rândurile aceleiași ore se ADUNĂ, nu se concatenează", async () => {
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "nginx", n: "10" });
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "sshd", n: "5" });

  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours.length, 1);
  assert.equal(hours[0].events, 15,
               "totalul orei nu e suma — `\"10\" + \"5\"` dă `\"105\"`, iar pe " +
               "grafic asta e un vârf de zece ori mai mare decât realitatea");
});

test("`uniq_src` e un MAXIM peste rânduri, nu o sumă", async () => {
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "a", uniq_src: "7" });
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "b", uniq_src: "3" });

  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours[0].uniqSources, 7,
               "valoarea de pe server e deja un maxim peste minute; suma unor " +
               "maxime nu răspunde la nicio întrebare");
});

test("octeții se adună, și ca numere", async () => {
  fixture.db.addRollupHour(INSTANCE,
    { bucket: hourAt(0), source: "a", bytes_in: "100", bytes_out: "200" });
  fixture.db.addRollupHour(INSTANCE,
    { bucket: hourAt(0), source: "b", bytes_in: "50", bytes_out: "25" });

  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours[0].bytesIn, 150);
  assert.equal(hours[0].bytesOut, 225);
});

test("orele vin cu cea mai nouă întâi", async () => {
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "veche" });
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(2), source: "noua" });
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(1), source: "mijloc" });

  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.deepEqual(hours.map((h) => h.top[0].source), ["noua", "mijloc", "veche"]);
});

test("sursele unei ore sunt cele mai active, în ordine, și mărginite", async () => {
  for (let i = 0; i < TOP_PER_HOUR + 3; i += 1) {
    fixture.db.addRollupHour(INSTANCE,
      { bucket: hourAt(0), source: `s${i}`, n: String(i + 1) });
  }
  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours[0].top.length, TOP_PER_HOUR);
  assert.deepEqual(hours[0].top.map((t) => t.events),
                   [...hours[0].top.map((t) => t.events)].sort((a, b) => b - a),
                   "sursele nu sunt în ordinea activității");
  assert.equal(hours[0].top[0].events, TOP_PER_HOUR + 3,
               "cea mai activă sursă lipsește din listă");
  // Totalul rămâne al TUTUROR surselor, nu doar al celor arătate: altfel linia
  // ar contrazice suma de sub ea.
  const asteptat = Array.from({ length: TOP_PER_HOUR + 3 }, (_, i) => i + 1)
    .reduce((a, b) => a + b, 0);
  assert.equal(hours[0].events, asteptat,
               "totalul a fost calculat doar din sursele arătate");
});

test("se arată cel mult `HOURS_SHOWN` ore", async () => {
  for (let i = 0; i < HOURS_SHOWN + 5; i += 1) {
    fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(i), source: "nginx" });
  }
  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours.length, HOURS_SHOWN);
});

test("o oră bună NU se aruncă atunci când plafonul de citire nu a fost atins",
     async () => {
  // Aruncată necondiționat, s-ar pierde o oră reală pe fiecare gazdă liniștită
  // — și n-ar spune nimeni de ce lipsește.
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "nginx" });
  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours.length, 1, "singura oră a fost aruncată degeaba");
});

test("ora tăiată de plafonul de citire se ARUNCĂ, nu se arată pe jumătate",
     async () => {
  // Prin EFECT, nu prin citirea instrucțiunii: se seamănă peste plafon, iar ora
  // cea mai veche — singura care poate fi tăiată — nu are voie să apară cu un
  // total mai mic decât cel real. Un total prea mic nu pică nimic; e chiar
  // raportul care minte liniștit.
  // Destule surse pe oră ca plafonul să se termine ÎNĂUNTRUL ferestrei arătate.
  // Cu puține surse pe oră, ora tăiată cade dincolo de `HOURS_SHOWN` și testul
  // n-ar putea s-o vadă niciodată — verificat prin falsificare: cu 3 surse pe
  // oră, ștergerea gărzii trecea neobservată.
  const perHour = Math.ceil(MAX_ROWS_READ / (HOURS_SHOWN - 2));
  const hours = HOURS_SHOWN;
  for (let h = 0; h < hours; h += 1) {
    for (let s = 0; s < perHour; s += 1) {
      fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(h), source: `s${s}` });
    }
  }

  const got = await listHours(fixture.db, scope, INSTANCE);
  assert.ok(got.length > 0, "nu s-a întors nicio oră");
  assert.ok(got.length <= HOURS_SHOWN, `${got.length} ore, plafonul e ${HOURS_SHOWN}`);
  for (const hour of got) {
    assert.equal(hour.events, perHour * 10,
                 `ora ${hour.bucket} are un total tăiat: ${hour.events} în loc de ` +
                 `${perHour * 10}`);
  }
});

test("o instanță fără drept nu vede nimic", async () => {
  fixture.db.addInstance("prod-b", { label: "B" });
  fixture.db.addRollupHour("prod-b", { bucket: hourAt(0), source: "al-lui-B" });
  fixture.db.addRollupHour(INSTANCE, { bucket: hourAt(0), source: "al-lui-A" });

  const hours = await listHours(fixture.db, scope, INSTANCE);
  assert.equal(hours.length, 1);
  assert.deepEqual(hours[0].top.map((t) => t.source), ["al-lui-A"],
                   "traficul altui server a fost adunat peste al tău");
});

test("numerele ajung CHIAR în pagină, nu doar în obiectul întors", async () => {
  // Ultima verigă: o funcție de date corectă și un șablon care n-o folosește
  // arată împreună exact ca o pagină goală. Aici se cere HTML-ul.
  const { reportsPage } = await import("../lib/panel-page");
  const chrome = {
    username: "operator", csrfToken: "x", instances: [], selected: INSTANCE,
    active: "/panel/rapoarte", arrivals: new Map(),
  };
  const html = reportsPage({
    ...chrome,
    hours: [{
      bucket: "2026-08-21 13:00:00", events: 1234, uniqSources: 9,
      bytesIn: 2048, bytesOut: 1_048_576,
      top: [{ source: "nginx", action: "req", events: 1200 }],
    }],
  } as Parameters<typeof reportsPage>[0]);

  assert.match(html, /1234/, "totalul orei nu apare în pagină");
  assert.match(html, /nginx/, "sursa nu apare în pagină");
  // O zecimală sub 10, ca `2.0 KB` să nu se confunde cu `2 KB` rotunjit
  // dintr-un 2,4 — pe o pagină de contori, rotunjirea tăcută e chiar
  // felul în care un raport devine aproximativ fără să spună.
  assert.match(html, /2\.0 KB/, "octeții de intrare nu sunt formatați");
  assert.match(html, /1\.0 MB/, "octeții de ieșire nu sunt formatați");
  assert.ok(!html.includes("<script"),
            "pagina a căpătat un script inline — CSP-ul strict l-ar bloca");
});
