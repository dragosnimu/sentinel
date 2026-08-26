/**
 * Pagina martorului: arată TOATE instanțele, nu scapă detaliile fără cheie, și
 * se servește sub politica de conținut a panoului.
 *
 * Eșecurile, toate tăcute:
 *
 * 1. **O pagină care arată prima instanță.** Cu un singur server arată perfect,
 *    deci trece de orice privire; al doilea server pur și simplu nu există în
 *    ea, iar cine se uită crede că le vede pe amândouă.
 * 2. **Poarta `?key=` care nu ține.** Numărul de incidente deschise și de
 *    adrese blocate spun ceva despre ce se întâmplă pe server, iar pagina e
 *    publică. Dacă gardul cedează, scurgerea nu produce niciun simptom.
 * 3. **Pagina randată cu scripturi inline.** Politica agregatorului n-are
 *    `unsafe-inline`; o pagină care ar aduce vreunul ajunge ruptă pe telefonul
 *    operatorului, în ziua în care el o deschide fiindcă bănuiește o tăcere.
 *    Nici asta nu se vede de aici — de-aia se probează pe răspunsul REAL.
 * 4. **Escaparea greșită.** În aplicația asta există două funcții `escapeHtml`:
 *    cea din `lib/auth/render.ts`, care acoperă și ghilimelele, și cea din
 *    `lib/telegram.ts`, care acoperă doar cele trei caractere cerute de
 *    Telegram. Pagina o folosește pe prima; cu a doua, o etichetă cu ghilimele
 *    ar ieși întreagă în HTML, iar eticheta vine dintr-un payload semnat pe o
 *    mașină care poate fi compromisă.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  baseEnv, configureInstances, pretendStateIsInsideApp, removeState,
  writeRawInstance, CHECK_KEY,
} from "./witness-harness";
import { GET } from "../app/route";
import { writeInstance } from "../lib/store";
import { CONTENT_SECURITY_POLICY } from "../lib/auth/http";

beforeEach(async () => {
  baseEnv();
  await removeState();
});

afterEach(async () => {
  await removeState();
});

function beatAt(iso: string, over: Record<string, unknown> = {}) {
  return {
    seq: 4471, sent_at: iso, received_at: iso,
    last_event_id: 918273, detect_cursor: 918200, incidents_open: 7, blocklist_size: 41,
    audit_head: "a".repeat(64), interval_s: 60,
    selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: iso },
    ...over,
  };
}

async function seed(instances: Record<string, Record<string, unknown>>): Promise<void> {
  configureInstances(Object.keys(instances));
  for (const [id, state] of Object.entries(instances)) {
    await writeInstance(id, state as never);
  }
}

/** Ruta reală, chemată ca funcție. Întoarce răspunsul, nu doar corpul. */
async function respond(key?: string): Promise<Response> {
  const url = key === undefined
    ? "https://exemplu.ro/"
    : `https://exemplu.ro/?key=${encodeURIComponent(key)}`;
  return GET(new Request(url));
}

async function render(key?: string): Promise<string> {
  return (await respond(key)).text();
}

test("fiecare instanță are propriul card", async () => {
  const now = new Date().toISOString();
  const old = new Date(Date.now() - 3600 * 1000).toISOString();
  await seed({
    a1b2c3d4e5: { last: beatAt(now, { label: "web-public" }), counters_moved_at: now },
    f6g7h8i9j0: { last: beatAt(old), counters_moved_at: old },
  });

  const html = await render();
  assert.equal((html.match(/class="card /g) ?? []).length, 2, "nu sunt două carduri");
  assert.match(html, /web-public/);
  // Una verde, una roșie — instanțele se judecă independent.
  assert.match(html, /card ok/);
  assert.match(html, /card bad/);
  assert.match(html, /nu răspunde/);
});

test("fără cheie, identificatorul întreg nu apare în pagină", async () => {
  // Nu e secret criptografic, dar e cheia de căutare a semnalului și n-are de ce
  // să stea pe o pagină publică. Ce se arată e eticheta, sau un fragment.
  const now = new Date().toISOString();
  await seed({ a1b2c3d4e5f6: { last: beatAt(now), counters_moved_at: now } });

  const anonim = await render();
  assert.doesNotMatch(anonim, /a1b2c3d4e5f6/);
  assert.match(anonim, /a1b2c3d4/);

  const cuCheie = await render(CHECK_KEY);
  assert.match(cuCheie, /a1b2c3d4e5f6/);
});

test("fără cheie, contoarele nu apar; cu cheia corectă, apar", async () => {
  const now = new Date().toISOString();
  await seed({ default: { last: beatAt(now), counters_moved_at: now } });

  const anonim = await render();
  assert.doesNotMatch(anonim, /Incidente deschise/);
  assert.doesNotMatch(anonim, /Adrese blocate/);

  const gresit = await render("nu-e-cheia");
  assert.doesNotMatch(gresit, /Incidente deschise/, "o cheie greșită a deschis detaliile");

  const bun = await render(CHECK_KEY);
  assert.match(bun, /Incidente deschise/);
  assert.match(bun, /Adrese blocate/);
});

test("fără `SENTINEL_CHECK_SECRET` setat, nicio cheie nu deschide detaliile", async () => {
  // Eșecul pe care îl previne: o comparație cu `undefined` care ar face ca
  // `?key=` gol să treacă drept potrivire pe o instalare neterminată.
  const now = new Date().toISOString();
  await seed({ default: { last: beatAt(now), counters_moved_at: now } });
  baseEnv();
  process.env.SENTINEL_CHECK_SECRET = "";
  for (const k of ["", "orice"]) {
    assert.doesNotMatch(await render(k), /Incidente deschise/, `cheia ${JSON.stringify(k)} a trecut`);
  }
});

test("fără nicio instanță configurată, pagina spune exact asta", async () => {
  await removeState();
  configureInstances([]);
  const html = await render();
  assert.match(html, /Niciun semnal încă/);
  assert.match(html, /cheie configurată/);
  assert.doesNotMatch(html, /nu răspunde/, "a inventat o tăcere pe un martor abia instalat");
});

test("o copie de siguranță pusă lângă stare nu apare în pagină", async () => {
  const now = new Date().toISOString();
  await seed({ a1b2c3: { last: beatAt(now), counters_moved_at: now } });
  await writeRawInstance("backup-2026-08-12", JSON.stringify({
    last: beatAt(new Date(Date.now() - 3600 * 1000).toISOString()),
  }));
  const html = await render(CHECK_KEY);
  assert.doesNotMatch(html, /backup-2026-08-12/);
  assert.equal((html.match(/class="card /g) ?? []).length, 1);
});

test("eticheta unei instanțe nu poate injecta marcaj în pagină", async () => {
  const now = new Date().toISOString();
  await seed({
    a1b2c3: { last: beatAt(now, { label: "<script>alert(1)</script>" }), counters_moved_at: now },
  });
  const html = await render();
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});

test("pagina avertizează, vizibil, când starea se pierde la publicare", async () => {
  // Avertismentul trebuie să fie pe pagină, nu doar în jurnal: găzduirea are
  // jurnal Node pe care nu-l citește nimeni, iar asta a mai ascuns o dată un
  // defect care ștergea servere de pe hartă. Nu e nici ascuns în spatele lui
  // `?key=`: e o defecțiune de configurare, iar operatorul o vede de pe telefon.
  const now = new Date().toISOString();
  await seed({ aaa111: { last: beatAt(now), counters_moved_at: now } });

  const restore = pretendStateIsInsideApp();
  try {
    const html = await render();
    assert.match(html, /se pierde la următoarea publicare/);
    assert.match(html, /SENTINEL_STATE_PATH/);
  } finally { restore(); }

  // Iar pe o cale sigură nu apare nimic — altfel avertismentul ar deveni zgomot
  // permanent și n-ar mai fi citit nici el.
  const curat = await render();
  assert.doesNotMatch(curat, /se pierde la următoarea publicare/);
});

test("pagina pleacă sub politica panoului și fără niciun script", async () => {
  // Eșecul pe care îl previne, și e cel din cauza căruia pagina nu mai e React:
  // o pagină Next randată pe server aduce șase elemente de script INLINE, pe
  // care `script-src 'self'` le refuză. Simptomul nu e un test roșu, e o pagină
  // ruptă pe telefonul operatorului — exact în clipa în care o deschide fiindcă
  // bănuiește că un server a amuțit.
  //
  // Se citește RĂSPUNSUL, nu configurația: antetul e ce ajunge la browser, iar
  // `tests/unit/test_aggregator_csp_parity.py` ține valoarea în acord cu vhostul
  // serverului monitorizat. Cele două jumătăți sunt necesare amândouă.
  const now = new Date().toISOString();
  await seed({ a1b2c3: { last: beatAt(now), counters_moved_at: now } });

  const res = await respond();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(res.headers.get("content-security-policy"), CONTENT_SECURITY_POLICY);
  assert.match(res.headers.get("cache-control") ?? "", /no-store/);

  const html = await res.text();
  assert.doesNotMatch(html, /<script/i, "pagina aduce un script, deci politica o rupe");
  // Și foaia de stil rămâne de aceeași origine — o adresă absolută ar fi refuzată
  // de `style-src 'self'` și pagina ar ajunge nestilizată, tăcut.
  assert.match(html, /<link rel="stylesheet" href="\/martor.css">/);
  assert.doesNotMatch(html, /href="http/, "pagina cere ceva de la o origine externă");
});

test("o etichetă cu ghilimele e escapată, nu doar cea cu paranteze unghiulare", async () => {
  // Eșecul pe care îl previne: pagina folosește `escapeHtml` din
  // `lib/telegram.ts` în loc de cel din `lib/auth/render.ts`. Cele două au
  // același nume și acoperă mulțimi diferite — Telegram cere trei caractere,
  // HTML cinci —, iar diferența nu se vede pe eticheta obișnuită. Se vede aici.
  const now = new Date().toISOString();
  await seed({
    a1b2c3: { last: beatAt(now, { label: 'web" onmouseover=x' }), counters_moved_at: now },
  });
  const html = await render();
  assert.doesNotMatch(html, /web" onmouseover/, "ghilimelele au ajuns întregi în HTML");
  assert.match(html, /web&quot; onmouseover/);
});
