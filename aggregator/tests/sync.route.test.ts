/**
 * Ruta de ingestie: ce acceptă, ce refuză, cu ce cod, și ce ecouă.
 *
 * Codul de răspuns nu e cosmetic — e diagnosticul pe care îl are operatorul,
 * prin `curl` sau prin jurnalul expeditorului, fără acces la agregator:
 *
 *   500  nu sunt configurat (secret principal lipsă, cheie lipsă sau ilizibilă)
 *   500  lotul a rulat și efectul nu se confirmă — NU s-a preluat nimic
 *   503  baza nu răspunde
 *   401  te-am refuzat (cheie, semnătură sau identitate)
 *   413  lot prea mare — nimic nu s-a scris și nimic nu s-a tăiat
 *   413  plic care se desface peste plafon — nimic nu s-a citit din el
 *   400  lot malformat, prea vechi, sau cu un flux necunoscut
 *   400  plic stricat, de altă versiune, sau cu base64 nevalid
 *   200  preluat, cu filigranul ecouat exact
 *
 * Dacă „nu sunt configurat" ar da 401, cel care instalează ar căuta o cheie
 * greșită pe serverul monitorizat în timp ce problema e o variabilă goală aici.
 *
 * ## De ce contează CEL MAI MULT ultimul rând al tabelului
 *
 * `sentinel/report/shipper.py` avansează cursorul unui flux DOAR pe ecou, nu pe
 * HTTP 200. Un 200 fără ecou — sau cu unul inventat — face cursorul să treacă
 * peste rânduri care nu există nicăieri, definitiv și în tăcere. Testele de mai
 * jos care se uită la corpul răspunsului sunt jumătatea de aici a acelei reguli.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import zlib from "node:zlib";

import { POST } from "../app/api/sentinel/sync/route";
import { MAX_BODY_BYTES, MAX_ROWS_PER_BATCH } from "../lib/ingest";
import { MAX_WIRE_BYTES } from "../lib/envelope";
import {
  FakeServer, INSTANCE, SHIP_KEY, auditHash, auditRow, captureError, captureWarn,
  columnAt, forgetServer, sealedShipKey, setEnv, syncPayload, syncRequest, useFakeServer,
  wireOf,
} from "./sync-harness";
import type { FakeOptions } from "./sync-harness";

let server: FakeServer;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

async function withServer(opts: FakeOptions = {}): Promise<FakeServer> {
  server = await useFakeServer(opts);
  return server;
}

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  await withServer();
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetServer();
});

// ---------------------------------------------------------------------------
// Drumul bun
// ---------------------------------------------------------------------------
test("un lot valid e preluat, iar răspunsul ecouă EXACT filigranul", async () => {
  const rows = [auditRow({ id: 100 }), auditRow({ id: 101 })];
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(),
                   { ok: true, accepted: { audit_log: 101 }, instance: INSTANCE });
  // Efectul, nu doar codul: rândurile chiar sunt în tabelă.
  assert.equal(server.countFor(), 2);
  assert.equal(server.storedRow(101)?.entry_hash, auditHash(101));
});

test("filigranul ecouat e un NUMĂR, egal exact, nu unul mai mare", async () => {
  // `accepted_watermarks` din shipper.py refuză un ecou de alt tip și unul cu
  // altă valoare. Dacă ruta ar întoarce un șir sau `true`, cursorul n-ar avansa
  // niciodată, iar simptomul ar fi „loturile pleacă și nu intră" pe un agregator
  // care le-a primit pe toate.
  const rows = [auditRow({ id: 200 })];
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));
  const body = await res.json() as { accepted: Record<string, unknown> };
  assert.equal(typeof body.accepted.audit_log, "number");
  assert.equal(body.accepted.audit_log, 200);
});

test("răspunsul poartă no-store — un ecou din cache e un filigran vechi", async () => {
  const res = await POST(syncRequest({}));
  assert.match(String(res.headers.get("cache-control")), /no-store/);
});

test("ACELAȘI lot de două ori: numărul de rânduri nu se schimbă", async () => {
  // Criteriul de acceptanță 2 din plan, prin efect. Retrimiterea e tratamentul
  // pentru „nu știu ce s-a întâmplat", deci trebuie să fie gratuită.
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 300 }), auditRow({ id: 301 })] } });
  const first = await POST(syncRequest({ payload }));
  assert.equal(first.status, 200);
  const count = server.countFor();
  assert.equal(count, 2);

  const second = await POST(syncRequest({ payload }));
  assert.equal(second.status, 200, "reluarea a fost refuzată");
  assert.deepEqual((await second.json() as { accepted: unknown }).accepted, { audit_log: 301 });
  assert.equal(server.countFor(), count, "reluarea a schimbat numărul de rânduri");
});

// ---------------------------------------------------------------------------
// Pasul 1: cine ești
// ---------------------------------------------------------------------------
test("fără antetul de instanță, 401 — nu există instanță implicită", async () => {
  // La martor există un `default`, ca toleranță pentru expeditorul de heartbeat
  // aflat în producție. Aici ar însemna istoriile a două servere amestecate sub
  // o identitate, iar un lanț de audit făcut din două istorii arată rupt pentru
  // totdeauna.
  const res = await POST(syncRequest({ instance: null }));
  assert.equal(res.status, 401);
  assert.equal(server.countFor(), 0);
});

test("o instanță necunoscută primește 401, nu 404", async () => {
  // 404 ar confirma care identificatori există, pe o rută care nu cere nimic ca
  // să întrebe.
  const res = await POST(syncRequest({ instance: "necunoscuta" }));
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: "refuzat" });
});

test("un identificator malformat e refuzat fără să atingă baza", async () => {
  // `__proto__` ca identificator, și un antet mai lung decât coloana. Verificarea
  // de formă e înaintea oricărei interogări fiindcă valoarea intră și în AAD-ul
  // cu care se deschide cheia.
  for (const bad of ["__proto__", "-incepe-cu-liniuta", "a".repeat(65), "are spatiu"]) {
    const res = await POST(syncRequest({ instance: bad }));
    assert.equal(res.status, 401, `${bad} nu a fost refuzat`);
  }
  assert.deepEqual(server.asked, [], "s-a interogat baza pentru un identificator malformat");
});

test("o instanță oprită (`enabled = 0`) e refuzată, dar istoria ei rămâne", async () => {
  await withServer({
    instances: [{ instance_id: INSTANCE, enabled: 0, ship_secret_enc: sealedShipKey() }],
  });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 401);
  assert.equal(server.countFor(), 0);
});

test("o instanță FĂRĂ cheie instalată dă 500, nu 401", async () => {
  // „Nu sunt configurat" și „te-am refuzat" cer reacții diferite: prima e o
  // cheie de scris aici, a doua e un expeditor de verificat acolo.
  await withServer({
    instances: [{ instance_id: INSTANCE, enabled: 1, ship_secret_enc: null }],
  });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 500);
  assert.deepEqual(await res.json(), { error: "nu sunt configurat" });
});

test("o cheie care nu se poate descifra dă 500, cu altă linie în jurnal", async () => {
  // Ori secretul principal a fost rotit, ori rândul a fost umblat. În ambele
  // cazuri reacția e aici, nu pe serverul monitorizat — iar un 401 ar fi trimis
  // pe cineva să caute o cheie greșită acolo.
  await withServer({
    instances: [{
      instance_id: INSTANCE, enabled: 1,
      ship_secret_enc: sealedShipKey(SHIP_KEY, INSTANCE, "9".repeat(64)),
    }],
  });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 500);
  assert.ok(error.lines.some((l) => l.join(" ").includes("descifra")),
            `jurnalul nu spune că problema e descifrarea: ${JSON.stringify(error.lines)}`);
});

test("fără secretul principal, 500 — nu se verifică nimic pe o presupunere", async () => {
  setEnv({ SENTINEL_AGGREGATOR_SECRET: undefined });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 500);
  assert.deepEqual(await res.json(), { error: "nu sunt configurat" });
});

test("un secret principal prea scurt e „nu sunt configurat”, nu o excepție", async () => {
  // O rută care crapă nu mai poate spune de ce a crapat.
  setEnv({ SENTINEL_AGGREGATOR_SECRET: "scurt" });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 500);
});

test("o bază care nu răspunde dă 503, nu „instanță necunoscută”", async () => {
  // Confundate, toate serverele sănătoase ar primi 401 iar operatorul ar căuta o
  // cheie greșită.
  await withServer({ failOn: "SELECT enabled, ship_secret_enc FROM instances" });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 503);
});

test("cheia din BAZĂ e chiar cea folosită la verificare", async () => {
  // Fără aserțiunea asta, o rută care ignoră complet baza și verifică cu o
  // constantă ar trece toate testele de mai sus.
  await withServer({
    instances: [{
      instance_id: INSTANCE, enabled: 1,
      ship_secret_enc: sealedShipKey("cu-totul-alta-cheie"),
    }],
  });
  assert.equal((await POST(syncRequest({ key: SHIP_KEY }))).status, 401);
  assert.equal((await POST(syncRequest({ key: "cu-totul-alta-cheie" }))).status, 200);
});

// ---------------------------------------------------------------------------
// Pasul 2: semnătura
// ---------------------------------------------------------------------------
test("semnătura calculată cu altă cheie e refuzată cu 401", async () => {
  const res = await POST(syncRequest({ key: "cheie-cu-totul-alta" }));
  assert.equal(res.status, 401);
  assert.equal(server.countFor(), 0);
});

test("corpul modificat după semnare e refuzat cu 401", async () => {
  // Exact ce ar face cineva care vrea să strecoare un rând inventat într-un lot
  // altfel valid, sau să umfle filigranul.
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 400 })] } });
  const raw = JSON.stringify(payload);
  const signature = crypto.createHmac("sha256", SHIP_KEY).update(Buffer.from(raw, "utf8")).digest("hex");
  const tampered = raw.replace('"audit_log":400', '"audit_log":999');
  assert.notEqual(tampered, raw, "fixtura nu a modificat nimic — testul n-ar dovedi nimic");

  const res = await POST(syncRequest({ raw: tampered, signature }));
  assert.equal(res.status, 401);
  assert.equal(server.countFor(), 0);
});

test("antetul de semnătură lipsă dă 401, nu excepție", async () => {
  const req = new Request("https://exemplu.invalid/api/sentinel/sync", {
    method: "POST",
    body: JSON.stringify(syncPayload()),
    headers: { "X-Sentinel-Instance": INSTANCE },
  });
  assert.equal((await POST(req)).status, 401);
});

// ---------------------------------------------------------------------------
// Pasul 3: identitatea din payload
// ---------------------------------------------------------------------------
test("cine deține cheia lui A nu poate scrie în istoria lui B", async () => {
  // Pasul care se uită ușor și e cel care contează la mai multe instanțe: fără
  // el, un payload care pretinde că e B, semnat cu cheia lui A, cu antetul lui
  // A, ar intra ca... ceea ce zice payload-ul. Aici mai e o miză peste cea de la
  // martor: rândurile lui A ajunse în lanțul lui B fac lanțul lui B să arate
  // rupt pentru totdeauna, adică o falsificare raportată pe două servere
  // sănătoase.
  await withServer({
    instances: [
      { instance_id: "aaaa1111", enabled: 1, ship_secret_enc: sealedShipKey("cheia-lui-a", "aaaa1111") },
      { instance_id: "bbbb2222", enabled: 1, ship_secret_enc: sealedShipKey("cheia-lui-b", "bbbb2222") },
    ],
  });
  const payload = syncPayload({ instance_id: "bbbb2222" });
  const res = await POST(syncRequest({ payload, instance: "aaaa1111", key: "cheia-lui-a" }));

  assert.equal(res.status, 401);
  assert.equal(server.countFor("bbbb2222"), 0, "s-a scris în istoria lui B");
  assert.equal(server.countFor("aaaa1111"), 0);
});

test("un payload fără `instance_id` e refuzat, nu pus pe seama antetului", async () => {
  const payload = syncPayload();
  delete payload.instance_id;
  assert.equal((await POST(syncRequest({ payload }))).status, 401);
});

// ---------------------------------------------------------------------------
// Forma lotului
// ---------------------------------------------------------------------------
test("un corp semnat corect dar care nu e JSON dă 400", async () => {
  // Semnătura e validă, deci am trecut de autentificare; problema e forma.
  const res = await POST(syncRequest({ raw: "nu-e-json" }));
  assert.equal(res.status, 400);
});

test("un lot mai vechi decât max_age_s e refuzat cu 400", async () => {
  const old = new Date(Date.now() - 900 * 1000).toISOString();
  const res = await POST(syncRequest({ payload: syncPayload({ sent_at: old }) }));
  assert.equal(res.status, 400);
  assert.equal(server.countFor(), 0);
});

test("un lot din viitor e refuzat tot cu 400", async () => {
  const future = new Date(Date.now() + 900 * 1000).toISOString();
  assert.equal((await POST(syncRequest({ payload: syncPayload({ sent_at: future }) }))).status, 400);
});

test("`max_age_s` scris greșit e o EROARE, nu o cădere pe implicit", async () => {
  // `Number(payload.max_age_s || 300)` pe o valoare care nu e număr dă `NaN`,
  // iar `Math.abs(age) > NaN` e FALS — adică orice vechime ar fi trecut, tăcut.
  // Verificarea de prospețime ar fi arătat că există și n-ar fi verificat nimic.
  const old = new Date(Date.now() - 100_000 * 1000).toISOString();
  // `"curând"` și `1e9` sunt cele două care chiar deosebesc implementarea
  // corectă de cea naivă: primul dă `NaN` (deci comparația e falsă și lotul
  // trece), al doilea face fereastra de prospețime practic infinită. Restul
  // listei ar fi trecut și pe o cădere tăcută pe implicit.
  for (const bad of ["300", "curând", null, 0, -1, 1.5, 1e9]) {
    const res = await POST(syncRequest({
      payload: syncPayload({ sent_at: old, max_age_s: bad }),
    }));
    assert.notEqual(res.status, 200, `max_age_s=${JSON.stringify(bad)} a lăsat să treacă un lot vechi`);
    assert.equal(res.status, 400, `max_age_s=${JSON.stringify(bad)}`);
  }
  // Iar absent înseamnă implicitul, nu refuz: expeditorul îl trimite mereu, dar
  // protocolul îl are ca opțional.
  const fresh = syncPayload();
  delete fresh.max_age_s;
  assert.equal((await POST(syncRequest({ payload: fresh }))).status, 200);
});

test("`sent_at` de neînțeles e refuzat, nu tratat ca proaspăt", async () => {
  for (const bad of ["acum, cred", "", 5, null]) {
    const res = await POST(syncRequest({ payload: syncPayload({ sent_at: bad }) }));
    assert.equal(res.status, 400, `sent_at=${JSON.stringify(bad)} a fost acceptat`);
  }
});

test("`batch_seq` lipsă sau nevalid e refuzat", async () => {
  for (const bad of [undefined, "4471", 0, -3, 1.5]) {
    const payload = syncPayload();
    if (bad === undefined) delete payload.batch_seq;
    else payload.batch_seq = bad;
    assert.equal((await POST(syncRequest({ payload }))).status, 400,
                 `batch_seq=${JSON.stringify(bad)} a fost acceptat`);
  }
});

// ---------------------------------------------------------------------------
// Fluxurile — testul care contează cel mai mult
// ---------------------------------------------------------------------------
test("un flux NECUNOSCUT nu primește NICIODATĂ filigran", async () => {
  // ESTE eșecul pentru care există toată regula ecoului. Un agregator care
  // primește un flux pe care nu-l știe și îl confirmă arată identic cu unul care
  // l-a preluat: expeditorul avansează cursorul, iar rândurile dispar definitiv
  // și în tăcere — pe agregator lipsa nu se vede, fiindcă nimeni nu știe ce
  // trebuia să fie acolo.
  //
  // Două forme, cu răspunsuri diferite și DIN MOTIVE diferite:
  //
  //   * singur → nimic nu a intrat, deci nu e 200. Un `accepted: {}` ar fi tot
  //     un refuz, dar scris în singurul dialect pe care un CDN îl poate imita;
  //   * lângă un flux cunoscut → 200, `accepted` are DOAR fluxul cunoscut, iar
  //     cel necunoscut lipsește din el. Asta e chiar forma pe care
  //     `accepted_watermarks` o iterează pe flux ca să o poată trata:
  //     `audit_log` avansează, cel necunoscut nu, iar `ShipResult.ok` rămâne fals.
  //     Respins tot lotul, `audit_log` — singura copie a lanțului de audit — s-ar
  //     opri din cauza altui flux.
  // Un nume care NU va deveni niciodată un flux real. `detections` a stat
  // aici până pe 20 august 2026, când a fost declarat la ambele capete —
  // iar atunci testul care apără refuzul unui flux necunoscut a început
  // să-l trimită pe unul cunoscut. Un exemplu luat din vocabularul viitor
  // al programului expiră; unul evident inventat nu.
  const necunoscut = [{ id: 1, payload: "{}" }];

  await withServer();
  const alone = await POST(syncRequest({ payload: syncPayload({ rows: { flux_inexistent_9xk2: necunoscut } }) }));
  assert.notEqual(alone.status, 200, "un lot din care n-a intrat nimic a răspuns 200");
  assert.equal(alone.status, 400);
  const aloneBody = await alone.json() as { ok?: unknown; accepted?: unknown; error: string };
  assert.equal(aloneBody.ok, undefined, "un refuz nu are voie să spună ok");
  assert.equal(aloneBody.accepted, undefined, "un refuz nu are voie să ecoueze un filigran");
  assert.match(aloneBody.error, /flux_inexistent_9xk2/);

  await withServer();
  const mixed = await POST(syncRequest({
    payload: syncPayload({ rows: { audit_log: [auditRow({ id: 500 })], flux_inexistent_9xk2: necunoscut } }),
  }));
  assert.equal(mixed.status, 200);
  const body = await mixed.json() as
    { accepted: Record<string, unknown>; refused?: Record<string, string> };
  assert.equal(body.accepted.flux_inexistent_9xk2, undefined, "fluxul necunoscut a primit un filigran");
  assert.deepEqual(body.accepted, { audit_log: 500 });
  assert.match(String(body.refused?.flux_inexistent_9xk2), /nu e cunoscut/);
  // Fluxul cunoscut chiar a intrat — altfel ecoul lui ar fi o minciună.
  assert.equal(server.countFor(), 1);
});


test("dintr-un lot fără nimic acceptat iese codul CELUI MAI GRAV eșec", async () => {
  // Ordonarea nu e cosmetică: e diferența dintre „lotul tău e stricat" (400) și
  // „baza mea nu răspunde" (503), adică între operatorul trimis la expeditor și
  // operatorul trimis la agregator. Cu un singur flux nu se atinge niciodată, și
  // exact acolo a scăpat: o ordonare inversată sau un „primul, nu cel mai grav"
  // trec verzi peste orice lot cu un flux.
  //
  // Fluxul necunoscut e pus PRIMUL în amândouă loturile, dinadins: dacă
  // implementarea ar lua primul motiv în loc de cel mai grav, ar răspunde 400.
  // Un nume care NU va deveni niciodată un flux real. `detections` a stat
  // aici până pe 20 august 2026, când a fost declarat la ambele capete —
  // iar atunci testul care apără refuzul unui flux necunoscut a început
  // să-l trimită pe unul cunoscut. Un exemplu luat din vocabularul viitor
  // al programului expiră; unul evident inventat nu.
  const necunoscut = [{ id: 1, payload: "{}" }];

  // 400 (flux necunoscut) + 503 (baza nu poate confirma) → 503.
  await withServer({ blindCount: true });
  const unavailable = await POST(syncRequest({
    payload: syncPayload({ rows: { flux_inexistent_9xk2: necunoscut, audit_log: [auditRow({ id: 810 })] } }),
  }));
  assert.equal(unavailable.status, 503,
               await unavailable.text().then((t) => `a răspuns altceva: ${t}`));

  // 400 (flux necunoscut) + 413 (lot prea mare) → 413.
  await withServer();
  const tooMany = Array.from({ length: MAX_ROWS_PER_BATCH + 1 },
                             (_, i) => auditRow({ id: 200_000 + i }));
  const oversize = await POST(syncRequest({
    payload: syncPayload({ rows: { flux_inexistent_9xk2: necunoscut, audit_log: tooMany } }),
  }));
  assert.equal(oversize.status, 413, await oversize.text().then((t) => `a răspuns altceva: ${t}`));
});

test("`rows` și `cursors` trebuie să vorbească despre aceleași fluxuri", async () => {
  // Un filigran fără rânduri ar cere avansarea cursorului peste un gol; rânduri
  // fără filigran n-ar putea fi confirmate niciodată.
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 600 })] } });
  payload.cursors = { audit_log: 600, flux_inexistent_9xk2: 7 };
  assert.equal((await POST(syncRequest({ payload }))).status, 400);

  const missing = syncPayload({ rows: { audit_log: [auditRow({ id: 601 })] } });
  missing.cursors = {};
  assert.equal((await POST(syncRequest({ payload: missing }))).status, 400);
});

test("un lot fără niciun flux e refuzat", async () => {
  const payload = syncPayload({ rows: {} });
  payload.cursors = {};
  assert.equal((await POST(syncRequest({ payload }))).status, 400);
});

test("un lot peste plafon: 413 cu mesaj; EXACT plafonul intră", async () => {
  // Cele două jumătăți sunt una: un plafon mai mic decât ce `sentinel/config.py`
  // declară legal oprește `audit_log` definitiv, fiindcă `ship_once` tratează
  // orice non-2xx la fel, nu citește corpul, și nimic nu micșorează lotul. Cazul
  // probabil e chiar cel recomandat de capul lui `shipper.py`: operatorul ridică
  // `max_rows_per_batch` ca să recupereze o restanță.
  const rows = Array.from({ length: MAX_ROWS_PER_BATCH + 1 },
                          (_, i) => auditRow({ id: 100_000 + i }));
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));
  assert.equal(res.status, 413);
  assert.match(String((await res.json() as { error: string }).error),
               new RegExp(`${MAX_ROWS_PER_BATCH + 1}.*${MAX_ROWS_PER_BATCH}`, "s"));
  assert.equal(server.countFor(), 0, "un lot prea mare a scris rânduri");

  // Și lotul de exact `MAX_ROWS_PER_BATCH` rânduri — cel mai mare pe care
  // config.py îl acceptă — trece până la capăt, cu filigran.
  await withServer();
  const ok = await POST(syncRequest({
    payload: syncPayload({ rows: { audit_log: rows.slice(0, MAX_ROWS_PER_BATCH) } }),
  }));
  const okBody = await ok.json() as { accepted?: unknown; error?: string };
  assert.equal(ok.status, 200, okBody.error);
  assert.deepEqual(okBody.accepted, { audit_log: 100_000 + MAX_ROWS_PER_BATCH - 1 });
  assert.equal(server.countFor(), MAX_ROWS_PER_BATCH);
});

test("un corp peste plafon e oprit LA CITIRE, cu 413", async () => {
  // Route Handlers din Next 15 n-au limită implicită (`bodySizeLimit` e doar
  // pentru Server Actions), deci fără plafon corpul se bufferizează întreg
  // înainte de orice verificare de mărime. Pe o găzduire partajată, cine deține
  // o cheie de expediere — adică exact atacatorul cu root pe mașina monitorizată
  // — poate opri agregatorul la cerere.
  //
  // Se probează amândouă drumurile, fiindcă `content-length` e scris de client
  // și nu poate fi singurul: cel declarat (gratuit, dar minciunos) și cel
  // măsurat pe flux (cel care ține).
  //
  // Plafonul de la citire e `MAX_WIRE_BYTES`, nu `MAX_BODY_BYTES`: corpul primit
  // poate fi un plic, iar un plic e base64 peste gzip, deci pe conținut
  // necomprimabil iese mai mare decât conținutul. Plafonul pe CONȚINUT se aplică
  // octeților semnați și e probat de testul următor.
  const declared = new Request("https://exemplu.invalid/api/sentinel/sync", {
    method: "POST",
    body: "{}",
    headers: {
      "X-Sentinel-Instance": INSTANCE,
      "X-Sentinel-Signature": "0".repeat(64),
      "Content-Length": String(MAX_WIRE_BYTES + 1),
    },
  });
  assert.equal((await POST(declared)).status, 413);

  // Fără `content-length`: un flux care dă mai mult decât încape. Se numără
  // bucățile citite, ca să se vadă că citirea chiar S-A OPRIT — un plafon
  // verificat după bufferizare ar da tot 413, dar ar fi alocat deja tot.
  const CHUNK = 8 * 1024 * 1024;
  const needed = Math.ceil(MAX_WIRE_BYTES / CHUNK) + 4;
  let read = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (read >= needed) { controller.close(); return; }
      read++;
      controller.enqueue(new Uint8Array(CHUNK));
    },
  });
  const streamed = new Request("https://exemplu.invalid/api/sentinel/sync", {
    method: "POST",
    body,
    headers: {
      "X-Sentinel-Instance": INSTANCE,
      "X-Sentinel-Signature": "0".repeat(64),
    },
    // Cerut de undici pentru un corp trimis ca flux.
    duplex: "half",
  });
  const res = await POST(streamed);
  assert.equal(res.status, 413);
  assert.ok(read < needed, `s-a citit tot fluxul (${read}/${needed} bucăți)`);
  assert.equal(server.countFor(), 0);
});

// ---------------------------------------------------------------------------
// Plicul de transport: amândouă formele, în timpul rulării
// ---------------------------------------------------------------------------
test("un lot ÎMPACHETAT e preluat, cu același ecou ca unul în clar", async () => {
  // Reparația panei din 25 august 2026: marginea găzduirii punctează conținutul
  // cererii, iar `session_commands` — singurul flux format din linii de comandă
  // — trece pragul la patru-șase apariții ale unei comenzi banale. Cursorul
  // avansează doar pe ecou, deci lotul respins se retrimite la infinit.
  //
  // Proba cere ca plicul să nu schimbe NIMIC din ce vede restul rutei: același
  // filigran, aceleași rânduri în tabelă.
  const rows = [auditRow({ id: 300 }), auditRow({ id: 301 })];
  const payload = syncPayload({ rows: { audit_log: rows } });
  const res = await POST(syncRequest({ payload, wrapped: true }));

  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(),
                   { ok: true, accepted: { audit_log: 301 }, instance: INSTANCE });
  assert.equal(server.countFor(), 2);
  assert.equal(server.storedRow(301)?.entry_hash, auditHash(301));
});

test("aceleași octeți semnați, cele două forme: același rezultat", async () => {
  // Agregatorul se publică ÎNAINTEA gazdei, deci trebuie să accepte și
  // expeditorul de azi (JSON în clar) și pe cel de mâine (plic), fără comutator.
  // Dacă una dintre forme ar fi tratată altfel, ziua publicării ar opri fluxul.
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 400 })] } });
  const plain = await POST(syncRequest({ payload }));
  assert.equal(plain.status, 200);
  const plainBody = await plain.json();

  await withServer();
  const wrapped = await POST(syncRequest({ payload, wrapped: true }));
  assert.equal(wrapped.status, 200);
  assert.deepEqual(await wrapped.json(), plainBody);
  assert.equal(server.countFor(), 1);
});

test("semnătura peste PLIC e refuzată cu 401", async () => {
  // Jumătatea de aici a contractului trans-limbaj: HMAC-ul e peste octeții
  // canonici dinăuntru. Dacă ruta ar verifica peste ce a sosit, un expeditor
  // care semnează plicul ar fi acceptat, iar `lib/verify.ts` n-ar mai fi geamăn
  // cu `sentinel/report/signing.py` — divergență care se descoperă abia când
  // cineva schimbă nivelul de comprimare.
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 500 })] } });
  const signed = Buffer.from(JSON.stringify(payload), "utf8");
  const wire = wireOf(signed);
  const overWire = crypto.createHmac("sha256", SHIP_KEY).update(wire).digest("hex");

  const res = await POST(syncRequest({ raw: wire, signature: overWire }));
  assert.equal(res.status, 401);
  assert.equal(server.countFor(), 0);
});

test("un plic-bombă e refuzat cu 413 și nu scrie nimic", async () => {
  // Plicul se deschide ÎNAINTE de verificarea semnăturii — nu poate fi altfel,
  // fiindcă semnătura e peste ce iese din el. Deci un plic care se desface în
  // sute de megaocteți e o cerere NESEMNATĂ care consumă memoria agregatorului.
  // Bombă adevărată, comprimată aici, nu un plic care pretinde o mărime.
  const bomb = zlib.gzipSync(Buffer.alloc(64 * 1024 * 1024), { level: 9 });
  const wire = Buffer.from(
    `{"enc":"gzip+base64","v":1,"pad":"","body":"${bomb.toString("base64")}"}`,
    "ascii");
  assert.ok(wire.length < 1024 * 1024, `plicul are ${wire.length} octeți`);

  const res = await POST(syncRequest({ raw: wire, signature: "0".repeat(64) }));
  assert.equal(res.status, 413);
  assert.match(String((await res.json() as { error: string }).error),
               /raportul acceptat|plafonul de corp/);
  assert.equal(server.countFor(), 0);
});

test("un plic stricat dă 400, iar refuzul ajunge în jurnal", async () => {
  // `ship_once` scrie primii 200 de octeți ai corpului în jurnalul de pe gazdă
  // la orice non-2xx; ăla e singurul diagnostic al operatorului. Un „refuzat"
  // opac aici ar fi o pană tăcută cu un cod de stare pe ea.
  const wire = Buffer.from(
    '{"enc":"gzip+base64","v":1,"pad":"","body":"bm90IGd6aXAgYXQgYWxsIQ=="}', "ascii");
  const res = await POST(syncRequest({ raw: wire, signature: "0".repeat(64) }));
  assert.equal(res.status, 400);
  assert.match(String((await res.json() as { error: string }).error), /decomprima/);
  assert.ok(warn.lines.some((l) => l.join(" ").includes("plic refuzat")),
            `refuzul plicului nu a ajuns în jurnal: ${JSON.stringify(warn.lines)}`);
});

test("plicul se deschide DUPĂ căutarea cheii: o instanță necunoscută nu-l atinge",
     async () => {
  // Ordinea din protocol. Deschis înaintea pasului 1, oricine de pe internet ar
  // putea cere agregatorului să decomprime, fără să cunoască nici măcar un
  // identificator de instanță.
  const bomb = zlib.gzipSync(Buffer.alloc(64 * 1024 * 1024), { level: 9 });
  const wire = Buffer.from(
    `{"enc":"gzip+base64","v":1,"pad":"","body":"${bomb.toString("base64")}"}`,
    "ascii");
  const res = await POST(syncRequest({ raw: wire, instance: "nu-exista",
                                       signature: "0".repeat(64) }));
  assert.equal(res.status, 401, "o instanță necunoscută a ajuns la decomprimare");
});

test("un corp SEMNAT peste plafonul de conținut e 413, în amândouă formele",
     async () => {
  // Regula e pe conținut, nu pe sârmă: *corpul semnat nu are voie să treacă de
  // `MAX_BODY_BYTES`, oricum ar fi călătorit*. Fără linia asta, plicul ar
  // deveni o poartă prin care intră mai mult decât acceptă calea în clar — iar
  // plafonul de acolo apără o găzduire partajată de cine deține o cheie de
  // expediere, adică exact atacatorul cu root pe mașina monitorizată.
  const signed = Buffer.alloc(MAX_BODY_BYTES + 1, 0x20);
  signed.write('{"batch_seq":1}');

  const plain = await POST(syncRequest({ raw: signed }));
  assert.equal(plain.status, 413);
  assert.match(String((await plain.json() as { error: string }).error),
               new RegExp(String(MAX_BODY_BYTES)));

  // Și împachetat: 8 MB de spații se comprimă foarte bine, deci plicul e mic și
  // trece de citire — plafonul care îl oprește e cel de la decomprimare.
  const wrapped = await POST(syncRequest({ raw: signed, wrapped: true }));
  assert.equal(wrapped.status, 413);
  assert.equal(server.countFor(), 0);
});

test("un corp de entropie MAXIMĂ, sub plafonul de conținut, nu e refuzat pentru mărime",
     async () => {
  // Plicul nu are voie să accepte mai puțin decât calea pe care o înlocuiește.
  // Un plic e base64 (×4/3) peste gzip, iar gzip nu comprimă nimic pe text de
  // entropie mare — `argv` e nemărginit la sursă și influențat de cine are shell
  // pe gazda monitorizată. Cu plafonul de conținut pus la citire, un lot care azi
  // pleacă neîmpachetat ar fi refuzat DEFINITIV după împachetare, iar de pe gazdă
  // asta arată ca un agregator căzut: `ship_once` nu deosebește un non-2xx de
  // altul și nu citește corpul.
  //
  // Se cere doar „nu 413": lotul e fabricat, deci pică mai departe pe identitate.
  // Proprietatea probată e că NU pică pentru mărime.
  // Compus, nu scris ca un literal: alfabetul întreg pe un rând e o secvență de
  // 62 de caractere care arată a base64, iar garda din
  // `tests/security/test_repo_is_sanitised.py` o raportează ca posibil secret.
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const alphabet = lower + lower.toUpperCase() + "0123456789" + " .,-_/=+";
  const noise = Buffer.alloc(MAX_BODY_BYTES - 64);
  for (let i = 0; i < noise.length; i++) {
    noise[i] = alphabet.charCodeAt((Math.random() * alphabet.length) | 0);
  }
  const signed = Buffer.from(`{"batch_seq":1,"pad":"${noise.toString("latin1")}"}`, "utf8");
  assert.ok(signed.length <= MAX_BODY_BYTES);

  const wire = wireOf(signed);
  assert.ok(wire.length > MAX_BODY_BYTES,
            `plicul are ${wire.length} octeți: conținutul s-a comprimat, deci ` +
            "proba nu mai spune nimic despre plafonul de sârmă");
  assert.ok(wire.length <= MAX_WIRE_BYTES);

  const res = await POST(syncRequest({ raw: wire, signature: "0".repeat(64) }));
  assert.notEqual(res.status, 413,
                  "un corp sub plafonul de conținut a fost refuzat pentru mărime");
});

test("un rând stricat oprește lotul cu 400 și numește câmpul", async () => {
  const rows = [auditRow({ id: 700 }), auditRow({ id: 701, params: "{nu e json" })];
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));
  assert.equal(res.status, 400);
  assert.match(String((await res.json() as { error: string }).error), /params/);
  assert.equal(server.countFor(), 0, "s-a scris ceva dintr-un lot refuzat");
});

test("un filigran care nu e cel mai mare id din lot e refuzat", async () => {
  const payload = syncPayload({ rows: { audit_log: [auditRow({ id: 800 })] } });
  payload.cursors = { audit_log: 900 };
  const res = await POST(syncRequest({ payload }));
  assert.equal(res.status, 400);
  assert.equal(server.countFor(), 0);
});

// ---------------------------------------------------------------------------
// Efectul
// ---------------------------------------------------------------------------
test("un rând înghițit tăcut de INSERT IGNORE dă 500, fără `accepted`", async () => {
  // Aceeași proprietate ca în `tests/ingest.test.ts`, verificată prin RĂSPUNS:
  // ce ajunge la expeditor trebuie să fie „n-am preluat", nu un 200 politicos.
  // `INSERT IGNORE` nu aruncă atunci când un rând cade pe `CHECK
  // (json_valid(...))` sau pe o coloană prea scurtă, iar `affectedRows` nu
  // deosebește „era deja acolo" de „a fost aruncat".
  await withServer({ swallow: new Set([901]) });
  const rows = [auditRow({ id: 900 }), auditRow({ id: 901 })];
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));

  assert.equal(res.status, 500);
  const body = await res.json() as { ok?: unknown; accepted?: unknown; error: string };
  assert.equal(body.ok, undefined);
  assert.equal(body.accepted, undefined, "a ecouat un filigran peste un lot incomplet");
  assert.match(body.error, /2 rânduri.*1/s);
});

test("dacă baza nu poate confirma efectul, 503 — nu 200", async () => {
  await withServer({ blindCount: true });
  const res = await POST(syncRequest({}));
  assert.equal(res.status, 503);
  assert.equal((await res.json() as { accepted?: unknown }).accepted, undefined);
});

test("un lot preluat scrie și contabilitatea instanței, tot în UTC", async () => {
  const res = await POST(syncRequest({ payload: syncPayload({ batch_seq: 4471 }) }));
  assert.equal(res.status, 200);
  assert.deepEqual(server.instanceUpdates, [[4471, INSTANCE]]);
  // `CURRENT_TIMESTAMP(6)` ar da ora sesiunii, iar `last_batch_at` e documentat
  // ca UTC. Aserțiune pe interogarea TRIMISĂ — un dublu n-are fus orar.
  const updates = server.asked.filter((s) => s.startsWith("UPDATE instances SET"));
  assert.equal(updates.length, 1);
  assert.ok(updates[0].includes("UTC_TIMESTAMP(6)"), updates[0]);
  assert.ok(!/[^_]CURRENT_TIMESTAMP/.test(updates[0]), updates[0]);
});

test("un lot preluat verifică lanțul și consemnează verdictul", async () => {
  // Verificarea la ingestie e jumătatea care se uită la joncțiune: ultimul rând
  // al lotului N și primul al lotului N+1. Fără ea, singura verificare ar fi cea
  // programată, iar între două rulări de cron o tăietură ar sta neobservată.
  //
  // „Niciodată verificat" NU are voie să arate ca „verificat și e bine", deci se
  // probează și absența dinainte.
  assert.equal(server.chainState.get(INSTANCE), undefined);

  const rows = [auditRow({ id: 400 }), auditRow({ id: 401 })];
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: rows } }) }));
  assert.equal(res.status, 200);

  const state = server.chainState.get(INSTANCE);
  assert.equal(state?.status, "ok", JSON.stringify(state));
  assert.equal(Number(state?.verified_through), 401);
  assert.equal(state?.break_source_id, null);
});

test("un lot cu lanțul rupt e PRELUAT, iar ruptura se consemnează", async () => {
  // Decizia de proiectare care contează cel mai mult aici, și motivul ei:
  // refuzul lotului ar transforma detecția într-o pârghie de NEGARE A
  // DOVEZILOR. Cine poate rupe lanțul o dată — adică exact atacatorul împotriva
  // căruia există arhitectura — ar opri prin asta toate expedierile viitoare,
  // fix în clipa în care arhiva începe să conteze.
  //
  // Deci: rândurile intră, filigranul se ecouă, ruptura se consemnează.
  const first = [auditRow({ id: 500 }), auditRow({ id: 501 })];
  assert.equal((await POST(syncRequest({
    payload: syncPayload({ rows: { audit_log: first } }) }))).status, 200);

  // Al doilea lot începe la 503, iar `prev_hash`-ul lui arată spre 502 — un rând
  // care a existat în lanț și nu e în arhivă. Ambele capete sunt sub filigran
  // după preluare, deci nu mai poate fi „pe drum".
  const second = [auditRow({ id: 503 }), auditRow({ id: 504 })];
  const res = await POST(syncRequest({
    payload: syncPayload({ rows: { audit_log: second }, batch_seq: 4472 }) }));

  const body = await res.json() as { accepted?: unknown; error?: string };
  assert.equal(res.status, 200, body.error);
  assert.deepEqual(body.accepted, { audit_log: 504 });
  assert.equal(server.countFor(), 4, "rândurile nu au fost preluate");

  const state = server.chainState.get(INSTANCE);
  assert.equal(state?.status, "broken", JSON.stringify(state));
  assert.equal(Number(state?.break_source_id), 503);
  // Și ruptura ajunge în jurnalul agregatorului — singura urmă automată de azi.
  assert.ok(error.lines.some((l) => l.join(" ").includes("LANȚ RUPT")),
            `jurnalul nu spune nimic: ${JSON.stringify(error.lines)}`);
});

test("fereastra de prospețime acceptată e chiar cea pe care config.py o permite", async () => {
  // Plafonul de aici e o constrângere pusă pe configurația expeditorului, iar
  // expeditorul n-o poate descoperi: `ship_once` tratează orice non-2xx la fel
  // și nu citește corpul. Deci valoarea maximă pe care `sentinel/config.py` o
  // acceptă la încărcare trebuie să treacă și aici. Perechea e ținută de
  // `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`.
  const ceiling = 86_400;
  assert.equal((await POST(syncRequest({
    payload: syncPayload({ max_age_s: ceiling }) }))).status, 200);
  assert.equal((await POST(syncRequest({
    payload: syncPayload({ max_age_s: ceiling + 1, batch_seq: 4472 }) }))).status, 400);
});

test("contabilitatea instanței care eșuează NU anulează un ecou meritat", async () => {
  // Rândurile sunt dovedit în arhivă. A refuza ecoul din cauza unei coloane de
  // diagnostic ar opri sincronizarea la nesfârșit pentru ceva la care nu se uită
  // nimeni în timp real. Eșecul rămâne în jurnal.
  await withServer({ failOn: "UPDATE instances SET" });
  const res = await POST(syncRequest({ payload: syncPayload({ rows: { audit_log: [auditRow({ id: 950 })] } }) }));
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json() as { accepted: unknown }).accepted, { audit_log: 950 });
  assert.ok(error.lines.some((l) => l.join(" ").includes("contabilitatea")),
            `eșecul nu a ajuns în jurnal: ${JSON.stringify(error.lines)}`);
});

// ---------------------------------------------------------------------------
// Filigranul TEXT, la nivel de rută
// ---------------------------------------------------------------------------
test("ruta cere filigranul de FELUL declarat pe flux", async () => {
  // `selfcheck_state` e primul flux cu cheie text. Ruta trebuie să ceară un șir
  // pentru el — și un întreg pentru celelalte, în aceeași cerere. Fără
  // distincție, un flux întreg căruia i-ar sosi un șir ar trece mai departe și
  // s-ar scrie în cealaltă coloană de cursor, iar `lib/chain.ts` — care citește
  // `last_source_id` ca poziție confirmată — ar vedea un cursor înghețat.
  const rand = {
    key: "web", status: "ok", title: "Panoul", detail: "",
    facts: "{}", since: "2026-08-20T06:00:00.000000+00:00",
    last_seen: "2026-08-20T06:00:00.000000+00:00", last_alert_at: null,
    stale: false, updated_at: "2026-08-20T06:00:00.000000+00:00",
  };

  await withServer();
  const intreg = await POST(syncRequest({
    payload: (() => {
      const p = syncPayload({ rows: { selfcheck_state: [rand] } });
      p.cursors = { selfcheck_state: 1 };
      return p;
    })(),
  }));
  assert.equal(intreg.status, 400,
               "un filigran ÎNTREG a fost acceptat pe un flux declarat text");

  // Diacriticele sunt refuzate DINADINS: Python compară șirurile pe puncte de
  // cod, JavaScript pe unități UTF-16, MariaDB pe octeți. Pe ASCII toate trei
  // coincid; în afara lui pot alege alt maxim, iar cursorul n-ar mai avansa
  // niciodată pe un lot valid.
  await withServer();
  const neascii = await POST(syncRequest({
    payload: (() => {
      const p = syncPayload({ rows: { selfcheck_state: [{ ...rand, key: "verificări" }] } });
      p.cursors = { selfcheck_state: "verificări" };
      return p;
    })(),
  }));
  assert.equal(neascii.status, 400,
               "un filigran text cu diacritice a fost acceptat");

  await withServer();
  const bun = await POST(syncRequest({
    payload: (() => {
      const p = syncPayload({ rows: { selfcheck_state: [rand] } });
      p.cursors = { selfcheck_state: "web" };
      return p;
    })(),
  }));
  // Corpul se citește O SINGURĂ DATĂ: `text()` în mesajul aserțiunii l-ar
  // consuma, iar `json()` de mai jos ar arunca „Body is unusable" — o eroare
  // despre citire, nu despre ce probează testul.
  const raw = await bun.text();
  assert.equal(bun.status, 200, raw);
  const body = JSON.parse(raw) as { accepted: Record<string, unknown> };
  assert.equal(body.accepted.selfcheck_state, "web",
               "ecoul nu e filigranul text trimis, deci cursorul nu s-ar muta");
});
