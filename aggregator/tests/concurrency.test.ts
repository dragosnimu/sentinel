/**
 * Semnale simultane. Motivul pentru care starea NU mai e un singur document.
 *
 * Înainte de mai multe instanțe, doi expeditori care scriau în același timp erau
 * o anomalie. Cu mai multe instanțe, e regula: N servere trimit pe intervale
 * independente, iar la un moment dat două cereri se suprapun. Fereastra e de
 * câteva milisecunde, deci la cinci instanțe se nimerește cam zilnic — și
 * continuu în ziua în care toate au fost repornite de aceeași rulare de deploy,
 * fiindcă atunci fazele lor sunt aliniate.
 *
 * Ce se întâmpla cu un singur document citit-modificat-scris:
 *
 *   - expeditorul B citea fișierul înainte ca A să-l redenumească, deci copia
 *     lui B a instanțelor nu-l conținea pe A; scrierea lui B ștergea A de pe
 *     disc. Instanța dispărea din panou, din `/status` și din bucla de
 *     verificare — iar când reapărea, avea `counters_moved_at` resetat (alarma
 *     de conductă moartă întârziată cu până la 15 minute) și `alerted` șters
 *     (alerta rezolvată se retrimitea, sau una reală pleca de două ori). Dacă
 *     serverul murea chiar în fereastra aia, nu mai alerta nimic.
 *   - amândoi foloseau același nume de fișier temporar, deci cel care pierdea
 *     cursa primea ENOENT la redenumire, iar un semnal semnat corect se
 *     întorcea cu 500.
 *
 * Testele de aici reproduc exact asta la nivel de rută, adică prin tot drumul
 * pe care îl parcurge un semnal adevărat.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { baseEnv, beatPayload, beatRequest, leftoverTempFiles, removeState, setEnv } from "./witness-harness";
import { POST } from "@/app/api/sentinel/beat/route";
import { readAll, readInstance, writeInstance } from "@/lib/store";

const KEYS: Record<string, string> = {
  aaa111: "cheie-aaa-test",
  bbb222: "cheie-bbb-test",
  ccc333: "cheie-ccc-test",
};

beforeEach(async () => {
  baseEnv();
  // Exact cele trei instanțe, fără `default`: registrul e ce enumeră `readAll`,
  // deci o cheie în plus ar adăuga o instanță în aserțiuni.
  setEnv({ SENTINEL_BEACON_SECRET: undefined, SENTINEL_INSTANCE_SECRETS: JSON.stringify(KEYS) });
  await removeState();
});

afterEach(async () => {
  await removeState();
});

function send(id: string, seq: number): Promise<Response> {
  return beatRequest({
    instance: id,
    key: KEYS[id],
    payload: beatPayload({ instance_id: id, seq, last_event_id: 1000 + seq }),
  }).then(POST);
}

test("semnale simultane de la instanțe diferite nu se pierd unul pe altul", async () => {
  // 25 de runde, fiindcă e o cursă: o singură rundă poate să nimerească
  // ordinea fericită și să treacă verde peste un defect care există.
  const ids = Object.keys(KEYS);
  for (let round = 1; round <= 25; round++) {
    const responses = await Promise.all(ids.map((id) => send(id, round)));

    for (let i = 0; i < ids.length; i++) {
      assert.equal(responses[i].status, 200,
        `runda ${round}: ${ids[i]} a primit ${responses[i].status} pe un semnal semnat corect`);
    }

    const state = await readAll();
    assert.deepEqual(Object.keys(state.instances).sort(), ids.slice().sort(),
      `runda ${round}: o instanță a dispărut din stare`);
    for (const id of ids) {
      assert.equal(state.instances[id].last?.seq, round,
        `runda ${round}: ${id} nu are ultimul semnal`);
    }
  }
});

test("scrierile simultane pentru aceeași instanță nu se lovesc de același fișier temporar", async () => {
  // Numele temporar trebuie să fie unic per scriere. Cu unul singur, cel care
  // pierde cursa redenumește un fișier pe care celălalt l-a mutat deja, primește
  // ENOENT, iar apelantul lui vede o eroare pentru o operație corectă.
  const writes = Array.from({ length: 20 }, (_, i) =>
    writeInstance("aaa111", { counters_moved_at: `2026-08-12T09:00:${String(i).padStart(2, "0")}.000Z` }));
  await assert.doesNotReject(Promise.all(writes));

  const after = await readInstance("aaa111");
  assert.ok(after?.counters_moved_at, "starea a rămas nescrisă după scrieri simultane");
});

test("două semnale simultane pe ACEEAȘI instanță nu produc niciodată 5xx", async () => {
  // Doi expeditori pe o singură identitate rămân o anomalie — de obicei o gazdă
  // clonată dintr-un backup. Reacția corectă e 200 sau 409, niciodată o eroare
  // de server: un 500 aici l-ar face pe expeditor să creadă că martorul e rupt.
  await send("aaa111", 1);
  const [a, b] = await Promise.all([send("aaa111", 2), send("aaa111", 3)]);
  for (const r of [a, b]) {
    assert.ok(r.status < 500, `a răspuns ${r.status} la un semnal semnat corect`);
  }
  const seq = (await readInstance("aaa111"))?.last?.seq;
  assert.ok(seq === 2 || seq === 3, `secvență neașteptată după cursă: ${seq}`);
});

test("nicio scriere nu lasă fișiere temporare în urmă", async () => {
  await Promise.all(Object.keys(KEYS).map((id) => send(id, 1)));
  const leftovers = await leftoverTempFiles();
  assert.deepEqual(leftovers, [], `fișiere temporare rămase: ${leftovers.join(", ")}`);
});
