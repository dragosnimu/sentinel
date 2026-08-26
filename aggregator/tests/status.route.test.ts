/**
 * `/status`: starea ca număr HTTP, pentru un monitor de uptime.
 *
 * Ruta asta e plasa de siguranță pentru găzduirile fără cron: alertarea
 * monitorului devine escaladarea noastră. Deci un 200 greșit nu e o
 * inexactitate, e o alarmă care nu se declanșează.
 *
 * `age_s` e valoarea prin care se dovedește că CDN-ul nu pune ruta în cache —
 * două cereri la câteva secunde distanță trebuie să dea numere diferite.
 * Procedura e în watcher/INCARCARE-HOSTINGER.md; testul de aici ține câmpul viu.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  baseEnv, bodyOf, configureInstances, pretendStateIsInsideApp, removeState,
  writeRawInstance, writeRawState,
} from "./witness-harness";
import { GET } from "@/app/api/sentinel/status/route";
import { writeInstance } from "@/lib/store";

beforeEach(async () => {
  baseEnv();
  await removeState();
});

afterEach(async () => {
  await removeState();
});

function beatAt(iso: string) {
  return {
    seq: 5, sent_at: iso, received_at: iso,
    last_event_id: 10, detect_cursor: 9, incidents_open: 0, blocklist_size: 0,
    audit_head: "a".repeat(64), interval_s: 60,
    selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: iso },
  };
}

async function seed(instances: Record<string, Record<string, unknown>>): Promise<void> {
  // Cheile ÎNTÂI: o instanță fără cheie configurată nu există, deci fișierul ei
  // ar fi ignorat și testul ar verifica altceva decât crede.
  configureInstances(Object.keys(instances));
  for (const [id, state] of Object.entries(instances)) {
    await writeInstance(id, state as never);
  }
}

function get(query = ""): Promise<Response> {
  return GET(new Request(`https://exemplu.ro/api/sentinel/status${query}`));
}

function fresh() {
  const iso = new Date().toISOString();
  return { last: beatAt(iso), counters_moved_at: iso };
}

function silent() {
  const iso = new Date(Date.now() - 3600 * 1000).toISOString();
  return { last: beatAt(iso), counters_moved_at: iso };
}

test("semnal proaspăt → 200 și status ok", async () => {
  await seed({ default: fresh() });
  const res = await get();
  assert.equal(res.status, 200);
  const body = await bodyOf(res);
  assert.equal(body.status, "ok");
  assert.equal(typeof body.age_s, "number");
  assert.ok((body.age_s as number) < 5, `age_s neașteptat: ${body.age_s}`);
});

test("semnal vechi → 503, ca monitorul de uptime să sune", async () => {
  await seed({ default: silent() });
  const res = await get();
  assert.equal(res.status, 503);
  assert.equal((await bodyOf(res)).status, "silent");
});

test("răspunsul poartă no-store — altfel monitorul citește ore în șir ultimul răspuns bun", async () => {
  await seed({ default: fresh() });
  assert.match(String((await get()).headers.get("cache-control")), /no-store/);
});

test("fără nicio instanță configurată, ruta nu pretinde că a văzut una", async () => {
  await removeState();
  configureInstances([]);
  const res = await get();
  // Codul HTTP e SINGURA valoare pe care o consumă un monitor de uptime. O
  // versiune anterioară a testului verifica doar corpul — deci trecea verde
  // peste un 200 „ok" dat pe o stare pe care ruta nu o citise niciodată.
  assert.equal(res.status, 503, "zero instanțe cunoscute au fost raportate ca 200");
  const body = await bodyOf(res);
  assert.equal(body.status, "unconfigured");
  assert.equal(body.last_seen, null);
  assert.equal(body.age_s, null);
  assert.deepEqual(body.instances, []);
});

test("o stare coruptă nu e „ok\": e „unreadable\", cu 503", async () => {
  // «Unknown» și «fine» sunt stări diferite, iar contopirea lor e felul în care
  // o unealtă de monitorizare minte. Ruta asta e citită de un monitor care nu
  // are cum să afle altfel.
  await removeState();
  configureInstances(["default"]);
  await writeRawState('{"last":{"seq":1,');
  const res = await get();
  assert.equal(res.status, 503);
  // Fișierul de bază e ilizibil, deci instanța `default` nu a trimis niciodată
  // nimic din ce putem citi. Nu e „ok" în nicio interpretare.
  assert.equal((await bodyOf(res)).status, "no-beat");
});

test("o instanță cu fișier ilizibil apare ca „unreadable\", nu dispare", async () => {
  // Dispariția ar fi mai rea decât un verdict greșit: instanța n-ar mai fi
  // nicăieri, iar tăcerea ei n-ar mai fi observată de nimeni.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  await writeInstance("aaa111", fresh() as never);
  await writeRawInstance("bbb222", "}}stricata{{");
  const res = await get();
  assert.equal(res.status, 503);
  const body = await bodyOf(res);
  assert.deepEqual(body.instances.map((i) =>
    [i.instance, i.status]), [["aaa111", "ok"], ["bbb222", "unreadable"]]);

  const one = await get("?instance=bbb222");
  assert.equal(one.status, 503);
  assert.equal((await bodyOf(one)).status, "unreadable");
});

// ---------------------------------------------------------------------------
// Mai multe instanțe

test("o copie de siguranță pusă lângă stare NU devine un server", async () => {
  // Eșecul care a produs regula: martorul își ține starea în directorul home al
  // operatorului (watcher/INCARCARE-HOSTINGER.md), adică exact unde cineva pune o copie
  // înainte de o publicare. O copie are prin definiție un semnal vechi, deci
  // devenea un server tăcut, cu alertă critică pe Telegram, repetată la fiecare
  // patru ore, despre o mașină care nu există.
  //
  // Un marcaj scris în fișier nu ar fi ajutat: copia îl poartă și pe acela.
  await removeState();
  await seed({ aaa111: fresh() });
  await writeRawInstance("backup-2026-08-12", JSON.stringify(silent()));

  const res = await get();
  assert.equal(res.status, 200, "o copie de fișier a stricat verdictul general");
  const body = await bodyOf(res);
  assert.deepEqual(body.instances.map((i) => i.instance), ["aaa111"]);

  // Și nici întrebată direct nu există.
  const direct = await get("?instance=backup-2026-08-12");
  assert.equal(direct.status, 503);
  assert.equal((await bodyOf(direct)).status, "unknown");
});

test("o instanță configurată care n-a trimis niciodată e `no-beat`, nu `ok`", async () => {
  // Ăsta e cazul pe care `judge()` îl consideră corect „fără alarmă" — și are
  // dreptate pentru ce decide ea. Dar un monitor de uptime nu întreabă „să
  // sun?", ci „e viu?", iar răspunsul e că nu știm. Un 200 aici face verde un
  // server care poate nu a pornit niciodată.
  await removeState();
  configureInstances(["aaa111"]);
  const res = await get();
  assert.equal(res.status, 503);
  const body = await bodyOf(res);
  assert.equal(body.status, "no-beat");
  assert.deepEqual(body.instances, [{
    instance: "aaa111", status: "no-beat", last_seen: null, age_s: null,
  }]);
});

test("un fișier propriu fără semnal în el nu e verde", async () => {
  // Forma pe care plasa de „ilizibil" NU o prinde: obiect valid, doar că fără
  // `last`. Se poate ajunge la ea printr-o scriere concurentă, iar rezultatul ar
  // fi o instanță permanent verde pentru o mașină care poate fi moartă.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  await writeRawInstance("aaa111", "{}");
  await writeRawInstance("bbb222", '{"counters_moved_at":"2026-08-12T09:00:00.000Z"}');
  const res = await get();
  assert.equal(res.status, 503);
  assert.deepEqual((await bodyOf(res)).instances.map(
    (i) => i.status), ["no-beat", "no-beat"]);
});

test("o instanță care n-a trimis niciodată NU ține plasa de siguranță roșie", async () => {
  // `SENTINEL_BEACON_SECRET` e permanent, după `watcher/.env.example`, deci `default`
  // rămâne în registru pentru totdeauna. Din clipa în care fiecare server își
  // trimite propriul `instance_id` — adică scopul întregii faze — `default` nu
  // mai primește niciodată nimic. Numărată, ar fi ținut `/status` pe 503 la
  // nesfârșit, cu trei servere sănătoase. O alarmă care nu se oprește e o
  // alarmă pe care operatorul o oprește.
  await removeState();
  await seed({ aaa111: fresh(), bbb222: fresh() });
  configureInstances(["aaa111", "bbb222", "default"]);

  const res = await get();
  assert.equal(res.status, 200, "o instanță care n-a trimis niciodată a înroșit răspunsul");
  const body = await bodyOf(res);
  assert.equal(body.status, "ok");
  // Se VEDE, chiar dacă nu se numără.
  assert.deepEqual(body.instances.map((i) =>
    [i.instance, i.status]),
  [["aaa111", "ok"], ["bbb222", "ok"], ["default", "no-beat"]]);
  // Iar rezumatul descrie o instanță care chiar a trimis, ca `age_s` să existe:
  // e valoarea cu care se dovedește că CDN-ul nu pune ruta în cache.
  assert.equal(typeof body.age_s, "number");
});

test("o instanță tăcută înroșește răspunsul chiar dacă alta n-a trimis niciodată", async () => {
  await removeState();
  await seed({ aaa111: silent() });
  configureInstances(["aaa111", "default"]);
  const res = await get();
  assert.equal(res.status, 503);
  assert.equal((await bodyOf(res)).status, "silent");
});

test("un fișier care poartă identitatea altcuiva nu poate face un server tăcut să pară verde", async () => {
  // Lanțul complet al defectului: identitatea din fișier ajunge greșită →
  // fișierul e clasificat străin → instanța cade la `no-beat` → `no-beat` nu se
  // numără → `/status` răspunde 200 „ok" despre un server al cărui ultim semnal
  // e vechi de o oră. Silențiu în formă de sănătate.
  await removeState();
  configureInstances(["pacalit", "viu"]);
  await writeInstance("viu", fresh() as never);
  await writeInstance("pacalit", { ...silent(), instance_id: "altcineva" } as never);

  const res = await get();
  assert.equal(res.status, 503, "un server tăcut a fost raportat 200 ok");
  const body = await bodyOf(res);
  assert.equal(body.status, "silent");
  assert.deepEqual(body.instances.map((i) =>
    [i.instance, i.status]), [["pacalit", "silent"], ["viu", "ok"]]);
});

test("un server viu căruia i se șterge cheia rămâne vizibil și tace", async () => {
  // Proprietatea numărul unu. Fără identitatea scrisă în fișier, ștergerea unei
  // chei făcea serverul să dispară din listă, iar `/status` răspundea 200 „ok"
  // pe baza celorlalte.
  await removeState();
  await seed({ aaa111: fresh(), bbb222: silent() });
  configureInstances(["aaa111"]);

  const res = await get();
  assert.equal(res.status, 503, "un server viu fără cheie a dispărut, iar ruta a spus ok");
  const body = await bodyOf(res);
  assert.equal(body.status, "silent");
  assert.deepEqual(body.instances.map((i) => i.instance),
    ["aaa111", "bbb222"]);
});

// ---------------------------------------------------------------------------
// Starea care se pierde la publicare

test("starea scrisă în directorul aplicației face răspunsul roșu, chiar cu totul sănătos", async () => {
  // Configurația NESIGURĂ e cea implicită: fără `SENTINEL_STATE_PATH`, starea
  // stă în directorul de lucru, iar acela se rescrie la fiecare publicare.
  // Efectul nu e o eroare, e uitare — o instanță care alarma recade în
  // `no-beat`, care nu se numără, deci tace. Martorul refuză să pară sănătos
  // până când calea e mutată.
  await removeState();
  await seed({ aaa111: fresh(), bbb222: fresh() });

  const restore = pretendStateIsInsideApp();
  try {
    const res = await get();
    assert.equal(res.status, 503, "starea volatilă a trecut drept sănătate");
    const body = await bodyOf(res);
    assert.equal(body.status, "state-volatile");
    assert.equal(body.state_volatile, true);
    // Instanțele rămân raportate corect: problema e a martorului, nu a lor.
    assert.deepEqual(body.instances.map((i) => i.status), ["ok", "ok"]);
  } finally { restore(); }

  // Iar cu o cale din afara aplicației, același set de date e verde.
  const res = await get();
  assert.equal(res.status, 200);
  assert.equal((await bodyOf(res)).state_volatile, false);
});

test("o instanță tăcută bate volatilitatea în rezumat", async () => {
  // Amândouă sunt probleme, dar una e a unui server monitorizat. Aia trebuie să
  // scrie în vârf.
  await removeState();
  await seed({ aaa111: silent() });
  const restore = pretendStateIsInsideApp();
  try {
    const body = await bodyOf(await get());
    assert.equal(body.status, "silent");
    assert.equal(body.state_volatile, true);
  } finally { restore(); }
});

test("`?instance=` nu contrazice ruta agregată despre volatilitate", async () => {
  // Două suprafețe care se contrazic sunt cum se pierde încrederea în amândouă.
  await removeState();
  await seed({ aaa111: fresh() });
  const restore = pretendStateIsInsideApp();
  try {
    const res = await get("?instance=aaa111");
    assert.equal(res.status, 503, "instanța a ieșit verde pe o stare care se pierde");
    const body = await bodyOf(res);
    assert.equal(body.status, "state-volatile");
    assert.equal(body.state_volatile, true);
  } finally { restore(); }
});

test("o singură instanță tăcută trage tot răspunsul la 503", async () => {
  // Compromisul e scris în modulul rutei: agregatul e un bit pentru N servere.
  // Ce nu are voie să facă e să spună „ok" când unul tace.
  await seed({ a1b2c3: silent(), d4e5f6: fresh(), z9y8x7: fresh() });
  const res = await get();
  assert.equal(res.status, 503);
  const body = await bodyOf(res);
  assert.equal(body.status, "silent");
  assert.deepEqual(body.instances.map((i) => i.instance),
    ["a1b2c3", "d4e5f6", "z9y8x7"]);
});

test("rezumatul din vârf descrie instanța cu probleme, nu doar pe cea mai veche", async () => {
  // Eșecul pe care îl previne: o instanță blocată are semnalul PROASPĂT, deci
  // un rezumat ales după vechime ar fi spus „ok" într-un răspuns cu codul 503.
  const iso = new Date().toISOString();
  const stalled = {
    last: beatAt(iso),
    counters_moved_at: new Date(Date.now() - 3600 * 1000).toISOString(),
  };
  const olderButFine = {
    last: beatAt(new Date(Date.now() - 100 * 1000).toISOString()),
    counters_moved_at: new Date(Date.now() - 100 * 1000).toISOString(),
  };
  await seed({ a1b2c3: stalled, d4e5f6: olderButFine });
  const res = await get();
  assert.equal(res.status, 503);
  assert.equal((await bodyOf(res)).status, "stalled");
});

test("`?instance=` întreabă despre una singură, independent de celelalte", async () => {
  await seed({ a1b2c3: silent(), d4e5f6: fresh() });

  const b = await get("?instance=d4e5f6");
  assert.equal(b.status, 200);
  assert.equal((await bodyOf(b)).status, "ok");

  const a = await get("?instance=a1b2c3");
  assert.equal(a.status, 503);
  assert.equal((await bodyOf(a)).status, "silent");
});

test("o instanță despre care nu știm nimic dă 503, nu 200", async () => {
  // Cine întreabă despre un identificator anume a declarat că se așteaptă să
  // existe. Un 200 aici înseamnă un monitor de uptime verde pe un server care
  // n-a trimis niciodată nimic — adică o gardă care nu prinde nimic, tăcut.
  await seed({ a1b2c3: fresh() });
  const res = await get("?instance=nu-exista");
  assert.equal(res.status, 503);
  const body = await bodyOf(res);
  assert.equal(body.status, "unknown");
  assert.equal(body.last_seen, null);
});

test("`?instance=` nu poate ajunge la proprietăți moștenite", async () => {
  // `instances["constructor"]` întoarce o funcție pe orice obiect obișnuit.
  // Fără citire de proprietate proprie, instanța aia ar părea că există.
  await seed({ a1b2c3: fresh() });
  for (const bad of ["constructor", "toString", "hasOwnProperty"]) {
    const res = await get(`?instance=${bad}`);
    assert.equal(res.status, 503, `a răspuns pentru ${bad}`);
    assert.equal((await bodyOf(res)).status, "unknown");
  }
});
