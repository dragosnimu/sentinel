/**
 * Ruta care primește semnalul: ce acceptă, ce refuză și cu ce cod.
 *
 * Codul de răspuns nu e cosmetic aici — e diagnosticul pe care îl are
 * operatorul la instalare, prin `curl`, fără acces la jurnale:
 *
 *   500  nu sunt configurat (lipsește cheia)
 *   401  te-am refuzat (semnătură, cheie sau identitate)
 *   400  semnal malformat sau prea vechi
 *   409  secvență care nu a crescut
 *
 * Dacă „nu sunt configurat" ar da 401, procedura de acceptanță din
 * watcher/INCARCARE-HOSTINGER.md ar arăta verde pe un martor care nu verifică nimic.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import {
  baseEnv, beatPayload, beatRequest, bodyOf, removeState, setEnv, BEACON_KEY,
} from "./witness-harness";
import { POST } from "@/app/api/sentinel/beat/route";
import { readAll, instanceFile } from "@/lib/store";
import { canonical } from "@/lib/verify";

beforeEach(async () => {
  baseEnv();
  await removeState();
});

afterEach(async () => {
  await removeState();
});

test("fără nicio cheie configurată, ruta întoarce 500, nu 401", async () => {
  setEnv({ SENTINEL_BEACON_SECRET: undefined, SENTINEL_INSTANCE_SECRETS: undefined });
  const res = await POST(await beatRequest({}));
  assert.equal(res.status, 500);
});

test("un semnal valid e acceptat și scris în stare", async () => {
  const res = await POST(await beatRequest({ payload: beatPayload({ seq: 5 }) }));
  assert.equal(res.status, 200);
  assert.deepEqual(await bodyOf(res), { ok: true, seq: 5, instance: "default" });

  const state = await readAll();
  assert.equal(state.instances.default?.last?.seq, 5, "semnalul acceptat nu a ajuns în stare");
});

test("răspunsul poartă no-store — un heartbeat pus în cache e chiar minciuna apărată", async () => {
  const res = await POST(await beatRequest({}));
  assert.match(String(res.headers.get("cache-control")), /no-store/);
});

test("semnătura calculată cu altă cheie e refuzată cu 401", async () => {
  const res = await POST(await beatRequest({ key: "cheie-cu-totul-alta" }));
  assert.equal(res.status, 401);
});

test("corpul modificat după semnare e refuzat cu 401", async () => {
  const payload = beatPayload({ last_event_id: 1000 });
  const raw = canonical(payload);
  const req = await beatRequest({ payload });
  // Aceeași semnătură, alt corp: exact ce ar face cineva care vrea contoare
  // umflate ca să pară că ingestia merge.
  const tampered = new Request(req.url, {
    method: "POST",
    body: raw.replace('"last_event_id":1000', '"last_event_id":9000'),
    headers: req.headers,
  });
  assert.equal((await POST(tampered)).status, 401);
});

test("antetul de semnătură lipsă dă 401, nu excepție", async () => {
  const raw = canonical(beatPayload());
  const req = new Request("https://exemplu.ro/api/sentinel/beat", { method: "POST", body: raw });
  assert.equal((await POST(req)).status, 401);
});

test("un corp semnat corect dar care nu e JSON dă 400", async () => {
  // Semnătura e validă, deci am trecut de autentificare; problema e forma.
  const res = await POST(await beatRequest({ raw: "nu-e-json" }));
  assert.equal(res.status, 400);
});

test("un semnal mai vechi decât max_age_s e refuzat cu 400", async () => {
  // Fără fereastra asta, un semnal valid capturat o dată poate fi reluat la
  // nesfârșit, iar martorul ar arăta „viu" pe o mașină oprită de o săptămână.
  const old = new Date(Date.now() - 500 * 1000).toISOString();
  const res = await POST(await beatRequest({
    payload: beatPayload({ sent_at: old, max_age_s: 120 }),
  }));
  assert.equal(res.status, 400);
});

test("un semnal din viitor e refuzat tot cu 400", async () => {
  const future = new Date(Date.now() + 500 * 1000).toISOString();
  const res = await POST(await beatRequest({
    payload: beatPayload({ sent_at: future, max_age_s: 120 }),
  }));
  assert.equal(res.status, 400);
});

/**
 * Semnează OCTEȚII dați, fără să treacă prin forma canonică.
 *
 * `beatRequest` cu `payload` folosește `canonical`, care refuză din start un
 * `1.5` sau un `NaN` — corect pentru expeditorul cinstit, inutil aici. Cine
 * exploatează fereastra de reluare are cheia HMAC și semnează ce octeți vrea:
 * `1.5`, un șir, un obiect. Testul trebuie să meargă pe drumul LUI, altfel ar
 * proba doar că expeditorul nostru nu greșește.
 */
function rawBeat(payload: Record<string, unknown>) {
  return beatRequest({ raw: JSON.stringify(payload) });
}

test("`max_age_s` scris greșit e un REFUZ, nu o fereastră de reluare nemărginită", async () => {
  // Eșecul, în producție până azi: `Number(payload.max_age_s || 120)` pe orice
  // valoare care nu e număr dă `NaN`, iar `Math.abs(age) > NaN` e FALS.
  // Comparația nu eșua — TRECEA. Verificarea de prospețime exista și nu
  // verifica nimic, deci cine deține cheia HMAC (root pe mașina monitorizată)
  // putea retrimite oricând un semnal captat, ca să spună „sunt viu" despre un
  // server oprit de ore. Adică exact minciuna pentru care există martorul.
  //
  // `1e9` e cealaltă jumătate, care nu e `NaN`: o fereastră de 31 de ani,
  // semnată perfect corect și la fel de tăcută.
  const old = new Date(Date.now() - 3600 * 1000).toISOString();
  //
  // Se asertează și RAMURA pe care iese fiecare, nu doar codul. Un 400 poate
  // veni din două locuri — „câmpul e scris greșit" sau „semnalul e prea vechi" —
  // iar dacă testul nu le deosebește, o verificare scoasă din `readMaxAge` nu se
  // vede: valoarea trece mai departe și e refuzată oricum de vechime, adică
  // exact o gardă care nu prinde nimic fără să spună. Cu ramura fixată, o
  // valoare care ar trebui respinsă ca formă, dar iese pe vechime, pică.
  //
  // `null` e cazul aparte, și e singurul de pe ramura de vechime: înseamnă
  // „absent", deci cade pe implicitul de 120 s, iar semnalul de o oră e refuzat
  // de fereastra aia.
  const CAMP = "camp";
  const VECHIME = "vechime";
  const rele: { valoare: unknown; ramura: string }[] = [
    { valoare: "120", ramura: CAMP },      // șir care ARATĂ ca un număr
    { valoare: "curând", ramura: CAMP },   // `NaN` — cazul din raport
    { valoare: "", ramura: CAMP },
    { valoare: null, ramura: VECHIME },    // absent → implicitul
    { valoare: 0, ramura: CAMP },          // ține `raw < 1` în viață
    { valoare: -1, ramura: CAMP },
    { valoare: 1.5, ramura: CAMP },        // ține `Number.isSafeInteger` în viață
    { valoare: 1e9, ramura: CAMP },        // fereastră de 31 de ani
    { valoare: {}, ramura: CAMP },         // `NaN`
    { valoare: [], ramura: CAMP },
    { valoare: true, ramura: CAMP },
  ];
  assert.equal(rele.length, 11, "lista a ieșit alta decât cea scrisă — testul nu mai probează ce spune");

  for (const { valoare, ramura } of rele) {
    const eticheta = `max_age_s=${JSON.stringify(valoare)}`;
    const res = await POST(await rawBeat(beatPayload({ sent_at: old, max_age_s: valoare })));
    assert.notEqual(res.status, 200, `${eticheta} a lăsat să treacă un semnal vechi de o oră`);
    assert.equal(res.status, 400, eticheta);
    const { error } = await bodyOf(res);
    if (ramura === CAMP) {
      assert.match(String(error), /max_age_s/,
        `${eticheta} a fost refuzat ca «prea vechi», nu ca valoare imposibilă`);
    } else {
      assert.equal(error, "refuzat", `${eticheta} nu a ieșit pe ramura de vechime`);
    }
  }

  // Și nimic din toate astea nu a ajuns în stare: un refuz care totuși scrie
  // `received_at` ar reseta ceasul tăcerii, adică ar face reluarea să meargă pe
  // altă ușă.
  assert.equal((await readAll()).instances.default?.last, undefined,
    "un semnal refuzat pentru `max_age_s` a fost totuși înregistrat");
});

test("`max_age_s` absent înseamnă implicitul de 120 s, nu «fără fereastră»", async () => {
  // Podeaua reparației de mai sus. Protocolul are câmpul opțional, iar dacă
  // absența ar fi tratată ca refuz, un expeditor mai vechi ar fi tăiat complet
  // — simptomul fiind chiar alarma pe care martorul o dă când moare un server.
  const fresh = beatPayload();
  delete fresh.max_age_s;
  assert.equal((await POST(await rawBeat(fresh))).status, 200);

  const old = beatPayload({ sent_at: new Date(Date.now() - 500 * 1000).toISOString(), seq: 2 });
  delete old.max_age_s;
  assert.equal((await POST(await rawBeat(old))).status, 400,
    "fără `max_age_s` nu s-a aplicat nicio fereastră");
});

test("un `max_age_s` valid CHIAR lărgește fereastra, nu e doar tolerat", async () => {
  // Fără proba asta, testele de mai sus ar trece și pe o implementare care
  // refuză orice semnal vechi indiferent de câmp — adică pe una care nu citește
  // deloc `max_age_s`. Atunci plafonul ar părea că apără ceva ce nu există.
  const old = new Date(Date.now() - 3600 * 1000).toISOString();
  assert.equal((await POST(await rawBeat(beatPayload({ sent_at: old, max_age_s: 7200 })))).status,
    200, "un `max_age_s` mai mare decât vechimea nu a fost luat în seamă");
});

test("un `max_age_s` peste plafon e refuzat, oricât de corect ar fi semnat", async () => {
  // Plafonul e singurul lucru care oprește o fereastră de reluare arbitrar de
  // lungă instalată dintr-o greșeală de configurație pe serverul monitorizat.
  // 86400 e aceeași valoare ca `MAX_AGE_CEILING_S` din agregator.
  const old = new Date(Date.now() - 3600 * 1000).toISOString();
  assert.equal((await POST(await rawBeat(beatPayload({ sent_at: old, max_age_s: 86_400 })))).status,
    200, "chiar plafonul a fost refuzat");
  assert.equal((await POST(await rawBeat(beatPayload({
    sent_at: old, max_age_s: 86_401, seq: 2,
  })))).status, 400, "o fereastră peste plafon a fost acceptată");
});

test("refuzul pentru `max_age_s` NUMEȘTE câmpul, ca operatorul să-l poată găsi", async () => {
  // Expeditorul scrie în jurnalul de pe serverul monitorizat codul și primii 200
  // de octeți ai corpului (`sentinel/report/beacon.py`). Aia e singura suprafață
  // pe care o greșeală de configurație e citibilă: jurnalul găzduirii martorului
  // nu ajunge la operator. Un corp opac ar lăsa „400" ca tot diagnosticul, pe o
  // instalare care în același timp alertează că serverul tace.
  const res = await POST(await rawBeat(beatPayload({ max_age_s: "curând" })));
  assert.equal(res.status, 400);
  assert.match(String((await bodyOf(res)).error), /max_age_s/,
    "corpul refuzului nu numește câmpul greșit");
});

test("un `sent_at` de neînțeles e refuzat, nu tratat ca proaspăt", async () => {
  const res = await POST(await beatRequest({
    payload: beatPayload({ sent_at: "acum, cred" }),
  }));
  assert.equal(res.status, 400);
});

test("o secvență care nu a crescut e refuzată cu 409", async () => {
  assert.equal((await POST(await beatRequest({ payload: beatPayload({ seq: 7 }) }))).status, 200);
  // Aceeași secvență: reluare.
  assert.equal((await POST(await beatRequest({ payload: beatPayload({ seq: 7 }) }))).status, 409);
  // Una mai mică: expeditor cu baza refăcută dintr-un backup, sau un al doilea
  // expeditor pe aceeași identitate.
  assert.equal((await POST(await beatRequest({ payload: beatPayload({ seq: 3 }) }))).status, 409);
  // Una mai mare: semnal proaspăt, acceptat.
  assert.equal((await POST(await beatRequest({ payload: beatPayload({ seq: 8 }) }))).status, 200);
});

test("un 409 nu suprascrie ultimul semnal bun", async () => {
  // Eșecul pe care îl previne: o reluare care rescrie `received_at` ar reseta
  // ceasul tăcerii, iar un atacator care retrimite un semnal capturat ar ține
  // martorul verde la nesfârșit.
  await POST(await beatRequest({ payload: beatPayload({ seq: 7, last_event_id: 100 }) }));
  const before = JSON.stringify(await readAll());
  await POST(await beatRequest({ payload: beatPayload({ seq: 7, last_event_id: 999 }) }));
  assert.equal(JSON.stringify(await readAll()), before);
});

test("contoarele care nu avansează nu mișcă `counters_moved_at`", async () => {
  // Ăsta E detectorul de conductă moartă: dacă momentul s-ar reseta la fiecare
  // semnal, martorul n-ar vedea niciodată un proces viu cu ingestia oprită.
  const first = beatPayload({ seq: 1, last_event_id: 100, detect_cursor: 90 });
  await POST(await beatRequest({ payload: first }));
  const moved1 = movedAt(await readAll());
  assert.ok(moved1, "primul semnal nu a stabilit `counters_moved_at`");

  await new Promise((r) => setTimeout(r, 10));
  await POST(await beatRequest({
    payload: beatPayload({ seq: 2, last_event_id: 100, detect_cursor: 90 }),
  }));
  assert.equal(movedAt(await readAll()), moved1, "contoare neschimbate au mișcat momentul");

  await new Promise((r) => setTimeout(r, 10));
  await POST(await beatRequest({
    payload: beatPayload({ seq: 3, last_event_id: 101, detect_cursor: 90 }),
  }));
  assert.notEqual(movedAt(await readAll()), moved1, "contoare avansate NU au mișcat momentul");
});

function movedAt(state: Awaited<ReturnType<typeof readAll>>, id = "default"): string | undefined {
  return state.instances[id]?.counters_moved_at;
}

test("cheia din mediu e chiar cea folosită la verificare", async () => {
  // Fără aserțiunea asta, un test care semnează cu aceeași constantă pe care o
  // citește ruta ar trece și dacă ruta ar ignora complet mediul.
  setEnv({ SENTINEL_BEACON_SECRET: "alta-cheie-de-test" });
  assert.equal((await POST(await beatRequest({ key: BEACON_KEY }))).status, 401);
  assert.equal((await POST(await beatRequest({ key: "alta-cheie-de-test" }))).status, 200);
});

/**
 * Un corp mărginit: numărul din refuz e chiar plafonul, iar plafonul chiar taie.
 *
 * Plafonul NU se importă din rută. Un modul de rută Next exportă `POST`,
 * `dynamic` și `revalidate`; a mai exporta o constantă doar ca s-o citească
 * testul înseamnă a schimba forma modulului livrat pentru comoditatea probei.
 * Se citește din corpul refuzului, care e oricum singura suprafață pe care
 * numărul ajunge la cineva.
 */
async function bodyLimit(): Promise<number> {
  const res = await POST(await beatRequest({ raw: "x".repeat(1024 * 1024) }));
  assert.equal(res.status, 413, "un corp de 1 MiB nu a fost refuzat");
  const { error } = await bodyOf(res);
  const found = String(error).match(/(\d+)/);
  assert.ok(found, `corpul refuzului nu numește plafonul: ${error}`);
  return Number(found[1]);
}

test("un corp peste plafon e refuzat cu 413 și nu ajunge în stare", async () => {
  // Ruta e publică și nu cere nimic ca să întrebe. Fără plafon, oricine de pe
  // internet putea face procesul martorului să tamponeze date arbitrare —
  // măsurat pe 15 august 2026: 16 MiB acceptați și hashuiți în 19 ms. Martorul e
  // singura mașină pe care un atacator cu root pe serverul monitorizat NU o
  // controlează; memoria lui e cea care nu are voie să fie a lui.
  const limit = await bodyLimit();
  assert.ok(limit >= 1024, `plafonul e ${limit} octeți, sub orice semnal real`);

  // Exact plafonul TRECE de citire. `beatRequest` semnează corect octeții dați,
  // deci corpul ajunge dincolo de semnătură și cade abia la parsarea JSON: 400,
  // nu 413. Fără proba asta, un plafon coborât din greșeală ar arăta la fel de
  // „reparat" și ar refuza fiecare bătaie a serverului real.
  const laLimita = await POST(await beatRequest({ raw: "x".repeat(limit) }));
  assert.equal(laLimita.status, 400, "un corp exact cât plafonul a fost oprit la citire");

  assert.equal((await POST(await beatRequest({ raw: "x".repeat(limit + 1) }))).status, 413,
    "un octet peste plafon a trecut de citire");

  assert.equal((await readAll()).instances.default?.last, undefined,
    "un semnal refuzat pentru dimensiune a fost totuși înregistrat");
});

test("plafonul se aplică și fără `content-length`, OPRIND citirea", async () => {
  // `content-length` e scris de client și lipsește cu totul dintr-o cerere în
  // bucăți. Un plafon verificat doar pe antet ar fi exact tiparul din CLAUDE.md:
  // o gardă care raportează „nimic în neregulă" fiindcă nu se uită la ce trebuie.
  //
  // Se asertează EFECTUL, nu doar codul: sursa numără câte bucăți i s-au cerut.
  //
  // Ce oprește citirea e `return "too-large"` — nu se mai emite niciun
  // `reader.read()`, deci sursa nu mai e trasă. O versiune anterioară a
  // comentariului ăstuia dădea meritul lui `reader.cancel()`, și era FALS:
  // măsurat, cu `cancel()` scos suita rămâne verde, fiindcă `return`-ul face
  // singur toată oprirea. Contează în direcția obișnuită — cine crede că
  // `cancel()` e paza poate restructura în jurul lui și muta `return`-ul.
  //
  // `cancel()` e curățenie, și e curățenie care se vede: îi spune SURSEI să se
  // oprească, iar într-un server adevărat sursa e socketul. Fără el, cine
  // trimite nu află că nu mai citește nimeni. De-aia se asertează separat mai
  // jos, prin propriul callback al fluxului — altfel ștergerea lui ar fi o
  // mutație pe care nimic n-o vede.
  const BUCATI = 1024;
  let trase = 0;
  let anulat = false;
  const stream = new ReadableStream({
    pull(c) {
      trase++;
      if (trase > BUCATI) { c.close(); return; }
      c.enqueue(new Uint8Array(4096));
    },
    cancel() { anulat = true; },
  });
  const req = new Request("https://exemplu.ro/api/sentinel/beat", {
    method: "POST",
    body: stream,
    headers: { "X-Sentinel-Signature": "00" },
    // `duplex` e cerut de undici pentru un corp în flux. Purta un
    // `@ts-expect-error` cât timp tipurile veneau din lib.dom; sub tipurile lui
    // Node câmpul există, iar o directivă care nu mai stinge nimic e ea însăși
    // o eroare de compilare.
    duplex: "half",
  });
  assert.equal(req.headers.get("content-length"), null,
    "cererea are totuși content-length, deci nu probează ramura de flux");

  assert.equal((await POST(req)).status, 413, "un corp în bucăți a trecut de plafon");
  assert.ok(trase < BUCATI / 4,
    `citirea nu s-a oprit: s-au tras ${trase} bucăți din ${BUCATI}`);
  assert.ok(anulat,
    "fluxul nu a fost anulat: sursa — într-un server adevărat, socketul — nu a "
    + "aflat că nu mai citește nimeni");
});

test("un `content-length` peste plafon oprește cererea FĂRĂ să atingă corpul", async () => {
  // A doua jumătate a plafonului, și singura cu efect propriu: verificarea pe
  // antet e gratuită și, când clientul declară cinstit, fluxul nici nu se
  // deschide. Scoasă, ruta ar întoarce tot 413 — plafonul pe bucăți prinde
  // oricum — deci nimic din codul de stare n-ar arăta lipsa ei, iar mutația care
  // o șterge trecea verde. Se asertează ceea ce chiar diferă: dacă fluxul a fost
  // ACAPARAT. `getReader()` îl blochează și nu-l mai eliberează, nici după
  // `cancel()`, deci `locked` e faptul exact.
  let trase = 0;
  const stream = new ReadableStream({
    pull(c) { trase++; if (trase > 64) { c.close(); return; } c.enqueue(new Uint8Array(4096)); },
  });
  const req = new Request("https://exemplu.ro/api/sentinel/beat", {
    method: "POST",
    body: stream,
    headers: { "X-Sentinel-Signature": "00", "content-length": String(4096 * 64) },
    // `duplex` e cerut de undici pentru un corp în flux.
    duplex: "half",
  });

  assert.equal((await POST(req)).status, 413, "un content-length peste plafon a fost acceptat");
  assert.equal(req.body?.locked, false,
    `fluxul a fost deschis pentru un corp care se anunța singur peste plafon `
    + `(${trase} bucăți cerute)`);
});

test("`alerted_kinds` cu o valoare non-boolean e aruncat, nu convertit", async () => {
  // `readAlertedKinds` există fiindcă un `true` de aici poate tăcea o alertă
  // reală. Mutația `typeof v === "boolean"` -> `Boolean(v)` trecea verde pe
  // toată suita agregatorului (1067 teste): nimic nu POSTa vreodată un
  // `alerted_kinds` cu o valoare care nu era deja boolean, deci nimic nu
  // observa diferența. Cu `Boolean(v)`, `{selfcheck: "false"}` — un șir
  // nevid, deci adevărat — ar trece garda.
  //
  // Se citește FIȘIERUL DE PE DISC, nu prin `readAll()`: `asInstanceState`
  // din `lib/store.ts` curăță la CITIRE orice valoare non-boolean rămasă în
  // `alerted_kinds` (vezi testul dedicat din `check.route.test.ts`), deci un
  // test care trece prin `readAll()` ar verifica plasa de siguranță de la
  // capătul celălalt, nu garda de-aici — cele două există separat, dinadins,
  // și fiecare are nevoie de propriul test.
  const res = await POST(await beatRequest({
    payload: beatPayload({ alerted_kinds: { selfcheck: "false" } }),
  }));
  assert.equal(res.status, 200);

  const onDisk = JSON.parse(await readFile(instanceFile("default"), "utf8"));
  assert.deepEqual(onDisk.last.alerted_kinds, {},
    `o valoare non-boolean a fost SCRISĂ ca și cum ar fi fost boolean: ${JSON.stringify(onDisk.last.alerted_kinds)}`);
});

test("`alerted_kinds` cu valori boolean amestecate cu altele păstrează doar boolean-ele", async () => {
  const res = await POST(await beatRequest({
    payload: beatPayload({
      alerted_kinds: { selfcheck: true, altceva: 1, mai_mult: null },
    }),
  }));
  assert.equal(res.status, 200);

  const state = await readAll();
  assert.deepEqual(state.instances.default?.last?.alerted_kinds, { selfcheck: true });
});

test("un semnal real, cu eticheta și capul de audit la maximum, încape lejer", async () => {
  // Podeaua plafonului. Un plafon sub cel mai mare semnal legitim ar opri
  // heartbeat-ul serverului real cu 413 — vizibil în jurnalul lui, dar tot o
  // pană de alertare. Eticheta e cu diacritice dinadins: `MAX_LABEL` numără
  // caractere, plafonul numără OCTEȚI, iar un caracter românesc are doi.
  const limit = await bodyLimit();
  const payload = beatPayload({
    instance_label: "ăîșțâ".repeat(13).slice(0, 64),
    audit_head: "f".repeat(64),
    last_event_id: 999999999,
    detect_cursor: 999999999,
    seq: 999999999999,
  });
  const raw = canonical(payload);
  assert.ok(Buffer.byteLength(raw, "utf8") * 4 < limit,
    `semnalul maximal are ${Buffer.byteLength(raw, "utf8")} octeți, iar plafonul ` +
    `e ${limit}: sub patru ori marginea, un câmp nou l-ar putea depăși`);
  assert.equal((await POST(await beatRequest({ raw }))).status, 200,
    "un semnal legitim maximal a fost refuzat");
});
