/**
 * Retragerea unei identități: cum iese din evidență un server dezafectat.
 *
 * Eșecul pentru care există mecanismul, măsurat în producție pe 15 august 2026:
 * identitatea moștenită `default`, pe care serverul real nu o mai folosește de
 * când poartă `instance_id`, A BĂTUT cândva — deci nu e `no-beat`, care nu se
 * numără, ci `silent`, care se numără. Rezultatul: `/status` roșu la nesfârșit
 * și o alertă critică pe Telegram la fiecare patru ore despre un server care nu
 * există, în timp ce toate serverele reale sunt sănătoase. O alarmă care nu se
 * poate opri e o alarmă pe care operatorul o oprește — și atunci nu o mai citește
 * nici pe cea adevărată.
 *
 * Pe gazda martorului, „scoate variabila" nu e o operație disponibilă:
 * variabilele de mediu nu se pot șterge și nu pot fi goale (măsurat în aceeași
 * zi, vezi watcher/INCARCARE-HOSTINGER.md). Deci retragerea se declară explicit, iar
 * fișierul ăsta ține în viață cele patru jumătăți ale ei:
 *
 *   1. iese din registru, deci tăcerea ei nu mai intră în verdicte și nu mai sună;
 *   2. fișierul rămas pe disc nu o mai învie — și nici nu devine „ilizibil",
 *      care e roșu;
 *   3. cheia ei nu mai autentifică, fiindcă retragerea e o revocare;
 *   4. ce NU are voie să se schimbe: un server viu căruia i s-a ȘTERS cheia
 *      rămâne membru, tace și alarmează. Retragerea e o declarație deliberată,
 *      ștergerea unei chei nu e.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  baseEnv, beatPayload, beatRequest, bodyOf, captureLog, captureTelegram, captureWarn,
  configureInstances, keyFor, removeState, setEnv, writeRawInstance, writeRawState, CHECK_KEY,
} from "./witness-harness";
import { GET as status } from "@/app/api/sentinel/status/route";
import { GET as check } from "@/app/api/sentinel/check/route";
import { POST as beat } from "@/app/api/sentinel/beat/route";
import { configuredInstanceIds } from "@/lib/beat-keys";
import { readAll, readInstance, writeInstance } from "@/lib/store";

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

/** Semnal proaspăt: serverul care chiar mai trimite. */
function fresh() {
  const iso = new Date().toISOString();
  return { last: beatAt(iso), counters_moved_at: iso };
}

/** Semnal vechi de o oră: peste orice prag de tăcere, deci `silent`. */
function silent() {
  const iso = new Date(Date.now() - 3600 * 1000).toISOString();
  return { last: beatAt(iso), counters_moved_at: iso };
}

function get(query = ""): Promise<Response> {
  return status(new Request(`https://exemplu.ro/api/sentinel/status${query}`));
}

function send(instance: string, key = keyFor(instance), seq = 1) {
  return beatRequest({
    instance, key, payload: beatPayload({ instance_id: instance, seq }),
  });
}

// ---------------------------------------------------------------------------
// 1. Iese din registru

test("o identitate retrasă iese din registru, deci tăcerea ei nu mai înroșește agregatul", async () => {
  // Forma exactă din producție: un server real proaspăt, plus identitatea
  // moștenită care a bătut ultima dată acum 17 ore. Fără retragere, verdictul
  // agregat e `silent`/503 la nesfârșit — plasa de siguranță blocată pe roșu
  // pentru o mașină care nu există.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  await writeInstance("a1b2c3", fresh() as never);
  await writeInstance("default", silent() as never);

  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  assert.deepEqual(configuredInstanceIds(), ["a1b2c3"],
    "identitatea retrasă a rămas în registru");
  const res = await get();
  assert.equal(res.status, 200, "o identitate retrasă a ținut agregatul pe roșu");
  const body = await bodyOf(res);
  assert.equal(body.status, "ok");
  assert.deepEqual(body.instances.map((i) => i.instance), ["a1b2c3"]);
});

test("`/check` nu mai alertează despre o identitate retrasă", async () => {
  // Jumătatea care sună. Fișierul retras poartă un semnal vechi de o oră, deci
  // înainte de retragere producea o alertă critică, repetată la fiecare patru
  // ore, despre un server dezafectat.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  await writeInstance("a1b2c3", fresh() as never);
  await writeInstance("default", silent() as never);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const t = captureTelegram();
  try {
    const body = await bodyOf(await check(
      new Request(`https://exemplu.ro/api/sentinel/check?key=${CHECK_KEY}`),
    ));
    assert.equal(t.sent.length, 0, "a sunat pentru o identitate retrasă");
    assert.equal(body.ok, true, "identitatea retrasă a ținut verificarea pe roșu");
    assert.deepEqual(body.instances.map((i) => i.id), ["a1b2c3"]);
  } finally { t.restore(); }
});

// ---------------------------------------------------------------------------
// 2. Fișierul rămas pe disc

test("fișierul rămas al unei identități retrase nu o învie și nu ajunge „ilizibil\"", async () => {
  // Registrul singur NU e de-ajuns: fișierele se identifică singure, iar un
  // fișier care spune „sunt `vechi1`" ar readuce instanța pe ușa cealaltă — cu
  // semnalul lui vechi, deci `silent`, deci exact alarma de retras.
  //
  // A doua jumătate, fișierul stricat: `unreadable` e ROȘU și nu se poate opri
  // decât ștergând fișierul de pe gazdă. Un fișier abandonat dinadins nu e o
  // defecțiune a martorului.
  await removeState();
  configureInstances(["a1b2c3", "vechi1", "vechi2"]);
  await writeInstance("a1b2c3", fresh() as never);
  await writeInstance("vechi1", silent() as never);
  await writeRawInstance("vechi2", "}}stricata{{");

  setEnv({ SENTINEL_RETIRED_INSTANCES: "vechi1;vechi2" });

  const log = captureLog();
  let state: Awaited<ReturnType<typeof readAll>>;
  try {
    state = await readAll();
  } finally { log.restore(); }

  assert.deepEqual(Object.keys(state.instances), ["a1b2c3"],
    "un fișier rămas a înviat o identitate retrasă");
  assert.deepEqual(state.unreadable, [],
    "o identitate retrasă a fost raportată ilizibilă, adică roșu");

  // Se raportează ca fișiere ignorate — numărul, niciodată numele.
  const ignorate = log.lines.filter((l) => l.join(" ").includes("ignorate"));
  assert.equal(ignorate.length, 1, "nu s-a spus nimic despre fișierele rămase");
  assert.match(ignorate[0].join(" "), /\b2\b/, "avertismentul nu spune CÂTE fișiere");
  for (const line of log.lines) {
    assert.ok(!line.join(" ").includes("vechi1"),
      `jurnalul a scris un nume de fișier: ${line.join(" ")}`);
  }
});

test("un semnal de la o instanță vie nu e atins de retragerea alteia", async () => {
  // Podeaua: dacă retragerea ar lovi mai larg decât identitatea numită, ar tăcea
  // servere pe care nu le-a retras nimeni — și tăcerea aia nu ar mai alarma,
  // fiindcă instanțele nu ar mai fi în registru.
  await removeState();
  configureInstances(["a1b2c3", "d4e5f6"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "d4e5f6" });

  assert.equal((await beat(await send("a1b2c3"))).status, 200);
  assert.deepEqual(Object.keys((await readAll()).instances), ["a1b2c3"]);
});

// ---------------------------------------------------------------------------
// 3. Revocarea

test("cheia moștenită a unei identități retrase nu mai autentifică", async () => {
  // Retragerea e revocare. Altfel cine deține cheia unui server dezafectat
  // păstrează o intrare validă la martor, iar starea scrisă de el n-ar mai fi
  // citită de nimeni. Cazul contează dublu aici: `SENTINEL_BEACON_SECRET` nu se
  // poate șterge din panoul găzduirii, deci fără revocare cheia asta ar rămâne
  // bună pentru totdeauna.
  await removeState();
  configureInstances(["default"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const w = captureWarn();
  let res: Response;
  try {
    res = await beat(await beatRequest({ payload: beatPayload({ seq: 9 }) }));
  } finally { w.restore(); }

  assert.equal(res.status, 401, "o identitate retrasă a fost autentificată");
  assert.deepEqual((await readAll()).instances, {},
    "semnalul unei identități retrase a fost înregistrat");
});

test("nici rezerva din fișierul de bază nu mai dă starea unei identități retrase", async () => {
  // `readInstance` are două căi: fișierul propriu al instanței și rezerva
  // migrată din fișierul de bază (forma veche, cea care e chiar acum în
  // producție). Regula din `fileBelongsTo` o închide pe prima. Fără verificarea
  // de la intrare, a doua ar rămâne deschisă, iar o identitate retrasă ar primi
  // înapoi starea de dinainte — inclusiv `seq`, adică fix valoarea care decide
  // dacă semnalul următor e o reluare.
  await removeState();
  configureInstances(["default"]);
  await writeRawState(JSON.stringify(silent()));

  // Podeaua: fără retragere, rezerva CHIAR se citește. Altfel testul de dedesubt
  // ar trece și pe o cale care nu întoarce nimic oricum.
  assert.notEqual(await readInstance("default"), undefined,
    "rezerva din fișierul de bază nu se citea nici înainte de retragere");

  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });
  assert.equal(await readInstance("default"), undefined,
    "starea unei identități retrase s-a citit din fișierul de bază");
});

test("o identitate rămâne retrasă chiar dacă are cheie în hartă", async () => {
  // Contradicția pe care o poate scrie operatorul: aceeași identitate ȘI cu
  // cheie, ȘI retrasă. Câștigă retragerea. „Cheia câștigă" ar face mecanismul
  // inutil exact în cazul obișnuit — un server dezafectat care își avea propria
  // cheie — fiindcă retragerea ar cere și editarea unei a doua valori. `broken`
  // ar însemna 500 pentru TOATE serverele sănătoase din cauza unei propoziții
  // despre unul mort.
  await removeState();
  configureInstances(["a1b2c3", "d4e5f6"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "d4e5f6" });

  const w = captureWarn();
  let res: Response;
  try {
    res = await beat(await send("d4e5f6"));
  } finally { w.restore(); }

  assert.equal(res.status, 401, "cheia din hartă a bătut retragerea");
  assert.deepEqual(configuredInstanceIds(), ["a1b2c3"],
    "identitatea cu cheie a rămas în registru după retragere");
});

/** Tot ce s-a scris în ambele fluxuri, ca un singur text. */
function textul(...capturi: { lines: string[][] }[]): string {
  return capturi.flatMap((c) => c.lines.map((l) => l.join(" "))).join("\n");
}

/**
 * Trimite fără cheie și fără semnătură validă, doar cu antetul.
 *
 * Adică exact ce poate produce oricine de pe internet: ruta e publică și nu cere
 * nimic ca să întrebe.
 */
function zgomot(instance: string): Promise<Request> {
  return beatRequest({ instance, raw: "nici măcar json", signature: "00" });
}

test("urma din jurnal se scrie doar pentru un semnal SEMNAT, nu pentru orice antet", async () => {
  // Eșecul pe care îl previne, în forma exactă din CLAUDE.md — o regulă care nu
  // poate deosebi „nu s-a întâmplat nimic" de „n-am putut să mă uit":
  //
  // O identitate retrasă din GREȘEALĂ tace fără să alarmeze, fiindcă martorul nu
  // o mai așteaptă. Documentația declară linia asta de jurnal SINGURA urmă că
  // mașina e de fapt vie. Cu retragerea verificată înaintea semnăturii, aceeași
  // linie o producea orice scanner care nimerea antetul — deci operatorul nu
  // putea deosebi „serverul meu viu încă bate sub identitatea asta" de zgomot de
  // pe internet, și ar fi trebuit să ignore singurul semnal pe care îl are.
  //
  // Mecanismul are dovada în mână: un beat semnat corect nu poate veni decât de
  // la deținătorul cheii. Deci semnătura se verifică ÎNAINTEA refuzului, iar
  // linia rămâne doar pentru cazul care înseamnă ceva.
  await removeState();
  configureInstances(["a1b2c3", "d4e5f6"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "d4e5f6" });

  // (1) Semnat corect cu cheia identității retrase: un fapt care cere un om.
  const eSemnat = { warn: captureWarn(), err: captureLog() };
  let semnat: Response;
  try {
    semnat = await beat(await send("d4e5f6"));
  } finally { eSemnat.err.restore(); eSemnat.warn.restore(); }

  assert.equal(semnat.status, 401, "o identitate retrasă a fost autentificată");
  assert.match(textul(eSemnat.err), /retras/,
    "un semnal SEMNAT de la o identitate retrasă nu a lăsat nicio urmă");
  // Nivelul urmează cine poate produce linia: asta nu se poate produce fără
  // cheie, deci e o eroare, nu un avertisment provocabil de oricine.
  assert.doesNotMatch(textul(eSemnat.warn), /retras/,
    "faptul a ajuns pe fluxul de avertismente, unde îl îneacă refuzurile obișnuite");

  // (2) Aceeași identitate, fără cheie și fără semnătură — adică zgomot.
  const eZgomot = { warn: captureWarn(), err: captureLog() };
  let zgomotos: Response;
  try {
    zgomotos = await beat(await zgomot("d4e5f6"));
  } finally { eZgomot.err.restore(); eZgomot.warn.restore(); }

  assert.equal(zgomotos.status, 401, "zgomotul a primit alt cod decât un refuz");
  assert.doesNotMatch(textul(eZgomot.err, eZgomot.warn), /retras/,
    "o cerere pe care o poate trimite oricine a produs «urma» unei retrageri");
});

test("refuzul unei identități retrase are ACELAȘI cod și corp, și e mărginit la fel", async () => {
  // Codul HTTP e deliberat sărac: un 410 „Gone" ar spune unui necunoscut că
  // identificatorul a existat cândva AICI — aceeași scurgere pentru care o
  // instanță necunoscută primește 401, nu 404.
  //
  // Titlul spune exact ce asertează testul, și a fost rescris de două ori ca să
  // ajungă acolo. O rundă a promis „cod, corp și cale" — fals: drumul
  // identității necunoscute se întoarce înaintea lui `signatureValid`, deci sare
  // peste HMAC, iar reziduul măsurat e ~10 µs pe un corp de 8000 de octeți.
  // Înainte de `MAX_BODY_BYTES` diferența era 19,0 ms față de 0,2 ms pe un corp
  // de 16 MiB, deci plafonul a redus-o de ~1900× și a coborât-o cu trei ordine de
  // mărime sub jitterul de rețea. Nedistinse din afară, da; aceeași cale, nu.
  //
  // Ce se asertează mai jos e ce se poate asserta stabil: codul, corpul, și
  // faptul că amândouă trec prin plafon. Un nume care promite mai mult decât
  // asertează e felul în care cineva crede că o proprietate e păzită când nu e.
  await removeState();
  configureInstances(["a1b2c3", "d4e5f6"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "d4e5f6" });

  const wRetras = { warn: captureWarn(), err: captureLog() };
  let retras: Response;
  try {
    retras = await beat(await send("d4e5f6"));
  } finally { wRetras.err.restore(); wRetras.warn.restore(); }

  const wNecunoscut = { warn: captureWarn(), err: captureLog() };
  let necunoscut: Response;
  try {
    necunoscut = await beat(await send("z9y8x7", keyFor("z9y8x7")));
  } finally { wNecunoscut.err.restore(); wNecunoscut.warn.restore(); }

  assert.equal(retras.status, necunoscut.status, "retrasul a primit alt cod HTTP");
  assert.equal(retras.status, 401);
  assert.deepEqual(await bodyOf(retras), await bodyOf(necunoscut),
    "corpul răspunsului deosebește o identitate retrasă de una necunoscută");

  // Calea. Un corp peste plafon trebuie să dea ACELAȘI 413 în ambele cazuri:
  // dacă identitatea necunoscută ar fi refuzată înaintea citirii, ea ar primi
  // 401 iar cea retrasă 413, adică un oracol de existență pe codul de stare —
  // mai curat și mai ieftin decât deosebirea în timp pe care plafonul o repară.
  const urias = "x".repeat(1024 * 1024);
  const cap = { warn: captureWarn(), err: captureLog() };
  let retrasMare: Response;
  let necunoscutMare: Response;
  try {
    retrasMare = await beat(await beatRequest({ instance: "d4e5f6", raw: urias }));
    necunoscutMare = await beat(await beatRequest({ instance: "z9y8x7", raw: urias }));
  } finally { cap.err.restore(); cap.warn.restore(); }

  assert.equal(retrasMare.status, 413, "corpul uriaș al unei identități retrase nu a fost mărginit");
  assert.equal(necunoscutMare.status, retrasMare.status,
    "identitatea necunoscută a fost refuzată pe altă cale decât cea retrasă");
  assert.deepEqual(await bodyOf(retrasMare), await bodyOf(necunoscutMare),
    "corpul refuzului de dimensiune deosebește cele două identități");

  assert.doesNotMatch(textul(wNecunoscut.err, wNecunoscut.warn), /retras/,
    "o instanță necunoscută e raportată ca retrasă");
  // Și fără identificator: valoarea vine din antetul cererii, adică e text ales
  // de cine trimite, iar jurnalul martorului nu e locul lui.
  assert.doesNotMatch(textul(wRetras.err, wRetras.warn), /d4e5f6/,
    "jurnalul a scris identificatorul din antet");
});

test("o identitate retrasă căreia i s-a scos și cheia e tratată ca necunoscută", async () => {
  // Fără cheie nu se poate dovedi nimic despre expeditor, niciodată. A scrie
  // atunci „semnal de la o identitate retrasă" ar readuce exact problema
  // reparată mai sus: o afirmație pe care o poate provoca oricine, într-un
  // jurnal în care ea trebuie să însemne „mașina aia e vie".
  await removeState();
  configureInstances(["a1b2c3"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "d4e5f6" });

  const cap = { warn: captureWarn(), err: captureLog() };
  let res: Response;
  try {
    res = await beat(await send("d4e5f6", keyFor("d4e5f6")));
  } finally { cap.err.restore(); cap.warn.restore(); }

  assert.equal(res.status, 401);
  assert.doesNotMatch(textul(cap.err, cap.warn), /retras/,
    "s-a afirmat un fapt care nu se poate dovedi");
  assert.match(textul(cap.warn), /necunoscut/,
    "refuzul nu a lăsat nicio urmă");
});

// ---------------------------------------------------------------------------
// 4. `?instance=<retrasă>`

test("`?instance=<retrasă>` întoarce 503 `unknown`, nu verde și nu un nume propriu", async () => {
  // Verde nu e o opțiune: cine întreabă despre un id anume a declarat că se
  // așteaptă să existe. Un nume propriu (`retired`) nu e nici el: ruta e publică
  // și nu cere nimic ca să întrebe, deci ar confirma gratuit că identificatorul
  // a existat cândva aici. „Necunoscută" e adevărat — după retragere, martorul
  // chiar nu mai știe de ea.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  await writeInstance("a1b2c3", fresh() as never);
  await writeInstance("default", silent() as never);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const res = await get("?instance=default");
  assert.equal(res.status, 503, "o identitate retrasă a ieșit verde la întrebare directă");
  const body = await bodyOf(res);
  assert.equal(body.status, "unknown");
  assert.equal(body.last_seen, null, "s-a întors ultimul semnal al unei identități retrase");
});

// ---------------------------------------------------------------------------
// 5. Ce NU are voie să se schimbe

test("o cheie ȘTEARSĂ nu e o retragere: serverul rămâne membru, tace și alarmează", async () => {
  // Proprietatea din E1.2, cu mecanismul de retragere pornit lângă ea. Cele două
  // nu au voie să se confunde: retragerea e o declarație deliberată care numește
  // identitatea, ștergerea unei chei e un accident — o virgulă greșită într-un
  // formular web. Dacă a doua ar tăcea, un server monitorizat ar dispărea de pe
  // toate suprafețele exact ca în pana pentru care există martorul.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  await writeInstance("aaa111", fresh() as never);
  await writeInstance("bbb222", silent() as never);

  // Cheia lui `bbb222` dispare, iar lista de retrase vorbește despre ALTCINEVA.
  configureInstances(["aaa111"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "vechi-server-2" });

  const res = await get();
  assert.equal(res.status, 503, "un server viu fără cheie a dispărut, iar ruta a spus ok");
  const body = await bodyOf(res);
  assert.equal(body.status, "silent");
  assert.deepEqual(body.instances.map((i) => i.instance),
    ["aaa111", "bbb222"]);
});

test("`default` retrasă prea devreme ascunde un server viu — și lasă urma care o spune", async () => {
  // Costul documentat al mecanismului, fixat aici ca să nu poată fi nici uitat,
  // nici schimbat tăcut. NU e o proprietate dorită: e prețul unei declarații
  // deliberate, iar apărarea e precondiția din README și din docs/DEPLOYMENT.md
  // §7 — nu retrage o identitate sub care mai bate cineva.
  //
  // `default` e cazul cel mai expus fiindcă e găleata comună a fiecărui server
  // care nu trimite încă antetul. Retrasă cât timp unul dintre ele mai trimite,
  // serverul ăla dispare de pe toate suprafețele și martorul răspunde „ok".
  //
  // Ce SALVEAZĂ situația e ordinea reparată la pasul 3 din `beat/route.ts`:
  // semnalul vechi e semnat corect, deci refuzul lui e un FAPT, scris pe fluxul
  // de erori la fiecare bătaie. Aia e singura urmă, și de-aia trebuie să
  // însemne ceva.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  await writeInstance("a1b2c3", fresh() as never);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const err = captureLog();
  let vechi: Response;
  try {
    // Serverul neactualizat: fără antet, fără `instance_id`, semnat cu cheia
    // moștenită. Exact ce trimite o gazdă care n-a trecut încă pe identități.
    vechi = await beat(await beatRequest({ payload: beatPayload({ seq: 11 }) }));
  } finally { err.restore(); }

  assert.equal(vechi.status, 401, "un semnal semnat corect a fost totuși înregistrat");

  // Invizibil peste tot — costul.
  const body = await bodyOf(await get());
  assert.deepEqual(body.instances.map((i) => i.instance), ["a1b2c3"]);
  assert.equal(body.status, "ok",
    "starea agregată s-a schimbat: testul nu mai descrie costul pe care îl fixează");

  // Dar nu tăcut: fiecare bătaie a serverului viu lasă faptul în jurnal.
  assert.match(textul(err), /retras/,
    "un server viu ascuns de o retragere greșită nu a lăsat nicio urmă");
});

// ---------------------------------------------------------------------------
// Formatul valorii

test("lista de retrase acceptă `,`, `;` și linie nouă, ca și perechile de chei", async () => {
  // Cu `split(",")` singur, o listă scrisă cu `;` sau cu linie nouă ar retrage
  // DOAR prima identitate. Celelalte ar continua să alarmeze la fiecare patru
  // ore, cu o valoare care în panou arată exact ca cea cerută — adică ore de
  // căutat cauza în partea greșită.
  await removeState();
  configureInstances(["a1b2c3", "v1", "v2", "v3"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: " v1, v2;\nv3 " });

  assert.deepEqual(configuredInstanceIds(), ["a1b2c3"],
    "un separator nu a fost recunoscut, deci o identitate a rămas în registru");
});

test("intrările nevalide se numără în jurnal, niciodată ca valoare", async () => {
  // Aceeași regulă ca la chei: un mesaj care conține fragmentul stricat conține
  // ce a scris operatorul în câmp, iar jurnalul găzduirii e o suprafață pe care
  // o citește și panoul. Numărul spune că s-a pierdut ceva; ce anume, nu.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  await writeInstance("a1b2c3", fresh() as never);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "id nevalid,default" });

  const log = captureLog();
  let body: { instances: { instance: string }[] };
  try {
    body = await bodyOf<{ instances: { instance: string }[] }>(await get());
  } finally { log.restore(); }

  // Intrarea bună retrage; cea stricată nu retrage nimic și nu strică restul.
  assert.deepEqual(body.instances.map((i) => i.instance), ["a1b2c3"]);

  const linii = log.lines.filter((l) => l.join(" ").includes("SENTINEL_RETIRED_INSTANCES"));
  assert.ok(linii.length >= 1, "intrarea nevalidă nu a lăsat nicio urmă în jurnal");
  assert.match(linii[0].join(" "), /\b1\b/, "avertismentul nu spune CÂTE intrări");
  for (const line of log.lines) {
    assert.ok(!line.join(" ").includes("nevalid"),
      `jurnalul a scris valoarea intrării: ${line.join(" ")}`);
  }
});

test("o listă de retrase din care nu iese nimic nu retrage nimic și NU oprește martorul", async () => {
  // Asimetria față de `SENTINEL_INSTANCE_SECRETS` e deliberată. Acolo, o valoare
  // nevidă din care nu iese nicio pereche e `broken` → 500, fiindcă eșecul ei e
  // TĂCUT: 401 la fiecare bătaie, pe o valoare care în panou arată corectă.
  //
  // Aici eșecul e zgomotos prin construcție — nu se retrage nimic, deci
  // identitatea rămâne membră și continuă să alarmeze, exact ce vedea operatorul
  // înainte să scrie variabila. Un 500 ar opri în schimb înregistrarea
  // semnalelor pentru TOATE serverele sănătoase din cauza unei propoziții despre
  // unul mort.
  await removeState();
  configureInstances(["a1b2c3", "default"]);
  setEnv({ SENTINEL_RETIRED_INSTANCES: "-nu e un id" });

  const log = captureLog();
  let res: Response;
  try {
    res = await beat(await send("a1b2c3"));
  } finally { log.restore(); }

  assert.equal(res.status, 200, "o listă de retrase stricată a oprit un server sănătos");
  assert.deepEqual(configuredInstanceIds(), ["a1b2c3", "default"],
    "o listă din care nu iese nicio identitate a retras ceva");
});
