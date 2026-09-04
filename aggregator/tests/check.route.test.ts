/**
 * Ruta care întreabă „a tăcut?" și trimite alerta.
 *
 * Trei eșecuri, toate întâlnite în producție undeva:
 *
 * 1. **Ruta deschisă.** Cine o poate declanșa poate consuma starea de „am
 *    alertat deja" și te lasă fără a doua alertă. De-aia are secret propriu.
 * 2. **Alerta repetată la fiecare rundă de cron.** La 5 minute interval, o
 *    tăcere de o oră ar însemna 12 mesaje identice; a treia oară operatorul
 *    oprește notificările, iar a patra e cea adevărată.
 * 3. **Alerta marcată ca trimisă fără să fi plecat.** Dacă API-ul Telegram e
 *    picat exact atunci, iar noi scriem oricum „am alertat", singura alertă s-a
 *    consumat în gol. Asta e chiar tiparul din CLAUDE.md: codul de ieșire al
 *    intenției, nu faptul.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  baseEnv, beatPayload, beatRequest, bodyOf, captureLog, captureTelegram,
  configureInstances, keyFor, removeState, setEnv, writeRawInstance,
  CHECK_KEY, STATE_FILE,
} from "./witness-harness";
import { GET } from "@/app/api/sentinel/check/route";
import { POST } from "@/app/api/sentinel/beat/route";
import { readAll, writeInstance } from "@/lib/store";

beforeEach(async () => {
  baseEnv();
  await removeState();
});

afterEach(async () => {
  await removeState();
});

function req(key?: string): Request {
  const url = key === undefined
    ? "https://exemplu.ro/api/sentinel/check"
    : `https://exemplu.ro/api/sentinel/check?key=${encodeURIComponent(key)}`;
  return new Request(url);
}

/** Un semnal vechi de o oră: peste orice prag de tăcere. */
function silentState(over: Record<string, unknown> = {}) {
  const oldIso = new Date(Date.now() - 3600 * 1000).toISOString();
  return {
    last: {
      seq: 12, sent_at: oldIso, received_at: oldIso,
      last_event_id: 100, detect_cursor: 90, incidents_open: 3, blocklist_size: 7,
      audit_head: "a".repeat(64), interval_s: 60,
      selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: oldIso },
    },
    counters_moved_at: oldIso,
    ...over,
  };
}

function freshState(over: Record<string, unknown> = {}) {
  const nowIso = new Date().toISOString();
  return {
    last: {
      seq: 13, sent_at: nowIso, received_at: nowIso,
      last_event_id: 100, detect_cursor: 90, incidents_open: 0, blocklist_size: 0,
      audit_head: "a".repeat(64), interval_s: 60,
      selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: nowIso },
    },
    counters_moved_at: nowIso,
    ...over,
  };
}

async function seed(instances: Record<string, Record<string, unknown>>): Promise<void> {
  await removeState();
  // Cheile ÎNTÂI: o instanță fără cheie configurată nu există.
  configureInstances(Object.keys(instances));
  for (const [id, state] of Object.entries(instances)) {
    await writeInstance(id, state as never);
  }
}

/** Ce s-a raportat pentru o instanță anume. */
function reportFor(body: Record<string, unknown>, id = "default") {
  const list = (body.instances ?? []) as { id: string; kind: unknown; alerted: unknown }[];
  return list.find((i) => i.id === id);
}

// ---------------------------------------------------------------------------

test("fără cheie, ruta refuză cu 401 și nu citește starea", async () => {
  const t = captureTelegram();
  try {
    assert.equal((await GET(req())).status, 401);
    assert.equal((await GET(req("gresit"))).status, 401);
    assert.equal(t.sent.length, 0);
  } finally { t.restore(); }
});

test("cu `SENTINEL_CHECK_SECRET` nesetat, ruta refuză — nu se deschide singură", async () => {
  // Eșecul pe care îl previne: o comparație care tratează „nesetat" ca
  // „potrivit cu orice" ar face ruta publică exact pe instalările neterminate.
  setEnv({ SENTINEL_CHECK_SECRET: undefined });
  assert.equal((await GET(req(""))).status, 401);
  assert.equal((await GET(req("orice"))).status, 401);
});

test("tăcerea produce o alertă pe Telegram", async () => {
  await seed({ default: silentState() });
  const t = captureTelegram();
  try {
    const res = await GET(req(CHECK_KEY));
    assert.equal(res.status, 200);
    const body = await bodyOf(res);
    assert.equal(body.ok, false);
    assert.equal(reportFor(body)?.kind, "silent");
    assert.equal(t.sent.length, 1, "nu a plecat nicio alertă");
    assert.match(t.sent[0].text, /MARTOR EXTERN/, "lipsește prefixul care o deosebește de Sentinel");
    assert.match(t.sent[0].text, /Niciun semnal/);
  } finally { t.restore(); }
});

test("a doua verificare nu repetă alerta", async () => {
  await seed({ default: silentState() });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    const res = await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1, "alerta s-a repetat la a doua rundă de cron");
    assert.equal(reportFor(await bodyOf(res))?.alerted, false);
  } finally { t.restore(); }
});

test("dacă Telegram refuză, starea NU e marcată ca alertată", async () => {
  await seed({ default: silentState() });
  const failing = captureTelegram({ ok: false });
  try {
    await GET(req(CHECK_KEY));
    assert.equal(failing.sent.length, 1);
  } finally { failing.restore(); }

  // A doua rundă trebuie să reîncerce: altfel singura alertă s-a consumat
  // într-un API picat.
  const working = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(working.sent.length, 1, "alerta nu a fost reîncercată după eșecul Telegram");
  } finally { working.restore(); }
});

test("revenirea închide alerta și o anunță", async () => {
  // O alertă care nu se închide niciodată lasă operatorul să se întrebe dacă
  // s-a rezolvat, iar peste o săptămână nu se mai uită la niciuna.
  await seed({ default: freshState({ alerted: { kind: "silent", at: new Date(Date.now() - 60000).toISOString() } }) });
  const t = captureTelegram();
  try {
    const res = await GET(req(CHECK_KEY));
    const body = await bodyOf(res);
    assert.equal(body.ok, true);
    assert.equal(t.sent.length, 1);
    assert.match(t.sent[0].text, /revenit/i);
  } finally { t.restore(); }

  // Și nu se mai repetă la runda următoare.
  const t2 = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t2.sent.length, 0, "mesajul de revenire s-a repetat");
  } finally { t2.restore(); }
});

test("fără nicio instanță configurată, verificarea nu alertează și NU spune „e bine\"", async () => {
  // Două lucruri diferite, amândouă obligatorii: un martor instalat înaintea
  // expeditorilor n-are voie să sune, dar nici n-are voie să publice `ok: true`
  // despre un registru gol. Prima e politețe, a doua ar fi aceeași minciună
  // reparată în ruta vecină.
  await removeState();
  configureInstances([]);
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0, "a alertat pe un martor abia instalat");
    assert.equal(body.ok, false, "a publicat „e în regulă\" despre un registru gol");
    assert.deepEqual(body.instances, []);
  } finally { t.restore(); }
  assert.equal(STATE_FILE.length > 0, true);
});

test("o instanță configurată care n-a trimis niciodată e raportată, dar NU alertată", async () => {
  await removeState();
  configureInstances(["aaa111"]);
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0, "a sunat pentru un expeditor care nu a pornit încă");
    assert.equal(body.ok, false);
    assert.equal(reportFor(body, "aaa111")?.kind, "no-beat");
  } finally { t.restore(); }
});

test("o copie de siguranță pusă lângă stare nu produce nicio alertă", async () => {
  // Fișierul are un semnal vechi de o oră, deci ar fi fost „silent", critic, pe
  // Telegram — despre o mașină care nu există. Repetat la fiecare patru ore.
  await seed({ a1b2c3: freshState() });
  await writeRawInstance("backup-2026-08-12", JSON.stringify(silentState()));
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0, "a alertat despre o copie de fișier");
    assert.equal(body.ok, true);
    assert.deepEqual(body.instances.map((i) => i.id), ["a1b2c3"]);
  } finally { t.restore(); }
});

// ---------------------------------------------------------------------------
// Mai multe instanțe

test("alerta numește instanța care a tăcut", async () => {
  // Eșecul pe care îl previne: „Sentinel nu răspunde" pe un panou cu cinci
  // servere te trimite să le verifici pe toate, la 3 dimineața.
  await seed({
    a1b2c3: silentState({ last: { ...silentState().last, label: "web-public" } }),
    d4e5f6: freshState(),
  });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1, "s-a alertat pentru altceva decât instanța tăcută");
    assert.match(t.sent[0].text, /web-public/);
    assert.match(t.sent[0].text, /a1b2c3/);
    assert.doesNotMatch(t.sent[0].text, /d4e5f6/);
  } finally { t.restore(); }
});

test("o instanță tăcută nu blochează alerta pentru a doua care cade după ea", async () => {
  // Cu o singură stare `alerted`, a doua cădere ar fi fost înghițită ca
  // duplicat, iar al doilea server ar fi murit fără ca nimeni să afle.
  await seed({ a1b2c3: silentState(), d4e5f6: freshState() });
  const first = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(first.sent.length, 1);
  } finally { first.restore(); }

  await seed({
    a1b2c3: { ...silentState(), alerted: { kind: "silent", at: new Date().toISOString() } },
    d4e5f6: silentState(),
  });
  const second = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(second.sent.length, 1, "a doua instanță căzută nu a produs alertă");
    assert.match(second.sent[0].text, /d4e5f6/);
    assert.equal(reportFor(body, "a1b2c3")?.alerted, false);
    assert.equal(reportFor(body, "d4e5f6")?.alerted, true);
  } finally { second.restore(); }
});

test("revenirea unei instanțe nu șterge alerta alteia", async () => {
  const alerted = { kind: "silent", at: new Date(Date.now() - 60000).toISOString() };
  await seed({
    a1b2c3: silentState({ alerted }),
    d4e5f6: freshState({ alerted }),
  });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    // Un singur mesaj: revenirea lui B. A e deja alertat și încă tace.
    assert.equal(t.sent.length, 1);
    assert.match(t.sent[0].text, /revenit/i);
    assert.match(t.sent[0].text, /d4e5f6/);
  } finally { t.restore(); }
  // Iar starea lui A a rămas alertată, deci nu se retrimite.
  const t2 = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t2.sent.length, 0);
  } finally { t2.restore(); }
});

test("o etichetă cu marcaj HTML nu strică mesajul — altfel Telegram îl refuză", async () => {
  // Nu e cosmetică: Telegram respinge tot mesajul dacă marcajul e stricat, deci
  // un `<` într-o etichetă oprește ALERTA, nu doar afișarea. Eticheta vine
  // dintr-un payload semnat pe o mașină care poate fi compromisă.
  const base = silentState();
  await seed({
    a1b2c3: { ...base, last: { ...base.last, label: "<b>fals</b> & <i>x" } },
  });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1);
    assert.doesNotMatch(t.sent[0].text.split("\n\n").slice(1).join("\n\n"), /<b>fals<\/b>/);
    assert.match(t.sent[0].text, /&lt;b&gt;fals&lt;\/b&gt; &amp; &lt;i&gt;x/);
  } finally { t.restore(); }
});

test("un semnal sosit ÎN TIMPUL verificării nu se pierde", async () => {
  // Interleaving determinist: verificarea citește starea, apoi așteaptă apelul
  // către Telegram. Trimitem semnalul chiar din interiorul acelui apel, deci
  // ajunge fix între citirea și scrierea rutei de verificare.
  //
  // Fără recitire înainte de scriere, semnalul acela ar fi rescris cu starea
  // veche: instanța ar rămâne „tăcută" încă o rundă de cron, deși tocmai a dat
  // semn de viață.
  await seed({ a1b2c3: silentState() });

  const sent: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: { body?: string }) => {
    sent.push(String(JSON.parse(String(init?.body ?? "{}")).text ?? ""));
    // Semnalul sosește ACUM, cât timp verificarea e blocată aici.
    const res = await POST(await beatRequest({
      instance: "a1b2c3",
      key: keyFor("a1b2c3"),
      payload: beatPayload({ instance_id: "a1b2c3", seq: 99, last_event_id: 5000 }),
    }));
    assert.equal(res.status, 200, "semnalul din timpul verificării a fost refuzat");
    void input;
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof globalThis.fetch;

  try {
    await GET(req(CHECK_KEY));
  } finally {
    globalThis.fetch = original;
  }

  assert.equal(sent.length, 1, "verificarea nu a alertat, deci testul nu a interleaved nimic");
  const after = (await readAll()).instances.a1b2c3;
  assert.equal(after?.last?.seq, 99, "semnalul sosit în timpul verificării s-a pierdut");
  assert.equal(after?.alerted?.kind, "silent", "starea de alertare nu a fost scrisă");
});

test("o instanță ilizibilă e raportată, dar NU alertată", async () => {
  // Raportată, fiindcă „n-am putut să mă uit" nu e „e în regulă". Nealertată,
  // fiindcă starea de dedublare stă chiar în fișierul pe care nu-l pot citi:
  // o alertă de aici ar pleca la fiecare rundă de cron, la nesfârșit, iar o
  // alarmă care nu se oprește e o alarmă pe care operatorul o oprește.
  await seed({ a1b2c3: freshState(), bbb222: freshState() });
  await writeRawInstance("bbb222", "}}stricata{{");
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0, "a alertat pentru o stare pe care nu o poate citi");
    assert.equal(body.ok, false, "o instanță ilizibilă a fost raportată ca fiind în regulă");
    assert.equal(reportFor(body, "bbb222")?.kind, "unreadable");
  } finally { t.restore(); }
});

test("un server viu căruia i se șterge cheia AJUNGE să alerteze", async () => {
  // Proprietatea numărul unu, cap-coadă. Cu apartenența derivată doar din chei,
  // ștergerea unei chei ștergea serverul de pe toate suprafețele: verde peste
  // tot, zero mesaje, iar singura urmă era o linie de jurnal cu un număr.
  //
  // Serverul e viu și tăcut de o oră, apoi îi dispare cheia. Trebuie să sune.
  await seed({ aaa111: silentState(), bbb222: freshState() });
  configureInstances(["bbb222"]);

  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 1, "un server viu fără cheie nu a produs nicio alertă");
    assert.match(t.sent[0].text, /aaa111/);
    assert.equal(reportFor(body, "aaa111")?.kind, "silent");
    assert.equal(body.ok, false);
  } finally { t.restore(); }
});

test("o hartă de chei stricată nu face martorul să tacă despre nimeni", async () => {
  // Forma probabilă: o virgulă în plus într-un JSON editat într-un formular web.
  // Toate instanțele mapate își pierd cheia deodată, iar semnalele lor primesc
  // 500. Dacă ar dispărea și din registru, martorul ar raporta „ok" despre trei
  // servere refuzate.
  await seed({ aaa111: silentState(), bbb222: silentState() });
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{nu-e json", SENTINEL_BEACON_SECRET: undefined });

  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 2, "nu s-a alertat pentru ambele servere rămase fără cheie");
    assert.deepEqual(body.instances.map((i) => [i.id, i.kind]),
      [["aaa111", "silent"], ["bbb222", "silent"]]);
  } finally { t.restore(); }
});

test("o instanță care n-a trimis niciodată nu face răspunsul roșu", async () => {
  // `SENTINEL_BEACON_SECRET` e permanent, deci `default` rămâne în registru
  // pentru totdeauna; din clipa în care fiecare server își trimite propriul
  // `instance_id`, ea nu mai primește niciodată nimic. Dacă ar fi numărată,
  // `ok` ar fi fals la nesfârșit pe o instalare perfect sănătoasă.
  await seed({ aaa111: freshState(), bbb222: freshState() });
  configureInstances(["aaa111", "bbb222", "default"]);

  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(body.ok, true, "o instanță care n-a trimis niciodată a înroșit răspunsul");
    assert.equal(reportFor(body, "default")?.kind, "no-beat", "`default` a dispărut din raport");
    assert.equal(t.sent.length, 0);
  } finally { t.restore(); }
});

test("`recorded` spune dacă scrierea de dedublare chiar s-a făcut", async () => {
  // Mesajul pleacă, apoi fișierul devine necitibil, deci scrierea e refuzată.
  // A raporta o scriere care nu s-a întâmplat ca și cum s-ar fi întâmplat e
  // chiar tiparul după care e numit depozitul ăsta.
  await seed({ aaa111: silentState() });

  const original = globalThis.fetch;
  globalThis.fetch = (async () => {
    // Fișierul se strică exact între trimiterea mesajului și scrierea stării.
    await writeRawInstance("aaa111", "}}stricata{{");
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof globalThis.fetch;
  let body: { instances: { id: string; alerted: boolean; recorded: boolean }[] };
  try {
    body = await bodyOf<{ instances: { id: string; alerted: boolean; recorded: boolean }[] }>(
      await GET(req(CHECK_KEY)));
  } finally {
    globalThis.fetch = original;
  }

  const r = body.instances.find((i) => i.id === "aaa111");
  assert.equal(r?.alerted, true, "mesajul a plecat, deci `alerted` trebuie să fie adevărat");
  assert.equal(r?.recorded, false, "a raportat o scriere care a fost refuzată");
});

test("`alerted` e adevărat doar dacă mesajul chiar a plecat", async () => {
  await seed({ aaa111: silentState() });
  const t = captureTelegram({ ok: false });
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 1);
    assert.equal(reportFor(body, "aaa111")?.alerted, false,
      "Telegram a refuzat mesajul, dar raportul spune că s-a alertat");
  } finally { t.restore(); }
});

test("avertismentul despre fișiere străine apare, și nu conține numele lor", async () => {
  // E singura urmă pe care o lasă o copie pusă lângă stare. Regula „numărul, nu
  // numele" e deliberată: numele e ales de cine a pus fișierul acolo, iar
  // jurnalul martorului nu e locul în care să ajungă text ales de altcineva.
  await seed({ aaa111: freshState() });
  await writeRawInstance("copie-suspecta-2026", JSON.stringify(freshState()));

  const log = captureLog();
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    const relevante = log.lines.filter((l) => l.join(" ").includes("ignorate"));
    assert.equal(relevante.length, 1, "nu s-a scris niciun avertisment despre fișierul străin");
    assert.match(relevante[0].join(" "), /\b1\b/, "avertismentul nu spune câte fișiere");
    assert.doesNotMatch(relevante[0].join(" "), /copie-suspecta-2026/,
      "avertismentul a scris în jurnal un nume de fișier ales de altcineva");
  } finally { t.restore(); log.restore(); }
});

test("avertismentul se repetă când se SCHIMBĂ mulțimea de fișiere străine", async () => {
  // Memorarea există ca să nu scriem o linie la fiecare cerere de la monitor.
  // Dacă ar tăcea și la schimbare, un al doilea fișier apărut mai târziu nu ar
  // lăsa nicio urmă — adică memorarea ar deveni o ascunzătoare.
  await seed({ aaa111: freshState() });
  const t = captureTelegram();
  try {
    await writeRawInstance("copie-unu", JSON.stringify(freshState()));
    let log = captureLog();
    await GET(req(CHECK_KEY));
    await GET(req(CHECK_KEY));
    let n = log.lines.filter((l) => l.join(" ").includes("ignorate")).length;
    log.restore();
    assert.equal(n, 1, "avertismentul s-a repetat la fiecare cerere");

    await writeRawInstance("copie-doi", JSON.stringify(freshState()));
    log = captureLog();
    await GET(req(CHECK_KEY));
    n = log.lines.filter((l) => l.join(" ").includes("ignorate")).length;
    log.restore();
    assert.equal(n, 1, "un fișier străin nou nu a lăsat nicio urmă");
  } finally { t.restore(); }
});

test("toate instanțele sunt raportate, nu doar prima cu probleme", async () => {
  await seed({ a1b2c3: silentState(), d4e5f6: freshState(), z9y8x7: freshState() });
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.deepEqual(body.instances.map((i) => i.id), ["a1b2c3", "d4e5f6", "z9y8x7"]);
    assert.equal(body.ok, false);
  } finally { t.restore(); }
});

// ---------------------------------------------------------------------------
// Alarma rămasă deschisă pe o identitate retrasă
// ---------------------------------------------------------------------------
test("o identitate retrasă CÂT TIMP era în alertă primește mesajul de închidere",
     async () => {
  // Eșecul măsurat pe 19 august 2026, raportat de operator: a primit
  // „🔴 default — silent" pe Telegram, a retras identitatea, și după aceea
  // tăcere. Din locul lui, alarma nu s-a închis niciodată.
  //
  // Cauza: retragerea scoate identitatea din enumerare, deci bucla lui `/check`
  // nu mai ajunge la ea, iar ramura de revenire — singura care șterge steagul
  // și anunță — e chiar în buclă. Comentariul de pe ea spunea deja principiul.
  // Registrul are ȘI o instanță vie, ca în producție. Fără ea, `ok` ar fi fals
  // din alt motiv — registru gol —, iar aserțiunea de mai jos ar trece peste
  // exact ce vrea să verifice: că o închidere de retragere nu strică verdictul.
  await seed({
    default: silentState({ alerted: { kind: "silent", at: "2026-08-19T08:10:00.000Z" } }),
    viu: freshState(),
  });
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const t = captureTelegram();
  try {
    const res = await GET(req(CHECK_KEY));
    const body = await bodyOf(res);

    assert.equal(t.sent.length, 1, "nu a plecat niciun mesaj de închidere");
    const text = t.sent[0].text;
    assert.match(text, /retrasă/, "mesajul nu spune că identitatea a fost retrasă");
    assert.ok(!/a revenit/.test(text),
              "mesajul spune „a revenit”, dar nu s-a întors nimic — retragerea " +
              "și revenirea sunt lucruri diferite");
    assert.match(text, /silent/, "mesajul nu numește alarma pe care o închide");

    const raportat = reportFor(body as Record<string, unknown>, "default");
    assert.equal(raportat?.kind, "retired-closed");
    assert.equal(body.ok, true,
                 "o retragere reușită a făcut runda să raporteze `ok: false`");
  } finally { t.restore(); }
});

test("închiderea pleacă O SINGURĂ DATĂ, nu la fiecare rundă de cron", async () => {
  // Cronul rulează la cinci minute. Un steag care nu se șterge ar trimite
  // închiderea la nesfârșit — iar o alarmă care nu se oprește e o alarmă pe
  // care operatorul o oprește, exact ce scrie pe ramura instanțelor ilizibile.
  await seed({
    default: silentState({ alerted: { kind: "silent", at: "2026-08-19T08:10:00.000Z" } }),
  });
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1);
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1, "a doua rundă a retrimis închiderea");
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1, "a treia rundă a retrimis închiderea");
  } finally { t.restore(); }
});

// ---------------------------------------------------------------------------
// Alertele duble: martorul tace dacă principalul a livrat CONFIRMAT același
// fel de mesaj recent — cerința operatorului, verificată la nivel de rută
// (nu doar `principalAlreadyDelivered` izolat), fiindcă efectul care contează
// e ce se scrie în starea instanței, nu doar valoarea întoarsă de o funcție.
// ---------------------------------------------------------------------------

/** Semnal proaspăt (fără tăcere, fără conductă oprită) cu autodiagnosticul căzut. */
function selfcheckDownState(alertedKinds?: Record<string, boolean>) {
  const base = freshState();
  const last = { ...(base.last as Record<string, unknown>) };
  last.selfcheck = { worst: "down", checks: 33, bad: 4, ran_at: last.received_at };
  if (alertedKinds) last.alerted_kinds = alertedKinds;
  return { ...base, last };
}

test("selfcheck livrat CONFIRMAT de principal suprimă mesajul martorului", async () => {
  await seed({ aaa111: selfcheckDownState({ selfcheck: true }) });
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0,
      "martorul a dublat alerta pe care principalul tocmai a livrat-o");
    assert.equal(reportFor(body, "aaa111")?.kind, "selfcheck");
    assert.equal(reportFor(body, "aaa111")?.alerted, false);
  } finally { t.restore(); }
});

test("fără livrare confirmată, selfcheck căzut TOT alertează", async () => {
  await seed({ aaa111: selfcheckDownState({ selfcheck: false }) });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1, "lipsa livrării confirmate n-a mai alertat");
  } finally { t.restore(); }
});

test("`alerted_kinds` LIPSĂ (Sentinel vechi, martor nou) duce la alertă, nu la tăcere", async () => {
  await seed({ aaa111: selfcheckDownState() }); // fără `alerted_kinds` deloc
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 1,
      "un câmp absent a fost citit ca „a livrat\", deci martorul a tăcut");
  } finally { t.restore(); }
});

test("`silent` NU se suprimă niciodată, indiferent ce pretinde beaconul", async () => {
  const base = silentState();
  await seed({
    aaa111: { ...base, last: { ...base.last, alerted_kinds: { selfcheck: true, silent: true } } },
  });
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 1,
      "un `silent` a fost suprimat pe baza unei chei pe care beaconul n-are voie s-o controleze");
    assert.equal(reportFor(body, "aaa111")?.kind, "silent");
  } finally { t.restore(); }
});

test("`stalled` NU se suprimă niciodată, indiferent ce pretinde beaconul", async () => {
  const base = freshState();
  await seed({
    aaa111: {
      ...base,
      last: { ...base.last, alerted_kinds: { stalled: true, selfcheck: true } },
      // Peste STALL_SECONDS (15 min): literal, nu numele constantei.
      counters_moved_at: new Date(Date.now() - (15 * 60 + 60) * 1000).toISOString(),
    },
  });
  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 1, "un `stalled` a fost suprimat");
    assert.equal(reportFor(body, "aaa111")?.kind, "stalled");
  } finally { t.restore(); }
});

test("o alertă SUPRIMATĂ nu produce mai târziu o revenire falsă", async () => {
  // Testul cel mai important: dacă suprimarea ar marca oricum `alerted`, când
  // selfcheck-ul revine la „ok" ramura de revenire ar anunța „Sentinel a
  // revenit" despre o alarmă pe care martorul n-a dat-o NICIODATĂ — a doua
  // formă de mesaj fals, nu o reparație a primeia.
  await seed({ aaa111: selfcheckDownState({ selfcheck: true }) });
  const first = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(first.sent.length, 0,
      "prima rundă a alertat, deci testul ăsta nu verifică suprimarea");
  } finally { first.restore(); }

  const afterFirst = (await readAll()).instances.aaa111;
  assert.equal(afterFirst?.alerted, undefined,
    "o alertă suprimată a fost marcată ca alertată oricum");

  // Runda următoare: autodiagnosticul a revenit la „ok".
  await seed({ aaa111: freshState() });
  const second = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(second.sent.length, 0,
      "martorul a anunțat o „revenire” falsă pentru o alarmă pe care n-a dat-o niciodată");
  } finally { second.restore(); }
});

test("revenirea e suprimată când principalul a anunțat-o el, dar starea tot se închide", async () => {
  // O alarmă REALĂ, deschisă de martor (nu suprimată). La runda următoare
  // problema s-a rezolvat, iar principalul tocmai a livrat propriul mesaj
  // `selfcheck` — cerința operatorului spune explicit că și revenirea tace în
  // cazul ăsta. Starea tot trebuie ștearsă, altfel o recădere REALĂ de același
  // fel ar fi înghițită ca duplicat în următoarele patru ore.
  const alerted = { kind: "selfcheck", at: new Date(Date.now() - 60000).toISOString() };
  const base = freshState({ alerted });
  await seed({
    aaa111: { ...base, last: { ...base.last, alerted_kinds: { selfcheck: true } } },
  });
  const t = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t.sent.length, 0,
      "martorul a anunțat revenirea deși principalul o anunțase deja");
  } finally { t.restore(); }

  const after = (await readAll()).instances.aaa111;
  assert.equal(after?.alerted, undefined,
    "starea de alertare n-a fost închisă, deci o recădere reală ar fi înghițită ca duplicat");

  // Fără nicio livrare nouă, runda următoare n-are ce anunța din nou.
  const t2 = captureTelegram();
  try {
    await GET(req(CHECK_KEY));
    assert.equal(t2.sent.length, 0);
  } finally { t2.restore(); }
});

test("o identitate retrasă FĂRĂ alarmă deschisă nu produce niciun mesaj",
     async () => {
  // Cazul obișnuit: se retrage ceva care tăcea liniștit, fără să fi alarmat.
  // Un mesaj aici ar fi zgomot pur, iar la fiecare cinci minute ar fi zgomot
  // care se învață să fie ignorat.
  await seed({ default: silentState() });
  setEnv({ SENTINEL_RETIRED_INSTANCES: "default" });

  const t = captureTelegram();
  try {
    const body = await bodyOf(await GET(req(CHECK_KEY)));
    assert.equal(t.sent.length, 0, "s-a trimis un mesaj pentru o alarmă inexistentă");
    assert.equal(reportFor(body as Record<string, unknown>, "default"), undefined,
                 "identitatea retrasă a reapărut în raport fără motiv");
  } finally { t.restore(); }
});
