/**
 * Starea pe fișier: un fișier per instanță, ce se întâmplă când lipsește, și ce
 * se întâmplă când scrierea e întreruptă.
 *
 * Șase eșecuri pe care fișierul ăsta le apără:
 *
 * 1. **„Nu știu" citit ca „e în regulă".** O stare absentă — martor proaspăt
 *    instalat, sau găzduire care șterge directorul la publicare — trebuie să
 *    însemne că nu avem ce judeca, nu că totul e bine. Diferența e vizibilă
 *    abia când cineva se uită la pagină și vede verde pe un server care nu mai
 *    trimite de trei zile.
 * 2. **Scriere neatomică.** O întrerupere la mijloc lasă un JSON trunchiat.
 *    Trunchiat înseamnă neparsabil, neparsabil înseamnă stare pierdută, iar
 *    starea pierdută înseamnă că `counters_moved_at` o ia de la zero și
 *    următoarea alarmă de conductă moartă întârzie 15 minute.
 * 3. **Starea existentă din producție aruncată la publicare.** Fișierul de azi
 *    e în forma veche, cu un singur obiect.
 * 4. **O înregistrare stricată care trece drept instanță tăcută sau sănătoasă.**
 *    E a treia stare — ilizibilă — și trebuie să se vadă ca atare.
 * 5. **Apartenența greșită, în ambele direcții.** O copie de fișier care devine
 *    un server (alarmă despre o mașină care nu există), și un server viu care
 *    dispare fiindcă i s-a șters cheia (nicio alarmă despre o mașină care
 *    moare). A doua e mai gravă și a fost livrată o dată.
 * 6. **O alarmă de configurare care nu se poate opri.** Detecția stării
 *    volatile pornește un 503 pe care nimic din afara configurației nu îl
 *    stinge, deci un fals pozitiv e la fel de scump ca o ratare.
 */

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { promises as fsp } from "fs";
import path from "path";

import {
  STATE_FILE, configureInstances, leftoverTempFiles, pretendCwd, removeState, setEnv,
  stateFileExists, writeRawInstance, writeRawState,
} from "./witness-harness";
import {
  instanceFile, readAll, readInstance, stateIsVolatile, updateInstance, writeInstance,
} from "@/lib/store";
import { judge } from "@/lib/verify";

/**
 * Fiecare test declară ce instanțe sunt CONFIGURATE.
 *
 * Apartenența are două surse: fișiere care se identifică singure și chei
 * configurate (vezi docstring-ul din `lib/store.ts`). Testele scriu prin
 * `writeInstance`, care pune identitatea în fișier, deci majoritatea ar
 * funcționa și fără chei — configurarea le ține însă aproape de cum arată o
 * instalare reală, iar testele care chiar depind de o sursă anume și-o declară
 * singure.
 */
beforeEach(() => {
  configureInstances(["default", "aaa111", "bbb222", "ccc333", "a1b2c3", "a1b2", "ok1"]);
});

/** Un semnal valid, ca fixturile să treacă de verificarea de formă. */
function beat(over: Record<string, unknown> = {}) {
  return {
    seq: 42, sent_at: "2026-08-12T09:00:00.000Z", received_at: "2026-08-12T09:00:01.000Z",
    last_event_id: 5, detect_cursor: 4, incidents_open: 1, blocklist_size: 2,
    audit_head: "f".repeat(64), interval_s: 60,
    selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: null },
    ...over,
  };
}

test("starea lipsă înseamnă „nu știu\", nu „a tăcut\"", async () => {
  await removeState();
  configureInstances([]);
  assert.deepEqual(await readAll(), { instances: {}, unreadable: [] });
  // Iar „nu știu" nu are voie să producă o alarmă din `judge()`: martorul tocmai
  // a fost instalat și expeditorul poate să nu fie încă pornit. Ce NU are voie
  // e ca `/status` să răspundă 200 pe asta — vezi status.route.test.ts.
  assert.equal(judge({}, new Date()).kind, null);
});

test("un fișier de bază corupt e tratat ca „nu știu\", nu ca excepție", async () => {
  // O rută care aruncă pe stare coruptă întoarce 500 la fiecare cerere, deci
  // martorul nu mai primește niciun semnal și nici nu poate raporta de ce.
  await removeState();
  configureInstances(["default"]);
  await writeRawState('{"last":{"seq":1,');
  // `default` e configurată, deci EXISTĂ — dar fișierul de bază nu spune nimic
  // despre ea, deci e o instanță fără niciun semnal, nu una sănătoasă.
  assert.deepEqual(await readAll(), { instances: { default: {} }, unreadable: [] });
});

test("scrierea ajunge lângă calea din SENTINEL_STATE_PATH, nu în directorul de lucru", async () => {
  // Verificare prin efect: dacă modulul ar citi variabila la import și nu la
  // apel, testele ar scrie altundeva și ar trece verde peste starea altcuiva.
  await removeState();
  await writeInstance("default", { counters_moved_at: "2026-08-12T09:00:00.000Z" });
  assert.equal(await stateFileExists(instanceFile("default")), true,
    `nu s-a scris nimic lângă ${STATE_FILE}`);
});

test("fiecare instanță are fișierul ei, nu o intrare într-un document comun", async () => {
  // Asta E reparația: două instanțe nu ating aceiași octeți, deci nu se pot
  // pierde una pe alta.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  await writeInstance("aaa111", { counters_moved_at: "2026-08-12T09:00:00.000Z" });
  await writeInstance("bbb222", { counters_moved_at: "2026-08-12T09:00:01.000Z" });
  assert.notEqual(instanceFile("aaa111"), instanceFile("bbb222"));
  assert.equal(await stateFileExists(instanceFile("aaa111")), true);
  assert.equal(await stateFileExists(instanceFile("bbb222")), true);
  assert.deepEqual(Object.keys((await readAll()).instances).sort(), ["aaa111", "bbb222"]);
});

test("ce s-a scris se citește înapoi identic", async () => {
  await removeState();
  const one = {
    last: beat({ label: "web-1" }),
    alerted: { kind: "silent", at: "2026-08-12T08:00:00.000Z" },
    counters_moved_at: "2026-08-12T09:00:01.000Z",
  };
  await writeInstance("default", one);
  await writeInstance("a1b2c3", { last: beat() });
  const state = await readAll();
  assert.deepEqual(state.instances.default, one);
  assert.deepEqual(state.instances.a1b2c3, { last: beat() });
});

test("scrierea nu lasă fișiere temporare în urmă", async () => {
  await removeState();
  await writeInstance("default", { counters_moved_at: "2026-08-12T09:00:00.000Z" });
  assert.deepEqual(await leftoverTempFiles(), []);
});

test("un identificator invalid nu poate scrie niciun fișier", async () => {
  // Fără verificarea asta, un identificator cu `/` sau `..` ar decide unde
  // scrie martorul. Nu e atins de rute — acolo e validat deja — dar magazia nu
  // are voie să se bazeze pe apelant.
  await removeState();
  for (const bad of ["../evadare", "a/b", "__proto__", ""]) {
    await assert.rejects(writeInstance(bad, {}), /identificator/);
  }
  assert.deepEqual(await leftoverTempFiles(), []);
});

// ---------------------------------------------------------------------------
// Registrul: cine e o instanță

test("un fișier fără cheie configurată NU e o instanță", async () => {
  // Cazul care a produs regula: martorul își ține starea în directorul home al
  // operatorului, adică exact unde se pune o copie înainte de o publicare. Cu
  // enumerare după fișiere, `state.backup-2026-08-12.json` devenea un server —
  // și, fiindcă o copie are prin definiție un semnal vechi, un server TĂCUT,
  // adică o alertă critică despre o mașină care nu există.
  await removeState();
  configureInstances(["aaa111"]);
  await writeRawInstance("aaa111", JSON.stringify({ last: beat() }));
  await writeRawInstance("backup-2026-08-12", JSON.stringify({ last: beat() }));
  await writeRawInstance("copie", JSON.stringify({ last: beat() }));

  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["aaa111"]);
  assert.deepEqual(state.unreadable, []);
});

test("un fișier străin nici măcar stricat nu devine „ilizibil\"", async () => {
  // Altfel copia ar fi dispărut din alerte doar ca să reapară ca „nu pot citi
  // starea instanței", adică tot o problemă inventată.
  await removeState();
  configureInstances(["aaa111"]);
  await writeRawInstance("backup-2026-08-12", "}}nu-e json{{");
  const state = await readAll();
  assert.deepEqual(state.unreadable, []);
  assert.deepEqual(Object.keys(state.instances), ["aaa111"]);
});

test("o instanță configurată fără fișier există, ca înregistrare goală", async () => {
  // „Configurată și n-a trimis niciodată" e o stare reală și trebuie să fie
  // vizibilă. Dacă ar lipsi din enumerare, un server care n-a pornit niciodată
  // ar fi invizibil în loc să fie roșu.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  const state = await readAll();
  assert.deepEqual(state.instances, { aaa111: {}, bbb222: {} });
});

test("un server viu căruia i se ȘTERGE cheia rămâne membru", async () => {
  // Regresia care a costat runda a treia. O versiune anterioară enumera numai
  // identificatorii configurați, deci ștergerea unei chei — sau o virgulă
  // greșită în JSON-ul din formularul web al găzduirii — ștergea serverul de pe
  // toate suprafețele, iar martorul raporta „ok" despre restul. Un server
  // monitorizat dispărea fără o vorbă: exact pana pentru care există martorul,
  // produsă de martor.
  //
  // Cu identitatea scrisă în fișier, instanța rămâne membră, nu mai poate
  // trimite, tace și alarmează.
  await removeState();
  configureInstances(["aaa111", "bbb222"]);
  await writeInstance("bbb222", { last: beat() });

  configureInstances(["aaa111"]);
  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances).sort(), ["aaa111", "bbb222"]);
  assert.equal(state.instances.bbb222.last?.seq, beat().seq, "starea lui bbb222 s-a pierdut");
});

test("o hartă de chei stricată nu șterge niciun server de pe hartă", async () => {
  // Forma probabilă a defectului: o virgulă în plus într-un JSON editat într-un
  // formular web. Toate instanțele mapate își pierd cheia deodată. Trebuie să
  // rămână membre — semnalele lor vor fi refuzate, deci vor tăcea, deci vor
  // alarma.
  await removeState();
  configureInstances(["aaa111", "bbb222", "ccc333"]);
  for (const id of ["aaa111", "bbb222", "ccc333"]) await writeInstance(id, { last: beat() });

  setEnv({ SENTINEL_INSTANCE_SECRETS: "{nu-e json", SENTINEL_BEACON_SECRET: undefined });
  assert.deepEqual(Object.keys((await readAll()).instances).sort(),
    ["aaa111", "bbb222", "ccc333"]);
});

test("o instanță fără cheie și fără fișier NU e inventată", async () => {
  // Cealaltă direcție a aceleiași reguli: apartenența vine din fișiere care se
  // identifică SAU din chei, nu din nimic.
  await removeState();
  configureInstances([]);
  assert.deepEqual(await readAll(), { instances: {}, unreadable: [] });
});

test("copia unui fișier poartă identitatea originalului, deci nu devine server", async () => {
  // Proprietatea care trebuie să reziste la reproiectare: fișierul copiat spune
  // înăuntru că e `aaa111`, iar numele lui nou spune altceva. Nepotrivirea îl
  // scoate din registru chiar dacă numele ales întâmplător ar fi configurat.
  await removeState();
  configureInstances(["aaa111", "ccc333"]);
  await writeInstance("aaa111", { last: beat() });

  const original = await fsp.readFile(instanceFile("aaa111"), "utf8");
  assert.match(original, /"instance_id":\s*"aaa111"/, "identitatea nu a fost scrisă în fișier");
  await writeRawInstance("backup-2026-08-12", original);
  await writeRawInstance("ccc333", original);

  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["aaa111"]);
  // Copia sub un nume necunoscut e ignorată în tăcere. Copia pusă exact la
  // calea unei instanțe CONFIGURATE e altceva: acolo ar fi trebuit să fie
  // starea ei, deci e raportată `unreadable` — roșu — nu `no-beat`, care nu se
  // numără și ar fi lăsat un server tăcut să pară verde.
  assert.deepEqual(state.unreadable, ["ccc333"]);
});

test("un fișier străin la calea unei instanțe configurate e roșu, nu `no-beat`", async () => {
  // Forma exactă a defectului reparat, verificată prin efect: `no-beat` nu se
  // numără în verdictul agregat, deci un server tăcut al cărui fișier poartă
  // altă identitate ar fi ieșit 200 „ok".
  await removeState();
  configureInstances(["pacalit"]);
  await writeRawInstance("pacalit", JSON.stringify({
    instance_id: "altcineva", last: beat(),
  }));
  const state = await readAll();
  assert.deepEqual(state.instances, {});
  assert.deepEqual(state.unreadable, ["pacalit"]);
});

test("un fișier vechi, fără identitate scrisă, e adoptat doar dacă e configurat", async () => {
  // Calea de migrare, și gaura de evitat: dacă am accepta orice fișier fără
  // identitate, copia unui fișier vechi ar reintra pe ușa asta.
  await removeState();
  configureInstances(["aaa111"]);
  const vechi = JSON.stringify({ last: beat() });
  await writeRawInstance("aaa111", vechi);
  await writeRawInstance("backup-2026-08-12", vechi);

  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["aaa111"]);
  assert.equal(state.instances.aaa111.last?.seq, beat().seq);
});

test("prima scriere scoate un fișier vechi din regimul de tranziție", async () => {
  await removeState();
  configureInstances(["aaa111"]);
  await writeRawInstance("aaa111", JSON.stringify({ last: beat() }));
  await writeInstance("aaa111", (await readInstance("aaa111")) ?? {});

  // Acum se identifică singur, deci supraviețuiește ștergerii cheii.
  configureInstances([]);
  assert.deepEqual(Object.keys((await readAll()).instances), ["aaa111"]);
});

test("starea apelantului NU poate rescrie identitatea fișierului", async () => {
  // `{ [ID_FIELD]: id, ...state }` punea identitatea ÎNAINTEA stării, deci o
  // stare care poartă `instance_id` o suprascria — exact invers decât spune
  // comentariul de deasupra scrierii. Un fișier cu identitatea altcuiva se
  // clasifică străin la următoarea citire, instanța cade la `no-beat`, iar
  // `no-beat` nu se numără: un server tăcut ajunge raportat verde.
  await removeState();
  configureInstances(["aaa111"]);
  await writeInstance("aaa111", { instance_id: "altcineva", last: beat() } as never);

  const raw = JSON.parse(await fsp.readFile(instanceFile("aaa111"), "utf8"));
  assert.equal(raw.instance_id, "aaa111", "apelantul a rescris identitatea fișierului");
  assert.deepEqual(Object.keys((await readAll()).instances), ["aaa111"]);
});

test("identitatea nu se scurge nici prin fișierul de bază", async () => {
  // `readRecord` o curăță pe calea fișierului propriu, dar migrarea trece prin
  // `adoptBase`, care nu o curăța. De acolo ajungea în `updateInstance`, care o
  // scria înapoi ca stare — și abia atunci otrăvea fișierul.
  await removeState();
  configureInstances(["default"]);
  await writeRawState(JSON.stringify({ instance_id: "altcineva", last: beat() }));

  const st = await readInstance("default");
  assert.deepEqual(Object.keys(st ?? {}), ["last"], "identitatea a intrat în stare");
});

test("o stare migrată și rescrisă rămâne a instanței ei", async () => {
  // Lanțul complet, cap-coadă: fișier de bază cu identitate străină → citire →
  // rescriere (ce face `/check` la fiecare rundă) → recitire.
  await removeState();
  configureInstances(["default"]);
  await writeRawState(JSON.stringify({ instance_id: "altcineva", last: beat() }));

  await updateInstance("default", (p) => ({ ...p, counters_moved_at: "2026-08-12T09:00:00.000Z" }));
  // Fișierul de bază dispare — starea de regim după migrare. Până acum el
  // acoperea otrăvirea: instanța pica pe rezerva moștenită și părea întreagă.
  await fsp.rm(STATE_FILE, { force: true });

  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["default"]);
  assert.equal(state.instances.default.last?.seq, beat().seq,
    "semnalul s-a pierdut: fișierul a fost clasificat străin după propria rescriere");
  assert.deepEqual(state.unreadable, []);
});

test("identitatea scrisă nu se scurge în starea văzută de apelanți", async () => {
  // E metadată de fișier, nu stare de instanță. Dacă ar ajunge în `InstanceState`,
  // ar intra și în ce compară `judge()` și în ce scrie înapoi `updateInstance`.
  await removeState();
  configureInstances(["aaa111"]);
  await writeInstance("aaa111", { counters_moved_at: "2026-08-12T09:00:00.000Z" });
  assert.deepEqual(await readInstance("aaa111"),
    { counters_moved_at: "2026-08-12T09:00:00.000Z" });
});

// ---------------------------------------------------------------------------
// Formă stricată = a treia stare

test("o instanță cu fișier ilizibil e raportată ilizibilă, nu sănătoasă", async () => {
  await removeState();
  configureInstances(["aaa111"]);
  await writeRawInstance("aaa111", "{nu-e json");
  const state = await readAll();
  assert.deepEqual(state.instances, {});
  assert.deepEqual(state.unreadable, ["aaa111"]);
});

test("un `last` care nu are forma unui semnal e respins, nu lăsat să crape mai târziu", async () => {
  // Ce se întâmpla altfel: `judge()` citea `last.selfcheck.worst` dintr-un
  // obiect care nu-l are, arunca, iar `/status` și `/check` răspundeau 500 la
  // fiecare cerere. Un martor care nu mai poate răspunde nu mai poate nici să
  // spună de ce.
  await removeState();
  configureInstances(["aaa111", "bbb222", "ccc333"]);
  await writeRawInstance("aaa111", '{"last":{"seq":"nu-e numar"}}');
  await writeRawInstance("bbb222", '{"last":"un sir"}');
  await writeRawInstance("ccc333", JSON.stringify({ last: { ...beat(), selfcheck: 7 } }));
  const state = await readAll();
  assert.deepEqual(state.instances, {});
  assert.deepEqual(state.unreadable, ["aaa111", "bbb222", "ccc333"]);
  // Și nimic din drumul ăsta nu aruncă.
  await assert.doesNotReject(readAll());
});

test("un fișier propriu ilizibil NU lasă înregistrarea veche să treacă drept curentă", async () => {
  // Fișierul instanței e autoritativ. Dacă e stricat, starea moștenită din
  // fișierul de bază e veche, iar vechiul prezentat ca actual e chiar minciuna.
  await removeState();
  configureInstances(["default"]);
  await writeRawState(JSON.stringify({ last: beat(), counters_moved_at: "2026-08-12T08:00:00.000Z" }));
  await writeRawInstance("default", "}}stricata{{");
  const state = await readAll();
  assert.deepEqual(state.instances, {});
  assert.deepEqual(state.unreadable, ["default"]);
});

test("o cale care există dar nu e un fișier e „ilizibilă\", nu „încă niciun semnal\"", async () => {
  // Un director cu numele fișierului de stare — ce rămâne după o dezarhivare
  // greșită, sau după un `SENTINEL_STATE_PATH` prost pus. Ambele stări dau 503,
  // deci diferența nu schimbă alarma; schimbă ce citește operatorul când se uită
  // de ce. „Instanța n-a trimis niciodată" îl trimite la server, „nu pot citi
  // starea" îl trimite la găzduire, și doar una dintre ele e adevărată.
  await removeState();
  configureInstances(["aaa111"]);
  await fsp.mkdir(instanceFile("aaa111"), { recursive: true });

  const state = await readAll();
  assert.deepEqual(state.unreadable, ["aaa111"]);
  assert.deepEqual(state.instances, {});
  assert.equal(await readInstance("aaa111"), undefined);
});

test("`readInstance` și `readAll` spun ACELAȘI lucru despre un fișier stricat", async () => {
  // Două căi de citire care nu sunt de acord despre aceiași octeți sunt un bug
  // care așteaptă un apelant. Aici: `readInstance` cădea pe înregistrarea veche
  // din fișierul de bază și o dădea drept curentă, în timp ce `readAll` o marca
  // ilizibilă. Vechiul prezentat ca actual e chiar minciuna.
  await removeState();
  configureInstances(["default"]);
  await writeRawState(JSON.stringify({ last: beat({ seq: 1 }) }));

  for (const stricat of ["}}nu-e json{{", '{"last":{"seq":"text"}}']) {
    await writeRawInstance("default", stricat);
    assert.equal(await readInstance("default"), undefined, `readInstance pe ${stricat}`);
    assert.deepEqual((await readAll()).unreadable, ["default"], `readAll pe ${stricat}`);
  }
});

test("`updateInstance` NU scrie peste o stare devenită necitibilă", async () => {
  // Fereastra e reală: `/check` citește starea, apoi așteaptă apelul către
  // Telegram, apoi scrie. Dacă fișierul s-a stricat între timp, o scriere peste
  // `{}` ar instala o înregistrare fără niciun semnal — o instanță permanent
  // „proaspăt instalată" pentru o mașină care poate fi moartă.
  await removeState();
  configureInstances(["aaa111"]);
  await writeRawInstance("aaa111", "}}stricata{{");

  const written = await updateInstance("aaa111", (p) => ({ ...p, alerted: { kind: "silent", at: "x" } }));
  assert.equal(written, false, "a scris peste o stare pe care nu o putea citi");
  assert.deepEqual((await readAll()).unreadable, ["aaa111"],
    "starea ilizibilă a fost înlocuită cu una goală și verde");
});

test("`updateInstance` păstrează semnalul aflat pe disc", async () => {
  await removeState();
  configureInstances(["aaa111"]);
  await writeInstance("aaa111", { last: beat({ seq: 7 }) });
  const written = await updateInstance("aaa111", (p) => ({ ...p, alerted: { kind: "silent", at: "x" } }));
  assert.equal(written, true);
  const after = await readInstance("aaa111");
  assert.equal(after?.last?.seq, 7);
  assert.equal(after?.alerted?.kind, "silent");
});

// ---------------------------------------------------------------------------
// Migrarea formei vechi

test("un fișier în forma veche e citit ca instanța `default`, nu aruncat", async () => {
  // Martorul din producție are un fișier în forma asta chiar acum. Dacă
  // publicarea versiunii cu instanțe l-ar ignora, `counters_moved_at` ar
  // reporni de la zero — deci prima alarmă reală de conductă moartă ar
  // întârzia 15 minute — iar `alerted` pierdut ar retrimite o alertă deja
  // trimisă. Amândouă arată ca un martor care funcționează.
  await removeState();
  configureInstances(["default"]);
  const old = {
    last: beat({ seq: 4471 }),
    alerted: { kind: "silent", at: "2026-08-12T05:00:00.000Z" },
    counters_moved_at: "2026-08-12T08:30:00.000Z",
  };
  await writeRawState(JSON.stringify(old));

  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["default"]);
  assert.deepEqual(state.instances.default, old);
  // Și pe drumul pe care îl folosește ruta de semnal, nu doar pe cel agregat:
  // altfel primul semnal după publicare ar reseta `counters_moved_at`.
  assert.deepEqual(await readInstance("default"), old);
});

test("fișierul propriu al instanței umbrește fișierul de bază", async () => {
  await removeState();
  await writeRawState(JSON.stringify({ counters_moved_at: "2026-08-12T08:00:00.000Z" }));
  await writeInstance("default", { counters_moved_at: "2026-08-12T10:00:00.000Z" });
  assert.equal((await readInstance("default"))?.counters_moved_at, "2026-08-12T10:00:00.000Z");
  assert.equal((await readAll()).instances.default.counters_moved_at, "2026-08-12T10:00:00.000Z");
});

test("o stare veche cu doar `alerted` se migrează tot, nu doar cea cu semnal", async () => {
  // Cazul real: martorul a alertat pentru tăcere și nu a mai primit nimic de
  // atunci. Pierderea lui `alerted` ar retrimite alerta la prima rundă de cron.
  await removeState();
  await writeRawState(JSON.stringify({ alerted: { kind: "silent", at: "2026-08-12T05:00:00.000Z" } }));
  assert.equal((await readAll()).instances.default?.alerted?.kind, "silent");
});

test("un fișier gol din forma veche NU inventează o instanță", async () => {
  await removeState();
  configureInstances([]);
  await writeRawState("{}");
  assert.deepEqual(await readAll(), { instances: {}, unreadable: [] });
});

test("forma intermediară, cu `instances` în fișierul de bază, se citește tot", async () => {
  // Forma aia a existat o singură rundă și nu a fost niciodată publicată, dar o
  // migrare care o aruncă ar pierde starea oricui a rulat-o local.
  await removeState();
  await writeRawState(JSON.stringify({
    instances: { a1b2: { counters_moved_at: "2026-08-12T09:00:00.000Z" } },
  }));
  assert.equal((await readAll()).instances.a1b2?.counters_moved_at, "2026-08-12T09:00:00.000Z");
});

test("intrările cu identificator imposibil sunt ignorate, nu încărcate", async () => {
  // `__proto__` folosit ca nume de instanță nu ar deveni o intrare în hartă, ci
  // ar rescrie prototipul ei — iar de acolo orice căutare de instanță ar
  // întoarce ceva.
  //
  // JSON scris de mână, nu prin `JSON.stringify`: într-un literal de obiect
  // JavaScript, `"__proto__"` e deja forma specială, deci cheia nu ar fi ajuns
  // niciodată în fișier și testul ar fi verificat altceva decât credea.
  await removeState();
  configureInstances(["ok1"]);
  await writeRawState(
    '{"instances":{"__proto__":{"counters_moved_at":"x"},"b/c":{},"ok1":{}}}',
  );
  const state = await readAll();
  assert.deepEqual(Object.keys(state.instances), ["ok1"]);
  // Și, mai important, prototipul hărții a rămas curat.
  assert.equal((state.instances as Record<string, unknown>).oricine, undefined);
  assert.equal(Object.getPrototypeOf(state.instances), Object.prototype);
});

test("o stare care nu e obiect nu devine „totul e în regulă\"", async () => {
  for (const raw of ["[]", '"text"', "42", "null"]) {
    await removeState();
    configureInstances([]);
    await writeRawState(raw);
    assert.deepEqual(await readAll(), { instances: {}, unreadable: [] }, `a acceptat ${raw}`);
  }
});

test("starea goală întoarsă de `readAll` nu e un obiect comun pe tot procesul", async () => {
  // O versiune anterioară întorcea o constantă de modul. „Nu știu" devenea
  // astfel o valoare pe care oricine o putea modifica pentru toți ceilalți.
  await removeState();
  configureInstances([]);
  const a = await readAll();
  (a.instances as Record<string, unknown>).intrus = { last: beat() };
  a.unreadable.push("intrus");
  const b = await readAll();
  assert.deepEqual(b, { instances: {}, unreadable: [] });
});

// ---------------------------------------------------------------------------
// Detecția stării volatile

test("apartenența la directorul aplicației se decide pe segmente de cale, nu pe prefix de șir", async () => {
  // Detecția asta pornește o alarmă care nu se poate opri din altă parte decât
  // din configurație. Un fals pozitiv o blochează pe 503 la nesfârșit, pe o
  // instalare perfect bună — exact eșecul „alarma pe care nimeni nu o poate
  // opri" pe care faza asta l-a produs deja de două ori.
  //
  // `path.relative`, nu `dir.startsWith(appDir)`: un director VECIN care începe
  // cu același nume — `app-2026-08-12` lângă `app`, adică fix cum arată o copie
  // datată sau un director de lansare — trece de o comparație de prefix și
  // cade corect prin comparația pe segmente.
  const cases: [string, string, boolean][] = [
    // [director de lucru, calea de bază a stării, e volatilă?]
    ["/x/app", "/x/app/state.json", true],
    ["/x/app", "/x/state.json", false],
    ["/x/app", "/x/app-2026-08-12/state.json", false],
    ["/x/app", "/x/appX/state.json", false],
    ["/x/app", "/x/date/state.json", false],
    // Ieșit și întors: tot înăuntru.
    ["/x/app", "/x/app/../app/state.json", true],
    // Ieșit către vecinul cu același prefix: tot afară.
    ["/x/app", "/x/app/../app-2026-08-12/state.json", false],
  ];

  const originalPath = process.env.SENTINEL_STATE_PATH;
  try {
    for (const [cwd, statePath, expected] of cases) {
      const restore = pretendCwd(path.resolve(cwd));
      try {
        process.env.SENTINEL_STATE_PATH = path.resolve(statePath);
        assert.equal(stateIsVolatile(), expected,
          `cwd=${cwd} stare=${statePath} ar fi trebuit să dea ${expected}`);
      } finally { restore(); }
    }
  } finally {
    process.env.SENTINEL_STATE_PATH = originalPath;
  }
});

// ---------------------------------------------------------------------------
// Scriere atomică

test("o scriere întreruptă la mijloc NU distruge starea dinainte", async () => {
  // Reproducem întreruperea: `writeFile` scrie jumătate din octeți și apoi
  // eșuează. Cu scriere atomică, jumătatea ajunge în fișierul temporar și
  // originalul rămâne întreg. Fără ea — `writeFile` direct peste destinație —
  // starea reală devine JSON trunchiat și se pierde definitiv.
  await removeState();
  const good = { counters_moved_at: "2026-08-12T09:00:00.000Z" };
  await writeInstance("default", good);

  const original = fsp.writeFile;
  (fsp as { writeFile: unknown }).writeFile = async (
    file: Parameters<typeof original>[0],
    data: string,
    enc: unknown,
  ) => {
    await original.call(fsp, file, data.slice(0, Math.floor(data.length / 2)), enc as never);
    throw new Error("test: întrerupere simulată la mijlocul scrierii");
  };
  try {
    await assert.rejects(writeInstance("default", { counters_moved_at: "2026-08-12T10:00:00.000Z" }));
  } finally {
    (fsp as { writeFile: unknown }).writeFile = original;
  }

  assert.deepEqual(await readInstance("default"), good,
    "starea dinainte s-a pierdut la o scriere întreruptă");
  // Iar bucata scrisă pe jumătate nu a rămas pe disc ca să se adune.
  assert.deepEqual(await leftoverTempFiles(), []);
});
