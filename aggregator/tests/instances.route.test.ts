/**
 * Mai multe instanțe: cine e cine, și ce nu are voie să se amestece.
 *
 * Eșecul central pe care fișierul ăsta îl păzește e falsificarea între
 * instanțe. Cheia HMAC stă pe mașina monitorizată, deci un atacator cu root pe
 * A o are. Dacă martorul ar accepta un payload care pretinde că e B doar
 * fiindcă semnătura lui A e validă, atunci compromiterea UNEI mașini ar
 * cumpăra minciuna despre TOATE — inclusiv „B e viu" în timp ce B e oprit.
 * Cheile separate nu ajung singure; e nevoie și de legătura antet ↔ payload.
 *
 * Al doilea eșec: instanțele care se calcă. Un `seq` global ar face ca al
 * doilea server să primească 409 la fiecare semnal, iar simptomul — „B nu apare
 * niciodată" — s-ar diagnostica drept problemă de rețea.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  baseEnv, beatPayload, beatRequest, bodyOf, captureLog, removeState, setEnv, BEACON_KEY,
} from "./witness-harness";
import { POST } from "@/app/api/sentinel/beat/route";
import { readAll } from "@/lib/store";

const KEY_A = "cheie-instanta-a";
const KEY_B = "cheie-instanta-b";
const MAP = JSON.stringify({ a1b2c3: KEY_A, d4e5f6: KEY_B });

beforeEach(async () => {
  baseEnv();
  setEnv({ SENTINEL_INSTANCE_SECRETS: MAP });
  await removeState();
});

afterEach(async () => {
  await removeState();
});

/**
 * Instanțele care chiar au înregistrat un semnal.
 *
 * `readAll()` întoarce ACUM și instanțele configurate care n-au trimis
 * niciodată, ca înregistrări goale — asta e reparația pentru „configurat și
 * fără semnal e o stare reală, nu «ok»". O aserțiune pe lista de chei ar
 * număra și instanțele goale, deci ar spune altceva decât vrea testul: aici ne
 * interesează cine a fost ACCEPTAT.
 */
async function withBeats(): Promise<string[]> {
  const state = await readAll();
  return Object.keys(state.instances)
    .filter((id) => state.instances[id].last !== undefined).sort();
}

async function send(instance: string, key: string, over: Record<string, unknown> = {}) {
  return POST(await beatRequest({
    instance,
    key,
    payload: beatPayload({ instance_id: instance, ...over }),
  }));
}

// ---------------------------------------------------------------------------
// Pasul 3 al verificării

test("un payload semnat cu cheia lui A dar care pretinde că e B e refuzat", async () => {
  // Antetul spune A, cheia e a lui A, deci semnătura e validă. Payload-ul
  // pretinde B. Fără pasul 3, martorul ar înregistra asta ca semnal de la B.
  const res = await POST(await beatRequest({
    instance: "a1b2c3",
    key: KEY_A,
    payload: beatPayload({ instance_id: "d4e5f6" }),
  }));
  assert.equal(res.status, 401);
  assert.deepEqual(await withBeats(), []);
});

test("antetul lui B cu cheia lui A e refuzat la semnătură", async () => {
  const res = await POST(await beatRequest({
    instance: "d4e5f6",
    key: KEY_A,
    payload: beatPayload({ instance_id: "d4e5f6" }),
  }));
  assert.equal(res.status, 401);
  assert.deepEqual(await withBeats(), []);
});

test("o instanță necunoscută primește 401, nu 404", async () => {
  // 404 ar confirma care identificatori există. Ruta nu cere nimic ca să
  // întrebe, deci ar fi o listă de instanțe oferită gratuit.
  const res = await POST(await beatRequest({
    instance: "necunoscuta",
    key: KEY_A,
    payload: beatPayload({ instance_id: "necunoscuta" }),
  }));
  assert.equal(res.status, 401);
});

test("cheia moștenită NU acoperă o instanță necunoscută", async () => {
  // Testul de deasupra ar trece și dacă `SENTINEL_BEACON_SECRET` ar fi acceptat
  // pentru ORICE identificator — semnătura lui era făcută cu altă cheie, deci
  // 401-ul venea de la pasul 2, nu de la pasul 1. Aici semnătura e chiar cea
  // moștenită, deci singurul motiv de refuz rămâne că instanța nu e configurată.
  //
  // Ce ar strica altfel: oricine află un identificator poate crea instanțe noi
  // cu cheia instanței implicite, iar panoul se umple de servere inventate.
  const res = await POST(await beatRequest({
    instance: "necunoscuta",
    key: BEACON_KEY,
    payload: beatPayload({ instance_id: "necunoscuta" }),
  }));
  assert.equal(res.status, 401);
  assert.deepEqual(await withBeats(), []);
});

test("un identificator malformat e refuzat, nu folosit ca nume de proprietate", async () => {
  for (const bad of ["__proto__", "a/b", "a b", "a".repeat(65), "-abc"]) {
    const res = await POST(await beatRequest({
      instance: bad, key: KEY_A, payload: beatPayload({ instance_id: bad }),
    }));
    assert.equal(res.status, 401, `a acceptat identificatorul ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(await withBeats(), []);
});

// ---------------------------------------------------------------------------
// Toleranța pentru serverul care nu s-a actualizat încă

test("un semnal fără antet și fără instance_id intră ca `default`", async () => {
  // Ordinea de livrare e martorul întâi. Dacă asta ar da 401, actualizarea
  // martorului ar tăia semnalul serverului aflat în producție, iar simptomul ar
  // fi chiar alarma pe care martorul o dă când un server moare.
  const res = await POST(await beatRequest({ payload: beatPayload({ seq: 3 }) }));
  assert.equal(res.status, 200);
  assert.equal((await bodyOf(res)).instance, "default");
  assert.equal((await readAll()).instances.default?.last?.seq, 3);
});

test("`default` folosește SENTINEL_BEACON_SECRET, nu o intrare din hartă", async () => {
  assert.equal((await POST(await beatRequest({ key: KEY_A }))).status, 401);
  assert.equal((await POST(await beatRequest({}))).status, 200);
});

test("o intrare explicită pentru `default` bate variabila moștenită", async () => {
  setEnv({ SENTINEL_INSTANCE_SECRETS: JSON.stringify({ default: KEY_B }) });
  assert.equal((await POST(await beatRequest({}))).status, 401);
  assert.equal((await POST(await beatRequest({ key: KEY_B }))).status, 200);
});

test("un `instance_id` care nu e șir e refuzat, nu convertit", async () => {
  // `String({toString: "x"})` ARUNCĂ. Un payload ostil dar semnat corect ar
  // transforma refuzul într-un 500 — nu o ocolire, fiindcă cine îl trimite are
  // deja cheia, dar o rută care crapă în loc să refuze e greu de diagnosticat
  // și umple jurnalul cu excepții care par ale altcuiva.
  for (const hostile of [{ toString: "x" }, [1, 2], 42, true, { a: 1 }]) {
    const res = await POST(await beatRequest({
      instance: "a1b2c3",
      key: KEY_A,
      payload: beatPayload({ instance_id: hostile }),
    }));
    assert.equal(res.status, 401, `a răspuns ${res.status} la ${JSON.stringify(hostile)}`);
  }
  assert.deepEqual(await withBeats(), []);
});

test("un payload cu instance_id dar fără antet e refuzat", async () => {
  // Fail closed: antetul lipsă înseamnă `default`, iar payload-ul spune altceva.
  const res = await POST(await beatRequest({ payload: beatPayload({ instance_id: "a1b2c3" }) }));
  assert.equal(res.status, 401);
});

// ---------------------------------------------------------------------------
// Independența dintre instanțe

test("două instanțe își țin secvențele separat", async () => {
  assert.equal((await send("a1b2c3", KEY_A, { seq: 100 })).status, 200);
  // B pornește de la 1. Cu un contor global, ar fi primit 409 aici, iar
  // simptomul ar fi fost „B nu apare niciodată".
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 200);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 409);
  assert.equal((await send("a1b2c3", KEY_A, { seq: 101 })).status, 200);

  const state = await readAll();
  assert.equal(state.instances.a1b2c3?.last?.seq, 101);
  assert.equal(state.instances.d4e5f6?.last?.seq, 1);
});

test("un semnal de la A nu atinge starea lui B", async () => {
  await send("a1b2c3", KEY_A, { seq: 1, last_event_id: 10 });
  await send("d4e5f6", KEY_B, { seq: 1, last_event_id: 500 });
  const before = JSON.stringify((await readAll()).instances.d4e5f6);

  await send("a1b2c3", KEY_A, { seq: 2, last_event_id: 11 });
  assert.equal(JSON.stringify((await readAll()).instances.d4e5f6), before);
});

test("contoarele oprite se urmăresc pe instanță, nu global", async () => {
  // Eșecul pe care îl previne: cu un singur `counters_moved_at`, două servere
  // care alternează semnalele ar arăta veșnic ca și cum ar avansa amândouă —
  // unul dintre ele poate avea conducta moartă de ore fără ca nimic să spună.
  await send("a1b2c3", KEY_A, { seq: 1, last_event_id: 10 });
  await send("d4e5f6", KEY_B, { seq: 1, last_event_id: 500 });
  const bMoved = (await readAll()).instances.d4e5f6?.counters_moved_at;

  await new Promise((r) => setTimeout(r, 10));
  // A avansează, B trimite fără să avanseze.
  await send("a1b2c3", KEY_A, { seq: 2, last_event_id: 11 });
  await send("d4e5f6", KEY_B, { seq: 2, last_event_id: 500 });

  const state = await readAll();
  assert.equal(state.instances.d4e5f6?.counters_moved_at, bMoved,
    "contorul lui B a fost mișcat de avansul lui A");
  assert.notEqual(state.instances.a1b2c3?.counters_moved_at, bMoved);
});

// ---------------------------------------------------------------------------
// Configurație lipsă sau stricată

test("o hartă de chei stricată dă 500, nu 401", async () => {
  // „Nu pot citi nicio cheie" și „te-am refuzat" sunt stări diferite, iar
  // diferența e exact ce citește cel care instalează, dintr-un curl.
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{nu-e json", SENTINEL_BEACON_SECRET: undefined });
  assert.equal((await POST(await beatRequest({ instance: "a1b2c3", key: KEY_A }))).status, 500);
});

test("o hartă stricată dă 500 și când cheia moștenită există", async () => {
  // Testul de deasupra ar trece și fără nicio tratare a hărții stricate: cu
  // `SENTINEL_BEACON_SECRET` scos, „nimic configurat" duce oricum la 500.
  // Diferența se vede doar aici: cheia implicită există, dar despre instanța
  // cerută NU putem spune nimic — și „nu pot citi" nu e „te-am refuzat".
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{nu-e json" });
  assert.equal((await POST(await beatRequest({ instance: "a1b2c3", key: KEY_A }))).status, 500);
});

test("o hartă stricată nu anulează cheia moștenită a instanței `default`", async () => {
  // Altfel o greșeală de tipar făcută la adăugarea celui de-al doilea server ar
  // opri semnalul primului, iar cauza ar părea fără legătură.
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{nu-e json" });
  assert.equal((await POST(await beatRequest({}))).status, 200);
});

test("o hartă care nu e obiect e tratată ca stricată", async () => {
  setEnv({ SENTINEL_INSTANCE_SECRETS: '["a","b"]', SENTINEL_BEACON_SECRET: undefined });
  assert.equal((await POST(await beatRequest({ instance: "a1b2c3", key: KEY_A }))).status, 500);
});

test("intrările fără valoare de tip șir sunt ignorate, restul hărții rămâne bună", async () => {
  setEnv({ SENTINEL_INSTANCE_SECRETS: JSON.stringify({ a1b2c3: KEY_A, d4e5f6: 42 }) });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 401);
});

test("o cheie GOALĂ în JSON e ignorată, nu acceptată ca și cheie", async () => {
  // Ce se strică fără regula asta: `{"a1b2c3":""}` e o valoare pe care o produce
  // un `.env` completat pe jumătate. Cheia goală ajunge în hartă, harta pare
  // configurată, iar instanța primește 401 „te-am refuzat" — adică martorul
  // pretinde că a citit valoarea. Ignorată, e ultima intrare pierdută dintr-o
  // valoare nevidă, deci `broken`: 500 „nu sunt configurat", care e singura
  // stare vizibilă dintr-un curl și e cea care aduce omul la jurnal.
  //
  // `SENTINEL_BEACON_SECRET` rămâne SETAT: fără el, „nimic configurat" ar da
  // oricum 500 și testul ar trece și cu regula scoasă.
  setEnv({ SENTINEL_INSTANCE_SECRETS: '{"a1b2c3":""}' });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
});

test("o hartă JSON din care s-a pierdut TOT e stricată, nu goală", async () => {
  // Aceeași regulă ca la perechi, oglindită: o valoare nevidă din care nu iese
  // nicio intrare bună nu e „nicio instanță configurată", e o valoare scrisă
  // greșit. Cu 401 în loc de 500, operatorul citește „te-am refuzat" și caută
  // problema în cheia de pe serverul monitorizat, unde nu e.
  setEnv({ SENTINEL_INSTANCE_SECRETS: JSON.stringify({ "a b": KEY_A }) });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
});

test("`{}` e o listă goală DECLARATĂ, nu o hartă stricată", async () => {
  // Ce se strică dacă `{}` devine `broken`: o instalare cu un singur server,
  // care lasă variabila pe `{}` fiindcă n-are instanțe suplimentare, începe să
  // primească 500 pe fiecare bătaie a serverului `default` care funcționa. E o
  // problemă inventată de martor, pe o configurație corectă — și cea mai
  // scumpă formă de alarmă falsă, fiindcă vine chiar de la mecanismul de
  // alarmare.
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{}" });
  // Instanță necunoscută: 401 „te-am refuzat", fiindcă valoarea S-A citit.
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 401);
  // Iar `default` merge mai departe pe cheia moștenită.
  assert.equal((await POST(await beatRequest({}))).status, 200);
  assert.deepEqual(Object.keys((await readAll()).instances).sort(), ["default"]);
});

test("`{}` fără cheie moștenită înseamnă «nu sunt configurat», și registrul e gol", async () => {
  // Cealaltă jumătate a lui `{}`: fără `SENTINEL_BEACON_SECRET` chiar nu există
  // nicio cheie, iar atunci 401 ar fi minciuna inversă — „te-am refuzat" pe o
  // instalare căreia nu i s-a dat nimic. Registrul gol contează la fel de mult:
  // martorul nu are voie să aștepte semnale de la instanțe pe care nu le poate
  // verifica, altfel alarmează la nesfârșit pentru servere care nu există.
  setEnv({ SENTINEL_INSTANCE_SECRETS: "{}", SENTINEL_BEACON_SECRET: undefined });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
  assert.deepEqual(Object.keys((await readAll()).instances), []);
});

test("în JSON, un identificator repetat NU strică valoarea: ultima intrare câștigă", async () => {
  // Direcția asta e o ALEGERE, nu o proprietate dovedită: `JSON.parse`
  // colapsează duplicatul înainte să-l vedem, iar detectarea lui ar cere un al
  // doilea parser peste șirul brut. Testul nu o aprobă, o FIXEAZĂ — fără el, un
  // refactor o poate întoarce în oricare sens, gratis, iar operatorul ar afla
  // schimbarea din faptul că serverul care mergea primește dintr-odată 500.
  //
  // Se scrie ca șir brut: `JSON.stringify` nu poate produce o cheie duplicată.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `{"a1b2c3":"${KEY_A}","a1b2c3":"${KEY_B}"}` });
  const log = captureLog();
  let first: number, last: number;
  try {
    first = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
    last = (await send("a1b2c3", KEY_B, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(first, 401, "prima intrare a fost acceptată — direcția s-a schimbat");
  assert.equal(last, 200, "ultima intrare nu mai câștigă — direcția s-a schimbat");
  assert.deepEqual(log.lines, [], "duplicatul JSON a început să scrie în jurnal");
});

// ---------------------------------------------------------------------------
// Formatul fără `{`, `}`, `"` — găzduirea le elimină din valorile variabilelor
// de mediu (măsurat pe 14 august 2026, vezi lib/beat-keys.ts).

test("o hartă scrisă `<id>:<cheie>,<id>:<cheie>` autentifică exact ca JSON", async () => {
  // Eșecul pe care îl previne, și care s-a întâmplat: panoul găzduirii scoate
  // acoladele și ghilimelele, JSON.parse aruncă, martorul rămâne fără nicio
  // cheie, iar serverul monitorizat primește 401 la fiecare bătaie. Peste opt
  // ore fără nicio înregistrare, cu ambele capete pornite și sănătoase.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},d4e5f6:${KEY_B}` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 200);
  // Cheile nu s-au amestecat între identități: fără asta, testul de sus ar
  // trece și dacă parserul ar da aceeași cheie tuturor.
  assert.equal((await send("a1b2c3", KEY_B, { seq: 2 })).status, 401);
  assert.deepEqual(await withBeats(), ["a1b2c3", "d4e5f6"]);
});

test("spațiile în jurul separatorilor nu fac instanța necunoscută", async () => {
  // Un formular web poate adăuga un spațiu fără să întrebe pe nimeni. Dacă un
  // spațiu ar însemna „instanță necunoscută", simptomul ar fi 401 la fiecare
  // bătaie, cu o valoare care în panou arată perfect corectă.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `  a1b2c3 : ${KEY_A} ,  d4e5f6 : ${KEY_B}  ` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 200);
});

test("formatul se alege după primul caracter NESPAȚIU, deci JSON rămâne JSON", async () => {
  // Cu alegerea făcută pe `raw[0]`, un singur spațiu pus înaintea acoladei ar
  // trimite o hartă JSON perfect validă la parserul de perechi, unde s-ar
  // pierde toată — adică o gazdă normală ar începe să dea 500 din senin.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `  ${MAP}` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
});

test("cheia se ia după PRIMUL `:`, restul segmentului rămâne întreg", async () => {
  // Cheile de azi sunt hexa, deci nu conțin `:`. Ziua în care nu vor mai fi,
  // împărțirea greșită ar tăia cheia tăcut: semnătura nu se potrivește, 401 la
  // fiecare bătaie, iar valoarea din panou pare corectă.
  const KEY_COLON = "aa:bb:cc";
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_COLON}` });
  assert.equal((await send("a1b2c3", KEY_COLON, { seq: 1 })).status, 200);
  assert.equal((await send("a1b2c3", "aa", { seq: 2 })).status, 401);
});

test("o intrare stricată nu anulează perechile bune din aceeași valoare", async () => {
  // Aceeași regulă ca la JSON: identitatea scrisă greșit rămâne necunoscută și
  // alarmează prin tăcere, celelalte funcționează. Altfel o greșeală la
  // adăugarea celui de-al doilea server ar opri primul.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},ceva-fara-doua-puncte` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
});

test("un segment fără `:` se NUMĂRĂ ca intrare ignorată, nu dispare tăcut", async () => {
  // Testul de deasupra folosește aceeași valoare, dar cere doar 200 — adică
  // trece și dacă segmentul stricat e sărit fără să fie numărat. Ce se pierde
  // atunci e singurul lucru care spune ce s-a întâmplat.
  //
  // Scenariul: lipești al doilea server în panou și uiți cheia lui, deci rămâne
  // doar identificatorul. Primul server merge mai departe și `/beat` răspunde
  // 200, deci nimic din afară nu arată o problemă. Al doilea primește 401 la
  // fiecare bătaie și NU intră în registru — deci nici tăcerea lui nu alarmează,
  // fiindcă nimeni nu-l așteaptă. Singura urmă rămâne linia „intrări ignorate";
  // fără `dropped++` nu se scrie nici ea, iar valoarea din panou arată corectă.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},d4e5f6` });
  const log = captureLog();
  let status: number;
  try {
    status = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
  } finally {
    log.restore();
  }

  assert.equal(status, 200, "o intrare stricată a oprit perechea bună din aceeași valoare");
  const ignorate = log.lines.filter((l) => l.join(" ").includes("intrări ignorate"));
  assert.ok(ignorate.length >= 1, "segmentul fără `:` nu s-a numărat ca intrare ignorată");
  for (const line of ignorate) {
    const text = line.join(" ");
    assert.match(text, /SENTINEL_INSTANCE_SECRETS/, "linia nu spune CARE variabilă");
    assert.match(text, /\b1\b/, "linia nu spune CÂTE intrări s-au ignorat");
    assert.ok(!text.includes("d4e5f6"), `jurnalul a scris conținutul intrării: ${text}`);
  }
});

test("o virgulă în plus nu strică valoarea și nu scrie nimic în jurnal", async () => {
  // Jurnalul de execuție al găzduirii e suprafața pe care se diagnostichează o
  // configurație refuzată (watcher/INCARCARE-HOSTINGER.md). O linie de EROARE la
  // fiecare cerere, pe o configurație care funcționează perfect, îl învață pe
  // operator să nu-l mai citească — și atunci nu-l va citi nici în ziua în care
  // acolo scrie de ce nu mai ajunge niciun semnal.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},` });
  const log = captureLog();
  let status: number;
  try {
    status = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(status, 200, "o virgulă la capăt a stricat o valoare bună");
  assert.deepEqual(log.lines, [], "s-a scris în jurnal pentru o virgulă în plus");
});

test("un identificator singur, fără `:`, e `broken`, nu hartă goală", async () => {
  // Cazul măsurat pe 14 august 2026: câmpul conținea doar identificatorul,
  // fără separator și fără cheie. Arăta configurat și nu producea nimic.
  //
  // `SENTINEL_BEACON_SECRET` rămâne SETAT dinadins — aici e diferența:
  // cu hartă goală, ruta ar răspunde 401 „te-am refuzat", adică ar pretinde că
  // a citit valoarea; `broken` răspunde 500 „nu sunt configurat", care e
  // singurul lucru vizibil dintr-un curl și e ce a permis diagnosticul.
  setEnv({ SENTINEL_INSTANCE_SECRETS: "a1b2c3d4e5f60718" });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
});

test("o valoare formată numai din separatori e `broken`, nu hartă goală", async () => {
  // Cazul în care operatorul a șters conținutul câmpului dar a lăsat virgulele,
  // sau a lipit o valoare din care s-au pierdut perechile. Câmpul arată plin.
  // Cu hartă goală, ruta ar răspunde 401 „te-am refuzat" — adică ar pretinde că
  // a citit o valoare din care n-a ieșit nimic — și operatorul ar căuta cauza în
  // cheia de pe serverul monitorizat. `broken` dă 500 „nu sunt configurat", care
  // arată dintr-un curl și trimite la jurnal, unde scrie ce lipsește.
  setEnv({ SENTINEL_INSTANCE_SECRETS: " , , " });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
});

// --- Separatorul de perechi: o clasă, nu un caracter presupus ---------------
//
// Eșecul comun al celor patru teste de mai jos: cu `split(",")` singur, orice
// alt separator lasă UN segment, `indexOf(":")` taie la primul `:`, iar a doua
// pereche devine cheia primei. Ambele instanțe primesc 401 la fiecare bătaie, a
// doua nici nu intră în registru — deci nici tăcerea ei nu alarmează — și NIMIC
// nu ajunge în jurnal, fiindcă nimic nu s-a numărat ca ignorat. Măsurat prin
// rută pe 15 august 2026, exact așa, pentru newline, `;` și spațiu.

test("perechile despărțite prin newline se citesc, nu se lipesc în cheia primei", async () => {
  setEnv({
    SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A}\nd4e5f6:${KEY_B}`,
    SENTINEL_BEACON_SECRET: undefined,
  });
  const log = captureLog();
  let a: number, b: number;
  try {
    a = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
    b = (await send("d4e5f6", KEY_B, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(a, 200);
  assert.equal(b, 200, "a doua pereche a fost înghițită de cheia primei");
  // Cheile nu s-au amestecat: fără asta, testul ar trece și dacă parserul ar da
  // aceeași cheie amândurora.
  assert.equal((await send("a1b2c3", KEY_B, { seq: 2 })).status, 401);
  // Și amândouă în REGISTRU: o instanță pe care martorul n-o așteaptă nu poate
  // alarma prin tăcere, deci un server mort înainte de prima bătaie e invizibil.
  assert.deepEqual(Object.keys((await readAll()).instances).sort(), ["a1b2c3", "d4e5f6"]);
  assert.deepEqual(log.lines, [], "o valoare perfect bună a scris în jurnal");
});

test("perechile despărțite prin `;` se citesc, nu se lipesc în cheia primei", async () => {
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A};d4e5f6:${KEY_B}` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 200,
    "a doua pereche a fost înghițită de cheia primei");
  assert.equal((await send("a1b2c3", KEY_B, { seq: 2 })).status, 401);
});

test("perechile despărțite prin SPAȚIU sunt refuzate zgomotos, nu absorbite tăcut", async () => {
  // Spațiul nu poate fi separator — e singurul caracter pe care un formular web
  // îl adaugă singur în jurul lui `:` și `,`, iar dacă ar despărți perechi, o
  // valoare bună cu un spațiu în plus s-ar rupe în bucăți. Deci forma asta se
  // REFUZĂ, și trebuie să se refuze cu zgomot: 500 „nu sunt configurat" plus o
  // linie în jurnal care spune CÂTE intrări s-au ignorat. Alternativa măsurată e
  // 401 la fiecare bătaie, cu jurnalul gol și cu valoarea arătând corect în
  // panou — adică ore de căutat cauza în partea greșită.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A} d4e5f6:${KEY_B}` });
  const log = captureLog();
  let a: number, b: number;
  try {
    a = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
    b = (await send("d4e5f6", KEY_B, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(a, 500, "segmentul lipit a fost acceptat ca pereche");
  assert.equal(b, 500);
  const ignorate = log.lines.filter((l) => l.join(" ").includes("ignorate"));
  assert.equal(ignorate.length, 2, "segmentul greșit nu s-a numărat ca intrare ignorată");
  assert.match(ignorate[0].join(" "), /\b1\b/, "avertismentul nu spune CÂTE intrări");
  // Și niciun fragment de cheie în jurnal: e o suprafață pe care o citește și
  // panoul găzduirii, nu doar operatorul.
  for (const line of log.lines) {
    assert.ok(!line.join(" ").includes(KEY_B), `jurnalul a scris o cheie: ${line.join(" ")}`);
  }
  assert.deepEqual(await withBeats(), []);
});

test("un CR singur desparte perechile, ca `,` și `;`", async () => {
  // `\r` e în `PAIR_SEPARATORS` pe lângă `\n`, și nu e decorativ. La CRLF chiar
  // ar fi: `\n` desparte deja, iar `.trim()` mătură CR-ul rămas la capătul
  // segmentului. Ce acoperă `\r` singur e o valoare cu terminații de linie
  // VECHI — un fișier `.env` construit pe altă mașină și importat în panou, care
  // e singura operație ce chiar schimbă o variabilă acolo
  // (watcher/INCARCARE-HOSTINGER.md).
  //
  // Fără `\r` în clasă, valoarea rămâne UN segment: cheia primei instanțe
  // înghite un caracter care nu e de cheie, `SECRET_CHARS` o refuză, din valoare
  // nu mai iese nicio pereche, deci `broken` — adică 500 la fiecare bătaie, de
  // la TOATE serverele, pe o valoare care în panou arată corectă.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A}\rd4e5f6:${KEY_B}` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 200,
    "un CR singur nu a despărțit perechile");
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 200,
    "a doua pereche a fost înghițită de cheia primei");
  // Cheile nu s-au amestecat: fără asta, testul ar trece și dacă parserul ar da
  // aceeași cheie amândurora.
  assert.equal((await send("a1b2c3", KEY_B, { seq: 2 })).status, 401);
});

test("un separator neanticipat în cheie e refuzat, nu păstrat ca parte din ea", async () => {
  // `PAIR_SEPARATORS` acoperă separatorii pe care i-ar scrie un om ca listă;
  // lista aia nu poate fi completă. Regula care închide clasa e alfabetul
  // cheii: orice caracter care nu e din hexa/base64 înseamnă că segmentul a
  // înghițit altceva. Fără ea, `|` — sau tab, sau orice a inventat cineva — ar
  // deveni tăcut parte din cheia primei instanțe, adică exact eșecul reparat.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A}|d4e5f6:${KEY_B}` });
  const log = captureLog();
  let status: number;
  try {
    status = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(status, 500, "cheia a înghițit un caracter care nu e de cheie");
  assert.equal(log.lines.filter((l) => l.join(" ").includes("ignorate")).length, 1,
    "segmentul greșit nu s-a numărat ca intrare ignorată");
});

test("o cheie hexa obișnuită trece prin alfabetul cheii", async () => {
  // Podeaua alfabetului: `SECRET_CHARS` e o listă închisă, iar o listă închisă
  // scrisă prea strâns transformă o instalare corectă — `openssl rand -hex 32`,
  // exact ce cere watcher/INCARCARE-HOSTINGER.md — în 500 la fiecare bătaie. Proba
  // folosește forma reală a cheii, nu una de test.
  const HEXA = "0123456789abcdef".repeat(4);
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${HEXA}` });
  assert.equal((await send("a1b2c3", HEXA, { seq: 1 })).status, 200);
});

test("un identificator repetat strică TOATĂ valoarea, nu «ultima câștigă»", async () => {
  // Două chei pentru aceeași identitate înseamnă că nu știm care e cea bună.
  // „Ultima câștigă" ar alege tăcut una: dacă alege greșit, instanța primește
  // 401 la nesfârșit în timp ce valoarea din panou pare corectă. Un
  // identificator scris de două ori e dovada că valoarea a fost editată
  // greșit, deci nici restul ei nu merită încredere.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},d4e5f6:${KEY_B},a1b2c3:${KEY_B}` });
  assert.equal((await send("a1b2c3", KEY_A, { seq: 1 })).status, 500);
  assert.equal((await send("a1b2c3", KEY_B, { seq: 1 })).status, 500);
  assert.equal((await send("d4e5f6", KEY_B, { seq: 1 })).status, 500);
  assert.deepEqual(await withBeats(), []);
});

test("un identificator care e și nume de proprietate moștenită nu e «duplicat»", async () => {
  // `ID_PATTERN` acceptă `constructor`, `toString`, `valueOf`, `hasOwnProperty`
  // — sunt alfanumerice și încep cu literă, deci nimic nu le oprește să fie
  // identificatori de instanță. Pe un obiect obișnuit însă, `"constructor" in
  // map` e ADEVĂRAT înainte ca cineva să fi scris ceva acolo.
  //
  // Deci cu `in` în locul lui `own`, PRIMA apariție a unui astfel de
  // identificator se declară duplicat, iar un duplicat strică TOATĂ valoarea:
  // 500 „nu sunt configurat" pentru toate serverele, inclusiv cele care n-au
  // nicio legătură cu numele ăla. Adică adăugarea unui server ar opri
  // înregistrarea semnalelor de la toate celelalte, la nesfârșit, pe o valoare
  // care în panou arată perfect corectă. Comentariul din `parsePairsMap` afirmă
  // protecția; testul ăsta e ce o ține în viață.
  const nume = ["constructor", "toString", "valueOf", "hasOwnProperty"];
  assert.equal(nume.length, 4, "lista de nume a ieșit alta — testul nu mai probează ce spune");

  for (let i = 0; i < nume.length; i++) {
    const id = nume[i];
    setEnv({ SENTINEL_INSTANCE_SECRETS: `${id}:${KEY_A},a1b2c3:${KEY_B}` });
    assert.equal((await send(id, KEY_A, { seq: i + 1 })).status, 200,
      `identificatorul ${id} a fost declarat duplicat față de nimic`);
    assert.equal((await send("a1b2c3", KEY_B, { seq: i + 1 })).status, 200,
      `un identificator ca ${id} a stricat perechile bune din aceeași valoare`);
  }
});

test("o instanță configurată cu nume de proprietate moștenită intră în REGISTRU", async () => {
  // Perechea celui de deasupra, pe cealaltă suprafață. `readAll()` adaugă
  // instanțele configurate fără fișier ca înregistrări goale — starea `no-beat`,
  // vizibilă în `/status` și pe pagină. Cu `id in instances` pe un obiect
  // obișnuit, `"constructor" in instances` e adevărat înainte ca cineva să fi
  // scris acolo, deci instanța e sărită și nu apare NICĂIERI până la prima ei
  // bătaie — adică exact în minutele în care operatorul verifică dacă cheia pusă
  // în panou a ajuns unde credea.
  setEnv({
    SENTINEL_INSTANCE_SECRETS: `constructor:${KEY_A},a1b2c3:${KEY_B}`,
    SENTINEL_BEACON_SECRET: undefined,
  });
  assert.deepEqual(Object.keys((await readAll()).instances).sort(),
    ["a1b2c3", "constructor"], "o instanță configurată a lipsit din listă");
});

test("o valoare cu identificator repetat nu anulează cheia moștenită", async () => {
  // Ca la harta JSON stricată: o greșeală făcută la adăugarea unui server nou
  // n-are voie să taie semnalul serverului care merge deja.
  setEnv({ SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},a1b2c3:${KEY_B}` });
  assert.equal((await POST(await beatRequest({}))).status, 200);
});

test("instanțele din formatul cu perechi intră în REGISTRU, deci tăcerea lor alarmează", async () => {
  // Cheia găsită la verificarea semnăturii nu ajunge: dacă instanța nu intră și
  // în registru, martorul n-o așteaptă niciodată, iar un server care moare
  // înainte să trimită prima bătaie nu produce nicio alertă.
  setEnv({
    SENTINEL_INSTANCE_SECRETS: `a1b2c3:${KEY_A},d4e5f6:${KEY_B}`,
    SENTINEL_BEACON_SECRET: undefined,
  });
  assert.deepEqual(Object.keys((await readAll()).instances).sort(), ["a1b2c3", "d4e5f6"]);
});

test("jurnalul spune CÂTE intrări a ignorat, niciodată ce conțineau", async () => {
  // Un mesaj de eroare care conține fragmentul stricat conține o cheie. Iar
  // jurnalul de execuție al găzduirii e o suprafață pe care o citește panoul,
  // nu doar operatorul.
  const CHEIE_DE_TEST = "zzzcheiecarenutrebuiesaaparazzz";
  setEnv({ SENTINEL_INSTANCE_SECRETS: `id nevalid:${CHEIE_DE_TEST}` });
  const log = captureLog();
  let status: number;
  try {
    status = (await send("a1b2c3", KEY_A, { seq: 1 })).status;
  } finally {
    log.restore();
  }
  assert.equal(status, 500, "o valoare din care nu iese nicio pereche nu a dat 500");

  const ignorate = log.lines.filter((l) => l.join(" ").includes("ignorate"));
  assert.equal(ignorate.length, 1, "nu s-a scris nimic despre intrarea ignorată");
  assert.match(ignorate[0].join(" "), /\b1\b/, "avertismentul nu spune CÂTE intrări");
  for (const line of log.lines) {
    const text = line.join(" ");
    assert.ok(!text.includes(CHEIE_DE_TEST), `jurnalul a scris cheia: ${text}`);
    assert.ok(!text.includes("zzzcheie"), `jurnalul a scris un fragment din cheie: ${text}`);
    assert.ok(!text.includes("nevalid"), `jurnalul a scris valoarea intrării: ${text}`);
  }
});

test("eticheta primită e păstrată, tăiată la lungime și nu devine identitate", async () => {
  await POST(await beatRequest({
    instance: "a1b2c3",
    key: KEY_A,
    payload: beatPayload({ instance_id: "a1b2c3", instance_label: "x".repeat(200) }),
  }));
  const state = await readAll();
  assert.equal(state.instances.a1b2c3?.last?.label?.length, 64);
  assert.deepEqual(await withBeats(), ["a1b2c3"], "eticheta a creat o instanță");
});

test("o etichetă cu caractere imposibile e curățată la primire", async () => {
  // Un surogat neperecheat nu se poate codifica în UTF-8. Ajuns în corpul
  // cererii către Telegram, e genul de caracter pentru care API-ul respinge TOT
  // mesajul — deci oprește alerta. Aceeași clasă de eșec ca diacriticul care a
  // ținut canalul de alertare oprit o zi, doar cu alt caracter.
  //
  // Corpul se construiește cu `JSON.stringify`, nu cu `canonical()`: din E2.1
  // forma canonică REFUZĂ surogatii neîmperecheati — vezi contractul din
  // `sentinel/report/signing.py`. Adică exact ce trebuie: un expeditor conform
  // nu poate produce corpul ăsta. Ruta îl poate primi totuși, de la unul stricat
  // sau ostil, iar curățarea de mai jos e ce se întâmplă atunci — deci testul
  // pune octeții pe fir de mână. `JSON.stringify` scrie surogatul ca `\\uD800`,
  // deci ajunge întreg în `JSON.parse` la celălalt capăt.
  await POST(await beatRequest({
    instance: "a1b2c3",
    key: KEY_A,
    raw: JSON.stringify(beatPayload({
      instance_id: "a1b2c3",
      instance_label: "web\n\uD800prod🚀",
    })),
  }));
  const label = (await readAll()).instances.a1b2c3?.last?.label;
  assert.equal(label, "webprod🚀", "eticheta nu a fost curățată corect");
});
