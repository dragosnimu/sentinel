/**
 * Autorizarea multi-instanță, probată prin RUTE REALE și prin efect.
 *
 * Ce se strică fără regulile de aici, în termeni de operator:
 *
 *   * **omul greșit vede serverul greșit.** Un cont care primește „toate
 *     instanțele" în loc de „niciuna" nu produce nicio eroare: panoul arată
 *     plin, totul pare să meargă, iar defectul se descoperă când cineva
 *     recunoaște în listă un server care nu e al lui. E o scurgere de date între
 *     clienți, nu o problemă de afișare;
 *   * **harta serverului celuilalt, prin coduri de stare.** Un 403 pentru
 *     „incidentul ăsta nu e al tău" spune că incidentul EXISTĂ. Cine cere id-uri
 *     la rând află câte incidente are celălalt server și când apar, fără să vadă
 *     vreun rând. De-aia răspunsul e 404 — și trebuie să fie identic LA OCTET cu
 *     cel pentru un id care nu există nicăieri, altfel diferența e chiar
 *     oracolul;
 *   * **un drept retras care rămâne valabil o zi.** Sesiunile trăiesc 12 ore. Un
 *     panou care ține drepturile în sesiune ar aplica retragerea la următoarea
 *     autentificare, adică mult după ce operatorul a crezut că a luat accesul.
 *
 * ## Contul de probă are drept pe DOUĂ instanțe, nu pe una
 *
 * Regula asta e scrisă cu cerneală, fiindcă lipsa ei a lăsat o scurgere reală
 * verde peste toată suita. `incidentTimeline` poartă două filtre pe aceeași
 * coloană: `instance_id = ?` (cronologia ACESTUI incident) și `instance_id IN
 * (…)` (autorizarea). Cu un cont care vede o singură instanță, al doilea îl
 * ASCUNDE pe primul: rândurile celuilalt server sunt oricum excluse de `IN
 * (prod-a)`, deci `instance_id = ?` se poate șterge fără ca nimic să se
 * înroșească — probat, 478 verzi cu filtrul scos. Iar efectul pe un cont cu
 * două servere, cazul normal al unui agregator multi-instanță, e că sub un
 * incident al lui A apar acțiunile întâmplate pe B.
 *
 * Deci: **orice probă de autorizare care poate fi făcută cu un cont cu două
 * instanțe se face așa.** Un filtru exterior mai larg decât cel probat e cum
 * arată o gardă goală.
 *
 * ## Nimic nu se afirmă despre forma unui handler
 *
 * Fiecare aserțiune de mai jos se face pe un `Response` întors de funcția rutei,
 * cu dublul pus ÎN LOCUL DRIVERULUI. Sesiunile sunt obținute trecând chiar prin
 * `/login` și `/totp`, cu un cod TOTP calculat din secretul contului — deci ce
 * se probează e drumul întreg, nu o schelă care sare peste el.
 *
 * ## O parte din garda asta o ține COMPILATORUL, nu `node --test`
 *
 * `neverCalled` de la capătul fișierului nu se execută niciodată: liniile ei sunt
 * marcate `@ts-expect-error`, iar dacă vreuna dintre ele ar începe să compileze,
 * `npm run typecheck` pică. Aia e proba pentru „o funcție de acces la date
 * chemată fără `allowedInstanceIds` nu compilează". `node --test` nu o vede;
 * `tsc --noEmit` o vede, și e rulat în aceeași trecere.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as instancesGet } from "../app/api/panel/instances/route";
import { GET as incidentsGet } from "../app/api/panel/incidents/route";
import { GET as incidentGet } from "../app/api/panel/incidents/[id]/route";
import { grantInstance, revokeInstance } from "../lib/auth/accounts";
import {
  MAX_PAGE, MAX_TIMELINE, incidentById, incidentTimeline, listIncidents,
} from "../lib/data/incidents";
import { visibleInstances } from "../lib/data/instances";
import { scopeForUser, scopePlaceholders } from "../lib/auth/scope";
import { TotpCipher, generateSecret } from "../lib/auth/totp";
import {
  PASSWORD, SESSION_SECRET, USERNAME, captureError, captureWarn, completeLogin,
  forgetAuthServer, getRequest, testPasswordHash, useAuthServer,
} from "./auth-routes-harness";
import { readShipped, shippedFiles } from "./shipped-files";
import type { Fixture } from "./auth-routes-harness";
import type { AuthDb } from "../lib/auth/db";
import type { InstanceScope } from "../lib/auth/scope";

const HANDLERS = { loginGet, loginPost, totpGet, totpPost };

const INSTANCE_A = "prod-a";
const INSTANCE_B = "prod-b";
/** A treia instanță NU se înregistrează în `beforeEach`, ci în singurul test care
 *  are nevoie de ea: „un cont fără niciun drept vede ZERO instanțe" numără
 *  `fixture.db.instances.length` și cere exact două. */
const INSTANCE_C = "prod-c";
const SECOND_USER = "ana";

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };
/** Secretul TOTP al celui de-al doilea cont, ca să poată și el să se autentifice. */
let secondSecret: string;

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();

  // Două instanțe înregistrate, ca „vede doar una" să însemne ceva. Fără a doua,
  // un cont care ar vedea TOT ar arăta identic cu unul corect autorizat.
  fixture.db.addInstance(INSTANCE_A, { label: "Serverul A" });
  fixture.db.addInstance(INSTANCE_B, { label: "Serverul B" });

  secondSecret = generateSecret();
  fixture.db.addUser(2, {
    username: SECOND_USER,
    password_hash: await testPasswordHash(),
    role: "viewer",
    totp_secret_enc: new TotpCipher(SESSION_SECRET).encrypt(secondSecret, 2),
    totp_confirmed_at: fixture.db.nowMs,
  });
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

/** Cookie-ul unei sesiuni ÎNTREGI pentru contul implicit al schelei. */
async function signIn(username = USERNAME, totpSecret = fixture.totpSecret)
: Promise<Record<string, string>> {
  const token = await completeLogin(HANDLERS, { username, password: PASSWORD,
                                                totpSecret });
  return { sentinel_session: token };
}

async function grant(username: string, instanceId: string,
                     role = "viewer"): Promise<void> {
  const result = await grantInstance(fixture.db, username, instanceId, role);
  assert.equal(result.ok, true,
               `pregătirea a eșuat: ${result.ok ? "" : result.detail}`);
}

async function body(res: Response): Promise<unknown> {
  return JSON.parse(await res.text());
}

// ---------------------------------------------------------------------------
// Zero instanțe, nu toate
// ---------------------------------------------------------------------------
test("un cont fără niciun drept vede ZERO instanțe, deși există două", async () => {
  // Eșecul pe care îl previne: „vede tot din start". E tăcut — nimic nu pică,
  // nimeni nu vede o eroare — și se descoperă când persoana greșită recunoaște
  // în listă un server care nu e al ei.
  const res = await instancesGet(getRequest("/api/panel/instances",
                                            { cookies: await signIn() }));
  assert.equal(res.status, 200);
  assert.deepEqual(await body(res), { instances: [] });
  // Și instanțele CHIAR există: altfel testul ar trece pe o bază goală.
  assert.equal(fixture.db.instances.length, 2);
});

test("după `grant`, contul vede exact instanța dată — și numai pe ea", async () => {
  await grant(USERNAME, INSTANCE_A, "operator");
  const res = await instancesGet(getRequest("/api/panel/instances",
                                            { cookies: await signIn() }));
  const seen = (await body(res) as { instances: { instanceId: string; role: string }[] })
    .instances;
  assert.deepEqual(seen.map((row) => row.instanceId), [INSTANCE_A]);
  assert.equal(seen[0].role, "operator", "rolul de pe instanță nu vine din grant");
});

test("un drept retras se aplică la URMĂTOAREA cerere, nu la următorul login",
     async () => {
  // Sesiunea trăiește 12 ore. Dacă drepturile ar fi copiate în ea la
  // autentificare, retragerea ar avea efect abia mâine — iar operatorul care
  // tocmai a luat accesul cuiva ar crede că l-a luat.
  await grant(USERNAME, INSTANCE_A);
  const cookies = await signIn();
  const before = await instancesGet(getRequest("/api/panel/instances", { cookies }));
  assert.equal(((await body(before)) as { instances: unknown[] }).instances.length, 1);

  const revoked = await revokeInstance(fixture.db, USERNAME, INSTANCE_A);
  assert.equal(revoked.ok, true);

  const after = await instancesGet(getRequest("/api/panel/instances", { cookies }));
  assert.deepEqual(await body(after), { instances: [] },
                   "aceeași sesiune vede în continuare instanța de la care i s-a " +
                   "luat dreptul");
});

// ---------------------------------------------------------------------------
// Incidentele: lista
// ---------------------------------------------------------------------------
test("lista de incidente conține DOAR instanțele permise", async () => {
  fixture.db.addIncident(INSTANCE_A, { source_id: 11, title: "al lui A" });
  fixture.db.addIncident(INSTANCE_B, { source_id: 22, title: "al lui B" });
  await grant(USERNAME, INSTANCE_A);

  const res = await incidentsGet(getRequest("/api/panel/incidents",
                                            { cookies: await signIn() }));
  const rows = (await body(res) as { incidents: { instanceId: string }[] }).incidents;
  assert.equal(rows.length, 1, "lista a adus și incidentele altei instanțe");
  assert.equal(rows[0].instanceId, INSTANCE_A);
});

test("filtrul e în SQL, nu în JavaScript: interogarea poartă `IN (?)` cu " +
     "instanțele ca parametri", async () => {
  // Un filtru aplicat DUPĂ interogare ar însemna că rândurile celuilalt server
  // au fost deja citite din bază și au trecut prin proces. De acolo până la un
  // răspuns care le conține e o singură scăpare de refactor — și niciun test
  // care se uită doar la ce s-a întors n-ar vedea diferența.
  fixture.db.addIncident(INSTANCE_B, { source_id: 22 });
  await grant(USERNAME, INSTANCE_A);
  fixture.db.statements.length = 0;

  await incidentsGet(getRequest("/api/panel/incidents", { cookies: await signIn() }));

  const query = fixture.db.statements.find(
    (stmt) => stmt.sql.includes("FROM incident_entries"));
  assert.ok(query, "nu s-a interogat deloc tabela de incidente");
  assert.match(query.sql, /instance_id IN \(\?\)/,
               "interogarea nu poartă filtrul de instanțe");
  assert.ok(query.params.includes(INSTANCE_A),
            "instanțele permise nu pleacă spre bază ca parametri");
  assert.ok(!query.sql.includes(INSTANCE_A),
            "identificatorul de instanță e lipit în textul interogării, nu legat " +
            "ca parametru — asta e o injecție care așteaptă primul id cu apostrof");
});

test("lista vine cea mai recentă întâi, și se oprește la `limit`", async () => {
  // Două lucruri care s-ar strica tăcut. **Ordinea**: fără `id` ca departajare,
  // incidentele cu aceeași ultimă detecție ies în ordine arbitrară, iar
  // paginarea sare rânduri. **Plafonul**: fără el, o cerere cu `?limit=1000000`
  // ar citi toată tabela pentru oricine e autentificat.
  //
  // Și, la fel de important: `ORDER BY` / `LIMIT` sunt drum NOU în dublul de
  // bază de date. Un drum din dublu pe care nu se sprijină niciun test e un drum
  // care poate să nu facă nimic, iar atunci probele care trec prin el nu probează
  // ce cred ele.
  const day = 24 * 3600 * 1000;
  fixture.db.addIncident(INSTANCE_A, { source_id: 1, title: "vechi",
                                       last_detection_at: fixture.db.nowMs - day });
  fixture.db.addIncident(INSTANCE_A, { source_id: 2, title: "nou",
                                       last_detection_at: fixture.db.nowMs });
  fixture.db.addIncident(INSTANCE_A, { source_id: 3, title: "mijloc",
                                       last_detection_at: fixture.db.nowMs - 60_000 });
  await grant(USERNAME, INSTANCE_A);
  const cookies = await signIn();

  const all = await incidentsGet(getRequest("/api/panel/incidents", { cookies }));
  assert.deepEqual(
    ((await body(all)) as { incidents: { title: string }[] })
      .incidents.map((row) => row.title), ["nou", "mijloc", "vechi"],
    "lista nu vine cea mai recentă întâi");

  const two = await incidentsGet(getRequest("/api/panel/incidents?limit=2",
                                            { cookies }));
  assert.deepEqual(
    ((await body(two)) as { incidents: { title: string }[] })
      .incidents.map((row) => row.title), ["nou", "mijloc"],
    "`limit` nu a tăiat lista");

  // Un `limit` peste plafon se STRÂNGE, nu se refuză: un 400 ar fi o suprafață
  // de mesaje în plus fără nimic câștigat.
  fixture.db.statements.length = 0;
  const huge = await incidentsGet(getRequest("/api/panel/incidents?limit=1000000",
                                             { cookies }));
  assert.equal(huge.status, 200);
  const asked = fixture.db.statements.find(
    (stmt) => stmt.sql.includes("FROM incident_entries")
              && stmt.sql.includes("LIMIT ?"));
  assert.ok(asked, "interogarea listei nu mai poartă LIMIT");
  assert.equal(asked.params[asked.params.length - 1], MAX_PAGE,
               "`limit` cerut de client a ajuns nestrâns la bază");

  // Departajarea, afirmată pe TEXTUL instrucțiunii și nu pe rândurile întoarse,
  // fiindcă dublul nu o poate proba: `Array.prototype.sort` e STABILĂ în V8, deci
  // rândurile cu aceeași ultimă detecție ar ieși în aceeași ordine și fără
  // `id DESC` — o probă care ar trece din alt motiv decât cel adevărat. MariaDB
  // nu promite nimic la egalitate, iar simptomul e o paginare care sare rânduri.
  // Aserțiunea asta e din clasa celor pe TEXT: apără decizia, nu o dovedește.
  assert.match(asked.sql, /ORDER BY last_detection_at DESC, id DESC/,
               "ordonarea nu mai are o departajare stabilă");
});

// ---------------------------------------------------------------------------
// 404, identic la octet
// ---------------------------------------------------------------------------
test("un incident al altei instanțe → 404 IDENTIC LA OCTET cu un id inexistent",
     async () => {
  // Criteriul de acceptanță al piesei, verificat pe octeți și nu pe formă: orice
  // diferență — un cuvânt în mesaj, un antet, un spațiu în JSON — e chiar
  // oracolul care spune că obiectul există.
  const onB = fixture.db.addIncident(INSTANCE_B, { source_id: 22 });
  await grant(USERNAME, INSTANCE_A);
  const cookies = await signIn();

  const denied = await incidentGet(
    getRequest(`/api/panel/incidents/${onB.id}`, { cookies }),
    { params: Promise.resolve({ id: String(onB.id) }) });
  const missing = await incidentGet(
    getRequest("/api/panel/incidents/999999", { cookies }),
    { params: Promise.resolve({ id: "999999" }) });

  assert.equal(denied.status, 404, "un obiect al altei instanțe nu a dat 404");
  assert.equal(missing.status, 404);

  const deniedBytes = Buffer.from(await denied.arrayBuffer());
  const missingBytes = Buffer.from(await missing.arrayBuffer());
  assert.ok(deniedBytes.length > 0, "corpul e gol: comparația n-ar dovedi nimic");
  assert.ok(deniedBytes.equals(missingBytes),
            `corpurile diferă:\n  refuzat: ${deniedBytes.toString("utf8")}\n` +
            `  inexistent: ${missingBytes.toString("utf8")}`);

  // Și antetele, tot: un `Retry-After` sau un `Content-Length` diferit ar spune
  // același lucru ca un corp diferit.
  assert.deepEqual([...denied.headers].sort(), [...missing.headers].sort());

  // Iar incidentul CHIAR există — altfel cele două cazuri ar fi același caz.
  assert.equal(fixture.db.incidentEntries.length, 1);
});

test("un id malformat primește același 404, nu un 400 care l-ar deosebi",
     async () => {
  // Un 400 pentru „id nevalid" ar împărți spațiul id-urilor în „valide" și
  // „nevalide", iar mulțimea celor valide e chiar informația care se apără.
  //
  // Contul TREBUIE să aibă drepturi, și asta e jumătatea care lipsea: până pe
  // 17 august 2026 proba se făcea cu un cont fără nicio instanță, care se
  // oprește în `seesNothing` ÎNAINTE de orice interogare. Toate formele de mai
  // jos primeau 404 din alt motiv decât cel scris aici, iar garda de formă din
  // `incidentById` se putea scoate fără ca nimic să se înroșească. Pe gazdă,
  // scoasă, `WHERE id = NaN` e `ERROR 1054` la MariaDB, deci „abc" ar da 503 și
  // „999999" 404 — exact oracolul pe care testul ăsta pretinde că îl închide.
  await grant(USERNAME, INSTANCE_A);
  await grant(USERNAME, INSTANCE_B);
  const cookies = await signIn();
  const shapes = ["abc", "0", "-3", "", "1e999", "5x"];
  const missing = await incidentGet(
    getRequest("/api/panel/incidents/999999", { cookies }),
    { params: Promise.resolve({ id: "999999" }) });
  const expected = Buffer.from(await missing.arrayBuffer());
  assert.equal(missing.status, 404);

  for (const id of shapes) {
    const res = await incidentGet(
      getRequest(`/api/panel/incidents/${id}`, { cookies }),
      { params: Promise.resolve({ id }) });
    assert.equal(res.status, 404, `id-ul „${id}” nu a dat 404`);
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(expected),
              `id-ul „${id}” a primit alt corp decât un id inexistent`);
  }

  // Și drumul CHIAR duce la o interogare: un id valid al unei instanțe permise
  // se vede. Fără jumătatea asta, proba ar trece și pentru o rută care răspunde
  // 404 la orice.
  const mine = fixture.db.addIncident(INSTANCE_A, { source_id: 11 });
  const found = await incidentGet(
    getRequest(`/api/panel/incidents/${mine.id}`, { cookies }),
    { params: Promise.resolve({ id: String(mine.id) }) });
  assert.equal(found.status, 200, "ruta răspunde 404 la orice, deci probele de " +
                                  "mai sus nu deosebesc nimic");
});

test("un incident al instanței permise se vede întreg, cu cronologia lui",
     async () => {
  // Cealaltă jumătate a regulii: dacă nimic nu s-ar vedea niciodată, toate
  // testele de refuz de mai sus ar trece degeaba.
  //
  // Contul primește AMÂNDOUĂ instanțele, și aia e partea care contează. Cu una
  // singură, `instance_id IN (prod-a)` exclude oricum rândul lui B, deci proba
  // ar fi despre filtrul de autorizare și nu despre cel pe care pretinde că-l
  // verifică — iar `instance_id = ?` s-ar putea șterge din `incidentTimeline`
  // fără ca nimic din suită să se înroșească. Un cont cu drept pe două servere
  // e cazul NORMAL al unui agregator multi-instanță, iar acolo cronologia lui B
  // ar apărea sub incidentul lui A: acțiuni, note și verdicte ale altui client,
  // fără nicio eroare nicăieri.
  const mine = fixture.db.addIncident(INSTANCE_A, { source_id: 11, title: "al meu" });
  fixture.db.addIncident(INSTANCE_B, { source_id: 11, title: "al lui B" });
  fixture.db.incidentTimelineEntries.push({
    id: 1, instance_id: INSTANCE_A, source_id: 1, incident_source_id: 11,
    at: fixture.db.nowMs, kind: "detection", actor: null,
  });
  // Aceeași cronologie, cu ACELAȘI `incident_source_id`, pe cealaltă instanță.
  fixture.db.incidentTimelineEntries.push({
    id: 2, instance_id: INSTANCE_B, source_id: 1, incident_source_id: 11,
    at: fixture.db.nowMs, kind: "action", actor: "al lui B",
  });
  await grant(USERNAME, INSTANCE_A);
  await grant(USERNAME, INSTANCE_B);

  const res = await incidentGet(
    getRequest(`/api/panel/incidents/${mine.id}`, { cookies: await signIn() }),
    { params: Promise.resolve({ id: String(mine.id) }) });
  assert.equal(res.status, 200);
  const payload = await body(res) as {
    incident: { title: string; instanceId: string };
    timeline: { kind: string; actor: string | null }[];
    timelineTruncated: boolean;
  };
  assert.equal(payload.incident.title, "al meu");
  assert.equal(payload.incident.instanceId, INSTANCE_A);
  assert.deepEqual(payload.timeline.map((row) => row.kind), ["detection"],
                   "cronologia altei instanțe a intrat sub incidentul ăsta: contul " +
                   "vede două servere, iar rândurile lui B au același " +
                   "`incident_source_id`");
  assert.ok(!payload.timeline.some((row) => row.actor === "al lui B"),
            "un actor de pe celălalt server e citit sub incidentul ăsta");
  assert.equal(payload.timelineTruncated, false);

  // Și rândul lui B CHIAR e acolo, altfel cele două cazuri ar fi același caz.
  assert.equal(fixture.db.incidentTimelineEntries.length, 2);
});

test("cronologia poartă amândouă filtrele de instanță, și fiecare are altă treabă",
     async () => {
  // Aserțiune pe TEXTUL instrucțiunii, din clasa celor care apără o decizie fără
  // s-o dovedească — ca departajarea din `ORDER BY` de mai sus. `instance_id = ?`
  // se poate proba prin efect (testul de dinainte); `instance_id IN (…)` NU se
  // poate, fiindcă pe orice apel legitim perechea vine de la `incidentById`,
  // adică dintr-o interogare deja filtrată. Filtrul de autorizare e acolo pentru
  // apelantul de mâine, care poate n-o să treacă pe acolo.
  const mine = fixture.db.addIncident(INSTANCE_A, { source_id: 11 });
  await grant(USERNAME, INSTANCE_A);
  await grant(USERNAME, INSTANCE_B);
  fixture.db.statements.length = 0;

  await incidentGet(
    getRequest(`/api/panel/incidents/${mine.id}`, { cookies: await signIn() }),
    { params: Promise.resolve({ id: String(mine.id) }) });

  const query = fixture.db.statements.find(
    (stmt) => stmt.sql.includes("FROM incident_timeline_entries"));
  assert.ok(query, "cronologia nu s-a interogat deloc");
  assert.match(query.sql, /instance_id = \?/,
               "cronologia nu mai e legată de instanța incidentului");
  assert.match(query.sql, /instance_id IN \(\?, \?\)/,
               "interogarea cronologiei nu mai poartă filtrul de autorizare");
  assert.ok(query.params.includes(INSTANCE_A) && query.params.includes(INSTANCE_B),
            "instanțele permise nu pleacă spre bază ca parametri");
});

test("cronologia e MĂRGINITĂ, iar tăierea se spune — nu se ascunde", async () => {
  // Ce se strică fără plafon: un incident de forță brută are cronologia cât
  // detecțiile lui, iar o singură cerere autentificată materializează tot în
  // memoria procesului de pe găzduire. Ce se strică fără fanion: operatorul
  // citește „asta e tot ce s-a întâmplat" dintr-o listă căreia îi lipsește
  // sfârșitul — o unealtă de monitorizare care minte liniștit.
  const mine = fixture.db.addIncident(INSTANCE_A, { source_id: 11 });
  for (let i = 1; i <= MAX_TIMELINE + 3; i++) {
    fixture.db.incidentTimelineEntries.push({
      id: i, instance_id: INSTANCE_A, source_id: 1, incident_source_id: 11,
      at: fixture.db.nowMs + i, kind: "detection", actor: null,
    });
  }
  await grant(USERNAME, INSTANCE_A);
  fixture.db.statements.length = 0;

  const scope = await scopeForUser(fixture.db, 1);
  const timeline = await incidentTimeline(fixture.db, scope,
                                          { instanceId: INSTANCE_A, sourceId: 11 });
  assert.equal(timeline.entries.length, MAX_TIMELINE,
               "cronologia a întors mai mult decât plafonul");
  assert.equal(timeline.truncated, true, "tăierea nu s-a raportat");

  // Plafonul e în SQL, nu o feliere după ce s-au citit toate rândurile: altfel
  // baza tot ar trimite totul, iar plafonul n-ar apăra nimic.
  const query = fixture.db.statements.find(
    (stmt) => stmt.sql.includes("FROM incident_timeline_entries"));
  assert.ok(query, "cronologia nu s-a interogat deloc");
  assert.match(query.sql, /LIMIT \?/, "interogarea cronologiei nu poartă LIMIT");
  assert.equal(query.params[query.params.length - 1], MAX_TIMELINE + 1,
               "se cere exact plafonul, deci „atât era” și „atât am citit” arată " +
               "la fel și tăierea nu se poate afla");

  // Și sub plafon nu se raportează nicio tăiere — altfel fanionul ar fi mereu
  // adevărat, adică n-ar spune nimic.
  fixture.db.incidentTimelineEntries.length = 2;
  const short = await incidentTimeline(fixture.db, scope,
                                       { instanceId: INSTANCE_A, sourceId: 11 });
  assert.equal(short.entries.length, 2);
  assert.equal(short.truncated, false);
  assert.equal(mine.instance_id, INSTANCE_A);
});

// ---------------------------------------------------------------------------
// Cine are voie să întrebe
// ---------------------------------------------------------------------------
test("fără sesiune, rutele de date răspund 401 — și nu ating baza", async () => {
  fixture.db.statements.length = 0;
  const res = await incidentsGet(getRequest("/api/panel/incidents"));
  assert.equal(res.status, 401);
  assert.deepEqual(await body(res), { error: "unauthenticated" });
  assert.deepEqual(fixture.db.statements, [],
                   "o cerere neautentificată a interogat totuși baza");
});

test("o sesiune care a trecut DOAR de parolă nu ajunge la date", async () => {
  // Al doilea factor ar fi ocolibil cerând direct datele, fără să treci prin
  // `/totp`. Sesiunea în așteptare există și e validă — tocmai de-aia contează.
  const pending = await (async () => {
    const { preauthPair, formRequest, cookiesOf } = await import("./auth-routes-harness");
    const pair = await preauthPair(loginGet);
    const res = await loginPost(formRequest(
      "/login", { username: USERNAME, password: PASSWORD, csrf_token: pair.token },
      { cookies: { sentinel_csrf: pair.cookie } }));
    assert.equal(res.status, 303);
    return cookiesOf(res).get("sentinel_session") as string;
  })();

  const res = await instancesGet(getRequest(
    "/api/panel/instances", { cookies: { sentinel_session: pending } }));
  assert.equal(res.status, 401, "o sesiune în așteptarea TOTP a primit date");
});

test("un cont dezactivat pierde accesul la următoarea cerere, nu la următorul login",
     async () => {
  await grant(USERNAME, INSTANCE_A);
  const cookies = await signIn();
  assert.equal((await instancesGet(getRequest("/api/panel/instances", { cookies })))
    .status, 200);

  fixture.user.disabled = 1;

  const after = await instancesGet(getRequest("/api/panel/instances", { cookies }));
  assert.equal(after.status, 401,
               "contul dezactivat citește în continuare, cu sesiunea de dinainte");
});

test("doi oameni, două drepturi: fiecare vede numai ce i s-a dat", async () => {
  // Proba că filtrul chiar depinde de CINE întreabă, nu de o listă memorată
  // undeva. Cu un domeniu global, testele de mai sus ar trece toate.
  fixture.db.addIncident(INSTANCE_A, { source_id: 11 });
  fixture.db.addIncident(INSTANCE_B, { source_id: 22 });
  await grant(USERNAME, INSTANCE_A);
  await grant(SECOND_USER, INSTANCE_B);

  const mine = await incidentsGet(getRequest(
    "/api/panel/incidents", { cookies: await signIn() }));
  const hers = await incidentsGet(getRequest(
    "/api/panel/incidents",
    { cookies: await signIn(SECOND_USER, secondSecret) }));

  assert.deepEqual(
    ((await body(mine)) as { incidents: { instanceId: string }[] })
      .incidents.map((row) => row.instanceId), [INSTANCE_A]);
  assert.deepEqual(
    ((await body(hers)) as { incidents: { instanceId: string }[] })
      .incidents.map((row) => row.instanceId), [INSTANCE_B]);
});

// ---------------------------------------------------------------------------
// Domeniul nu se poate fabrica
// ---------------------------------------------------------------------------
test("un domeniu FABRICAT nu citește nimic — aruncă", async () => {
  // Tipul singur ar fi o afirmație: `{ allowedInstanceIds: ["prod-b"] } as
  // InstanceScope` trece de compilator. Ce trebuie să nu treacă e execuția,
  // altfel prima rută care „știe ce face" își fabrică drepturile dintr-un
  // parametru de URL.
  fixture.db.addIncident(INSTANCE_B, { source_id: 22 });
  const forged = { userId: 1, allowedInstanceIds: [INSTANCE_A, INSTANCE_B],
                   roles: new Map() } as InstanceScope;

  await assert.rejects(() => listIncidents(fixture.db, forged), /scopeForUser/);
  await assert.rejects(() => incidentById(fixture.db, forged, 1), /scopeForUser/);
  await assert.rejects(() => visibleInstances(fixture.db, forged), /scopeForUser/);
});

test("un domeniu LIPSĂ aruncă, nu întoarce tot", async () => {
  // Perechea de execuție a probei de compilare din `neverCalled`: cine ajunge
  // aici printr-un `any` primește o excepție, nu toate instanțele.
  fixture.db.addIncident(INSTANCE_B, { source_id: 22 });
  await assert.rejects(
    () => listIncidents(fixture.db, undefined as unknown as InstanceScope),
    /scopeForUser/);
});

test("un domeniu GOL nu construiește niciodată `IN ()`", async () => {
  // `WHERE instance_id IN ()` e eroare de sintaxă în MariaDB, iar reparația
  // evidentă a unei erori de sintaxă, sub presiune, e scoaterea clauzei — adică
  // toate instanțele, pentru toată lumea. De-aia se oprește mai devreme.
  const empty = await scopeForUser(fixture.db, 1);
  assert.deepEqual(empty.allowedInstanceIds, []);
  assert.throws(() => scopePlaceholders(empty), /IN \(\)/);

  fixture.db.addIncident(INSTANCE_A, { source_id: 11 });
  fixture.db.statements.length = 0;
  assert.deepEqual(await listIncidents(fixture.db, empty), []);
  assert.deepEqual(fixture.db.statements, [],
                   "un cont fără nicio instanță a interogat totuși tabela");
});

test("`scopeForUser` citește drepturile din bază, nu dintr-o listă memorată",
     async () => {
  await grant(USERNAME, INSTANCE_A, "owner");
  await grant(USERNAME, INSTANCE_B, "viewer");
  const scope = await scopeForUser(fixture.db, 1);
  assert.deepEqual([...scope.allowedInstanceIds].sort(), [INSTANCE_A, INSTANCE_B]);
  assert.equal(scope.roles.get(INSTANCE_A), "owner");
  assert.equal(scope.roles.get(INSTANCE_B), "viewer");
  // Alt cont, aceleași rânduri în tabelă: zero.
  assert.deepEqual((await scopeForUser(fixture.db, 2)).allowedInstanceIds, []);
});

// ---------------------------------------------------------------------------
// Un domeniu EMIS nu se poate lărgi
// ---------------------------------------------------------------------------
/**
 * Aceleași câmpuri, fără `readonly` — forma pe care o capătă un domeniu emis
 * după un cast, adică exact ce trebuie să nu meargă la EXECUȚIE. `readonly` e o
 * promisiune făcută compilatorului, iar un cast o retrage fără ca `tsc` să aibă
 * ceva de spus.
 */
type WidenedScope = { -readonly [K in keyof InstanceScope]: InstanceScope[K] };

test("lista unui domeniu emis nu se poate lărgi cu `push`", async () => {
  // Eșecul pe care îl previne, măsurat: două linii puse în `lib/data/instances.ts`
  // — cod livrat, casturi acceptate de `tsc`, suita verde —
  //
  //     (scope.allowedInstanceIds as string[]).push("prod-b");
  //     (scope.roles as Map<string, string>).set("prod-b", "owner");
  //
  // au făcut ca un cont cu drept DOAR pe `prod-a` să primească din
  // `visibleInstances` lista `["prod-a/viewer", "prod-b/owner"]`: serverul altui
  // client în panou, cu un rol pe care nu i l-a dat nimeni, fără nicio excepție
  // și fără nimic în jurnal. Identitatea din `WeakSet` nu vede asta — obiectul
  // CHIAR e unul emis, doar că i s-a scris în el după emitere.
  await grant(USERNAME, INSTANCE_A);
  const scope = await scopeForUser(fixture.db, 1);

  assert.throws(() => (scope.allowedInstanceIds as string[]).push(INSTANCE_B),
                TypeError,
                "lista unui domeniu emis primește instanțe noi după emitere");
  assert.deepEqual([...scope.allowedInstanceIds], [INSTANCE_A]);

  // Și prin EFECT, pe chiar funcția pe care a lărgit-o evadarea măsurată: fără
  // aserțiunea asta, testul ar dovedi doar că `push` aruncă, nu că panoul rămâne
  // îngust.
  const seen = await visibleInstances(fixture.db, scope);
  assert.deepEqual(seen.map((row) => `${row.instanceId}/${row.role}`),
                   [`${INSTANCE_A}/viewer`]);
});

test("rolurile unui domeniu emis nu se pot rescrie: harta n-are cu ce", async () => {
  // Jumătatea pe care un `Object.freeze` superficial NU o acoperă: un `Map`
  // rămâne modificabil oricât de înghețat ar fi obiectul care îl poartă. Iar
  // rolul pe instanță e ce decide acțiunile de scriere în E3c, deci un „owner"
  // fabricat aici nu e un cuvânt greșit în panou, e o acțiune de scriere pe
  // serverul altcuiva.
  await grant(USERNAME, INSTANCE_A, "viewer");
  const scope = await scopeForUser(fixture.db, 1);
  const mutable = scope.roles as Map<string, string>;

  assert.throws(() => mutable.set(INSTANCE_B, "owner"), TypeError,
                "un rol pe o instanță NEPERMISĂ se poate scrie după emitere");
  assert.throws(() => mutable.set(INSTANCE_A, "owner"), TypeError,
                "rolul de pe o instanță permisă se poate ridica după emitere");
  assert.throws(() => mutable.delete(INSTANCE_A), TypeError);
  assert.throws(() => mutable.clear(), TypeError);

  // Și forma la care ajunge cine citește codul și vede că metodele lipsesc: dacă
  // vederea n-are `set`, îl ÎMPRUMUTĂ de la `Map.prototype` și îi dă vederea ca
  // receptor. Ar merge dacă vederea ar fi un `Map` deghizat — un obiect cu
  // slotul intern al hărții, peste care s-a pus altceva. Nu e, iar ultima
  // aserțiune e chiar proba: nici măcar CITIREA prin metoda motorului nu o
  // acceptă, deci `data` din închidere nu se atinge pe drumul ăsta.
  assert.throws(() => Map.prototype.set.call(mutable, INSTANCE_B, "owner"), TypeError,
                "`Map.prototype.set` împrumutat a scris în harta de roluri");
  assert.throws(() => Reflect.apply(Map.prototype.clear, mutable, []), TypeError,
                "`Map.prototype.clear` împrumutat a golit harta de roluri");
  assert.throws(() => Map.prototype.get.call(mutable, INSTANCE_A), TypeError,
                "harta de roluri e un `Map` deghizat: metodele motorului o acceptă " +
                "ca receptor, deci harta din închidere e la îndemâna oricui");

  assert.equal(scope.roles.get(INSTANCE_B), undefined);
  assert.equal(scope.roles.get(INSTANCE_A), "viewer");
  const seen = await visibleInstances(fixture.db, scope);
  assert.deepEqual(seen.map((row) => `${row.instanceId}/${row.role}`),
                   [`${INSTANCE_A}/viewer`]);
});

test("vederea de roluri nu minte pe nicio metodă, nu doar pe `get`", async () => {
  // Ce se strică pentru operator: panoul spune despre un cont altceva decât
  // scrie în `user_instances`, fără nicio eroare. `readonlyRoles` a mutat
  // `size`, `has`, `keys`, `values` și `entries` de la garantat-de-motor
  // (`Map.prototype`) la cod scris de mână, iar codul scris de mână se poate
  // înșela. Probate una câte una pe 18 august 2026, toate trei cu suita
  // ÎNTREAGĂ verde și `tsc` la zero: `size: 0`, `values: () => data.keys()`,
  // `has: () => true`. Azi nu le consumă nimic livrat — singurul apelant e
  // `roles.get(id)` din `lib/data/instances.ts` —, deci ce prinde testul ăsta e
  // capcana pentru primul apelant care întreabă „câte instanțe" sau „ce roluri".
  //
  // Garda din `tests/data-scope-coverage.test.ts` NU ține locul ăsta, deși se
  // uită la `roles.values()`: `new Set(roles.values()).size` dă 2 și dacă
  // `values()` întoarce cheile, fiindcă `prod-a` și `prod-b` sunt tot două
  // șiruri distincte.
  //
  // De-aia DOUĂ instanțe cu DOUĂ roluri DIFERITE: altfel `keys()` și `values()`
  // pot trece una drept cealaltă, iar perechile din `entries()` n-ar dovedi că
  // fiecare instanță e legată de rolul ei, ci doar că sunt tot atâtea.
  //
  // Domeniul GOL se citește ÎNAINTE de orice `grant`, fiindcă atunci e gol
  // dintr-un motiv real: e chiar starea unui cont proaspăt creat, pe care capul
  // lui `lib/auth/scope.ts` o numește portantă — absența unui rând înseamnă
  // „nicio instanță", nu „toate".
  const empty = await scopeForUser(fixture.db, 1);

  await grant(USERNAME, INSTANCE_A, "viewer");
  await grant(USERNAME, INSTANCE_B, "owner");
  // Al doilea cont primește TREI instanțe pe DOUĂ roluri: rolul REPETAT e ce
  // arată că `entries` nu deduplică perechile după valoare, iar a treia instanță
  // e chiar cea despre care `has` de mai jos trebuie să spună „nu o are".
  fixture.db.addInstance(INSTANCE_C, { label: "Serverul C" });
  await grant(SECOND_USER, INSTANCE_A, "viewer");
  await grant(SECOND_USER, INSTANCE_B, "viewer");
  await grant(SECOND_USER, INSTANCE_C, "owner");

  const scope = await scopeForUser(fixture.db, 1);
  const threeOnTwoRoles = await scopeForUser(fixture.db, 2);
  const truth = [[INSTANCE_A, "viewer"], [INSTANCE_B, "owner"]];
  const anaTruth = [[INSTANCE_A, "viewer"], [INSTANCE_B, "viewer"],
                    [INSTANCE_C, "owner"]];

  // `size` NU se mai afirmă aici. Trei domenii alese de mână — de 2, de 3 și
  // GOL — închideau literalii, plafonul la 2 și implicitele pe gol, și lăsau
  // deschisă chiar clasa dinăuntru: măsurat pe 18 august 2026, cu `tsc` la zero
  // și suita ÎNTREAGĂ verde (524/524), `data.size > 1 ? data.size : 0` raporta
  // ZERO instanțe pentru un cont cu exact UNA. Acum cardinalitatea e PARAMETRU,
  // în bucla „`size` numără exact câte rânduri a întors `SELECT`-ul" de mai jos.
  // Ce rămâne aici sunt ancorele pe parcurgere, fiindcă ele probează `entries`.

  // Fiecare domeniu se ANCOREAZĂ prin parcurgere: dacă fixtura ar aluneca — o
  // instanță în minus, un drept dat din greșeală —, aserțiunile de sub ea ar
  // coincide vacuu, iar ce se citește ar fi „verde" în loc de „fixtura s-a
  // schimbat". Ancora se înroșește cu mesajul ei în amândouă direcțiile.
  assert.deepEqual([...threeOnTwoRoles.roles.entries()].sort(), anaTruth,
                   "al doilea cont n-a primit exact trei instanțe pe două " +
                   "roluri; `entries` nu mai arată atunci un rol REPETAT, deci " +
                   "n-ar mai deosebi o hartă care deduplică după valoare");

  assert.deepEqual([...empty.roles.entries()], [],
                   "contul de probă avea deja drepturi înainte de primul " +
                   "`grant`; `entries` nu mai e atunci despre domeniul GOL, " +
                   "starea pe care capul lui `lib/auth/scope.ts` o numește portantă");

  assert.equal(scope.roles.has(INSTANCE_A), true);
  assert.equal(scope.roles.has(INSTANCE_B), true);
  // `INSTANCE_C` e acum o instanță ÎNREGISTRATĂ, dată altui cont — deci „nu o
  // are" e despre drepturi, nu despre un identificator care nu există nicăieri.
  assert.equal(scope.roles.has(INSTANCE_C), false,
               "`has` spune „da” despre o instanță pe care contul n-o are");

  assert.equal(scope.roles.get(INSTANCE_A), "viewer");
  assert.equal(scope.roles.get(INSTANCE_B), "owner");
  assert.equal(scope.roles.get(INSTANCE_C), undefined);

  assert.deepEqual([...scope.roles.keys()].sort(), [INSTANCE_A, INSTANCE_B],
                   "`keys` nu întoarce identificatorii de instanță");
  assert.deepEqual([...scope.roles.values()].sort(), ["owner", "viewer"],
                   "`values` nu întoarce ROLURILE — și numărul lor nu deosebește " +
                   "nimic, fiindcă și cheile sunt două șiruri distincte");
  assert.deepEqual([...scope.roles.entries()].sort(), truth,
                   "`entries` nu leagă fiecare instanță de rolul ei");
  assert.deepEqual([...scope.roles].sort(), truth,
                   "iterarea directă nu dă aceleași perechi ca `entries`");

  const walked: string[][] = [];
  scope.roles.forEach((value, key) => { walked.push([key, value]); });
  assert.deepEqual(walked.sort(), truth,
                   "`forEach` nu parcurge aceleași perechi ca `entries`");
});

// ---------------------------------------------------------------------------
// `size`, cu cardinalitatea ca PARAMETRU
// ---------------------------------------------------------------------------

/**
 * Câte instanțe are contul, la fiecare trecere a buclei de mai jos.
 *
 * Niciun număr nu e aici „ca să fie mai multe" — fiecare desparte altă clasă de
 * minciuni pe care `size` le poate spune, iar clasele astea au fost găsite pe
 * rând, fiecare după ce o fixtură aleasă de mână a tăcut despre ea:
 *
 *   * **0** — contul proaspăt creat. Prinde orice implicit pus „ca să nu fie
 *     gol" (`data.size || 99`, `Math.max(data.size, 1)`): un domeniu gol numărat
 *     altfel decât 0 e „toate" scris cu alt număr;
 *   * **1** — clientul cu UN singur server, forma cea mai obișnuită. E chiar
 *     gaura pe care fixtura de dinainte (2, 3, gol) a lăsat-o deschisă:
 *     `data.size > 1 ? data.size : 0` trecea de ea cu suita ÎNTREAGĂ verde;
 *   * **2 și 3** — vecine, deci niciun literal nu le mulțumește pe amândouă; 3
 *     desparte și numărul de INSTANȚE de numărul de roluri DISTINCTE, care pe
 *     domeniile de 1 și 2 coincideau;
 *   * **5 și 11** — peste plafoanele care se scriu de mână într-o aplicație pe
 *     care `package.json` o descrie ca agregator pentru N instanțe: măsurat,
 *     `Math.min(data.size, 3)` se vede pe 5, iar `Math.min(data.size, 10)` abia
 *     pe 11. Cât ține și cât nu ține lista asta e scris o singură dată, la
 *     `readonlyRoles` în `lib/auth/scope.ts`. 11 e și impar, deci alternanța de
 *     roluri iese neechilibrată (6 pe `viewer`, 5 pe `owner`), iar un număr
 *     dedus din roluri nu-l nimerește nici din întâmplare.
 *
 * O dimensiune în plus costă o intrare în lista asta, nu un test nou — și de-aia
 * lista e ce se citește când cineva întreabă pe ce s-a probat `size`.
 */
const CARDINALITIES = [0, 1, 2, 3, 5, 11];

/**
 * Rolurile ALTERNEAZĂ pe instanțe, dinadins.
 *
 * Cu un singur rol pe toate, `keys()` și `values()` pot trece unul drept altul,
 * iar perechile din `entries()` n-ar dovedi că fiecare instanță e legată de
 * rolul EI, ci doar că sunt tot atâtea — vezi testul de mai sus. Amândouă
 * valorile sunt din `INSTANCE_ROLES`, iar contul implicit al schelei are
 * `users.role = "owner"`, deci niciun drept dat aici nu-l depășește.
 */
function alternatingRole(index: number): string {
  return index % 2 === 0 ? "viewer" : "owner";
}

for (const n of CARDINALITIES) {
  // Numărul intră în NUMELE testului, nu doar în aserțiuni: cine citește
  // ieșirea suitei vede pe ce cardinalități a rulat garda, fără să deschidă
  // fișierul — iar o listă parametrizată ieșită goală se vede atunci ca lipsă.
  test("`size` numără exact câte rânduri a întors `SELECT`-ul: " + n +
       (n === 1 ? " instanță" : " instanțe"), async () => {
    // Ce se strică pentru operator: panoul spune „ai atâtea servere" altceva
    // decât scrie în `user_instances`, fără nicio eroare și fără nimic în
    // jurnal. `size` e o valoare COPIATĂ la emitere în `readonlyRoles`
    // (`lib/auth/scope.ts`), nu numărătoarea motorului — iar o valoare scrisă de
    // mână se poate înșela pe o dimensiune și nimeri pe toate celelalte. Măsurat
    // pe 18 august 2026, cu `size` afirmat doar pe 2, pe 3 și pe gol:
    // `data.size > 1 ? data.size : 0` raporta ZERO instanțe pentru un cont cu
    // exact UNA, cu `tsc` la zero și cu suita ÎNTREAGĂ verde (524/524).
    const truth: string[][] = [];
    for (let i = 0; i < n; i += 1) {
      const id = `prod-${i}`;
      fixture.db.addInstance(id, { label: `Serverul ${i}` });
      await grant(USERNAME, id, alternatingRole(i));
      truth.push([id, alternatingRole(i)]);
    }
    // Fixtura, verificată pe ea însăși: dacă `alternatingRole` ar ajunge să dea
    // un singur rol, `new Set(data.values()).size` pus pe `size` ar înceta să se
    // mai deosebească de numărul de instanțe pe jumătate din lista de mai sus,
    // iar bucla ar rămâne verde cu mai puțin decât spune despre ea.
    if (n >= 2) {
      assert.equal(new Set(truth.map(([, role]) => role)).size, 2,
                   "rolurile nu mai alternează pe cele " + n + " instanțe");
    }

    const scope = await scopeForUser(fixture.db, 1);

    // ANCORA, înaintea oricărui număr: ce s-a semănat chiar e ce s-a citit. Fără
    // ea, un `grant` care n-ar ajunge în bază ar face și numărul cerut, și
    // lungimea parcurgerii să coincidă pe un domeniu mai mic — adică „verde" în
    // loc de „fixtura s-a schimbat". Se compară PERECHILE, nu doar cheile: o
    // alunecare de rol care păstrează dimensiunea trece de `keys()`.
    assert.deepEqual([...scope.roles.entries()].sort(), [...truth].sort(),
                     "domeniul citit nu are chiar instanțele semănate (" + n +
                     ") cu rolurile lor; numerele de sub ancoră ar coincide " +
                     "atunci vacuu");
    assert.equal(scope.roles.size, n,
                 "`size` nu numără rândurile pe care le-a întors `SELECT`-ul (" +
                 n + ")");
    assert.equal(scope.roles.size, [...scope.roles.entries()].length,
                 "`size` spune altceva decât se poate parcurge din hartă, pe " +
                 "domeniul de " + n);
  });
}

test("`forEach` pe roluri nu împrumută harta din care citește", async () => {
  // Ușa pe care o lasă deschisă chiar apărarea, dacă e scrisă în grabă: o hartă
  // doar-citire care își deleagă `forEach` unui `Map` adevărat dă callback-ului,
  // ca al treilea argument, exact harta aia. Atunci
  // `scope.roles.forEach((_v, _k, m) => (m as Map<string, string>).set(…))`
  // lărgește domeniul prin poarta pusă ca să-l îngusteze.
  await grant(USERNAME, INSTANCE_A, "viewer");
  const scope = await scopeForUser(fixture.db, 1);

  let handed = 0;
  scope.roles.forEach((value, key, map) => {
    handed += 1;
    assert.equal(key, INSTANCE_A);
    assert.equal(value, "viewer");
    assert.throws(() => (map as Map<string, string>).set(INSTANCE_B, "owner"),
                  TypeError, "`forEach` a dat mai departe o hartă modificabilă");
  });
  assert.equal(handed, 1,
               "`forEach` n-a chemat callback-ul, deci aserțiunea de sus n-a rulat");
  assert.equal(scope.roles.get(INSTANCE_B), undefined);
});

test("nici câmpurile întregi nu se pot înlocui într-un domeniu emis", async () => {
  // A treia cale, pe care n-a folosit-o niciuna dintre probele de până acum: nu
  // scrii ÎN listă, ci pui altă listă în locul ei. Patru forme care ajung la
  // același rezultat dacă obiectul emis e „doar-citire" numai pentru compilator,
  // plus schimbarea prototipului — care nu lărgește nimic singură, dar deschide
  // drumul spre un `get` fabricat pe lanțul de prototipuri.
  //
  // Aceleași forme se dau pe urmă și pe `scope.roles`, fiindcă acolo le oprește
  // ALT înghețat — cel din `readonlyRoles`, nu cel din `register`. Verificarea
  // de efect de la coadă e una singură pentru amândouă: `visibleInstances` merge
  // pe listă ȘI cheamă `roles.get(id)`, deci o listă lărgită și un rol fabricat
  // se văd amândouă în ea.
  await grant(USERNAME, INSTANCE_A, "viewer");
  const scope = await scopeForUser(fixture.db, 1);
  const wide = [INSTANCE_A, INSTANCE_B];

  assert.throws(() => Object.assign(scope, { allowedInstanceIds: wide }), TypeError,
                "`Object.assign` a înlocuit lista de instanțe a unui domeniu emis");
  assert.throws(
    () => Object.defineProperty(scope, "roles",
                                { value: new Map([[INSTANCE_B, "owner"]]) }),
    TypeError, "`defineProperty` a înlocuit harta de roluri a unui domeniu emis");
  assert.throws(() => { (scope as WidenedScope).allowedInstanceIds = wide; },
                TypeError, "atribuirea directă a înlocuit lista de instanțe");
  assert.throws(() => (scope.allowedInstanceIds as string[]).splice(0, 1, INSTANCE_B),
                TypeError, "`splice` a rescris lista pe loc");
  assert.throws(() => Object.setPrototypeOf(scope, { userId: 1 }), TypeError,
                "prototipul unui domeniu emis se poate schimba");

  // Aceleași forme, mutate pe `scope.roles` — unde înghețul de mai sus NU
  // ajunge: el oprește înlocuirea lui `scope.roles`, nimic din el nu oprește
  // înlocuirea lui `scope.roles.get`. Măsurat pe 18 august 2026, cu
  // `Object.freeze` scos DOAR de pe vedere și cu tot restul apărării la locul
  // lui, `tsc` la zero și suita ÎNTREAGĂ verde:
  //
  //     Object.assign(scope.roles, { get: () => "owner" });
  //
  // Nu cere niciun cast — `ReadonlyMap.get` e o metodă, nu un câmp `readonly` —
  // și a ridicat ce citește panoul din `prod-a/viewer` în `prod-a/owner`. E mai
  // rău decât evadarea cu `set`, care măcar avea nevoie de un cast la `Map`: un
  // „owner" fabricat aici e o acțiune de scriere pe serverul altcuiva în E3c.
  const rolesView = scope.roles as unknown as Record<string, unknown>;
  const forgedGet = (): string => "owner";

  assert.throws(() => Object.assign(scope.roles, { get: forgedGet }), TypeError,
                "`Object.assign` a înlocuit `get`-ul hărții de roluri");
  assert.throws(
    () => Object.defineProperty(scope.roles, "get", { value: forgedGet }),
    TypeError, "`defineProperty` a înlocuit `get`-ul hărții de roluri");
  assert.throws(() => { rolesView.get = forgedGet; }, TypeError,
                "atribuirea directă a înlocuit `get`-ul hărții de roluri");
  assert.throws(() => { delete rolesView.get; }, TypeError,
                "`get`-ul hărții de roluri se poate ȘTERGE — deci și pune la loc");
  assert.throws(() => { rolesView.set = () => undefined; }, TypeError,
                "harta de roluri a primit scriitorul pe care dinadins nu-l are");
  assert.throws(() => Object.setPrototypeOf(scope.roles, { get: forgedGet }),
                TypeError, "prototipul hărții de roluri se poate schimba");

  const seen = await visibleInstances(fixture.db, scope);
  assert.deepEqual(seen.map((row) => `${row.instanceId}/${row.role}`),
                   [`${INSTANCE_A}/viewer`]);
});

/**
 * Fișierele livrate care au voie să înregistreze un obiect ca „emis de mine".
 *
 * Mecanica `WeakSet` e aceeași în amândouă — dinadins aceeași, ca să fie una
 * singură de învățat —, dar registrele sunt separate: un `ThrottlePass` nu poate
 * trece drept domeniu de instanțe și invers. Ce se numără aici sunt locurile din
 * codul livrat care SCRIU `issued.add(` — nu, cum a scris textul ăsta până pe
 * 17 august 2026, toate locurile care pot produce un obiect acceptat de o gardă.
 * Diferența dintre cele două e chiar ce n-a prins recensământul; vezi testul.
 */
const MAY_ISSUE: Record<string, string> = {
  "lib/auth/gate.ts": "`ThrottlePass` — dovada că limitatoarele au fost chiar " +
                      "întrebate înainte de o verificare de parolă",
  "lib/auth/scope.ts": "`InstanceScope` — dovada că lista de instanțe vine dintr-un " +
                       "`SELECT` peste `user_instances`",
};

test("gardă ORIENTATIVĂ: o a doua cale de emitere, scrisă pe față, ridică numărul",
     () => {
  // Recensământul de dinainte era pe `scopeFromIds` — o funcție livrată care
  // fabrica un domeniu autorizat fără nicio citire din `user_instances`, „pentru
  // teste". N-o chema nimeni: nici cod livrat, nici vreun test (proba de domeniu
  // fabricat de mai sus folosește dinadins un cast, ca să treacă prin
  // `assertScope`). A fost scoasă, fiindcă o scurtătură nefolosită spre
  // autorizare e tot o scurtătură.
  //
  // Ce se numără acum e EMITEREA, iar eșecul pe care îl previne e o funcție care
  // întoarce un obiect acceptat de `assertScope` fără ca vreun `SELECT` să fi
  // spus cine ce vede — adică autorizare scrisă de cel care cere.
  //
  // ## Ce NU prinde, măsurat, nu presupus
  //
  // Testul ăsta e o gardă pe ORTOGRAFIE, deci prinde scurtătura scrisă din
  // neatenție și nu pe cea scrisă anume ca să treacă de el. Verificatorul a
  // probat două evadări, amândouă cu suita verde ȘI `tsc` la zero:
  //
  //     const mint = issued;   +   export function scopeAnyone(ids) { mint.add(…) }
  //     export function register(…)   +   un fișier livrat nou care îl cheamă
  //
  // La prima, `assertScope` a acceptat un domeniu fabricat fără niciun `SELECT`.
  // Un al treilea recensământ pe șir ar fi evadat la fel, deci nu s-a scris:
  // ce ar face proprietatea structurală e o schimbare de proiectare, scrisă la
  // `register` în `lib/auth/scope.ts`, și e o decizie de operator.
  //
  // Ce rămâne, și e treaba lui: dacă cineva adaugă a doua cale FĂRĂ să încerce
  // s-o ascundă — cazul obișnuit —, numărul de mai jos nu mai iese.
  const minting = shippedFiles().filter(
    (file) => readShipped(file).includes("issued.add("));
  assert.deepEqual(minting, Object.keys(MAY_ISSUE).sort(),
                   "un fișier livrat înregistrează obiecte de identitate pe lângă " +
                   "cele declarate în MAY_ISSUE");

  const scope = readShipped("lib/auth/scope.ts");
  assert.equal((scope.match(/issued\.add\(/g) ?? []).length, 1,
               "`lib/auth/scope.ts` are mai mult de un loc care înregistrează un " +
               "domeniu ca emis; al doilea nu citește neapărat `user_instances`");
  // `register(` apare exact de două ori: definiția și singurul apel, cel din
  // `scopeForUser`. Un al treilea ar fi o a doua cale de emitere.
  assert.equal((scope.match(/\bregister\(/g) ?? []).length, 2,
               "`register` are alt apelant în afară de `scopeForUser`");
  assert.match(scope, /return register\(\{ userId, allowedInstanceIds, roles \}\)/,
               "`scopeForUser` nu mai e cel care emite domeniul");

  // Și `scopeFromIds` chiar a dispărut ca FUNCȚIE din tot codul livrat. Se caută
  // cu paranteză dinadins: numele ei mai apare o dată, în proza care spune de ce
  // a fost scoasă, iar o gardă care ar înroși la o explicație e o gardă pe care
  // o șterge primul om care o citește (același argument ca la `JOIN_MENTIONS`).
  assert.deepEqual(
    shippedFiles().filter((file) => /scopeFromIds\(/.test(readShipped(file))), [],
    "`scopeFromIds` a fost scoasă fiindcă fabrica un domeniu autorizat fără nicio " +
    "citire din `user_instances`; a apărut înapoi");
});

// ---------------------------------------------------------------------------
// Ce dovedește compilatorul, nu `node --test`
// ---------------------------------------------------------------------------
/**
 * Nu se cheamă NICIODATĂ. Ce se probează aici e că fiecare linie NU compilează.
 *
 * `@ts-expect-error` e o aserțiune inversată: dacă linia de sub el ar începe să
 * compileze, `tsc --noEmit` pică pe „unused @ts-expect-error directive". Deci
 * cerința „o funcție de acces la date chemată fără `allowedInstanceIds` nu
 * compilează" e ținută de `npm run typecheck`, nu de suita de mai sus.
 */
export async function neverCalled(db: AuthDb): Promise<void> {
  // @ts-expect-error — fără domeniu, `listIncidents` nu are cum să fie chemată.
  await listIncidents(db);
  // @ts-expect-error — nici `visibleInstances`.
  await visibleInstances(db);
  // @ts-expect-error — nici `incidentById`, care mai are nevoie și de id.
  await incidentById(db);
  // @ts-expect-error — un tablou de șiruri NU e un domeniu citit din bază.
  await listIncidents(db, ["prod-a"]);
}
