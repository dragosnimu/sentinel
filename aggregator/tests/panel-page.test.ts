/**
 * Panoul ca PAGINĂ: ce vede omul care s-a autentificat.
 *
 * `tests/panel-authz.test.ts` probează că stratul de date nu scapă nimic peste
 * granița instanțelor. Fișierul ăsta probează stratul de deasupra lui, care are
 * eșecuri proprii și nu se moștenesc:
 *
 *   * pagina cere o sesiune, iar refuzul ei e o REDIRECTARE, nu un 401 cu corp
 *     JSON — altfel operatorul primește un ecran gol fără nicio cale înainte;
 *   * marcajul nu are `<script>`, fiindcă politica de conținut n-are
 *     `unsafe-inline` și o pagină care cere ce nu poate primi arată stricată
 *     fără să spună de ce;
 *   * titlurile incidentelor sunt text produs din trafic, adică valori pe care
 *     le alege un atacator, deci trec escapate;
 *   * un incident de pe o instanță nevăzută întoarce EXACT ce întoarce un id
 *     inexistent. Ăsta e criteriul de acceptanță scris în plan, și e singurul de
 *     aici care se compară la octet.
 *
 * Sesiunile se obțin trecând prin `/login` și `/totp` cu un cod TOTP adevărat,
 * ca în `panel-authz`: ce se probează e drumul întreg.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as panelGet } from "../app/panel/route";
import { GET as incidenteGet } from "../app/panel/incidente/route";
import { GET as detectiiGet } from "../app/panel/detectii/route";
import { GET as vulnGet } from "../app/panel/vulnerabilitati/route";
import { GET as blocariGet } from "../app/panel/blocari/route";
import { GET as patchGet } from "../app/panel/patch-uri/route";
import { GET as rapoarteGet } from "../app/panel/rapoarte/route";
import { GET as serviciiGet } from "../app/panel/servicii/route";
import { GET as sesiuniGet } from "../app/panel/sesiuni/route";
import { PAGES } from "../lib/panel-page";

import { GET as incidentPageGet } from "../app/panel/incidente/[id]/route";
import { grantInstance } from "../lib/auth/accounts";
import {
  PASSWORD, USERNAME, captureError, captureWarn, completeLogin,
  forgetAuthServer, getRequest, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture } from "./auth-routes-harness";

const HANDLERS = { loginGet, loginPost, totpGet, totpPost };
/** Ruta fiecărei pagini din meniu, ca recensământul să le poată cere pe toate. */
const HANDLERS_PANEL: Record<string, (req: Request) => Promise<Response>> = {
  "/panel": panelGet,
  "/panel/incidente": incidenteGet,
  "/panel/detectii": detectiiGet,
  "/panel/vulnerabilitati": vulnGet,
  "/panel/blocari": blocariGet,
  "/panel/patch-uri": patchGet,
  "/panel/rapoarte": rapoarteGet,
  "/panel/sesiuni": sesiuniGet,
  "/panel/servicii": serviciiGet,
};


const INSTANCE_A = "prod-a";
const INSTANCE_B = "prod-b";

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
  fixture.db.addInstance(INSTANCE_A, { label: "Serverul A" });
  fixture.db.addInstance(INSTANCE_B, { label: "Serverul B" });
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

async function signIn(): Promise<Record<string, string>> {
  const token = await completeLogin(HANDLERS, {
    username: USERNAME, password: PASSWORD, totpSecret: fixture.totpSecret,
  });
  return { sentinel_session: token };
}

async function grant(instanceId: string, role = "owner"): Promise<void> {
  const result = await grantInstance(fixture.db, USERNAME, instanceId, role);
  assert.equal(result.ok, true);
}

test("fără sesiune, panoul REDIRECTEAZĂ la login; nu răspunde 401 JSON",
     async () => {
  // Eșecul pe care îl previne: refuzul rutelor de date, refolosit ca atare pe o
  // pagină. Operatorul cu sesiunea expirată ar primi `{"error":...}` afișat ca
  // text, fără niciun formular și fără nicio legătură înapoi.
  const res = await panelGet(getRequest("/panel"));
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "/login?e=expired");
  const body = await res.text();
  assert.ok(!body.includes("unauthenticated"),
            "refuzul paginii poartă corpul JSON al rutelor de date");
});

test("panoul arată incidentele instanței permise, escapate și fără script",
     async () => {
  // Titlul e ales de un atacator: vine din trafic. Politica ar refuza scriptul,
  // dar marcajul stricat ar ascunde rândurile de dedesubt — iar un incident
  // pierdut dintr-o listă nu se observă niciodată.
  await grant(INSTANCE_A);
  fixture.db.addIncident(INSTANCE_A, {
    source_id: 11, title: "<script>alert(1)</script> & altele", severity: "high",
  });
  const cookies = await signIn();

  const res = await panelGet(getRequest("/panel", { cookies }));
  assert.equal(res.status, 200);
  assert.match(res.headers.get("content-type") ?? "", /text\/html/);
  const html = await res.text();

  assert.ok(!html.includes("<script"),
            "pagina conține un element de script, pe care politica îl refuză");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt; &amp; altele"),
            "titlul nu a fost escapat");
  assert.ok(html.includes("Serverul A"), "instanța permisă nu apare");
  assert.ok(html.includes('href="/panel.css"'),
            "foaia de stil de la aceeași origine lipsește");
});

test("un cont fără niciun drept vede un panou care SPUNE că e gol, nu unul mut",
     async () => {
  // Starea e normală pentru un cont proaspăt, nu o eroare — și arată identic cu
  // „agregatorul e gol", deși reparația celor două e complet diferită.
  fixture.db.addIncident(INSTANCE_A, { source_id: 11, title: "al lui A" });
  const cookies = await signIn();

  const html = await (await panelGet(getRequest("/panel", { cookies }))).text();
  assert.ok(html.includes("nu are drept pe nicio instanță"),
            "panoul gol nu spune de ce e gol");
  assert.ok(!html.includes("al lui A"),
            "un incident de pe o instanță fără drept a ajuns în pagină");
});

test("incidentul altei instanțe dă 404 IDENTIC LA OCTET cu unul inexistent",
     async () => {
  // Criteriul de acceptanță din plan. Un 403 ar confirma existența, iar
  // confirmarea e chiar informația pe care autorizarea o apără: cine numără
  // id-urile ar afla câte incidente are celălalt server.
  await grant(INSTANCE_A);
  const alB = fixture.db.addIncident(INSTANCE_B, {
    source_id: 22, title: "secretul lui B",
  });
  const cookies = await signIn();

  const ascuns = await incidentPageGet(
    getRequest(`/panel/incidente/${alB.id}`, { cookies }),
    { params: Promise.resolve({ id: String(alB.id) }) });
  const inexistent = await incidentPageGet(
    getRequest("/panel/incidente/999999", { cookies }),
    { params: Promise.resolve({ id: "999999" }) });

  assert.equal(ascuns.status, 404);
  assert.equal(inexistent.status, 404);
  assert.equal(await ascuns.text(), await inexistent.text(),
               "cele două refuzuri se pot deosebi, deci existența se poate deduce");
});

test("un id care nu e strict numeric e 404, nu un incident apropiat",
     async () => {
  // `Number.parseInt("12abc")` e 12. Fără verificarea de formă, două adrese
  // diferite ar duce la același incident, iar una dintre ele n-ar apărea în
  // niciun jurnal ca fiind ce a fost.
  await grant(INSTANCE_A);
  const meu = fixture.db.addIncident(INSTANCE_A, { source_id: 11, title: "al meu" });
  const cookies = await signIn();

  const res = await incidentPageGet(
    getRequest(`/panel/incidente/${meu.id}abc`, { cookies }),
    { params: Promise.resolve({ id: `${meu.id}abc` }) });
  assert.equal(res.status, 404);
  assert.ok(!(await res.text()).includes("al meu"));
});

test("pagina unui incident permis arată cronologia și spune când e tăiată",
     async () => {
  // `lib/data/incidents.ts` scrie explicit că cine afișează lista TREBUIE să
  // spună când e trunchiată. O cronologie tăiată tăcut se citește ca „asta a
  // fost tot ce s-a întâmplat".
  await grant(INSTANCE_A);
  const meu = fixture.db.addIncident(INSTANCE_A, {
    source_id: 11, title: "incidentul meu", severity: "medium",
  });
  const cookies = await signIn();

  const res = await incidentPageGet(
    getRequest(`/panel/incidente/${meu.id}`, { cookies }),
    { params: Promise.resolve({ id: String(meu.id) }) });
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes("incidentul meu"));
  assert.ok(html.includes("Cronologie"));
  assert.ok(!html.includes("<script"));
});

// ---------------------------------------------------------------------------
// Selectorul de server
// ---------------------------------------------------------------------------
test("`?instanta=` alege serverul, dar NU poate lărgi ce vede contul", async () => {
  // Eșecul pe care îl previne: selecția vine din URL, deci de la client. Tratată
  // ca domeniu în loc de filtru, ar fi chiar mecanismul prin care cineva cere
  // datele altui server scriind identificatorul lui în bara de adrese.
  //
  // Forma care apără: `WHERE instance_id IN (<domeniu>) AND instance_id = ?`.
  // A doua clauză pare redundantă lângă prima și e exact proprietatea — poate
  // îngusta, niciodată lărgi.
  await grant(INSTANCE_A);
  fixture.db.addIncident(INSTANCE_A, { source_id: 11, title: "al lui A" });
  fixture.db.addIncident(INSTANCE_B, { source_id: 22, title: "secretul lui B" });
  const cookies = await signIn();

  const cerutB = await panelGet(
    getRequest(`/panel?instanta=${INSTANCE_B}`, { cookies }));
  assert.equal(cerutB.status, 200);
  const html = await cerutB.text();
  assert.ok(!html.includes("secretul lui B"),
            "un id scris în URL a adus datele unui server nepermis");
  assert.ok(html.includes("al lui A"),
            "selecția nepermisă n-a căzut pe primul server permis");
});

test("un `?instanta=` inventat nu e o eroare, e o cădere pe primul permis",
     async () => {
  // O legătură veche către un server retras între timp trebuie să ducă la
  // panoul următorului server, nu la un ecran mort. Un 404 aici ar transforma
  // o adresă pusă la favorite într-o pană.
  await grant(INSTANCE_A);
  const cookies = await signIn();

  const res = await panelGet(
    getRequest("/panel?instanta=nu-exista-9xk2", { cookies }));
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes(INSTANCE_A));
});

test("o pagină spune dacă fluxul ei N-A SOSIT vreodată, nu doar că e goală",
     async () => {
  // Cele două stări au reparații complet diferite: „nu s-a întâmplat nimic" e
  // despre server, „nu mi s-a trimis nimic" e despre conductă. Confundate, cine
  // se uită la o listă goală de blocări crede că nu e nimeni blocat.
  await grant(INSTANCE_A);
  const cookies = await signIn();

  const fara = await blocariGet(getRequest("/panel/blocari", { cookies }));
  assert.equal(fara.status, 200);
  const textFara = await fara.text();
  assert.match(textFara, /nu a fost expediat niciodat/,
               "pagina nu spune că fluxul lipsește din conductă");

  // Iar în ziua în care fluxul sosește, mesajul dispare SINGUR — verdictul se
  // citește din `sync_cursors`, nu dintr-o listă scrisă de mână.
  fixture.db.addArrival(INSTANCE_A, "blocklist", 0);
  const cu = await blocariGet(getRequest("/panel/blocari", { cookies }));
  const textCu = await cu.text();
  assert.ok(!/nu a fost expediat niciodat/.test(textCu),
            "mesajul a rămas deși fluxul chiar a sosit");
  assert.match(textCu, /n-a adus niciun rând/,
               "flux sosit fără rânduri trebuie spus altfel decât flux absent");
});

test("fiecare pagină din meniu răspunde 200 și poartă meniul", async () => {
  // Recensământ, nu listă scrisă de mână: o pagină adăugată în `PAGES` fără
  // rută trece de aici doar dacă chiar răspunde. Fără el, o intrare de meniu
  // care duce la 404 se descoperă de cineva care dă clic.
  await grant(INSTANCE_A);
  const cookies = await signIn();

  for (const page of PAGES) {
    const handler = HANDLERS_PANEL[page.href];
    assert.ok(handler, `pagina ${page.href} e în meniu și n-are rută în test`);
    const res = await handler(getRequest(page.href, { cookies }));
    assert.equal(res.status, 200, `${page.href} a răspuns ${res.status}`);
    const html = await res.text();
    assert.match(html, /class="meniu"/, `${page.href} nu poartă meniul`);
    assert.ok(!html.includes("<script"), `${page.href} conține un script`);
  }
});

// ---------------------------------------------------------------------------
// Vulnerabilități: grupele de stare
// ---------------------------------------------------------------------------
test("filtrul de grupă arată DOAR stările grupei, iar numerele sunt ale ei",
     async () => {
  // Cererea operatorului: „ce e rezolvat, ce nu e aplicat". Vocabularul are însă
  // șapte stări, iar două dintre ele — `accepted_risk`, `false_positive` — sunt
  // închise FĂRĂ reparație. Puse la rezolvate, pagina ar pretinde o reparație
  // care n-a existat; puse la neaplicate, ar bate la cap cu lucruri închise
  // deliberat. De-aia sunt trei grupe, iar testul le cere pe toate trei.
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, status: "open", cve: "CVE-DESCHIS" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 2, status: "patching", cve: "CVE-INLUCRU" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 3, status: "resolved", cve: "CVE-REZOLVAT" });
  fixture.db.addFinding(INSTANCE_A, { source_id: 4, status: "false_positive", cve: "CVE-FALS" });
  const cookies = await signIn();

  const toate = await (await vulnGet(
    getRequest("/panel/vulnerabilitati", { cookies }))).text();
  for (const cve of ["CVE-DESCHIS", "CVE-INLUCRU", "CVE-REZOLVAT", "CVE-FALS"]) {
    assert.ok(toate.includes(cve), `${cve} lipsește din lista completă`);
  }

  const neaplicate = await (await vulnGet(
    getRequest("/panel/vulnerabilitati?grupa=neaplicate", { cookies }))).text();
  assert.ok(neaplicate.includes("CVE-DESCHIS"));
  assert.ok(neaplicate.includes("CVE-INLUCRU"), "o constatare în curs de patch-uire nu e aplicată");
  assert.ok(!neaplicate.includes("CVE-REZOLVAT"), "o constatare rezolvată apare la neaplicate");
  assert.ok(!neaplicate.includes("CVE-FALS"),
            "un fals pozitiv apare la neaplicate, deci bate la cap cu ceva închis deliberat");

  const rezolvate = await (await vulnGet(
    getRequest("/panel/vulnerabilitati?grupa=rezolvate", { cookies }))).text();
  assert.ok(rezolvate.includes("CVE-REZOLVAT"));
  assert.ok(!rezolvate.includes("CVE-FALS"),
            "un fals pozitiv apare la REZOLVATE — pagina pretinde o reparație care n-a existat");
  assert.ok(!rezolvate.includes("CVE-DESCHIS"));

  const inchise = await (await vulnGet(
    getRequest("/panel/vulnerabilitati?grupa=inchise", { cookies }))).text();
  assert.ok(inchise.includes("CVE-FALS"));
  assert.ok(!inchise.includes("CVE-REZOLVAT"));
});

test("o grupă inventată în URL arată TOT, nu un ecran gol", async () => {
  // O legătură veche către o grupă redenumită trebuie să ducă la pagină. Un 404
  // sau o listă goală ar transforma o adresă pusă la favorite într-o pană, iar
  // lista goală ar minți: ar arăta ca „nu e nimic în grupa asta".
  await grant(INSTANCE_A);
  fixture.db.addFinding(INSTANCE_A, { source_id: 1, status: "open", cve: "CVE-DESCHIS" });
  const cookies = await signIn();

  const res = await vulnGet(
    getRequest("/panel/vulnerabilitati?grupa=nu-exista-9xk2", { cookies }));
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes("CVE-DESCHIS"),
            "o grupă necunoscută a golit lista în loc s-o lase întreagă");
});

test("o sesiune curățată nu mai pretinde comenzi pe care arhiva nu le mai are",
     async () => {
  // Eșecul, măsurat: `command_count` vine de pe gazdă și e un contor MEMORAT al
  // rândurilor. Curățarea de aici șterge din `session_command_entries` și, prin
  // proiectare, nu atinge rândul de sesiune. Fără nicio urmă pe pagină, sesiunea
  // 2521 ar arăta «558 079 comenzi» deasupra unui tabel gol — iar operatorul ar
  // avea de ales între a crede numărul și a crede lista.
  await grant(INSTANCE_A);
  fixture.db.addLoginSession(INSTANCE_A, {
    source_id: 1, session_key: "2521", username: "sentinel-deploy",
    terminal: "pts0", interactive: 1,
    command_count: 558079, commands_purged: 558079,
  });
  const cookies = await signIn();

  const res = await sesiuniGet(
    getRequest("/panel/sesiuni?sesiune=1", { cookies }));
  assert.equal(res.status, 200);
  const html = await res.text();

  assert.ok(html.includes("558079 comenzi ale sesiunii au fost șterse"),
            "pagina nu spune că tabelul e gol fiindcă s-a curățat");
  assert.ok(html.includes("558079 comenzi"),
            "pagina nu mai spune câte comenzi a rulat sesiunea pe gazdă");
});

test("o sesiune necurățată nu capătă nicio notă despre ștergere", async () => {
  // O notă permanentă pe fiecare sesiune e zgomot pe care ochiul îl sare — iar
  // atunci nici cea care contează nu se mai citește.
  await grant(INSTANCE_A);
  fixture.db.addLoginSession(INSTANCE_A, { source_id: 1, command_count: 3 });
  fixture.db.addSessionCommand(INSTANCE_A, { source_id: 1, session_source_id: 1 });
  const cookies = await signIn();

  const html = await (await sesiuniGet(
    getRequest("/panel/sesiuni?sesiune=1", { cookies }))).text();
  assert.ok(!html.includes("au fost șterse"));
});
