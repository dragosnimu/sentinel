/**
 * Poarta arată ca aplicația din spatele ei.
 *
 * Eșecul pe care îl previne nu e cosmetic. Paginile de autentificare n-aveau
 * nicio foaie de stil: fundal alb de browser, câmpuri nestilizate, altă
 * tipografie decât panoul. Cine ajunge acolo de pe un link nu are cum să
 * deosebească o pagină nefinisată de una care NU E A TA — iar aia e chiar
 * întrebarea pe care o pune o pagină care cere o parolă.
 *
 * Și o a doua proprietate, care se pierde ușor: foaia trebuie să fie ACEEAȘI ca
 * a panoului. Două foi înseamnă două locuri în care se scriu aceleași culori,
 * iar tema întunecată s-ar despărți de a panoului la prima schimbare.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { loginPage, totpPage } from "../lib/auth/render";

const CSS = readFileSync(join(import.meta.dirname, "..", "public", "panel.css"), "utf8");

const pagini: [string, string][] = [
  ["login", loginPage({ csrfToken: "x" })],
  ["totp", totpPage({ csrfToken: "x", username: "operator" })],
];

test("fiecare poartă încarcă foaia PANOULUI, nu una a ei", () => {
  for (const [nume, html] of pagini) {
    assert.match(html, /<link rel="stylesheet" href="\/panel\.css">/,
                 `${nume}: pagina n-are foaie de stil, deci arată ca un formular gol`);
    // O a doua foaie ar fi al doilea loc în care se scriu culorile.
    const foi = html.match(/rel="stylesheet"/g) ?? [];
    assert.equal(foi.length, 1, `${nume}: ${foi.length} foi de stil`);
  }
});

test("marcajul poartă clasele pe care foaia le stilează", () => {
  for (const [nume, html] of pagini) {
    assert.match(html, /<body class="poarta">/, `${nume}: lipsește clasa de pagină`);
    assert.match(html, /<main class="carte">/, `${nume}: lipsește cardul`);
    assert.match(html, /<\/main>/, `${nume}: cardul nu e închis`);
  }
});

test("foaia chiar definește ce cere marcajul", () => {
  // Clasa pusă în marcaj și nedefinită în foaie e o pagină care arată tot
  // nestilizată — exact starea de dinainte, dar mai greu de observat.
  for (const selector of ["body.poarta", ".carte", ".carte button", ".carte input"]) {
    assert.ok(CSS.includes(selector), `foaia nu definește ${selector}`);
  }
});

test("tema întunecată vine din ACELEAȘI variabile ca panoul", () => {
  // Nicio culoare scrisă de mână în regulile porții: dacă apare una, tema
  // întunecată se desparte de a panoului fără ca nimic să se plângă.
  // Taiat la CAPETE, nu pana la sfarsitul fisierului. Prima versiune lua tot ce
  // urma dupa `body.poarta`, ceea ce a mers exact atat timp cat portile au fost
  // ultima sectiune din foaie — iar la prima sectiune adaugata dupa ele, testul
  // a inceput sa numere culorile GRAFICELOR ca fiind ale portii.
  const de_la = CSS.indexOf("body.poarta");
  assert.ok(de_la > 0, "regulile portii au disparut din foaie");
  const pana_la = CSS.indexOf("/* ---", de_la);
  assert.ok(pana_la > de_la,
            "sectiunea portii nu mai e urmata de niciun titlu de sectiune, deci " +
            "taietura de mai jos ar inghiti tot ce se adauga dupa ea");
  // Comentariile se scot ÎNAINTE de numărătoare. Regula e despre ce PICTEAZĂ
  // foaia, iar un comentariu care explică de ce o culoare e cea aleasă — și o
  // numește — nu pictează nimic. Fără tăietura asta, mesajul de eșec ar acuza
  // documentația, iar reparația evidentă ar fi să fie ștearsă.
  const poarta = CSS.slice(de_la, pana_la)
    .replace(/\/\*[\s\S]*?\*\//g, "");
  const litere = poarta.match(/#[0-9a-f]{3,8}\b/gi) ?? [];
  // ZERO, nu „cel mult două". Roșul mesajului de eroare era excepția, scris de
  // două ori — o dată pe temă — fiindcă `--border` și `--fg` nu spun „greșit".
  // Acum e `--sev-critical`, același token pe care îl folosește și coloana de
  // severitate a panoului, deci nu mai rămâne nimic de întreținut separat aici.
  assert.equal(litere.length, 0,
            `${litere.length} culori scrise de mână în regulile porții: ${litere}`);
  assert.ok(poarta.includes("var(--bg)") && poarta.includes("var(--fg)"),
            "regulile porții nu folosesc variabilele temei");
  // Și numele sunt cele ale SISTEMULUI, nu cele vechi, proprii panoului. Un
  // `var(--fundal)` rămas pe undeva nu se plânge: o variabilă nedefinită face
  // declarația să cadă, iar câmpul rămâne cu fundalul implicit al browserului
  // — adică alb, pe o pagină întunecată.
  for (const vechi of ["--fundal", "--panou", "--linie", "--slab"]) {
    assert.ok(!poarta.includes(`var(${vechi})`),
              `regulile porții cer ${vechi}, care nu mai e definit nicăieri`);
  }
});

test("nicio regulă din foaie nu cere o variabilă nedefinită NICĂIERI", () => {
  // Eșecul pe care îl previne: o redenumire de token lasă în urmă un `var(--x)`
  // pentru care nu mai există nicio declarație. Browserul nu se plânge și nu
  // aprinde nimic în consolă — proprietatea ia pur și simplu valoarea inițială,
  // deci un fundal devine transparent și un text negru pe negru. Se vede doar
  // uitându-te la pagină, iar pagina asta se uită rar.
  //
  // CÂT acoperă, exact: numără declarațiile din TOT fișierul, fără să
  // deosebească `:root` de blocul `@media (prefers-color-scheme: dark)`. Un
  // token șters DOAR din tema deschisă, dar rămas în cea întunecată, trece pe
  // aici — verificat, nu presupus: ștergerea lui `--accent-hover` din `:root`
  // lasă testul ăsta verde. Varianta pe teme e
  // `tests/unit/test_design_system.py::test_no_rule_asks_for_a_token_nobody_declares`,
  // care chiar pică pe mutația aia. Aici rămâne plasa groasă, ieftină, care
  // prinde redenumirea completă.
  const declarate = new Set((CSS.match(/^\s*(--[a-z0-9-]+)\s*:/gim) ?? [])
    .map((line) => line.trim().split(":")[0]));
  assert.ok(declarate.size > 10,
            `doar ${declarate.size} tokenuri declarate: scanarea e stricată`);

  const cerute = new Set((CSS.match(/var\(\s*(--[a-z0-9-]+)/gi) ?? [])
    .map((m) => m.replace(/var\(\s*/i, "")));
  assert.ok(cerute.size > 10,
            `doar ${cerute.size} folosiri găsite: scanarea e stricată`);

  const lipsa = [...cerute].filter((name) => !declarate.has(name)).sort();
  assert.deepEqual(lipsa, [], `foaia cere tokenuri care nu există: ${lipsa}`);
});

test("poarta arată MARCA, nu doar culorile ei", () => {
  // Eșecul pe care îl previne: cineva scoate `url("/logo.svg")` din foaie și
  // nimic nu se plânge. Un `background-image` lipsă nu e o eroare — pseudo-
  // elementul rămâne, gol, iar cardul arată cu un spațiu alb deasupra
  // titlului. Exact întrebarea pe care pagina asta trebuie s-o închidă
  // — „e a ta pagina asta?" — rămâne deschisă, tăcut.
  //
  // FIȘIER, nu `data:`: politica agregatorului e `img-src 'self'` fără
  // `data:`, deci o marcă inlinată în CSS ar fi refuzată de browser și tot
  // n-ar apărea. Vezi `lib/csp.ts`.
  const de_la = CSS.indexOf(".carte::before");
  assert.ok(de_la > 0, "cardul porții nu mai are pseudo-elementul mărcii");
  const regula = CSS.slice(de_la, CSS.indexOf("}", de_la));
  assert.match(regula, /url\("\/logo\.svg"\)/,
               "regula mărcii nu mai încarcă `/logo.svg`");
  assert.doesNotMatch(regula, /url\(\s*["']?data:/,
                      "marca e o adresă `data:`, pe care `img-src 'self'` o refuză");
  // Și bara panoului, din aceeași foaie: cele două se scot la fel de ușor.
  const bara = CSS.indexOf(".marca::before");
  assert.ok(bara > 0, "bara panoului nu mai are marca");
  assert.match(CSS.slice(bara, CSS.indexOf("}", bara)), /url\("\/logo\.svg"\)/);
});

test("focusul din tastatură rămâne vizibil", () => {
  // `outline: none` fără înlocuitor e cel mai frecvent fel în care o pagină
  // devine inutilizabilă fără mouse — și o pagină de login e ultima pe care
  // vrei să nu poți completa din tastatură.
  assert.match(CSS, /\.carte input:focus-visible[\s\S]{0,120}outline:/,
               "câmpurile n-au focus vizibil");
});

test("porțile nu conțin nimic din ce ar refuza politica", () => {
  for (const [nume, html] of pagini) {
    assert.ok(!/<script/i.test(html), `${nume}: are un <script>`);
    assert.ok(!/\sstyle="/i.test(html), `${nume}: are un atribut style=`);
    assert.ok(!/https?:\/\//i.test(html.split("</head>")[0]),
              `${nume}: cere o resursă de la altă origine`);
  }
});

test("formularul rămâne întreg: câmpuri, CSRF, buton", () => {
  // Stilizarea n-avea voie să atingă ce face pagina să funcționeze.
  const [, login] = pagini[0];
  assert.match(login, /name="csrf_token"/);
  assert.match(login, /id="username"[^>]*autocomplete="username"/);
  assert.match(login, /id="password"[^>]*autocomplete="current-password"/);
  assert.match(login, /<button type="submit">/);
  assert.match(login, /<label for="username">/, "câmpul n-are etichetă legată");
});
