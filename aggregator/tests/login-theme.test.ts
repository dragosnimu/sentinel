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
  const poarta = CSS.slice(de_la, pana_la);
  const litere = poarta.match(/#[0-9a-f]{3,8}\b/gi) ?? [];
  // Roșul de eroare e singurul admis, și e declarat de două ori — o dată pentru
  // fiecare temă — fiindcă `--linie` și `--text` nu spun „greșit".
  assert.ok(litere.length <= 2,
            `${litere.length} culori scrise de mână în regulile porții: ${litere}`);
  assert.ok(poarta.includes("var(--fundal)") && poarta.includes("var(--text)"),
            "regulile porții nu folosesc variabilele temei");
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
