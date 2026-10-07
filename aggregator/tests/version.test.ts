/**
 * Nota de versiune din antetul panoului, și de unde vine.
 *
 * Eșecurile pe care le previne, în termeni de ce vede operatorul:
 *
 *   * panoul arată `0.1.0` la nesfârșit, deși `package.json` s-a mutat — fiindcă versiunea a fost
 *     scrisă într-un șablon în loc să fie citită de la sursă. Testul citește `package.json`
 *     SEPARAT (`readFileSync`, nu importul din `lib/version.ts`) și compară cu ce a randat pagina;
 *   * cuvântul «beta» rămâne pe pagină după 1.0.0 — o etichetă care minte, fiindcă nu mai e legată
 *     de cifră;
 *   * «beta» apare peste o versiune pe care n-am putut-o citi (`0.0.0+unknown` e sub 1.0 doar
 *     tehnic) — o afirmație fără fapt în spate;
 *   * regula din agregator se desparte de cea de pe serverul monitorizat
 *     (`sentinel/web/jinja.py:release_stage`) — verificat din partea Python
 *     (`tests/unit/test_version_label.py`), care compară expresia regulată la octet;
 *   * foaia de stil primește o regulă care folosește o variabilă CSS pe care foaia nu o definește:
 *     culoarea cade pe cea moștenită, fără nicio eroare.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { pendingPage, summaryPage, versionNote } from "../lib/panel-page";
import { VERSION, releaseStage } from "../lib/version";

const ROOT = join(import.meta.dirname, "..");
const PACKAGE_VERSION: string =
  JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const CSS = readFileSync(join(ROOT, "public", "panel.css"), "utf8");

const VIEW = {
  username: "operator", csrfToken: "x", instances: [], selected: null,
  active: "/panel/detectii", arrivals: new Map(),
} as never;

/** Textul vizibil al notei, fără marcaj. */
function vizibil(html: string): string {
  return html.replace(/<[^>]+>/g, "").replace(/&middot;/g, "·").replace(/\s+/g, " ").trim();
}

/** Nota din antetul unei pagini randate, sau eșec dacă antetul n-o are. */
function notaDinAntet(html: string): string {
  const antet = /<header class="bara">([\s\S]*?)<\/header>/.exec(html);
  assert.ok(antet, "pagina n-are antet");
  const nota = /<span class="versiune"[^>]*>[\s\S]*?<\/span>(?:<\/span>)?/.exec(antet[1]);
  assert.ok(nota, "antetul n-are nota de versiune");
  return nota[0];
}

test("pagina arată versiunea din package.json, citit separat — nu un șir scris în cod", () => {
  // Eșecul pe care îl previne: versiunea scrisă de mână în `panel-page.ts` sau `version.ts`.
  // Când `package.json` se mută, pagina o urmează sau testul pică.
  const html = pendingPage(VIEW, "Detecții", "detections", "explicație");
  assert.equal(vizibil(notaDinAntet(html)).startsWith(`Agregator ${PACKAGE_VERSION}`), true,
               `antetul nu arată ${PACKAGE_VERSION}: ${notaDinAntet(html)}`);
  assert.equal(VERSION, PACKAGE_VERSION, "lib/version.ts nu citește package.json");
});

test("nota stă în antet, între utilizator și butonul de ieșire, o singură dată", () => {
  const html = pendingPage(VIEW, "Detecții", "detections", "explicație");
  const antet = /<header class="bara">([\s\S]*?)<\/header>/.exec(html)![1];
  const cine = antet.indexOf('class="cine"');
  const nota = antet.indexOf('class="versiune"');
  const iesire = antet.indexOf('action="/logout"');
  assert.ok(cine >= 0 && nota > cine && iesire > nota,
            `ordinea e greșită: cine=${cine} nota=${nota} ieșire=${iesire}`);
  assert.equal(html.match(/class="versiune"/g)?.length, 1);
});

test("și rezumatul, care își asamblează singur corpul, are nota în antet", () => {
  // `chrome()` e un singur loc, dar un test care vede o singură pagină n-ar prinde o pagină
  // viitoare care își scrie propriul antet.
  const sumar = summaryPage({
    username: "operator", csrfToken: "x", instances: [], selected: null,
    active: "/panel", arrivals: new Map(), incidents: [], sumar: {} as never,
  } as never);
  // Fără instanțe, `summaryPage` arată starea „cont proaspăt" — tot cu antet.
  assert.match(sumar, /class="versiune"/);
});

test("sub 1.0 e marcată beta, de la 1.0 nu mai e", () => {
  const sub = vizibil(versionNote("0.18.0"));
  assert.equal(sub, "Agregator 0.18.0 · beta");
  const peste = vizibil(versionNote("1.0.0"));
  assert.equal(peste, "Agregator 1.0.0");
  assert.doesNotMatch(versionNote("1.0.0"), /beta/i,
                      "cuvântul «beta» a rămas după 1.0.0 — eticheta nu mai e legată de cifră");
});

test("o versiune care nu se poate citi se spune necunoscută, nu beta", () => {
  for (const rau of ["0.0.0+unknown", "", "abc", "1.0"]) {
    const html = versionNote(rau);
    assert.match(vizibil(html), /necunoscută/, `${JSON.stringify(rau)}: nu spune că nu știe`);
    assert.doesNotMatch(html, /beta/i, `${JSON.stringify(rau)}: «beta» peste o versiune necitită`);
  }
  // Hover-ul nu acuză o cauză: șirul poate fi și citit bine, dar fără forma `X.Y.Z` (`1.0`).
  const titlu = /title="([^"]*)"/.exec(versionNote("1.0"));
  assert.ok(titlu, "nota «necunoscută» n-are nicio explicație la hover");
  assert.match(titlu[1], /X\.Y\.Z/, "titlul nu spune ce formă se așteaptă");
  assert.doesNotMatch(titlu[1], /n-a putut fi citit/, "titlul acuză o cauză care poate fi alta");
  assert.equal(releaseStage(undefined), "unknown");
  assert.equal(releaseStage(1), "unknown");
});

test("un șir cu marcaj nu ajunge în pagină ca marcaj", () => {
  // Nota nu trece prin `escapeHtml`: gardianul e expresia regulată din `releaseStage`, care
  // primește doar `[0-9A-Za-z.+-]`. Testul o apasă cu o versiune care arată bine la început —
  // dacă expresia se relaxează, marcajul iese în antet (și testul pică).
  const html = versionNote("1.0.0-<b>x</b>");
  assert.doesNotMatch(html, /<b>/);
  assert.match(vizibil(html), /necunoscută/);
});

test("regula de etapă: tabelul comun cu partea Python", () => {
  const cazuri: [string, string][] = [
    ["0.1.0", "beta"], ["0.18.0", "beta"], ["0.99.99", "beta"],
    ["1.0.0", "stable"], ["1.2.3", "stable"], ["10.0.0", "stable"],
    ["1.0.0-rc1", "beta"], ["1.2.3+build5", "stable"], ["0.0.0+unknown", "unknown"],
    ["", "unknown"], ["x", "unknown"], ["1.0", "unknown"], ["1.0.0\n", "unknown"],
    ["1.0.0-<b>x</b>", "unknown"],
    // Cifre care nu sunt 0-9: `\d` din Python le primește fără `re.ASCII`, cel din JavaScript nu.
    ["\uff11.0.0", "unknown"], ["0.\u0663.0", "unknown"],
  ];
  for (const [v, asteptat] of cazuri) {
    assert.equal(releaseStage(v), asteptat, `releaseStage(${JSON.stringify(v)})`);
  }
});

test("foaia de stil are regula notei și fiecare variabilă pe care o folosește e definită", () => {
  // Eșecul pe care îl previne: `color: var(--fg-dim)` într-o foaie care nu definește `--fg-dim`
  // — valoarea e invalidă la momentul calculării, culoarea cade pe cea moștenită, nicio eroare.
  const reguli = [...CSS.matchAll(/\.(versiune(?:-beta)?)\s*\{([^}]*)\}/g)];
  // `.versiune` mai apare o dată, în banda îngustă, cu `display: none`: aceea nu e regula care o
  // stilează, deci nu trebuie să țină locul uneia lipsă (altfel, ștergând regula principală,
  // nota ar ieși în culoarea și mărimea moștenite, cu testul verde).
  const nume = new Set(reguli.filter((m) => !m[2].includes("display: none")).map((m) => m[1]));
  assert.ok(nume.has("versiune") && nume.has("versiune-beta"),
            "foaia nu stilează clasele pe care le emite versionNote");
  for (const m of reguli) {
    for (const v of m[2].matchAll(/var\((--[a-z0-9-]+)/g)) {
      const definita = new RegExp("^ *" + v[1] + " *:", "m");
      assert.ok(definita.test(CSS), `.${m[1]} folosește ${v[1]}, nedefinită în panel.css`);
    }
  }
});
