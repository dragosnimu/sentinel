/**
 * Anteturile de securitate ale agregatorului — și dovada că politica se
 * potrivește cu ce livrează chiar aplicația.
 *
 * Eșecul pe care îl previne: panoul rulează pe găzduire partajată, unde nu există
 * nici sandbox systemd, nici SELinux, nici un fail2ban pe care să-l controlezi,
 * iar personalul furnizorului are acces la baza de date. Anteturile sunt aproape
 * singurul control care rămâne. Măsurat pe 21 august 2026, aplicația declara
 * patru anteturi și niciun CSP; singurul care ajungea la browser era un
 * `upgrade-insecure-requests` pus de platformă, care nu restrânge nicio sursă de
 * script și trece drept „CSP prezent" la orice scanare superficială.
 *
 * Al doilea test e cel care contează pe termen lung. O politică strictă se
 * strică nu când cineva o slăbește, ci când cineva adaugă un `<script>` inline
 * într-o pagină și descoperă un ecran alb. Atunci presiunea e să pui
 * `unsafe-inline`, iar toată proiectarea — panou randat ca șiruri, tocmai ca să
 * nu aibă nevoie de nonce — se pierde într-o linie. Testul mută descoperirea
 * din browser în suită și spune ce s-a stricat.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

// `next.config.mjs` e JavaScript pur, fără declarații de tip — și rămâne așa:
// e fișierul pe care îl citește Next, iar o copie `.ts` a lui ar fi un al doilea
// loc în care anteturile pot să nu fie de acord.
// @ts-expect-error - modul JS fără tipuri, importat dinadins
import nextConfig from "../next.config.mjs";

const ROOT = join(import.meta.dirname, "..");

async function headers(): Promise<Map<string, string>> {
  const groups = await (nextConfig as any).headers();
  assert.equal(groups.length, 1, "o singură grupă, aplicată pe toate rutele");
  assert.equal(groups[0].source, "/:path*");
  return new Map<string, string>(
    groups[0].headers.map((h: { key: string; value: string }) =>
      [h.key.toLowerCase(), h.value]));
}

function directives(csp: string): Map<string, string> {
  return new Map(csp.split(";").map((part) => {
    const words = part.trim().split(/\s+/);
    return [words[0], words.slice(1).join(" ")];
  }));
}

/** Fiecare fișier sursă din care se construiește HTML servit. */
function sourceFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      if (name === "node_modules" || name === ".next") continue;
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else if (name.endsWith(".ts") || name.endsWith(".tsx")) out.push(path);
    }
  };
  walk(join(ROOT, "lib"));
  walk(join(ROOT, "app"));
  return out;
}

test("CSP-ul pleacă de la `default-src 'none'`", async () => {
  const csp = (await headers()).get("content-security-policy");
  assert.ok(csp, "niciun CSP declarat de aplicație — vezi defectul din 21 august");
  const d = directives(csp!);
  assert.equal(d.get("default-src"), "'none'",
               "fără o bază `'none'`, tot ce nu e enumerat rămâne permis");
});

test("CSP-ul nu conține nicio scăpare de tip `unsafe`", async () => {
  const csp = (await headers()).get("content-security-policy")!;
  for (const escape of ["unsafe-inline", "unsafe-eval", "unsafe-hashes", "*"]) {
    assert.ok(!csp.includes(escape),
              `CSP-ul conține ${escape}, deci nu mai apără de injecția de script`);
  }
});

test("formularele nu pot fi trimise în altă parte", async () => {
  const d = directives((await headers()).get("content-security-policy")!);
  assert.equal(d.get("form-action"), "'self'",
               "fără `form-action`, o injecție reușită ar putea trimite sesiunea " +
               "sau parola către alt server");
  assert.equal(d.get("base-uri"), "'none'",
               "fără `base-uri`, un `<base>` injectat rescrie fiecare cale relativă");
  assert.equal(d.get("frame-ancestors"), "'none'");
});

test("HSTS e pe cel puțin un an, cu subdomenii, și fără `preload`", async () => {
  const hsts = (await headers()).get("strict-transport-security");
  assert.ok(hsts, "fără HSTS, prima cerere a unei sesiuni noi merge pe HTTP");
  const age = Number(/max-age=(\d+)/.exec(hsts!)?.[1] ?? 0);
  assert.ok(age >= 31_536_000, `max-age=${age} e sub un an`);
  assert.ok(hsts!.includes("includeSubDomains"));
  assert.ok(!hsts!.includes("preload"),
            "`preload` e o promisiune pentru tot domeniul, luată de pe un " +
            "subdomeniu, din care ieșirea durează luni și nu depinde de noi");
});

test("anteturile de dinainte n-au fost pierdute la adăugarea CSP-ului", async () => {
  const h = await headers();
  assert.match(h.get("cache-control") ?? "", /no-store/);
  assert.equal(h.get("x-content-type-options"), "nosniff");
  assert.equal(h.get("x-frame-options"), "DENY");
  assert.equal(h.get("referrer-policy"), "no-referrer");
});

test("nicio pagină nu are nevoie de o politică mai slabă decât cea declarată", () => {
  // Proba că politica se potrivește cu aplicația, nu doar că e strictă. Fiecare
  // tipar de aici ar fi BLOCAT de CSP-ul de mai sus, deci apariția lui într-o
  // pagină înseamnă un ecran alb pentru operator — descoperit aici, nu acolo.
  const forbidden: [RegExp, string][] = [
    [/<script\b/i, "un `<script>` — `default-src 'none'` nu permite niciun script"],
    [/<style\b/i, "un `<style>` inline — `style-src 'self'` cere fișier separat"],
    [/\bstyle="/i, "un atribut `style=` inline, blocat la fel"],
    [/\bon(?:click|submit|load|error|change|input)="/i,
     "un handler inline de eveniment"],
    [/(?:src|href)="https?:\/\//i, "o origine externă"],
    [/<base\b/i, "un `<base>`, blocat de `base-uri 'none'`"],
  ];

  const offenders: string[] = [];
  const files = sourceFiles();
  assert.ok(files.length > 0, "niciun fișier sursă găsit: testul n-ar proba nimic");

  for (const path of files) {
    // Comentariile vorbesc DESPRE tiparele astea; conțin cuvintele fără să le
    // livreze. Se scot înainte de căutare, altfel testul ar acuza documentația.
    const text = readFileSync(path, "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    for (const [pattern, why] of forbidden) {
      if (pattern.test(text)) {
        offenders.push(`${path.slice(ROOT.length + 1)}: ${why}`);
      }
    }
  }

  assert.deepEqual(offenders, [],
                   "CSP-ul ar bloca ce livrează aplicația:\n  " +
                   offenders.join("\n  "));
});


// ---------------------------------------------------------------------------
// Calea care CHIAR ajunge la browser: meta-tagul.
//
// Măsurat pe 21 august 2026, imediat după ce anteturile au fost livrate: CDN-ul
// găzduirii ÎNLOCUIEȘTE `Content-Security-Policy` cu al lui,
// `upgrade-insecure-requests`. Dovada că nu e o greșeală a aplicației e că
// `Strict-Transport-Security`, declarat în același loc și în același fel, trece
// — platforma nu-l pune pe ăla. Antetul nu e greșit; e revendicat de altcineva.
//
// Deci politica merge și prin meta-tag, calea pe care o controlăm noi. Testele
// de aici probează că ajunge în FIECARE pagină, nu doar că e definită.
// ---------------------------------------------------------------------------

import { CSP_META, CSP_META_TAG } from "../lib/csp";

test("meta-politica nu conține nicio scăpare de tip `unsafe`", () => {
  for (const escape of ["unsafe-inline", "unsafe-eval", "unsafe-hashes", "*"]) {
    assert.ok(!CSP_META.includes(escape), `meta-politica conține ${escape}`);
  }
  assert.match(CSP_META, /^default-src 'none'/);
  assert.ok(CSP_META.includes("form-action 'self'"));
  assert.ok(CSP_META.includes("base-uri 'none'"));
});

test("`frame-ancestors` NU e în meta — acolo e ignorat prin specificație", () => {
  // Scrisă unde e ignorată, ar fi o apărare pe hârtie: cineva ar citi lista și
  // ar crede că încadrarea în iframe e oprită. E oprită, dar de
  // `X-Frame-Options: DENY`, care chiar trece.
  assert.ok(!CSP_META.includes("frame-ancestors"),
            "directivă scrisă într-un loc în care browserul o ignoră");
});

test("fiecare pagină poartă meta-tagul, PRIMUL în `<head>`", async () => {
  const { reportsPage } = await import("../lib/panel-page");
  const { loginPage } = await import("../lib/auth/render");
  const chrome = {
    username: "operator", csrfToken: "x", instances: [], selected: null,
    active: "/panel/rapoarte", arrivals: new Map(),
  };

  const pages: [string, string][] = [
    ["panou", reportsPage({ ...chrome, hours: [] } as never)],
    ["login", loginPage({ csrfToken: "x" } as never)],
  ];

  for (const [name, html] of pages) {
    assert.ok(html.includes(CSP_META_TAG.trim()),
              `${name}: pagina nu poartă meta-politica`);
    const head = html.indexOf("<head>");
    const meta = html.indexOf("http-equiv=\"Content-Security-Policy\"");
    const charset = html.indexOf("<meta charset");
    assert.ok(head >= 0 && meta > head, `${name}: meta-tagul nu e în <head>`);
    assert.ok(meta < charset,
              `${name}: meta-politica vine DUPĂ alte elemente; guvernează doar ` +
              "ce urmează după ea");
  }
});
