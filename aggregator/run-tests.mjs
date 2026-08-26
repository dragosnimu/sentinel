#!/usr/bin/env node
/**
 * Rulează suita proiectului — panoul, ingestia de loturi ȘI martorul.
 *
 * Până pe 18 august 2026 erau două scripturi gemene, unul aici și unul în
 * `watcher/`, copiate dinadins fiindcă erau două aplicații publicate separat.
 * Martorul s-a mutat aici, deci sunt una singură, iar geamănul a fost șters cu
 * tot cu testul lui (`tests/security/test_watcher_test_runner.py`). A rămas cel
 * cu TERMENE, fiindcă între două scripturi identice în rest diferența era chiar
 * asta: unul oprea un test care atârnă, celălalt nu.
 *
 * Ce dovedește că scriptul ăsta chiar pică pe o suită care n-a rulat:
 * `tests/security/test_aggregator_test_runner.py`, care îl rulează pe el, nu o
 * copie a lui.
 *
 * De ce nu forma evidentă (`node --test tests/`): pe Node 20 — versiunea de pe
 * găzduire — aia raportează `# pass 0  # fail 0` și **iese cu 0**. Un script de
 * teste care raportează succes fără să fi rulat nimic e chiar defectul după care
 * e numit depozitul ăsta, iar aici ar ascunde jumătatea care dovedește că
 * runner-ul de migrații reia de la instrucțiunea la care a murit.
 *
 * Deci fișierele se caută AICI, cu `readdirSync`, și se dau lui `node --test`
 * unul câte unul:
 *
 *   * nu depinde de expandarea globurilor din shell — care pe Windows, unde
 *     `npm` rulează prin `cmd.exe`, nu există deloc;
 *   * merge la fel pe Node 20 și pe Node 24, fiindcă `--test <fișier>` e
 *     acceptat de amândouă;
 *   * **zero fișiere de test e un EȘEC**, nu o suită goală care iese cu 0.
 *
 * ## De ce are termene
 *
 * `node --test` n-are termen implicit, iar `spawnSync` n-avea niciunul aici:
 * un test care așteaptă la infinit oprea `npm test` fără să tipărească nimic și
 * fără să iasă vreodată. Măsurat, pe chiar suita asta: cu `release()` scos din
 * `finally` în `lib/auth/password.ts`, permisul semaforului se pierde la prima
 * excepție, iar `node --import tsx --test tests/auth-password.test.ts
 * tests/auth-password-burst.test.ts` a rulat 300 s fără nicio linie și a trebuit
 * omorât din afară.
 *
 * Un blocaj tăcut e mai rău decât un eșec: pe o mașină de livrare arată ca o
 * suită care „încă rulează", nu ca una roșie, deci nimeni nu-l citește ca defect.
 * Sunt două termene fiindcă prind lucruri diferite:
 *
 *   * `--test-timeout` transformă testul care atârnă într-un test PICAT, cu
 *     numele lui, iar restul suitei rulează mai departe;
 *   * termenul lui `spawnSync` e plasa de dedesubt: prinde și ce nu e un test
 *     (o încărcare de modul care nu se termină), și Node-urile care nu cunosc
 *     `--test-timeout`.
 */

import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const testsDir = path.join(here, "tests");

let entries;
try {
  entries = readdirSync(testsDir);
} catch (err) {
  console.error(`[run-tests] nu pot citi ${testsDir}: ${err.message}`);
  console.error("[run-tests] o suită care nu se poate citi NU e o suită verde.");
  process.exit(1);
}

const files = entries
  .filter((f) => f.endsWith(".test.ts") || f.endsWith(".test.tsx"))
  .sort()
  .map((f) => path.join("tests", f));

if (files.length === 0) {
  console.error(`[run-tests] niciun fișier *.test.ts / *.test.tsx în ${testsDir}.`);
  console.error("[run-tests] „n-a rulat nimic” nu e „a trecut totul”.");
  process.exit(1);
}

/**
 * Cât are voie să dureze UN test. Cel mai lung din suită — rafala de 17 calcule
 * Argon2id din `tests/auth-password-burst.test.ts` — costă ~2,6 s aici, deci e
 * de peste douăzeci de ori marginea, ca o găzduire partajată încetinită să nu
 * înroșească nimic. Termenul nu e o măsură de viteză, e granița dintre „încet"
 * și „nu se mai întoarce".
 *
 * `SENTINEL_TEST_TIMEOUT_MS` există dintr-un singur motiv, și nu e configurarea:
 * `tests/security/test_aggregator_test_runner.py` probează PRIN EFECT că un test
 * care atârnă chiar e oprit — pune un fișier care așteaptă la infinit și cere ca
 * scriptul să iasă roșu. Cu 60 s, proba aia ar costa un minut la fiecare rulare
 * a suitei Python, iar un test scump e un test pe care cineva îl scoate.
 */
const PER_TEST_TIMEOUT_MS = Number(process.env.SENTINEL_TEST_TIMEOUT_MS) || 60_000;

/** Și cât are voie să dureze toată suita. ~16 s aici, măsurat pe 18 august 2026
 *  cu martorul înăuntru, deci tot marginea e mare. */
const WHOLE_SUITE_TIMEOUT_MS = 10 * 60_000;

// `--test-timeout` există din Node 20.11, iar găzduirea rulează Node 20. Dacă îl
// acceptă NU se presupune, se măsoară: un Node care nu-l cunoaște iese cu 9 și
// „bad option", iar dat orbește ar transforma o suită verde într-o suită care nu
// pornește. Dacă lipsește, se spune pe față — atunci un blocaj e mărginit doar de
// termenul întregii suite, iar aia e altă purtare, nu aceeași.
const probe = spawnSync(
  process.execPath, [`--test-timeout=${PER_TEST_TIMEOUT_MS}`, "-e", "0"],
  { stdio: "ignore" },
);
const perTestTimeout = probe.status === 0;
if (!perTestTimeout) {
  console.error(`[run-tests] ${process.version} nu acceptă --test-timeout: un test ` +
                "care atârnă va fi prins abia de termenul întregii suite, fără să i " +
                "se afle numele.");
}

const child = spawnSync(
  process.execPath,
  ["--import", "tsx",
   ...(perTestTimeout ? [`--test-timeout=${PER_TEST_TIMEOUT_MS}`] : []),
   "--test", ...files],
  { cwd: here, stdio: "inherit", timeout: WHOLE_SUITE_TIMEOUT_MS },
);

if (child.error) {
  // Termenul depășit și „n-a pornit" sunt două eșecuri diferite, iar mesajul
  // dinainte le-ar fi confundat pe amândouă într-unul care trimite pe cineva să
  // caute un `node` lipsă. Măsurat: la termen depășit, `spawnSync` întoarce
  // `error.code === "ETIMEDOUT"`, `status === null`, `signal === "SIGTERM"`.
  if (child.error.code === "ETIMEDOUT") {
    console.error(`[run-tests] suita a depășit ${WHOLE_SUITE_TIMEOUT_MS / 1000} s și ` +
                  "a fost oprită. O suită care atârnă NU e o suită verde.");
  } else {
    console.error(`[run-tests] nu am putut porni node --test: ${child.error.message}`);
  }
  process.exit(1);
}
// `status === null` înseamnă că procesul a fost omorât de un semnal. Nu e
// succes, și `process.exit(null)` ar fi ieșit cu 0.
process.exit(child.status === null ? 1 : child.status);
