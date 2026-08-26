/**
 * Marginile cititorului de intrare — jumătățile pe care drumul fericit le ocolește.
 *
 * `tests/accounts.test.ts` probează perechea de citiri a lui `create`: parola
 * ascunsă, apoi codul de confirmare, de pe același flux. Ce rămâne neatins acolo
 * e tot ce se întâmplă la marginea unei citiri, iar fiecare dintre cele trei
 * lucruri de mai jos se strică TĂCUT:
 *
 *   * **fluxul rămâne pornit după ce citirea s-a terminat.** Unealta și-a făcut
 *     treaba, a scris ce avea de scris, și nu se mai termină: `process.stdin`
 *     pornit ține bucla de evenimente vie. Pe un terminal, operatorul vede un
 *     prompt care nu se mai întoarce; într-un script, comanda următoare nu mai
 *     pornește niciodată. Măsurat de verificator pe un proces adevărat: 147 ms
 *     cu `pause()`, 5859 ms fără el (adică exact cât a ținut conducta deschisă
 *     cel care a pornit-o);
 *   * **`\r\n` numărat ca doi terminatori.** Citirea de după promptul ascuns
 *     începe atunci cu o linie goală venită de nicăieri — pe drumul `create`,
 *     un cod de confirmare gol, care arde tăcut una din cele trei încercări ale
 *     operatorului;
 *   * **Ctrl-C fără ieșire.** În mod brut terminalul nu mai produce SIGINT, deci
 *     ramura de abort e SINGURA ieșire din promptul de parolă. Fără ea, `0x03`
 *     intră în valoare și citirea nu se mai întoarce.
 *
 * ## Ce NU probează fișierul ăsta
 *
 * Că un terminal ADEVĂRAT se poartă ca fluxul injectat aici — un TTY nu se poate
 * imita fără pseudo-terminal, iar `setRawMode` nu există pe un `PassThrough`.
 * Și nici cazul în care `\r` sosește la capătul unui chunk iar `\n` în
 * următorul: înghițirea din `readHidden` se uită în tamponul de ATUNCI, deci
 * despicătura aia i-ar scăpa. Proba de mai jos pune amândoi octeții în aceeași
 * scriere, adică exact ce face un terminal care trimite CRLF.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

import { readShipSecret, readerFor } from "../lib/secret-input";
import { captureStderr, fakeStdin } from "./stdin-harness";
import { ROOT } from "./shipped-files";

/**
 * Cât are voie să dureze ieșirea copilului, cu conducta ținută deschisă.
 *
 * Măsurat aici: ~150 ms cu `pause()`, la nesfârșit fără el. Marginea e de zeci
 * de ori, ca o mașină încărcată să nu înroșească nimic — termenul nu e o măsură
 * de viteză, e granița dintre „încet" și „nu se mai întoarce".
 */
const EXIT_BUDGET_MS = 10_000;

/** Același rol, pentru o citire care ar trebui să se întoarcă imediat. */
const ABORT_BUDGET_MS = 2_000;

/** Ce se întoarce din cursă când citirea nu s-a întors deloc. */
const NIMIC = Symbol("citirea nu s-a întors");

// ---------------------------------------------------------------------------
// `pause()` — jumătatea de care atârnă terminarea procesului
// ---------------------------------------------------------------------------
test("un instrument care a terminat de citit IESE, cu conducta încă deschisă",
     async () => {
  // Eșecul pe care îl previne: `resume()` la intrarea în citire fără `pause()`
  // la ieșire. Citirea reușește — deci nimic nu pare stricat —, dar fluxul rămâne
  // pornit, iar un `process.stdin` pornit ține handle-ul libuv referit, adică
  // ține procesul în viață până când cel de la celălalt capăt al conductei
  // închide. O unealtă care și-a terminat treaba și pare că atârnă.
  //
  // Probat pe un PROCES adevărat, nu pe un `PassThrough`: `isPaused()` ar fi
  // fost mecanica, nu efectul, iar un `PassThrough` n-are handle care să țină
  // ceva în viață. Copilul e `tests/exits-after-read.ts` și NU cheamă
  // `process.exit` — cu el, proba ar trece în ambele cazuri.
  const child = spawn(process.execPath,
                      ["--import", "tsx", "tests/exits-after-read.ts"],
                      { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { out += chunk; });
  child.stderr.on("data", (chunk: string) => { err += chunk; });

  // Conducta rămâne DESCHISĂ dinadins. Închisă, `end` ar ajunge la copil și el
  // s-ar termina oricum — proba n-ar mai deosebi nimic.
  child.stdin.write("parola-din-conducta\n");

  const started = Date.now();
  const ended = await new Promise<{ code: number | null; ms: number } | null>(
    (resolve) => {
      const timer = setTimeout(() => resolve(null), EXIT_BUDGET_MS);
      child.on("exit", (code) => {
        clearTimeout(timer);
        resolve({ code, ms: Date.now() - started });
      });
    });

  if (ended === null) {
    child.kill();
    assert.fail(
      `copilul nu a ieșit în ${EXIT_BUDGET_MS} ms deși citise deja ` +
      `(ieșire: ${JSON.stringify(out)}). Fluxul a rămas pornit după citire, ` +
      "deci o unealtă care și-a terminat treaba atârnă până când cel care a " +
      "pornit-o închide conducta.");
  }

  // Și a CITIT chiar valoarea. Fără jumătatea asta, un copil care moare la
  // pornire — o eroare de sintaxă, un modul lipsă — ar fi „a ieșit repede".
  assert.equal(ended.code, 0, `copilul a murit cu ${ended.code}: ${err}`);
  assert.equal(out, `${JSON.stringify("parola-din-conducta")}\n`,
               `copilul nu a citit linia din conductă: ${JSON.stringify(out)}`);
});

// ---------------------------------------------------------------------------
// `readHidden` — cele două ieșiri din bucla de citire caracter cu caracter
// ---------------------------------------------------------------------------
test("CRLF e UN terminator: citirea de după promptul ascuns nu începe cu o " +
     "linie goală", async () => {
  // Eșecul pe care îl previne, în termeni de operator: pe drumul `create`,
  // citirea de după parolă întoarce imediat linia goală rămasă din `\r\n`, iar
  // aia ajunge la `confirmEnrolment` ca un cod gol. Una din cele trei încercări
  // arde fără ca operatorul să fi tastat nimic — și el nu poate ști de ce,
  // fiindcă mesajul spune „cod greșit". Terminalele care trimit CRLF sunt chiar
  // cele de pe care se administrează gazda de la distanță.
  const { stream } = fakeStdin(true);
  const stderr = captureStderr();
  stream.write("secretul-de-expediere\r\n");
  stream.write("ce-vine-dupa\n");

  const read = await readShipSecret({ env: {}, stdin: stream as never, stderr });
  assert.deepEqual(read, { ok: true, raw: "secretul-de-expediere", from: "prompt" },
                   "promptul ascuns nu s-a oprit la `\\r`");

  assert.equal(await readerFor(stream as never).readLine(), "ce-vine-dupa",
               "citirea de după promptul ascuns a întors altceva: `\\n`-ul din " +
               "CRLF a rămas în tampon și a devenit o linie goală");
});

test("Ctrl-C și Ctrl-D ies din promptul ascuns — în mod brut nu mai vine niciun " +
     "SIGINT", async () => {
  // Eșecul pe care îl previne: promptul de parolă nu răspunde la nimic. Modul
  // brut oprește tocmai interpretarea caracterelor de control de către terminal,
  // deci Ctrl-C nu mai omoară procesul; fără ramura asta, `0x03` intră în
  // valoare și bucla așteaptă un terminator care nu mai vine. Operatorul rămâne
  // cu o unealtă blocată DUPĂ ce ea a afișat secretul TOTP care „se afișează O
  // SINGURĂ DATĂ", și singura ieșire e să omoare procesul din altă parte.
  //
  // Măsurat: cu garda, `{"ok":false,"detail":"întrerupt"}`; fără ea, nimic.
  for (const key of [3, 4]) {
    const { stream, rawModes } = fakeStdin(true);
    const stderr = captureStderr();
    stream.write(String.fromCharCode(key));

    // Cursa e AICI, nu la termenul suitei: fără gardă citirea nu se mai întoarce,
    // iar un test care atârnă arată ca o suită care „încă rulează", nu ca una
    // roșie. Vezi de ce are termene `run-tests.mjs`.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const read = await Promise.race([
      readShipSecret({ env: {}, stdin: stream as never, stderr }),
      new Promise<typeof NIMIC>((resolve) => {
        timer = setTimeout(() => resolve(NIMIC), ABORT_BUDGET_MS);
      }),
    ]);
    if (timer !== undefined) clearTimeout(timer);

    assert.notEqual(read, NIMIC,
                    `0x0${key} nu a ieșit din promptul ascuns în ${ABORT_BUDGET_MS} ` +
                    "ms: caracterul a intrat în valoare, iar citirea așteaptă un " +
                    "terminator care nu mai vine");
    assert.deepEqual(read, { ok: false, detail: "întrerupt" },
                     `0x0${key} nu a fost citit ca întrerupere`);
    assert.deepEqual(rawModes, [true, false],
                     "modul brut a rămas pornit după întrerupere: terminalul " +
                     "operatorului rămâne fără ecou și fără Ctrl-C");
  }
});
