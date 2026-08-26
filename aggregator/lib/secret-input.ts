/**
 * De unde vine secretul de expediere — și de ce niciodată din `argv`.
 *
 * `argv` ajunge în lista de procese (`ps`, `/proc/<pid>/cmdline`), vizibilă
 * altor utilizatori pe o găzduire partajată, și în istoricul shellului, care
 * supraviețuiește sesiunii și ajunge în copiile de siguranță ale directorului
 * home. Un secret dat pe linia de comandă e un secret publicat.
 *
 * Trei căi, în ordinea în care se încearcă:
 *
 *   1. **`SENTINEL_SHIP_SECRET` din mediu** — aceeași cale pe care `bin/migrate.ts`
 *      primește datele de conectare, deci nimic nou de învățat. Rămâne totuși în
 *      mediul procesului, deci e a doua alegere ca igienă;
 *   2. **prompt ascuns**, dacă intrarea e un terminal. Nu se tipărește nimic din
 *      ce se tastează, nici măcar asteriscuri: numărul lor spune lungimea;
 *   3. **o linie de la intrarea standard**, dacă e o conductă. Asta e forma bună:
 *      `pass show ... | npm run instance -- register <id>` nu lasă valoarea
 *      nicăieri.
 *
 * Terminatorul de linie se taie ca ÎNCADRARE, nu ca normalizare a valorii: o
 * conductă termină linia cu `\n`, iar ăla nu e un caracter pe care l-a scris
 * cineva. Orice alt spațiu rămâne, ca `checkSecretShape` să-l poată refuza —
 * vezi acolo de ce forma se refuză în loc să fie reparată.
 *
 * ## Cine deține fluxul de intrare — un singur cititor, per flux
 *
 * Fișierul ăsta a avut până pe 17 august 2026 două funcții care citeau amândouă
 * direct din `stdin` și nu se puneau de acord pe nimic: promptul ascuns își
 * ataşa ascultătorul, iar la sfârșit chema `pause()`; cititorul de linie își
 * ataşa ascultătorul lui și **nu chema niciodată `resume()`**. Node nu reia un
 * flux oprit explicit (`Readable.on("data")` reia doar dacă `flowing !== false`),
 * deci a doua citire de pe același flux ATÂRNA la nesfârșit. Iar pe conductă,
 * unde nu se atârna, cititorul de linie arunca restul chunk-ului de după `\n` —
 * deci a doua citire nu găsea o valoare care sosise deja.
 *
 * Ce s-a stricat pentru operator: `npm run user -- create` cerea parola (prompt
 * ascuns), afișa secretul TOTP care „se afișează O SINGURĂ DATĂ", și apoi nu mai
 * putea citi codul de confirmare. Contul rămânea fără al doilea factor, deci
 * nimeni nu se putea autentifica pe panou.
 *
 * De-aia nu mai există două funcții care citesc, ci **un cititor care deține
 * fluxul**, iar apartenența e a FLUXULUI, nu a apelantului: `readerFor` ține un
 * `WeakMap`, deci oricâte locuri ar citi din `process.stdin`, toate primesc
 * același obiect, cu același tampon. Regula, într-o propoziție: *octeții care au
 * sosit și n-au fost ceruți încă stau în tamponul cititorului, nu se pierd și nu
 * se citesc de două ori.*
 *
 * Fiecare citire cheamă `resume()` la intrare și `pause()` la ieșire —
 * amândouă, în același loc. `pause()` nu pierde nimic (ce a sosit e deja în
 * tampon, iar ce n-a sosit rămâne în tamponul intern al fluxului) și e ce
 * lasă un proces care a terminat de citit să se termine singur.
 *
 * ## Ce NU se poate proba de pe mașina de dezvoltare
 *
 * Că un TERMINAL adevărat se poartă ca fluxul injectat în teste. Un TTY nu se
 * poate imita fără un pseudo-terminal, iar `setRawMode` nu există pe un
 * `PassThrough`. Ce se probează aici e mecanica — ordinea `resume`/`pause`,
 * tamponul păstrat între citiri, comutarea modului brut — pe un flux care spune
 * `isTTY = true`. Că `stty` chiar oprește ecoul se vede prima dată pe gazdă.
 */

/** Numele variabilei, identic cu cel de pe serverul monitorizat
 *  (`sentinel/report/shipper.py::SECRET_NAME`). Un al doilea nume pentru aceeași
 *  valoare e un al doilea loc din care poate lipsi. */
export const SHIP_SECRET_ENV = "SENTINEL_SHIP_SECRET";

export type InputStream = NodeJS.ReadableStream & {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => void;
};

export type ErrorStream = { write(text: string): unknown };

export type SecretInput = {
  env?: Record<string, string | undefined>;
  stdin?: InputStream;
  /** Unde se scrie invitația. `stderr`, nu `stdout`: ieșirea instrumentului
   *  trebuie să rămână redirecționabilă fără să înghită promptul. */
  stderr?: { write(text: string): unknown };
};

export type SecretRead =
  | { ok: true; raw: string; from: "env" | "prompt" | "stdin" }
  | { ok: false; detail: string };

/** Taie DOAR terminatorul de linie: `\n` sau `\r\n`. Nimic altceva. */
function stripLineEnding(text: string): string {
  if (text.endsWith("\r\n")) return text.slice(0, -2);
  if (text.endsWith("\n") || text.endsWith("\r")) return text.slice(0, -1);
  return text;
}

/**
 * Cititorul fiecărui flux, ținut de FLUX și nu de apelant.
 *
 * `WeakMap`, deci nimic nu crește cu numărul de fluxuri și un flux uitat nu ține
 * cititorul lui în viață. Ăsta e mecanismul care face imposibilă întoarcerea
 * defectului: doi apelanți nu pot avea două tampoane peste aceiași octeți,
 * fiindcă nu pot obține două cititoare.
 */
const owners = new WeakMap<InputStream, LineReader>();

export function readerFor(stdin: InputStream): LineReader {
  const existing = owners.get(stdin);
  if (existing !== undefined) return existing;
  const reader = new LineReader(stdin);
  owners.set(stdin, reader);
  return reader;
}

/**
 * Citirile de pe un flux de intrare, toate prin același tampon.
 *
 * Nu se construiește direct din afara fișierului — se cere prin `readerFor`, ca
 * apartenența să rămână a fluxului. Constructorul e public doar fiindcă
 * `readerFor` e singurul care îl cheamă și un constructor privat n-ar adăuga
 * nimic în plus față de regula asta scrisă.
 */
export class LineReader {
  private readonly stdin: InputStream;
  /** Ce a sosit și n-a fost cerut încă. Aici e reparația, în esență. */
  private buffer = "";
  private ended = false;
  private reading = false;
  private wake: (() => void) | null = null;

  constructor(stdin: InputStream) {
    this.stdin = stdin;
    this.stdin.on("data", this.onData);
    this.stdin.on("end", this.onEnd);
    // Oprit până cere cineva ceva: un flux pornit din constructor ar ține
    // procesul în viață chiar și când nimeni nu mai citește.
    this.stdin.pause();
  }

  private readonly onData = (chunk: Buffer | string): void => {
    this.buffer += chunk.toString();
    this.wakeUp();
  };

  private readonly onEnd = (): void => {
    this.ended = true;
    this.wakeUp();
  };

  private wakeUp(): void {
    const wake = this.wake;
    this.wake = null;
    if (wake !== null) wake();
  }

  /** Așteaptă următorul chunk (sau capătul fluxului). */
  private more(): Promise<void> {
    if (this.ended) return Promise.resolve();
    return new Promise<void>((resolve) => { this.wake = resolve; });
  }

  /**
   * O citire, cu fluxul pornit doar cât ține ea.
   *
   * Două citiri deodată sunt o EROARE, nu o împărțire a octeților: ar fi exact
   * neînțelegerea pe care fișierul ăsta o repară, doar mutată de la două funcții
   * la două apeluri.
   */
  private async turn<T>(body: () => Promise<T>): Promise<T> {
    if (this.reading) {
      throw new Error(
        "două citiri deodată de pe același flux de intrare: octeții s-ar împărți " +
        "între ele după cine apucă, iar valoarea citită ar depinde de planificare");
    }
    this.reading = true;
    this.stdin.resume();
    try {
      return await body();
    } finally {
      this.reading = false;
      this.stdin.pause();
    }
  }

  /**
   * Următoarea linie, FĂRĂ terminatorul ei. `null` = nu mai vine nimic.
   *
   * Restul chunk-ului rămâne în tampon. Fără asta, `printf 'parola\ncod\n' |
   * unealta` pierdea `cod`: sosea în același chunk cu parola și era aruncat.
   */
  async readLine(): Promise<string | null> {
    return await this.turn(async () => {
      for (;;) {
        const at = this.buffer.indexOf("\n");
        if (at >= 0) {
          const line = this.buffer.slice(0, at + 1);
          this.buffer = this.buffer.slice(at + 1);
          return stripLineEnding(line);
        }
        if (this.ended) {
          // Ultima linie a unei conducte poate să nu aibă terminator. Goală
          // înseamnă că n-a venit nimic — altceva decât o linie goală.
          if (this.buffer === "") return null;
          const rest = this.buffer;
          this.buffer = "";
          return stripLineEnding(rest);
        }
        await this.more();
      }
    });
  }

  /**
   * Citire fără ecou dintr-un terminal.
   *
   * Mod brut, ca nici măcar shellul să nu vadă linia: fără el, valoarea apare pe
   * ecran în timp ce se tastează și rămâne în scrollback. Nu se tipăresc nici
   * asteriscuri — numărul lor spune lungimea cuiva care se uită peste umăr.
   *
   * `setRawMode(false)` e în `finally` dinadins: dacă s-ar sări peste el pe o
   * cale de eroare, terminalul operatorului ar rămâne în mod brut după ce
   * procesul moare — fără ecou și fără Ctrl-C.
   */
  async readHidden(label: string, stderr: ErrorStream): Promise<string | null> {
    return await this.turn(async () => {
      stderr.write(label);
      this.stdin.setRawMode?.(true);
      try {
        // Caracterele de control se scriu prin codul lor, nu ca octeți în sursă:
        // un caracter pe care nu-l vede nimeni într-un diff e chiar felul în care
        // un diacritic într-un alias a oprit canalul de alertare o zi.
        const ABORT = [String.fromCharCode(3), String.fromCharCode(4)];   // Ctrl-C, Ctrl-D
        const ERASE = [String.fromCharCode(127), String.fromCharCode(8)]; // DEL, Backspace
        let typed = "";
        for (;;) {
          while (this.buffer.length > 0) {
            const ch = this.buffer[0];
            this.buffer = this.buffer.slice(1);
            if (ch === "\r" || ch === "\n") {
              // CRLF: al doilea octet e tot terminator, nu prima literă a
              // valorii următoare. Fără linia asta, citirea de după ar începe cu
              // o linie goală venită de nicăieri.
              if (ch === "\r" && this.buffer.startsWith("\n")) {
                this.buffer = this.buffer.slice(1);
              }
              return typed;
            }
            if (ABORT.includes(ch)) return null;
            if (ERASE.includes(ch)) { typed = typed.slice(0, -1); continue; }
            typed += ch;
          }
          // Fluxul s-a închis în timp ce se tasta: „întrerupt", nu o parolă goală.
          if (this.ended) return null;
          await this.more();
        }
      } finally {
        this.stdin.setRawMode?.(false);
        stderr.write("\n");
      }
    });
  }
}

export async function readShipSecret(io: SecretInput = {}): Promise<SecretRead> {
  const env = io.env ?? process.env;
  const stdin = io.stdin ?? process.stdin;
  const stderr = io.stderr ?? process.stderr;

  const fromEnv = env[SHIP_SECRET_ENV];
  // `!== undefined`, nu adevăr: o variabilă setată din greșeală la gol e un caz
  // obișnuit, iar căderea pe promptul următor ar face-o să pară că n-a fost
  // setată niciodată. `checkSecretShape` o refuză cu „valoarea e goală".
  if (fromEnv !== undefined) return { ok: true, raw: fromEnv, from: "env" };

  const reader = readerFor(stdin);

  if (stdin.isTTY) {
    const typed = await reader.readHidden(`${SHIP_SECRET_ENV} (nu se afișează): `,
                                          stderr);
    if (typed === null) return { ok: false, detail: "întrerupt" };
    return { ok: true, raw: typed, from: "prompt" };
  }

  const piped = await reader.readLine();
  if (piped === null) {
    return {
      ok: false,
      detail: `nu am de unde lua secretul: ${SHIP_SECRET_ENV} nu e în mediu, ` +
              "intrarea nu e un terminal, iar de la intrarea standard nu a venit " +
              "nimic. Dă-l printr-o conductă (`... | npm run instance -- ...`) " +
              "sau rulează comanda dintr-un terminal. Pe linia de comandă NU se " +
              "poate: `argv` se vede în lista de procese.",
    };
  }
  return { ok: true, raw: piped, from: "stdin" };
}
