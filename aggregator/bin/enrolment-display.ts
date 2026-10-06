/**
 * Ce vede operatorul la înrolarea celui de-al doilea factor: URI-ul, secretul și
 * un cod QR desenat în terminal.
 *
 * Până acum se tipărea doar URI-ul, iar operatorul a trebuit să deschidă un al
 * doilea terminal și să randeze un QR de mână, cât timp promptul de confirmare
 * aștepta în primul. Funcția de aici e ce cheamă `bin/user.ts`, în loc de
 * scrieri risipite în consolă, ca un test să poată citi ÎNTREAGA ieșire și să
 * decodeze QR-ul din ea.
 *
 * ## Ce nu are voie să iasă prost: QR-ul care codifică altceva
 *
 * Un QR care arată perfect și codifică alt șir blochează operatorul în afara
 * propriului panou, iar el afla abia când codul nu se potrivește niciodată. De-aia:
 *
 *   * ce se codifică e CHIAR `enrolment.uri`, variabila pe care o tipărește și
 *     rândul de deasupra — nu un URI refăcut;
 *   * înainte de desen, matricea se decodează înapoi cu decodorul bibliotecii și
 *     se compară cu URI-ul, octet cu octet. Dacă nu e egal sau decodorul nu poate
 *     rula, QR-ul NU se desenează și se spune de ce; URI-ul și secretul rămân.
 *     Un QR nedesenat se vede; unul greșit nu;
 *   * `tests/enrolment-display.test.ts` decodează QR-ul din ieșirea tipărită, nu
 *     din matrice, cu un mic emulator de terminal scris în test și independent de
 *     cod: asta prinde glife puse invers sau polaritate greșită.
 *
 * ## Ce poate primi terminalul — se verifică, nu se presupune
 *
 * Randarea Python a picat pe o consolă cp1252 cu `'charmap' codec can't encode
 * character '█'`. Operatorul e pe Windows PowerShell. Alegerea e pe două axe:
 *
 *   * **glife**: pe Windows, un TTY primește textul prin API-ul consolei
 *     (UTF-16), deci pagina de coduri nu contează; o ieșire redirecționată
 *     primește octeți UTF-8 pe care cititorul îi decodează cum vrea — acolo NU se
 *     presupune. Pe celelalte sisteme contează localul (`LC_ALL`, `LC_CTYPE`,
 *     `LANG`). Fără glife, fiecare modul e două spații cu fundal colorat: ASCII
 *     curat, doar secvențe de culoare;
 *   * **culoare**: se cer culori explicite, negru pe alb. Fără ele, un QR e
 *     „negru pe fundalul temei", adică inversat pe un terminal întunecat, iar
 *     multe aplicații nu scanează un QR inversat. Fără culoare (ieșire
 *     redirecționată, `NO_COLOR`, `TERM=dumb`) polaritatea nu se poate cunoaște,
 *     deci QR-ul NU se desenează, în loc să se deseneze unul care poate fi
 *     inversat. `SENTINEL_QR=unicode|ascii` îl forțează, cu polaritate pentru fundal
 *     deschis, iar `off` îl oprește.
 *
 * Lățimea: pe un terminal mai îngust decât QR-ul, rândurile se rup și desenul nu
 * se mai scanează, deci nu se desenează.
 *
 * ## Dependența
 *
 * `qr` e în `devDependencies`, cu versiune EXACTĂ: o unealtă care nu rulează pe
 * găzduire nu adaugă nimic la instalarea de producție, iar biblioteca vede secretul
 * în clar, deci nu plutește. (0.6.0 avea un decodor care refuza simboluri valide —
 * lungimi de utilizator 61, 122, ... —, iar verificarea de mai sus le-ar fi
 * suprimat; de-aia 0.7.0.) Se încarcă cu `import()` DINTR-O
 * `try`, nu static: pe o instalare fără dependențe de dezvoltare, `create` și
 * `list` trebuie să meargă în continuare, iar `enroll-totp` să arate URI-ul și
 * secretul, cu un rând care spune de ce lipsește QR-ul.
 *
 * Nimic de aici nu scrie pe disc și nu tipărește altceva decât ce primește.
 */

export type Enrolment = { username: string; uri: string; secret: string };

export type TerminalInfo = {
  isTTY: boolean;
  /** Lățimea în coloane, dacă se știe (doar pe un TTY). */
  columns?: number;
  platform: NodeJS.Platform;
  env: Record<string, string | undefined>;
};

export type QrStyle = { glyphs: "unicode" | "ascii"; color: boolean };

export type QrChoice =
  | { kind: "render"; style: QrStyle; notes: string[] }
  | { kind: "skip"; why: string; notes: string[] };

/** Ce cere `SENTINEL_QR`. */
export const QR_VARIABLE = "SENTINEL_QR";

/** Câte module de margine liberă (spec: 4). Zona liberă face parte din cod:
 *  un QR lipit de marginea ferestrei se citește mult mai greu. */
export const QUIET_ZONE = 4;

const INDENT = "      ";

// Negru și alb din paleta de 256 de culori, nu „negru" și „alb" din cele
// șaisprezece: alea sunt ce a ales tema, iar un „alb" gri-verzui sau un „negru"
// albastru strică contrastul de care are nevoie cititorul. Cele două de aici nu
// le remapează nicio temă.
const SGR_BLACK_ON_WHITE = "\u001b[38;5;16;48;5;231m";
const SGR_BLACK_BG = "\u001b[48;5;16m";
const SGR_WHITE_BG = "\u001b[48;5;231m";
const SGR_RESET = "\u001b[0m";

// Scrise cu cod, nu cu literal: sursa nu poartă glifele, deci nu depinde de cum o
// deschide un editor sau de pagina de coduri a consolei care o afișează.
const FULL = "\u2588";    // █
const UPPER = "\u2580";   // ▀
const LOWER = "\u2584";   // ▄

export function chooseQr(term: TerminalInfo): QrChoice {
  const notes: string[] = [];
  const raw = (term.env[QR_VARIABLE] ?? "").trim().toLowerCase();
  let requested = raw === "" ? "auto" : raw;
  if (!["auto", "unicode", "ascii", "off"].includes(requested)) {
    notes.push(`${QR_VARIABLE}=${JSON.stringify(raw)} nu e recunoscut ` +
               "(auto, unicode, ascii, off): se folosește auto.");
    requested = "auto";
  }
  if (requested === "off") {
    return { kind: "skip", why: `oprit prin ${QR_VARIABLE}=off.`, notes };
  }

  const color = term.isTTY &&
                (term.env.NO_COLOR ?? "") === "" &&
                (term.env.TERM ?? "") !== "dumb";
  if (requested === "auto" && !color) {
    return {
      kind: "skip", notes,
      why: "ieșirea nu e un terminal cu culori (redirecționată, NO_COLOR sau " +
           "TERM=dumb), deci nu se poate ști dacă fundalul e închis sau deschis, " +
           "iar un QR cu polaritatea greșită nu se scanează. Folosește URI-ul sau " +
           `secretul, sau forțează cu ${QR_VARIABLE}=unicode / ascii.`,
    };
  }

  let glyphs: "unicode" | "ascii";
  if (requested === "unicode" || requested === "ascii") {
    glyphs = requested;
    if (glyphs === "unicode" && term.platform === "win32" && !term.isTTY) {
      notes.push("Ieșirea nu e un terminal: glifele pleacă ca octeți UTF-8, iar " +
                 "cine îi citește (PowerShell cu pagina de coduri 437/1252) îi " +
                 "poate afișa rupți. Dacă apar rupți, folosește " +
                 `${QR_VARIABLE}=ascii.`);
    }
  } else if (term.platform === "win32") {
    // Aici terminalul are culori, deci e un TTY: pe Windows textul ajunge prin
    // API-ul consolei (UTF-16), iar pagina de coduri nu mai contează.
    glyphs = "unicode";
  } else {
    const locale = (term.env.LC_ALL || term.env.LC_CTYPE || term.env.LANG || "");
    glyphs = /utf-?8/i.test(locale) ? "unicode" : "ascii";
  }
  if (!color) {
    notes.push("Fără culori nu pot alege polaritatea: QR-ul e desenat pentru " +
               "fundal DESCHIS. Pe un terminal întunecat, dacă aplicația nu " +
               "scanează, folosește URI-ul sau secretul.");
  }
  return { kind: "render", style: { glyphs, color }, notes };
}

/** Câte coloane ocupă desenul, fără indentare. */
export function qrWidth(modules: number, style: QrStyle): number {
  return (modules + 2 * QUIET_ZONE) * (style.glyphs === "unicode" ? 1 : 2);
}

/**
 * Matricea (rând, coloană; `true` = modul închis) ca rânduri de text.
 * Zona liberă se adaugă aici.
 */
export function renderQrLines(matrix: boolean[][], style: QrStyle): string[] {
  const n = matrix.length;
  const total = n + 2 * QUIET_ZONE;
  const dark = (row: number, col: number): boolean => {
    const r = row - QUIET_ZONE;
    const c = col - QUIET_ZONE;
    return r >= 0 && r < n && c >= 0 && c < n && matrix[r][c] === true;
  };

  const lines: string[] = [];
  if (style.glyphs === "unicode") {
    // Două rânduri de module pe un rând de text: jumătatea de sus și cea de jos.
    for (let row = 0; row < total; row += 2) {
      let text = "";
      for (let col = 0; col < total; col++) {
        const top = dark(row, col);
        const bottom = dark(row + 1, col);
        text += top && bottom ? FULL : top ? UPPER : bottom ? LOWER : " ";
      }
      lines.push(INDENT + (style.color
        ? SGR_BLACK_ON_WHITE + text + SGR_RESET : text));
    }
  } else {
    for (let row = 0; row < total; row++) {
      let text = "";
      if (style.color) {
        // Un modul = două spații cu fundal; două, fiindcă o celulă de terminal e
        // de ~2× mai înaltă decât lată, iar modulul trebuie să iasă pătrat.
        let previous: boolean | null = null;
        for (let col = 0; col < total; col++) {
          const d = dark(row, col);
          if (d !== previous) text += d ? SGR_BLACK_BG : SGR_WHITE_BG;
          text += "  ";
          previous = d;
        }
        text += SGR_RESET;
      } else {
        for (let col = 0; col < total; col++) text += dark(row, col) ? "##" : "  ";
      }
      lines.push(INDENT + text);
    }
  }
  return lines;
}

/**
 * Matricea ca imagine RGBA (4 px pe modul, cu zona liberă), pentru decodor.
 * NU e desenul din terminal — e matricea care ar ajunge la desen.
 */
function matrixImage(matrix: boolean[][]): { width: number; height: number;
                                              data: Uint8ClampedArray } {
  const scale = 4;
  const side = (matrix.length + 2 * QUIET_ZONE) * scale;
  const data = new Uint8ClampedArray(side * side * 4).fill(255);
  for (let y = 0; y < matrix.length; y++) {
    for (let x = 0; x < matrix.length; x++) {
      if (!matrix[y][x]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const px = ((y + QUIET_ZONE) * scale + dy) * side +
                     (x + QUIET_ZONE) * scale + dx;
          data[px * 4] = data[px * 4 + 1] = data[px * 4 + 2] = 0;
        }
      }
    }
  }
  return { width: side, height: side, data };
}

type Built = { matrix: boolean[][] } | { failed: string };

/** Cele două funcții de care are nevoie desenul. Parametrul `load` există ca un
 *  test să poată pune în locul lor o bibliotecă stricată sau absentă. */
export type QrLibs = {
  encodeQR: typeof import("qr").encodeQR;
  decodeQR: typeof import("qr/decode.js").decodeQR;
};

async function loadLibs(): Promise<QrLibs> {
  const { encodeQR } = await import("qr");
  const { decodeQR } = await import("qr/decode.js");
  return { encodeQR, decodeQR };
}

/**
 * Codifică URI-ul și dovedește, înainte de orice desen, că matricea se decodează
 * înapoi la același șir. Nu include niciodată URI-ul sau secretul în mesaj.
 */
export async function buildVerifiedMatrix(
  uri: string, load: () => Promise<QrLibs> = loadLibs,
): Promise<Built> {
  let libs: QrLibs;
  try {
    libs = await load();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return {
      failed: code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND"
        ? "pachetul `qr` nu e instalat (e în devDependencies: `npm install` " +
          "fără `--omit=dev`)."
        : "pachetul `qr` nu s-a putut încărca.",
    };
  }
  const { encodeQR, decodeQR } = libs;

  // `border: 0` e REFUZAT de bibliotecă (zona liberă e obligatorie în standard).
  // Cea mai mică e 1, iar inelul ăla se taie, ca zona liberă să fie a noastră:
  // aceeași în toate stilurile de desen. Decodarea de mai jos e proba că tăierea
  // a păstrat exact simbolul.
  //
  // Corecția de erori `low`: ecranul nu se murdărește și nu se rupe ca hârtia, iar
  // un cod mai mic înseamnă module mai late pe același ecran și — mai ales — o
  // lățime care încape într-o consolă de 120 de coloane și în stilul ASCII, unde
  // un modul are două coloane.
  let matrix: boolean[][];
  try {
    const bordered = encodeQR(uri, "raw", { ecc: "low", border: 1 });
    matrix = bordered.slice(1, -1).map((row) => row.slice(1, -1));
  } catch (err) {
    return { failed: `codificarea a eșuat (${(err as Error).name}).` };
  }
  const n = matrix.length;
  if (n < 21 || matrix.some((row) => row.length !== n)) {
    return { failed: "biblioteca a întors o matrice care nu e pătrată." };
  }

  let decoded: string;
  try {
    decoded = decodeQR(matrixImage(matrix));
  } catch (err) {
    return { failed: "decodarea de verificare a eșuat " +
                     `(${(err as Error).name}), deci nu pot dovedi că QR-ul e corect.` };
  }
  if (decoded !== uri) {
    return { failed: "decodat înapoi, QR-ul NU dă URI-ul — desenul ar fi " +
                     "înrolat altceva decât secretul de mai sus." };
  }
  return { matrix };
}

/** Proză pe rânduri de cel mult 78 de coloane, cu aceeași indentare. */
function wrap(text: string, width = 78): string[] {
  const lines: string[] = [];
  let line = " ";
  for (const word of text.split(" ")) {
    if (line.length > 1 && line.length + 1 + word.length > width) {
      lines.push(line);
      line = " ";
    }
    line += " " + word;
  }
  lines.push(line);
  return lines;
}

/**
 * Întreaga ieșire a înrolării, rând cu rând. Ordinea: instrucțiunea, URI-ul și
 * secretul, avertismentul, apoi QR-ul ultimul — ca să rămână pe ecran lângă
 * promptul de confirmare care urmează, nu împins în sus de el.
 *
 * Instrucțiunea din cap depinde de rezultat: nu trimite la „codul QR de mai jos"
 * dacă dedesubt scrie că a fost omis.
 */
export async function enrolmentLines(
  enrolment: Enrolment, term: TerminalInfo,
  load: () => Promise<QrLibs> = loadLibs,
): Promise<string[]> {
  // Mai întâi se hotărăște soarta QR-ului, apoi se scrie restul.
  const choice = chooseQr(term);
  const tail: string[] = choice.notes.flatMap((note) => wrap(note));
  let drawn = false;
  if (choice.kind === "skip") {
    tail.push(...wrap(`QR omis: ${choice.why}`));
  } else {
    const built = await buildVerifiedMatrix(enrolment.uri, load);
    if ("failed" in built) {
      tail.push(...wrap(`QR omis: ${built.failed} URI-ul și secretul de mai sus ` +
                        "rămân valabile."));
    } else {
      const need = INDENT.length + qrWidth(built.matrix.length, choice.style);
      if (term.columns !== undefined && need > term.columns) {
        tail.push(...wrap(`QR omis: are nevoie de ${need} coloane, iar terminalul ` +
                          `are ${term.columns}; rândurile s-ar rupe și desenul nu ` +
                          "s-ar scana. Mărește fereastra și rulează din nou " +
                          "`enroll-totp` (alt secret), sau folosește URI-ul."));
      } else {
        drawn = true;
        tail.push(...renderQrLines(built.matrix, choice.style), "");
        if (choice.style.glyphs === "unicode") {
          tail.push(...wrap("Dacă QR-ul apare rupt (blocuri lipsă sau «?»): Ctrl+C " +
                            `și rulează din nou \`enroll-totp\` cu ${QR_VARIABLE}=` +
                            "ascii (alt secret; cel de acum se abandonează)."));
        }
      }
    }
  }

  return [
    "",
    "=".repeat(64),
    `  ÎNROLARE AL DOILEA FACTOR — ${enrolment.username}`,
    "=".repeat(64),
    "",
    ...(drawn
      ? ["  Scanează codul QR de mai jos cu aplicația de autentificare (Aegis,",
         "  1Password, Google Authenticator), sau lipește URI-ul / introdu secretul",
         "  de mână:"]
      : ["  Lipește URI-ul în aplicația de autentificare (Aegis, 1Password,",
         "  Google Authenticator) sau introdu secretul de mână:"]),
    "",
    `      ${enrolment.uri}`,
    "",
    `      secret: ${enrolment.secret}`,
    "",
    ...wrap(`ATENȚIE: ${drawn ? "URI-ul, secretul și QR-ul poartă" :
                                "URI-ul și secretul poartă"} ACEEAȘI valoare și se ` +
            "afișează O SINGURĂ DATĂ. În bază e cifrat, deci nu poate fi " +
            "reafișat. Pierdut, rulează `enroll-totp`. Nu face captură de ecran, " +
            "iar după scanare curăță terminalul: secretul rămâne în istoricul lui."),
    "",
    ...tail,
    "=".repeat(64),
    "",
  ];
}
