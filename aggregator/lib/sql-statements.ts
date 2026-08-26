/**
 * Din text SQL în instrucțiuni, fiecare cu garda ei.
 *
 * Modulul ăsta există fiindcă runner-ul de migrații al agregatorului e granular
 * pe INSTRUCȚIUNE, nu pe fișier — vezi `lib/migrate.ts` pentru de ce. Ca să
 * poată fi, cineva trebuie să spargă fișierul în instrucțiuni, iar spargerea pe
 * `text.split(";")` e greșită în două feluri care nu se văd la citire: un `;`
 * dintr-un literal de șir („DELETE refused; nu se poate") taie instrucțiunea în
 * două, iar un `;` dintr-un comentariu produce o instrucțiune goală. Ambele
 * ajung la bază ca eroare de sintaxă pe un fișier care e corect.
 *
 * ## Garda e OBLIGATORIE
 *
 * Fiecare instrucțiune trebuie să aibă exact un comentariu `-- @guard ...` în
 * intervalul ei. O instrucțiune fără gardă e o EROARE de încărcare, nu o
 * instrucțiune fără pre-verificare. Motivul e chiar tiparul din `CLAUDE.md`:
 * dacă lipsa gărzii ar însemna „rulează fără să verifici", atunci o migrație
 * reluată după o cădere ar re-rula acea instrucțiune și ar muri pe „obiectul
 * există deja" — adică o migrație blocată definitiv, cu un mesaj care arată ca
 * o problemă de bază de date. Tăcerea nu e o valoare implicită acceptabilă.
 *
 * ## Ce REFUZĂM, în loc să ghicim
 *
 * * `DELIMITER` — e o directivă de CLIENT, nu SQL. Driverul nu o cunoaște, deci
 *   un fișier care are nevoie de ea nu mai poate fi rulat identic de runner și
 *   de `mysql`, iar cele două ar ajunge să aplice lucruri diferite. Corpurile
 *   de trigger din schema asta sunt de o singură instrucțiune tocmai ca să nu
 *   fie nevoie de ea.
 * * `/*!` — comentariu executabil condiționat de versiune. Un parser care îl
 *   tratează ca pe un comentariu obișnuit ȘTERGE cod pe care serverul l-ar fi
 *   executat. Mai bine refuzat decât tăiat tăcut.
 * * text rămas după ultimul `;` — un fișier trunchiat (transfer întrerupt,
 *   editor care a murit) se termină exact așa. Executarea unei instrucțiuni
 *   trunchiate e mai rea decât o eroare.
 *
 * ## Suma de control
 *
 * Se calculează peste textul EXECUTABIL: comentariile scoase, spațiile din
 * afara literalilor normalizate la unul singur. Consecința intenționată e că
 * rescrierea unui comentariu sau reindentarea nu contează ca „istorie
 * rescrisă", iar schimbarea unui identificator sau a unui tip contează. Spațiile
 * DINĂUNTRUL literalilor rămân neatinse — acolo o normalizare ar schimba datele.
 */

import { createHash } from "node:crypto";

export class SqlParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SqlParseError";
  }
}

export type Guard =
  | { kind: "table"; table: string }
  | { kind: "index"; table: string; name: string }
  | { kind: "column"; table: string; name: string }
  | { kind: "trigger"; name: string }
  /** Nimic de verificat. Cere un motiv scris, ca să nu devină ieșirea comodă. */
  | { kind: "none"; reason: string };

export type Statement = {
  /** Poziția în fișier, de la 1. Împreună cu numele fișierului, identitatea. */
  index: number;
  /** Textul care se execută: fără comentarii, spații normalizate. */
  sql: string;
  sha256: string;
  guard: Guard;
  /** Garda exact cum a fost scrisă, pentru registru și pentru mesaje. */
  guardText: string;
  /** Linia pe care începe instrucțiunea, ca mesajele să fie găsibile. */
  line: number;
};

/** Identificatori SQL simpli. Nu e o măsură de securitate — gărzile pleacă spre
 *  `information_schema` ca PARAMETRI — ci o protecție împotriva unei gărzi
 *  scrise greșit, care n-ar potrivi niciodată nimic și ar raporta „lipsește"
 *  pentru totdeauna. */
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

function parseGuard(text: string, where: string): Guard {
  const parts = text.trim().split(/\s+/);
  const kind = parts[0];
  const bad = (why: string): never => {
    throw new SqlParseError(`${where}: gardă invalidă (${why}): "@guard ${text.trim()}"`);
  };

  const ident = (value: string | undefined, what: string): string => {
    if (!value || !IDENT.test(value)) bad(`${what} nu e un identificator simplu`);
    return value as string;
  };

  switch (kind) {
    case "table":
      if (parts.length !== 2) bad("forma e: table <nume>");
      return { kind: "table", table: ident(parts[1], "numele tabelei") };
    case "index":
      if (parts.length !== 3) bad("forma e: index <tabelă> <nume>");
      return {
        kind: "index",
        table: ident(parts[1], "numele tabelei"),
        name: ident(parts[2], "numele indexului"),
      };
    case "column":
      if (parts.length !== 3) bad("forma e: column <tabelă> <nume>");
      return {
        kind: "column",
        table: ident(parts[1], "numele tabelei"),
        name: ident(parts[2], "numele coloanei"),
      };
    case "trigger":
      if (parts.length !== 2) bad("forma e: trigger <nume>");
      return { kind: "trigger", name: ident(parts[1], "numele triggerului") };
    case "none": {
      const reason = parts.slice(1).join(" ").trim();
      // Un motiv scris, obligatoriu: `none` e singura gardă care nu poate
      // dovedi nimic după execuție, deci trebuie să coste ceva să o alegi.
      if (!reason) bad("`none` cere un motiv scris după el");
      return { kind: "none", reason };
    }
    default:
      return bad("tipuri cunoscute: table, index, column, trigger, none");
  }
}

type Scan = {
  /** Textul executabil acumulat pentru instrucțiunea curentă. */
  out: string[];
  /** Gărzile găsite în intervalul instrucțiunii curente. */
  guards: string[];
  /** Linia pe care a început instrucțiunea curentă. */
  startLine: number;
  started: boolean;
  /** A intrat vreun caracter executabil în instrucțiunea curentă? */
  hasContent: boolean;
};

/** Adaugă un caracter, normalizând spațiile albe din afara literalilor. */
function pushOutside(scan: Scan, ch: string): void {
  if (/\s/.test(ch)) {
    if (scan.out.length && scan.out[scan.out.length - 1] !== " ") scan.out.push(" ");
    return;
  }
  scan.out.push(ch);
  scan.hasContent = true;
}

export function splitStatements(text: string, source: string): Statement[] {
  if (text.includes("/*!")) {
    throw new SqlParseError(
      `${source}: conține un comentariu executabil \`/*!\`. Parserul ăsta l-ar ` +
      "trata ca pe un comentariu obișnuit, adică ar ȘTERGE cod pe care serverul " +
      "l-ar fi executat. Scrie instrucțiunea pe față sau ține-o în alt fișier.");
  }

  const statements: Statement[] = [];
  const scan: Scan = {
    out: [], guards: [], startLine: 1, started: false, hasContent: false,
  };
  let line = 1;
  let i = 0;

  const finish = (): void => {
    const sql = scan.out.join("").trim();
    const where = `${source}:${scan.startLine}`;
    if (!sql) {
      // Un `;` fără nimic în fața lui. Nu se sare tăcut: e aproape sigur o
      // greșeală de editare, iar o instrucțiune goală într-un registru ar fi un
      // rând care nu descrie nimic.
      throw new SqlParseError(`${where}: instrucțiune goală (un ";" fără conținut)`);
    }
    if (scan.guards.length === 0) {
      throw new SqlParseError(
        `${where}: instrucțiunea nu are \`-- @guard ...\`. Fără gardă, o migrație ` +
        "reluată după o cădere ar re-rula-o și ar muri pe „obiectul există deja”.");
    }
    if (scan.guards.length > 1) {
      throw new SqlParseError(
        `${where}: ${scan.guards.length} gărzi pentru o instrucțiune. Nu se poate ` +
        "ști care decide, iar a alege una ar fi o ghicire.");
    }
    const guardText = scan.guards[0].trim();
    statements.push({
      index: statements.length + 1,
      sql,
      sha256: createHash("sha256").update(sql, "utf8").digest("hex"),
      guard: parseGuard(guardText, where),
      guardText,
      line: scan.startLine,
    });
    scan.out = [];
    scan.guards = [];
    scan.started = false;
    scan.hasContent = false;
  };

  while (i < text.length) {
    const ch = text[i];
    const next = text[i + 1];

    // --- comentarii ------------------------------------------------------
    // `--` e comentariu doar urmat de spațiu sau de sfârșit de linie; asta e
    // regula MariaDB, și e motivul pentru care gărzile se scriu `-- @guard`.
    const isDashComment = ch === "-" && next === "-" &&
      (i + 2 >= text.length || /[\s]/.test(text[i + 2]));
    if (isDashComment || ch === "#") {
      const skip = isDashComment ? 2 : 1;
      let end = text.indexOf("\n", i + skip);
      if (end === -1) end = text.length;
      const body = text.slice(i + skip, end).trim();
      const guard = /^@guard\b(.*)$/.exec(body);
      if (guard) {
        if (!scan.started) scan.startLine = line;
        scan.started = true;
        scan.guards.push(guard[1]);
      }
      // Aici NU se pune un separator. Comentariul de linie se termină la `\n`
      // (sau la sfârșitul fișierului), iar `i = end` lasă chiar acel `\n` să
      // fie procesat de bucla principală, care îl normalizează la un spațiu.
      // Un `pushOutside(scan, " ")` în plus ar fi o linie pe care nicio probă
      // n-o poate deosebi de absența ei — adică o cale care se poate șterge cu
      // suita verde. A stat aici o rundă și a fost scoasă când mutantul care o
      // ștergea a rămas verde.
      i = end;
      continue;
    }
    if (ch === "/" && next === "*") {
      const end = text.indexOf("*/", i + 2);
      if (end === -1) {
        throw new SqlParseError(`${source}:${line}: comentariu bloc neînchis`);
      }
      for (const c of text.slice(i, end)) if (c === "\n") line++;
      // Aici, în schimb, separatorul e obligatoriu: `SELECT/*x*/1` nu are voie
      // să devină `SELECT1`. Un comentariu bloc poate sta între doi identifi-
      // catori fără niciun spațiu în jur.
      pushOutside(scan, " ");
      i = end + 2;
      continue;
    }

    // --- literali --------------------------------------------------------
    if (ch === "'" || ch === '"' || ch === "`") {
      if (!scan.started) { scan.startLine = line; scan.started = true; }
      const quote = ch;
      scan.out.push(quote);
      scan.hasContent = true;
      i++;
      for (;;) {
        if (i >= text.length) {
          throw new SqlParseError(`${source}:${line}: literal neînchis (${quote})`);
        }
        const c = text[i];
        if (c === "\n") line++;
        // Backslash escape: valabil în MariaDB pentru ' și " (nu pentru
        // backtick). Fără el, un `\'` ar închide literalul aici și ar deschide
        // unul nou — adică textul de după ar fi citit ca SQL.
        if (c === "\\" && quote !== "`" && i + 1 < text.length) {
          scan.out.push(c, text[i + 1]);
          i += 2;
          continue;
        }
        if (c === quote) {
          // Ghilimea dublată e ghilimea, nu sfârșit.
          if (text[i + 1] === quote) {
            scan.out.push(c, c);
            i += 2;
            continue;
          }
          scan.out.push(c);
          i++;
          break;
        }
        scan.out.push(c);
        i++;
      }
      continue;
    }

    // --- directivă de client, refuzată ------------------------------------
    if (!scan.hasContent && /^delimiter\b/i.test(text.slice(i, i + 10))) {
      throw new SqlParseError(
        `${source}:${line}: \`DELIMITER\` e o directivă de CLIENT, pe care driverul ` +
        "nu o înțelege. Un fișier care are nevoie de ea nu se mai aplică la fel " +
        "prin runner și prin `mysql`. Scrie corpuri de trigger de o singură " +
        "instrucțiune, fără BEGIN ... END.");
    }

    if (ch === ";") {
      finish();
      i++;
      continue;
    }

    if (ch === "\n") line++;
    if (!/\s/.test(ch) && !scan.started) { scan.startLine = line; scan.started = true; }
    pushOutside(scan, ch);
    i++;
  }

  const trailing = scan.out.join("").trim();
  if (trailing) {
    throw new SqlParseError(
      `${source}:${scan.startLine}: text după ultimul ";" — instrucțiune neterminată. ` +
      "Așa arată un fișier trunchiat, iar executarea unei instrucțiuni trunchiate " +
      "e mai rea decât o eroare.");
  }
  if (statements.length === 0) {
    throw new SqlParseError(`${source}: niciun statement. Un fișier gol nu e o migrație.`);
  }
  return statements;
}
