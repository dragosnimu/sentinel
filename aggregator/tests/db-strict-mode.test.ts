/**
 * `sql_mode` strict pe FIECARE sesiune, și nicio cale de conectare pe lângă.
 *
 * ## Ce se strică fără regula asta
 *
 * Măsurat pe MariaDB al agregatorului pe 17 august 2026:
 * `sql_mode = NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION` — **fără**
 * `STRICT_TRANS_TABLES`. Sub un mod nestrict un șir mai lung decât coloana nu e
 * refuzat, e TĂIAT, cu un avertisment. Instrucțiunea reușește, rândul e
 * PREZENT — iar `countPresent` din `lib/ingest.ts` numără prezența. Deci rândul
 * tăiat trece drept bun, filigranul se ecouă, iar cursorul expeditorului trece
 * peste el definitiv: nimic nu se mai întoarce după un rând pe care emitentul îl
 * crede livrat. Pe autentificare, același mod face dintr-un nume cu diacritice
 * un cont scris cu `?`, sub o cheie unică, pe care nimeni nu-l mai poate retasta.
 *
 * ## Unde ajunge reparația, și unde NU — scris aici ca să nu fie citit mai larg
 *
 * Modul strict ridică tăierea la eroare pe instrucțiunile fără `IGNORE`:
 * `INSERT`/`UPDATE` simplu și `INSERT ... ON DUPLICATE KEY UPDATE`. Adică pe
 * fluxurile mutabile ale ingestiei (`incidents` → `incident_entries`), pe
 * scrierile de autentificare, pe migrații, pe datele zero.
 *
 * **Pe calea vie nu.** `writeSql` din `lib/ingest.ts` scrie cu `INSERT IGNORE`
 * fluxurile append-only și tabelele de legătură care sunt numai identitate, iar
 * `audit_log` → `audit_entries` — singurul flux înregistrat azi în producție —
 * e chiar acolo, obligat de triggerul append-only din `migrations/0001_core.sql`.
 * Sub `IGNORE`, MariaDB documentează că modurile stricte **nu se aplică deloc**
 * și că erorile de date coboară la avertismente; un șir prea lung nu ridică
 * 1406, se taie cu 1265, iar 1265 e chiar în lista coborâtă. Pe gazda noastră
 * NEMĂSURAT — pasul 4 al probei din `README.md` există ca să răspundă. Ce apără
 * calea aia azi e `checkString` + `column.maxBytes` din `lib/ingest.ts`, la
 * nivel de aplicație, refuz în loc de tăiere.
 *
 * Deci ce se probează mai jos e că modul CERUT ajunge pe fiecare sesiune, nu că
 * fiecare scriere e apărată de el.
 *
 * ## Ce se poate dovedi de aici, și ce NU
 *
 * **Se poate:** că fiecare cale de conectare chiar emite instrucțiunea, în ce
 * ordine, ce face cu răspunsul — și că nu există o a treia cale nedeclarată.
 * Astea sunt afirmații pe EFECT: dublurile primesc chiar instrucțiunea și
 * răspund cu ce ar răspunde serverul.
 *
 * **NU se poate:** că serverul chiar refuză o scriere care ar fi fost tăiată.
 * Aia cere MariaDB la capăt, iar procedura pe care o rulează operatorul e în
 * `README.md`, secțiunea „Proba prin EFECT, pe gazdă — ce trebuie rulat și ce
 * răspuns e bun" (titlul e citat verbatim dinadins: dacă se redenumește, cine
 * caută nu găsește). Câteva aserțiuni de mai jos sunt pe FORMA instrucțiunii (că
 * adaugă în loc să înlocuiască, că tratează un `sql_mode` gol); alea sunt
 * afirmații pe ce CEREM, nu pe ce face serverul, și sunt scrise aici ca să nu
 * fie citite ca mai mult.
 *
 * ## De ce recensăminte, și de ce NUMĂRĂ în loc să recunoască
 *
 * Reparația ține doar dacă e în SINGURUL loc prin care trec TOATE conexiunile.
 * O cale nouă adăugată mâine fără mod strict e cel mai greu defect de găsit
 * tocmai fiindcă restul e reparat: simptomul e un rând tăiat, o dată, pe un flux.
 *
 * Deci regulile de mai jos nu caută tipare greșite cunoscute — numără, și numără
 * NUME. Două nume, fiindcă la o sesiune nestrictă se ajunge în două feluri:
 *
 *   1. **ajungând la driver pe lângă `lib/db.ts`** — numele `mysql` apare în
 *      CODUL fișierelor livrate numai unde e declarat, și acolo de exact atâtea
 *      ori cât e declarat. Numărul pe fișier prinde și cazul greu: o a doua cale
 *      deschisă CHIAR ÎN `lib/db.ts`, care n-ar schimba lista de fișiere;
 *   2. **anulând modul după ce a fost pus** — numele `sql_mode` apare în cod
 *      numai în `lib/db.ts`, deci nimeni nu-l rescrie pe o sesiune deja pornită.
 *
 * ### De ce pe NUME, și nu pe forma lucrului păzit
 *
 * Fiindcă forma a fost evadată, de două ori, în aceeași lună.
 *
 * La `sql_mode`, prima versiune căuta
 * `SET [SESSION|GLOBAL|@@SESSION.|@@GLOBAL.] sql_mode`, iar MariaDB acceptă cel
 * puțin încă cinci ortografii ale ACELEIAȘI atribuiri pe sesiune: `SET @@sql_mode`
 * (cea obișnuită), `SET @@local.sql_mode`, `SET LOCAL sql_mode`,
 * `SET STATEMENT sql_mode = '' FOR <instrucțiune>` (suprascrierea per-instrucțiune
 * a MariaDB — exact lucrul spre care întinde mâna cineva când modul strict începe
 * să refuze o instrucțiune și vrea să treacă azi), a doua atribuire dintr-o listă
 * (`SET autocommit = 1, sql_mode = ''`), și oricare dintre ele scrisă în alt fel
 * de spații. O alternanță nu se termină niciodată de scris; numele variabilei,
 * da: nu există atribuire care să nu-l conțină.
 *
 * La driver, versiunea dinainte potrivea ORTOGRAFIA specificatorului de modul
 * (`/["']mysql\d*(?:\/[\w./-]+)?["']/`) și își scria premisa pe față: „proza
 * folosește accente grave, importul folosește ghilimele". Premisa e FALSĂ.
 * `require()` și `await import()` iau orice expresie, iar un literal de șablon —
 * ``requireFrom(`mysql2/promise`)`` — e chiar forma pe care o scrie cineva care
 * lucrează în TypeScript; sunt și cele două forme pe care `lib/db.ts` însuși le
 * folosește. Măsurat pe 17 august 2026: un `lib/reports-db.ts` scris așa lăsa
 * suita ÎNTREAGĂ verde. Un specificator n-are ortografie obligatorie; numele
 * pachetului, da: nu se poate ajunge la el fără să-l scrii.
 *
 * ### Ce e „cod" și ce e „proză", fiindcă de asta atârnă amândouă
 *
 * Aceeași premisă falsă a doua oară: verificarea care păzea fișierele declarate
 * ca proză sărea peste orice apariție învelită în accente grave. În `.md` aia e
 * proză; într-un `.ts` accentele grave sunt COD. Măsurat: linia
 * ``await q.query("SET SESSION " + `sql_mode` + " = ''")`` pusă în
 * `lib/auth/users.ts` — fișier declarat drept „doar vorbește despre asta" —
 * lăsa suita ÎNTREAGĂ verde. Jetonul era întreg în text, garda îl citea, și îl
 * sărea dinadins.
 *
 * Deosebirea adevărată nu e ortografia, e LOCUL: proza stă în COMENTARII.
 *
 * A treia oară, cauza s-a mutat încă un strat mai jos: nu ortografia
 * specificatorului, nu accentele grave, ci LINIA. Versiunea dinainte golea linia
 * ÎNTREAGĂ după `/^\s*(\/\/|\/\*|\*($|[\s\/]))/`. Dar `//` la început chiar
 * înseamnă linie de comentariu, iar `/*` NU: un comentariu de bloc deschis și
 * închis la începutul liniei e urmat de COD pe aceeași linie, iar scuza scrisă
 * lângă gest e chiar felul în care se scrie gestul. Măsurat de două ori, cu
 * suita la `pass 519 / fail 0` și `tsc` cu ieșire 0: un
 * `SET STATEMENT sql_mode = '' FOR UPDATE users …` pus în `lib/auth/users.ts`
 * după o scuză de o linie, și un al doilea `createRequire(…)("mysql2/promise")`
 * pus CHIAR ÎN `lib/db.ts` după alta. Amândouă verzi, amândouă vii.
 *
 * Deci nu se mai ghicește din capul liniei. Comentariile se cer LEXERULUI care
 * citește oricum fișierul mai departe:
 *
 *   * `.ts` și rudele lui: parserul din `typescript` — deja devDependency, e
 *     chiar cel care rulează la `npm run typecheck`. Din arbore se iau
 *     intervalele de comentariu și se golesc caracter cu caracter, păstrând
 *     sfârșiturile de linie. Ce rămâne e ce ajunge la Node: un literal de șablon
 *     rămâne întreg oricum ar începe liniile lui, o expresie regulată nu se
 *     confundă cu o împărțire, iar un comentariu de la capătul unei linii de cod
 *     DISPARE — corect, fiindcă un comentariu e proză oriunde ar sta;
 *   * `.sql`: `splitStatements` din `lib/sql-statements.ts`, adică chiar
 *     cititorul care sparge migrațiile pentru MariaDB. Nu un al doilea — capul
 *     lui `tests/sql-reading.ts` scrie de ce o a doua copie e a doua șansă ca
 *     cele două să difere.
 *
 * Un fișier pe care lexerul NU-l poate citi până la capăt (`.ts` care nu se
 * parsează, `.sql` care nu e o migrație validă) e REFUZAT, cu numele lui. „Nu
 * știu ce e în el" și „nu e nimic în el" sunt stări diferite: colapsate, un
 * fișier necitit ar intra în recensământ cu zero apariții — adică ar trece.
 *
 * Registrele de proză rămân, dar au acum alt rol: nu mai sunt ele cele care
 * deosebesc proza de cod, sunt plasa de dedesubt. Dacă golirea mușcă vreodată
 * dintr-o linie pe care n-ar fi trebuit, recensământul pe TEXTUL întreg tot vede
 * fișierul — și îl refuză, dacă nu e declarat.
 *
 * ### Ce NU văd recensămintele astea (limitele, scrise fiindcă sunt reale)
 *
 * * **Un director frate nou.** `shippedFiles()` umblă prin `app`, `lib`, `bin`,
 *   `migrations` plus rădăcina — lista e scrisă cu mâna. Un `aggregator/jobs/`
 *   care importă driverul și golește `sql_mode` e INVIZIBIL pentru amândouă.
 *   E preexistent și împărțit de fiecare gardă construită pe
 *   `tests/shipped-files.ts`; acolo e scris pe larg.
 * * **Alt driver.** Se numără numele `mysql`. Pachetul npm `mariadb` — celălalt
 *   driver Node pentru serverul ăsta — ar trece nevăzut, iar nimic de aici nu se
 *   uită la dependențele din `package.json`.
 * * **Jetonul rupt în două.** Amândouă citesc TEXTUL fișierelor. `"SET @@sql" +
 *   "_mode = ''"` sau o instrucțiune venită din date nu se potrivesc.
 *   Concatenarea care PĂSTREAZĂ jetonul întreg se prinde (`"mysql" +
 *   "2/promise"` conține `mysql`). Garda e pentru calea pe care se scrie din
 *   greșeală, nu împotriva cuiva care o ocolește dinadins.
 * * **Jetonul scris cu evadări.** Măsurat pe 18 august 2026, pe lexerul de mai
 *   jos: `"SET @@\u0073ql_mode = ''"` și `requireFrom("m\u0079sql2/promise")` se
 *   parsează curat, nu conțin niciun comentariu, și tot nu se văd — fiindcă în
 *   TEXT scrie `\u0073ql_mode`, iar la Node ajunge `sql_mode`. E aceeași clasă
 *   cu jetonul rupt în două, scrisă separat fiindcă aici jetonul PARE întreg la
 *   citire. Un lexer nu o închide: ar trebui evaluată valoarea literalilor, iar
 *   asta e deja un interpret. Garda rămâne pentru greșeală, nu pentru ocolire.
 *
 * În sesiunea în care a fost scris fișierul ăsta, gărzile pe ORTOGRAFIE din
 * depozit au fost evadate de opt ori (un `ON (\w+)` care nu vedea
 * `schema.tabela`, un `SQL_TOUCH` fără fanionul `i`, accente grave de două ori,
 * un `SHIPPED` care nu cuprindea rădăcina proiectului Next.js, unul care nu
 * cuprindea `.mts`/`.cts`, și chiar `SET ... sql_mode` de mai sus). De-aia
 * fiecare tipar de mai jos e probat în AMBELE direcții înainte să fie folosit —
 * cu formele POZITIVE derivate din gramatica lucrului păzit, nu din ce s-a mai
 * scris pe aici —, iar verdictul e un `deepEqual` cu un registru, nu un „nu
 * conține".
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import ts from "typescript";

import {
  READ_SESSION_SQL_MODE, REQUIRED_SQL_MODES, SET_SESSION_SQL_MODE,
  applyStrictSession, closePool, createDirectConnection, getPool,
  initPooledConnection, missingSqlModes,
} from "../lib/db";
import { splitStatements } from "../lib/sql-statements";
import { readShipped, shippedFiles, shippedMatching } from "./shipped-files";
import type { Connection, Pool, PooledConnection } from "../lib/db";

const ENV = {
  AGGREGATOR_DB_USER: "u",
  AGGREGATOR_DB_PASSWORD: "p",
  AGGREGATOR_DB_NAME: "d",
};

/** Ce ar răspunde gazda MĂSURATĂ după ce instrucțiunea noastră a intrat. */
const HOST_MODES = "NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION";
const STRICT_ANSWER = `${HOST_MODES},${REQUIRED_SQL_MODES.join(",")}`;

// ---------------------------------------------------------------------------
// Cod și proză: primitiva pe care se sprijină amândouă recensămintele
// ---------------------------------------------------------------------------

/**
 * Ce fel de fișier îi dăm parserului, după extensie.
 *
 * Nu e cosmetic: un `.tsx` citit ca `.ts` nu se parsează — `<p>` devine o
 * aserțiune de tip —, iar un fișier care nu se parsează e REFUZAT mai jos, nu
 * citit pe jumătate. Niciun `.tsx` livrat azi, dar extensia e în
 * `SHIPPED_EXTENSIONS`, iar `app/` e chiar locul unde apare primul.
 */
const SCRIPT_KINDS: ReadonlyArray<readonly [RegExp, ts.ScriptKind]> = [
  [/\.tsx$/, ts.ScriptKind.TSX],
  [/\.jsx$/, ts.ScriptKind.JSX],
  [/\.(mjs|cjs|js)$/, ts.ScriptKind.JS],
];

function scriptKindOf(file: string): ts.ScriptKind {
  for (const [extension, kind] of SCRIPT_KINDS) if (extension.test(file)) return kind;
  return ts.ScriptKind.TS;
}

/**
 * Frunzele arborelui, în ordinea din fișier.
 *
 * Ele poartă tot ce NU e trivia, iar trivia dinaintea fiecăreia e chiar
 * intervalul din care se culeg comentariile. Se coboară cu `getChildren`, nu cu
 * `forEachChild`: al doilea sare peste jetoanele de punctuație, deci un
 * comentariu de bloc scris chiar înaintea unei virgule n-ar avea nicio frunză
 * care să-l vadă și ar rămâne neatins.
 *
 * Nodurile JSDoc sunt SĂRITE. TypeScript le agață în arbore ca noduri, deși
 * textul lor e un comentariu — jetonul de după își păstrează oricum trivia
 * întreagă, deci comentariul se culege de acolo. Ținute, ele ar fi „jetoane"
 * care există în fișierul original și dispar din cel golit, iar proba pe fluxul
 * de jetoane de mai jos ar raporta ca diferență chiar lucrul pe care îl cere.
 */
const JSDOC_KINDS = { from: ts.SyntaxKind.FirstJSDocNode, to: ts.SyntaxKind.LastJSDocNode };

function leafTokens(source: ts.SourceFile): ts.Node[] {
  const leaves: ts.Node[] = [];
  const visit = (node: ts.Node): void => {
    if (node.kind >= JSDOC_KINDS.from && node.kind <= JSDOC_KINDS.to) return;
    const children = node.getChildren(source);
    if (children.length === 0) { leaves.push(node); return; }
    for (const child of children) visit(child);
  };
  visit(source);
  return leaves;
}

/**
 * Intervalele de comentariu ale unui fișier TypeScript.
 *
 * Se cer AMÂNDOUĂ familiile pentru fiecare frunză, fiindcă TypeScript le împarte
 * după linie, nu după apartenență: `getLeadingCommentRanges` începe să adune
 * abia după primul sfârșit de linie, deci comentariul scris pe ACEEAȘI linie cu
 * jetonul dinainte — chiar forma care a evadat versiunea pe linii — îl dă numai
 * `getTrailingCommentRanges`. Măsurat: cu numai prima, un comentariu de bloc
 * urmat de cod pe aceeași linie rămânea întreg în „cod".
 *
 * Și se taie la ÎNCEPUTUL jetonului. Amândouă citesc textul brut de la o
 * poziție, deci pe o frunză fără trivia înaintea ei se uită la frunza însăși —
 * iar textul JSX chiar poate începe cu două bare oblice. Măsurat: fără tăiere,
 * `<p>` urmat de așa ceva golea restul liniei, cu tot codul de după el.
 */
function commentRanges(text: string, source: ts.SourceFile): ts.CommentRange[] {
  const found = new Map<number, ts.CommentRange>();
  for (const leaf of leafTokens(source)) {
    const from = leaf.getFullStart();
    const until = leaf.getStart(source);
    for (const range of [...(ts.getLeadingCommentRanges(text, from) ?? []),
                         ...(ts.getTrailingCommentRanges(text, from) ?? [])]) {
      if (range.end <= until) found.set(range.pos, range);
    }
  }
  return [...found.values()].sort((a, b) => a.pos - b.pos);
}

/** Textul cu intervalele date golite. Sfârșiturile de linie rămân, ca linia
 *  raportată la un eșec să fie chiar linia din fișier. */
function blankOut(text: string, ranges: ReadonlyArray<ts.CommentRange>): string {
  let out = "";
  let at = 0;
  for (const range of ranges) {
    out += text.slice(at, range.pos) +
           text.slice(range.pos, range.end).replace(/[^\n]/g, " ");
    at = range.end;
  }
  return out + text.slice(at);
}

type Lexed = {
  /** Ce rămâne după ce se golesc comentariile. */
  code: string;
  /** De ce NU s-a putut citi fișierul. Gol înseamnă „citit până la capăt", și e
   *  singura stare din care are voie să iasă un verdict. */
  unreadable: string[];
};

function lexTs(text: string, file: string): Lexed {
  const source = ts.createSourceFile(
    file, text, ts.ScriptTarget.Latest, /* setParentNodes */ false, scriptKindOf(file));
  // `parseDiagnostics` nu e în tipurile publice ale lui TypeScript, deci se
  // verifică pe față că e un tablou: dacă o versiune viitoare îl redenumește, ce
  // trebuie să iasă e „nu se știe dacă fișierul s-a parsat", nu „s-a parsat
  // curat" — a doua ar fi chiar minciuna împotriva căreia e scris tot fișierul.
  const diagnostics =
    (source as unknown as { parseDiagnostics?: unknown }).parseDiagnostics;
  if (!Array.isArray(diagnostics)) {
    return { code: text, unreadable: [
      "typescript nu mai expune `parseDiagnostics`, deci nu se poate ști dacă " +
      "fișierul s-a parsat întreg"] };
  }
  if (diagnostics.length) {
    // Un fișier care nu se parsează are un arbore cu găuri, iar dintr-un arbore
    // cu găuri comentariile ies greșit în AMÂNDOUĂ direcțiile. Nu se ghicește.
    const first = diagnostics[0] as ts.Diagnostic;
    const line = first.start === undefined
      ? "?"
      : source.getLineAndCharacterOfPosition(first.start).line + 1;
    return { code: text, unreadable: [
      `nu se parsează (${diagnostics.length} erori; linia ${line}: ` +
      `${ts.flattenDiagnosticMessageText(first.messageText, " ")})`] };
  }
  return { code: blankOut(text, commentRanges(text, source)), unreadable: [] };
}

/**
 * Codul unui fișier `.sql`: instrucțiunile, așa cum le citește runnerul.
 *
 * Nu un al doilea cititor — `splitStatements` din `lib/sql-statements.ts` e chiar
 * cel care sparge migrațiile pentru MariaDB: urmărește șirurile, scoate
 * comentariile și refuză `/*!`. Capul lui `tests/sql-reading.ts` scrie de ce a
 * doua copie a unui cititor de instrucțiuni e a doua șansă ca cele două să
 * difere.
 *
 * Fiecare instrucțiune se așază pe LINIA pe care începe, ca numărul raportat la
 * un eșec să ducă unde trebuie în fișier.
 */
function lexSql(text: string, file: string): Lexed {
  const lines = text.split("\n").map(() => "");
  try {
    for (const statement of splitStatements(text, file)) {
      const at = statement.line - 1;
      lines[at] = lines[at] ? `${lines[at]} ${statement.sql}` : statement.sql;
    }
  } catch (err) {
    return { code: "", unreadable: [(err as Error).message] };
  }
  return { code: lines.join("\n"), unreadable: [] };
}

function lex(text: string, file: string): Lexed {
  return file.endsWith(".sql") ? lexSql(text, file) : lexTs(text, file);
}

/**
 * Codul unui text livrat: ce ajunge la Node sau la MariaDB.
 *
 * ARUNCĂ dacă lexerul nu l-a putut citi până la capăt. Un fișier necitit ar intra
 * în recensămintele de mai jos cu zero apariții — adică ar trece, iar „n-am putut
 * citi" ar fi raportat ca „nu e nimic acolo".
 */
function codeText(text: string, file: string): string {
  const { code, unreadable } = lex(text, file);
  if (unreadable.length) {
    throw new Error(
      `${file} nu s-a putut citi: ${unreadable.join("; ")}. Un fișier pe care ` +
      "lexerul nu-l parcurge nu e un fișier fără `mysql` și fără `sql_mode`, e " +
      "un fișier despre care nu se știe nimic.");
  }
  return code;
}

/**
 * Amprenta fiecărui jeton: fel, poziție ȘI text.
 *
 * Textul, nu doar întinderea: o golire care ar mușca din interiorul unui șir ar
 * lăsa poziția și felul neatinse, iar o comparație pe ele ar trece.
 */
function tokenPrints(text: string, file: string): string[] {
  const source = ts.createSourceFile(
    file, text, ts.ScriptTarget.Latest, false, scriptKindOf(file));
  return leafTokens(source).map((leaf) => {
    const from = leaf.getStart(source);
    return `${leaf.kind}@${from}-${leaf.end}:${text.slice(from, leaf.end)}`;
  });
}

/** Codul fișierelor livrate, ținut în memorie: nu se schimbă în timpul unei
 *  rulări, iar recensămintele trec de mai multe ori prin toate. */
const CODE = new Map<string, string>();

/** Codul unui fișier livrat, adică ce ajunge la Node sau la MariaDB. */
function codeOf(file: string): string {
  const known = CODE.get(file);
  if (known !== undefined) return known;
  const code = codeText(readShipped(file), file);
  CODE.set(file, code);
  return code;
}

/** Același tipar, dar global. Tiparele declarate mai jos n-au voie să poarte `g`
 *  singure: un `test()` cu `g` e cu stare, iar a doua chemare minte. */
function everywhere(token: RegExp): RegExp {
  return token.flags.includes("g")
    ? token
    : new RegExp(token.source, `${token.flags}g`);
}

/** Aparițiile jetonului în CODUL fișierului, cu linia și vecinătatea lor. */
function codeMentions(file: string, token: RegExp): string[] {
  const code = codeOf(file);
  const found: string[] = [];
  for (const match of code.matchAll(everywhere(token))) {
    const at = match.index ?? 0;
    const line = code.slice(0, at).split("\n").length;
    found.push(`linia ${line}: ` +
               code.slice(Math.max(0, at - 40), at + 40).replace(/\s+/g, " ").trim());
  }
  return found;
}

/**
 * Fișier → ORTOGRAFIA fiecărei apariții din cod → de câte ori.
 *
 * Ortografia, nu doar totalul: `Mysql2` schimbat în `mysql2` mută o apariție de
 * la un nume de tip la un specificator de modul — exact deosebirea care contează
 * —, iar un total ar rămâne același.
 */
function codeMentionCounts(token: RegExp): Record<string, Record<string, number>> {
  const out: Record<string, Record<string, number>> = {};
  for (const file of shippedFiles()) {
    for (const match of codeOf(file).matchAll(everywhere(token))) {
      const per = out[file] ?? (out[file] = {});
      per[match[0]] = (per[match[0]] ?? 0) + 1;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Recensământul 1: cine ajunge la driver
// ---------------------------------------------------------------------------

/**
 * NUMELE pachetului, nu ortografia specificatorului. De ce, în capul fișierului.
 *
 * `\d*` fiindcă `mysql` și `mysql2` sunt amândouă pachete npm reale; `\b` la
 * capete ca `mysql2/promise` să se numere o dată; `i` fiindcă tipul din
 * `lib/db.ts` se cheamă `Mysql2` iar proza scrie „MySQL".
 */
const DRIVER_TOKEN = /\bmysql\d*\b/i;

/**
 * Fișierele livrate în al căror COD apare numele driverului, cu ortografia și
 * numărul fiecărei apariții.
 *
 * Pe fișier ȘI pe număr, ca să acopere și cazul greu: o a doua cale de conectare
 * deschisă CHIAR ÎN `lib/db.ts` — o funcție care își cere singură driverul, cu
 * orice fel de ghilimele sau printr-un `await import` — nu schimbă lista de
 * fișiere, dar mută `mysql2` de la 1 la 2.
 *
 * O intrare în plus care nu mai corespunde niciunui fișier pică la fel ca una
 * lipsă: o scutire moartă e o scutire care într-o zi acoperă altceva.
 */
const DRIVER_IN_CODE: Record<string, Record<string, number>> = {
  // Singurul loc care deschide conexiuni; tot de aici pleacă și sql_mode-ul
  // strict. Cele trei ortografii sunt trei lucruri diferite, de-aia sunt numărate
  // separat.
  "lib/db.ts": {
    mysql: 3,   // accesorul: definiția lui, plus cele două folosiri din DRIVER_ENTRIES
    Mysql2: 3,  // tipul îngust prin care trece tot ce vine de la driver
    mysql2: 1,  // SPECIFICATORUL de modul — exact o dată
  },
  // Mesajul care refuză `DELIMITER` numește CLIENTUL `mysql`, nu pachetul npm:
  // text pentru operator, într-un fișier care nu deschide nicio conexiune.
  "lib/sql-statements.ts": { mysql: 1 },
};

/**
 * Fișierele livrate care îl pomenesc numai în COMENTARII, cu ce explică fiecare.
 *
 * Registrul nu mai e cel care deosebește proza de cod — aia o face lexerul. E
 * plasa de dedesubt: dacă golirea comentariilor mușcă vreodată dintr-o linie pe
 * care n-ar fi trebuit, fișierul se vede tot aici, iar unul nedeclarat pică.
 * Prețul e că un comentariu nou care scrie „MySQL" pică garda până e trecut în
 * listă — direcția bună de greșeală, și costă o linie.
 */
const NAMES_THE_DRIVER_IN_PROSE: Record<string, string> = {
  "app/api/sentinel/sync/route.ts": "de ce semnătura se verifică fără driverul " +
                                    "de MySQL și fără `node:crypto`",
  "lib/auth/db.ts": "de ce stratul de autentificare n-are nevoie de mysql2",
  "lib/auth/panel.ts": "de ce middleware-ul, pe runtime-ul Edge, nu-l poate avea",
  "lib/ingest.ts": "de ce `VALUES()` și nu aliasul de rând din MySQL 8.0.19+",
  "lib/migrate.ts": "de ce interfața cerută de runner e mai îngustă decât mysql2",
  "lib/retention.ts": "de ce retenția cere `Queryable` din `lib/db.ts` și nu tipul din mysql2 — un dublu de test s-ar scrie altfel cu treizeci de metode",
  "migrations/0001_core.sql": "că fișierul se poate da și direct clientului `mysql`",
  "migrations/0008_auth.sql": "același lucru, pentru migrația de autentificare",
};

/** Ce anume se deschide cu accesorul din `lib/db.ts`, și pentru cine. */
const DRIVER_ENTRIES: Record<string, string> = {
  "mysql().createConnection(": "createDirectConnection — uneltele din bin/ și " +
                               "runnerul de migrații",
  "mysql().createPool(": "getPool — pool-ul rutelor Next.js",
};

/**
 * NUMELE variabilei, nu forma instrucțiunii. De ce, în capul fișierului.
 *
 * `\b` la ambele capete: identificatorii noștri (`SET_SESSION_SQL_MODE`,
 * `REQUIRED_SQL_MODES`) conțin șirul, dar lipit de un caracter de cuvânt. Ei nu
 * sunt atribuiri, iar dacă i-ar potrivi, registrul ar trebui să numere fișiere
 * care doar importă din `lib/db.ts` — adică s-ar umple de scutiri, ceea ce e
 * felul în care moare o gardă.
 */
const SQL_MODE_TOKEN = /\bsql_mode\b/i;

/**
 * Fișierele livrate în al căror COD apare numele, cu numărul aparițiilor.
 *
 * Un `SET STATEMENT sql_mode = '' FOR …` strecurat oriunde — inclusiv în
 * `lib/db.ts`, care are voie să scrie numele — mută numărul, deci pică.
 */
const SQL_MODE_IN_CODE: Record<string, Record<string, number>> = {
  // Îl pune, o dată, pe fiecare sesiune nouă: de două ori în instrucțiunea de
  // `SET` (numele atribuit, plus `@@SESSION.sql_mode` din `CONCAT_WS`), de două
  // ori în citirea înapoi (coloana și aliasul ei), o dată la citirea răspunsului.
  "lib/db.ts": { sql_mode: 5 },
};

/**
 * Fișierele livrate care îl pomenesc numai în COMENTARII, cu ce explică fiecare.
 *
 * Același rol ca `NAMES_THE_DRIVER_IN_PROSE`: plasa de sub lexer, nu
 * criteriul. Un fișier care ȘI explică, ȘI atribuie nu scapă trecându-l aici —
 * recensământul pe COD de mai jos îl numără oricum.
 */
const MENTIONS_SQL_MODE: Record<string, string> = {
  "lib/auth/accounts.ts": "de ce numele contului se validează în cod: sub alt mod " +
                          "un nume cu diacritice ar deveni `?`",
  "lib/auth/users.ts": "același motiv, la capătul care refuză, plus de ce " +
                       "vocabularul se verifică înainte de scriere",
  "migrations/0008_auth.sql": "de ce `CHECK` și nu `ENUM`: `ENUM` se aplică " +
                              "strict doar sub `STRICT_TRANS_TABLES`",
};

test("căutarea chiar umblă prin tot codul livrat", () => {
  // Fără aserțiunea asta, un walker rupt ar face recensămintele de mai jos să
  // pice din alt motiv decât cel numit — sau, dacă vreun registru ar ajunge
  // vreodată gol, să treacă pe o listă goală. `lib/db.ts` e la al doilea nivel.
  const files = shippedFiles();
  assert.ok(files.length >= 24, `prea puține fișiere livrate găsite: ${files.length}`);
  for (const expected of ["lib/db.ts", "lib/migrate.ts", "bin/migrate.ts",
                          "app/api/sentinel/sync/route.ts", "next.config.mjs"]) {
    assert.ok(files.includes(expected), `căutarea nu vede ${expected}`);
  }
});

test("fiecare fișier livrat chiar se poate citi până la capăt", () => {
  // Prima regulă din fișier, fiindcă toate celelalte se sprijină pe ea: un
  // fișier pe care lexerul nu-l parcurge n-are voie să intre în recensăminte cu
  // zero apariții. Aici pică cu numele lui și cu motivul, în loc să pice mai jos
  // cu un `deepEqual` care nu spune ce s-a întâmplat.
  const unreadable: string[] = [];
  const read: string[] = [];
  for (const file of shippedFiles()) {
    try { codeOf(file); read.push(file); }
    catch (err) { unreadable.push((err as Error).message); }
  }
  assert.deepEqual(unreadable, [],
                   "fișiere livrate pe care lexerul nu le poate citi. Nu sunt " +
                   "fișiere goale, sunt fișiere despre care nu se știe nimic.");
  assert.ok(read.length >= 40, `prea puține fișiere citite: ${read.length}`);
});

test("codul se deosebește de proză prin LEXER, nu printr-un tipar pe linie", () => {
  // Toată greutatea recensămintelor stă pe golirea comentariilor, deci se
  // probează în AMBELE direcții. Formele POZITIVE sunt cele care au evadat
  // gărzile de dinainte — literal de șablon la specificator, jeton între accente
  // grave — plus cele două măsurate pe 18 august 2026, în care scuza de o linie
  // stă pe ACEEAȘI linie cu gestul. Fiecare trebuie să rămână vizibilă.
  const code: Array<[string, string, RegExp]> = [
    // Măsurată: un `SET STATEMENT ... FOR` viu într-un fișier declarat drept
    // proză, cu scuza scrisă în față, pe aceeași linie.
    ['/* temporar, pana marim coloana: modul strict refuza numele lungi */ ' +
     "export async function rename(id: number, name: string) { " +
     'return await db.write("SET STATEMENT sql_mode = \'\' FOR UPDATE users ' +
     'SET username = ? WHERE id = ?", [name, id]); }\n',
     "probă.ts", SQL_MODE_TOKEN],
    // Măsurată: a doua cale de conectare deschisă CHIAR în fișierul care are
    // voie să numească driverul, tot după o scuză de o linie.
    ['/* pool separat pentru rapoarte */ export function reportPool(): unknown ' +
     '{ return createRequire(import.meta.url)("mysql2/promise").createPool({}); }\n',
     "probă.ts", DRIVER_TOKEN],
    // Un literal de șablon e COD, oricum ar începe liniile lui. Versiunea pe
    // linii golea linia a doua fiindcă începe cu asterisc și spațiu.
    ["const t = `\n * sql_mode = 0\n`;\n", "probă.ts", SQL_MODE_TOKEN],
    // Evadările vechi, păstrate ca regresie.
    ["const drv = requireFrom(`mysql2/promise`) as Mysql2;\n", "probă.ts", DRIVER_TOKEN],
    ["async function open() { return await import(`mysql2/promise`); }\n",
     "probă.ts", DRIVER_TOKEN],
    ["const { createPool } = req(`mysql2/promise`);\n", "probă.ts", DRIVER_TOKEN],
    ['const drv = requireFrom("mysql2/promise") as Mysql2;\n', "probă.ts", DRIVER_TOKEN],
    ["import mysql from 'mysql2';\n", "probă.ts", DRIVER_TOKEN],
    ['const spec = "mysql" + "2/promise";\n', "probă.ts", DRIVER_TOKEN],
    ["q.query(\"SET SESSION \" + `sql_mode` + \" = ''\");\n", "probă.ts", SQL_MODE_TOKEN],
    ["q.query(`SET SESSION sql_mode = ''`);\n", "probă.ts", SQL_MODE_TOKEN],
    // Metodă generator: asteriscul lipit de nume nu e un comentariu de
    // continuare, e cod.
    ["class C { *reset() { return q.query(\"SET @@sql_mode = ''\"); } }\n",
     "probă.ts", SQL_MODE_TOKEN],
    // Decrementare, nu comentariu: `--` e comentariu numai în SQL.
    ["--i; q.query(\"SET @@sql_mode = ''\");\n", "probă.ts", SQL_MODE_TOKEN],
    // Textul JSX nu e trivia, oricât ar semăna începutul lui cu un comentariu.
    // Măsurat: fără tăierea la începutul jetonului, tot restul liniei — inclusiv
    // cererea driverului — se golea.
    ['const page = <p>//nota</p>; const drv = requireFrom("mysql2/promise");\n',
     "probă.tsx", DRIVER_TOKEN],
    // În `.sql`, un literal e date, deci e cod: se numără.
    ["-- @guard none probă\nSET SESSION sql_mode = '';\n", "probă.sql", SQL_MODE_TOKEN],
    ["-- @guard none probă\nINSERT INTO note (t) VALUES ('SET @@sql_mode = 0');\n",
     "probă.sql", SQL_MODE_TOKEN],
  ];
  assert.equal(code.length, 16, "lista de forme de cod a fost tăiată");
  for (const [source, file, token] of code) {
    assert.ok(token.test(codeText(source, file)),
              `jetonul a fost golit ca și cum ar fi comentariu: ${source}`);
  }

  // Cealaltă direcție: proza, care TREBUIE golită — altfel registrele s-ar umple
  // de scutiri, iar un registru plin de scutiri nu mai apără nimic.
  const prose: Array<[string, string, RegExp]> = [
    ["/**\n *  Nimic de aici nu trebuie să cunoască mysql2.\n */\nexport const x = 1;\n",
     "probă.ts", DRIVER_TOKEN],
    ["/* mysql2 se încarcă la cerere */\nconst x = 1;\n", "probă.ts", DRIVER_TOKEN],
    ["// SET SESSION sql_mode = '' — nu, vezi capul fișierului\nconst x = 1;\n",
     "probă.ts", SQL_MODE_TOKEN],
    // Direcția schimbată de lexer, scrisă pe față: comentariul de la capătul
    // unei linii de cod e PROZĂ acum. Versiunea pe linii îl număra drept cod și
    // spunea că e zgomotul ales dinadins; un comentariu e proză oriunde ar sta,
    // iar zgomotul ăla costa o gardă picată pe o linie care nu executa nimic.
    ["connect(); // vezi sql_mode în capul lui lib/db.ts\n", "probă.ts", SQL_MODE_TOKEN],
    ["const a = 1; /* mysql2 nu se atinge aici */\nconst b = 2;\n",
     "probă.ts", DRIVER_TOKEN],
    ["-- @guard none probă\n-- se poate da direct clientului `mysql`\nSELECT 1;\n",
     "probă.sql", DRIVER_TOKEN],
    ["-- @guard none probă\n# mysql2 nu are ce căuta într-o migrație\nSELECT 1;\n",
     "probă.sql", DRIVER_TOKEN],
    ["-- @guard none probă\n/* sql_mode se pune din aplicație */ SELECT 1;\n",
     "probă.sql", SQL_MODE_TOKEN],
    ["-- @guard table t\nINSERT INTO t VALUES (1); -- vezi sql_mode\n",
     "probă.sql", SQL_MODE_TOKEN],
  ];
  assert.equal(prose.length, 9, "lista de forme de proză a fost tăiată");
  for (const [source, file, token] of prose) {
    assert.ok(!token.test(codeText(source, file)), `proza a rămas cod: ${source}`);
  }
});

test("golirea comentariilor nu atinge niciun jeton din fișierele livrate", () => {
  // Direcția periculoasă a primitivei, probată pe fișierele ADEVĂRATE: dacă
  // golirea mușcă din cod, recensământul nu mai vede o cale de conectare și trece
  // verde — exact eșecul tăcut pentru care există tot fișierul.
  //
  // Se compară fluxul de jetoane — fel, poziție ȘI text — dinainte și de după.
  // Un comentariu golit nu e jeton, deci nu schimbă nimic; un șir sau un
  // identificator ciuntit schimbă. `.sql` are alt cititor (`splitStatements`),
  // probat în `tests/sql-statements.test.ts`.
  const checked: string[] = [];
  for (const file of shippedFiles()) {
    if (file.endsWith(".sql")) continue;
    assert.deepEqual(tokenPrints(codeOf(file), file),
                     tokenPrints(readShipped(file), file),
                     `golirea comentariilor a schimbat jetoanele din ${file}`);
    checked.push(file);
  }
  assert.ok(checked.length >= 40, `prea puține fișiere verificate: ${checked.length}`);

  // Și pe forme în care comentariul e LIPIT de cod. În fișierele livrate de azi
  // după fiecare comentariu urmează un spațiu sau un sfârșit de linie, deci o
  // golire cu un caracter mai lungă nu mușcă nimic acolo — măsurat: mutația care
  // golea `range.end + 1` lăsa bucla de mai sus verde. Corpusul nu e o probă;
  // formele astea sunt.
  const abutting = [
    '/* scuza */const drv = requireFrom("mysql2/promise");\n',
    'const a = 1;/* scuza */const drv = requireFrom("mysql2/promise");\n',
    'import/* scuza */mysql from "mysql2";\n',
    "q.query(/* scuza */`SET SESSION sql_mode = ''`);\n",
  ];
  assert.equal(abutting.length, 4, "lista de comentarii lipite a fost tăiată");
  for (const source of abutting) {
    assert.deepEqual(tokenPrints(codeText(source, "probă.ts"), "probă.ts"),
                     tokenPrints(source, "probă.ts"),
                     `golirea a mușcat din cod lângă comentariu: ${source}`);
  }
});

test("în codul livrat nu mai rămâne niciun comentariu", () => {
  // Cealaltă direcție: un comentariu RATAT face ca proza să se numere drept cod.
  // Nu minte pe tăcere — pică garda —, dar trimite pe cineva să caute o cale de
  // conectare care nu există, iar o gardă care pică din motive false e o gardă pe
  // care o scoate cineva.
  //
  // Se cere: fiecare început de comentariu rămas în cod stă ÎNTR-UN literal (șir,
  // șablon, expresie regulată, text JSX), unde e date, nu comentariu.
  const literalKinds = new Set<ts.SyntaxKind>([
    ts.SyntaxKind.StringLiteral,
    ts.SyntaxKind.NoSubstitutionTemplateLiteral,
    ts.SyntaxKind.TemplateHead,
    ts.SyntaxKind.TemplateMiddle,
    ts.SyntaxKind.TemplateTail,
    ts.SyntaxKind.RegularExpressionLiteral,
    ts.SyntaxKind.JsxText,
  ]);
  const leftovers: string[] = [];
  let checked = 0;
  for (const file of shippedFiles()) {
    if (file.endsWith(".sql")) continue;
    const code = codeOf(file);
    const source = ts.createSourceFile(
      file, code, ts.ScriptTarget.Latest, false, scriptKindOf(file));
    const literals = leafTokens(source)
      .filter((leaf) => literalKinds.has(leaf.kind))
      .map((leaf) => [leaf.getStart(source), leaf.end] as const);
    for (const match of code.matchAll(/\/\/|\/\*/g)) {
      const at = match.index ?? 0;
      if (literals.some(([from, until]) => from <= at && at < until)) continue;
      const line = code.slice(0, at).split("\n").length;
      leftovers.push(`${file}:${line}: ${code.slice(at, at + 60).split("\n")[0]}`);
    }
    checked++;
  }
  assert.deepEqual(leftovers, [],
                   "au rămas comentarii în ce recensămintele numără drept cod");
  assert.ok(checked >= 40, `prea puține fișiere verificate: ${checked}`);
});

test("un fișier pe care lexerul nu-l poate citi e REFUZAT, nu socotit gol", () => {
  // „Nu se poate citi" și „nu e nimic acolo" sunt stări diferite. Colapsate,
  // fișierul necitit ar intra în recensământ cu zero apariții — adică ar trece,
  // iar garda ar raporta „nimic în neregulă" pentru totdeauna.
  const unreadable: Array<[string, string]> = [
    ['const drv = requireFrom("mysql2/promise"\n', "rupt.ts"],
    ["const page = <p>x</p>;\n", "jsx-în-ts.ts"],
    ["SELECT 1;\n", "fără-gardă.sql"],
    ["-- @guard none probă\nSELECT /*!40101 1 */ 2;\n", "condiționat.sql"],
    ["-- @guard none probă\nSELECT 'neînchis;\n", "literal-deschis.sql"],
  ];
  assert.equal(unreadable.length, 5, "lista de fișiere ilizibile a fost tăiată");
  for (const [text, file] of unreadable) {
    assert.throws(() => codeText(text, file), /nu s-a putut citi/,
                  `fișierul ilizibil ${file} a trecut drept citit`);
  }

  // Și controlul: fișierele bune chiar trec. Fără el, aserțiunile de mai sus ar
  // putea fi verzi fiindcă ARUNCĂ TOTUL.
  assert.equal(codeText("const a = 1;\n", "bun.ts"), "const a = 1;\n");
  assert.ok(codeText("-- @guard none probă\nSELECT 1;\n", "bun.sql").includes("SELECT 1"));
});

test("numele se vede în ORICE ortografie MariaDB a atribuirii", () => {
  // Formele pozitive sunt derivate din gramatica MariaDB pentru atribuirea unei
  // variabile de sesiune, NU din ce s-a mai scris în depozit — de-aia a scăpat
  // versiunea dinainte, care căuta `SET [SESSION|GLOBAL|@@…] sql_mode` și lăsa
  // să treacă exact ortografiile spre care întinde mâna cineva grăbit.
  const spellings = [
    "SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''), 'X')",
    "set sql_mode='STRICT_TRANS_TABLES'",
    "SET @@sql_mode = ''",                       // ortografia OBIȘNUITĂ
    "SET @@session.sql_mode = ''",
    "SET @@local.sql_mode = ''",
    "SET LOCAL sql_mode = ''",                   // `LOCAL` e sinonimul lui `SESSION`
    "SET GLOBAL sql_mode = @old",
    "SET @@GLOBAL.sql_mode = ''",
    // Suprascrierea per-instrucțiune a MariaDB: nu atinge sesiunea, dar scoate
    // modul strict de pe chiar instrucțiunea care tocmai a fost refuzată.
    "SET STATEMENT sql_mode = '' FOR INSERT INTO audit_entries VALUES (1)",
    // A doua atribuire dintr-o listă: `SET` nu mai e lipit de nume.
    "SET autocommit = 1, sql_mode = ''",
    "SET SESSION sql_mode = DEFAULT",
    "SET\n  SESSION\n  sql_mode = ''",           // rupt pe rânduri
  ];
  assert.equal(spellings.length, 12, "lista de ortografii a fost tăiată");
  for (const real of spellings) {
    assert.ok(SQL_MODE_TOKEN.test(real), `tiparul nu vede atribuirea: ${real}`);
  }

  // Cealaltă direcție: ce conține șirul fără să fie variabila. Un tipar care le
  // potrivește ar cere o scutire pentru fiecare fișier care importă din
  // `lib/db.ts`, iar un registru plin de scutiri nu mai apără nimic.
  for (const notIt of [
    "export const SET_SESSION_SQL_MODE =",
    "  return REQUIRED_SQL_MODES.filter((mode) => !present.has(mode));",
    "  const missing = missingSqlModes(rows);",
    "  await q.query(`SET ${PROBE_VAR} = ?`, [stmt.sql]);",
  ]) {
    assert.ok(!SQL_MODE_TOKEN.test(notIt), `tiparul potrivește un identificator: ${notIt}`);
  }

  // Iar proza CHIAR se potrivește — dinadins. Nu e o scăpare, e prețul plătit
  // pentru ca nicio ortografie să nu treacă: fișierele de proză se declară.
  assert.ok(SQL_MODE_TOKEN.test(
    " * Deci refuzul e al aplicației, cu mesaj, indiferent ce `sql_mode` are gazda."));

  // Și fiecare atribuire trebuie să treacă și de lexer, în ambele dialecte: o
  // atribuire e cod oriunde ar sta, oricum ar fi ruptă pe rânduri. În `.ts` stă
  // acolo unde stă de fapt — într-un literal dat driverului, aici de șablon,
  // fiindcă unele ortografii sunt rupte pe rânduri —, în `.sql` e chiar
  // instrucțiunea.
  for (const real of spellings) {
    assert.ok(SQL_MODE_TOKEN.test(codeText(`q.query(\`${real}\`);\n`, "probă.ts")),
              `atribuirea a fost golită ca și cum ar fi comentariu (ts): ${real}`);
    assert.ok(
      SQL_MODE_TOKEN.test(codeText(`-- @guard none probă\n${real};\n`, "probă.sql")),
      `atribuirea a fost golită ca și cum ar fi comentariu (sql): ${real}`);
  }
});

test("driverul e numit în CODUL livrat numai unde e declarat, și de câte ori", () => {
  // O cale nouă de conectare — un `lib/reports-db.ts` care își face pool-ul lui,
  // o rută care deschide o conexiune „doar pentru un SELECT", sau o a doua
  // funcție ÎN `lib/db.ts` care își cere singură driverul — nu trece prin
  // `applyStrictSession`/`initPooledConnection`, deci sesiunea ei rămâne pe
  // `sql_mode`-ul gazdei. Măsurat, ăla nu e strict: pe calea aia rândurile intră
  // tăiate și numărate ca bune, iar cursorul expeditorului trece peste ele.
  //
  // Se numără NUMELE pachetului, în cod, nu ortografia specificatorului: aia a
  // fost evadată de un literal de șablon, care e chiar forma folosită de
  // `lib/db.ts`. Vezi capul fișierului.
  assert.deepEqual(codeMentionCounts(DRIVER_TOKEN), DRIVER_IN_CODE,
                   "numele driverului apare în codul livrat altfel decât e " +
                   "declarat în DRIVER_IN_CODE. Un fișier nou înseamnă o a doua " +
                   "cale de conectare; un număr crescut în lib/db.ts înseamnă " +
                   "aceeași cale deschisă a doua oară, pe lângă accesor.");
});

test("numele driverului apare numai în fișierele livrate declarate", () => {
  // Plasa de sub lexer: recensământul de mai sus citește CODUL, ăsta
  // citește TOT textul. Dacă golirea liniilor de comentariu greșește vreodată în
  // direcția rea, un fișier nou tot se vede aici.
  const declared = [...Object.keys(DRIVER_IN_CODE),
                    ...Object.keys(NAMES_THE_DRIVER_IN_PROSE)].sort();
  assert.deepEqual(shippedMatching(DRIVER_TOKEN), declared,
                   "fișierele livrate care pomenesc driverul nu sunt exact cele " +
                   "declarate. Dacă fișierul nou doar SCRIE despre el, treci-l în " +
                   "NAMES_THE_DRIVER_IN_PROSE cu motivul; dacă îl încarcă, e o a " +
                   "doua cale de conectare, care nu primește sql_mode strict.");
});

test("accesorul din `lib/db.ts` are exact folosirile declarate", () => {
  // Recensământul de mai sus spune CÂTE apariții are numele; ăsta spune ce
  // DESCHIDE fiecare. Un al treilea `mysql().createPool(` — un pool separat
  // pentru rapoarte, o conexiune pentru un job — are alt motiv decât cele două
  // declarate, iar motivul e ce se citește când pică.
  //
  // Se citește CODUL, nu textul: comentariile lui `lib/db.ts` au voie să scrie
  // numele accesorului cu paranteze, fiindcă un comentariu nu deschide nimic.
  const source = codeOf("lib/db.ts");
  const entries = (source.match(/\bmysql\(\)\.\w+\(/g) ?? []).sort();
  assert.deepEqual(entries, Object.keys(DRIVER_ENTRIES).sort(),
                   "folosirile accesorului `mysql()` din lib/db.ts nu sunt exact " +
                   "cele declarate în DRIVER_ENTRIES. Fiecare deschide sesiuni, " +
                   "deci fiecare trebuie să pună sql_mode strict.");

  // Și nu se poate strecura una printr-un alias: `const m = mysql(); m.createPool()`
  // n-ar fi potrivit tiparul de mai sus. Deci se numără APELURILE accesorului —
  // toate aparițiile lui, mai puțin definiția — și trebuie să fie exact atâtea
  // câte sunt declarate.
  const declarations = (source.match(/\bfunction mysql\(\)/g) ?? []).length;
  assert.equal(declarations, 1,
               "accesorul `mysql()` nu mai e definit exact o dată în lib/db.ts");
  assert.equal((source.match(/\bmysql\(\)/g) ?? []).length - declarations,
               Object.keys(DRIVER_ENTRIES).length,
               "`mysql()` e apelat de alte ori decât cele declarate — un alias " +
               "ține driverul într-o variabilă și deschide de acolo");
});

test("numele `sql_mode` apare în CODUL livrat numai unde e declarat", () => {
  // Al doilea fel de a ajunge la o sesiune nestrictă, și cel mai greu de văzut:
  // modul e pus corect la conectare, iar altcineva îl rescrie mai târziu pe
  // aceeași sesiune. Un `SET @@sql_mode` într-un instrument, un
  // `SET STATEMENT sql_mode = '' FOR INSERT …` pus într-o rută ca să treacă azi
  // o scriere pe care modul strict tocmai a refuzat-o — oricare dezarmează tot
  // fișierul fără să pice nimic.
  //
  // Se numără NUMELE, nu forma: MariaDB are prea multe ortografii pentru
  // aceeași atribuire ca o alternanță să le poată cuprinde (capul fișierului le
  // enumeră), iar niciuna nu se poate scrie fără nume.
  assert.deepEqual(codeMentionCounts(SQL_MODE_TOKEN), SQL_MODE_IN_CODE,
                   "numele `sql_mode` apare în codul livrat altfel decât e " +
                   "declarat în SQL_MODE_IN_CODE. Un fișier nou care îl ATRIBUIE " +
                   "poate scoate modul strict de pe o sesiune deja pornită; dacă " +
                   "doar scrie despre el, apariția trebuie să fie într-un " +
                   "comentariu, iar fișierul trecut în MENTIONS_SQL_MODE.");
});

test("numele `sql_mode` apare numai în fișierele livrate declarate", () => {
  // Aceeași plasă ca la driver, din același motiv.
  const declared = [...Object.keys(SQL_MODE_IN_CODE),
                    ...Object.keys(MENTIONS_SQL_MODE)].sort();
  assert.deepEqual(shippedMatching(SQL_MODE_TOKEN), declared,
                   "fișierele livrate care pomenesc `sql_mode` nu sunt exact cele " +
                   "declarate. Dacă fișierul nou doar SCRIE despre asta, treci-l " +
                   "în MENTIONS_SQL_MODE cu motivul; dacă atribuie, atunci e o a " +
                   "doua atribuire, care poate scoate modul strict de pe o " +
                   "sesiune deja pornită.");
});

test("în fișierele declarate ca proză, numele e NUMAI în comentarii", () => {
  // Fără asta, registrele de proză ar fi portița: cine adaugă un fișier care ȘI
  // explică, ȘI atribuie l-ar trece acolo și ar trece verde. Recensămintele pe
  // COD de mai sus prind același lucru; ăsta îl prinde per fișier și cu LINIA,
  // care e ce se citește când pică.
  //
  // Listele se numără ÎNAINTE — una ieșită goală ar fi sărită tăcut, iar testul
  // ar trece fără să verifice nimic.
  assert.equal(Object.keys(MENTIONS_SQL_MODE).length, 3,
               "registrul de proză pentru `sql_mode` s-a schimbat; verifică fiecare " +
               "intrare nouă");
  assert.equal(Object.keys(NAMES_THE_DRIVER_IN_PROSE).length, 8,
               "registrul de proză pentru driver s-a schimbat; verifică fiecare " +
               "intrare nouă");
  const registers: Array<[Record<string, string>, RegExp, string]> = [
    [MENTIONS_SQL_MODE, SQL_MODE_TOKEN, "o a doua atribuire de sql_mode"],
    [NAMES_THE_DRIVER_IN_PROSE, DRIVER_TOKEN, "o a doua cale către driver"],
  ];
  for (const [register, token, what] of registers) {
    for (const [file, why] of Object.entries(register)) {
      assert.deepEqual(codeMentions(file, token), [],
                       `${file} e declarat ca proză (${why}), dar are aparițiile de ` +
                       "mai sus în COD, nu într-un comentariu. Ori e proză și se " +
                       `scrie într-un comentariu, ori e ${what} — și atunci e o cale ` +
                       "către o sesiune nestrictă.");
    }
  }
});

test("recensământul chiar refuză un fișier nedeclarat — declanșat izolat", () => {
  // Regula văzută picând singură. O regulă a cărei declanșare n-a fost văzută e
  // o regulă despre care nu se știe pe ce pică.
  const pretend = { ...DRIVER_IN_CODE, "lib/reports-db.ts": { mysql2: 1 } };
  assert.throws(() => assert.deepEqual(pretend, DRIVER_IN_CODE), /reports-db/);

  // Și pe numărul dintr-un fișier deja declarat: a doua cale deschisă ÎN
  // `lib/db.ts` nu schimbă nicio listă de fișiere, doar un număr.
  const twice = { ...DRIVER_IN_CODE, "lib/db.ts": { mysql: 3, Mysql2: 3, mysql2: 2 } };
  assert.throws(() => assert.deepEqual(twice, DRIVER_IN_CODE), /mysql2/);
});

// ---------------------------------------------------------------------------
// Lista de moduri și instrucțiunea derivată din ea
// ---------------------------------------------------------------------------

test("instrucțiunea chiar cere fiecare mod din listă", () => {
  // Lista și instrucțiunea sunt același lucru spus o dată (instrucțiunea e
  // derivată), dar dacă vreodată n-ar mai fi, desincronizarea ar fi tăcută
  // într-o direcție: un mod cerut de citirea înapoi și absent din `SET` face
  // FIECARE conexiune să moară, iar mesajul n-ar spune de ce.
  assert.ok(REQUIRED_SQL_MODES.length >= 1, "lista de moduri a ieșit goală");
  assert.ok(REQUIRED_SQL_MODES.includes("STRICT_TRANS_TABLES"),
            "STRICT_TRANS_TABLES lipsește: exact modul fără de care un rând prea " +
            "lung se scrie TĂIAT și e numărat drept prezent");
  for (const mode of REQUIRED_SQL_MODES) {
    assert.ok(SET_SESSION_SQL_MODE.includes(mode),
              `modul ${mode} e cerut la citirea înapoi, dar nu e în instrucțiune`);
  }
});

test("instrucțiunea ADAUGĂ la ce a pus gazda, nu înlocuiește", () => {
  // Afirmație pe FORMA a ce cerem, nu pe ce face serverul — vezi capul
  // fișierului. Ce apără: `NO_ENGINE_SUBSTITUTION` e pus de gazdă și e util (un
  // motor lipsă devine eroare, nu o substituție tăcută), iar o listă literală
  // l-ar șterge. Tot ea ne scutește de a scrie `NO_AUTO_CREATE_USER`, pe care
  // MariaDB l-a depreciat: scris pe față, ziua în care serverul îl scoate e ziua
  // în care FIECARE conexiune eșuează.
  assert.ok(SET_SESSION_SQL_MODE.includes("@@SESSION.sql_mode"),
            "instrucțiunea nu mai citește modul curent, deci îl înlocuiește");
  // Și un `sql_mode` gol nu produce o virgulă la început, pe care serverul o
  // refuză ca element gol.
  assert.ok(SET_SESSION_SQL_MODE.includes("NULLIF(@@SESSION.sql_mode, '')"),
            "un sql_mode gol ar da o listă cu element gol");
});

// ---------------------------------------------------------------------------
// Citirea răspunsului: „nu știu" nu e „e bine"
// ---------------------------------------------------------------------------

test("`missingSqlModes` spune «nu știu» când răspunsul nu se poate citi", () => {
  // Un tablou gol întors pentru un răspuns neînțeles ar însemna „nu lipsește
  // nimic", adică sesiunea ar trece drept strictă fiindcă nimeni n-a putut
  // verifica. E chiar tiparul din CLAUDE.md, mutat într-o funcție pură.
  for (const unreadable of [null, undefined, [], [null], [{}],
                            [{ sql_mode: null }], [{ sql_mode: 7 }],
                            { sql_mode: STRICT_ANSWER }]) {
    assert.equal(missingSqlModes(unreadable), null,
                 `răspuns ilizibil citit ca verdict: ${JSON.stringify(unreadable)}`);
  }
});

test("`missingSqlModes` numește exact modurile care lipsesc", () => {
  assert.deepEqual(missingSqlModes([{ sql_mode: STRICT_ANSWER }]), []);
  // Spațiile și minusculele vin de la un server care formatează altfel; ce
  // contează e mulțimea, nu ortografia lui.
  assert.deepEqual(
    missingSqlModes([{ sql_mode: ` ${STRICT_ANSWER.toLowerCase().split(",").join(" , ")} ` }]),
    []);
  assert.deepEqual(missingSqlModes([{ sql_mode: HOST_MODES }]),
                   [...REQUIRED_SQL_MODES]);

  // Fiecare mod, scos pe rând. Lista parametrizată se numără ÎNAINTE: o listă
  // ieșită goală ar fi sărită tăcut, iar testul ar trece fără să verifice nimic.
  assert.equal(REQUIRED_SQL_MODES.length, 4);
  for (const mode of REQUIRED_SQL_MODES) {
    const answer = [HOST_MODES, ...REQUIRED_SQL_MODES.filter((m) => m !== mode)].join(",");
    assert.deepEqual(missingSqlModes([{ sql_mode: answer }]), [mode]);
  }
});

// ---------------------------------------------------------------------------
// Calea 1: conexiunea singură (bin/, migrații). Se AȘTEAPTĂ verdictul.
// ---------------------------------------------------------------------------

class FakeConnection implements Connection {
  readonly seen: string[] = [];
  ended = 0;
  failToEnd = false;

  constructor(private readonly answer: unknown) {}

  async query(sql: string): Promise<[unknown, unknown]> {
    this.seen.push(sql);
    if (sql === READ_SESSION_SQL_MODE) return [this.answer, []];
    return [{ affectedRows: 0 }, []];
  }

  async end(): Promise<void> {
    this.ended++;
    if (this.failToEnd) throw new Error("socket deja închis");
  }
}

test("conexiunea singură pune modul ȘI îl citește înapoi, în ordinea asta", async () => {
  // Ordinea nu e cosmetică: citit ÎNAINTE de `SET`, răspunsul ar fi modul
  // gazdei, iar verificarea ar cădea mereu — sau, dacă gazda ar fi într-o zi
  // strictă, ar trece fără ca instrucțiunea noastră să fi făcut ceva.
  const connection = new FakeConnection([{ sql_mode: STRICT_ANSWER }]);
  const opened = await createDirectConnection(ENV, async () => connection);
  assert.equal(opened, connection);
  assert.deepEqual(connection.seen, [SET_SESSION_SQL_MODE, READ_SESSION_SQL_MODE]);
  assert.equal(connection.ended, 0, "conexiunea bună a fost închisă degeaba");
});

test("un `SET` care «a reușit» fără efect NU dă o conexiune", async () => {
  // Chiar tiparul după care e numit depozitul: serverul acceptă instrucțiunea și
  // sesiunea rămâne nestrictă (un proxy care o înghite, un mod scos de altceva).
  // Codul de ieșire al lui `SET` nu e dovadă; citirea înapoi e.
  const connection = new FakeConnection([{ sql_mode: HOST_MODES }]);
  await assert.rejects(
    () => createDirectConnection(ENV, async () => connection),
    /STRICT_TRANS_TABLES/,
    "o sesiune nestrictă a fost dată mai departe");
  assert.equal(connection.ended, 1,
               "conexiunea refuzată a rămas deschisă — un `npm run migrate` care " +
               "eșuează ar lăsa o sesiune atârnând pe găzduirea partajată");
});

test("un răspuns ilizibil e refuz, nu trecere", async () => {
  // „Nu se poate citi" și „e în regulă" sunt stări diferite. Colapsate, uneltele
  // din bin/ ar scrie în baza reală crezând că sunt în mod strict.
  for (const answer of [[], [{}], [{ sql_mode: null }], { sql_mode: STRICT_ANSWER }]) {
    const connection = new FakeConnection(answer);
    await assert.rejects(
      () => createDirectConnection(ENV, async () => connection),
      /nu s-a aflat nimic/,
      `răspunsul ${JSON.stringify(answer)} a fost citit ca trecere`);
    assert.equal(connection.ended, 1);
  }
});

test("un eșec la închidere nu acoperă motivul adevărat", async () => {
  // Ce citește operatorul trebuie să fie „sesiunea nu e strictă", nu „socket
  // deja închis" — al doilea l-ar trimite să caute o problemă de rețea.
  const connection = new FakeConnection([{ sql_mode: HOST_MODES }]);
  connection.failToEnd = true;
  await assert.rejects(
    () => createDirectConnection(ENV, async () => connection),
    /STRICT_TRANS_TABLES/);
});

test("`applyStrictSession` refuză și o sesiune căreia îi lipsește UN mod", async () => {
  assert.equal(REQUIRED_SQL_MODES.length, 4);
  for (const mode of REQUIRED_SQL_MODES) {
    const answer = [HOST_MODES, ...REQUIRED_SQL_MODES.filter((m) => m !== mode)].join(",");
    await assert.rejects(
      () => applyStrictSession(new FakeConnection([{ sql_mode: answer }])),
      new RegExp(mode),
      `${mode} lipsă a trecut ca sesiune bună`);
  }
});

// ---------------------------------------------------------------------------
// Calea 2: conexiunile pool-ului. Nu se poate aștepta; se DISTRUGE.
// ---------------------------------------------------------------------------

/** Dublul NU cheamă singur tratanții: testul îi cheamă, ca să se poată vedea ce
 *  a intrat în coadă SINCRON și ce abia după un răspuns. */
class FakePooledConnection implements PooledConnection {
  readonly issued: Array<{ sql: string; callback: (err: unknown, rows?: unknown) => void }> = [];
  destroyed = 0;

  query(sql: string, callback: (err: unknown, rows?: unknown) => void): unknown {
    this.issued.push({ sql, callback });
    return this;
  }

  destroy(): void { this.destroyed++; }

  get statements(): string[] { return this.issued.map((i) => i.sql); }
}

test("amândouă instrucțiunile intră în coadă SINCRON, în ordine", () => {
  // Eșecul pe care îl previne: `mysql2` emite `connection` înainte de a da
  // conexiunea apelantului, iar coada e FIFO — deci doar ce se pune ACUM ajunge
  // înaintea primei interogări a apelantului. Citirea înapoi pusă înlănțuit (din
  // tratantul lui `SET`) ar fi ajuns DUPĂ ea, adică ar fi verificat sesiunea
  // după ce se scrisese deja pe ea, și n-ar mai fi apărat lotul ăla.
  const connection = new FakePooledConnection();
  initPooledConnection(connection, () => { /* nimic de spus în testul ăsta */ });
  assert.deepEqual(connection.statements,
                   [SET_SESSION_SQL_MODE, READ_SESSION_SQL_MODE],
                   "instrucțiunile nu sunt amândouă în coadă înainte ca vreun " +
                   "răspuns să fi venit");
});

test("o sesiune strictă e lăsată în pace și nu spune nimic", () => {
  // Jumătatea care lipsește din testele de mai jos: dacă tratantul ar distruge
  // orice conexiune, ele ar trece toate fără să dovedească nimic.
  const connection = new FakePooledConnection();
  const said: string[] = [];
  initPooledConnection(connection, (m) => said.push(m));
  connection.issued[0].callback(null);
  connection.issued[1].callback(null, [{ sql_mode: STRICT_ANSWER }]);
  assert.equal(connection.destroyed, 0, "o conexiune bună a fost distrusă");
  assert.deepEqual(said, []);
});

test("o sesiune nestrictă e DISTRUSĂ, nu doar raportată", () => {
  // Jurnalul nu e poarta. Un mesaj scris și o conexiune lăsată în pool înseamnă
  // că rândurile continuă să intre tăiate, iar singura urmă e o linie pe care
  // n-o citește nimeni — exact „grep după un tipar din jurnal" din CLAUDE.md.
  assert.equal(REQUIRED_SQL_MODES.length, 4);
  for (const mode of REQUIRED_SQL_MODES) {
    const answer = [HOST_MODES, ...REQUIRED_SQL_MODES.filter((m) => m !== mode)].join(",");
    const connection = new FakePooledConnection();
    const said: string[] = [];
    initPooledConnection(connection, (m) => said.push(m));
    connection.issued[0].callback(null);
    connection.issued[1].callback(null, [{ sql_mode: answer }]);
    assert.equal(connection.destroyed, 1, `${mode} lipsă: conexiunea a rămas în pool`);
    assert.equal(said.length, 1);
    assert.match(said[0], new RegExp(mode));
  }
});

test("un răspuns ilizibil distruge conexiunea la fel", () => {
  for (const answer of [[], [{}], [{ sql_mode: 7 }], { sql_mode: STRICT_ANSWER }]) {
    const connection = new FakePooledConnection();
    const said: string[] = [];
    initPooledConnection(connection, (m) => said.push(m));
    connection.issued[0].callback(null);
    connection.issued[1].callback(null, answer);
    assert.equal(connection.destroyed, 1,
                 `răspunsul ${JSON.stringify(answer)} a fost citit ca trecere`);
    assert.match(said[0], /nu s-a aflat nimic/);
  }
});

test("un `SET` refuzat distruge o dată, cu motivul LUI", () => {
  // După distrugere, citirea înapoi eșuează și ea. Al doilea mesaj ar acoperi
  // motivul adevărat, iar operatorul ar căuta o conexiune pierdută în loc de un
  // mod respins de server.
  const connection = new FakePooledConnection();
  const said: string[] = [];
  initPooledConnection(connection, (m) => said.push(m));
  connection.issued[0].callback(
    new Error("Variable 'sql_mode' can't be set to the value of 'FOO'"));
  connection.issued[1].callback(new Error("Connection lost: The server closed"));
  assert.equal(connection.destroyed, 1, "conexiunea a fost distrusă de două ori");
  assert.deepEqual(said.length, 1);
  assert.match(said[0], /can't be set/);
  assert.doesNotMatch(said[0], /Connection lost/);
});

// ---------------------------------------------------------------------------
// Legătura: `getPool` chiar pune cârligul, pe pool-ul PRIMIT
// ---------------------------------------------------------------------------

test("`getPool` înregistrează cârligul, o singură dată, și el trimite modul", async () => {
  // Testul care leagă cele două jumătăți. Fără el, tratantul ar putea fi corect
  // și neînregistrat: pool-ul de producție ar deschide conexiuni pe `sql_mode`-ul
  // gazdei, iar toate testele de mai sus ar rămâne verzi.
  await closePool();
  const handlers: Array<(connection: PooledConnection) => void> = [];
  const pool: Pool = {
    async query() { return [[], []]; },
    async end() { /* nimic */ },
    on(_event, handler) { handlers.push(handler); return this; },
  };

  getPool(() => pool, ENV);
  getPool(() => pool, ENV);
  assert.equal(handlers.length, 1,
               "cârligul nu e înregistrat exact o dată per pool");

  const connection = new FakePooledConnection();
  handlers[0](connection);
  assert.deepEqual(connection.statements,
                   [SET_SESSION_SQL_MODE, READ_SESSION_SQL_MODE],
                   "cârligul înregistrat de getPool nu trimite modul strict");
  await closePool();
});
