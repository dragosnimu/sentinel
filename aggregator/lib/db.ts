/**
 * Legătura cu MariaDB: un pool, ținut într-un singur loc.
 *
 * ## Dimensionarea, și de ce NU se calculează din `max_connections`
 *
 * Măsurat pe gazdă: `max_connections = 2000`. E o cifră care invită la o
 * greșeală — nu e bugetul nostru. E limita ÎNTREGULUI server MariaDB, împărțită
 * cu toate celelalte baze de pe găzduirea partajată, iar limita care ne
 * privește pe noi, `max_user_connections`, **nu a fost măsurată**. Un pool
 * dimensionat „generos, avem 2000" e un pool care, în ziua în care găzduirea
 * chiar aplică o limită per utilizator, produce erori de conectare pe care
 * nimeni nu le leagă de o cifră scrisă cu luni în urmă.
 *
 * Deci se dimensionează din ce se știe, în sus:
 *
 * * Next.js pe Node e un proces (sau câteva, dacă găzduirea pornește mai
 *   multe); rutele sunt asincrone, iar concurența e a buclei de evenimente, nu
 *   a firelor. O rută ține o conexiune cât durează interogarea ei, nu cât
 *   durează cererea.
 * * Traficul agregatorului e un POST de sincronizare per instanță per interval,
 *   plus un panou read-only cu un om în fața lui. Interogările simultane se
 *   numără pe degete.
 * * **8** e implicit, configurabil, plafonat la 64. Opt interogări simultane
 *   per proces e deja mult peste ce cere forma asta de trafic, iar dacă
 *   vreodată nu e, coada de mai jos o spune înainte să o spună baza.
 *
 * ## Coada mărginită
 *
 * `queueLimit: 0` (nemărginit, implicit în mysql2) transformă o bază care s-a
 * împotmolit în memorie care crește până la OOM, iar procesul moare fără să
 * spună de ce. Cu o coadă mărginită, cererea de peste limită primește o eroare
 * — urât, dar numit, imediat, și în jurnal. Preferăm eșecul zgomotos.
 *
 * ## Două opțiuni care par cosmetice și nu sunt
 *
 * **`dateStrings: true`.** Implicit, mysql2 convertește DATETIME într-un `Date`
 * JS folosind fusul PROCESULUI. Coloanele noastre țin UTC (vezi
 * `migrations/0001_core.sql`); pe o gazdă pornită în alt fus, fiecare timp
 * citit ar fi mutat tăcut cu câteva ore, iar rapoartele ar fi greșite fără să
 * pară. Cu `dateStrings`, driverul dă înapoi exact ce e stocat, iar
 * interpretarea e o decizie explicită a apelantului.
 *
 * **`supportBigNumbers` + `bigNumberStrings`.** `source_id` e BIGINT. Fără
 * ele, mysql2 întoarce un `number`, care e exact doar până la 2^53; cu
 * `supportBigNumbers` singur, tipul depinde de MĂRIME — număr sub prag, șir
 * peste —, adică un bug care apare peste ani, o dată. Aici sunt întotdeauna
 * șiruri, iar conversia se face explicit unde e nevoie.
 *
 * **`multipleStatements` rămâne fals** (implicitul), scris pe față: cu el
 * pornit, un singur `;` strecurat într-un parametru devine SQL arbitrar.
 *
 * ## De ce pool-ul stă pe `globalThis`
 *
 * În dezvoltare, Next.js reîncarcă modulele la fiecare salvare, iar o variabilă
 * de modul ar da un pool nou la fiecare reîncărcare — conexiuni care se adună
 * până când serverul refuză. Cheia e un `Symbol.for`, deci e aceeași și dacă
 * modulul ajunge încărcat de două ori sub identități diferite.
 *
 * Migrația NU folosește pool-ul: are nevoie de o singură sesiune, fiindcă
 * lacătul (`GET_LOCK`) și verificarea de sintaxă (`PREPARE`) sunt legate de
 * sesiune. Un pool i-ar da conexiuni diferite între două interogări, iar
 * lacătul luat pe una s-ar elibera pe alta.
 *
 * ## `sql_mode`: îl pune APLICAȚIA, pe fiecare sesiune
 *
 * Măsurat pe gazdă pe 17 august 2026, MariaDB 11.8.8:
 * `sql_mode = NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION`. **Fără
 * `STRICT_TRANS_TABLES`.**
 *
 * Sub un mod nestrict un șir mai lung decât coloana nu e refuzat, e TĂIAT, cu un
 * avertisment pe care nu-l citește nimeni; un `NULL` într-o coloană `NOT NULL`
 * dintr-un `INSERT` cu mai multe rânduri devine `''`. Instrucțiunea reușește.
 * Rândul e PREZENT.
 *
 * Iar `countPresent` din `lib/ingest.ts` numără PREZENȚA. Deci un rând tăiat e
 * numărat drept bun, deci filigranul se ecouă, deci cursorul expeditorului
 * trece peste el — definitiv, fiindcă nimic nu se mai întoarce după un rând pe
 * care emitentul îl crede livrat. E chiar clasa de eșec pentru care există tot
 * modulul de ingestie: regula ecoului cumpără „a aterizat", nu „a aterizat
 * întreg".
 *
 * Și pe autentificare: `users.username` e `VARCHAR(64) ascii ascii_bin`. Sub mod
 * nestrict un nume cu diacritice devine tăcut `?` — un cont sub un nume pe care
 * nimeni nu-l mai poate retasta, cu o cheie unică peste el. Validarea din
 * `lib/auth/users.ts` rămâne acolo unde e: e apărarea care nu depinde deloc de
 * `sql_mode`, iar două apărări pentru același lucru nu sunt o risipă când una
 * din ele e a serverului altcuiva.
 *
 * Nu se cere nimic de la găzduire, fiindcă nu avem de unde ști ce acceptă și
 * fiindcă o setare pusă într-un panou web nu lasă urmă în depozit. Se pune pe
 * SESIUNE, la fiecare conexiune, din singurul loc prin care trec toate:
 * `getPool` și `createDirectConnection` sunt cele DOUĂ funcții care ating
 * driverul. Că nu apare a treia se ține prin NUMĂRARE, în
 * `tests/db-strict-mode.test.ts`, și se numără NUME, nu forme:
 *
 * * numele pachetului (`mysql`) apare în CODUL fișierelor livrate — adică în ce
 *   rămâne după ce se golesc comentariile — numai unde e declarat, și
 *   acolo de exact atâtea ori cât e declarat. Numărul pe fișier e cel care
 *   contează pentru o funcție nouă scrisă AICI: una care își cere singură
 *   driverul (`createRequire` a doua oară, `await import`, orice fel de
 *   ghilimele) n-ar chema niciodată accesorul de mai jos, dar ar muta numărul;
 * * numele `sql_mode` apare în cod numai în fișierul ăsta, deci nimeni nu-l
 *   rescrie mai târziu pe o sesiune deja pornită.
 *
 * Prima formă a recensământului potrivea ortografia specificatorului de modul
 * (`"mysql2/promise"` între ghilimele) și a fost evadată de un literal de
 * șablon — chiar forma folosită mai jos. De-aia acum se numără numele, iar
 * deosebirea dintre cod și proză o face LEXERUL: pentru `.ts` parserul din
 * `typescript`, pentru `.sql` `splitStatements` din `lib/sql-statements.ts`. Nu
 * după accente grave (în `.ts` sunt cod) și nici după începutul liniei — o scuză
 * de o linie scrisă înaintea gestului, pe aceeași linie cu el, a lăsat de două
 * ori suita verde cu o a doua cale de conectare în ea.
 *
 * ### Ce se adaugă, și de ce exact atât
 *
 * * **`STRICT_TRANS_TABLES`** — blocantul de mai sus, pe instrucțiunile care NU
 *   poartă `IGNORE`: `INSERT`/`UPDATE` simplu și `INSERT ... ON DUPLICATE KEY
 *   UPDATE`. Acolo tăierea și `NULL`-ul convertit devin erori, iar `prezent`
 *   redevine `prezent întreg`. Pe `INSERT IGNORE` nu se poate conta, și exact
 *   acolo scrie fluxul viu — vezi „Ce NU cumpără" mai jos.
 * * **`NO_ZERO_DATE` + `NO_ZERO_IN_DATE`** — fără ele, `'0000-00-00'` se scrie.
 *   Toată contabilitatea de aici se sprijină pe `DATETIME(6)`: `expires_at` se
 *   compară cu ora serverului la fiecare cerere (o sesiune cu zero nu expiră
 *   niciodată), iar rapoartele și retenția ordonează pe timp, unde un zero stă
 *   înaintea a tot. Sub mod strict, cele două devin erori. Nicio migrație nu
 *   scrie o dată zero azi, deci nu strică nimic din ce există.
 * * **`ERROR_FOR_DIVISION_BY_ZERO`** — face `x/0` eroare într-un `INSERT` sau
 *   `UPDATE`, în loc de `NULL` tăcut. Nu împărțim nimic în DML azi; e aici ca a
 *   doua împărțire scrisă mâine să nu poată intra ca `NULL`. E și un mod despre
 *   care se știe sigur că serverul îl acceptă: face parte din implicitul de
 *   fabrică al MariaDB, din care gazda a scos tocmai partea strictă.
 *
 * **`STRICT_ALL_TABLES` NU e pus.** Pe o tabelă netranzacțională el întrerupe
 * instrucțiunea la mijloc și lasă rândurile scrise până acolo — adică un
 * `INSERT` cu mai multe rânduri intrat pe jumătate, care e mai rău pentru o
 * replică decât oricare dintre celelalte două capete. Toate tabelele din
 * `migrations/` sunt `ENGINE=InnoDB`, deci `STRICT_TRANS_TABLES` le acoperă deja
 * pe toate; `STRICT_ALL_TABLES` ar schimba purtarea doar pentru o tabelă pe care
 * nu o avem, și ar schimba-o în rău.
 *
 * ### Ce NU cumpără modul strict: `INSERT IGNORE`, adică fluxul viu
 *
 * Scris aici fiindcă e chiar cazul pentru care sună tot restul secțiunii, și
 * fiindcă cine citește „prezent redevine prezent întreg" și oprește acolo pleacă
 * cu o garanție pe care calea vie nu i-o dă.
 *
 * `writeSql` din `lib/ingest.ts` alege `INSERT IGNORE` pentru fluxurile
 * append-only și pentru tabelele de legătură care sunt numai identitate. Acolo
 * intră `audit_log` → `audit_entries`, SINGURUL flux înregistrat azi în
 * producție. Tabelele de legătură ar intra tot acolo — patru din cele cinci sunt
 * numai identitate, deci `writeSql` n-ar avea ce să le pună în clauza de
 * actualizare —, dar azi nu se scrie NICIUNA: niciun flux din `lib/streams.ts`
 * nu declară `children`, deci sub-rândurile n-au încă nici emitent, nici
 * receptor. Nu e o alegere de stil:
 * `migrations/0001_core.sql` pune pe `audit_entries` un trigger `BEFORE UPDATE`
 * care refuză orice rescriere, deci ramura de UPDATE a lui `ON DUPLICATE KEY`
 * ar eșua la primul rând deja prezent. Idempotența de acolo nu se poate scrie
 * decât cu `IGNORE`.
 *
 * Iar `IGNORE` e chiar modificatorul care coboară erorile de DATE înapoi la
 * avertismente și scrie rândul ajustat. Asta o documentează MariaDB, pentru
 * familia noastră de versiuni, în două feluri care se sprijină unul pe altul:
 * pagina `IGNORE` enumeră codurile convertite în avertisment — 1022, 1048, 1062,
 * 1242, 1264, **1265**, 1292, 1366, 1369, 1451, 1452, 1526, 1586, 1591, 1748 —
 * și spune pe față că sub `IGNORE` modurile `STRICT_TRANS_TABLES`,
 * `STRICT_ALL_TABLES`, `NO_ZERO_IN_DATE` și `NO_ZERO_DATE` sunt IGNORATE. Deci
 * acolo modul strict nu se aplică deloc: un șir prea lung nu ridică 1406, se
 * taie cu 1265 („Data truncated for column"), iar 1265 e chiar în listă.
 *
 * **Nu a fost măsurat pe gazda noastră**: pasul 4 al probei din `README.md`
 * există exact ca să răspundă, și rămâne singura măsurătoare pe 11.8.8. Dacă
 * iese invers față de documentație, se scrie NUMĂRUL de versiune lângă
 * afirmație, fiindcă ar fi o purtare specifică unei versiuni.
 *
 * Ce apără calea aia AZI, oricare ar fi răspunsul, e `checkString` +
 * `column.maxBytes` din `lib/ingest.ts`: un șir mai lung decât coloana e REFUZAT
 * cu lotul cu tot, înainte să se construiască vreo instrucțiune. E o apărare de
 * APLICAȚIE, deci nu depinde deloc de `sql_mode`-ul serverului altcuiva — dar pe
 * calea cu `IGNORE` e și singura, deci nu are voie să fie ștearsă cândva „fiindcă
 * oricum avem mod strict".
 *
 * Ce cumpără atunci modul strict, și de ce rămâne net pozitiv: fluxurile
 * mutabile (`incidents` → `incident_entries`, care scrie cu `ON DUPLICATE KEY
 * UPDATE`, fără `IGNORE`), scrierile de autentificare din `lib/auth/`,
 * migrațiile, datele zero și împărțirea la zero.
 *
 * ### De ce se ADAUGĂ la ce e deja acolo, în loc să se scrie o listă
 *
 * `CONCAT_WS` peste `@@SESSION.sql_mode`, nu un literal, din două motive:
 *
 * * `NO_ENGINE_SUBSTITUTION` e pus de gazdă și e util — un motor lipsă devine
 *   eroare, nu o substituție tăcută. Nu avem de ce să-l ștergem;
 * * ca să nu trebuiască să scriem `NO_AUTO_CREATE_USER`, pe care MariaDB l-a
 *   depreciat. Un mod scris pe față și scos într-o versiune viitoare a
 *   serverului înseamnă că FIECARE conexiune eșuează în ziua actualizării.
 *   Nescriindu-l, întrebarea nu se pune.
 *
 * `NULLIF(@@SESSION.sql_mode, '')` fiindcă un `sql_mode` gol ar da prin `CONCAT`
 * o virgulă la început, iar un element gol e refuzat de server.
 *
 * ### Ce dovedește efectul, și ce nu
 *
 * Pe conexiunea singură (`bin/`, migrații) modul se pune ȘI se CITEȘTE ÎNAPOI,
 * iar un răspuns care nu conține tot ce am cerut ARUNCĂ. Un `SET` care întoarce
 * „ok" nu e dovadă că modul e în sesiune — e chiar tiparul din `CLAUDE.md`.
 * „Nu se poate citi răspunsul" e tratat la fel cu „lipsește un mod": nu știm, nu
 * trecem.
 *
 * Pe pool poarta nu se poate ține la fel, și e scris pe față: `mysql2` emite
 * `connection` sincron, iar interogarea apelantului intră în coada aceleiași
 * conexiuni imediat după. Ce se pune în coadă SINCRON în tratantul evenimentului
 * ajunge înaintea ei — deci `SET` și citirea înapoi ajung —, dar verdictul
 * citirii vine după ce interogarea apelantului e deja în coadă. Așa că verdictul
 * nu amână nimic: DISTRUGE conexiunea.
 *
 * Ce face `destroy()` — citit în sursa lui `mysql2` (`lib/pool_connection.js`,
 * `lib/base/connection.js`), cu deducția ținută separat de fapt:
 *
 * * **Scoasă din pool**, sigur: `PoolConnection.destroy()` cheamă
 *   `_removeFromPool()` ÎNAINTE de `super.destroy()`, iar aia o scoate din
 *   `_allConnections`. Conexiunea nestrictă nu mai e dată nimănui altcuiva —
 *   asta e jumătatea care mărginește paguba la un singur apelant.
 * * **Ce se adaugă DUPĂ** eșuează numit, tot sigur: `close()` înlocuiește
 *   `addCommand` cu `_addCommandClosedState`, care întoarce imediat, pe
 *   callbackul comenzii, „Can't add new command when connection is in closed
 *   state".
 * * **Ce era DEJA în coadă** — aici mecanismul nu e cel la care te-ai aștepta, și
 *   nu e măsurat: `close()` NU golește coada, iar tratantul de `close` al
 *   socketului iese devreme exact pe fanionul `_closing` pe care `close()`
 *   tocmai l-a pus, deci nu ajunge la `_notifyError`. DEDUS din sursă, fără
 *   MariaDB la capăt: interogarea apelantului se scrie pe un socket deja
 *   încheiat, iar eroarea de scriere intră prin `_handleNetworkError` →
 *   `_handleFatalError` → `_notifyError`, care chiar golește coada cu eroare.
 *
 * Dacă deducția aia e greșită, ce iese nu e o interogare picată, ci o promisiune
 * de rută care nu se așază niciodată — un blocaj tăcut, adică lucrul despre care
 * depozitul ăsta scrie deja că e mai rău decât un eșec (`run-tests.mjs`). Se
 * măsoară pe gazdă, cu pool-ul adevărat; de aici nu se poate.
 *
 * Jurnalul rămâne informativ, nu e poarta: apelantul vede eroarea driverului, nu
 * motivul nostru, iar motivul e doar în `announce`.
 */

import { createRequire } from "node:module";

import { readDbConfig } from "./env";
import { SchemaGuardError, checkSchemaGuard } from "./schema-guard";
import type { Db } from "./migrate";
import type { DbConfig, Env } from "./env";
import type { SchemaGuardResult } from "./schema-guard";

/** Ce folosim de la driver. Îngust dinadins: nimic de aici nu trebuie să
 *  cunoască mysql2, iar un dublu de test nu trebuie să-l implementeze. */
export interface Queryable {
  query(sql: string, params?: unknown[]): Promise<[unknown, unknown]>;
}

/**
 * Conexiunea BRUTĂ pe care pool-ul o dă la evenimentul `connection`.
 *
 * API pe callback, nu pe promisiuni, fiindcă `mysql2/promise` re-emite
 * conexiunea DE BAZĂ, nu învelișul cu promisiuni (`lib/promise/pool.js`,
 * `inheritEvents`). Un tratant scris cu `await` ar fi cerut o formă pe care
 * obiectul emis nu o are.
 */
export interface PooledConnection {
  query(sql: string, callback: (err: unknown, rows?: unknown) => void): unknown;
  destroy(): void;
}

export interface Pool extends Queryable {
  end(): Promise<void>;
  /**
   * `connection` din `mysql2`: se emite cu FIECARE conexiune nouă a pool-ului.
   *
   * E în interfață, nu ocolit printr-un cast, tocmai ca un dublu nou să nu poată
   * fi scris fără să vadă că pool-ul are un cârlig per conexiune. Un dublu nu
   * deschide nicio sesiune MariaDB, deci al lui n-are ce să pună în mod strict;
   * că `getPool` chiar îl înregistrează și ce anume trimite pe el se probează în
   * `tests/db-strict-mode.test.ts`.
   */
  on(event: "connection", handler: (connection: PooledConnection) => void): unknown;
}

export interface Connection extends Queryable {
  end(): Promise<void>;
}

export type PoolFactory = (options: Record<string, unknown>) => Pool;

/** Cum se face o conexiune singură. Parametru ca să poată fi probată fără
 *  MariaDB — vezi `createDirectConnection`. */
export type ConnectionFactory =
  (options: Record<string, unknown>) => Promise<Connection>;

export function buildPoolOptions(cfg: DbConfig): Record<string, unknown> {
  return {
    host: cfg.host,
    port: cfg.port,
    user: cfg.user,
    password: cfg.password,
    database: cfg.database,

    waitForConnections: true,
    connectionLimit: cfg.connectionLimit,
    // Vezi „Coada mărginită" în capul modulului. Nu 0.
    queueLimit: 64,
    maxIdle: cfg.connectionLimit,
    idleTimeout: 60_000,
    connectTimeout: cfg.connectTimeoutMs,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10_000,

    // Vezi „Două opțiuni care par cosmetice".
    dateStrings: true,
    supportBigNumbers: true,
    bigNumberStrings: true,
    multipleStatements: false,

    charset: "utf8mb4_unicode_ci",
    timezone: "Z",
  };
}

// ---------------------------------------------------------------------------
// `sql_mode` strict, pe fiecare sesiune. Vezi capul modulului.
// ---------------------------------------------------------------------------

/** Modurile CERUTE de aplicație. Motivul fiecăruia e în capul modulului. */
export const REQUIRED_SQL_MODES = [
  "STRICT_TRANS_TABLES",
  "NO_ZERO_DATE",
  "NO_ZERO_IN_DATE",
  "ERROR_FOR_DIVISION_BY_ZERO",
] as const;

/**
 * Instrucțiunea, DERIVATĂ din lista de mai sus.
 *
 * Derivată, nu scrisă a doua oară: două liste care spun același lucru sunt două
 * liste care se pot desincroniza, iar aici desincronizarea ar fi tăcută — modul
 * lipsă din instrucțiune n-ar ajunge niciodată pe server, dar citirea înapoi
 * l-ar cere, deci fiecare conexiune ar muri fără să spună de ce. Numele sunt
 * constante din fișierul ăsta, nu date, deci nu e nimic de scăpat.
 */
export const SET_SESSION_SQL_MODE =
  "SET SESSION sql_mode = CONCAT_WS(',', NULLIF(@@SESSION.sql_mode, ''), " +
  `'${REQUIRED_SQL_MODES.join(",")}')`;

/** Citirea înapoi. Un `SET` care întoarce „ok" nu e dovadă că modul e în
 *  sesiune; asta e. */
export const READ_SESSION_SQL_MODE = "SELECT @@SESSION.sql_mode AS sql_mode";

/**
 * Ce lipsește din ce a răspuns serverul.
 *
 * `null` înseamnă **nu se poate citi răspunsul**, și e altceva decât „nu
 * lipsește nimic". Un tablou gol întors pentru un răspuns neînțeles ar fi exact
 * minciuna pe care o previne tot fișierul: sesiunea ar trece drept strictă
 * fiindcă nimeni n-a putut verifica.
 */
export function missingSqlModes(rows: unknown): string[] | null {
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const raw = (rows[0] as Record<string, unknown> | null | undefined)?.sql_mode;
  if (typeof raw !== "string") return null;
  const present = new Set(
    raw.split(",").map((mode) => mode.trim().toUpperCase()).filter(Boolean));
  return REQUIRED_SQL_MODES.filter((mode) => !present.has(mode));
}

/** Un text care spune ce s-ar strica, nu doar că ceva n-a mers. Îl citește
 *  operatorul într-o eroare de migrație sau într-un jurnal. */
function sqlModeFailure(detail: string): string {
  return `sesiunea MariaDB nu a putut fi pusă în mod strict: ${detail}. ` +
         "Nu se continuă: sub un mod nestrict un șir mai lung decât coloana e " +
         "TĂIAT cu un avertisment, iar rândul tăiat e „prezent” — adică numărat " +
         "drept bun de lib/ingest.ts, ecouat ca filigran, și trecut de cursorul " +
         "expeditorului pentru totdeauna. Vezi capul lui lib/db.ts.";
}

/**
 * Pune modul strict pe o sesiune și DOVEDEȘTE că a intrat.
 *
 * Se folosește acolo unde se poate aștepta răspunsul înainte ca altcineva să
 * scrie ceva pe sesiunea aia — adică pe conexiunea singură. Pe pool, vezi
 * `initPooledConnection`.
 */
export async function applyStrictSession(q: Queryable): Promise<void> {
  await q.query(SET_SESSION_SQL_MODE);
  const [rows] = await q.query(READ_SESSION_SQL_MODE);
  const missing = missingSqlModes(rows);
  if (missing === null) {
    throw new Error(sqlModeFailure(
      "serverul nu a răspuns la `" + READ_SESSION_SQL_MODE + "` cu ceva ce se " +
      "poate citi, deci despre modul sesiunii nu s-a aflat nimic"));
  }
  if (missing.length) {
    throw new Error(sqlModeFailure(
      `serverul a acceptat instrucțiunea, dar sesiunea tot nu are ${missing.join(", ")}`));
  }
}

/**
 * Același lucru pe o conexiune a pool-ului, cu ce se poate face acolo.
 *
 * Amândouă interogările se pun în coadă **sincron**, dinadins: `mysql2` emite
 * `connection` înainte de a da conexiunea apelantului, iar coada de comenzi e
 * FIFO — deci ce se adaugă aici, acum, pleacă înaintea primei interogări a
 * apelantului. Puse înlănțuit (a doua din tratantul primeia) ar fi ajuns DUPĂ
 * ea, adică ar fi verificat sesiunea după ce s-a scris pe ea.
 *
 * Verdictul citirii vine oricum după ce interogarea apelantului e în coadă, deci
 * nu poate amâna nimic. Ce poate face — și face — e să DISTRUGĂ conexiunea:
 * scoasă din pool, deci nedată nimănui altcuiva. Ce se întâmplă cu interogarea
 * apelantului aflată deja în coadă e dedus, nu măsurat — capul modulului scrie
 * pe ce drum credem că eșuează, și ce iese dacă drumul ăla nu e cel adevărat.
 */
export function initPooledConnection(
  connection: PooledConnection,
  announce: (message: string) => void = (m) => console.error(m),
): void {
  let dropped = false;
  const drop = (detail: string): void => {
    // Prima cauză e cea adevărată: dacă `SET` a eșuat și am distrus conexiunea,
    // citirea de după eșuează și ea, iar al doilea mesaj ar acoperi motivul.
    if (dropped) return;
    dropped = true;
    announce(sqlModeFailure(detail));
    connection.destroy();
  };

  connection.query(SET_SESSION_SQL_MODE, (err) => {
    if (err) drop(`serverul a refuzat instrucțiunea (${describe(err)})`);
  });
  connection.query(READ_SESSION_SQL_MODE, (err, rows) => {
    if (err) {
      drop(`citirea înapoi a modului a eșuat (${describe(err)})`);
      return;
    }
    const missing = missingSqlModes(rows);
    if (missing === null) {
      drop("citirea înapoi a modului nu a întors ceva ce se poate citi, deci " +
           "despre modul sesiunii nu s-a aflat nimic");
      return;
    }
    if (missing.length) {
      drop(`serverul a acceptat instrucțiunea, dar sesiunea tot nu are ` +
           `${missing.join(", ")}`);
    }
  });
}

function describe(err: unknown): string {
  const message = (err as { message?: unknown } | null)?.message;
  return typeof message === "string" ? message.slice(0, 200) : String(err);
}

const POOL_KEY = Symbol.for("sentinel.aggregator.pool");
type Holder = { [POOL_KEY]?: Pool };

/**
 * Învelește un pool ca fiecare `query()` să aștepte întâi garda de schemă din
 * `lib/schema-guard.ts` — o singură dată cât trăiește ÎNVELIȘUL, nu o dată pe
 * interogare. Vezi capul lui `schema-guard.ts` pentru CE verifică; aici e doar
 * cablarea: cine apelează, cât ține minte, și ce înseamnă „nu ține minte".
 *
 * Un obiect plan, nu un `Proxy` peste pool-ul brut al lui mysql2: pool-ul e un
 * `EventEmitter` care își scrie singur câmpuri interne (`this.x = …`) prin
 * metodele lui, iar un `Proxy` fără capcană `set` explicită le-ar redirecționa
 * pe RECEIVER (învelișul), nu pe `target` — o corupere tăcută a stării
 * driverului, pe drumul care duce spre baza de PRODUCȚIE. `Pool` din fișierul
 * ăsta e dinadins îngust (`query`, `end`, `on`), deci un obiect scris de mână
 * care deleagă exact cele trei metode e mai simplu ȘI mai sigur decât orice
 * încercare de a fi „transparent" cu un Proxy.
 *
 * ## Ce ține minte, și ce NU
 *
 * Un refuz REAL (`not-installed`, `outdated`) nu se rezolvă singur cât
 * procesul trăiește — schimbarea vine dintr-un `npm run migrate` urmat de un
 * restart, exact ciclul din `README.md`. Deci se ține minte, ca fiecare
 * interogare de după prima să nu mai plătească din nou recensământul pe
 * `schema_version`.
 *
 * Un `unknown` (baza n-a putut fi întrebată acum) NU se ține minte: altfel un
 * singur blip de rețea la pornire ar bloca definitiv procesul, chiar după ce
 * baza redevine sănătoasă — exact genul de eșec permanent dintr-o cădere
 * trecătoare împotriva căruia scrie `docs/ARHITECTURA.md` §3.13. La fel, o
 * eroare care nu vine de la gardă (conexiune refuzată, timeout) nu e o
 * concluzie despre SCHEMĂ, deci nici ea nu se ține minte.
 */
export function withSchemaGuard(
  rawPool: Pool, check: (db: Db) => Promise<SchemaGuardResult> = checkSchemaGuard,
): Pool {
  let attempt: Promise<void> | null = null;

  const ensure = (): Promise<void> => {
    if (attempt) return attempt;
    const running: Promise<void> = check(queryableDb(rawPool)).then((result) => {
      if (!result.ok) throw new SchemaGuardError(result);
    });
    attempt = running.catch((err) => {
      const sticky = err instanceof SchemaGuardError && err.result.kind !== "unknown";
      if (!sticky) attempt = null;
      throw err;
    });
    return attempt;
  };

  return {
    async query(sql: string, params?: unknown[]) {
      await ensure();
      return rawPool.query(sql, params);
    },
    end: () => rawPool.end(),
    on: (event, handler) => rawPool.on(event, handler),
  };
}

// `Env` scris pe față, nu dedus din `process.env`: tipul dedus ar fi
// `NodeJS.ProcessEnv`, iar Next îl augmentează cu un `NODE_ENV` OBLIGATORIU —
// deci orice apelant care dă un mediu de probă (testele) ar trebui să inventeze
// o valoare pentru o variabilă care nu are nicio treabă cu baza de date. Ce
// citește funcția e chiar `Env` din `lib/env.ts`.
//
// `guardCheck` există DOAR pentru `tests/db.test.ts`, ca proba „`getPool()`
// fără `factory` leagă garda" să nu ceară MariaDB la capăt: pool-ul lui mysql2
// e lazy — `createPool()` nu deschide nicio conexiune —, deci un `guardCheck`
// injectat poate respinge sau accepta ÎNAINTE ca `query()` să atingă vreodată
// rețeaua. Neprimit, cade pe implicitul lui `withSchemaGuard`
// (`checkSchemaGuard`), exact ca pe drumul de producție.
export function getPool(
  factory?: PoolFactory, env: Env = process.env,
  guardCheck?: (db: Db) => Promise<SchemaGuardResult>,
): Pool {
  const holder = globalThis as unknown as Holder;
  const existing = holder[POOL_KEY];
  if (existing) return existing;

  const make: PoolFactory = factory ?? ((options) => mysql().createPool(options) as Pool);
  const rawPool = make(buildPoolOptions(readDbConfig(env)));
  // AICI, nu în fabrica implicită: cârligul trebuie să prindă și pool-ul dat de
  // un apelant, altfel „toate conexiunile” ar însemna de fapt „cele pe care
  // le-am făcut eu”. Se înregistrează o singură dată, ca și pool-ul — pe
  // pool-ul BRUT, dinadins: garda de schemă de mai jos învelește doar `query`,
  // iar `sql_mode` trebuie pus pe fiecare conexiune nouă indiferent de gardă.
  rawPool.on("connection", (connection) => initPooledConnection(connection));
  // Garda se pune DOAR pe drumul driverului real (`factory` nesetat): un
  // dublu de test dat de un apelant nu vorbește cu MariaDB, deci n-are ce
  // schemă să apere — vezi `lib/schema-guard.ts` și `tests/schema-guard.test.ts`
  // pentru proba directă a învelișului, fără să treacă prin `getPool`.
  const pool = factory === undefined ? withSchemaGuard(rawPool, guardCheck) : rawPool;
  holder[POOL_KEY] = pool;
  return pool;
}

/** Închide și uită pool-ul. Există pentru teste și pentru procesele de o
 *  singură treabă, nu pentru rute. */
export async function closePool(): Promise<void> {
  const holder = globalThis as unknown as Holder;
  const pool = holder[POOL_KEY];
  delete holder[POOL_KEY];
  if (pool) await pool.end();
}

/**
 * O sesiune singură, pentru migrație și pentru verificarea de sintaxă.
 *
 * Aici modul strict e ȘI cerut, ȘI citit înapoi, ȘI așteptat: nimeni nu scrie pe
 * sesiunea asta până nu se întoarce funcția. Dacă nu se poate, nu se dă o
 * conexiune pe jumătate bună — se aruncă, iar `npm run migrate` se oprește cu
 * motivul scris. E și proba pe care o are operatorul că serverul chiar onorează
 * instrucțiunea, fiindcă e aceeași instrucțiune pe care o trimite și pool-ul.
 *
 * `factory` există pentru teste, nu pentru configurare: fără ea, calea asta n-ar
 * putea fi probată decât cu MariaDB la capăt.
 */
export async function createDirectConnection(
  env: Env = process.env, factory?: ConnectionFactory,
): Promise<Connection> {
  const options = buildPoolOptions(readDbConfig(env));
  // Opțiunile de pool n-au sens pentru o conexiune; mysql2 le ignoră, dar le
  // scoatem ca să nu pară configurate.
  for (const key of ["waitForConnections", "connectionLimit", "queueLimit",
                     "maxIdle", "idleTimeout"]) {
    delete options[key];
  }
  const make: ConnectionFactory = factory
    ?? (async (o) => await mysql().createConnection(o) as Connection);
  const connection = await make(options);
  try {
    await applyStrictSession(connection);
  } catch (err) {
    // Conexiunea nu pleacă mai departe și nici nu rămâne deschisă. Un eșec la
    // închidere nu are voie să acopere motivul adevărat — ăla e ce citește
    // operatorul.
    try {
      await connection.end();
    } catch {
      /* motivul adevărat e `err`; ce s-a întâmplat la închidere nu-l schimbă */
    }
    throw err;
  }
  return connection;
}

type Mysql2 = {
  createPool: (o: Record<string, unknown>) => unknown;
  createConnection: (o: Record<string, unknown>) => Promise<unknown>;
};

/**
 * mysql2, încărcat la cerere.
 *
 * `createRequire`, nu un `import` de sus: `lib/db.ts` e importat și de teste
 * care nu ating niciodată baza (dimensionarea pool-ului, adaptorul), iar
 * driverul e o dependență grea. Cast explicit — pool-ul lui mysql2 satisface
 * structural interfețele de mai sus, dar tipurile lui sunt mult mai largi.
 */
function mysql(): Mysql2 {
  const requireFrom = createRequire(import.meta.url);
  return requireFrom("mysql2/promise") as Mysql2;
}

/**
 * Adaptorul dintre driver și interfața cerută de runner-ul de migrații.
 *
 * `all` întoarce rândurile ca obiecte simple. `run` aruncă rezultatul: o
 * instrucțiune DDL nu întoarce nimic util, iar un apelant care s-ar uita la ce
 * a întors ar confunda „serverul a acceptat cererea" cu „obiectul există" —
 * distincția pe care `lib/migrate.ts` o face verificând `information_schema`
 * după fiecare instrucțiune.
 */
export function queryableDb(q: Queryable): Db {
  return {
    async all(sql: string, params: unknown[] = []): Promise<Record<string, unknown>[]> {
      const [rows] = await q.query(sql, params);
      // Un DDL sau un UPDATE întorc un ResultSetHeader, nu un tablou. Cine cere
      // rânduri și primește altceva nu are voie să primească `[]`: „n-am rânduri"
      // și „n-am întrebat ce credeam" sunt lucruri diferite.
      if (!Array.isArray(rows)) {
        throw new Error(
          "interogarea nu a întors un set de rânduri; `all` a fost chemat pentru " +
          "o instrucțiune care nu selectează nimic");
      }
      return rows as Record<string, unknown>[];
    },
    async run(sql: string, params: unknown[] = []): Promise<void> {
      await q.query(sql, params);
    },
  };
}
