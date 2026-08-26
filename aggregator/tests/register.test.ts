/**
 * Înregistrarea unei instanțe: sigilare, rotire, listare, oprire.
 *
 * ## Ce se strică pentru operator dacă modulul ăsta greșește
 *
 * Instrumentul ăsta e singurul lucru care scrie rândul din care ruta de
 * sincronizare își ia cheia. Dacă sigilează altceva decât ce semnează serverul —
 * altă valoare, alt AAD, altă coloană — fiecare lot primește 401 sau 500, la
 * infinit, iar simptomul e imposibil de deosebit de o cheie greșită pe serverul
 * monitorizat. Operatorul caută zile întregi pe partea nevinovată.
 *
 * Dacă suprascrie tăcut o cheie funcțională, oprește expedierea unui server
 * sănătos. Dacă tipărește secretul, îl pune în scrollback, în capturi și în
 * tichete.
 *
 * ## CE AFIRMĂ DUBLUL DE MAI JOS, ȘI CE NU POATE AFIRMA
 *
 * Nu există MariaDB pe mașina asta și nici conexiune la distanță pe găzduire —
 * aceeași situație ca la `tests/migrate.test.ts` și `tests/sync-harness.ts`, și
 * aceeași abordare. `FakeInstances` **citește instrucțiunea**: lista de coloane a
 * unui `INSERT` și atribuirile unui `UPDATE` se iau din textul SQL, nu se
 * presupun. Fără asta, o valoare sigilată scrisă în coloana greșită — `label` în
 * loc de `ship_secret_enc` — ar trece verde, fiindcă un dublu care leagă
 * parametrii după o ordine presupusă găsește exact ce se aștepta să găsească.
 *
 * Ce modelează: cheia unică pe `instance_id` (ER_DUP_ENTRY), scrierea coloanelor
 * numite, citirea coloanelor cerute.
 *
 * Ce NU se dovedește de aici, și trebuie verificat pe gazdă:
 *
 *   * că `UTC_TIMESTAMP(6)` e acceptat și că `ship_secret_set_at` chiar se scrie;
 *   * că `VARCHAR(255)` e destul pentru jetonul sigilat — un jeton mai lung ar fi
 *     TRUNCHIAT de MariaDB, iar `open()` ar întoarce `null` la prima cerere;
 *   * că driverul întoarce `code: "ER_DUP_ENTRY"` pe cheia unică;
 *   * că `enabled` citit înapoi vine ca număr, nu ca `Buffer` (TINYINT(1)).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough, Readable } from "node:stream";

import { SecretBox } from "../lib/crypto";
import { queryableDb } from "../lib/db";
import { SHIP_SECRET_FIELD, lookupInstanceKey } from "../lib/ship-keys";
import {
  MIN_SHIP_SECRET_LENGTH, checkSecretShape, listInstances, parseArgv, registerInstance,
  rotateSecret, serverSecretForm, setEnabled,
} from "../lib/register";
import { SHIP_SECRET_ENV, readShipSecret, readerFor } from "../lib/secret-input";
import type { InputStream } from "../lib/secret-input";
import type { Pool } from "../lib/db";

const MASTER = "0".repeat(32) + "abcdefabcdefabcdefabcdefabcdef12";
const A = "a1b2c3d4e5f60718";
const B = "b2c3d4e5f6071829";
/** 64 de caractere, forma pe care o produce `openssl rand -hex 32`. */
const SECRET = "7f".repeat(32);
const OTHER_SECRET = "3c".repeat(32);

// ---------------------------------------------------------------------------
// Dublul. Citește instrucțiunea; nu presupune ordinea coloanelor.
// ---------------------------------------------------------------------------
type Row = Record<string, unknown>;

class FakeInstances implements Pool {
  readonly rows = new Map<string, Row>();
  readonly asked: string[] = [];

  /**
   * Scrierile ies cu succes și NU au efect.
   *
   * Nu e o ciudățenie inventată: un `UPDATE` care nu potrivește niciun rând iese
   * cu succes, un `INSERT` pe altă bază decât cea la care te uiți la fel, iar un
   * `affectedRows` întors de driver nu spune că rândul e citibil. Fără starea
   * asta, „am scris" și „e acolo" n-ar putea fi deosebite de niciun test.
   */
  constructor(readonly dropWrites: boolean = false) {}

  /**
   * Câte scrieri ale cheii mai strică coloana înainte să se poarte normal.
   *
   * Modelează o coloană care nu întoarce ce a primit — trunchiere, o conversie
   * de set de caractere, o restaurare parțială. Nu se poate produce scriind
   * corect, deci trebuie să poată fi cerut; e singura cale prin care se poate
   * proba ce se întâmplă cu cheia VECHE când rotirea nu se confirmă.
   */
  corruptWrites = 0;

  async end(): Promise<void> { /* nimic de închis */ }

  /** Dublul ăsta nu trece prin `getPool`, deci nimeni nu-i cheamă cârligul.
   *  E aici fiindcă `Pool` îl cere — vezi `lib/db.ts`. */
  on(): unknown { return this; }

  async query(sql: string, params: unknown[] = []): Promise<[unknown, unknown]> {
    this.asked.push(sql);

    if (sql.startsWith("INSERT INTO instances")) {
      // Lista de coloane se ia DIN INSTRUCȚIUNE. `VALUES (...)` la fel: un `?`
      // consumă un parametru, orice altceva (`1`, `UTC_TIMESTAMP(6)`) e o
      // valoare scrisă în text. Așa, o coloană mutată sau un parametru în plus
      // pică zgomotos în loc să nimerească unde se aștepta dublul.
      const columns = splitTop(parenGroup(sql, sql.indexOf("(")));
      const values = splitTop(parenGroup(sql, sql.indexOf("(", sql.indexOf("VALUES"))));
      assert.equal(columns.length, values.length,
                   `INSERT cu ${columns.length} coloane și ${values.length} valori`);
      const row: Row = {};
      let next = 0;
      values.forEach((value, i) => {
        row[columns[i]] = value === "?" ? params[next++] : literal(value);
      });
      assert.equal(next, params.length, "parametri nefolosiți în INSERT");

      const id = String(row.instance_id);
      if (this.dropWrites) return [{ affectedRows: 1 }, []];
      if (this.rows.has(id)) {
        const err = new Error("Duplicate entry") as Error & { code: string };
        err.code = "ER_DUP_ENTRY";
        throw err;
      }
      this.rows.set(id, { label: null, enabled: 1, ship_secret_enc: null,
                          ship_secret_set_at: null, first_seen_at: null,
                          last_batch_at: null, last_batch_seq: null, ...row });
      return [{ affectedRows: 1 }, []];
    }

    if (sql.startsWith("UPDATE instances SET")) {
      // Atribuirile se citesc din text, în ordinea lor. Un `SET` care scrie altă
      // coloană decât cea intenționată se vede aici, nu peste o lună.
      const assignments = splitTop(sql.slice(sql.indexOf("SET") + 3, sql.indexOf("WHERE")));
      const id = String(params[params.length - 1]);
      assert.ok(sql.includes("WHERE instance_id = ?"), `UPDATE fără WHERE pe identitate: ${sql}`);
      const row = this.rows.get(id);
      let next = 0;
      const patch: Row = {};
      for (const assignment of assignments) {
        const [column, value] = assignment.split("=").map((s) => s.trim());
        patch[column] = value === "?" ? params[next++] : literal(value);
      }
      assert.equal(next, params.length - 1, "parametri nefolosiți în UPDATE");
      if (row && !this.dropWrites) {
        if (this.corruptWrites > 0 && typeof patch.ship_secret_enc === "string") {
          this.corruptWrites--;
          patch.ship_secret_enc = `${patch.ship_secret_enc}stricat`;
        }
        this.rows.set(id, { ...row, ...patch });
      }
      return [{ affectedRows: row ? 1 : 0 }, []];
    }

    if (sql.startsWith("SELECT") && sql.includes("FROM instances")) {
      const wanted = between(sql, "SELECT", "FROM").split(",").map((c) => c.trim());
      const all = sql.includes("WHERE instance_id = ?")
        ? [this.rows.get(String(params[0]))].filter(Boolean) as Row[]
        : [...this.rows.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([, r]) => r);
      return [all.map((row) => Object.fromEntries(
        wanted.map((c) => [c, row[c] ?? null]))), []];
    }

    throw new Error(`FakeInstances: interogare neprevăzută: ${sql}`);
  }
}

function between(text: string, open: string, close: string): string {
  const from = text.indexOf(open);
  const to = text.indexOf(close, from + open.length);
  assert.ok(from >= 0 && to > from, `nu găsesc ${open}…${close} în: ${text}`);
  return text.slice(from + open.length, to);
}

/**
 * Conținutul unei paranteze, până la PERECHEA ei.
 *
 * Numărare de adâncime, nu „primul `)`": `UTC_TIMESTAMP(6)` are unul înăuntru,
 * iar tăiatul acolo ar face dublul să citească altceva decât scrie
 * instrucțiunea — adică exact greșeala pe care dublul ăsta există ca să o
 * prindă, făcută de el însuși.
 */
function parenGroup(text: string, open: number): string {
  assert.equal(text[open], "(", `nu începe cu paranteză: ${text.slice(open, open + 20)}`);
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth === 0) return text.slice(open + 1, i);
  }
  throw new Error(`paranteză neînchisă în: ${text}`);
}

/** Împarte la virgulele de la adâncime zero. */
function splitTop(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let current = "";
  for (const ch of text) {
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "," && depth === 0) { out.push(current.trim()); current = ""; continue; }
    current += ch;
  }
  if (current.trim()) out.push(current.trim());
  return out;
}

/** Valorile scrise în text, nu ca parametru. Dublul nu are ceas, deci un timp
 *  al serverului devine un marcaj recunoscibil. */
function literal(value: string): unknown {
  if (value === "UTC_TIMESTAMP(6)") return "2026-08-15 10:00:00.000000";
  if (/^\d+$/.test(value)) return Number(value);
  throw new Error(`FakeInstances: valoare literală neprevăzută: ${value}`);
}

function dbOf(server: FakeInstances) {
  return queryableDb(server);
}

// ---------------------------------------------------------------------------
// Forma secretului
// ---------------------------------------------------------------------------
test("forma citită de server e cea care se sigilează, altfel se REFUZĂ", () => {
  // `load_secrets` din `sentinel/config.py` taie spațiile și o pereche de
  // ghilimele. Dacă instrumentul ar sigila valoarea cu ghilimele cu tot, serverul
  // ar semna cu alta, iar fiecare lot ar primi 401 — imposibil de deosebit de o
  // cheie greșită. Se refuză, nu se repară: un instrument care „repară" e al
  // doilea parser de secrete, de ținut în acord cu primul pentru totdeauna.
  assert.equal(checkSecretShape(SECRET).ok, true);

  // Ultimele șase sunt cele care scăpaseră: Python le taie la citirea lui
  // `secrets.env` (`str.strip()`), JavaScript nu, deci instrumentul sigila o
  // valoare și serverul semna alta. DE CE trebuie refuzate se dovedește în
  // `tests/unit/test_aggregator_secret_form.py`, cu parserul REAL al serverului;
  // aici se ține doar purtarea, ieftin și local. Scrise prin cod, nu ca litere.
  const pythonOnly = [0x1c, 0x1d, 0x1e, 0x1f, 0x85].map((c) => String.fromCharCode(c));
  let probed = 0;
  for (const bad of [` ${SECRET}`, `${SECRET} `, `"${SECRET}"`, `'${SECRET}'`,
                     `\t${SECRET}\n`,
                     ...pythonOnly.map((ch) => SECRET + ch),
                     // Și un sfârșit de linie ÎNĂUNTRU: `secrets.env` e un
                     // format pe linii, deci serverul ar semna doar prefixul.
                     `${SECRET.slice(0, 32)}\n${SECRET.slice(32)}`]) {
    const checked = checkSecretShape(bad);
    assert.equal(checked.ok, false, `${JSON.stringify(bad.slice(0, 4))}… a fost acceptat`);
    // Mesajul spune ce e în neregulă cu forma și NU conține valoarea.
    assert.ok(!(checked as { detail: string }).detail.includes(SECRET),
              "mesajul de refuz conține secretul");
    probed++;
  }
  assert.equal(probed, 11, "nu s-au probat toate formele");

  // Iar detectorul chiar oglindește parserul serverului.
  assert.equal(serverSecretForm(`  "${SECRET}"  `), SECRET);
  assert.equal(serverSecretForm(`"${SECRET}`), `"${SECRET}`, "o ghilimea singură nu se taie");
});

test("un secret prea scurt sau gol e refuzat, fără să apară în mesaj", () => {
  const short = "a".repeat(MIN_SHIP_SECRET_LENGTH - 1);
  const checked = checkSecretShape(short);
  assert.equal(checked.ok, false);
  assert.ok(!(checked as { detail: string }).detail.includes(short));
  assert.equal(checkSecretShape("").ok, false);
  assert.equal(checkSecretShape("a".repeat(MIN_SHIP_SECRET_LENGTH)).ok, true);
});

// ---------------------------------------------------------------------------
// De unde vine secretul
// ---------------------------------------------------------------------------
test("secretul vine din mediu sau de la intrare, NICIODATĂ din argv", async () => {
  const fromEnv = await readShipSecret({ env: { [SHIP_SECRET_ENV]: SECRET } });
  assert.deepEqual(fromEnv, { ok: true, raw: SECRET, from: "env" });

  // Conducta: terminatorul de linie e ÎNCADRARE și se taie; restul rămâne, ca
  // `checkSecretShape` să-l poată refuza.
  const piped = await readShipSecret({
    env: {}, stdin: Readable.from([`${SECRET}\n`]) as never });
  assert.deepEqual(piped, { ok: true, raw: SECRET, from: "stdin" });

  const crlf = await readShipSecret({
    env: {}, stdin: Readable.from([`${SECRET}\r\n`]) as never });
  assert.equal(crlf.ok && crlf.raw, SECRET, "CRLF-ul unei conducte de pe Windows nu s-a tăiat");

  // Spațiul dinaintea terminatorului NU se taie — altfel ar fi normalizare
  // tăcută, iar serverul ar semna cu altceva.
  const padded = await readShipSecret({
    env: {}, stdin: Readable.from([` ${SECRET}\n`]) as never });
  assert.equal(padded.ok && padded.raw, ` ${SECRET}`);
  assert.equal(checkSecretShape((padded as { raw: string }).raw).ok, false);
});

test("o variabilă setată la GOL nu cade pe altă cale, e refuzată ca goală", async () => {
  // Cazul obișnuit dintr-un `export SENTINEL_SHIP_SECRET=$(...)` care a eșuat.
  // Căderea pe prompt ar face-o să pară că n-a fost setată niciodată.
  //
  // Intrarea se dă explicit, goală: fără ea, o implementare care sare peste
  // variabila goală ar ajunge la `process.stdin` și testul ar ATÂRNA în loc să
  // pice — iar un test care atârnă e un test care se scoate din suită.
  const read = await readShipSecret({
    env: { [SHIP_SECRET_ENV]: "" }, stdin: Readable.from([]) as never });
  assert.deepEqual(read, { ok: true, raw: "", from: "env" });
  assert.equal(checkSecretShape("").ok, false);
});

test("fără mediu, fără terminal și fără conductă: eroare, nu presupunere", async () => {
  const read = await readShipSecret({ env: {}, stdin: Readable.from([]) as never });
  assert.equal(read.ok, false);
  assert.match((read as { detail: string }).detail, /argv/);
});

// ---------------------------------------------------------------------------
// Cine deține fluxul de intrare
// ---------------------------------------------------------------------------
test("un flux are UN cititor, oricâți l-ar cere — altfel octeții se împart",
     async () => {
  // Eșecul pe care îl previne, și e cel care a oprit `npm run user -- create`:
  // două locuri care citeau din același `stdin` cu ascultători proprii. Al
  // doilea nu vedea ce citise primul și nici nu repornea fluxul pe care primul
  // îl oprise. Apartenența e a FLUXULUI tocmai ca să nu se mai poată întâmpla:
  // cine cere de două ori primește același obiect, cu același tampon.
  const stream = new PassThrough() as unknown as InputStream;
  assert.equal(readerFor(stream), readerFor(stream),
               "două cereri au primit două cititoare; fiecare cu tamponul lui, " +
               "deci o valoare deja sosită e vizibilă doar unuia dintre ele");

  (stream as unknown as PassThrough).write("unu\ndoi\n");
  assert.equal(await readerFor(stream).readLine(), "unu");
  assert.equal(await readerFor(stream).readLine(), "doi",
               "restul chunk-ului s-a pierdut între două citiri");
});

test("două citiri deodată de pe același flux sunt REFUZATE, nu împărțite",
     async () => {
  // O împărțire după cine apucă ar face ca valoarea citită să depindă de
  // planificare — adică o parolă care uneori e parolă și uneori e jumătate de
  // parolă, fără nimic care să pice.
  const stream = new PassThrough() as unknown as InputStream;
  const reader = readerFor(stream);
  const first = reader.readLine();
  await assert.rejects(() => reader.readLine(), /două citiri deodată/);
  (stream as unknown as PassThrough).end("valoare\n");
  assert.equal(await first, "valoare");
});

test("argumentele: un secret strecurat ca argument e prins și se cere rotit", async () => {
  const sneaked = parseArgv(["register", A, SECRET]);
  assert.equal(sneaked.ok, false);
  assert.match((sneaked as { detail: string }).detail, /lista de procese.*[Rr]otește/s);

  assert.equal(parseArgv(["register", A]).ok, true);
  assert.deepEqual(parseArgv(["register", A, "--label", "web-1"]),
                   { ok: true, command: "register", id: A, label: "web-1" });
  assert.equal(parseArgv(["rotate", A, "--label", "x"]).ok, false, "--label la rotate");
  assert.equal(parseArgv(["register", A, "--lable", "x"]).ok, false, "flag scris greșit");
  assert.equal(parseArgv(["list", A]).ok, false, "`list` nu ia argumente");
  assert.equal(parseArgv(["sterge", A]).ok, false, "comandă necunoscută");
  assert.equal(parseArgv([]).ok, false);
});

// ---------------------------------------------------------------------------
// Sigilarea: proba care contează
// ---------------------------------------------------------------------------
test("ce sigilează instrumentul se deschide pe DRUMUL RUTEI", async () => {
  // ESTE proba pentru care există sarcina asta. Nu două funcții testate separat
  // care se presupun compatibile: `lookupInstanceKey` e chiar funcția pe care o
  // cheamă `app/api/sentinel/sync/route.ts`. Dacă AAD-ul, coloana sau secretul
  // principal diferă între instrument și aplicație, se vede aici.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  const result = await registerInstance(dbOf(server), A, SECRET, box, "web-1");
  assert.deepEqual(result, { ok: true, action: "registered" });

  // Prin drumul rutei, cu O ALTĂ instanță de SecretBox — ca proba să nu treacă
  // pe vreo stare păstrată în obiect.
  const found = await lookupInstanceKey(dbOf(server), A, new SecretBox(MASTER));
  assert.deepEqual(found, { ok: true, secret: SECRET });

  // Și chiar în coloana cifrată, nu în alta: textul în clar nu apare niciunde
  // în rând.
  const row = server.rows.get(A)!;
  assert.equal(row.label, "web-1");
  assert.equal(row.enabled, 1);
  assert.ok(String(row.ship_secret_enc).startsWith("sag1."), String(row.ship_secret_enc));
  assert.ok(!JSON.stringify(row).includes(SECRET), "secretul în clar e în rând");
});

test("un sigiliu al instanței A pus pe rândul lui B NU se deschide", async () => {
  // Proprietatea pentru care există AAD, verificată prin drumul întreg: AAD-ul
  // e `<versiune>|<instance_id>|<coloană>` (`lib/crypto.ts`), deci cine poate
  // scrie în bază nu poate muta cheia lui A pe rândul lui B ca să semneze în
  // numele lui. Fără asta, „root pe A nu poate fabrica date pentru B" — motivul
  // pentru care cheile sunt per instanță (`shipper.py:7-10`) — s-ar pierde fără
  // ca nimic să pară stricat.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);
  await registerInstance(dbOf(server), B, OTHER_SECRET, box);

  // Atacul: blobul lui A, copiat peste rândul lui B.
  const stolen = server.rows.get(A)!.ship_secret_enc;
  server.rows.set(B, { ...server.rows.get(B)!, ship_secret_enc: stolen });

  const found = await lookupInstanceKey(dbOf(server), B, box);
  assert.deepEqual(found, { ok: false, reason: "unreadable" },
                   "sigiliul lui A s-a deschis pe rândul lui B — AAD-ul nu leagă identitatea");
  // Iar A rămâne intactă: mutarea nu strică originalul.
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: true, secret: SECRET });
});

test("un secret principal diferit face cheia ILIZIBILĂ, nu „instanță necunoscută”", async () => {
  // Cazul real: `SENTINEL_AGGREGATOR_SECRET` rotit după înregistrare. Ruta
  // răspunde 500 „nu sunt configurat", iar `list` trebuie să spună de ce.
  const server = new FakeInstances();
  await registerInstance(dbOf(server), A, SECRET, new SecretBox(MASTER));

  const other = new SecretBox("9".repeat(64));
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, other),
                   { ok: false, reason: "unreadable" });
  assert.equal((await listInstances(dbOf(server), other))[0].key, "unreadable");
});

// ---------------------------------------------------------------------------
// Reînregistrarea
// ---------------------------------------------------------------------------
test("a doua înregistrare NU suprascrie o cheie funcțională", async () => {
  // Cineva rulează comanda din nou fiindcă n-a văzut prima ieșire. Dacă a doua
  // rulare ar rescrie cheia, un server sănătos s-ar opri din expediat, iar
  // simptomul ar apărea la următoarea rundă, fără nicio legătură vizibilă.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  assert.equal((await registerInstance(dbOf(server), A, SECRET, box)).ok, true);
  const sealed = server.rows.get(A)!.ship_secret_enc;

  const again = await registerInstance(dbOf(server), A, OTHER_SECRET, box);
  assert.equal(again.ok, false);
  assert.match((again as { detail: string }).detail, /rotate/);
  assert.equal(server.rows.get(A)!.ship_secret_enc, sealed, "cheia a fost rescrisă");
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box), { ok: true, secret: SECRET });
});

test("cursa dintre SELECT și INSERT cade tot pe cheia unică", async () => {
  // Verificarea prealabilă e pentru MESAJ; garanția e cheia unică din schemă.
  // Aici rândul apare între cele două, ca la două terminale deodată.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  const db = dbOf(server);
  const racing = {
    all: async (sql: string, params?: unknown[]) => {
      const rows = await db.all(sql, params);
      if (sql.startsWith("SELECT instance_id FROM instances")) {
        // Altcineva înregistrează exact acum.
        await registerInstance(db, A, OTHER_SECRET, box);
      }
      return rows;
    },
    run: db.run,
  };
  const result = await registerInstance(racing, A, SECRET, box);
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /rotate/);
});

test("rotirea cere o instanță existentă și schimbă chiar cheia", async () => {
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);

  const missing = await rotateSecret(dbOf(server), A, SECRET, box);
  assert.equal(missing.ok, false);
  assert.match((missing as { detail: string }).detail, /register/);
  assert.equal(server.rows.size, 0, "rotirea a creat o instanță");

  await registerInstance(dbOf(server), A, SECRET, box);
  const rotated = await rotateSecret(dbOf(server), A, OTHER_SECRET, box);
  assert.equal(rotated.ok, true, JSON.stringify(rotated));
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: true, secret: OTHER_SECRET });
  assert.equal(server.rows.get(A)!.ship_secret_set_at, "2026-08-15 10:00:00.000000",
               "momentul rotirii nu s-a scris");
});

test("o instanță OPRITĂ își poate roti cheia, iar răspunsul spune că rămâne oprită", async () => {
  // Rotirea după o compromitere se face pe o instanță deja oprită. A cere
  // pornirea ei ca să poți roti cheia ar fi exact pe dos.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);
  await setEnabled(dbOf(server), A, false, box);

  const rotated = await rotateSecret(dbOf(server), A, OTHER_SECRET, box);
  assert.equal(rotated.ok, true, JSON.stringify(rotated));
  assert.match(String((rotated as { note?: string }).note), /DEZACTIVATĂ/);
  // Cheia nouă e acolo — dovedită prin aceeași funcție, cu politica ignorată —
  // iar ruta o refuză în continuare.
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box, { ignoreDisabled: true }),
                   { ok: true, secret: OTHER_SECRET });
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: false, reason: "disabled" });
});

// ---------------------------------------------------------------------------
// Oprirea și pornirea
// ---------------------------------------------------------------------------
test("`disable` face ruta să refuze, `enable` o face să accepte", async () => {
  // Semantica nu se redefinește aici: e cea din `lib/ship-keys.ts`, iar dovada
  // e chiar întrebarea pe care o pune ruta.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);

  assert.deepEqual(await setEnabled(dbOf(server), A, false, box),
                   { ok: true, action: "disabled" });
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: false, reason: "disabled" });
  // Istoria rămâne: rândul e acolo, cu cheia lui.
  assert.equal(server.rows.get(A)!.ship_secret_enc !== null, true);

  assert.deepEqual(await setEnabled(dbOf(server), A, true, box),
                   { ok: true, action: "enabled" });
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: true, secret: SECRET });
});

test("o scriere care iese cu succes și NU are efect nu se raportează ca reușită", async () => {
  // Tiparul din `CLAUDE.md`, în locul în care contează cel mai mult aici: un
  // `INSERT`/`UPDATE` care nu a aruncat nu dovedește că rândul e acolo și
  // citibil. Raportat ca reușit, operatorul pleacă convins că a înregistrat
  // instanța, pornește expedierea, și abia peste ore vede 500-uri pe care nimic
  // nu le leagă de comanda asta.
  const box = new SecretBox(MASTER);

  const register = await registerInstance(dbOf(new FakeInstances(true)), A, SECRET, box);
  assert.equal(register.ok, false, "înregistrarea fără efect a fost raportată ca reușită");
  assert.match((register as { detail: string }).detail, /citirea înapoi|confirmat/);

  // Rotirea: rândul EXISTĂ, dar scrierea nu prinde. Aici verificarea nu poate
  // spune „unknown" — cheia veche se deschide în continuare —, deci singurul
  // lucru care prinde greșeala e compararea cu secretul cerut.
  const server = new FakeInstances();
  await registerInstance(dbOf(server), A, SECRET, box);
  const rotate = await rotateSecret(dbOf(frozen(server)), A, OTHER_SECRET, box);
  assert.equal(rotate.ok, false, "rotirea fără efect a fost raportată ca reușită");
  assert.match((rotate as { detail: string }).detail, /nu e cel sigilat/);

  const disable = await setEnabled(dbOf(frozen(server)), A, false, box);
  assert.equal(disable.ok, false, "oprirea fără efect a fost raportată ca reușită");
  assert.match((disable as { detail: string }).detail, /confirmat/);

  // Și pornirea, pe o instanță chiar oprită: fără verificare, comanda ar
  // raporta „ingestie pornită" peste o instanță pe care ruta o refuză în
  // continuare cu 401 — iar operatorul ar căuta problema pe server.
  await setEnabled(dbOf(server), A, false, box);
  const enable = await setEnabled(dbOf(frozen(server)), A, true, box);
  assert.equal(enable.ok, false, "pornirea fără efect a fost raportată ca reușită");
  assert.match((enable as { detail: string }).detail, /confirmat/);
});

/** Același dublu, aceleași rânduri, dar scrierile nu mai au efect. */
function frozen(server: FakeInstances): FakeInstances {
  return Object.assign(Object.create(Object.getPrototypeOf(server)), server,
                       { dropWrites: true }) as FakeInstances;
}

test("o rotire care nu se confirmă pune cheia VECHE la loc", async () => {
  // Înainte, mesajul spunea „nu s-a confirmat nimic" — fals: se făcuse ceva, și
  // anume paguba. Cheia funcțională fusese deja înlocuită, iar instanța rămânea
  // moartă până la o a doua rotire reușită, fără ca mesajul s-o spună.
  //
  // `MAX_SEALED_LENGTH` există tocmai fiindcă paguba e ireversibilă; asta e
  // cealaltă jumătate a aceluiași argument.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);

  // Prima scriere a cheii iese „cu succes" și lasă în coloană altceva.
  server.corruptWrites = 1;
  const rotated = await rotateSecret(dbOf(server), A, OTHER_SECRET, box);
  assert.equal(rotated.ok, false);
  assert.match((rotated as { detail: string }).detail, /pusă la loc și verificată/);
  // Faptul, nu mesajul: cheia veche chiar funcționează, pe drumul rutei.
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box), { ok: true, secret: SECRET });
});

test("dacă nici restaurarea nu prinde, mesajul spune că instanța e moartă", async () => {
  // A treia stare, și singura în care operatorul chiar trebuie să acționeze
  // imediat. Confundată cu a doua, ar citi „totul e bine" peste un server care
  // nu mai poate expedia.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);

  server.corruptWrites = 99;
  const rotated = await rotateSecret(dbOf(server), A, OTHER_SECRET, box);
  assert.equal(rotated.ok, false);
  assert.match((rotated as { detail: string }).detail, /NU mai poate autentifica/);
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: false, reason: "unreadable" });
});

test("dacă baza cade la citirea înapoi, mesajul spune ce a rămas în rând", async () => {
  // Fără ramura asta, excepția scapă din `rotateSecret` și operatorul vede doar
  // mesajul driverului: nimic despre starea rândului, deci nu poate ști dacă
  // mai are o cheie funcțională. Nu se restaurează nimic — nu se știe dacă
  // scrierea a prins, iar punerea la loc a cheii vechi ar ANULA o rotire care
  // poate a reușit, exact pe dos față de ce vrei după o compromitere.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box);

  const db = dbOf(server);
  let writes = 0;
  const flaky = {
    all: async (sql: string, params?: unknown[]) => {
      // Cade DOAR la citirea de verificare de după scriere.
      if (writes > 0 && sql.startsWith("SELECT enabled, ship_secret_enc")) {
        throw new Error("Connection lost: The server closed the connection");
      }
      return await db.all(sql, params);
    },
    run: async (sql: string, params?: unknown[]) => { writes++; await db.run(sql, params); },
  };

  const rotated = await rotateSecret(flaky, A, OTHER_SECRET, box);
  assert.equal(rotated.ok, false, "un efect neconfirmat a fost raportat ca reușită");
  assert.match((rotated as { detail: string }).detail, /Nu s-a pierdut nimic/);
  assert.match((rotated as { detail: string }).detail, /rotate/);
  // Și starea chiar e cea descrisă: cheia NOUĂ e în rând, deci o a doua rotire
  // cu aceeași valoare confirmă în loc să strice.
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box),
                   { ok: true, secret: OTHER_SECRET });
  assert.equal((await rotateSecret(dbOf(server), A, OTHER_SECRET, box)).ok, true);
});

test("o înregistrare neconfirmată spune că rândul a rămas, și ce comandă repară", async () => {
  // Rândul EXISTĂ acum, cu o cheie inutilizabilă. Fără propoziția asta, comanda
  // următoare a operatorului ar fi `register` din nou, iar răspunsul „e deja
  // înregistrată" ar părea o contrazicere.
  const server = new FakeInstances(true);
  const registered = await registerInstance(dbOf(server), A, SECRET, new SecretBox(MASTER));
  assert.equal(registered.ok, false);
  // Amândouă: CE stare a rămas în bază, și CE comandă o repară. Doar a doua ar
  // fi trecut și peste un mesaj care nu spune că rândul există.
  assert.match((registered as { detail: string }).detail, /Rândul a rămas creat/);
  assert.match((registered as { detail: string }).detail, /rotate/);
});

test("un secret care nu încape în coloană e refuzat ÎNAINTE de scriere", async () => {
  // La rotire paguba ar fi ireversibilă: MariaDB taie jetonul la 255 de
  // caractere, cheia funcțională dispare, iar cea scrisă nu se mai deschide
  // niciodată. Citirea înapoi ar raporta corect eșecul — dar după ce cheia bună
  // s-a dus. Deci se refuză înainte să atingă baza.
  //
  // Măsurat cu `SecretBox`: un secret de 64 de caractere dă un jeton de 131,
  // unul de 128 dă 216, unul de 256 dă 387.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  const huge = "a".repeat(256);

  const registered = await registerInstance(dbOf(server), A, huge, box);
  assert.equal(registered.ok, false);
  assert.match((registered as { detail: string }).detail, /prea lung.*Nimic nu a fost scris/s);
  assert.equal(server.rows.size, 0, "s-a scris un rând pentru un secret care nu încape");

  // Și mai ales: o rotire refuzată lasă cheia veche intactă.
  await registerInstance(dbOf(server), A, SECRET, box);
  const rotated = await rotateSecret(dbOf(server), A, huge, box);
  assert.equal(rotated.ok, false);
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, box), { ok: true, secret: SECRET },
                   "cheia veche a fost distrusă de o rotire refuzată");
});

test("oprirea unei instanțe neînregistrate e o eroare, nu o operație nulă", async () => {
  const server = new FakeInstances();
  const result = await setEnabled(dbOf(server), A, false, new SecretBox(MASTER));
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /register/);
});

// ---------------------------------------------------------------------------
// Listarea
// ---------------------------------------------------------------------------
test("`list` nu scoate niciodată secretul din funcție", async () => {
  // Un `SELECT *` întors ca atare ar fi ajuns pe ecran, în scrollback și în
  // tichet. Din textul cifrat rămâne o singură etichetă.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  await registerInstance(dbOf(server), A, SECRET, box, "web-1");
  await registerInstance(dbOf(server), B, OTHER_SECRET, box);
  await setEnabled(dbOf(server), B, false, box);

  const rows = await listInstances(dbOf(server), box);
  const dumped = JSON.stringify(rows);
  assert.ok(!dumped.includes(SECRET), "secretul în clar e în listare");
  assert.ok(!dumped.includes(OTHER_SECRET), "secretul în clar e în listare");
  assert.ok(!dumped.includes("sag1."), "textul cifrat e în listare");

  assert.deepEqual(rows.map((r) => [r.instanceId, r.enabled, r.key]),
                   [[A, true, "ok"], [B, false, "ok"]]);
  assert.equal(rows[0].label, "web-1");
});

test("o instanță fără cheie e „missing”, nu „ok”", async () => {
  // Starea în care ajunge o instanță creată de mână, direct în SQL. Ruta
  // răspunde 500 pentru ea; listarea trebuie să spună de ce.
  const server = new FakeInstances();
  server.rows.set(A, { instance_id: A, label: null, enabled: 1, ship_secret_enc: null,
                       ship_secret_set_at: null, first_seen_at: null,
                       last_batch_at: null, last_batch_seq: null });
  const rows = await listInstances(dbOf(server), new SecretBox(MASTER));
  assert.equal(rows[0].key, "missing");
  assert.deepEqual(await lookupInstanceKey(dbOf(server), A, new SecretBox(MASTER)),
                   { ok: false, reason: "unconfigured" });
});

// ---------------------------------------------------------------------------
// Identitatea
// ---------------------------------------------------------------------------
test("identitatea acceptată e EXACT cea din rută și de la martor", async () => {
  // Al treilea capăt al aceleiași reguli. O identitate pe care instrumentul o
  // acceptă și ruta o refuză înseamnă o instanță înregistrată care primește 401
  // la fiecare lot, iar identitatea nu se poate schimba: e scrisă în
  // `/etc/sentinel/instance_id`.
  const server = new FakeInstances();
  const box = new SecretBox(MASTER);
  let probed = 0;
  for (const bad of ["__proto__", "-incepe-cu-liniuta", "a".repeat(65), "are spatiu", ""]) {
    const result = await registerInstance(dbOf(server), bad, SECRET, box);
    assert.equal(result.ok, false, `${JSON.stringify(bad)} a fost înregistrat`);
    // Mesajul nu conține identificatorul — vine din linia de comandă și ajunge
    // în tichete.
    assert.ok(!(result as { detail: string }).detail.includes(bad) || bad === "",
              "mesajul conține identificatorul");
    probed++;
  }
  assert.equal(probed, 5, "nu s-au probat toate formele");
  assert.equal(server.rows.size, 0, "s-a scris un rând pentru o identitate refuzată");

  // Iar forma reală a unei identități de gazdă (`openssl rand -hex 16`) trece.
  assert.equal((await registerInstance(dbOf(server), "0".repeat(32), SECRET, box)).ok, true);
});
