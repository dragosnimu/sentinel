/**
 * Unealta de creare de cont: ce refuză, ce scrie, și primul login capăt-la-capăt.
 *
 * ## Ce se strică fără ea
 *
 * Totul. Până la piesa asta nu exista NICIO cale prin care un rând să ajungă în
 * `users`, deci nimeni nu se putea autentifica, deci Argon2id, TOTP, CSRF, cele
 * trei limitatoare și sesiunile cu jeton rotit nu fuseseră niciodată parcurse de
 * nimeni de la un capăt la altul. Testul „un cont creat de unealtă trece de
 * `/login` ȘI de `/totp`" de mai jos e prima dovadă că lanțul ăla se închide.
 *
 * ## Eșecurile pe care le previn testele, pe rând
 *
 *   * **o parolă peste plafon, stocată.** `hashPassword` aplică
 *     `MAX_PASSWORD_LENGTH`; `verifyPassword` NU. O unealtă care ar scrie hashul
 *     pe lângă `hashPassword` ar putea stoca o parolă de 2000 de caractere, iar
 *     `lib/auth/login.ts` ar refuza-o la fiecare autentificare ÎNAINTE de orice
 *     verificare — un 401 permanent, pe un cont cu parola corectă, fără nimic în
 *     jurnal care să spună de ce. Starea aia e inaccesibilă azi tocmai fiindcă
 *     nu există altă cale de creare de cont, iar unealta e cea care o creează;
 *   * **o parolă în `argv`.** Se vede în lista de procese a găzduirii partajate
 *     și rămâne în istoricul shellului. Refuzată zgomotos, nu ignorată: valoarea
 *     e deja publicată în clipa în care programul o vede;
 *   * **o înrolare neconfirmată raportată ca reușită.** Un cont care cere un cod
 *     pe care nu-l poate produce nimeni e un cont blocat definitiv, pe o
 *     găzduire fără altă ușă;
 *   * **un drept dat unei instanțe care nu există.** Comanda ar raporta succes,
 *     iar omul ar vedea în continuare un panou gol — un eșec tăcut.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as instancesGet } from "../app/api/panel/instances/route";
import {
  confirmEnrolment, createAccount, dropTotp, enrollTotp, grantInstance,
  listAccounts, parseUserArgv, readLine, readNewPassword, revokeInstance,
  setPassword,
} from "../lib/auth/accounts";
import { MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH } from "../lib/auth/password";
import { codeForCounter, counterAt } from "../lib/auth/totp";
import {
  PASSWORD, SESSION_SECRET, captureError, captureWarn, completeLogin,
  forgetAuthServer, getRequest, useAuthServer,
} from "./auth-routes-harness";
import { readShipped, shippedFiles } from "./shipped-files";
import { captureStderr, fakeStdin } from "./stdin-harness";
import type { Fixture } from "./auth-routes-harness";

const HANDLERS = { loginGet, loginPost, totpGet, totpPost };
const NEW_USER = "ana";
const NEW_PASSWORD = "parola-noua-de-test";

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

async function create(
  over: { username?: string; role?: string; password?: string; enrolTotp?: boolean } = {},
) {
  return await createAccount(fixture.db, {
    username: over.username ?? NEW_USER,
    role: over.role ?? "owner",
    password: over.password ?? NEW_PASSWORD,
    sessionSecret: SESSION_SECRET,
    // Implicitul schelei rămâne CU înrolare, ca testele scrise înainte de 19
    // august 2026 să probeze în continuare exact ce probau. Calea fără al doilea
    // factor se cere explicit, în testele ei.
    enrolTotp: over.enrolTotp ?? true,
  });
}

/** Rândurile din `users` în afară de contul pe care îl pune schela. */
function created() {
  return fixture.db.users.filter((row) => row.id !== 1);
}

/** Un cod valid ACUM. Ceasul real: `verifyCode` citește `Date.now()`. */
function currentCode(secret: string): string {
  return codeForCounter(secret, counterAt(Date.now() / 1000));
}

/**
 * Un cod din fereastra DE DINAINTE — încă acceptat (`TOTP_VALID_WINDOW = 1`).
 *
 * Confirmarea înrolării CONSUMĂ contorul codului cu care s-a făcut, iar
 * `consumeTotpCounter` cere strict mai mare. Deci un cont confirmat cu codul de
 * ACUM nu se poate autentifica până la fereastra următoare — purtare corectă,
 * și probată separat mai jos. Pentru probele care vor să treacă mai departe,
 * confirmarea se face cu codul dinainte, exact cum se întâmplă când omul îl
 * tastează cu câteva secunde înainte să se autentifice.
 */
function previousCode(secret: string): string {
  return codeForCounter(secret, counterAt(Date.now() / 1000) - 1);
}

// ---------------------------------------------------------------------------
// Linia de comandă
// ---------------------------------------------------------------------------
test("o parolă dată în `argv` e REFUZATĂ, nu ignorată", () => {
  // Ignorarea ar lăsa pe cineva să creadă că n-a pățit nimic. Valoarea e deja în
  // `ps` și în `~/.bash_history` în momentul în care programul pornește.
  for (const argv of [
    ["create", "ana", "--role", "owner", "--password", "ceva"],
    ["create", "ana", "--role", "owner", "--password=ceva"],
    ["create", "ana", "--pass=ceva"],
    ["create", "ana", "--pw", "ceva"],
    ["create", "ana", "--parola", "ceva"],
    ["create", "ana", "--secret=ceva"],
  ]) {
    const parsed = parseUserArgv(argv);
    assert.equal(parsed.ok, false, `linia a fost acceptată: ${argv.join(" ")}`);
    assert.match((parsed as { detail: string }).detail, /lista de procese/,
                 "refuzul nu spune DE CE valoarea e deja compromisă");
  }
});

test("`create` cere un rol explicit; niciun implicit nu e o ghicire bună", () => {
  // Un implicit `viewer` ar face primul cont al unei instalări inutil; unul
  // `owner` ar da rolul cel mai mare unei comenzi tastate în grabă.
  assert.equal(parseUserArgv(["create", "ana"]).ok, false);
  assert.deepEqual(parseUserArgv(["create", "ana", "--role", "owner"]),
                   { ok: true, command: "create", username: "ana", role: "owner",
                     totp: false },
                   "implicitul s-a mutat: fără `--totp` contul are un singur factor");
  assert.deepEqual(parseUserArgv(["create", "ana", "--role", "owner", "--totp"]),
                   { ok: true, command: "create", username: "ana", role: "owner",
                     totp: true },
                   "`--totp` nu a pornit înrolarea");
  assert.equal(parseUserArgv(["create", "ana", "--role", "owner", "--totp=nu"]).ok,
               false,
               "`--totp=nu` a fost acceptat, deci cineva poate crede că a oprit ceva");
  assert.equal(parseUserArgv(["create", "ana", "--role", "root"]).ok, false,
               "un rol din afara vocabularului a fost acceptat");
});

test("`grant` și `revoke` cer amândouă argumentele; `list` nu cere niciunul", () => {
  assert.deepEqual(parseUserArgv(["grant", "ana", "prod-a"]),
                   { ok: true, command: "grant", username: "ana",
                     instanceId: "prod-a", role: "viewer" });
  assert.deepEqual(parseUserArgv(["grant", "ana", "prod-a", "--role=operator"]),
                   { ok: true, command: "grant", username: "ana",
                     instanceId: "prod-a", role: "operator" });
  assert.equal(parseUserArgv(["grant", "ana"]).ok, false);
  assert.equal(parseUserArgv(["revoke", "ana"]).ok, false);
  assert.deepEqual(parseUserArgv(["list"]), { ok: true, command: "list" });
  assert.equal(parseUserArgv([]).ok, false);
  assert.equal(parseUserArgv(["ceva"]).ok, false);
});

test("parola vine dintr-o conductă, o linie, fără terminatorul ei", async () => {
  // Forma bună: `pass show panou | npm run user -- create ana --role owner`.
  // Valoarea nu ajunge nici în `argv`, nici în mediu.
  const read = await readNewPassword({
    stdin: Readable.from(["parola-dintr-o-conducta\n"]) as never,
  });
  assert.deepEqual(read, { ok: true, password: "parola-dintr-o-conducta" });
});

test("fără terminal și fără conductă, unealta spune de unde AR fi luat parola",
     async () => {
  const read = await readNewPassword({ stdin: Readable.from([]) as never });
  assert.equal(read.ok, false);
  assert.match((read as { detail: string }).detail, /conductă/);
});

// ---------------------------------------------------------------------------
// Cele DOUĂ citiri ale lui `create`: parola, apoi codul de confirmare
// ---------------------------------------------------------------------------
// Falsul terminal e în `tests/stdin-harness.ts`, nu aici: îl folosește și
// `tests/secret-input.test.ts`, iar două copii ale lui s-ar putea desincroniza
// exact acolo unde contează (una fără `setRawMode` face probele de prompt ascuns
// să treacă pe un flux care nu e terminal).

test("la TASTATURĂ, `create` citește parola ascunsă ȘI codul de după ea", async () => {
  // Eșecul pe care îl previne, exact cum arăta: promptul ascuns oprea fluxul la
  // sfârșit (`stdin.pause()`), iar citirea codului își punea ascultătorul fără
  // să repornească nimic — și Node nu reia un flux oprit explicit. Deci unealta
  // afișa secretul care „se afișează O SINGURĂ DATĂ" și apoi ATÂRNA. Contul
  // rămânea fără al doilea factor, adică nimeni nu se putea autentifica pe
  // panou — chiar scopul comenzii.
  const { stream, rawModes } = fakeStdin(true);
  const stderr = captureStderr();
  // Ca la tastare: Enter e `\r` în mod brut, iar codul vine pe o linie normală,
  // după ce promptul ascuns a ieșit din modul brut.
  stream.write("parola123\r");
  stream.write("parola123\r");
  stream.write("123456\n");

  const password = await readNewPassword({ stdin: stream as never, stderr });
  assert.deepEqual(password, { ok: true, password: "parola123" });

  const code = await readLine({ stdin: stream as never });
  assert.equal(code, "123456",
               "codul de confirmare nu se citește după promptul ascuns: cele două " +
               "citiri nu împart fluxul, deci `create` nu poate confirma niciodată " +
               "înrolarea");

  assert.deepEqual(rawModes, [true, false, true, false],
                   "modul brut nu s-a pus și scos la fiecare prompt ascuns; " +
                   "lăsat pornit, terminalul operatorului rămâne fără ecou");
  assert.ok(!stderr.text.includes("parola123"),
            "parola tastată a ajuns pe ecran, deci și în scrollback");
  assert.match(stderr.text, /Parolă \(nu se afișează\)/);
  assert.match(stderr.text, /Repetă parola/);
});

test("printr-o CONDUCTĂ, `create` citește parola, apoi codul din aceeași conductă",
     async () => {
  // Cealaltă jumătate a aceluiași defect, care nu atârna dar pierdea: cititorul
  // de linie arunca restul chunk-ului de după `\n`, iar parola și codul sosesc
  // în același chunk. Codul dispărea, iar `create` raporta „înrolare
  // neconfirmată" pentru o valoare pe care chiar o primise.
  const { stream } = fakeStdin(false);
  const stderr = captureStderr();
  stream.write("parola123\n123456\n");
  stream.end();

  const password = await readNewPassword({ stdin: stream as never, stderr });
  assert.deepEqual(password, { ok: true, password: "parola123" });
  assert.equal(await readLine({ stdin: stream as never }), "123456",
               "ce a sosit odată cu parola s-a pierdut: octeții deja citiți de pe " +
               "flux nu se mai pot cere a doua oară de nicăieri");
  assert.equal(stderr.text, "",
               "pe conductă nu se scrie nicio invitație; ar polua ieșirea unui " +
               "script fără să întrebe pe nimeni nimic");
});

test("o conductă care se termină odată cu parola spune că nu mai are de unde citi",
     async () => {
  // `pass show panou | npm run user -- create ana --role owner` — chiar exemplul
  // din USAGE. Codul de confirmare se poate produce abia după ce se afișează
  // secretul, deci nu are cum să vină din aceeași conductă. Ce contează e ca
  // starea asta să fie DEOSEBITĂ de un cod greșit: `null`, nu linie goală. Pe
  // linie goală, `bin/user.ts` ar mai încerca de trei ori și ar spune
  // operatorului că a tastat greșit un cod pe care nu l-a tastat niciodată.
  const { stream } = fakeStdin(false);
  const stderr = captureStderr();
  stream.end("parola123\n");

  assert.deepEqual(await readNewPassword({ stdin: stream as never, stderr }),
                   { ok: true, password: "parola123" });
  assert.equal(await readLine({ stdin: stream as never }), null,
               "capătul conductei s-a întors ca linie goală, deci `create` ar cere " +
               "de trei ori un cod care nu poate veni");
});

// ---------------------------------------------------------------------------
// Ce refuză înainte de a scrie ceva
// ---------------------------------------------------------------------------
test("o parolă PESTE plafon e refuzată, și nu se scrie niciun rând", async () => {
  // Criteriul măsurat al piesei. Ordinea din `createAccount` e cea care îl ține:
  // hashul se calculează ÎNAINTE de `INSERT`, deci un refuz de politică nu lasă
  // în urmă nici măcar un cont pe jumătate făcut.
  const result = await create({ password: "x".repeat(MAX_PASSWORD_LENGTH + 1) });
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /cel mult/);
  assert.deepEqual(created(), [], "s-a scris un rând pentru o parolă refuzată");
});

test("o parolă SUB plafon e refuzată la fel", async () => {
  const result = await create({ password: "x".repeat(MIN_PASSWORD_LENGTH - 1) });
  assert.equal(result.ok, false);
  assert.deepEqual(created(), []);
});

test("exact la plafon se acceptă — marginea nu e mutată cu unu", async () => {
  // Fără proba asta, un `>=` scris din greșeală în loc de `>` ar refuza o parolă
  // legitimă, iar nimeni n-ar observa că plafonul e cu unul mai jos.
  const result = await create({ password: "x".repeat(MAX_PASSWORD_LENGTH) });
  assert.equal(result.ok, true, (result as { detail?: string }).detail);
});

test("un nume care nu poate exista în coloană e refuzat de cod, nu de bază",
     async () => {
  // `users.username` e `ascii`. Sub un `sql_mode` nestrict, MariaDB ar înlocui
  // diacriticele cu `?` și ar crea un cont pe care nimeni nu-l mai poate tasta —
  // cu o cheie unică peste el, deci al doilea om cu diacritice n-ar mai putea fi
  // creat deloc.
  for (const username of ["ană", "cu spațiu", "", "   "]) {
    const result = await create({ username });
    assert.equal(result.ok, false, `numele „${username}” a fost acceptat`);
  }
  assert.deepEqual(created(), []);
});

test("un cont care există deja nu se rescrie", async () => {
  assert.equal((await create()).ok, true);
  const again = await create({ password: "cu-totul-alta-parola" });
  assert.equal(again.ok, false);
  assert.match((again as { detail: string }).detail, /există deja/);
  assert.equal(created().length, 1, "s-a scris un al doilea rând cu același nume");
});

test("un rol din afara vocabularului e refuzat înainte de orice scriere", async () => {
  const result = await create({ role: "root" });
  assert.equal(result.ok, false);
  assert.deepEqual(created(), []);
});

// ---------------------------------------------------------------------------
// Ce scrie, când acceptă
// ---------------------------------------------------------------------------
test("contul creat are hash Argon2id PHC și secretul TOTP CIFRAT, neconfirmat",
     async () => {
  const result = await create();
  assert.equal(result.ok, true, (result as { detail?: string }).detail);
  const enrolment = (result as { value: { secret: string; uri: string;
                                          userId: number } }).value;

  const row = created()[0];
  assert.match(row.password_hash, /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$/,
               "hashul nu are forma pe care `login.ts` o poate citi; " +
               "autentificarea ar eșua cu „parolă greșită” la nesfârșit");
  assert.ok(!row.password_hash.includes(NEW_PASSWORD),
            "parola în clar a ajuns în coloană");

  assert.ok(row.totp_secret_enc, "contul nu are secret TOTP");
  assert.ok(!(row.totp_secret_enc as string).includes(enrolment.secret),
            "secretul TOTP e stocat în clar; un dump al bazei ar da al doilea " +
            "factor al tuturor");
  assert.equal(row.totp_confirmed_at, null,
               "înrolarea e „confirmată” fără ca nimeni să fi produs un cod");
  assert.match(enrolment.uri, /^otpauth:\/\/totp\//);
  assert.ok(enrolment.uri.includes(enrolment.secret));
});

test("un cont neconfirmat NU se poate autentifica, oricât de corectă e parola",
     async () => {
  // Jumătatea care face confirmarea obligatorie: fără ea, „contul e creat" ar
  // părea suficient, iar operatorul ar descoperi abia la primul login că nu e.
  const result = await create();
  assert.equal(result.ok, true);
  await assert.rejects(
    () => completeLogin(HANDLERS, {
      username: NEW_USER, password: NEW_PASSWORD,
      totpSecret: (result as { value: { secret: string } }).value.secret,
    }),
    /etapa parolei a răspuns 403/,
    "un cont fără al doilea factor confirmat a trecut de etapa parolei");
});

test("confirmarea cere un cod ADEVĂRAT, și consumă contorul", async () => {
  const enrolment = (await create() as { value: { userId: number; secret: string } })
    .value;

  assert.equal(await confirmEnrolment(fixture.db, enrolment.userId, enrolment.secret,
                                      "000000"),
               false, "un cod inventat a confirmat înrolarea");
  assert.equal(created()[0].totp_confirmed_at, null);

  const code = currentCode(enrolment.secret);
  assert.equal(await confirmEnrolment(fixture.db, enrolment.userId, enrolment.secret,
                                      code),
               true);
  assert.notEqual(created()[0].totp_confirmed_at, null);
  assert.notEqual(created()[0].totp_last_counter, null,
                  "contorul nu s-a consemnat, deci chiar codul de înrolare ar mai " +
                  "merge o dată în aceeași fereastră de 30 s");
});

test("reînrolarea schimbă secretul, pierde confirmarea și revocă sesiunile",
     async () => {
  // O reînrolare înseamnă de obicei că dispozitivul vechi s-a pierdut. Sesiunile
  // deschise cu factorul vechi n-au voie să-i supraviețuiască, iar confirmarea
  // veche ar cere un cod pe care nu-l mai poate produce nimeni.
  const first = (await create() as { value: { userId: number; secret: string } }).value;
  assert.equal(await confirmEnrolment(fixture.db, first.userId, first.secret,
                                      previousCode(first.secret)),
               true);
  await completeLogin(HANDLERS, { username: NEW_USER, password: NEW_PASSWORD,
                                  totpSecret: first.secret });
  const live = fixture.db.sessions.filter((row) => row.user_id === first.userId
                                                   && row.revoked_at === null);
  assert.ok(live.length >= 1, "pregătirea nu a lăsat nicio sesiune vie");

  const again = await enrollTotp(fixture.db, NEW_USER, SESSION_SECRET);
  assert.equal(again.ok, true);
  const second = (again as { value: { secret: string; revokedSessions: number } }).value;
  assert.notEqual(second.secret, first.secret, "reînrolarea a dat același secret");
  assert.equal(created()[0].totp_confirmed_at, null);
  assert.ok(second.revokedSessions >= 1, "sesiunile vechi au supraviețuit");
});

// ---------------------------------------------------------------------------
// Primul login capăt-la-capăt din tot proiectul
// ---------------------------------------------------------------------------
test("un cont creat de unealtă trece de `/login` ȘI de `/totp`, cu un cod " +
     "calculat din secretul înrolat", async () => {
  // Asta e proba pe care nimeni n-o putea face până acum: nu „ruta răspunde
  // 303", ci „un cont care există doar fiindcă unealta l-a creat ajunge la o
  // sesiune întreagă, prin ambele etape, cu parola care i s-a pus și cu un cod
  // produs din secretul care i s-a înrolat".
  const enrolment = (await create() as { value: { userId: number; secret: string } })
    .value;
  assert.equal(await confirmEnrolment(fixture.db, enrolment.userId, enrolment.secret,
                                      previousCode(enrolment.secret)),
               true);

  const token = await completeLogin(HANDLERS, {
    username: NEW_USER, password: NEW_PASSWORD, totpSecret: enrolment.secret,
  });

  // Sesiunea e ÎNTREAGĂ — nu una în așteptarea celui de-al doilea factor.
  const session = fixture.db.sessions.find(
    (row) => row.user_id === enrolment.userId && row.revoked_at === null);
  assert.ok(session, "nu s-a creat nicio sesiune");
  assert.equal(session.pending_totp, 0, "sesiunea a rămas în așteptarea TOTP");
  assert.ok(token.length > 0);
});

test("chiar codul cu care s-a confirmat înrolarea NU mai deschide o sesiune",
     async () => {
  // Lanțul anti-reluare se închide peste unealtă ȘI peste rute: contorul scris
  // la confirmare e același pe care îl consumă `/totp`. Fără el, cine citește
  // codul peste umărul operatorului în timpul înrolării îl poate folosi în
  // aceeași fereastră de 30 s. Prețul, real și acceptat: cine se autentifică
  // imediat după înrolare primește „Cod deja folosit" și așteaptă codul următor.
  const enrolment = (await create() as { value: { userId: number; secret: string } })
    .value;
  const code = currentCode(enrolment.secret);
  assert.equal(await confirmEnrolment(fixture.db, enrolment.userId, enrolment.secret,
                                      code),
               true);

  await assert.rejects(
    () => completeLogin(HANDLERS, {
      username: NEW_USER, password: NEW_PASSWORD, totpSecret: enrolment.secret, code,
    }),
    /etapa codului a răspuns 401/,
    "codul consumat la înrolare a deschis totuși o sesiune");
});

test("contul proaspăt creat vede ZERO instanțe, deși ele există", async () => {
  // Prin EFECT, pe un cont chiar creat de unealtă, printr-o rută reală: „un
  // utilizator nou primește zero instanțe, nu toate".
  fixture.db.addInstance("prod-a");
  fixture.db.addInstance("prod-b");
  const enrolment = (await create() as { value: { userId: number; secret: string } })
    .value;
  await confirmEnrolment(fixture.db, enrolment.userId, enrolment.secret,
                         previousCode(enrolment.secret));
  const token = await completeLogin(HANDLERS, {
    username: NEW_USER, password: NEW_PASSWORD, totpSecret: enrolment.secret,
  });
  const cookies = { sentinel_session: token };

  const before = await instancesGet(getRequest("/api/panel/instances", { cookies }));
  assert.deepEqual(JSON.parse(await before.text()), { instances: [] });

  // Și abia după `grant` vede una. Fără jumătatea asta, testul ar trece și dacă
  // ruta n-ar întoarce niciodată nimic.
  assert.equal((await grantInstance(fixture.db, NEW_USER, "prod-a", "viewer")).ok,
               true);
  const after = await instancesGet(getRequest("/api/panel/instances", { cookies }));
  const seen = JSON.parse(await after.text()) as
    { instances: { instanceId: string }[] };
  assert.deepEqual(seen.instances.map((row) => row.instanceId), ["prod-a"]);
});

// ---------------------------------------------------------------------------
// Drepturile
// ---------------------------------------------------------------------------
test("un drept pe o instanță NEÎNREGISTRATĂ e refuzat", async () => {
  // Fără verificarea asta, o greșeală de tastare ar scrie un rând care nu se
  // potrivește cu nimic: comanda ar raporta succes, iar omul ar vedea în
  // continuare un panou gol.
  await create();
  const result = await grantInstance(fixture.db, NEW_USER, "prod-typo", "viewer");
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /nu e înregistrată/);
  assert.deepEqual(fixture.db.userInstances, []);
});

test("al doilea `grant` schimbă rolul, nu adaugă un al doilea rând", async () => {
  // `uk_user_instances` ar refuza al doilea rând pe gazdă (ERROR 1062), iar
  // dublul NU modelează cheia — deci proprietatea asta se ține în cod, aici.
  fixture.db.addInstance("prod-a");
  await create();
  assert.equal((await grantInstance(fixture.db, NEW_USER, "prod-a", "viewer")).ok, true);
  const second = await grantInstance(fixture.db, NEW_USER, "prod-a", "operator");
  assert.equal(second.ok, true);
  assert.equal((second as { value: { created: boolean } }).value.created, false);
  assert.equal(fixture.db.userInstances.length, 1);
  assert.equal(fixture.db.userInstances[0].role, "operator");
});

test("un drept inexistent nu se poate retrage — și se spune", async () => {
  await create();
  const result = await revokeInstance(fixture.db, NEW_USER, "prod-a");
  assert.equal(result.ok, false);
  assert.match((result as { detail: string }).detail, /niciun drept/);
});

test("inventarul spune cine e neînrolat și cine nu vede nimic", async () => {
  // Cele două stări care se citesc greșit dacă nu sunt arătate: un cont fără al
  // doilea factor NU se poate autentifica deloc, iar unul fără instanțe vede un
  // panou gol. Amândouă arată, dintr-o listă de conturi, ca un cont sănătos.
  fixture.db.addInstance("prod-a");
  await create();
  await grantInstance(fixture.db, NEW_USER, "prod-a", "operator");

  const rows = await listAccounts(fixture.db);
  const ana = rows.find((row) => row.username === NEW_USER);
  assert.ok(ana);
  assert.equal(ana.totpConfirmed, false);
  assert.deepEqual(ana.instances, [{ instanceId: "prod-a", role: "operator" }]);

  const operator = rows.find((row) => row.username === "operator");
  assert.ok(operator);
  assert.equal(operator.totpConfirmed, true);
  assert.deepEqual(operator.instances, [], "un cont fără drepturi pare să aibă");
});

test("inventarul deosebește «fără al doilea factor» de «înrolare ruptă»",
     async () => {
  // Eșecul pe care îl previne: până pe 19 august 2026 ambele stări se scriau
  // `2FA NU`, iar mesajul de sub listă spunea că un cont NU se poate autentifica
  // și că se repară cu `enroll-totp`. După ce factorul a devenit opțional, asta
  // trimite operatorul să „repare" un cont care merge perfect — și îi ascunde
  // pe cel care chiar e blocat.
  await create({ enrolTotp: true });
  await create({ username: "fara2fa", enrolTotp: false });

  const rows = await listAccounts(fixture.db);
  const rupt = rows.find((row) => row.username === NEW_USER);
  const simplu = rows.find((row) => row.username === "fara2fa");
  assert.ok(rupt && simplu);
  assert.equal(rupt.totpState, "unconfirmed",
               "o înrolare neterminată nu se deosebește de lipsa factorului");
  assert.equal(simplu.totpState, "none",
               "un cont creat fără al doilea factor pare să aibă unul rupt");
  assert.equal(rupt.totpConfirmed, false);
  assert.equal(simplu.totpConfirmed, false,
               "cele două stări trebuie să rămână amândouă «neconfirmat»");
});

test("`drop-totp` deblochează un cont cu înrolare ruptă, dovedit prin citire",
     async () => {
  // Starea fără ieșire pe care o repară: un cont creat pe vremea când înrolarea
  // era impusă are un secret neconfirmat, iar `login()` refuză exact starea aia.
  // Singura reparație era `enroll-totp` — adică tocmai lucrul scos. Fără comanda
  // asta, „al doilea factor e opțional" era adevărat doar pentru conturile noi.
  const made = await create({ enrolTotp: true });
  assert.equal(made.ok, true);
  assert.ok(created()[0].totp_secret_enc, "schela n-a produs starea de reparat");

  const dropped = await dropTotp(fixture.db, NEW_USER);
  assert.equal(dropped.ok, true);
  assert.equal((dropped as { value: { hadSecret: boolean } }).value.hadSecret, true);
  assert.equal(created()[0].totp_secret_enc, null,
               "secretul a rămas în bază, deci contul e tot blocat");
  assert.equal(created()[0].totp_confirmed_at, null);
  assert.equal(created()[0].totp_last_counter, null,
               "contorul rămas ar bloca o reînrolare viitoare la aceeași fereastră");

  const rows = await listAccounts(fixture.db);
  assert.equal(rows.find((row) => row.username === NEW_USER)?.totpState, "none");
});

test("`drop-totp` pe un cont care nu avea factor e o operație nulă REUȘITĂ",
     async () => {
  // `UPDATE` peste `NULL` raportează zero rânduri schimbate. O gardă scrisă pe
  // numărul ăla ar transforma o comandă deja-făcută într-o eroare, iar
  // operatorul ar crede că a rămas ceva de reparat.
  await create({ enrolTotp: false });
  const dropped = await dropTotp(fixture.db, NEW_USER);
  assert.equal(dropped.ok, true, "a doua rulare a raportat eșec");
  assert.equal((dropped as { value: { hadSecret: boolean } }).value.hadSecret, false,
               "a raportat că a scos un factor care nu exista");
});

test("`drop-totp` cere un utilizator, ca `enroll-totp`", () => {
  assert.deepEqual(parseUserArgv(["drop-totp", "ana"]),
                   { ok: true, command: "drop-totp", username: "ana" });
  assert.equal(parseUserArgv(["drop-totp"]).ok, false);
});

test("`passwd` chiar schimbă hashul, dovedit prin citire înapoi", async () => {
  // Eșecul pe care îl previne: până pe 19 august 2026 nu exista NICIO cale de a
  // schimba o parolă — nici în unealtă, nici în panou. O parolă uitată, sau una
  // tastată la un `create` care apoi a refuzat fiindcă utilizatorul exista deja,
  // însemna un cont pierdut definitiv. S-a descoperit exact așa, în producție.
  await create({ enrolTotp: false });
  const vechi = created()[0].password_hash;

  const changed = await setPassword(fixture.db, NEW_USER, "parola-noua-8chr");
  assert.equal(changed.ok, true);
  const nou = created()[0].password_hash;
  assert.notEqual(nou, vechi, "hashul a rămas cel vechi, deci parola veche merge");
  assert.ok(String(nou).startsWith("$argon2id$"),
            "hashul nou nu e Argon2id, deci cineva l-a calculat pe lângă " +
            "`hashPassword`, unde se aplică plafoanele de lungime");
  assert.ok(!String(nou).includes("parola-noua-8chr"),
            "parola în clar a ajuns în coloană");
});

test("`passwd` refuză o parolă sub minim ÎNAINTE de orice scriere", async () => {
  // O parolă respinsă n-are voie să lase contul schimbat pe jumătate: hashul se
  // calculează înaintea scrierii tocmai ca refuzul să nu atingă baza.
  await create({ enrolTotp: false });
  const vechi = created()[0].password_hash;

  const scurta = await setPassword(fixture.db, NEW_USER,
                                   "x".repeat(MIN_PASSWORD_LENGTH - 1));
  assert.equal(scurta.ok, false, "o parolă sub minim a fost acceptată");
  assert.equal(created()[0].password_hash, vechi,
               "un refuz a schimbat totuși coloana");
});

test("`passwd` pe un utilizator inexistent e un refuz, nu o excepție", async () => {
  const lipsa = await setPassword(fixture.db, "nimeni-9xk2", "parola-buna-8chr");
  assert.equal(lipsa.ok, false);
  assert.match((lipsa as { detail: string }).detail, /nu există/);
});

test("`passwd` cere un utilizator", () => {
  assert.deepEqual(parseUserArgv(["passwd", "ana"]),
                   { ok: true, command: "passwd", username: "ana" });
  assert.equal(parseUserArgv(["passwd"]).ok, false);
});

// ---------------------------------------------------------------------------
// Recensăminte: nimic nu ocolește `hashPassword`
// ---------------------------------------------------------------------------
/** Fișierele livrate care au voie să atingă hashuirea, fiecare cu motivul. */
const MAY_TOUCH_HASHING: Record<string, string> = {
  "lib/auth/password.ts": "o definește; e singurul loc care aplică plafoanele",
  "lib/auth/login.ts": "ridică hashul la parametrii curenți, după un login reușit",
  "lib/auth/accounts.ts": "singura cale prin care apare un cont",
  "lib/auth/http.ts": "o pomenește în proză, ca să explice de ce ruta mărginește " +
                      "corpul formularului",
};

/** Fișierele livrate care au voie să atingă COLOANA. */
const MAY_TOUCH_THE_COLUMN: Record<string, string> = {
  "lib/auth/users.ts": "o citește, și o rescrie la ridicarea hashului",
  "lib/auth/accounts.ts": "o scrie o singură dată, la crearea contului",
  "migrations/0008_auth.sql": "o definește",
};

test("nimeni nu scrie în `password_hash` pe lângă `hashPassword`", () => {
  // Eșecul pe care îl previne, și e cel măsurat de verificator: o parolă de
  // peste 1024 de caractere stocată de o unealtă care își calculează singură
  // hashul. `login.ts` o refuză apoi pe LUNGIME, înainte de orice verificare —
  // 401 permanent, pe un cont cu parola corectă. Recensământ, nu recunoscător:
  // o cale nouă e roșie chiar dacă e scrisă într-o formă la care nu s-a gândit
  // nimeni.
  const touchesHashing = shippedFiles().filter(
    (file) => readShipped(file).includes("hashPassword"));
  assert.deepEqual(touchesHashing, Object.keys(MAY_TOUCH_HASHING).sort(),
                   "fișierele livrate care ating `hashPassword` nu sunt exact cele " +
                   "declarate în MAY_TOUCH_HASHING");

  const touchesColumn = shippedFiles().filter(
    (file) => readShipped(file).includes("password_hash"));
  assert.deepEqual(touchesColumn, Object.keys(MAY_TOUCH_THE_COLUMN).sort(),
                   "fișierele livrate care ating coloana `password_hash` nu sunt " +
                   "exact cele declarate în MAY_TOUCH_THE_COLUMN. O cale nouă " +
                   "spre coloana asta trebuie să treacă prin `hashPassword`, care " +
                   "e singurul loc care aplică MIN/MAX_PASSWORD_LENGTH");

  // Și unealta CHIAR o cheamă — altfel recensământul de mai sus ar fi verde
  // pentru o unealtă care nu hashuiește nimic.
  assert.match(readShipped("lib/auth/accounts.ts"),
               /passwordHash = await hashPassword\(input\.password\)/,
               "`createAccount` nu mai cheamă `hashPassword`");
});

test("unealta nu citește nicio parolă din `argv` sau din mediu", () => {
  // Proprietate a DEPOZITULUI, nu a unei ramuri: `bin/user.ts` nu are voie să
  // ajungă la parolă altfel decât prin `readNewPassword`, care citește de la
  // tastatură sau dintr-o conductă.
  const cli = readShipped("bin/user.ts");
  assert.ok(cli.includes("readNewPassword"),
            "`bin/user.ts` nu mai citește parola prin `readNewPassword`");
  const accounts = readShipped("lib/auth/accounts.ts");
  for (const forbidden of ["process.env.SENTINEL_PANEL_PASSWORD", "argv[2]"]) {
    assert.ok(!cli.includes(forbidden) && !accounts.includes(forbidden),
              `unealta citește parola din ${forbidden}`);
  }
  // `PASSWORD` din schelă e parola contului implicit; aici doar ne asigurăm că
  // testul de mai sus n-a trecut fiindcă fișierul e gol.
  assert.ok(cli.length > 1000 && PASSWORD.length > 0);
});
