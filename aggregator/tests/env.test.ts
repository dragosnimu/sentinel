/**
 * Configurația din mediu.
 *
 * Ce se strică pentru operator: variabilele agregatorului se pun de mână
 * într-un panou web, fără API. O valoare salvată goală sau scrisă greșit care
 * cade tăcut pe un implicit produce o instalare care pare configurată și nu e
 * — iar simptomul apare mai târziu, ca o conexiune refuzată sau ca o limită pe
 * care cineva e sigur că a schimbat-o.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ConfigError, DEFAULT_POOL_SIZE, MAX_POOL_SIZE, readDbConfig, readMasterSecret,
  readSessionSecret, requiredNames,
} from "../lib/env";

const FULL = {
  AGGREGATOR_DB_USER: "u",
  AGGREGATOR_DB_PASSWORD: "p",
  AGGREGATOR_DB_NAME: "d",
  SENTINEL_AGGREGATOR_SECRET: "s".repeat(64),
  SENTINEL_SESSION_SECRET: "e".repeat(64),
};

test("o variabilă obligatorie lipsă e o eroare care o NUMEȘTE", () => {
  // Un mesaj care spune doar „configurație invalidă" trimite pe cineva să
  // caute prin cinci câmpuri într-un panou web.
  for (const key of ["AGGREGATOR_DB_USER", "AGGREGATOR_DB_PASSWORD",
                     "AGGREGATOR_DB_NAME"]) {
    const env = { ...FULL, [key]: undefined };
    assert.throws(() => readDbConfig(env),
                  (err: unknown) => err instanceof ConfigError &&
                                    (err as Error).message.includes(key),
                  `lipsa lui ${key} nu a fost numită`);
  }
  assert.throws(() => readMasterSecret({}),
                (err: unknown) => err instanceof ConfigError &&
                  (err as Error).message.includes("SENTINEL_AGGREGATOR_SECRET"));
  assert.throws(() => readSessionSecret({}),
                (err: unknown) => err instanceof ConfigError &&
                  (err as Error).message.includes("SENTINEL_SESSION_SECRET"));
});

test("cele două secrete se citesc separat, deci lipsa unuia nu-l oprește pe celălalt", () => {
  // Eșecul pe care îl previne: o singură citire care cere amândouă valorile.
  // Atunci o variabilă uitată în panoul de găzduire — cazul obișnuit, nu cel
  // exotic — ar opri INGESTIA tuturor instanțelor fiindcă lipsește o cheie de
  // care are nevoie autentificarea panoului. Loturile refuzate nu se retrimit
  // singure la nesfârșit: pe serverul monitorizat asta se vede ca `ship:lag`, cu
  // backoff de până la o oră, iar cauza reală („lipsește secretul de sesiune")
  // nu ajunge acolo niciodată.
  //
  // Și invers: panoul trebuie să poată spune „lipsește secretul de sesiune"
  // chiar dacă secretul de ingestie lipsește și el.
  const withoutSession = { ...FULL, SENTINEL_SESSION_SECRET: undefined };
  assert.doesNotThrow(() => readDbConfig(withoutSession));
  assert.equal(readMasterSecret(withoutSession), "s".repeat(64));

  const withoutMaster = { ...FULL, SENTINEL_AGGREGATOR_SECRET: undefined };
  assert.equal(readSessionSecret(withoutMaster), "e".repeat(64));

  // Și chiar sunt valori diferite în același mediu: dacă cineva le-ar face
  // aceeași variabilă, rotirea uneia ar strica ce ține cealaltă.
  assert.notEqual(readMasterSecret(FULL), readSessionSecret(FULL));
});

/**
 * Mesajul cu care se plânge lipsa unei variabile — oricare ar fi cititorul ei.
 *
 * Se încearcă amândouă funcțiile de citire, iar dacă NICIUNA nu se plânge,
 * variabila nu mai e obligatorie: atunci intrarea din `REQUIRED_REASONS` e o
 * explicație pentru ceva ce nu se mai întâmplă, și testul trebuie să spună asta,
 * nu să treacă.
 */
function messageFor(name: string): string {
  const env = { ...FULL, [name]: undefined };
  for (const read of [() => readDbConfig(env), () => readMasterSecret(env),
                      () => readSessionSecret(env)]) {
    try {
      read();
    } catch (err) {
      if (err instanceof ConfigError && err.message.startsWith(name)) return err.message;
    }
  }
  throw new Error(
    `${name}: nicio funcție de citire nu s-a plâns de lipsa ei. Ori nu mai e ` +
    "obligatorie, ori nimeni n-o mai citește — în ambele cazuri, motivul scris " +
    "pentru ea e despre altceva.");
}

test("fiecare variabilă obligatorie își spune PROPRIUL motiv", () => {
  // Eșecul pe care îl previne, observat în producție pe 15 august 2026: lipsa
  // lui `AGGREGATOR_DB_PASSWORD` raportată cu explicația lui
  // `AGGREGATOR_DB_NAME` — „nu pot ghici ce bază de date să folosesc". Un
  // șablon refolosit pentru toate variabilele. Verificarea era corectă, textul
  // era al altcuiva, iar operatorul a căutat în direcția greșită.
  //
  // Mesajul e prima suprafață pe care o citește cineva blocat. Aici se cere ca
  // fiecare variabilă să aibă un motiv al ei — nu ca textul să fie frumos, ci
  // ca refolosirea să nu mai poată trece tăcut.
  const reasons = new Map<string, string>();
  for (const name of requiredNames()) {
    const message = messageFor(name);
    assert.ok(message.startsWith(`${name} lipsește`),
              `mesajul pentru ${name} nu începe cu numele variabilei: ${message}`);
    const reason = message.slice(`${name} lipsește (sau e goală). `.length).trim();
    assert.ok(reason.length > 40, `${name}: motivul e prea scurt ca să spună ceva`);

    const already = [...reasons.entries()].find(([, text]) => text === reason);
    assert.ok(!already,
              `${name} și ${already?.[0]} au ACELAȘI text explicativ. Unul dintre ` +
              "ele e al altei variabile, iar cine îl citește e trimis greșit.");
    reasons.set(name, reason);
  }
  // Bucla goală ar trece verde — chiar tiparul din CLAUDE.md.
  assert.ok(reasons.size >= 4, `doar ${reasons.size} variabile obligatorii probate`);
});

test("lista de motive le acoperă pe TOATE variabilele obligatorii", () => {
  // Cealaltă jumătate: prima probă arată că fiecare variabilă DIN LISTĂ e
  // obligatorie și are un text al ei. Asta arată că fiecare variabilă
  // obligatorie e ÎN LISTĂ — altfel, cine adaugă un câmp și uită motivul află
  // abia de la operatorul blocat.
  //
  // Mulțimea se descoperă prin PURTARE, nu se scrie a doua oară: se pornește de
  // la un mediu gol și se adaugă câte o valoare pentru fiecare variabilă de care
  // se plânge cineva, până când nu se mai plânge nimeni.
  const env: Record<string, string> = {};
  const discovered: string[] = [];
  for (let round = 0; round < 20; round++) {
    let complained = false;
    for (const read of [() => readDbConfig(env), () => readMasterSecret(env),
                        () => readSessionSecret(env)]) {
      try {
        read();
      } catch (err) {
        if (!(err instanceof ConfigError)) throw err;
        const name = err.message.split(" ")[0];
        if (!discovered.includes(name)) {
          discovered.push(name);
          env[name] = "x".repeat(64);
          complained = true;
        }
      }
    }
    if (!complained) break;
  }

  assert.ok(discovered.length >= 4,
            `doar ${discovered.length} variabile obligatorii descoperite: ${discovered}`);
  assert.deepEqual(discovered.slice().sort(), requiredNames().slice().sort(),
                   "o variabilă obligatorie fără motiv scris (sau un motiv scris " +
                   "pentru o variabilă care nu mai e obligatorie)");
});

test("„setat la gol” e tratat ca „lipsă”, nu ca valoare", () => {
  // Cazul obișnuit într-un formular web, nu cel exotic. Cu `||` ar fi trecut
  // drept lipsă tăcut; aici e o eroare cu numele variabilei.
  for (const value of ["", "   "]) {
    assert.throws(() => readDbConfig({ ...FULL, AGGREGATOR_DB_NAME: value }),
                  ConfigError, `valoarea ${JSON.stringify(value)} a fost acceptată`);
  }
});

test("gazda și portul au implicite; numele bazei NU are", () => {
  // Numele bazei și al utilizatorului conțin identificatorul de cont, iar
  // depozitul e public: un implicit pentru ele ar fi o scurgere de
  // infrastructură scrisă în cod. `127.0.0.1:3306` nu spune nimic despre nimeni.
  const cfg = readDbConfig(FULL);
  assert.equal(cfg.host, "127.0.0.1");
  assert.equal(cfg.port, 3306);
  assert.equal(cfg.connectionLimit, DEFAULT_POOL_SIZE);
});

test("un număr scris greșit e o eroare, nu o cădere tăcută pe implicit", () => {
  // „Am schimbat limita" / „nu s-a schimbat nimic" e chiar tiparul
  // „confirmarea intenției în locul efectului".
  for (const bad of ["opt", "8.5", "0", String(MAX_POOL_SIZE + 1), "-1", "1e3"]) {
    assert.throws(() => readDbConfig({ ...FULL, AGGREGATOR_DB_POOL_SIZE: bad }),
                  ConfigError, `AGGREGATOR_DB_POOL_SIZE=${bad} a fost acceptat`);
  }
  // `parseInt("8abc")` ar fi întors 8. `Number` nu.
  assert.throws(() => readDbConfig({ ...FULL, AGGREGATOR_DB_POOL_SIZE: "8abc" }),
                ConfigError);
  assert.equal(readDbConfig({ ...FULL, AGGREGATOR_DB_POOL_SIZE: "16" }).connectionLimit, 16);
});

test("portul se validează în interval", () => {
  assert.throws(() => readDbConfig({ ...FULL, AGGREGATOR_DB_PORT: "70000" }), ConfigError);
  assert.equal(readDbConfig({ ...FULL, AGGREGATOR_DB_PORT: "3307" }).port, 3307);
});
