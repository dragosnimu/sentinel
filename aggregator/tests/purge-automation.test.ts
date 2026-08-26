/**
 * Curățarea istoricului de automatizări de pe replică.
 *
 * Eșecurile pe care le previne, în termeni de ce se strică pentru operator:
 *
 *   * **Un „dry-run" care șterge.** Modul uscat e singura cale prin care cineva
 *     vede ce ar cădea înainte să hotărască. Aici e mai grav decât pe gazdă:
 *     replica e tot ce mai rămâne dacă serverul e compromis.
 *   * **Altă regulă decât a filtrului de pe gazdă.** Dacă cele două nu potrivesc
 *     aceleași rânduri, datele vechi și cele noi înseamnă lucruri diferite.
 *   * **`DELETE` fără `LIMIT`.** Sute de mii de rânduri într-o instrucțiune țin
 *     un lock lung pe InnoDB, iar ingestia expiră în timpul lui — pentru toate
 *     cele douăsprezece fluxuri, nu doar pentru ăsta.
 *   * **Un nume de cont lipit în SQL.** Vine dintr-un argument de linie de
 *     comandă; interpolat, e injecție.
 *   * **Un raport care confirmă intenția.** «Am șters 2,9 milioane de rânduri»
 *     și o cotă la fel de plină, fiindcă InnoDB nu întoarce spațiul singur.
 *   * **«558 079 comenzi» deasupra unui tabel gol.** Curățarea nu atinge
 *     `login_session_entries`, iar panoul citește `command_count` de acolo.
 *   * **O colație CI care șterge alte rânduri decât filtrul viu.** Scris în
 *     predicat nu înseamnă aplicat de server, iar diferența nu se vede decât ca
 *     un număr ușor altul.
 *   * **Ștergerea sesiunii unui om.** Modul pe sesiune taie tot ce a rulat
 *     sesiunea aleasă, deci un identificator greșit costă chiar istoricul care
 *     contează cel mai mult.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  BATCH, COLLATION, COLLATION_PROBE_EXPECTED, COLLATION_PROBE_PARAMS,
  COLLATION_PROBE_SQL, REAL_TTY, SIZE_SQL, TABLE, assertRuleMatchesTheHost,
  countSql, deleteSql, listSessions, listSessionsSql, mb, purge,
} from "../lib/purge-automation";
import { parseArgs } from "../bin/purge-automation-commands";
import type { Queryable } from "../lib/db";

type Rand = {
  instanceId: string; sessionSourceId: number | null;
  username: string; tty: string | null;
};

type Sesiune = {
  instanceId: string; sourceId: number; sessionKey: string;
  username: string | null; interactive: number; openedAt: string;
  commandCount: number; commandsPurged: number;
};

function rand(over: Partial<Rand> = {}): Rand {
  return {
    instanceId: "srv-a", sessionSourceId: 1, username: "sentinel-deploy",
    tty: null, ...over,
  };
}

function sesiune(over: Partial<Sesiune> = {}): Sesiune {
  return {
    instanceId: "srv-a", sourceId: 1, sessionKey: "2521", username: "sentinel-deploy",
    interactive: 0, openedAt: "2026-08-25 10:00:00", commandCount: 0,
    commandsPurged: 0, ...over,
  };
}

function multe(n: number, over: Partial<Rand> = {}): Rand[] {
  return Array.from({ length: n }, () => rand(over));
}

/**
 * Dublu de conexiune care ȚINE RÂNDURI, nu doar un contor.
 *
 * Predicatele NU sunt reimplementate din memorie: se citesc din CHIAR TEXTUL pe
 * care i-l dă biblioteca. Un dublu care își face singur regulile probează
 * dublul, nu codul — iar aici tocmai despre ce anume potrivește regula e vorba.
 *
 * Colația e modelată ca un COMUTATOR: implicit se comportă ca `utf8mb4_bin`
 * (adică cum cere `COLLATE` din predicat), iar `collationIgnored` îl face să se
 * poarte ca `utf8mb4_unicode_ci` — serverul care ignoră marcajul. Fără
 * comutatorul ăsta, proba de colație ar fi un test care nu poate pica.
 */
function conexiune(opts: {
  randuri?: Rand[]; sesiuni?: Sesiune[]; bytes?: number;
  collationIgnored?: boolean;
} = {}) {
  const stare = {
    randuri: (opts.randuri ?? []).map((r) => ({ ...r })),
    sesiuni: (opts.sesiuni ?? []).map((s) => ({ ...s })),
    bytes: opts.bytes ?? 953_000_000,
    sql: [] as { q: string; params: unknown[] }[],
  };

  const ci = opts.collationIgnored === true;
  const pliaza = (v: string) => (ci ? v.toLowerCase().trimEnd() : v);

  function predicat(q: string, params: unknown[]): (r: Rand) => boolean {
    if (q.includes("username COLLATE")) {
      const tipar = new RegExp(REAL_TTY, ci ? "i" : "");
      const conturi = params.slice(0, params.length - 1).map((p) => pliaza(String(p)));
      assert.match(q, /tty IS NULL OR \(tty COLLATE \w+\) NOT REGEXP \?/);
      return (r) => conturi.includes(pliaza(r.username))
                    && (r.tty === null || !tipar.test(pliaza(r.tty)));
    }
    if (q.includes("instance_id = ? AND session_source_id IN")) {
      const inst = String(params[0]);
      const ids = params.slice(1).map(Number);
      return (r) => r.instanceId === inst && r.sessionSourceId !== null
                    && ids.includes(r.sessionSourceId);
    }
    throw new Error(`predicat nerecunoscut: ${q}`);
  }

  const db = {
    async query(q: string, params: unknown[] = []) {
      stare.sql.push({ q, params });

      if (q.startsWith("SELECT (?")) {
        // Proba de colație. Se răspunde EVALUÂND, nu întorcând constantele
        // așteptate: un dublu care ar întoarce răspunsul bun oricum ar face
        // proba un test care nu poate pica.
        const tipar = new RegExp(REAL_TTY, ci ? "i" : "");
        const p = params as string[];
        return [[{
          upper_not_tty: tipar.test(pliaza(p[0])) ? 0 : 1,
          lower_not_tty: tipar.test(pliaza(p[2])) ? 0 : 1,
          padded_not_tty: tipar.test(pliaza(p[4])) ? 0 : 1,
          upper_is_account: pliaza(p[6]) === pliaza(p[7]) ? 1 : 0,
        }], null] as [unknown, unknown];
      }
      if (/^\s*DELETE/i.test(q)) {
        const limita = Number(/LIMIT (\d+)/.exec(q)?.[1] ?? 0);
        const p = predicat(q, params);
        const cad = stare.randuri.filter(p).slice(0, limita);
        stare.randuri = stare.randuri.filter((r) => !cad.includes(r));
        return [{ affectedRows: cad.length }, null] as [unknown, unknown];
      }
      if (/^\s*OPTIMIZE/i.test(q)) {
        stare.bytes = Math.round(stare.bytes / 10);
        return [[{ Table: TABLE, Msg_text: "OK" }], null] as [unknown, unknown];
      }
      if (/^\s*UPDATE login_session_entries/i.test(q)) {
        assert.match(q, /commands_purged = commands_purged \+ \?/);
        assert.doesNotMatch(q, /command_count/,
                            "replica rescrie command_count, care e al gazdei");
        const [n, inst, sid] = params as [number, string, number];
        for (const s of stare.sesiuni) {
          if (s.instanceId === inst && s.sourceId === sid) s.commandsPurged += n;
        }
        return [{ affectedRows: 1 }, null] as [unknown, unknown];
      }
      if (q.includes("information_schema")) {
        return [[{ bytes: stare.bytes }], null] as [unknown, unknown];
      }
      if (q.includes("GROUP BY instance_id, session_source_id")) {
        const p = predicat(q, params);
        const pe: Record<string, number> = {};
        for (const r of stare.randuri) {
          if (r.sessionSourceId === null || !p(r)) continue;
          const k = `${r.instanceId}/${r.sessionSourceId}`;
          pe[k] = (pe[k] ?? 0) + 1;
        }
        return [Object.entries(pe).map(([k, n]) => ({
          instance_id: k.split("/")[0],
          session_source_id: Number(k.split("/")[1]), n,
        })), null] as [unknown, unknown];
      }
      if (q.includes("interactive, opened_at FROM login_session_entries")) {
        const inst = String(params[0]);
        const ids = params.slice(1).map(Number);
        return [stare.sesiuni
          .filter((s) => s.instanceId === inst && ids.includes(s.sourceId))
          .map((s) => ({ source_id: s.sourceId, username: s.username,
                         interactive: s.interactive, opened_at: s.openedAt })),
          null] as [unknown, unknown];
      }
      if (q.includes("ORDER BY rows_now DESC")) {
        const limita = Number(/LIMIT (\d+)/.exec(q)?.[1] ?? 0);
        // Filtrul se citește DIN INSTRUCȚIUNE. Aplicat din memorie, dublul ar
        // ascunde chiar dispariția lui — iar o listă de curățat care conține
        // sesiuni de om e cel mai scump fel de listă greșită de aici.
        const doarFaraTerminal = /s\.interactive = 0/.test(q);
        const out = stare.sesiuni
          .filter((s) => !doarFaraTerminal || s.interactive === 0)
          .map((s) => ({
            instance_id: s.instanceId, source_id: s.sourceId,
            session_key: s.sessionKey, username: s.username,
            opened_at: s.openedAt, command_count: s.commandCount,
            commands_purged: s.commandsPurged,
            rows_now: stare.randuri.filter(
              (r) => r.instanceId === s.instanceId
                     && r.sessionSourceId === s.sourceId).length,
          }))
          .sort((a, b) => b.rows_now - a.rows_now)
          .slice(0, limita);
        return [out, null] as [unknown, unknown];
      }
      if (q.includes("WHERE")) {
        const p = predicat(q, params);
        return [[{ n: stare.randuri.filter(p).length }], null] as [unknown, unknown];
      }
      return [[{ n: stare.randuri.length }], null] as [unknown, unknown];
    },
  };
  return { db, stare };
}

function jurnal() {
  const linii: string[] = [];
  return { linii, log: (l: string) => linii.push(l), text: () => linii.join("\n") };
}

const CONT = ["sentinel-deploy"];

// ---------------------------------------------------------------------------
// Modul uscat
// ---------------------------------------------------------------------------
test("modul uscat nu scrie nimic", async () => {
  /* Implicitul e „uită-te", nu „șterge". Pe replică e mai grav decât pe gazdă:
   * dacă serverul e compromis, asta e copia care mai există. */
  const { db, stare } = conexiune({
    randuri: multe(120), sesiuni: [sesiune({ commandCount: 120 })],
  });
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: false, log: j.log });

  const scrieri = stare.sql.filter((s) => /^\s*(DELETE|OPTIMIZE|UPDATE|INSERT)/i.test(s.q));
  assert.deepEqual(scrieri, [], "modul uscat a executat o scriere");
  assert.equal(r.deleted, 0);
  assert.equal(r.matching, 120);
  assert.equal(stare.sesiuni[0].commandsPurged, 0, "a atins contorul în modul uscat");
  assert.match(j.text(), /--apply/, "nu spune cum se face ștergerea");
});

// ---------------------------------------------------------------------------
// Aceeași regulă ca filtrul de pe gazdă
// ---------------------------------------------------------------------------
test("tiparul de terminal acceptă și respinge ACELEAȘI valori ca pe gazdă", () => {
  /* Lista e chiar cea din `tests/unit/test_login_projection.py`. Dacă cele două
   * s-ar despărți, ștergerea ar înghiți comenzile tastate de un om pe contul de
   * automatizare — exact cele care contează — sau ar lăsa în urmă mormanul pe
   * care filtrul nou nu-l mai poate curăța.
   *
   * Egalitatea LITERALĂ a celor două tipare se ține de partea cealaltă, în
   * `tests/unit/test_purge_automation_commands.py`, care citește chiar șirul
   * ăsta din fișierul livrat. Aici se probează comportamentul lui. */
  const tipar = new RegExp(REAL_TTY);
  for (const real of ["pts0", "pts12", "tty1", " pts0", "pts0 ", "\tpts0", "pts0\n"]) {
    assert.ok(tipar.test(real), `${JSON.stringify(real)} n-ar mai fi terminal real`);
  }
  for (const fals of ["(none)", "", "ssh", "cron", "pts", "ptsx", "PTS0", "xpts0"]) {
    assert.ok(!tipar.test(fals), `${fals} ar trece drept terminal real`);
  }
});

test("regula cere ȘI contul, ȘI absența terminalului", () => {
  /* Numai contul ar șterge și comenzile unei logări interactive pe contul de
   * automatizare — cele care promovează sesiunea și trimit alerta. Numai
   * terminalul ar șterge diagnosticele rulate de la distanță de un om. */
  const { sql } = countSql(CONT);
  assert.match(sql, /\(username COLLATE \w+\) IN \(\?\)/);
  assert.match(sql, /tty IS NULL OR \(tty COLLATE \w+\) NOT REGEXP \?/);
  assert.match(sql, / AND /);
});

test("un `tty` NULL cade sub regulă, ca `is_interactive(None)` pe gazdă", () => {
  /* „Nu știu ce terminal a avut" nu e „a avut unul". Fără bucata asta, rândurile
   * fără tty ar rămâne pentru totdeauna, iar cele două baze ar diverge. */
  assert.match(countSql(CONT).sql, /tty IS NULL/);
  assert.match(deleteSql(CONT, BATCH).sql, /tty IS NULL/);
});

test("numele contului pleacă LEGAT, niciodată lipit în SQL", () => {
  /* Vine dintr-un argument de linie de comandă. Interpolat, e injecție într-o
   * instrucțiune `DELETE`. */
  const rau = "x' OR '1'='1";
  const { sql, params } = deleteSql([rau], BATCH);
  assert.ok(!sql.includes(rau), "numele contului a ajuns în textul instrucțiunii");
  assert.deepEqual(params, [rau, REAL_TTY]);
});

// ---------------------------------------------------------------------------
// Colația: scris în predicat nu înseamnă aplicat de server
// ---------------------------------------------------------------------------
test("predicatul cere colația binară, nu pe cea a coloanei", () => {
  /* `utf8mb4_unicode_ci` face `IN` insensibil la majuscule ȘI la spațiile de
   * umplere, iar `REGEXP` insensibil la majuscule. PostgreSQL și Python nu fac
   * niciuna: `'PTS0'` era ARUNCAT de filtrul viu și PĂSTRAT aici, iar
   * `'SENTINEL-DEPLOY'` era socotit contul aici și nu acolo. Aceleași date, două
   * cronologii. */
  assert.equal(COLLATION, "utf8mb4_bin");
  assert.match(countSql(CONT).sql, /COLLATE utf8mb4_bin/);
  assert.match(deleteSql(CONT, BATCH).sql, /COLLATE utf8mb4_bin/);
  assert.match(COLLATION_PROBE_SQL, /COLLATE utf8mb4_bin/);
});

test("proba de colație întreabă serverul și trece pe un server care o aplică", async () => {
  const { db, stare } = conexiune({});
  await assertRuleMatchesTheHost(db);
  assert.equal(stare.sql.length, 1, "proba n-a întrebat serverul nimic");
  assert.deepEqual(stare.sql[0].params, COLLATION_PROBE_PARAMS);
  assert.deepEqual(Object.keys(COLLATION_PROBE_EXPECTED).sort(),
                   ["lower_not_tty", "padded_not_tty", "upper_is_account", "upper_not_tty"]);
});

test("un server care IGNORĂ colația oprește ștergerea, nu o face altfel", async () => {
  /* `COLLATE utf8mb4_bin` scris în predicat nu e dovadă că serverul îl aplică —
   * e chiar tiparul din `CLAUDE.md`: codul de retur nu e dovadă de efect. Dacă
   * marcajul e ignorat, ștergerea cade pe alte rânduri decât filtrul viu, iar
   * singurul semn ar fi un număr ușor altul. Deci nu se șterge deloc. */
  const { db, stare } = conexiune({
    randuri: multe(50), sesiuni: [sesiune()], collationIgnored: true,
  });
  const j = jurnal();
  await assert.rejects(() => purge(db, { accounts: CONT, apply: true, log: j.log }),
                       /NU se comport/);
  const scrieri = stare.sql.filter((s) => /^\s*(DELETE|OPTIMIZE|UPDATE)/i.test(s.q));
  assert.deepEqual(scrieri, [], "a șters pe un server care nu aplică colația");
  assert.equal(stare.randuri.length, 50);
});

test("proba rulează ÎNAINTE de prima ștergere, nu după", async () => {
  const { db, stare } = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  await purge(db, { accounts: CONT, apply: true, log: () => {} });
  const proba = stare.sql.findIndex((s) => s.q.startsWith("SELECT (?"));
  const sterge = stare.sql.findIndex((s) => /^\s*DELETE/i.test(s.q));
  assert.ok(proba >= 0, "nu s-a rulat nicio probă de colație");
  assert.ok(proba < sterge, "proba se face după ștergere, deci nu oprește nimic");
});

test("modul uscat întreabă și el, dar refuzul nu-l oprește — îl SPUNE", async () => {
  /* Cifra din modul uscat e singurul lucru pe care operatorul se uită ca să
   * DECIDĂ ce șterge, iar ea era singura care nu trecea prin nicio verificare:
   * proba stătea după întoarcerea din modul uscat. Pe un server care ignoră
   * colația, `potrivesc: N` numără alte rânduri decât ar cădea pe gazdă —
   * ștergerea era în siguranță, decizia nu.
   *
   * Ce trebuie să rămână adevărat în același timp: o numărătoare inofensivă nu
   * are voie să devină o operație care eșuează. Deci în modul uscat proba se
   * face, iar rezultatul ei intră în raport; nu aruncă. */
  const { db, stare } = conexiune({
    randuri: multe(10), sesiuni: [sesiune()], collationIgnored: true,
  });
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: false, log: j.log });

  assert.ok(stare.sql.some((s) => s.q.startsWith("SELECT (?")),
            "modul uscat n-a verificat regula cu care a numărat");
  assert.equal(r.deleted, 0);
  assert.equal(stare.randuri.length, 10, "modul uscat a șters");
  assert.match(j.text(), /NU e de crezut/);
  assert.match(j.text(), /NU se comport/);

  // Iar pe un server care aplică regula, raportul NU poartă avertismentul: unul
  // tipărit mereu ar fi zgomot, adică fix motivul pentru care nu se mai citește.
  const bun = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  const j2 = jurnal();
  await purge(bun.db, { accounts: CONT, apply: false, log: j2.log });
  assert.ok(!/NU e de crezut/.test(j2.text()), j2.text());
});

test("proba se face ÎNAINTE de numărătoarea pe care o validează", async () => {
  /* Ordinea contează pentru raport: cifra și avertismentul despre ea trebuie să
   * ajungă la operator în aceeași citire, nu într-una de mai târziu. */
  const { db, stare } = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  await purge(db, { accounts: CONT, apply: false, log: () => {} });
  const proba = stare.sql.findIndex((s) => s.q.startsWith("SELECT (?"));
  const numara = stare.sql.findIndex((s) => /^SELECT COUNT\(\*\) AS n FROM \w+ WHERE/.test(s.q));
  assert.ok(proba >= 0 && numara >= 0, JSON.stringify(stare.sql.map((s) => s.q)));
  assert.ok(proba < numara, "s-a numărat înainte să se știe cu ce regulă");
});

test("modul pe sesiune nu are ce dovedi, deci nu întreabă", async () => {
  /* Regula pe sesiune nu compară nici conturi, nici terminale: e `instance_id`
   * și `session_source_id`, adică numere. Colația n-are ce le face, iar o probă
   * cerută degeaba ar fi o cale în plus prin care curățarea poate eșua. */
  const { db, stare } = conexiune({
    randuri: multe(10, { sessionSourceId: 2521 }),
    sesiuni: [sesiune({ sourceId: 2521 })], collationIgnored: true,
  });
  await purge(db, { instanceId: "srv-a", sessionIds: [2521], apply: true,
                    log: () => {} });
  assert.ok(!stare.sql.some((s) => s.q.startsWith("SELECT (?")));
});

test("un răspuns care nu e număr oprește ștergerea, nu trece drept zero", async () => {
  /* `Number(null)` e `0`, iar trei din cele patru răspunsuri ale probei sunt
   * așteptate `0` — deci o coloană venită `null` era citită ca «serverul e de
   * acord». Azi proba pica închis din NOROC: `upper_not_tty` așteaptă `1`.
   * Norocul ăla ține de ce numere s-au ales, nu de vreo regulă, iar prima
   * întrebare adăugată cu răspuns așteptat `0` l-ar fi consumat în tăcere.
   *
   * Cazurile de mai jos sunt chiar felurile în care un driver poate întoarce
   * altceva decât un număr: coloană necunoscută, `NULL`, boolean, șir gol. */
  for (const rau of [null, undefined, true, "", " ", [], {}]) {
    const db: Queryable = {
      async query(q: string) {
        if (!q.startsWith("SELECT (?")) throw new Error(`neașteptat: ${q}`);
        return [[{ upper_not_tty: 1, lower_not_tty: 0,
                   padded_not_tty: rau, upper_is_account: 0 }], null] as
               [unknown, unknown];
      },
    } as unknown as Queryable;
    await assert.rejects(() => assertRuleMatchesTheHost(db),
                         /nu e un num/,
                         `«${JSON.stringify(rau)}» a fost citit ca un răspuns bun`);
  }

  // Și celălalt sens: un „0" ca ȘIR e un răspuns valid, fiindcă drivere
  // adevărate chiar întorc așa. Refuzat, curățarea n-ar mai putea rula deloc.
  const sir: Queryable = {
    async query() {
      return [[{ upper_not_tty: "1", lower_not_tty: "0",
                 padded_not_tty: "0", upper_is_account: "0" }], null] as
             [unknown, unknown];
    },
  } as unknown as Queryable;
  await assertRuleMatchesTheHost(sir);
});

// ---------------------------------------------------------------------------
// Tranșele
// ---------------------------------------------------------------------------
test("ștergerea are LIMIT și se face în tranșe", async () => {
  const { db, stare } = conexiune({
    randuri: multe(12_003), sesiuni: [sesiune({ commandCount: 12_003 })],
  });
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: true, batch: 5000, log: j.log });

  const stergeri = stare.sql.filter((s) => /^DELETE/.test(s.q));
  assert.equal(stergeri.length, 3, "12 003 rânduri într-un singur DELETE");
  for (const s of stergeri) assert.match(s.q, /LIMIT 5000$/);
  assert.equal(r.deleted, 12_003);
});

test("o tranșă absurdă e refuzată, nu lipită în instrucțiune", () => {
  /* `LIMIT` e singurul loc din fișier unde o valoare intră în SQL fără să fie
   * legată. Dacă n-ar fi verificată, ar fi și singura cale de injecție. */
  assert.throws(() => deleteSql(CONT, 0));
  assert.throws(() => deleteSql(CONT, 1.5));
  assert.throws(() => deleteSql(CONT, Number("nu-i număr")));
  assert.throws(() => deleteSql(CONT, 10 ** 9));
  assert.throws(() => listSessionsSql(0));
});

// ---------------------------------------------------------------------------
// Raportul: efectul, nu intenția
// ---------------------------------------------------------------------------
test("raportul spune ce a rămas, renumărat, nu ce a raportat DELETE", async () => {
  /* Expedierea de pe gazdă merge în paralel, deci pot apărea rânduri noi în
   * timpul rulării. «Gata» pe o tabelă în care regula mai potrivește șapte
   * rânduri e o afirmație falsă. */
  const { db, stare } = conexiune({ randuri: multe(100), sesiuni: [sesiune()] });
  const original = db.query.bind(db);
  let adaugat = false;
  db.query = async (q: string, params: unknown[] = []) => {
    const out = await original(q, params);
    if (/^\s*UPDATE login_session_entries/i.test(q) && !adaugat) {
      adaugat = true;
      stare.randuri.push(...multe(7));
    }
    return out;
  };
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: true, log: j.log });

  assert.equal(r.remaining, 7);
  assert.match(j.text(), /mai potrivesc regula: 7/);
  assert.match(j.text(), /din nou/);
});

test("fără OPTIMIZE, raportul spune că spațiul NU s-a întors", async () => {
  /* «Am șters 2,9 milioane de rânduri» urmat de o cotă la fel de plină e chiar
   * tiparul confirmării intenției. Raportul trebuie să spună amândouă și să
   * numească pasul care lipsește, cu costul lui. */
  const { db } = conexiune({ randuri: multe(1000), sesiuni: [sesiune()] });
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: true, log: j.log });

  assert.equal(r.optimised, false);
  assert.equal(r.bytesAfter, r.bytesBefore, "dublul pretinde că InnoDB scade singur");
  assert.match(j.text(), /nu întoarce spațiul/);
  assert.match(j.text(), /--optimize/);
  assert.match(j.text(), /încă o dată dimensiunea/);
});

test("cu --optimize, tabela chiar se rescrie și mărimea se raportează", async () => {
  const { db, stare } = conexiune({ randuri: multe(1000), sesiuni: [sesiune()] });
  const j = jurnal();
  const r = await purge(db, {
    accounts: CONT, apply: true, optimize: true, log: j.log,
  });

  assert.ok(stare.sql.some((s) => /^OPTIMIZE TABLE/.test(s.q)),
            "s-a raportat --optimize fără să se ruleze nimic");
  assert.equal(r.optimised, true);
  assert.ok(r.bytesAfter < r.bytesBefore);
  assert.match(j.text(), /mărime/);
});

test("mărimea se citește din information_schema, pentru CHIAR tabela asta", async () => {
  const { db, stare } = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  await purge(db, { accounts: CONT, apply: false, log: () => {} });
  const marimi = stare.sql.filter((s) => s.q === SIZE_SQL);
  assert.ok(marimi.length >= 1);
  assert.deepEqual(marimi[0].params, [TABLE]);
});

// ---------------------------------------------------------------------------
// Contorul sesiunii
// ---------------------------------------------------------------------------
test("sesiunea nu mai pretinde comenzi pe care arhiva asta nu le mai are", async () => {
  /* Panoul (`lib/panel-page.ts`) citește `command_count` de pe rândul sesiunii,
   * nu tabela de comenzi. Curățarea care nu lasă nicio urmă pe sesiune produce
   * «558 079 comenzi» deasupra unui tabel gol — exact eșecul pentru care există
   * contorul. */
  const { db, stare } = conexiune({
    randuri: multe(500), sesiuni: [sesiune({ commandCount: 500 })],
  });
  const j = jurnal();
  const r = await purge(db, { accounts: CONT, apply: true, log: j.log });

  assert.equal(r.deleted, 500);
  assert.equal(stare.sesiuni[0].commandsPurged, 500,
               "nu s-a păstrat nicăieri că sesiunea a rulat 500 de comenzi");
  assert.equal(r.sessionsTouched, 1);
  assert.match(j.text(), /commands_purged/);
});

test("`command_count` rămâne al gazdei: replica nu-l rescrie", async () => {
  /* Îl aduce expedierea (`lib/streams.ts`) și îl rescrie la fiecare lot. Pus pe
   * zero de aici, s-ar întoarce la următoarea expediere, iar panoul ar oscila
   * între două cifre fără ca vreuna să fie greșită. Ce știe replica, și numai
   * ea, e câte rânduri a șters EA. */
  const { db, stare } = conexiune({
    randuri: multe(20), sesiuni: [sesiune({ commandCount: 20 })],
  });
  await purge(db, { accounts: CONT, apply: true, log: () => {} });
  assert.equal(stare.sesiuni[0].commandCount, 20);
  const scrieri = stare.sql.filter((s) => /^\s*UPDATE/i.test(s.q));
  assert.ok(scrieri.length > 0, "nu s-a atins niciun contor");
  for (const s of scrieri) assert.doesNotMatch(s.q, /command_count/);
});

test("contorul numără ce a căzut, nu ce s-a plănuit", async () => {
  /* Expedierea de pe gazdă merge în paralel. Dacă `commands_purged` ar fi «câte
   * am vrut să șterg», un rând sosit între numărătoare și ștergere ar face
   * contorul să pretindă mai mult decât s-a întâmplat. */
  const { db, stare } = conexiune({
    randuri: [...multe(10), rand({ tty: "pts0" })],
    sesiuni: [sesiune({ commandCount: 11 })],
  });
  await purge(db, { accounts: CONT, apply: true, log: () => {} });
  assert.equal(stare.sesiuni[0].commandsPurged, 10);
  assert.equal(stare.randuri.length, 1, "s-a șters rândul cu terminal real");
});

// ---------------------------------------------------------------------------
// Modul pe sesiune
// ---------------------------------------------------------------------------
test("modul pe sesiune șterge tot ce a rulat sesiunea aleasă", async () => {
  /* Istoricul de dinaintea filtrului nu e pe contul de automatizare: deploy-ul
   * se rula sub contul de logare al operatorului, iar `auid` supraviețuiește lui
   * `sudo`. Pe același cont stau și diagnosticele lui, care se păstrează. Ce le
   * deosebește e sesiunea. */
  const { db, stare } = conexiune({
    randuri: [...multe(300, { username: "operator" }),
              ...multe(7, { username: "operator", sessionSourceId: 2 })],
    sesiuni: [sesiune({ username: "operator" }),
              sesiune({ sourceId: 2, username: "operator" })],
  });
  const j = jurnal();
  const r = await purge(db, {
    instanceId: "srv-a", sessionIds: [1], apply: true, log: j.log,
  });

  assert.equal(r.deleted, 300);
  assert.equal(stare.randuri.length, 7, "s-au șters și comenzile de diagnostic");
  assert.equal(stare.sesiuni[1].commandsPurged, 0, "contorul altei sesiuni a fost atins");
  assert.match(j.text(), /indiferent de cont/);
});

test("modul pe sesiune cere instanța: identificatorii se repetă între servere", async () => {
  /* `session_source_id` e `login_sessions.id` DE PE GAZDĂ, iar el se
   * renumerotează de la 1 pe fiecare instanță. Fără instanță, `--sessions 2521`
   * ar șterge sesiunea 2521 a fiecărui server din arhivă. */
  const { db, stare } = conexiune({ randuri: multe(5), sesiuni: [sesiune()] });
  await assert.rejects(
    () => purge(db, { sessionIds: [1], apply: true, log: () => {} }),
    /--instance/);
  assert.deepEqual(stare.sql, [], "a interogat baza fără să știe pe ce instanță");
});

test("o sesiune INTERACTIVĂ e refuzată, nu ștearsă", async () => {
  /* Modul pe sesiune taie TOT ce a rulat sesiunea. Singurul lucru pe care baza
   * îl știe sigur despre «a fost cineva acolo» e fanionul pus pe gazdă la prima
   * comandă cu `tty` real. */
  const { db, stare } = conexiune({
    randuri: multe(50, { tty: "pts0", username: "operator" }),
    sesiuni: [sesiune({ interactive: 1, username: "operator" })],
  });
  const j = jurnal();
  const r = await purge(db, {
    instanceId: "srv-a", sessionIds: [1], apply: true, log: j.log,
  });

  assert.equal(r.refused, true);
  assert.equal(r.deleted, 0);
  assert.equal(stare.randuri.length, 50, "s-a șters o sesiune interactivă");
  assert.match(j.text(), /INTERACTIV/);
});

test("un identificator inexistent e refuzat, nu raportat ca zero", async () => {
  /* «0 rânduri» pentru sesiunea 2251 în loc de 2521 arată exact ca o sesiune
   * deja curățată, iar operatorul pleacă crezând că a terminat. */
  const { db, stare } = conexiune({ randuri: multe(9), sesiuni: [sesiune()] });
  const j = jurnal();
  const r = await purge(db, {
    instanceId: "srv-a", sessionIds: [999], apply: true, log: j.log,
  });

  assert.equal(r.refused, true);
  assert.equal(stare.randuri.length, 9);
  assert.match(j.text(), /999 nu există/);
});

test("listarea arată granița și nu scrie nimic", async () => {
  /* Un deploy are 250 000–560 000 de comenzi, o sesiune de diagnostic a unui om
   * are sute. Un prag scris în cod ar fi o presupunere despre gazda altcuiva;
   * lista ordonată descrescător face diferența vizibilă și lasă alegerea
   * operatorului. */
  const { db, stare } = conexiune({
    randuri: [...multe(300), ...multe(4, { sessionSourceId: 2 }),
              ...multe(50, { sessionSourceId: 3 })],
    sesiuni: [sesiune(), sesiune({ sourceId: 2 }), sesiune({ sourceId: 3 }),
              sesiune({ sourceId: 4, interactive: 1 })],
  });
  const j = jurnal();
  const randuri = await listSessions(db, { limit: 10, log: j.log });

  assert.deepEqual(randuri.map((r) => r.sourceId), [1, 3, 2]);
  assert.deepEqual(stare.sql.filter((s) => /^\s*(DELETE|UPDATE|OPTIMIZE)/i.test(s.q)), []);
  assert.match(j.text(), /--sessions/);
});

test("o listă goală se citește ca goală, nu ca o interogare care n-a mers", async () => {
  const { db } = conexiune({});
  const j = jurnal();
  assert.deepEqual(await listSessions(db, { limit: 10, log: j.log }), []);
  assert.match(j.text(), /niciuna/);
});

// ---------------------------------------------------------------------------
// „Nu știu" nu e „nimic de făcut"
// ---------------------------------------------------------------------------
test("fără conturi, refuză în loc să raporteze zero", async () => {
  /* Replica nu vede `sentinel.yaml`. O listă goală înseamnă că nimeni n-a spus
   * pe cine, iar «0 rânduri» ar arăta identic cu o replică deja curată. */
  const { db, stare } = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  await assert.rejects(() => purge(db, { accounts: [], apply: true }));
  assert.deepEqual(stare.sql, [], "a interogat baza fără să știe ce caută");
});

test("cele două moduri nu se pot combina", async () => {
  /* Două reguli deodată dau un raport din care nu se mai citește ce a căzut și
   * de ce — iar raportul e tot ce are operatorul. */
  const { db } = conexiune({ randuri: multe(10), sesiuni: [sesiune()] });
  await assert.rejects(
    () => purge(db, { accounts: CONT, sessionIds: [1], instanceId: "srv-a", apply: true }),
    /exact unul/);
});

test("linia de comandă refuză fără --accounts, și refuză un flag scris greșit", () => {
  assert.ok(parseArgs([]).error, "fără --accounts ar fi rulat pe nimic");
  assert.ok(parseArgs(["--accounts"]).error);
  assert.ok(parseArgs(["--accounts", "--apply"]).error,
            "`--apply` a fost citit ca nume de cont");
  assert.ok(parseArgs(["--accounts", "a", "--aply"]).error,
            "un flag scris greșit s-a ignorat: cine l-a scris crede că a șters");
  assert.ok(parseArgs(["--accounts", "a", "--optimize"]).error,
            "--optimize fără --apply n-are ce rescrie");

  const bun = parseArgs(["--accounts", "sentinel-deploy, ci", "--apply"]);
  assert.equal(bun.error, undefined);
  assert.deepEqual(bun.accounts, ["sentinel-deploy", "ci"]);
  assert.equal(bun.apply, true);
  assert.equal(bun.optimize, false);
});

test("linia de comandă cere instanța pentru --sessions și refuză un id nenumeric", () => {
  /* `2521,25 30` — cine a tastat asta crede că a dat două sesiuni. O listă tăcut
   * mai scurtă ar lăsa în urmă exact rândurile pe care credea că le-a șters. */
  assert.ok(parseArgs(["--sessions", "2521"]).error, "fără --instance");
  assert.ok(parseArgs(["--instance", "srv-a", "--sessions", "2521,25 30"]).error);
  assert.ok(parseArgs(["--instance", "srv-a", "--sessions", "toate"]).error);
  assert.ok(parseArgs(["--accounts", "a", "--sessions", "1"]).error,
            "cele două moduri deodată");
  assert.ok(parseArgs(["--list-sessions", "--apply"]).error,
            "--list-sessions nu șterge nimic");

  const bun = parseArgs(["--instance", "srv-a", "--sessions", "2521, 2530", "--apply"]);
  assert.equal(bun.error, undefined);
  assert.deepEqual(bun.sessionIds, [2521, 2530]);
  assert.equal(bun.instanceId, "srv-a");

  const listare = parseArgs(["--list-sessions", "--limit", "5"]);
  assert.equal(listare.error, undefined);
  assert.equal(listare.limit, 5);
});

test("implicitul liniei de comandă e uscat", () => {
  /* Un implicit distructiv face dintr-o comandă tastată din curiozitate o
   * arhivă pierdută. */
  assert.equal(parseArgs(["--accounts", "sentinel-deploy"]).apply, false);
  assert.equal(parseArgs(["--instance", "a", "--sessions", "1"]).apply, false);
});

// ---------------------------------------------------------------------------
// Ce NU se atinge
// ---------------------------------------------------------------------------
test("din tabela de sesiuni nu se șterge niciodată nimic", async () => {
  /* «S-a deschis o sesiune de deploy» e faptul cu valoare de securitate, și sunt
   * câteva sute de rânduri. Șterse odată cu comenzile, ar dispărea chiar dovada
   * că automatizarea a intrat pe server.
   *
   * Contoarele LOR se ating, și trebuie: testul de dinainte cerea ca
   * `login_session_entries` să nu apară deloc în instrucțiuni, ceea ce fixa
   * exact bug-ul «558 079 comenzi» deasupra unui tabel gol. */
  const { db, stare } = conexiune({ randuri: multe(100), sesiuni: [sesiune()] });
  await purge(db, { accounts: CONT, apply: true, optimize: true, log: () => {} });
  for (const s of stare.sql) {
    assert.ok(!/^\s*DELETE[\s\S]*login_session_entries/i.test(s.q),
              `ștergere din tabela de sesiuni: ${s.q}`);
    assert.ok(!/DROP|TRUNCATE/i.test(s.q));
  }
  assert.equal(stare.sesiuni.length, 1, "a dispărut un rând de sesiune");
});

test("mb() raportează în MB, fiindcă raportul e citit de un om", () => {
  assert.equal(mb(953_000_000), "908.9 MB");
  assert.equal(mb(0), "0.0 MB");
});
