/**
 * Nicio îmbinare din SQL-ul agregatorului nu uită `instance_id`.
 *
 * ## Ce se strică fără garda asta
 *
 * Tabelele replicate poartă toate `instance_id`, iar cheile lor de sursă sunt
 * `(instance_id, source_id)`: `source_id` e id-ul rândului PE SERVERUL LUI, deci
 * două instanțe au aproape sigur incidente, detecții și rânduri de cronologie cu
 * același `source_id`. O îmbinare legată numai pe `source_id` lipește cronologia
 * serverului B sub incidentul serverului A. Nu dă nicio eroare, nu apare în
 * niciun jurnal, iar rezultatul arată exact ca datele cuiva: e cea mai frecventă
 * clasă de defect din designul ăsta, și e o scurgere de date între clienți.
 *
 * ## Două reguli, cu treburi diferite
 *
 * **A. Recunoscătorul.** Găsește o îmbinare CHIAR SCRISĂ — `JOIN <tabelă>
 * [alias] ON|USING` — și cere `instance_id` în clauza ei. Fereastra în care
 * caută se oprește la prima clauză următoare (`WHERE`, `ORDER BY`, alt `JOIN`,
 * `;`…), și asta e chiar miezul: un `JOIN b ON b.source_id = a.source_id WHERE
 * a.instance_id IN (?)` filtrează una dintre tabele și pe cealaltă nu. Dacă
 * fereastra ar merge până la capătul instrucțiunii, tocmai bug-ul ăsta ar trece.
 *
 * **B. Recensământul.** Numără CUVÂNTUL `JOIN` în fiecare fișier livrat și cere
 * ca numărul să fie declarat mai jos. E gard pentru formele pe care
 * recunoscătorul nu le vede: un `CROSS JOIN` fără `ON`, un `STRAIGHT_JOIN`, o
 * scriere la care nu s-a gândit nimeni. Recensământul nu poate spune ce e SQL și
 * ce e proză — și nici nu încearcă: **numără, nu recunoaște**. Prețul e că o
 * frază nouă care pomenește cuvântul înroșește garda până e declarată; ăsta e
 * prețul corect, fiindcă alternativa e o gardă care se poate ocoli scriind
 * altfel.
 *
 * Cele două se prind una pe alta: o îmbinare NOUĂ ridică numărul (B), iar una
 * scrisă în locul unei mențiuni de proză păstrează numărul dar e văzută de (A).
 *
 * ## Ce NU poate garda asta, spus pe față
 *
 *   * **îmbinarea prin virgulă.** `FROM a, b WHERE a.x = b.x` nu conține
 *     cuvântul `JOIN`, deci nu e văzută de niciuna dintre reguli. Nu e o scăpare
 *     ascunsă: e limita unei gărzi care citește text, nu un parser SQL. Ce ține
 *     locul aici e că nicio interogare din `lib/data/` nu numește două tabele,
 *     iar orice interogare nouă trece prin `tests/panel-authz.test.ts`, unde
 *     autorizarea se probează prin efect;
 *   * **SQL construit din bucăți în timpul execuției.** Un `` `JOIN ${t} ON …` ``
 *     e văzut ca text, deci regula A se aplică — dar dacă numele clauzei vine
 *     dintr-o variabilă, ce se citește aici nu mai e ce ajunge la server;
 *   * **că MariaDB execută ce citim noi.** Regulile de aici sunt aserțiuni pe
 *     TEXT, ca cele din `tests/schema.test.ts`. Apără o decizie de proiectare
 *     împotriva ștergerii ei; nu dovedesc nimic despre plan de execuție.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { readShipped, shippedFiles } from "./shipped-files";

/**
 * O îmbinare scrisă, în formele în care MariaDB o acceptă.
 *
 * Fiecare bucată e acolo pentru o formă care ALTFEL ar scăpa:
 *
 *   * `i` — `join incident_entries on …` cu minuscule e forma obișnuită într-un
 *     șir din JavaScript;
 *   * `` ` `` și `"` — ``JOIN `incident_entries` `` e acceptat de server;
 *   * `\s*\.\s*` — numele calificat cu schema (`sentinel_agg.incident_entries`);
 *   * `\s+` peste tot — un `JOIN` pe un rând și `ON` pe următorul e cum arată
 *     orice SQL formatat;
 *   * aliasul opțional, cu sau fără `AS`, dar NICIODATĂ `ON`/`USING` luat drept
 *     alias — altfel `JOIN t ON …` ar fi citit ca „tabela t, aliasul ON".
 */
const JOIN_STATEMENT =
  /\b(?:INNER\s+|CROSS\s+|LEFT\s+(?:OUTER\s+)?|RIGHT\s+(?:OUTER\s+)?|FULL\s+(?:OUTER\s+)?|NATURAL\s+)?JOIN\s+(?:`[^`]+`|"[^"]+"|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:`[^`]+`|"[^"]+"|[A-Za-z_][\w$]*))?(?:\s+(?:AS\s+)?(?!ON\b|USING\b)[A-Za-z_][\w$]*)?\s+(?:ON|USING)\b/gi;

/**
 * Unde se termină clauza unei îmbinări.
 *
 * `STRAIGHT_JOIN` e în listă separat fiindcă `\b` singur nu-l vede: `_` e
 * caracter de cuvânt, deci `\bJOIN\b` nu potrivește înăuntrul lui.
 */
const CLAUSE_END =
  /(?<![.\w$])(?:STRAIGHT_JOIN|JOIN)\b|\b(?:WHERE|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|UNION)\b|;/i;

/** Cât se citește cel mult după o îmbinare. O clauză `ON` mai lungă de atât ar
 *  fi oricum de nerecitit de un om. */
const WINDOW = 400;

/** Cuvântul `JOIN`, oriunde ar fi. `.join(` din JavaScript NU intră: e o metodă
 *  de tablou și apare peste tot, iar un recensământ care o numără e un
 *  recensământ pe care îl șterge cineva în prima zi. */
const JOIN_WORD = /(?<![.\w$])(?:STRAIGHT_JOIN|JOIN)\b/gi;

export type JoinSite = { at: number; clause: string; carriesInstanceId: boolean };

/** Îmbinările scrise într-un text, fiecare cu clauza ei. */
export function joinSites(text: string): JoinSite[] {
  const sites: JoinSite[] = [];
  const finder = new RegExp(JOIN_STATEMENT.source, "gi");
  for (let hit = finder.exec(text); hit !== null; hit = finder.exec(text)) {
    const from = hit.index + hit[0].length;
    const window = text.slice(from, from + WINDOW);
    const end = CLAUSE_END.exec(window);
    const clause = end ? window.slice(0, end.index) : window;
    sites.push({
      at: hit.index,
      clause,
      carriesInstanceId: /\binstance_id\b/.test(clause),
    });
  }
  return sites;
}

/** De câte ori apare cuvântul într-un text. */
export function joinWords(text: string): number {
  return (text.match(JOIN_WORD) ?? []).length;
}

/**
 * Fișierele livrate care au voie să conțină cuvântul, cu numărul exact.
 *
 * O intrare în plus care nu mai corespunde niciunui fișier pică la fel ca una
 * lipsă — ca `MAY_NAME_THE_TABLE` din `tests/auth-attempts-writers.test.ts`, și
 * din același motiv: o scutire moartă e o scutire care într-o zi acoperă
 * altceva.
 */
const JOIN_MENTIONS: Record<string, { count: number; why: string }> = {
  "lib/auth/accounts.ts": {
    count: 2,
    why: "proză: de ce `listAccounts` face două interogări în loc de o îmbinare",
  },
  "lib/data/incidents.ts": {
    count: 2,
    why: "proză: de ce cronologia e o a doua interogare, și ce amestecă o " +
         "îmbinare fără instance_id",
  },
  "lib/purge-automation.ts": {
    count: 1,
    why: "prozÄ: de ce listarea sesiunilor foloseÈte o SUB-INTEROGARE corelatÄ " +
         "Èi nu un `JOIN` â corelarea poartÄ `instance_id` prin construcÈie, iar " +
         "`source_id` singur ar numÄra comenzile altui server sub sesiunea asta",
  },
  "lib/retention.ts": {
    count: 2,
    why: "proză: de ce tăierea comenzilor de automatizare folosește o " +
         "SUB-INTEROGARE și nu un `JOIN` — MariaDB nu acceptă `DELETE … JOIN` " +
         "cu `LIMIT`, iar `LIMIT` e chiar ce ține lock-ul scurt. " +
         "Sub-interogarea E corelată pe `instance_id`, cu testul ei",
  },
};

/**
 * Câte îmbinări SCRISE există azi în tot codul livrat.
 *
 * Zero, și numărul e aici dinadins: fără el, regula „fiecare îmbinare poartă
 * `instance_id`" ar fi verde pentru totdeauna pe o mulțime goală — exact tiparul
 * din `CLAUDE.md`, grep-ul după un șablon care nu există. Când apare prima
 * îmbinare, numărul se schimbă AICI, cu mâna, iar cine îl schimbă se uită la
 * clauza ei.
 */
const SHIPPED_JOIN_STATEMENTS = 0;

test("garda citește tot codul livrat, inclusiv rădăcina proiectului", () => {
  // Fără rădăcină, un `middleware.ts` — care în Next.js TREBUIE să stea acolo —
  // ar putea purta orice interogare, invizibil pentru regulile de mai jos.
  const files = shippedFiles();
  assert.ok(files.includes("next.config.mjs"),
            "garda nu vede fișierele din rădăcina proiectului");
  assert.ok(files.includes("lib/data/incidents.ts"),
            "garda nu vede lib/data/, adică chiar stratul pe care îl apără");
  assert.ok(files.includes("migrations/0008_auth.sql"),
            "garda nu citește SQL-ul din migrații");
});

test("recunoscătorul vede o îmbinare în FIECARE formă acceptată de MariaDB", () => {
  // Formele astea nu sunt inventate ca să treacă testul: sunt cele în care un om
  // chiar scrie SQL. Un recunoscător care le ratează e o gardă verde pentru
  // chiar bug-ul pe care îl caută, iar minusculele și accentele grave au făcut
  // deja asta o dată, în garda de `login_attempts`.
  const forms = [
    "SELECT 1 FROM a JOIN b ON b.instance_id = a.instance_id",
    "select 1 from a join b on b.instance_id = a.instance_id",
    "SELECT 1 FROM a JOIN `b` ON `b`.instance_id = a.instance_id",
    'SELECT 1 FROM a JOIN "b" ON "b".instance_id = a.instance_id',
    "SELECT 1 FROM a JOIN sentinel_agg.b ON b.instance_id = a.instance_id",
    "SELECT 1 FROM a JOIN `sentinel_agg`.`b` ON b.instance_id = a.instance_id",
    "SELECT 1 FROM a\n  JOIN b\n    ON b.instance_id = a.instance_id",
    "SELECT 1 FROM a INNER JOIN b x ON x.instance_id = a.instance_id",
    "SELECT 1 FROM a LEFT OUTER JOIN b AS x ON x.instance_id = a.instance_id",
    "SELECT 1 FROM a RIGHT JOIN b ON b.instance_id = a.instance_id",
    "SELECT 1 FROM a JOIN b USING (instance_id, source_id)",
    "SELECT 1 FROM a JOIN b USING(instance_id)",
  ];
  for (const sql of forms) {
    const sites = joinSites(sql);
    assert.equal(sites.length, 1, `recunoscătorul nu vede îmbinarea: ${sql}`);
    assert.equal(sites[0].carriesInstanceId, true,
                 `îmbinarea poartă instance_id, dar garda n-a văzut-o: ${sql}`);
  }
});

test("o îmbinare FĂRĂ `instance_id` în clauza ei e roșie", () => {
  // Eșecul pe care îl previne, în cuvintele operatorului: cronologia serverului
  // B apare sub un incident al serverului A, fără nicio eroare nicăieri.
  const bad = [
    "SELECT 1 FROM a JOIN b ON b.source_id = a.source_id",
    "select 1 from a join `b` on b.source_id = a.source_id",
    "SELECT 1 FROM a\n  JOIN sentinel_agg.b AS x\n    ON x.source_id = a.source_id",
    "SELECT 1 FROM a JOIN b USING (source_id)",
  ];
  for (const sql of bad) {
    const sites = joinSites(sql);
    assert.equal(sites.length, 1, `recunoscătorul nu vede îmbinarea: ${sql}`);
    assert.equal(sites[0].carriesInstanceId, false,
                 `garda a acceptat o îmbinare fără instance_id: ${sql}`);
  }
});

test("fereastra se oprește la `WHERE` — altfel chiar bug-ul ăsta ar trece", () => {
  // Forma cea mai probabilă a defectului: una dintre tabele e filtrată pe
  // instanță, cealaltă nu. Dacă fereastra ar merge până la capătul
  // instrucțiunii, `instance_id` din `WHERE` ar face îmbinarea să pară corectă.
  const sql =
    "SELECT 1 FROM incident_entries i " +
    "  JOIN incident_timeline_entries t ON t.incident_source_id = i.source_id " +
    " WHERE i.instance_id IN (?, ?)";
  const sites = joinSites(sql);
  assert.equal(sites.length, 1);
  assert.equal(sites[0].carriesInstanceId, false,
               "`instance_id` din WHERE a fost citit ca parte din clauza " +
               "îmbinării; garda ar accepta atunci exact defectul pe care există " +
               "să-l oprească");
});

test("a doua îmbinare din aceeași interogare e judecată separat", () => {
  // O interogare cu două îmbinări, prima corectă și a doua nu: fără oprirea la
  // următorul `JOIN`, `instance_id` din prima clauză ar acoperi-o pe a doua.
  const sql =
    "SELECT 1 FROM a " +
    "  JOIN b ON b.instance_id = a.instance_id " +
    "  JOIN c ON c.source_id = a.source_id";
  const sites = joinSites(sql);
  assert.equal(sites.length, 2, "a doua îmbinare nu a fost văzută");
  assert.equal(sites[0].carriesInstanceId, true);
  assert.equal(sites[1].carriesInstanceId, false,
               "a doua îmbinare a fost acoperită de clauza primei");
});

test("proza nu e citită ca instrucțiune de către recunoscător", () => {
  // Jumătate din fișierele stratului de date explică în proză DE CE nu fac o
  // îmbinare. O gardă care le-ar număra pe alea ca instrucțiuni ar fi ștearsă de
  // primul om care o citește — argumentul e cel din
  // `tests/auth-attempts-writers.test.ts`.
  for (const prose of [
    " * Fiindcă un JOIN care uită `instance_id` amestecă două servere.",
    "// două interogări, niciun JOIN",
    " * Vezi `tests/joins.test.ts` pentru garda care numără îmbinările.",
  ]) {
    assert.deepEqual(joinSites(prose), [],
                     `recunoscătorul citește proza ca instrucțiune: ${prose}`);
  }
  // Dar recensământul le NUMĂRĂ pe toate — asta e diferența dintre cele două
  // reguli, și e ce face ca o formă neprevăzută să nu poată trece tăcut.
  assert.equal(joinWords(" * un JOIN care uită instance_id"), 1);
  assert.equal(joinWords("parts.join(\", \")"), 0,
               "`.join(` din JavaScript e numărat; garda ar fi zgomot pur");
  assert.equal(joinWords("SELECT 1 FROM a STRAIGHT_JOIN b ON b.x = a.x"), 1,
               "`STRAIGHT_JOIN` nu e numărat, deci ar fi o cale de ocolire");
});

test("recensământ: fiecare fișier livrat care conține cuvântul e declarat", () => {
  const found: Record<string, number> = {};
  for (const file of shippedFiles()) {
    const count = joinWords(readShipped(file));
    if (count > 0) found[file] = count;
  }
  const declared: Record<string, number> = {};
  for (const [file, entry] of Object.entries(JOIN_MENTIONS)) declared[file] = entry.count;

  assert.deepEqual(found, declared,
                   "fișierele livrate care conțin cuvântul `JOIN` nu sunt exact " +
                   "cele declarate în JOIN_MENTIONS, cu numărul lor. Dacă ai " +
                   "adăugat o îmbinare, pune `instance_id` în clauza ei ȘI " +
                   "actualizează numărul; dacă ai adăugat o frază, actualizează " +
                   "numărul. Garda numără, nu recunoaște.");
});

test("fiecare îmbinare din SQL-ul livrat poartă `instance_id` în clauza ei", () => {
  const sites: string[] = [];
  for (const file of shippedFiles()) {
    for (const site of joinSites(readShipped(file))) {
      sites.push(`${file}@${site.at}: ${site.clause.trim().slice(0, 120)}`);
      assert.equal(site.carriesInstanceId, true,
                   `${file}: o îmbinare fără \`instance_id\` în clauza ei. ` +
                   "`source_id` e id-ul rândului pe serverul lui, deci două " +
                   "instanțe au aceleași valori: legate doar pe el, datele a " +
                   `două servere se amestecă tăcut. Clauza: ${site.clause.trim()}`);
    }
  }
  // Și numărul lor, ca regula de sus să nu fie verde pe o mulțime goală.
  assert.equal(sites.length, SHIPPED_JOIN_STATEMENTS,
               `îmbinări găsite în codul livrat: ${JSON.stringify(sites, null, 2)}\n` +
               "Numărul lor e declarat în SHIPPED_JOIN_STATEMENTS. Dacă ai scris " +
               "prima îmbinare, schimbă numărul acolo — și uită-te la clauza ei.");
});

test("regula chiar refuză — declanșată izolat, pe amândouă jumătățile", () => {
  // O regulă a cărei declanșare n-a fost văzută e o regulă despre care nu se
  // știe pe ce pică. Ca `assertChildDeclarable` din `tests/subrows.test.ts`.
  assert.throws(
    () => assert.deepEqual({ "app/panou/route.ts": 1 }, {}),
    /panou/);

  const sneaked = joinSites(
    "SELECT 1 FROM incident_entries i join `sentinel_agg`.`asset_entries` a\n" +
    "  ON a.source_id = i.asset_source_id\n" +
    " WHERE i.instance_id IN (?)");
  assert.equal(sneaked.length, 1);
  assert.throws(
    () => assert.equal(sneaked[0].carriesInstanceId, true),
    /true/);
});
