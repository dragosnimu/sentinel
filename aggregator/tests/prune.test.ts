/**
 * Reconcilierea: singura operație din agregator care ȘTERGE.
 *
 * Există fiindcă ingestia e numai upsert, deci un rând șters pe serverul
 * monitorizat rămâne aici pentru totdeauna. Măsurat pe 21 august 2026, la o oră
 * după ce fluxul `selfcheck_state` a început să curgă: serverul avea 43 de
 * verificări, panoul 44 — a 44-a era una ștearsă cu zile în urmă, arătată în
 * continuare ca o problemă deschisă.
 *
 * Fiecare test de aici e un fel de a șterge rânduri care nu trebuiau șterse.
 * Nu sunt cazuri de margine: o listă goală, una tăiată pe drum, sau una sosită
 * pentru fluxul greșit produc toate un `DELETE` perfect valid, care iese cu
 * succes și lasă în urmă un panou fără date. Spre deosebire de restul
 * defectelor din depozitul ăsta, ăsta nu se repară singur la runda următoare.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  MAX_PRUNE_KEYS, MAX_PRUNE_KEY_BYTES, applyPrune, checkPruneList, pruneSql,
} from "../lib/prune";
import { streamFor } from "../lib/streams";

const SELFCHECK = streamFor("selfcheck_state")!;
const AUDIT = streamFor("audit_log")!;

test("fluxul reconciliabil acceptă o listă obișnuită", () => {
  const v = checkPruneList(SELFCHECK, "selfcheck_state", ["a", "b"]);
  assert.equal(v.ok, true);
  assert.deepEqual(v.ok && v.keys, ["a", "b"]);
});

test("un flux care nu declară `pruneKey` NU poate fi reconciliat", () => {
  // `audit_log` e arhiva care există tocmai ca să nu poată fi ștearsă de pe
  // mașina monitorizată. O listă acceptată aici ar șterge fiecare intrare care
  // nu e în ea — adică ar da înapoi exact proprietatea pentru care s-a construit
  // agregatorul.
  const v = checkPruneList(AUDIT, "audit_log", ["1", "2"]);
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.detail, /reconciliabil/);
});

test("un flux necunoscut e refuzat, nu ignorat", () => {
  const v = checkPruneList(undefined, "inventat", ["a"]);
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.detail, /nu e cunoscut/);
});

test("o listă GOALĂ e refuzată — ar goli tabelul", () => {
  // „Sursa nu mai are nimic" și „lista s-a pierdut pe drum" arată identic. Din
  // două citiri posibile se alege cea care nu golește un tabel.
  const v = checkPruneList(SELFCHECK, "selfcheck_state", []);
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.detail, /goal/);
});

test("o listă peste plafon e refuzată — a fost tăiată pe drum", () => {
  // Expeditorul o OMITE mai degrabă decât s-o taie. Una sosită oricum înseamnă
  // că altcineva a tăiat-o, iar o listă tăiată prezentată ca fiind completă
  // șterge rânduri reale.
  const keys = Array.from({ length: MAX_PRUNE_KEYS + 1 }, (_, i) => `k${i}`);
  const v = checkPruneList(SELFCHECK, "selfcheck_state", keys);
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.detail, /plafon/);
});

test("o listă de exact cât plafonul trece", () => {
  const keys = Array.from({ length: MAX_PRUNE_KEYS }, (_, i) => `k${i}`);
  assert.equal(checkPruneList(SELFCHECK, "selfcheck_state", keys).ok, true);
});

test("ce nu e listă, sau conține altceva decât șiruri, e refuzat", () => {
  for (const bad of [null, "abc", 7, { a: 1 }]) {
    assert.equal(checkPruneList(SELFCHECK, "selfcheck_state", bad).ok, false,
                 `${JSON.stringify(bad)} a fost acceptat ca listă`);
  }
  for (const bad of [[1], [null], [""], [{ }]]) {
    assert.equal(checkPruneList(SELFCHECK, "selfcheck_state", bad).ok, false,
                 `${JSON.stringify(bad)} a fost acceptat ca listă de chei`);
  }
});

test("o cheie mai lungă decât coloana e refuzată", () => {
  // O cheie care n-a putut fi scrisă niciodată în coloană nu se poate potrivi cu
  // niciun rând, deci ar contribui doar la lista de „păstrează" fără efect — iar
  // prezența ei înseamnă că cele două capete nu vorbesc despre aceeași schemă.
  const long = "k".repeat(MAX_PRUNE_KEY_BYTES + 1);
  const v = checkPruneList(SELFCHECK, "selfcheck_state", [long]);
  assert.equal(v.ok, false);
  assert.match(v.ok ? "" : v.detail, /octe/);
});

test("cheile multi-octet se măsoară în OCTEȚI, nu în caractere", () => {
  // `varchar(190)` e o limită de octeți în MySQL. Măsurată în caractere, o cheie
  // cu diacritice ar trece de verificare și ar fi tăiată de bază.
  const key = "ă".repeat(MAX_PRUNE_KEY_BYTES); // 2 octeți fiecare
  assert.equal(checkPruneList(SELFCHECK, "selfcheck_state", [key]).ok, false);
});

test("SQL-ul ștergerii poartă `instance_id` ca PRIM parametru", () => {
  // Fără el, lista unui server ar șterge rândurile celorlalte — chiar granița pe
  // care e construită toată autorizarea panoului.
  const sql = pruneSql(SELFCHECK, 3);
  assert.match(sql, /WHERE instance_id = \?/,
               "ștergerea nu e mărginită la o instanță");
  assert.ok(sql.indexOf("instance_id = ?") < sql.indexOf("NOT IN"),
            "`instance_id` trebuie să fie primul parametru, ca lista să vină după");
  assert.match(sql, /check_key NOT IN \(\?, \?, \?\)/);
  assert.match(sql, /^DELETE FROM selfcheck_state_entries /);
});

test("ștergerea numără prin efect, nu prin ce raportează driverul", async () => {
  // `affectedRows` diferă între drivere și configurații, iar numărul ăsta e
  // singura cifră pe care o vede operatorul despre o operație care șterge.
  const seen: { sql: string; params: unknown[] }[] = [];
  let remaining = 44;
  const db = {
    async run(sql: string, params: unknown[]) {
      seen.push({ sql, params });
      remaining = 43;
    },
    async all(_sql: string, _params: unknown[]) {
      return [{ n: remaining }];
    },
  };

  const gone = await applyPrune(db, SELFCHECK, "inst-a", ["a", "b"]);
  assert.equal(gone, 1, "numărul de rânduri dispărute nu e cel măsurat");
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0].params, ["inst-a", "a", "b"]);
});

test("o ștergere care nu a schimbat nimic raportează zero, nu un număr negativ",
     async () => {
  const db = {
    async run() { /* nimic nu se potrivește */ },
    async all() { return [{ n: 43 }]; },
  };
  assert.equal(await applyPrune(db, SELFCHECK, "inst-a", ["a"]), 0);
});
