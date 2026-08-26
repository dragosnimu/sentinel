/**
 * Retenția replicii: ce se taie, ce nu, și de ce în tranșe.
 *
 * Eșecul pe care îl previne, măsurat pe 25 august 2026: la câteva ore după ce
 * fluxul de comenzi a pornit, `session_command_entries` avea **253 MB din 468
 * MB** cât avea toată baza — mai mult decât celelalte unsprezece la un loc, și
 * în creștere cu ~405 000 de rânduri la fiecare deploy.
 *
 * Găzduirea e partajată și are cotă. O bază plină nu se manifestă ca „tabela e
 * mare"; se manifestă ca **ingestia refuzată pentru toate fluxurile**, adică
 * panoul extern îngheață în întregime din cauza unei singure tabele.
 *
 * A doua jumătate, la fel de importantă: o retenție care taie prea mult e mai
 * rea decât una absentă. `audit_entries` e o arhivă înlănțuită prin hash —
 * tăiată, lanțul se rupe și verificarea de integritate devine imposibilă.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AUTOMATION_DAYS, BATCH, MAX_BATCHES, POLICIES, pruneExpired, pruneSql,
} from "../lib/retention";

/** Dublu de pool: numără instrucțiunile și le răspunde după un plan. */
function pool(plan: Record<string, number[]>) {
  const sql: { q: string; params: unknown[] }[] = [];
  const pas: Record<string, number> = {};
  return {
    sql,
    async query(q: string, params: unknown[] = []) {
      sql.push({ q, params });
      // Cheia planului e TABELA plus numărul de zile: două politici împart acum
      // `session_command_entries`, iar un plan cheiat doar pe tabelă le-ar
      // răspunde amândurora la fel — adică testul despre una ar trece din
      // răspunsul celeilalte.
      const tabela = /DELETE FROM (\w+)/.exec(q)?.[1] ?? "";
      const zile = String(params[0] ?? "");
      const cheie = `${tabela}:${zile}`;
      const pasi = plan[cheie] ?? plan[tabela] ?? [0];
      const i = pas[cheie] ?? 0;
      pas[cheie] = i + 1;
      return [{ affectedRows: pasi[Math.min(i, pasi.length - 1)] }];
    },
  } as never;
}

// ---------------------------------------------------------------------------
// Ce se taie, și ce NU
// ---------------------------------------------------------------------------
test("istoricul de comenzi e tăiat", () => {
  const t = POLICIES.map((p) => p.table);
  assert.ok(t.includes("session_command_entries"),
            "tabela care a ajuns la 253 MB nu e în politica de retenție");
  assert.ok(t.includes("login_session_entries"));
});

test("arhiva de audit și incidentele NU se taie niciodată", () => {
  /* `audit_entries` e înlănțuit prin hash: tăiat, lanțul se rupe și verificarea
   * de integritate — singura proprietate pe care replica o poate dovedi despre
   * serverul monitorizat — devine imposibilă. Un incident e o decizie, iar
   * deciziile nu expiră. */
  const t = POLICIES.map((p) => p.table);
  for (const interzis of ["audit_entries", "incident_entries",
                          "incident_timeline_entries"]) {
    assert.ok(!t.includes(interzis),
              `${interzis} a intrat în retenție — vezi de ce nu are voie`);
  }
});

test("sesiunile și comenzile lor au ACEEAȘI fereastră", () => {
  /* Ferestre diferite ar produce sesiuni fără comenzile lor: un rând care spune
   * «s-a logat cineva și a rulat 412 comenzi» fără să poată arăta niciuna. */
  const zile = new Map(POLICIES.map((p) => [p.table, p.days]));
  assert.equal(zile.get("session_command_entries"),
               zile.get("login_session_entries"),
               "o sesiune ar rămâne fără comenzile ei, sau invers");
});

// ---------------------------------------------------------------------------
// Forma instrucțiunii
// ---------------------------------------------------------------------------
test("tăierea e MĂRGINITĂ, ca lock-ul să dureze milisecunde", () => {
  /* Un `DELETE` de sute de mii de rânduri ține un lock lung pe InnoDB și poate
   * face ingestia să expire în timpul lui — adică retenția, menită să prevină o
   * pană, ar produce una. */
  for (const p of POLICIES) {
    assert.match(pruneSql(p), new RegExp(`LIMIT ${BATCH}$`),
                 `${p.table}: tăierea n-are LIMIT`);
  }
});

test("vârsta e un PARAMETRU, nu text interpolat", () => {
  /* `days` vine dintr-o constantă azi. O politică citită vreodată din
   * configurație ar deveni injecție, iar regula «valorile nu se interpolează»
   * nu are excepții care merită ținute minte. */
  for (const p of POLICIES) {
    assert.match(pruneSql(p), /INTERVAL \? DAY/);
    assert.ok(!pruneSql(p).includes(String(p.days)),
              `${p.table}: numărul de zile e scris în instrucțiune`);
  }
});

test("se taie pe coloana de TIMP a tabelei, nu pe id", () => {
  assert.ok(pruneSql(POLICIES[0]).includes(POLICIES[0].column));
  assert.match(pruneSql(POLICIES[0]), /UTC_TIMESTAMP\(6\)/);
});

// ---------------------------------------------------------------------------
// Bucla
// ---------------------------------------------------------------------------
test("o tranșă plină cere alta", async () => {
  const p = pool({ "session_command_entries:180": [BATCH, BATCH, 12] });
  const rezultat = await pruneExpired(p);
  const comenzi = rezultat.find((r) => r.table.includes("180"));
  assert.equal(comenzi?.deleted, BATCH * 2 + 12);
  assert.equal(comenzi?.more, false);
});

test("o tranșă parțială oprește bucla", async () => {
  /* Fără oprire, fiecare rulare ar face `MAX_BATCHES` instrucțiuni degeaba pe o
   * bază deja curată. */
  const p = pool({ "session_command_entries:180": [3] });
  await pruneExpired(p);
  const stergeri = (p as unknown as { sql: { q: string; params: unknown[] }[] }).sql
    .filter((s) => s.q.includes("session_command_entries") && s.params[0] === 180);
  assert.equal(stergeri.length, 1);
});

test("plafonul de tranșe SPUNE că a rămas de tăiat", async () => {
  /* Un plafon tăcut arată identic cu o bază curată — iar diferența e între «am
   * terminat» și «mai e de trei ori atât, revin mâine». */
  const p = pool({ "session_command_entries:180": [BATCH] });
  const rezultat = await pruneExpired(p);
  const comenzi = rezultat.find((r) => r.table.includes("180"));
  assert.equal(comenzi?.more, true);
  assert.equal(comenzi?.deleted, BATCH * MAX_BATCHES);
});

test("o bază fără nimic expirat nu raportează nimic", async () => {
  const p = pool({ session_command_entries: [0], login_session_entries: [0] });
  assert.deepEqual(await pruneExpired(p), []);
});

test("o tabelă care nu există încă nu e o eroare", async () => {
  /* Retenția rulează din cron, iar o bază căreia încă nu i s-a aplicat migrația
   * e o instalare în curs, nu un defect de oprit. */
  const p = {
    async query() {
      throw Object.assign(new Error("nope"), { code: "ER_NO_SUCH_TABLE" });
    },
  } as never;
  assert.deepEqual(await pruneExpired(p), []);
});

test("orice ALTĂ eroare se ridică", async () => {
  /* O eroare înghițită aici lasă baza să crească în tăcere până se umple, iar
   * simptomul de atunci — ingestia refuzată pentru tot — e cel mai greu de legat
   * de cauză. */
  const p = {
    async query() {
      throw Object.assign(new Error("disc plin"), { code: "ER_DISK_FULL" });
    },
  } as never;
  await assert.rejects(() => pruneExpired(p), /disc plin/);
});


// ---------------------------------------------------------------------------
// Comenzile automatizărilor, tăiate devreme
// ---------------------------------------------------------------------------
test("comenzile sesiunilor fără terminal au fereastră mult mai scurtă", () => {
  /* Măsurat pe 25 august 2026: o sesiune de deploy a produs **405 777 de comenzi
   * în 140 de secunde**, iar binarele de sus au fost `systemctl` (320 591) și
   * `sleep` (173 376) — buclele de așteptare ale instalatorului, nu munca lui.
   * Replica a crescut de la 83 MB la 909 MB în câteva ore.
   *
   * Pe gazdă e în regulă. Aici, o bază plină oprește ingestia pentru TOATE
   * fluxurile. */
  const auto = POLICIES.find((p) => p.extra !== undefined);
  assert.ok(auto, "nu există nicio politică pentru comenzile automatizărilor");
  assert.equal(auto.days, AUTOMATION_DAYS);
  assert.ok(auto.days < 30, "fereastra automatizărilor nu e semnificativ mai scurtă");

  const om = POLICIES.find((p) => p.table === "session_command_entries"
                                  && p.extra === undefined);
  assert.ok(om && om.days > auto.days * 5,
            "comenzile oamenilor nu se păstrează semnificativ mai mult");
});

test("o comandă fără sesiune cunoscută NU se taie devreme", () => {
  /* O comandă orfană poate fi a unui om a cărui logare nu s-a văzut — colectorul
   * pornit la mijlocul unei sesiuni, sau înregistrări pierdute de nucleu. „Nu
   * știu a cui e" nu e „e a unui script", iar a le confunda ar șterge exact
   * urmele pe care le caută cineva. */
  const auto = POLICIES.find((p) => p.extra !== undefined);
  assert.ok(auto?.extra?.includes("interactive = 0"),
            "condiția nu cere explicit sesiuni NEinteractive");
  assert.ok(!auto?.extra?.includes("IS NULL"),
            "condiția prinde și comenzile fără sesiune cunoscută");
});

test("condiția de automatizare rămâne legată de instanță", () => {
  /* Sub-interogarea caută în `login_session_entries` — o tabelă care ține
   * sesiunile TUTUROR instanțelor. Fără corelarea pe `instance_id`, comenzile
   * unui server s-ar tăia după sesiunile altuia. */
  const auto = POLICIES.find((p) => p.extra !== undefined);
  assert.ok(auto?.extra?.includes("instance_id = session_command_entries.instance_id"),
            "sub-interogarea nu e corelată pe instanță");
});

test("condiția intră în instrucțiune, nu se pierde", () => {
  const auto = POLICIES.find((p) => p.extra !== undefined);
  assert.ok(auto);
  const sql = pruneSql(auto);
  assert.ok(sql.includes("interactive = 0"), sql);
  assert.match(sql, new RegExp(`LIMIT ${BATCH}$`),
               "condiția a împins `LIMIT` afară din instrucțiune");
});
