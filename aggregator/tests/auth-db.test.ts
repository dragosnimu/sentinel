/**
 * Adaptorul de bază de date al autentificării: „«Nu știu» nu e «zero»".
 *
 * `lib/auth/db.ts` e trei funcții și un docstring care susține chiar proprietatea
 * pe care stau două decizii de securitate. Până la testele astea, niciuna dintre
 * ele n-a fost văzută picând.
 *
 * ## Ce se strică pentru operator dacă `write` răspunde 0 în loc să arunce
 *
 * Numărul de rânduri afectate ESTE răspunsul, în două locuri:
 *
 *   * consumarea contorului TOTP (`UPDATE … WHERE … AND (totp_last_counter IS
 *     NULL OR totp_last_counter < ?)`) — 0 înseamnă „codul ăsta a fost deja
 *     folosit", deci REFUZ. Un driver care nu spune câte rânduri a atins ar
 *     produce 0, iar un cod TOTP capturat de pe umărul operatorului ar putea fi
 *     reluat de câte ori vrea cineva... sau, în cealaltă direcție, un cod
 *     legitim ar fi respins la fiecare autentificare, ceea ce e o pană;
 *   * revocarea unei sesiuni — 0 înseamnă „sesiunea nu exista sau era deja
 *     revocată". Raportat așa dintr-un „nu știu", panoul ar spune că a
 *     deconectat o sesiune pe care n-a atins-o.
 *
 * Ambele minciuni pornesc din același loc, și în direcții opuse. De-aia ce nu se
 * știe se ARUNCĂ.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { authDb } from "../lib/auth/db";
import type { Queryable } from "../lib/db";

/** Un driver fals care întoarce exact ce i se spune, și ține minte ce a primit. */
function driver(answer: [unknown, unknown]): Queryable & {
  calls: { sql: string; params?: unknown[] }[];
} {
  const calls: { sql: string; params?: unknown[] }[] = [];
  return {
    calls,
    async query(sql: string, params?: unknown[]): Promise<[unknown, unknown]> {
      calls.push({ sql, params });
      return answer;
    },
  };
}

test("`write` întoarce câte rânduri a atins instrucțiunea", async () => {
  const q = driver([{ affectedRows: 1 }, []]);
  const db = authDb(q);
  assert.equal(await db.write("UPDATE users SET totp_last_counter = ?", [7]), 1);
  // Zero e un răspuns legitim când driverul chiar l-a spus: „n-a potrivit
  // nimic" e ce refuză un cod TOTP reluat.
  const none = authDb(driver([{ affectedRows: 0 }, []]));
  assert.equal(await none.write("UPDATE users SET totp_last_counter = ?", [7]), 0);

  // Și instrucțiunea pleacă spre driver cu parametrii ei: legați altfel, ar
  // ajunge lipiți în text sau deloc.
  assert.deepEqual(q.calls, [
    { sql: "UPDATE users SET totp_last_counter = ?", params: [7] },
  ]);
});

test("un driver care NU spune câte rânduri a atins e o eroare, nu un zero", async () => {
  // Forma exactă a lui mysql2 când răspunsul nu e un `OkPacket` — și forma pe
  // care o are un dublu de test scris în grabă.
  for (const answer of [[{}, []], [null, []], [{ affectedRows: undefined }, []],
                        [{ affectedRows: "1" }, []], [[], []]] as [unknown, unknown][]) {
    const db = authDb(driver(answer));
    await assert.rejects(
      () => db.write("UPDATE sessions SET revoked_at = UTC_TIMESTAMP(6) WHERE id = ?", ["x"]),
      /nu a spus câte rânduri/,
      `răspunsul ${JSON.stringify(answer[0])} a fost citit ca un număr de rânduri`);
  }
});

test("`all` întoarce rândurile, iar un răspuns care nu e set de rânduri aruncă", async () => {
  const rows = [{ id: "s1", user_id: 3 }];
  const db = authDb(driver([rows, []]));
  assert.deepEqual(await db.all("SELECT id, user_id FROM sessions WHERE id = ?", ["s1"]),
                   rows);

  // `all` chemat pentru o instrucțiune care nu selectează nimic: driverul dă
  // atunci un `OkPacket`, nu un tablou. Întors ca `[]`, ar arăta ca „sesiunea nu
  // există" — adică o deconectare inexplicabilă în loc de un defect vizibil.
  const notRows = authDb(driver([{ affectedRows: 1 }, []]));
  await assert.rejects(() => notRows.all("UPDATE sessions SET last_seen_at = ?", [1]),
                       /nu a întors un set de rânduri/);
});

test("parametrii lipsă devin o listă goală, nu `undefined`", async () => {
  // `db.all(sql)` fără parametri e forma din cod pentru interogările fixe. Dat
  // mai departe ca `undefined`, mysql2 tratează instrucțiunea ca netratată
  // (`execute` aruncă), iar simptomul ar fi o rută care pică doar pe drumul ăla.
  const q = driver([[], []]);
  await authDb(q).all("SELECT 1 FROM sessions WHERE 1 = 0");
  const w = driver([{ affectedRows: 0 }, []]);
  await authDb(w).write("UPDATE sessions SET last_seen_at = UTC_TIMESTAMP(6)");
  assert.deepEqual(q.calls[0].params, []);
  assert.deepEqual(w.calls[0].params, []);
});
