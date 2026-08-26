#!/usr/bin/env node
/**
 * Linia de comandă a instanțelor agregatorului.
 *
 *     npm run instance -- list
 *     npm run instance -- register <instance_id> [--label "text"]
 *     npm run instance -- rotate   <instance_id>
 *     npm run instance -- disable  <instance_id>
 *     npm run instance -- enable   <instance_id>
 *
 * Secretul NU se dă pe linia de comandă — `argv` se vede în lista de procese și
 * rămâne în istoricul shellului. Vine din `SENTINEL_SHIP_SECRET`, dintr-un
 * prompt ascuns, sau de la intrarea standard; vezi `lib/secret-input.ts`.
 *
 * O conexiune singură, nu pool, ca la `bin/migrate.ts`: e un proces de o
 * singură treabă, iar un pool ar ține conexiuni deschise degeaba.
 *
 * ## Ce NU face
 *
 * Nu șterge o instanță. `migrations/0001_core.sql` spune de ce: `enabled = 0`
 * oprește ingestia ȘI păstrează istoria, iar `audit_entries` e o arhivă care nu
 * trebuie să poată fi ștearsă de aici. O instanță scoasă din uz se dezactivează.
 */

import { SecretBox } from "../lib/crypto";
import { createDirectConnection, queryableDb } from "../lib/db";
import { readMasterSecret } from "../lib/env";
import {
  USAGE, checkSecretShape, listInstances, parseArgv, registerInstance, rotateSecret,
  setEnabled,
} from "../lib/register";
import { readShipSecret } from "../lib/secret-input";
import type { WriteResult } from "../lib/register";

function report(result: WriteResult, id: string): number {
  if (!result.ok) {
    console.error(`EȘUAT: ${result.detail}`);
    return 1;
  }
  const done = {
    registered: "înregistrată",
    rotated: "cheie rotită",
    enabled: "ingestie pornită",
    disabled: "ingestie oprită",
  }[result.action];
  // „confirmat prin citire înapoi" nu e o formulă de politețe: fiecare drum de
  // scriere din `lib/register.ts` recitește efectul pe drumul rutei înainte să
  // ajungă aici. Fără asta, linia de mai jos ar raporta intenția.
  console.log(`${id}: ${done} — confirmat prin citire înapoi`);
  if (result.note) console.log(`  atenție: ${result.note}`);
  return 0;
}

async function main(): Promise<number> {
  const parsed = parseArgv(process.argv.slice(2));
  if (!parsed.ok) {
    if (parsed.detail) console.error(parsed.detail);
    console.error(USAGE);
    return 2;
  }
  const { command, id, label } = parsed;

  // Secretul principal ÎNAINTE de conexiune: fără el nimic nu se poate sigila,
  // iar mesajul e altul decât „baza nu răspunde".
  const box = new SecretBox(readMasterSecret());

  let secret = "";
  if (command === "register" || command === "rotate") {
    const read = await readShipSecret();
    if (!read.ok) {
      console.error(`EȘUAT: ${read.detail}`);
      return 2;
    }
    const shape = checkSecretShape(read.raw);
    if (!shape.ok) {
      // Mesajul descrie forma, nu valoarea.
      console.error(`EȘUAT: ${shape.detail}`);
      return 2;
    }
    secret = shape.secret;
  }

  const connection = await createDirectConnection();
  try {
    const db = queryableDb(connection);
    switch (command) {
      case "register":
        return report(await registerInstance(db, id, secret, box, label), id);
      case "rotate":
        return report(await rotateSecret(db, id, secret, box), id);
      case "enable":
        return report(await setEnabled(db, id, true, box), id);
      case "disable":
        return report(await setEnabled(db, id, false, box), id);
      case "list": {
        const rows = await listInstances(db, box);
        if (!rows.length) {
          console.log("nicio instanță înregistrată — ruta de sincronizare va " +
                      "răspunde 401 oricui");
          return 0;
        }
        for (const row of rows) {
          const state = row.enabled ? "activă  " : "OPRITĂ  ";
          const key = { ok: "cheie ok", unreadable: "CHEIE ILIZIBILĂ",
                        missing: "FĂRĂ CHEIE" }[row.key];
          console.log(`${row.instanceId}  ${state}  ${key}` +
                      `  ultimul lot: ${row.lastBatchAt ?? "niciodată"}` +
                      (row.label ? `  (${row.label})` : ""));
        }
        // Stările care se citesc greșit dacă nu sunt explicate: amândouă produc
        // 500 la rută, adică EXACT ce vede operatorul serverului ca „agregator
        // căzut", și niciuna nu se repară de pe partea lui.
        if (rows.some((r) => r.key !== "ok")) {
          console.log("\n`CHEIE ILIZIBILĂ` = SENTINEL_AGGREGATOR_SECRET a fost " +
                      "rotit sau rândul a fost umblat; `FĂRĂ CHEIE` = instanța " +
                      "nu a fost niciodată înregistrată complet. În ambele " +
                      "cazuri ruta răspunde 500 pentru instanța aia. Repară cu " +
                      "`rotate`.");
        }
        return 0;
      }
      default:
        console.error(USAGE);
        return 2;
    }
  } finally {
    await connection.end();
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    // Doar mesajul, niciodată stiva: o urmă de stivă dintr-o eroare de driver
    // poate purta parametrii interogării, iar unul dintre ei e textul cifrat.
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  },
);
