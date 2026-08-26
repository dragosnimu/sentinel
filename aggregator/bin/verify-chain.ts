#!/usr/bin/env node
/**
 * Verificarea programată a lanțului de audit, pentru toate instanțele.
 *
 *     npm run verify-chain
 *
 * Se rulează din cron pe găzduire. Verificarea de la ingestie se uită doar la
 * fereastra abia sosită și la joncțiunea ei; asta parcurge TOT ce e stocat,
 * fiindcă o ruptură poate fi introdusă și de altcineva decât conducta — o
 * restaurare parțială, un panou de administrare al găzduirii, o injecție.
 * Verificarea care se uită numai la ce tocmai a sosit n-ar vedea niciodată o
 * tăietură făcută în urmă.
 *
 * Parcurgerea e de la capăt, nu de la `verified_through`: reluarea de acolo ar
 * însemna să credem pe cuvânt rezultatul rulării anterioare, adică exact ce nu
 * se poate presupune despre o arhivă pe care altcineva o poate atinge.
 *
 * ## Codul de ieșire
 *
 *   0  nicio ruptură (inclusiv instanțe pentru care verdictul e „nu se poate
 *      ști încă" — spus pe față în ieșire, nu ascuns în cod)
 *   1  cel puțin o instanță cu lanțul RUPT
 *   2  nu se poate rula (configurație lipsă)
 *
 * Codul e singurul semnal automat pe care îl are agregatorul: **nu există canal
 * de alertare aici** (martorul are Telegram, ăsta nu). Un cron care trimite
 * ieșirea non-zero prin poștă e o posibilitate a operatorului, nu ceva livrat de
 * proiectul ăsta. Vezi README, secțiunea despre verificarea lanțului.
 */

import { createDirectConnection, queryableDb } from "../lib/db";
import { readState, recordVerdict, verifyStoredChain } from "../lib/chain";

async function main(): Promise<number> {
  if (process.argv.slice(2).length) {
    console.error("`verify-chain` nu ia argumente");
    return 2;
  }

  const connection = await createDirectConnection();
  try {
    const db = queryableDb(connection);
    const rows = await db.all(
      "SELECT instance_id FROM instances ORDER BY instance_id");
    if (!rows.length) {
      console.log("nicio instanță înregistrată — nimic de verificat");
      return 0;
    }

    let broken = 0;
    let unknown = 0;
    for (const row of rows) {
      const id = String(row.instance_id);
      // Starea consemnată se citește ÎNAINTE: capătul de jos fixat la prima
      // verificare e ce deosebește o trunchiere de un prag de backfill.
      const known = await readState(db, id);
      const verdict = await verifyStoredChain(db, id, known ?? undefined);
      await recordVerdict(db, id, verdict, "scheduled");

      if (verdict.status === "broken") {
        broken++;
        console.error(`${id}: LANȚ RUPT la source_id ${verdict.breakSourceId} — ` +
                      `${verdict.detail}`);
      } else if (verdict.status === "unknown") {
        unknown++;
        console.log(`${id}: nu se poate spune (${verdict.detail}) — ` +
                    `NU înseamnă „e în regulă"`);
      } else {
        console.log(`${id}: ${verdict.checkedLinks} legături verificate, ` +
                    `până la source_id ${verdict.verifiedThrough}`);
      }
    }

    console.log(`${rows.length} instanțe: ${broken} rupte, ${unknown} nedecise`);
    // Instanțele dezactivate se verifică și ele, dinadins: `enabled = 0`
    // oprește ingestia, nu păstrarea. Arhiva unei mașini scoase din uz e chiar
    // genul de dovadă pe care cineva ar vrea s-o schimbe după ce nimeni nu se
    // mai uită la ea.
    return broken ? 1 : 0;
  } finally {
    await connection.end();
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  },
);
