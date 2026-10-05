#!/usr/bin/env node
/**
 * Leagă de sesiunile lor comenzile replicate fără `session_source_id`.
 *
 *     npm run relink-session-commands                    uscat: numără, nu scrie
 *     npm run relink-session-commands -- --apply         leagă
 *     npm run relink-session-commands -- --instance <id> [--apply]
 *
 * Regula, motivul și ce NU se leagă sunt în `lib/session-links.ts`. Aici e
 * doar drumul de la argumente la ea, plus conexiunea.
 *
 * **Uscat implicit**, ca `purge-automation`: prima rulare pe baza reală trebuie
 * să arate ce ar atinge înainte să atingă ceva. Sigur de repetat — doar rânduri
 * cu legătura NULL se schimbă, deci a doua rulare cu `--apply` raportează zero.
 *
 * Ieșire nenulă când, după `--apply`, numărul de rânduri legate nu coincide cu
 * cel numărat dinainte: ori a sosit un lot în timpul rulării, ori instrucțiunile
 * n-au făcut ce se credea, și un cron nu are voie să le confunde cu „gata".
 */

import { createDirectConnection, queryableDb } from "../lib/db";
import { AUTOMATION_DAYS } from "../lib/retention";
import { backfill } from "../lib/session-links";
import type { BackfillReport } from "../lib/session-links";

export type Args = { apply: boolean; instanceId: string; error?: string };

export function parseArgs(argv: string[]): Args {
  const out: Args = { apply: false, instanceId: "" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--apply") out.apply = true;
    else if (arg === "--instance") {
      const v = argv[i + 1];
      if (!v || v.startsWith("--")) {
        return { ...out, error: "--instance cere un identificator de instanță" };
      }
      out.instanceId = v;
      i += 1;
    } else {
      // Un flag scris greșit nu se ignoră: cine a scris `--aply` crede că a legat.
      return { ...out, error: `argument necunoscut: ${arg}` };
    }
  }
  return out;
}

/** Ce spune raportul, pe românește, o instanță pe rând. */
export function describe(r: BackfillReport): string[] {
  const lines = [
    `instanța ${r.instanceId}: ${r.sessions} sesiuni, ` +
    `${r.unlinkedBefore} comenzi fără legătură`,
    r.applied
      ? `  legate acum: ${r.unlinkedBefore - r.unlinkedAfter} ` +
        `(numărate dinainte: ${r.wouldLink}); rămase fără legătură: ${r.unlinkedAfter}`
      : `  s-ar lega: ${r.wouldLink} (uscat — nu s-a scris nimic)`,
  ];
  if (r.prunableByRetention > 0) {
    lines.push(
      `  ATENȚIE: ${r.prunableByRetention} dintre ele aparțin sesiunilor fără ` +
      `terminal mai vechi de ${AUTOMATION_DAYS} zile. Legate, intră sub politica ` +
      "de retenție a automatizărilor și vor fi șterse la prima rulare a " +
      "retenției — NELEGATE, rămâneau 180 de zile.");
  }
  if (r.ambiguous.length > 0) {
    lines.push(`  nelegate dinadins (aceeași cheie, intervale suprapuse): ` +
               `sesiunile ${r.ambiguous.join(", ")}`);
  }
  if (r.unreadable.length > 0) {
    lines.push(`  cu dată necitibilă, sărite: sesiunile ${r.unreadable.join(", ")}`);
  }
  return lines;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.error) {
    console.error(args.error);
    console.error("folosire: npm run relink-session-commands -- [--instance <id>] [--apply]");
    return 2;
  }
  const connection = await createDirectConnection();
  try {
    const reports = await backfill(queryableDb(connection), {
      instanceId: args.instanceId || undefined,
      apply: args.apply,
      automationDays: AUTOMATION_DAYS,
    });
    if (reports.length === 0) {
      console.error("nicio instanță cu sesiuni de legat — baza e goală sau instanța cerută nu există");
      return 2;
    }
    let mismatch = false;
    for (const report of reports) {
      for (const line of describe(report)) console.log(line);
      if (report.applied
          && report.unlinkedBefore - report.unlinkedAfter !== report.wouldLink) {
        mismatch = true;
        console.error(`  NU COINCID: s-au numărat ${report.wouldLink}, ` +
                      `baza arată ${report.unlinkedBefore - report.unlinkedAfter}`);
      }
    }
    return mismatch ? 1 : 0;
  } finally {
    await connection.end();
  }
}

// Rulat direct, nu importat de teste.
if (process.argv[1] && process.argv[1].endsWith("relink-session-commands.ts")) {
  main().then((code) => { process.exitCode = code; },
              (err) => { console.error(err); process.exitCode = 1; });
}
