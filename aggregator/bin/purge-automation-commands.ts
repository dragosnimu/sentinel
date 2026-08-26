#!/usr/bin/env node
/**
 * Linia de comandă a curățării istoricului de automatizări, pe replică.
 *
 *     npm run purge-automation -- --accounts sentinel-deploy
 *                                     uscat: numără și raportează, nu scrie
 *     npm run purge-automation -- --accounts sentinel-deploy --apply
 *                                     șterge, în tranșe
 *     npm run purge-automation -- --accounts sentinel-deploy --apply --optimize
 *                                     și rescrie tabela, ca să întoarcă spațiul
 *
 *     npm run purge-automation -- --list-sessions
 *                                     ce sesiuni fără terminal sunt, cele mai
 *                                     grase întâi. Nu șterge nimic.
 *     npm run purge-automation -- --instance <id> --sessions 2521,2530 --apply
 *                                     șterge TOATE comenzile sesiunilor alese
 *
 * Regula și motivele ei sunt în `lib/purge-automation.ts`. Aici e doar drumul
 * de la argumente la ea, plus conexiunea.
 *
 * ## De ce două moduri
 *
 * Modul pe cont oglindește filtrul viu de pe gazdă: contul de automatizare, fără
 * terminal. Modul pe sesiune e pentru istoricul de DINAINTEA filtrului, care pe
 * gazdă nu e pe contul de automatizare deloc — deploy-ul se rula sub contul de
 * logare al operatorului, iar `auid` supraviețuiește lui `sudo`. Pe același cont
 * stau și diagnosticele lui, care trebuie păstrate; ce le deosebește e sesiunea,
 * nu contul. De-aia identificatorii se dau explicit, după ce operatorul s-a uitat
 * la listă.
 *
 * **Conturile nu au valoare implicită.** Numele contului de automatizare stă în
 * `sentinel.yaml`, pe gazdă, iar replica nu-l vede — un implicit scris aici ar
 * fi o presupunere despre o mașină pe care fișierul ăsta n-o cunoaște. Fără
 * `--accounts`, scriptul refuză și o spune: „nu știu" și „n-am ce curăța" sunt
 * lucruri diferite.
 *
 * Același cont ajunge în tabelă și sub `auid`-ul lui NUMERIC, atunci când nici
 * auditd nici `pwd` n-au putut rezolva un nume — 87 935 de rânduri, măsurat.
 * Replica n-are `/etc/passwd`-ul gazdei, deci nu poate rezolva singură: rularea
 * de pe gazdă tipărește ortografiile pe care le caută, și alea se dau aici.
 *
 * O conexiune singură, nu pool: e o unealtă de întreținere care rulează o dată,
 * la fel ca runner-ul de migrații.
 */

import { createDirectConnection } from "../lib/db";
import { listSessions, purge } from "../lib/purge-automation";

export type Args = {
  accounts: string[];
  sessionIds: number[];
  instanceId: string;
  listSessions: boolean;
  limit: number;
  apply: boolean;
  optimize: boolean;
  error?: string;
};

/** `2521, 2530` → `[2521, 2530]`, sau o eroare pe orice bucată care nu e număr.
 *
 * O bucată nenumerică nu se SARE: cine a tastat `2521,25 30` crede că a dat două
 * sesiuni, iar o listă tăcut mai scurtă ar lăsa exact rândurile pe care crede
 * că le-a șters.
 */
function parseIds(value: string): number[] | string {
  const out: number[] = [];
  for (const bucata of value.split(",")) {
    const t = bucata.trim();
    if (t === "") continue;
    if (!/^[0-9]+$/.test(t)) return `„${t}” nu e un identificator de sesiune`;
    out.push(Number(t));
  }
  return out;
}

export function parseArgs(argv: string[]): Args {
  const out: Args = {
    accounts: [], sessionIds: [], instanceId: "", listSessions: false,
    limit: 40, apply: false, optimize: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const valoare = (): string | null => {
      const v = argv[i + 1];
      if (!v || v.startsWith("--")) return null;
      i += 1;
      return v;
    };
    if (arg === "--apply") out.apply = true;
    else if (arg === "--optimize") out.optimize = true;
    else if (arg === "--list-sessions") out.listSessions = true;
    else if (arg === "--accounts") {
      const v = valoare();
      if (v === null) {
        return { ...out, error: "--accounts cere o listă de nume, separate prin virgulă" };
      }
      out.accounts = v.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (arg === "--sessions") {
      const v = valoare();
      if (v === null) {
        return { ...out, error: "--sessions cere o listă de identificatori, separați prin virgulă" };
      }
      const ids = parseIds(v);
      if (typeof ids === "string") return { ...out, error: `--sessions: ${ids}` };
      out.sessionIds = ids;
    } else if (arg === "--instance") {
      const v = valoare();
      if (v === null) return { ...out, error: "--instance cere un identificator de instanță" };
      out.instanceId = v;
    } else if (arg === "--limit") {
      const v = valoare();
      if (v === null || !/^[0-9]+$/.test(v) || Number(v) < 1) {
        return { ...out, error: "--limit cere un număr pozitiv" };
      }
      out.limit = Number(v);
    } else {
      // Un flag scris greșit nu se ignoră: cine a scris `--aply` crede că a
      // șters, sau — mai rău — crede că n-a șters.
      return { ...out, error: `argument necunoscut: ${arg}` };
    }
  }

  if (out.listSessions) {
    if (out.apply) return { ...out, error: "--list-sessions nu șterge nimic; scoate --apply" };
    return out;
  }
  if (out.accounts.length > 0 && out.sessionIds.length > 0) {
    // Două reguli diferite. Combinate, raportul n-ar mai spune care rânduri au
    // căzut pentru care motiv, iar asta e tot ce are operatorul.
    return { ...out, error: "--accounts și --sessions sunt două moduri diferite; alege unul" };
  }
  if (out.accounts.length === 0 && out.sessionIds.length === 0) {
    return { ...out, error: "lipsește --accounts sau --sessions; nu știu ce rânduri ar trebui să cadă" };
  }
  if (out.sessionIds.length > 0 && out.instanceId === "") {
    return { ...out, error: "--sessions cere și --instance: identificatorii se renumerotează pe fiecare instanță" };
  }
  if (out.optimize && !out.apply) {
    return { ...out, error: "--optimize n-are ce rescrie fără --apply" };
  }
  return out;
}

async function main(): Promise<number> {
  const args = parseArgs(process.argv.slice(2));
  if (args.error) {
    console.error(args.error);
    console.error("folosire: npm run purge-automation -- --accounts <a,b> " +
                  "[--apply] [--optimize]");
    console.error("          npm run purge-automation -- --list-sessions [--limit N]");
    console.error("          npm run purge-automation -- --instance <id> " +
                  "--sessions <id,id> [--apply]");
    return 2;
  }

  const connection = await createDirectConnection();
  try {
    if (args.listSessions) {
      await listSessions(connection, { limit: args.limit });
      return 0;
    }
    const rezultat = await purge(connection, {
      accounts: args.accounts.length > 0 ? args.accounts : undefined,
      sessionIds: args.sessionIds.length > 0 ? args.sessionIds : undefined,
      instanceId: args.instanceId || undefined,
      apply: args.apply,
      optimize: args.optimize,
    });
    // Ieșire nenulă când garda a refuzat sau când a mai rămas ceva: un cron care
    // ar rula asta trebuie să poată deosebi „gata" de „n-am făcut nimic".
    if (rezultat.refused) return 2;
    return args.apply && rezultat.remaining > 0 ? 1 : 0;
  } finally {
    await connection.end();
  }
}

// Rulat direct, nu importat de teste.
if (process.argv[1] && process.argv[1].endsWith("purge-automation-commands.ts")) {
  main().then((code) => { process.exitCode = code; },
              (err) => { console.error(err); process.exitCode = 1; });
}
