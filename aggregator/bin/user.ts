#!/usr/bin/env node
/**
 * Linia de comandă a conturilor de panou.
 *
 *     npm run user -- create <utilizator> --role owner|operator|viewer
 *     npm run user -- enroll-totp <utilizator>
 *     npm run user -- grant  <utilizator> <instanță> [--role ...]
 *     npm run user -- revoke <utilizator> <instanță>
 *     npm run user -- list
 *
 * Fără ea nu se poate autentifica nimeni: nu există nicio altă cale prin care un
 * rând să ajungă în `users`. Politica, verificările și scrierile sunt în
 * `lib/auth/accounts.ts` — aici sunt doar intrarea, ieșirea și codul de retur,
 * ca la `bin/instance.ts`, și pentru același motiv: ce se poate testa fără un
 * proces trebuie să stea unde se poate testa.
 *
 * Parola NU se dă pe linia de comandă. `parseUserArgv` refuză `--password` și
 * rudele lui, în loc să le ignore: `argv` se vede în lista de procese a
 * găzduirii partajate, deci valoarea e deja publicată în clipa în care programul
 * o vede.
 *
 * O conexiune singură, nu pool, ca la `bin/migrate.ts` și `bin/instance.ts`.
 *
 * ## Două citiri de pe aceeași intrare, la `create`
 *
 * Parola, apoi codul de confirmare a înrolării. Amândouă vin de pe `stdin`, iar
 * cine le citește e un singur cititor, ținut de FLUX (`readerFor` din
 * `lib/secret-input.ts`). Nu e un amănunt de implementare: până pe 17 august
 * 2026 erau două funcții cu ascultători proprii, prima oprea fluxul la sfârșit,
 * a doua nu-l repornea — deci codul nu se mai citea niciodată, iar contul rămânea
 * fără al doilea factor exact în comanda care există ca să i-l dea.
 *
 * ## Ce NU se poate proba de pe mașina de dezvoltare
 *
 * Citirea fără ecou dintr-un TERMINAL adevărat. Un TTY nu se poate imita fără un
 * pseudo-terminal, iar un dublu care ar pretinde că e unul ar confirma doar
 * imitația (`lib/secret-input.ts` scrie același lucru despre aceeași funcție).
 * Ce e testat, în `tests/accounts.test.ts`, e perechea de citiri — parolă, apoi
 * cod — pe amândouă căile, pe un flux injectat care spune `isTTY` și pe unul care
 * nu; plus toată logica de mai jos, cu un dublu de bază de date. Ce NU e testat
 * de nicăieri e `main()` însuși: are nevoie de o bază de date reală, deci
 * legătura dintre citirile de mai sus și comanda întreagă se vede prima dată pe
 * gazdă.
 */

import { authDb } from "../lib/auth/db";
import { createDirectConnection } from "../lib/db";
import { readSessionSecret } from "../lib/env";
import {
  USAGE, confirmEnrolment, createAccount, dropTotp, enrollTotp, grantInstance,
  listAccounts, setPassword,
  parseUserArgv, readLine, readNewPassword, revokeInstance,
} from "../lib/auth/accounts";
import type { AuthDb } from "../lib/auth/db";
import type { Enrolment } from "../lib/auth/accounts";

/**
 * Secretul, arătat o singură dată.
 *
 * Nu se poate reafișa: în bază stă cifrat cu `SENTINEL_SESSION_SECRET`, iar
 * unealta nu are o comandă care să-l scoată — asta ar fi chiar mecanismul prin
 * care cine capătă acces la găzduire capătă și al doilea factor al tuturor.
 * Pierdut, se reînrolează.
 */
function showEnrolment(enrolment: Enrolment): void {
  console.log("");
  console.log("=".repeat(64));
  console.log(`  ÎNROLARE AL DOILEA FACTOR — ${enrolment.username}`);
  console.log("=".repeat(64));
  console.log("");
  console.log("  Lipește URI-ul în aplicația de autentificare (Aegis, 1Password,");
  console.log("  Google Authenticator) sau introdu secretul de mână:");
  console.log("");
  console.log(`      ${enrolment.uri}`);
  console.log("");
  console.log(`      secret: ${enrolment.secret}`);
  console.log("");
  console.log("  ATENȚIE: se afișează O SINGURĂ DATĂ. În bază e cifrat, deci nu");
  console.log("  poate fi reafișat. Pierdut, rulează `enroll-totp`.");
  console.log("=".repeat(64));
  console.log("");
}

/**
 * Confirmarea: trei încercări, apoi contul rămâne fără al doilea factor.
 *
 * Fără confirmare, o scanare eșuată lasă un cont care cere un cod pe care nu-l
 * poate produce nimeni. De-aia eșecul de aici e un cod de retur nenul și un
 * mesaj care spune exact ce comandă repară situația — nu o linie de avertisment
 * pe care o citește cineva a doua zi.
 *
 * Eșecul are DOUĂ cauze, și nu au voie să arate la fel: „trei coduri greșite"
 * înseamnă că cineva a tastat și n-a nimerit, iar „nu mai e de unde citi"
 * înseamnă că intrarea s-a închis — pe o conductă care s-a terminat odată cu
 * parola, nicio reîncercare n-o să aducă vreodată un cod. Confundate, operatorul
 * ar căuta cauza în aplicația de autentificare.
 */
type Unconfirmed = "wrong-codes" | "no-input";
type Confirmation = { ok: true } | { ok: false; reason: Unconfirmed };

async function confirm(db: AuthDb, enrolment: Enrolment): Promise<Confirmation> {
  for (let attempt = 0; attempt < 3; attempt++) {
    process.stderr.write("Codul afișat de aplicație, pentru confirmare: ");
    const code = await readLine();
    if (code === null) return { ok: false, reason: "no-input" };
    if (await confirmEnrolment(db, enrolment.userId, enrolment.secret, code)) {
      return { ok: true };
    }
    console.error(`Cod incorect. Încercări rămase: ${2 - attempt}`);
  }
  return { ok: false, reason: "wrong-codes" };
}

/** Ce se spune când contul a rămas fără al doilea factor — cu comanda care
 *  repară, fiindcă starea asta nu se repară singură și nu se vede din panou. */
function unconfirmedMessage(reason: Unconfirmed, username: string): string {
  const repair = "Confirmă separat, dintr-un terminal: " +
                 `npm run user -- enroll-totp ${username}`;
  const state = "Contul există, dar nu are al doilea factor, deci `login.ts` îl " +
                "refuză — nu se poate autentifica.";
  if (reason === "no-input") {
    return "Înrolare NECONFIRMATĂ: codul nu s-a putut citi, fiindcă intrarea " +
           "standard s-a închis fără să trimită vreo linie. Codul se cere DUPĂ ce " +
           "se afișează secretul, deci nu poate veni dintr-o conductă care s-a " +
           "terminat mai devreme — cazul obișnuit fiind " +
           `\`pass show panou | npm run user -- create ...\`. ${state} ${repair}`;
  }
  return `Înrolare NECONFIRMATĂ: trei coduri greșite. ${state} ${repair}`;
}

async function main(): Promise<number> {
  const parsed = parseUserArgv(process.argv.slice(2));
  if (!parsed.ok) {
    if (parsed.detail) console.error(`EȘUAT: ${parsed.detail}`);
    console.error(USAGE);
    return 2;
  }

  // Secretul de sesiune ÎNAINTE de conexiune: fără el nu se poate cifra niciun
  // secret TOTP, iar mesajul e altul decât „baza nu răspunde".
  const sessionSecret =
    (parsed.command === "create" && parsed.totp) || parsed.command === "enroll-totp"
      ? readSessionSecret() : "";

  // Parola se citește ÎNAINTE de conexiune, din același motiv pentru care hashul
  // se calculează înaintea inserării: un refuz nu trebuie să lase nimic în urmă.
  let password = "";
  if (parsed.command === "create" || parsed.command === "passwd") {
    const read = await readNewPassword();
    if (!read.ok) {
      console.error(`EȘUAT: ${read.detail}`);
      return 2;
    }
    password = read.password;
  }

  const connection = await createDirectConnection();
  try {
    const db = authDb(connection);
    switch (parsed.command) {
      case "create": {
        const created = await createAccount(db, {
          username: parsed.username, role: parsed.role, password, sessionSecret,
          enrolTotp: parsed.totp,
        });
        if (!created.ok) {
          console.error(`EȘUAT: ${created.detail}`);
          return 1;
        }
        // Contul e scris în bază în ambele cazuri. Ce diferă e dacă mai urmează
        // înrolarea, iar `null` spune exact asta — nu e o valoare lipsă.
        const name = created.value === null ? parsed.username : created.value.username;
        if (created.value !== null) {
          showEnrolment(created.value);
          const confirmed = await confirm(db, created.value);
          if (!confirmed.ok) {
            console.error(unconfirmedMessage(confirmed.reason, created.value.username));
            return 1;
          }
          console.log(`Cont ${name} creat cu rol ${parsed.role}, ` +
                      "al doilea factor activ — confirmat printr-un cod verificat.");
        } else {
          console.log(`Cont ${name} creat cu rol ${parsed.role}, ` +
                      "cu UN SINGUR factor: parola.");
          console.log("Pe găzduire partajată parola e singurul control care a " +
                      "rămas. Al doilea factor se poate adăuga oricând, fără să " +
                      `se refacă contul: npm run user -- enroll-totp ${name}`);
        }
        console.log("Nu vede încă nicio instanță. Dă-i una: " +
                    `npm run user -- grant ${name} <instanță>`);
        return 0;
      }
      case "enroll-totp": {
        const enrolled = await enrollTotp(db, parsed.username, sessionSecret);
        if (!enrolled.ok) {
          console.error(`EȘUAT: ${enrolled.detail}`);
          return 1;
        }
        showEnrolment(enrolled.value);
        const confirmed = await confirm(db, enrolled.value);
        if (!confirmed.ok) {
          console.error(unconfirmedMessage(confirmed.reason, enrolled.value.username));
          return 1;
        }
        console.log(`Al doilea factor reînrolat. ${enrolled.value.revokedSessions} ` +
                    "sesiune/sesiuni revocate.");
        return 0;
      }
      case "passwd": {
        const changed = await setPassword(db, parsed.username, password);
        if (!changed.ok) {
          console.error(`EȘUAT: ${changed.detail}`);
          return 1;
        }
        console.log(`Parola lui ${changed.value.username} a fost schimbată — ` +
                    "confirmat prin citire înapoi, nu prin rânduri afectate. " +
                    `${changed.value.revokedSessions} sesiune/sesiuni revocate.`);
        return 0;
      }
      case "drop-totp": {
        const dropped = await dropTotp(db, parsed.username);
        if (!dropped.ok) {
          console.error(`EȘUAT: ${dropped.detail}`);
          return 1;
        }
        const { username, revokedSessions, hadSecret } = dropped.value;
        console.log(hadSecret
          ? `Al doilea factor scos de la ${username}. Contul intră acum cu ` +
            `parola singură. ${revokedSessions} sesiune/sesiuni revocate.`
          : `${username} nu avea al doilea factor; nimic de scos. ` +
            `${revokedSessions} sesiune/sesiuni revocate.`);
        console.log("Pe găzduire partajată parola e singurul control care " +
                    "rămâne. Se pune la loc oricând: " +
                    `npm run user -- enroll-totp ${username}`);
        return 0;
      }
      case "grant": {
        const granted = await grantInstance(db, parsed.username, parsed.instanceId,
                                            parsed.role);
        if (!granted.ok) {
          console.error(`EȘUAT: ${granted.detail}`);
          return 1;
        }
        const what = granted.value.created ? "drept dat" : "rol schimbat";
        console.log(`${granted.value.username} → ${granted.value.instanceId}: ` +
                    `${what} (${granted.value.role}) — confirmat prin citire înapoi`);
        return 0;
      }
      case "revoke": {
        const revoked = await revokeInstance(db, parsed.username, parsed.instanceId);
        if (!revoked.ok) {
          console.error(`EȘUAT: ${revoked.detail}`);
          return 1;
        }
        console.log(`${revoked.value.username} → ${revoked.value.instanceId}: ` +
                    "drept retras");
        return 0;
      }
      case "list": {
        const rows = await listAccounts(db);
        if (!rows.length) {
          console.log("Niciun cont — nimeni nu se poate autentifica pe panou. " +
                      "Creează primul: npm run user -- create <nume> --role owner");
          return 0;
        }
        for (const row of rows) {
          const state = row.disabled ? "DEZACTIVAT" : "activ     ";
          const factor = { active: "2FA da ", unconfirmed: "2FA RUPT",
                           none: "2FA nu  " }[row.totpState];
          const seen = row.instances.length
            ? row.instances.map((i) => `${i.instanceId}(${i.role})`).join(" ")
            : "nicio instanță";
          console.log(`${row.username.padEnd(20)} ${row.role.padEnd(9)} ${state} ` +
                      `${factor} ${seen}`);
        }
        // Cele două stări fără al doilea factor NU se raportează la fel. Una
        // funcționează, cealaltă e un cont blocat, iar un singur mesaj pentru
        // amândouă a fost chiar ce a trimis operatorul să repare ce mergea.
        if (rows.some((row) => row.totpState === "unconfirmed")) {
          console.log("\n`2FA RUPT` = înrolare începută și neconfirmată. " +
                      "Contul NU se poate autentifica. Termină înrolarea cu " +
                      "`enroll-totp`, sau scoate factorul cu `drop-totp`.");
        }
        if (rows.some((row) => row.totpState === "none")) {
          console.log("\n`2FA nu` = un singur factor, parola. Contul " +
                      "intră normal. Pe găzduire partajată parola e singurul " +
                      "control care rămâne.");
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
    // poate purta parametrii interogării, iar unul dintre ei e hashul parolei.
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  },
);
