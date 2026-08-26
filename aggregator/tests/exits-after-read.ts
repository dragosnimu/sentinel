/**
 * Copilul probei „un instrument care a terminat de citit se termină singur".
 *
 * Nu e un test și nu se rulează ca unul: `run-tests.mjs` ia doar `*.test.ts`.
 * E pornit ca PROCES de `tests/secret-input.test.ts`, cu conducta de intrare
 * ținută deschisă de părinte, iar ce se măsoară acolo e dacă procesul ăsta iese
 * fără să-l omoare cineva.
 *
 * De-aia NU cheamă `process.exit`: cu el, proba ar trece și cu fluxul lăsat
 * pornit, adică n-ar mai deosebi nimic. Amândouă uneltele livrate
 * (`bin/user.ts`, `bin/instance.ts`) cheamă azi `process.exit`, deci raza
 * defectului e mică — dar proprietatea e afirmată în capul lui
 * `lib/secret-input.ts`, iar o afirmație pe care n-o ține nimic e chiar felul în
 * care depozitul ăsta a plătit deja o pană.
 */

import { readerFor } from "../lib/secret-input";

async function main(): Promise<void> {
  const line = await readerFor(process.stdin).readLine();
  // JSON, ca `null` (conductă terminată) să nu arate ca o linie goală.
  process.stdout.write(`${JSON.stringify(line)}\n`);
}

void main();
