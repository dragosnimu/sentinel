/**
 * Al doilea factor: TOTP, cu aceeași fereastră ca pe server și cu aceeași
 * protecție la reluare.
 *
 * Geamănul e `sentinel/web/security.py:88-92` și `:216-246`, plus coloana
 * `users.totp_last_counter` din `sentinel/db/migrations/0009_web_session.sql`.
 * Acordul (6 cifre, 30 s, ±1 fereastră) e ținut de
 * `tests/unit/test_aggregator_auth_parity.py`, care nu compară doar numerele:
 * cere ca `pyotp` — biblioteca reală a serverului — și codul de aici să producă
 * ACELAȘI cod pentru același secret și același moment. Un algoritm care diferă
 * (alt digest, alt trunchiere, alt contor) trece de o comparație de constante și
 * pică acolo.
 *
 * ## Trei proprietăți, în ordinea în care se pierd la o rescriere
 *
 * 1. **Codul se CONSUMĂ, nu doar se verifică.** `verifyCode` întoarce contorul
 *    care s-a potrivit, iar apelantul trebuie să-l consume cu
 *    `consumeTotpCounter`. O verificare fără consum lasă codul valabil restul
 *    ferestrei — destul pentru cineva care l-a citit peste umăr, sau care reia o
 *    cerere capturată. Comparația e `<` STRICT și se face în SQL, deci două
 *    cereri simultane cu același cod nu pot câștiga amândouă.
 *
 * 2. **Fereastra e ±1, și se caută CARE contor s-a potrivit.** De-aia bucla e
 *    scrisă pe față și nu se cheamă o funcție `verify(window)`: fără să știm
 *    contorul, n-avem ce consuma. Motivul ferestrei e cel din `security.py`:
 *    ceasurile telefoanelor derapează, iar cine tastează un cod fix când se
 *    rotește nu trebuie să audă că parola lui e greșită.
 *
 * 3. **Secretul stă cifrat în repaus.** Un dump al bazei nu are voie să dea al
 *    doilea factor funcțional — altfel al doilea factor nu mai e un al doilea
 *    factor. Se refolosește `SecretBox` din `lib/crypto.ts` (AES-256-GCM cu AAD),
 *    cu alt scop de derivare; nu există un al doilea format de jeton în depozit.
 *
 * ## Din ce secret se derivă cheia, și de ce nu din cel de ingestie
 *
 * Din `SENTINEL_SESSION_SECRET`, ca pe server (`TOTPCipher`, `security.py:142`),
 * NU din `SENTINEL_AGGREGATOR_SECRET`. Cele două au cicluri de viață diferite, iar
 * argumentul e chiar cel scris în `lib/crypto.ts`, aplicat în ambele direcții:
 * rotirea secretului de sesiune trebuie să deconecteze utilizatorii, nu să oprească
 * tăcut sincronizarea tuturor instanțelor; iar rotirea secretului de ingestie —
 * operația pe care o faci după o compromitere a unei chei de instanță — nu are voie
 * să ceară reînrolarea TOTP a fiecărui om.
 *
 * Ce COSTĂ alegerea asta, scris pe față: rotirea lui `SENTINEL_SESSION_SECRET` face
 * secretele TOTP indescifrabile, deci cere reînrolare. E aceeași consecință ca pe
 * server, unde `TOTPCipher.decrypt` o numește în docstring, iar
 * `verify_second_factor` o duce până la operator ca `totp_undecryptable` în loc de
 * „cod greșit". `decrypt` de aici întoarce `null` din același motiv: „nu se poate
 * descifra" și „cod greșit" cer reacții diferite, iar apelantul trebuie să le poată
 * deosebi.
 *
 * (Comentariul din `lib/crypto.ts` anticipa derivarea cheii de TOTP din secretul
 * principal al agregatorului. Se schimbă aici, cu motivul de mai sus; tabelul de
 * proprietăți din plan cere `SENTINEL_SESSION_SECRET`.)
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { SecretBox } from "../crypto";
import type { AuthDb } from "./db";

// ---------------------------------------------------------------------------
// Parametrii. Identici cu `security.py:88-92`.
// ---------------------------------------------------------------------------
export const TOTP_DIGITS = 6;
export const TOTP_INTERVAL_S = 30;
export const TOTP_VALID_WINDOW = 1;

/** Câți octeți are un secret nou. 20 de octeți = 32 de caractere base32, exact
 *  ce produce `pyotp.random_base32()` pe server. */
export const TOTP_SECRET_BYTES = 20;

/** Scopul HKDF al cheii de cifrare. Altul decât al secretelor de instanță
 *  (`SHIP_SECRET_INFO`), ca o slăbiciune într-un context să nu devină una în
 *  celălalt. Local agregatorului: nimic din el nu pleacă și nimic nu-l compară cu
 *  serverul. */
export const TOTP_SECRET_INFO = "sentinel-aggregator-totp-v1";

/** Numele coloanei, folosit ca parte din AAD. Un blob mutat pe alt rând sau în
 *  altă coloană nu se mai deschide. */
export const TOTP_SECRET_FIELD = "totp_secret_enc";

/** RFC 4648, fără umplutură la generare. */
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export class TotpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TotpError";
  }
}

// ---------------------------------------------------------------------------
// Base32
// ---------------------------------------------------------------------------
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Octeții unui secret base32, sau eroare.
 *
 * Iertător exact cât e util unui om care copiază un secret dintr-un panou:
 * spații și umplutură `=` se ignoră, literele mici se ridică. NU e iertător cu
 * caracterele din afara alfabetului — `Buffer.from(x, "base64")` le-ar sări
 * tăcut și ar produce alți octeți, adică un cod greșit fără nicio eroare, iar
 * lecția e deja scrisă în `lib/crypto.ts` la `decodeStrict`.
 */
export function base32Decode(secret: string): Buffer {
  const cleaned = (secret ?? "").replace(/[\s=]/g, "").toUpperCase();
  if (cleaned.length === 0) throw new TotpError("secret TOTP gol");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    const index = BASE32_ALPHABET.indexOf(ch);
    if (index < 0) throw new TotpError("secret TOTP care nu e base32");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Un secret nou. `randomBytes`, nu `Math.random`: e o cheie. */
export function generateSecret(): string {
  return base32Encode(randomBytes(TOTP_SECRET_BYTES));
}

// ---------------------------------------------------------------------------
// Codurile
// ---------------------------------------------------------------------------
/** Contorul TOTP al unui moment (secunde Unix). */
export function counterAt(unixSeconds: number): number {
  return Math.floor(unixSeconds / TOTP_INTERVAL_S);
}

/**
 * Codul pentru un contor. HOTP (RFC 4226) cu SHA-1, ca `pyotp` — nu fiindcă
 * SHA-1 ar fi o alegere bună azi, ci fiindcă asta implementează fiecare
 * aplicație de autentificare, iar un digest „mai bun" ar produce coduri pe care
 * telefonul operatorului nu le poate genera.
 */
export function codeForCounter(secret: string, counter: number): string {
  const key = base32Decode(secret);
  const message = Buffer.alloc(8);
  message.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  message.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac("sha1", key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
               | ((digest[offset + 1] & 0xff) << 16)
               | ((digest[offset + 2] & 0xff) << 8)
               | (digest[offset + 3] & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

function sameDigits(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "ascii"), Buffer.from(b, "ascii"));
}

/**
 * Verifică un cod și întoarce CONTORUL care s-a potrivit, sau `null`.
 *
 * Contorul se întoarce ca apelantul să-l poată consuma (`consumeTotpCounter`).
 * Fără consum, codul rămâne valabil restul ferestrei lui.
 */
export function verifyCode(
  secret: string, code: string, nowSeconds: number = Date.now() / 1000,
): number | null {
  const cleaned = (code ?? "").trim().replace(/\s+/g, "");
  if (!/^[0-9]+$/.test(cleaned) || cleaned.length !== TOTP_DIGITS) return null;

  const now = counterAt(nowSeconds);
  for (let offset = -TOTP_VALID_WINDOW; offset <= TOTP_VALID_WINDOW; offset++) {
    const counter = now + offset;
    if (sameDigits(codeForCounter(secret, counter), cleaned)) return counter;
  }
  return null;
}

/** URI-ul de înrolare, în forma pe care o citesc aplicațiile de autentificare. */
export function provisioningUri(secret: string, username: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(username)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_INTERVAL_S),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Secretul în repaus
// ---------------------------------------------------------------------------
/**
 * Cine deține secretul, în AAD. Un blob mutat de pe rândul unui utilizator pe al
 * altuia nu se mai deschide — altfel cine poate scrie în bază și-ar muta propriul
 * secret pe contul altcuiva.
 */
function ownerOf(userId: number): string {
  if (!Number.isInteger(userId) || userId <= 0) {
    throw new TotpError("AAD incomplet: cifrarea unui secret TOTP cere id-ul utilizatorului");
  }
  return `user:${userId}`;
}

export class TotpCipher {
  private readonly box: SecretBox;

  /** `sessionSecret` e `SENTINEL_SESSION_SECRET` (vezi `lib/env.ts`). */
  constructor(sessionSecret: string) {
    this.box = new SecretBox(sessionSecret, TOTP_SECRET_INFO);
  }

  encrypt(secret: string, userId: number): string {
    return this.box.seal(secret, { owner: ownerOf(userId), field: TOTP_SECRET_FIELD });
  }

  /**
   * Secretul în clar, sau `null`.
   *
   * `null`, nu excepție, și apelantul trebuie să-l deosebească de „nu are
   * secret": înseamnă că `SENTINEL_SESSION_SECRET` a fost rotit sau că rândul a
   * fost umblat, iar atunci nicio reîncercare nu va reuși vreodată. Operatorului
   * i se spune asta, nu „cod greșit" — vezi `totp_undecryptable` în
   * `security.py`.
   */
  decrypt(token: string, userId: number): string | null {
    return this.box.open(token, { owner: ownerOf(userId), field: TOTP_SECRET_FIELD });
  }
}

// ---------------------------------------------------------------------------
// Consumul contorului
// ---------------------------------------------------------------------------
/**
 * Consumă un contor TOTP, refuzând reluarea. `true` = consumat ACUM.
 *
 * Comparația e în SQL și e STRICT mai mare, deci al doilea `UPDATE` cu același
 * contor nu potrivește niciun rând. Făcut în TypeScript (citește, compară,
 * scrie), două cereri simultane cu același cod ar citi amândouă valoarea veche.
 */
export async function consumeTotpCounter(
  db: AuthDb, userId: number, counter: number,
): Promise<boolean> {
  const affected = await db.write(
    "UPDATE users SET totp_last_counter = ? " +
    " WHERE id = ? AND (totp_last_counter IS NULL OR totp_last_counter < ?)",
    [counter, userId, counter]);
  return affected === 1;
}
