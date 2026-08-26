/**
 * CSRF, în două forme, fiindcă etapa dinainte de autentificare n-are sesiune.
 *
 * Geamănul e `sentinel/web/security.py:494-539`, iar regula de ALEGERE între
 * cele două e cea din middleware-ul serverului (`sentinel/web/app.py:192-198`):
 * dacă cererea poartă o sesiune, se cere jetonul SESIUNII; dacă nu, se cere cel
 * pre-autentificare. Nu „oricare dintre ele" — un formular care ar putea trece
 * cu jetonul pre-auth în timp ce o sesiune există ar accepta un jeton care nu e
 * legat de nimic.
 *
 * ## De ce jetonul pre-auth e SEMNAT și nu STOCAT
 *
 * Formularul de login are nevoie de un jeton înainte să existe vreo sesiune.
 * Varianta evidentă — un rând de sesiune de unică folosință care să-l țină — e o
 * negare de serviciu: fiecare `GET /login` devine un `INSERT`, iar cine cere
 * pagina de zece mii de ori pe minut umple tabela. Pe găzduirea partajată,
 * unde aceeași bază servește și arhiva de dovezi a tuturor instanțelor, aia n-ar
 * strica doar autentificarea.
 *
 * Deci cookie-ul poartă un nonce semnat și datat, formularul poartă nonce-ul gol,
 * și amândouă trebuie să fie de acord. Nicio scriere în bază, nimic de epuizat.
 *
 * ## De ce NU sunt de ajuns verificările de origine ale Server Actions
 *
 * Next.js verifică `Origin` față de `Host` la Server Actions. Asta e o apărare
 * reală, dar nu ACOPERĂ etapa de aici, din trei motive scrise ca să nu fie
 * reintrodusă concluzia greșită: rutele astea sunt Route Handlers, nu Server
 * Actions, deci verificarea nu se aplică; verificarea e a framework-ului, deci
 * o versiune care o schimbă schimbă tăcut o proprietate de securitate; și,
 * peste toate, `Origin` nu spune nimic despre faptul că formularul a fost
 * SERVIT de noi, care e chiar ce dovedește perechea cookie/câmp.
 *
 * ## Ce apără, concret, în etapa pre-auth
 *
 * Fără el, o pagină ostilă poate posta `/login` cu credențialele pe care le
 * ALEGE ea — atacul de „login CSRF": victima ajunge autentificată în CONTUL
 * ATACATORULUI fără să observe, și tot ce face mai departe în panou se scrie
 * acolo. Și, mai prozaic, oricine poate arde din afară plafoanele de încercări
 * ale unui cont cunoscut.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

import { deriveKey } from "../crypto";

/** Numele cookie-ului, ca pe server (`security.py:501`). */
export const PREAUTH_CSRF_COOKIE = "sentinel_csrf";

/** Cât trăiește un jeton pre-auth. Ca pe server: 15 minute. */
export const PREAUTH_CSRF_TTL_S = 900;

/** Scopul HKDF. Altul decât al cifrării TOTP și decât al secretelor de instanță:
 *  o slăbiciune într-un context nu are voie să devină una în celălalt. */
export const PREAUTH_CSRF_INFO = "sentinel-aggregator-preauth-csrf-v1";

/** 24 de octeți, ca `secrets.token_urlsafe(24)` pe server. */
const NONCE_BYTES = 24;

/**
 * Comparație în timp constant care nu cade pe lungimi diferite.
 *
 * `timingSafeEqual` ARUNCĂ dacă tampoanele au lungimi diferite, iar un jeton
 * trimis de atacator are exact lungimea pe care o alege el. Fără garda asta,
 * o comparație cu un jeton mai scurt ar fi o excepție în mijlocul rutei, nu un
 * refuz — adică 500 în loc de 403, pe o cale pe care oricine o poate atinge.
 */
export function constantTimeEquals(a: string | null, b: string | null): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length || left.length === 0) return false;
  return timingSafeEqual(left, right);
}

/**
 * Jetonul SESIUNII, comparat cu ce s-a trimis.
 *
 * Legat de o sesiune anume, deci strict mai bun decât cel pre-auth: un jeton
 * valid al altei sesiuni nu trece.
 */
export function csrfValid(sessionCsrfToken: string | null, submitted: string | null): boolean {
  if (!sessionCsrfToken || !submitted) return false;
  return constantTimeEquals(sessionCsrfToken, submitted);
}

export class PreAuthCsrf {
  private readonly key: Buffer;

  /** `sessionSecret` e `SENTINEL_SESSION_SECRET` (vezi `lib/env.ts`). */
  constructor(sessionSecret: string) {
    this.key = deriveKey(sessionSecret, PREAUTH_CSRF_INFO);
  }

  private sign(payload: string): string {
    return createHmac("sha256", this.key).update(payload, "utf8").digest("base64url");
  }

  /** `[valoarea din cookie, valoarea din formular]`. */
  issue(nowMs: number = Date.now()): [string, string] {
    const nonce = randomBytes(NONCE_BYTES).toString("base64url");
    const payload = `${nonce}.${Math.floor(nowMs / 1000)}`;
    return [`${payload}.${this.sign(payload)}`, nonce];
  }

  /**
   * Perechea cookie/formular e validă ACUM?
   *
   * Se verifică toate trei: semnătura (deci cookie-ul e emis de noi), vârsta
   * (deci un cookie vechi rămas într-un browser nu trăiește la nesfârșit) și
   * egalitatea cu câmpul din formular (deci formularul e chiar cel pe care i
   * l-am servit acelui browser). Fără a treia, cookie-ul singur ar fi de ajuns,
   * iar cookie-urile se trimit și de pe o pagină ostilă.
   */
  validate(
    cookieValue: string | null | undefined,
    formValue: string | null | undefined,
    nowMs: number = Date.now(),
  ): boolean {
    if (!cookieValue || !formValue) return false;
    const parts = cookieValue.split(".");
    if (parts.length !== 3) return false;
    const [nonce, issuedAt, signature] = parts;

    const payload = `${nonce}.${issuedAt}`;
    if (!constantTimeEquals(this.sign(payload), signature)) return false;

    // Data se citește DUPĂ semnătură: până acolo, e text ales de cine trimite.
    const issued = Number(issuedAt);
    if (!Number.isFinite(issued)) return false;
    const ageS = Math.floor(nowMs / 1000) - issued;
    // Și un jeton din VIITOR e refuzat: altfel un ceas dat înainte pe mașina
    // care l-a emis ar produce jetoane care nu expiră niciodată.
    if (ageS < 0 || ageS > PREAUTH_CSRF_TTL_S) return false;

    return constantTimeEquals(nonce, formValue);
  }
}
