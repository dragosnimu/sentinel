/**
 * Cine e expeditorul și cu ce cheie se verifică lotul lui.
 *
 * ## De ce din BAZĂ, și nu din mediu ca la cheile de heartbeat
 *
 * `lib/beat-keys.ts` — cheile cu care martorul verifică o BĂTAIE — stau într-o
 * variabilă de mediu, fiindcă martorul trebuie să poată raporta și când baza e
 * căzută. Loturile n-au constrângerea aia, iar asta schimbă răspunsul corect din
 * trei motive:
 *
 *   1. **Numărul.** Martorul ține câteva chei de heartbeat. Aici fiecare
 *      instalare adaugă un rând, iar o variabilă de mediu editată de mână într-un
 *      panou web (fără API — vezi `watcher/INCARCARE-HOSTINGER.md`) e chiar
 *      suprafața pe care s-a pierdut deja o zi.
 *   2. **Repausul.** Cheia stă cifrată (`lib/crypto.ts`), legată prin AAD de
 *      `instance_id` ȘI de numele coloanei. Un dump al bazei nu dă chei cu care
 *      se pot fabrica loturi. O variabilă de mediu nu poate avea proprietatea
 *      asta: valoarea ei ESTE cheia.
 *   3. **Starea.** `enabled`, `first_seen_at`, `last_batch_seq` sunt despre
 *      aceeași instanță. Ținute în două locuri, s-ar putea contrazice.
 *
 * ## Ce e „nu știu” aici
 *
 * Trei rezultate diferite, fiindcă cer trei reacții diferite de la operator:
 *
 *   * `unknown` / `disabled` — REFUZ. Expeditorul e respins (401). Istoria lui
 *     rămâne; `enabled = 0` e chiar mecanismul pentru asta (vezi comentariul
 *     coloanei în `migrations/0001_core.sql`).
 *   * `unconfigured` — instanța există, dar nu are cheie instalată. Nu e un
 *     refuz, e o configurație lipsă: 500, ca la martor, fiindcă diferența dintre
 *     „nu sunt configurat" și „te-am refuzat" e exact ce citește cel care
 *     instalează, printr-un `curl`, fără acces la jurnale.
 *   * `unreadable` — cheia e acolo și nu se poate deschide. Ori
 *     `SENTINEL_AGGREGATOR_SECRET` a fost rotit, ori rândul a fost umblat. Tot
 *     500, dar cu altă linie în jurnal: reacția e „restaurează secretul
 *     principal / rescrie cheia instanței", nu „verifică expeditorul".
 *
 * `SecretBox.open` întoarce `null` și pentru un jeton stricat, și pentru unul
 * cifrat cu altă cheie — de-aia `unreadable` nu spune care dintre ele e; ce
 * spune e că nu se poate ști de aici.
 */

import { SecretBox } from "./crypto";
import type { Db } from "./migrate";

/** Numele antetului, minuscule. Vezi nota din `lib/signature.ts`. */
export const INSTANCE_HEADER = "x-sentinel-instance";

/** Coloana în care stă cheia. E și AAD-ul, deci nu e un detaliu de SQL: mutat
 *  blobul în altă coloană, nu se mai deschide (`lib/crypto.ts`). */
export const SHIP_SECRET_FIELD = "ship_secret_enc";

/**
 * Ce forme de identificator sunt acceptate. IDENTIC cu
 * `lib/beat-keys.ts` — două reguli diferite pentru aceeași identitate ar
 * însemna o instanță acceptată la heartbeat și refuzată la sincronizare, cu
 * simptomul „merge heartbeat-ul, nu merge sincronizarea". Acordul dintre cele
 * două tipare e ținut de `tests/unit/test_shipper.py`, care citește ambele
 * fișiere.
 *
 * Primul caracter alfanumeric elimină din start `__proto__`. Restul clasei ține
 * identificatorul folosibil într-un nume de fișier și într-un parametru de URL,
 * și e chiar clasa pe care o presupune separatorul din AAD (`lib/crypto.ts`).
 */
const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export function isValidInstanceId(id: string): boolean {
  return ID_PATTERN.test(id);
}

export type KeyLookup =
  /** Am cheia instanței cerute. */
  | { ok: true; secret: string }
  /** Nu știu de instanța asta, sau identificatorul e malformat. → 401 */
  | { ok: false; reason: "unknown" }
  /** Instanța există, dar operatorul i-a oprit ingestia. → 401 */
  | { ok: false; reason: "disabled" }
  /** Instanța există, dar nu are cheie instalată. → 500 */
  | { ok: false; reason: "unconfigured" }
  /** Cheia e acolo și nu se poate deschide. → 500 */
  | { ok: false; reason: "unreadable" };

/**
 * Cheia de expediere a unei instanțe, decriptată.
 *
 * Ridică doar dacă baza nu răspunde — apelantul deosebește „nu pot citi baza"
 * (503) de orice refuz. Un `try` care ar înghiți excepția aici ar transforma o
 * bază căzută în „instanță necunoscută", adică 401 pentru toate serverele
 * sănătoase, iar operatorul ar căuta o cheie greșită.
 */
export async function lookupInstanceKey(
  db: Db, id: string, box: SecretBox,
  // Sare peste verificarea lui `enabled`. UN SINGUR apelant legitim:
  // `lib/register.ts`, care după ce rotește secretul unei instanțe DEZACTIVATE
  // trebuie totuși să dovedească faptul — că blobul scris se deschide, cu AAD-ul
  // ei. Fără opțiunea asta ar fi nevoie de a doua cale de decriptare, adică de
  // încă o pereche de implementări care pot să nu fie de acord; ruta de ingestie
  // n-are voie să o folosească niciodată, iar testul „o instanță oprită e
  // refuzată" păzește implicitul.
  { ignoreDisabled = false }: { ignoreDisabled?: boolean } = {},
): Promise<KeyLookup> {
  // Înaintea oricărei interogări: un identificator malformat nu are ce căuta
  // nici măcar ca parametru, iar AAD-ul de mai jos se construiește din el.
  if (!isValidInstanceId(id)) return { ok: false, reason: "unknown" };

  const rows = await db.all(
    "SELECT enabled, ship_secret_enc FROM instances WHERE instance_id = ?", [id]);
  if (rows.length !== 1) return { ok: false, reason: "unknown" };
  const row = rows[0];

  // `=== 1`, nu `!== 0`: „nu știu ce e în coloană" nu e permisiune. Aceeași
  // regulă ca la `GET_LOCK` în `lib/migrate.ts`, și din același motiv.
  if (!ignoreDisabled && Number(row.enabled) !== 1) return { ok: false, reason: "disabled" };

  const token = row.ship_secret_enc;
  if (typeof token !== "string" || token === "") {
    return { ok: false, reason: "unconfigured" };
  }

  const secret = box.open(token, { owner: id, field: SHIP_SECRET_FIELD });
  // `=== null`, nu `!secret`: `SecretBox.open` cere explicit ca apelantul să
  // deosebească „nu se poate deschide" de „s-a deschis și e gol". Un `if
  // (!secret)` le-ar confunda, iar confuzia aia e o cheie goală raportată ca
  // secret principal rotit.
  if (secret === null) return { ok: false, reason: "unreadable" };
  if (secret === "") return { ok: false, reason: "unconfigured" };

  return { ok: true, secret };
}
