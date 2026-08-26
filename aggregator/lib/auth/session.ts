/**
 * Sesiunile panoului: stare pe server, jeton opac, hash în bază.
 *
 * Geamănul e `sentinel/db/repo/sessions.py` plus schema din
 * `sentinel/db/migrations/0009_web_session.sql`. Formele care trebuie să fie
 * aceleași la ambele capete (32 de octeți de jeton, SHA-256 hexa, 300 s pentru o
 * sesiune pe jumătate autentificată) sunt ținute de
 * `tests/unit/test_aggregator_auth_parity.py`.
 *
 * ## De ce nu JWT
 *
 * Fiindcă amândouă lucrurile de care avem nevoie cer stare pe server:
 *
 *   * **revocarea.** Un JWT valabil e valabil până expiră, oriunde ar fi ajuns.
 *     „Deconectează toate sesiunile" devine atunci ori o listă de revocare —
 *     adică tot stare pe server, doar cu un pas în plus —, ori o minciună;
 *   * **loginul în două etape.** `pending_totp` trebuie să fie un fapt pe care
 *     clientul nu-l poate atinge. Într-un jeton semnat purtat de client, e un
 *     fanion pe care îl vede și îl reia; în bază, e rândul însuși.
 *
 * ## Ce se stochează, și ce nu
 *
 * Cookie-ul poartă 256 de biți opaci. În bază intră SHA-256 al lor — niciodată
 * jetonul. Un dump al bazei nu dă atunci nicio sesiune vie, exact ca la parole.
 * Jetonul în clar se întoarce O SINGURĂ DATĂ, la creare, și nu se poate
 * recupera. Proprietatea e probată în `tests/auth-session.test.ts`.
 *
 * ## Unicitatea sesiunii active o impune BAZA, nu codul de aici
 *
 * `sessions.active_token_hash` e o coloană obișnuită întreținută de două
 * triggere (`migrations/0008_auth.sql`), cu o cheie unică pe ea: două rânduri
 * ACTIVE cu același jeton sunt refuzate cu ERROR 1062, oricâte rânduri revocate
 * ar purta aceeași valoare. De-aia căutarea de mai jos se face pe
 * `active_token_hash` și nu pe `token_hash` cu un `AND revoked_at IS NULL`:
 * indexul unic garantează atunci că un jeton nu poate deschide două sesiuni,
 * chiar dacă cineva de aici ar scrie cândva un `INSERT` greșit.
 *
 * Ce NU se poate afirma de pe mașina asta: că MariaDB acceptă triggerele și că
 * refuzul e chiar 1062. Nu există bază de date aici. Drumul prin care se
 * dovedește e `npm run migrate -- --syntax-check` pe gazdă (care, măsurat pe
 * MariaDB 11.8.8, pregătește și `CREATE TRIGGER`) plus proba prin efect din
 * `README.md`.
 */

import { createHash, randomBytes } from "node:crypto";

import type { AuthDb } from "./db";

/** 256 de biți, ca `sessions.TOKEN_BYTES` pe server. */
export const SESSION_TOKEN_BYTES = 32;
export const CSRF_TOKEN_BYTES = 32;

/** Id-ul de rând: opac, și nu e credențialul. 16 octeți hexa = 32 de caractere,
 *  exact `CHAR(32)` din schemă. */
export const SESSION_ID_BYTES = 16;

/**
 * O sesiune doar-cu-parolă moare în 5 minute, indiferent ce TTL are configurat
 * panoul: destul cât să citești un cod de pe telefon, prea puțin cât să merite
 * furat. Aceeași valoare ca `PENDING_TOTP_TTL_S` de pe server.
 */
export const PENDING_TOTP_TTL_S = 300;

export type Session = {
  id: string;
  userId: number;
  pendingTotp: boolean;
  csrfToken: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  createdIp: string | null;
};

/** SHA-256 hexa, minuscule: exact ce încape în `CHAR(64)`. */
export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function newToken(): string {
  return randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

export function newCsrfToken(): string {
  return randomBytes(CSRF_TOKEN_BYTES).toString("base64url");
}

const COLUMNS =
  "id, user_id, pending_totp, csrf_token, created_at, last_seen_at, expires_at, " +
  "CAST(created_ip AS CHAR) AS created_ip";

/**
 * Rândul, în forma pe care o folosește codul.
 *
 * `pending_totp` vine din driver ca `0`/`1` (TINYINT), iar `Boolean(0)` e fals și
 * `Boolean("0")` e ADEVĂRAT — deci conversia se face pe față, o singură dată,
 * aici. O sesiune pe jumătate autentificată care ar fi citită ca autentificată e
 * chiar al doilea factor sărit.
 */
function toSession(row: Record<string, unknown>): Session {
  const pending = row.pending_totp;
  if (pending !== 0 && pending !== 1 && pending !== true && pending !== false) {
    throw new Error(
      `sessions.pending_totp are o valoare pe care nu o pot citi (${String(pending)}). ` +
      "Nu se presupune „nu e în așteptare”: aia ar fi o sesiune pe jumătate " +
      "autentificată tratată ca întreagă.");
  }
  return {
    id: String(row.id),
    userId: Number(row.user_id),
    pendingTotp: pending === 1 || pending === true,
    csrfToken: String(row.csrf_token),
    createdAt: String(row.created_at),
    lastSeenAt: String(row.last_seen_at),
    expiresAt: String(row.expires_at),
    createdIp: row.created_ip === null || row.created_ip === undefined
      ? null : String(row.created_ip),
  };
}

export type CreateSessionInput = {
  userId: number;
  ip: string | null;
  userAgent: string | null;
  ttlS: number;
  pendingTotp: boolean;
};

/**
 * Creează o sesiune. Întoarce jetonul în clar O SINGURĂ DATĂ, plus rândul.
 *
 * Timpii se calculează în SQL, cu `UTC_TIMESTAMP(6)`: ceasul procesului Node și
 * cel al serverului MariaDB pot să nu fie de acord, iar comparația de expirare o
 * face serverul. Cine scrie expirarea cu ceasul lui și o compară cu ceasul
 * altuia obține sesiuni care trăiesc mai mult sau mor la naștere, fără ca nimic
 * să arate spre un ceas.
 */
export async function createSession(
  db: AuthDb, input: CreateSessionInput,
): Promise<{ token: string; session: Session }> {
  if (!Number.isInteger(input.ttlS) || input.ttlS <= 0) {
    throw new Error("TTL-ul unei sesiuni trebuie să fie un număr de secunde pozitiv");
  }
  const token = newToken();
  const id = randomBytes(SESSION_ID_BYTES).toString("hex");
  // O sesiune în așteptarea TOTP nu primește TTL-ul panoului: vezi
  // `PENDING_TOTP_TTL_S`.
  const ttl = input.pendingTotp ? Math.min(PENDING_TOTP_TTL_S, input.ttlS) : input.ttlS;

  await db.write(
    "INSERT INTO sessions (id, user_id, token_hash, csrf_token, pending_totp, " +
    "                      created_ip, user_agent, created_at, last_seen_at, expires_at) " +
    "VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), " +
    "        UTC_TIMESTAMP(6) + INTERVAL ? SECOND)",
    [id, input.userId, hashToken(token), newCsrfToken(), input.pendingTotp ? 1 : 0,
     input.ip, (input.userAgent ?? "").slice(0, 512) || null, ttl]);

  const session = await sessionById(db, id);
  if (session === null) {
    // Inserarea a raportat succes și rândul nu e acolo. Se refuză, nu se
    // fabrică un obiect din ce am trimis: exact tiparul din `CLAUDE.md`.
    throw new Error(
      "sesiunea a fost inserată dar nu se poate citi înapoi; nu se întoarce un " +
      "jeton pentru un rând care nu s-a dovedit că există");
  }
  return { token, session };
}

/** Rândul, după id. Nu filtrează nimic — pentru citirea de după scriere. */
export async function sessionById(db: AuthDb, id: string): Promise<Session | null> {
  const rows = await db.all(`SELECT ${COLUMNS} FROM sessions WHERE id = ?`, [id]);
  return rows.length === 1 ? toSession(rows[0]) : null;
}

/**
 * Sesiunea după jetonul din cookie, sau `null`.
 *
 * Revocarea și expirarea se filtrează în SQL, deci o sesiune revocată, expirată
 * sau inexistentă arată la fel pentru apelant — n-are ce afla cine încearcă un
 * jeton. Căutarea merge pe `active_token_hash`, coloana pe care o întrețin
 * triggerele: pe ea e cheia unică, deci un jeton nu poate deschide două sesiuni.
 */
export async function sessionByToken(db: AuthDb, token: string): Promise<Session | null> {
  if (!token) return null;
  const rows = await db.all(
    `SELECT ${COLUMNS} FROM sessions ` +
    " WHERE active_token_hash = ? AND expires_at > UTC_TIMESTAMP(6)",
    [hashToken(token)]);
  if (rows.length > 1) {
    // Nu se poate întâmpla cât timp cheia unică există. Dacă se întâmplă, cheia
    // a dispărut, iar tăcerea de aici ar fi o autentificare pe un rând ales la
    // întâmplare.
    throw new Error(
      `${rows.length} sesiuni active cu același jeton: cheia unică ` +
      "`uk_sessions_active_token` lipsește din bază");
  }
  return rows.length === 1 ? toSession(rows[0]) : null;
}

/**
 * Al doilea factor a trecut: se șterge `pending_totp` și se ROTEȘTE jetonul.
 *
 * Rotirea nu e igienă, e reparație: dacă jetonul etapei întâi a scăpat între
 * cele două etape — un terminal partajat, un jurnal de proxy, istoricul
 * browserului —, valoarea scursă nu mai deschide nimic din clipa asta. Jetonul
 * CSRF se schimbă odată cu el, din același motiv.
 *
 * Întoarce jetonul nou, sau `null` dacă nu s-a promovat nimic (sesiune
 * inexistentă, deja revocată sau deja promovată) — `null` nu e „a mers".
 */
export async function promoteSession(
  db: AuthDb, sessionId: string, ttlS: number,
): Promise<string | null> {
  if (!Number.isInteger(ttlS) || ttlS <= 0) {
    throw new Error("TTL-ul unei sesiuni trebuie să fie un număr de secunde pozitiv");
  }
  const token = newToken();
  const affected = await db.write(
    "UPDATE sessions " +
    "   SET pending_totp = 0, token_hash = ?, csrf_token = ?, " +
    "       last_seen_at = UTC_TIMESTAMP(6), " +
    "       expires_at = UTC_TIMESTAMP(6) + INTERVAL ? SECOND " +
    " WHERE id = ? AND revoked_at IS NULL AND pending_totp = 1",
    [hashToken(token), newCsrfToken(), ttlS, sessionId]);
  return affected === 1 ? token : null;
}

/** Marchează ultima activitate. NU împinge expirarea — vezi `expires_at` în schemă. */
export async function touchSession(db: AuthDb, sessionId: string): Promise<void> {
  await db.write(
    "UPDATE sessions SET last_seen_at = UTC_TIMESTAMP(6) WHERE id = ?", [sessionId]);
}

/** Revocă o sesiune. `true` = chiar era activă și acum nu mai e. */
export async function revokeSession(
  db: AuthDb, sessionId: string, reason: string | null = null,
): Promise<boolean> {
  const affected = await db.write(
    "UPDATE sessions SET revoked_at = UTC_TIMESTAMP(6), revoked_reason = ? " +
    " WHERE id = ? AND revoked_at IS NULL",
    [reason === null ? null : reason.slice(0, 64), sessionId]);
  return affected === 1;
}

/**
 * Revocă toate sesiunile unui utilizator. Întoarce câte.
 *
 * Se cheamă la schimbarea parolei și când operatorul pierde un dispozitiv. O
 * resetare de parolă care lasă sesiunile vechi în viață n-a scos pe nimeni
 * afară.
 */
export async function revokeAllForUser(
  db: AuthDb, userId: number, reason: string | null = null,
): Promise<number> {
  return await db.write(
    "UPDATE sessions SET revoked_at = UTC_TIMESTAMP(6), revoked_reason = ? " +
    " WHERE user_id = ? AND revoked_at IS NULL",
    [reason === null ? null : reason.slice(0, 64), userId]);
}
