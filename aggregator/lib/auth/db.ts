/**
 * Ce cere autentificarea de la baza de date, și de ce nu e `Db` din `lib/migrate.ts`.
 *
 * Runner-ul de migrații are nevoie de două verbe: `all` (rânduri) și `run`
 * (execută, aruncă rezultatul). `run` care nu întoarce nimic e o alegere corectă
 * ACOLO — argumentul e scris în `lib/db.ts`, la `queryableDb`: cine s-ar uita la
 * ce a întors un DDL ar confunda „serverul a acceptat cererea" cu „obiectul
 * există".
 *
 * Aici e invers: **numărul de rânduri afectate ESTE răspunsul.** Consumarea unui
 * contor TOTP e un `UPDATE` condiționat (`... AND totp_last_counter < ?`), iar
 * singurul lucru care spune dacă a fost consumat ACUM sau fusese deja consumat e
 * dacă a potrivit un rând. Făcută altfel — `UPDATE`, apoi `SELECT` ca să vezi
 * valoarea — două cereri simultane cu același cod ar citi amândouă valoarea nouă
 * și ar crede amândouă că au câștigat. Adică fix reluarea împotriva căreia există
 * contorul.
 *
 * ## „Nu știu" nu e „zero"
 *
 * `write` ARUNCĂ dacă driverul nu întoarce un număr, în loc să răspundă 0. Zero
 * ar fi o propoziție („n-a potrivit nimic") pe care n-am dovedit-o, iar de la ea
 * pornesc două minciuni în direcții opuse: o revocare care n-a avut efect ar
 * părea „sesiunea nu exista", iar un contor neconsumat ar părea reluare. Un dublu
 * de test care uită să întoarcă numărul trebuie să pice, nu să pară că merge.
 */

import type { Queryable } from "../db";

export interface AuthDb {
  all(sql: string, params?: unknown[]): Promise<Record<string, unknown>[]>;
  /** Rânduri afectate. Vezi „«Nu știu» nu e «zero»" în capul modulului. */
  write(sql: string, params?: unknown[]): Promise<number>;
}

/** Adaptorul peste driver. Îngust dinadins, ca un dublu de test să nu aibă
 *  nevoie de mysql2. */
export function authDb(q: Queryable): AuthDb {
  return {
    async all(sql: string, params: unknown[] = []): Promise<Record<string, unknown>[]> {
      const [rows] = await q.query(sql, params);
      if (!Array.isArray(rows)) {
        throw new Error(
          "interogarea nu a întors un set de rânduri; `all` a fost chemat pentru " +
          "o instrucțiune care nu selectează nimic");
      }
      return rows as Record<string, unknown>[];
    },
    async write(sql: string, params: unknown[] = []): Promise<number> {
      const [result] = await q.query(sql, params);
      const affected = (result as { affectedRows?: unknown } | null)?.affectedRows;
      if (typeof affected !== "number") {
        throw new Error(
          "driverul nu a spus câte rânduri a afectat instrucțiunea. Nu se " +
          "presupune 0: „n-a potrivit nimic” și „nu știu” duc la decizii opuse " +
          "despre un cod TOTP reluat sau despre o sesiune revocată.");
      }
      return affected;
    },
  };
}
