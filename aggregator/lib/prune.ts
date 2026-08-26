/**
 * Reconcilierea: ce a fost șters la sursă se șterge și aici.
 *
 * Ingestia e numai upsert, deci fără mecanismul ăsta un rând șters pe serverul
 * monitorizat rămâne în panou pentru totdeauna, cu ultima lui stare. Măsurat pe
 * 21 august 2026, la o oră după ce fluxul `selfcheck_state` a început să curgă:
 * serverul avea 43 de verificări, panoul 44. A 44-a era verificarea care
 * semnalase chiar defectul reparat cu o oră înainte — ștearsă la sursă, arătată
 * aici în continuare ca o problemă deschisă. Un panou care arată o problemă
 * rezolvată ca fiind încă deschisă e chiar clasa după care e numit depozitul.
 *
 * ## Forma, și de ce e aceeași cu a sursei
 *
 * Lotul poartă mulțimea COMPLETĂ de chei de la sursă; se șterge ce nu e în ea.
 * E aceeași formă cu `DELETE … WHERE NOT (key = ANY($1))` din
 * `sentinel/selfcheck/runner.py`, dinadins: două mecanisme cu aceeași formă nu
 * pot fi de acord pe jumătate.
 *
 * ## Gărzile, fiecare pentru un fel de a pierde date
 *
 * Operația asta ȘTERGE, deci fiecare intrare greșită are un preț ireversibil:
 *
 *   * **flux nedeclarat ca reconciliabil** → refuz. O listă acceptată din
 *     greșeală pentru `audit_log` ar șterge fiecare intrare care nu e în ea,
 *     adică exact arhiva care există ca să nu poată fi ștearsă de pe mașină;
 *   * **listă goală** → refuz. „Sursa nu mai are nimic" și „lista s-a pierdut pe
 *     drum" arată identic, iar prima e legitimă doar teoretic: fluxul care se
 *     reconciliază are întotdeauna rânduri. Din două citiri posibile se alege
 *     cea care nu golește un tabel;
 *   * **listă peste plafon** → refuz. Expeditorul o omite mai degrabă decât s-o
 *     taie; una sosită oricum înseamnă că altcineva a tăiat-o, iar o listă
 *     tăiată prezentată ca fiind completă e o ștergere de rânduri reale;
 *   * **fără `instance_id` în clauză** → imposibil prin construcție: parametrul
 *     e primul, iar un `WHERE` fără el ar șterge rândurile ALTOR servere.
 *
 * Refuzul nu oprește lotul. Rândurile sunt treaba; reconcilierea e igienă, iar
 * un lot pierdut fiindcă lista era stricată ar fi mai scump decât un rând
 * fantomă care mai stă o rundă.
 */

import type { Stream } from "./streams";

/**
 * Cel mai lung șir de chei acceptat.
 *
 * Trebuie să fie CEL PUȚIN cât `MAX_PRUNE_KEYS` din `sentinel/report/shipper.py`,
 * altfel expeditorul ar trimite o listă pe care receptorul o refuză mereu, iar
 * reconcilierea n-ar avea loc niciodată — tăcut, fiindcă refuzul nu oprește
 * lotul.
 */
export const MAX_PRUNE_KEYS = 5_000;

/** Cât de lungă poate fi o cheie. `check_key` e `varchar(190)`. */
export const MAX_PRUNE_KEY_BYTES = 190;

export type PruneVerdict =
  | { ok: true; keys: string[] }
  | { ok: false; detail: string };

/**
 * Verifică o listă înainte ca ea să poată șterge ceva. Funcție PURĂ.
 *
 * Separată de execuție ca să poată fi probată fără bază: fiecare ramură de aici
 * e un fel de a șterge rânduri care nu trebuiau șterse.
 */
export function checkPruneList(stream: Stream | undefined, name: string,
                               value: unknown): PruneVerdict {
  if (stream === undefined) {
    return { ok: false, detail: `fluxul "${name}" nu e cunoscut de agregator` };
  }
  if (stream.pruneKey === undefined) {
    return { ok: false, detail:
      `fluxul "${name}" nu e declarat ca reconciliabil, deci o listă de chei ` +
      `pentru el ar șterge rânduri pe care sursa nu le-a șters niciodată` };
  }
  if (!Array.isArray(value)) {
    return { ok: false, detail: `prune.${name} nu e o listă` };
  }
  if (value.length === 0) {
    return { ok: false, detail:
      `prune.${name} e goală; „sursa nu mai are nimic" și „lista s-a pierdut" ` +
      `arată la fel, iar prima ar goli tabelul` };
  }
  if (value.length > MAX_PRUNE_KEYS) {
    return { ok: false, detail:
      `prune.${name} are ${value.length} chei, peste plafonul de ` +
      `${MAX_PRUNE_KEYS}; expeditorul o omite în loc s-o taie, deci una mai ` +
      `lungă a fost tăiată pe drum` };
  }
  const keys: string[] = [];
  for (const key of value) {
    if (typeof key !== "string" || key.length === 0) {
      return { ok: false, detail: `prune.${name} conține o cheie care nu e un șir` };
    }
    if (Buffer.byteLength(key, "utf8") > MAX_PRUNE_KEY_BYTES) {
      return { ok: false, detail:
        `prune.${name} conține o cheie mai lungă de ${MAX_PRUNE_KEY_BYTES} octeți, ` +
        `deci una care n-a putut fi scrisă niciodată în coloană` };
    }
    keys.push(key);
  }
  return { ok: true, keys };
}

/** SQL-ul ștergerii. Separat ca să poată fi citit într-un test. */
export function pruneSql(stream: Stream, count: number): string {
  const holes = new Array(count).fill("?").join(", ");
  // `instance_id = ?` PRIMUL și întotdeauna: fără el, lista unui server ar
  // șterge rândurile celorlalte.
  return `DELETE FROM ${stream.table} WHERE instance_id = ? ` +
         `AND ${stream.pruneKey} NOT IN (${holes})`;
}

export interface PruneRunner {
  run(sql: string, params: unknown[]): Promise<void>;
  all(sql: string, params: unknown[]): Promise<Record<string, unknown>[]>;
}

/**
 * Aplică o listă verificată. Întoarce câte rânduri au dispărut.
 *
 * Numărul se citește prin numărare ÎNAINTE și DUPĂ, nu din ce raportează
 * driverul: `affectedRows` diferă între drivere și configurații, iar aici e
 * singura cifră pe care o vede operatorul despre o operație care șterge.
 */
export async function applyPrune(db: PruneRunner, stream: Stream,
                                 instanceId: string,
                                 keys: string[]): Promise<number> {
  const countSql = `SELECT count(*) AS n FROM ${stream.table} WHERE instance_id = ?`;
  const count = async (): Promise<number> =>
    Number((await db.all(countSql, [instanceId]))[0]?.n ?? 0);

  const before = await count();
  await db.run(pruneSql(stream, keys.length), [instanceId, ...keys]);
  return Math.max(0, before - await count());
}
