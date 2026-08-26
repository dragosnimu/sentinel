/**
 * Retenția replicii: ce se taie, cât de des, și de ce nu totul.
 *
 * ## De ce există
 *
 * Pe gazdă, istoricul de comenzi are retenție NELIMITATĂ: e mașina operatorului,
 * are 91 GB liberi, iar întrebarea „ce a rulat cineva acum trei luni" e chiar
 * cazul de folosință.
 *
 * Aici e altceva. Măsurat pe 25 august 2026, la câteva ore după ce fluxul a
 * pornit: **`session_command_entries` = 253 MB, din 468 MB cât avea toată baza.**
 * Fluxul ăsta singur e mai mare decât celelalte unsprezece la un loc, și crește
 * cu ~405 000 de rânduri la fiecare deploy.
 *
 * Găzduirea e partajată și are cotă. O creștere nemărginită nu se termină cu
 * „tabela e mare" — se termină cu **ingestia refuzată pentru TOATE fluxurile**,
 * fiindcă baza e plină. Un flux care crește necontrolat le doboară pe celelalte.
 *
 * ## Ce NU se taie, niciodată
 *
 * `audit_entries` — e o arhivă înlănțuită prin hash, iar tăierea ei ar rupe
 * lanțul și ar face verificarea de integritate imposibilă. `incident_entries` —
 * un incident e o decizie, iar deciziile nu expiră.
 *
 * Lista de mai jos e explicită tocmai de-asta: ce nu e în ea nu se atinge, iar
 * adăugarea unei tabele acolo e o decizie vizibilă în diff.
 *
 * ## De ce în tranșe
 *
 * Un `DELETE` de sute de mii de rânduri ține un lock lung pe InnoDB și poate
 * face ingestia să expire în timpul lui. Tăiat în tranșe, fiecare durează
 * milisecunde și lasă loc între ele. Costul: mai multe treceri până se golește
 * o restanță mare — și e costul corect, fiindcă alternativa e o pană.
 */

// Tipul PROPRIU al proiectului, nu cel din `mysql2`: interfața de aici e
// intenționat mai îngustă — `query` și atât —, iar un dublu de test se poate
// scrie fără să implementeze treizeci de metode pe care retenția nu le atinge.
import type { Queryable } from "./db";

/** O tabelă tăiată de retenție, cu coloana de timp și vârsta maximă. */
export type Policy = {
  table: string;
  /** Coloana pe care se măsoară vârsta. */
  column: string;
  days: number;
  why: string;
  /**
   * Condiție suplimentară, ca text SQL fără parametri.
   *
   * Există pentru un singur caz, și e mai bine să fie citit decât generalizat:
   * comenzile sesiunilor NEINTERACTIVE se taie mult mai devreme decât ale
   * oamenilor. Vezi politica de mai jos.
   */
  extra?: string;
};

/**
 * Câte rânduri se șterg într-o singură instrucțiune.
 *
 * 5000: destul cât o restanță de o zi să se golească în câteva treceri, puțin
 * cât lock-ul să dureze milisecunde. Aceeași valoare pe care o folosește și
 * `docs/PLAN-arhitectura-distribuita.md` pentru bucla de retenție.
 */
export const BATCH = 5000;

/**
 * Câte tranșe se fac într-o rulare, pe tabelă.
 *
 * Mărginit ca să nu blocheze un cron într-o buclă de ore la prima rulare de după
 * o restanță mare. Ce rămâne se taie la rularea următoare, iar `RetentionResult`
 * SPUNE că a rămas — un plafon tăcut ar arăta ca „am terminat".
 */
export const MAX_BATCHES = 40;

/**
 * Ce se taie. Ce nu e aici nu se atinge — vezi nota din capul fișierului.
 */
//: Câte zile trăiesc pe replică comenzile unei sesiuni FĂRĂ terminal.
//:
//: Paisprezece, față de 180 pentru cele ale unui om. Motivul e o măsurătoare de
//: pe 25 august 2026, și e mai rea decât estimarea de dinaintea ei:
//:
//:   * o sesiune de deploy a produs **405 777 de comenzi în 140 de secunde**;
//:   * binarele de sus sunt `systemctl` (320 591) și `sleep` (173 376) — adică
//:     buclele de așteptare ale instalatorului, nu munca lui;
//:   * replica a crescut de la 83 MB la **909 MB în câteva ore**.
//:
//: Pe gazdă e în regulă: 91 GB liberi, și acolo istoricul chiar e nelimitat.
//: Aici, o bază plină nu înseamnă „tabela e mare" — înseamnă ingestia refuzată
//: pentru toate cele douăsprezece fluxuri, adică panoul îngheață din cauza unei
//: singure tabele.
//:
//: Ce se pierde, spus pe față: după paisprezece zile nu se mai poate răspunde
//: din panoul extern la „ce a rulat deploy-ul din 3 martie". Se poate răspunde
//: de pe gazdă, unde rândurile rămân. Ce NU se pierde e partea care contează
//: pentru securitate: comenzile oamenilor, și faptul că sesiunea a existat.
export const AUTOMATION_DAYS = 14;

export const POLICIES: readonly Policy[] = Object.freeze([
  {
    table: "session_command_entries",
    column: "ts",
    days: AUTOMATION_DAYS,
    // Sub-interogare și nu `JOIN`: `DELETE ... LIMIT` cu `JOIN` nu e acceptat de
    // MariaDB, iar `LIMIT` e ce ține lock-ul scurt. Comenzile fără sesiune
    // cunoscută NU se taie devreme — o comandă orfană poate fi a unui om a cărui
    // logare nu s-a văzut, iar „nu știu" nu e „e a unui script".
    extra: "session_source_id IN (SELECT source_id FROM login_session_entries " +
           "WHERE instance_id = session_command_entries.instance_id " +
           "AND interactive = 0)",
    why: "comenzile automatizărilor: 405 777 pentru un singur deploy",
  },
  {
    table: "session_command_entries",
    column: "ts",
    days: 180,
    why: "restul comenzilor — ale oamenilor, și cele fără sesiune cunoscută",
  },
  {
    table: "login_session_entries",
    column: "opened_at",
    days: 180,
    // Aceeași fereastră ca la comenzi, dinadins: o sesiune fără comenzile ei e
    // un rând care spune „s-a logat cineva și a rulat 412 comenzi" fără să poată
    // arăta niciuna. Două ferestre diferite ar produce exact starea aia.
    why: "aceeași fereastră ca la comenzi, ca o sesiune să nu rămână fără ele",
  },
]);

export type RetentionResult = {
  table: string;
  deleted: number;
  /** `true` când plafonul de tranșe s-a atins și au mai rămas rânduri vechi. */
  more: boolean;
};

/**
 * Instrucțiunea de tăiere pentru o politică.
 *
 * Funcție separată, și pură, ca forma ei să se poată proba fără bază — inclusiv
 * faptul că poartă `LIMIT`, care e ce ține lock-ul scurt.
 */
export function pruneSql(policy: Policy): string {
  // `?` pentru zile, nu interpolare: `days` vine dintr-o constantă de aici azi,
  // dar o politică citită vreodată din configurație ar deveni injecție. Costul
  // e zero, iar regula „valorile nu se interpolează niciodată" nu are excepții
  // care merită ținute minte.
  const extra = policy.extra ? ` AND (${policy.extra})` : "";
  return `DELETE FROM ${policy.table} ` +
         `WHERE ${policy.column} < UTC_TIMESTAMP(6) - INTERVAL ? DAY${extra} ` +
         `LIMIT ${BATCH}`;
}

/**
 * Taie ce a expirat. Întoarce ce a șters, pe tabelă.
 *
 * Nu aruncă pe o tabelă lipsă: retenția rulează dintr-un cron, iar o bază căreia
 * încă nu i s-a aplicat migrația nu e o eroare de oprit — e o instalare în curs.
 */
export async function pruneExpired(pool: Queryable): Promise<RetentionResult[]> {
  const out: RetentionResult[] = [];
  for (const policy of POLICIES) {
    let deleted = 0;
    let more = false;
    for (let i = 0; i < MAX_BATCHES; i += 1) {
      let affected = 0;
      try {
        const [res] = await pool.query(pruneSql(policy), [policy.days]);
        affected = (res as { affectedRows?: number }).affectedRows ?? 0;
      } catch (err) {
        // O tabelă care nu există încă înseamnă „migrația n-a ajuns aici", nu
        // „retenția e stricată". Orice altceva se ridică: o eroare înghițită
        // aici ar face ca baza să crească în tăcere până se umple.
        if ((err as { code?: string }).code === "ER_NO_SUCH_TABLE") break;
        throw err;
      }
      deleted += affected;
      if (affected < BATCH) break;
      if (i === MAX_BATCHES - 1) more = true;
    }
    // Numele poartă și fereastra: două politici pe aceeași tabelă ar produce
    // altfel două rânduri identice în raport, iar cine îl citește n-ar putea
    // spune care a tăiat ce.
    if (deleted > 0 || more) {
      out.push({ table: `${policy.table} (${policy.days}z)`, deleted, more });
    }
  }
  return out;
}
