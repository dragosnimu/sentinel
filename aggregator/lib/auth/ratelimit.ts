/**
 * Limitarea de rată, în trei straturi — și ce se întâmplă când unul lipsește.
 *
 * Planul cere trei: per utilizator, per sursă, plafon global. Pe server ele
 * există toate (`security.py:94-96`, plus `limit_req` în nginx). Aici, unul
 * dintre ele stă pe o presupunere care NU S-A PUTUT MĂSURA: adresa sursei vine
 * dintr-un antet, fiindcă CDN-ul termină conexiunea. Argumentul întreg e în
 * `lib/auth/client-ip.ts`; consecințele lui se aplică aici.
 *
 * | strat | ce oprește | ce NU oprește |
 * |---|---|---|
 * | per utilizator | ghicitul CODULUI la etapa a doua; rândurile repetate de la etapa întâi | ghicitul parolei — vezi mai jos |
 * | per sursă | o singură sursă care încearcă multe conturi | o sursă distribuită |
 * | global | epuizarea gazdei, oricine ar fi | nimic țintit; e ultima plasă |
 *
 * Prima linie a spus altceva până pe 17 august 2026 („oprește ghicitul parolei
 * unui cont anume"), și era falsă în cod, nu doar în text: `Authenticator.login`
 * consulta fereastra abia DUPĂ ce parola se dovedea corectă, deci o parolă
 * greșită n-a fost niciodată refuzată de stratul ăsta. Singurul lucru pe care
 * îl oprea era folosirea unei parole CORECTE — a operatorului, cel mai des.
 *
 * ## Toate trei au ACEEAȘI formă: o fereastră alunecătoare peste `login_attempts`
 *
 * Nu e simetrie de dragul simetriei, e singura formă care se autorepară. Până pe
 * 17 august 2026 stratul per cont era altfel — un contor MONOTON în
 * `users.failed_attempts`, golit doar de `recordSuccess`, adică abia la capătul
 * etapei TOTP. Ce ieșea din asta, măsurat prin sondă:
 *
 *   * un cont care a strâns vreodată 5 eșecuri rămânea permanent la O parolă
 *     greșită distanță de un nou blocaj de 15 minute, fiindcă `UPDATE … WHERE
 *     failed_attempts >= ?` se redeclanșa la fiecare eșec de după;
 *   * **4 cereri pe oră** țineau contul afară pentru totdeauna, iar parola
 *     CORECTĂ a operatorului primea 429 — niciun drum prin, și niciun semnal
 *     care să deosebească asta de un panou stricat.
 *
 * Cu fereastra, atacatorul trebuie să SUSȚINĂ pragul înăuntrul ferestrei, iar
 * starea se golește singură când se oprește.
 *
 * ## Ce mărginește azi fereastra per cont, și ce nu
 *
 * Decizia operatorului din 17 august 2026: **fereastra nu mai refuză o parolă
 * corectă.** Până atunci o refuza, iar asta era ultima negare permanentă la
 * îndemâna oricui — 5 eșecuri la fiecare 15 minute pe numele operatorului, adică
 * ~20 de cereri pe oră, și operatorul stătea afară cu parola bună în mână.
 *
 * Deci fereastra face azi două lucruri, amândouă observabile:
 *
 *   * la **etapa a doua** refuză, și acolo chiar mărginește un ghicit: `limit`
 *     coduri TOTP per fereastră. Pârghia aia cere parola contului, deci n-o are
 *     oricine. Numără doar eșecurile etapei a doua (`stage = 'totp'`) — vezi
 *     `accountWindow`;
 *   * la **etapa întâi** mărginește ce se SCRIE, nu ce se răspunde: ramurile
 *     „cont dezactivat" și „al doilea factor neînrolat" scriu cel mult `limit`
 *     rânduri `locked` per nume, per fereastră. Argumentul întreg e în capul lui
 *     `lib/auth/login.ts`, la „Ce are voie să hrănească un plafon".
 *
 * Ce NU mărginește, spus pe față: ghicitul parolei. Nici nu l-a mărginit
 * vreodată (vezi tabelul de sus), și nici nu poate fără să refuze exact cererea
 * pe care operatorul o trimite cu parola corectă — cele două sunt aceeași
 * cerere până când parola e verificată. Ghicitul rămâne mărginit de plafonul
 * global (fiecare ghicire scrie un rând numărat) și de faptul că fiecare
 * verificare costă un Argon2 serializat.
 *
 * ## Un refuz de limitare NU se scrie în `login_attempts`
 *
 * Regula e a lui `lib/auth/gate.ts` și se aplică tuturor celor trei straturi: un
 * refuz scris în tabela pe care o numără chiar limitatorul care l-a produs e un
 * plafon care se prelungește singur. Refuzurile merg în jurnalul procesului,
 * unde nu numără nimic.
 *
 * ## Când antetul nu e de încredere — implicitul
 *
 * Stratul per sursă **se stinge**, nu slăbește. Aplicat pe o valoare pe care
 * clientul o alege, ar fi mai rău decât inutil: cine trimite douăzeci de
 * încercări eșuate cu adresa operatorului în antet blochează operatorul.
 *
 * Compensarea e la stratul care rămâne: plafonul per cont scade de la 10 la 5.
 * Diferența e observabilă, nu declarativă — un test o cere prin efect.
 *
 * ## Ce COSTĂ plafonul global, spus pe față
 *
 * Un plafon global e o pârghie de negare de serviciu prin construcție: cine
 * produce destule eșecuri închide autentificarea pentru toți, inclusiv pentru
 * operator. Nu există variantă fără costul ăsta — un plafon care nu se aplică
 * nu e un plafon. Alegerile făcute ca să fie cât mai mic:
 *
 *   * pragul e sus (200 de eșecuri în 15 minute înseamnă un flux susținut, nu
 *     un om care a greșit parola);
 *   * răspunsul e **503 cu `Retry-After`**, adică „revino", nu o blocare;
 *   * refuzul NU se înregistrează ca încercare eșuată, deci plafonul nu se
 *     poate hrăni singur și nu se auto-prelungește;
 *   * fereastra e alunecătoare și scurtă, deci starea se autorepară;
 *   * **ce poate hrăni plafonul costă o verificare de parolă.** Regula și
 *     cifrele măsurate sunt în `lib/auth/login.ts`, la „Ce costă în continuare";
 *     aici contează doar consecința: 200 de rânduri la fiecare 15 minute
 *     înseamnă un rând la ~4,5 secunde, iar fiecare rând cere azi un Argon2
 *     serializat (`MAX_CONCURRENT_ARGON2 = 1`) în loc de o inserare. Plafonul
 *     rămâne hrănibil de cine vrea să plătească atât; ce s-a scos e „gratuit"
 *     (măsurat: 1 cerere la 3 secunde, fără cont și fără parolă, ținea panoul la
 *     503 la nesfârșit), nu „posibil".
 *
 * **Decizia rămâne a operatorului**, și e scrisă aici ca s-o poată lua: pe
 * găzduirea asta, alternativa la un plafon global nu e „mai multă
 * disponibilitate", ci un proces Node omorât de plafonul de memorie al planului
 * — care ar opri și ingestia arhivei de dovezi a tuturor instanțelor, nu doar
 * panoul. Dacă pragul se dovedește prea jos în practică, se ridică; nu se scoate.
 */

import type { AuthDb } from "./db";
import type { ClientIp } from "./client-ip";
import type { ThrottlePass } from "./gate";
import { countFailuresForUser, countFailuresFromIp, countFailuresGlobal } from "./users";
import { grantThrottlePass } from "./gate";

/** Fereastra tuturor numărătorilor. Ca `IP_FAILURE_WINDOW_MINUTES` pe server. */
export const FAILURE_WINDOW_MINUTES = 15;

/** Eșecuri de la o singură sursă în fereastră. Ca `IP_FAILURE_LIMIT` pe server. */
export const IP_FAILURE_LIMIT = 20;

/** Eșecuri de oriunde în fereastră. Vezi „Ce costă plafonul global". */
export const GLOBAL_FAILURE_LIMIT = 200;

/** Cu o sursă de încredere, stratul per sursă prinde ghicitul întins. */
export const MAX_FAILED_LOGINS_WITH_TRUSTED_IP = 10;

/** Fără ea, plafonul per cont e singurul lucru țintit care mai ține. */
export const MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP = 5;

/** Cât i se spune celui refuzat să aștepte. Fereastra întreagă, în secunde. */
export const THROTTLE_RETRY_AFTER_S = FAILURE_WINDOW_MINUTES * 60;

export function maxFailedLogins(trustedIp: boolean): number {
  return trustedIp ? MAX_FAILED_LOGINS_WITH_TRUSTED_IP
                   : MAX_FAILED_LOGINS_WITHOUT_TRUSTED_IP;
}

export type ThrottleVerdict =
  | { allowed: true; pass: ThrottlePass }
  | { allowed: false; layer: "ip" | "global"; retryAfterS: number };

/**
 * Straturile care se verifică ÎNAINTE de orice muncă scumpă.
 *
 * Ordinea — sursa, apoi globalul — e cea care dă mesajul cel mai apropiat de
 * cauză celui care e chiar cauza. Când sursa nu e de încredere se face O
 * SINGURĂ interogare, nu două, fiindcă a doua ar număra pe o valoare pe care nu
 * se sprijină nicio decizie.
 *
 * ARUNCĂ dacă o numărătoare nu se poate citi, și asta e voit: apelantul
 * transformă asta în 503, nu în „treci mai departe". Un limitator care nu poate
 * citi și lasă să treacă e un limitator care raportează că există.
 *
 * Ramura care PERMITE e singura care poartă un `ThrottlePass`, adică singura de
 * pe care se poate scrie apoi un rând în `login_attempts`. Vezi `gate.ts`.
 */
export async function checkThrottles(db: AuthDb, ip: ClientIp): Promise<ThrottleVerdict> {
  if (ip.trusted && ip.address !== null) {
    const fromIp = await countFailuresFromIp(db, ip.address, FAILURE_WINDOW_MINUTES);
    if (fromIp >= IP_FAILURE_LIMIT) {
      return { allowed: false, layer: "ip", retryAfterS: THROTTLE_RETRY_AFTER_S };
    }
  }

  const global = await countFailuresGlobal(db, FAILURE_WINDOW_MINUTES);
  if (global >= GLOBAL_FAILURE_LIMIT) {
    return { allowed: false, layer: "global", retryAfterS: THROTTLE_RETRY_AFTER_S };
  }
  return { allowed: true, pass: grantThrottlePass() };
}

export type AccountWindow = {
  /** Eșecuri ale contului în fereastră, ÎNAINTE de rândul cererii curente. */
  failures: number;
  limit: number;
  over: boolean;
};

/**
 * Stratul per cont: câte eșecuri are contul ăsta în fereastră, și dacă e peste.
 *
 * Numărătoarea se face pe NUMELE tastat, din `login_attempts`, nu dintr-o
 * coloană a contului — vezi „Toate trei au aceeași formă" în capul modulului.
 *
 * `stage` nu e un filtru de comoditate, e granița dintre două pârghii: fiecare
 * etapă numără DOAR eșecurile ei, ca pârghia care închide o etapă să ceară
 * credențialul etapei dinainte. Numărate laolaltă — cum erau până pe 17 august
 * 2026 —, `limit` parole greșite scrise de oricine pe numele operatorului
 * revocau sesiunea pe care operatorul tocmai o obținuse cu parola CORECTĂ, la
 * etapa a doua, cu mesajul „Sesiune invalidă".
 *
 * `failures` e starea de dinaintea cererii curente, deci apelantul care tocmai a
 * eșuat scrie `failures + 1` în jurnal. Numărat după scriere, mesajul ar sări
 * peste primul eșec sau l-ar număra de două ori, după cum cade ordinea.
 */
export async function accountWindow(
  db: AuthDb, username: string, trustedIp: boolean, stage: "password" | "totp",
): Promise<AccountWindow> {
  const limit = maxFailedLogins(trustedIp);
  const failures = await countFailuresForUser(db, username, FAILURE_WINDOW_MINUTES,
                                              stage);
  return { failures, limit, over: failures >= limit };
}
