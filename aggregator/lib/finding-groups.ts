/**
 * Vocabularul stărilor unei constatări, împărțit în grupe.
 *
 * Stă în afara lui `lib/data/` dinadins. Acolo sunt ACCESELE la date, fiecare
 * păzit de domeniul contului; un predicat pur n-are domeniu de apărat, iar
 * recensământul de acolo i-ar fi cerut o verificare pe două instanțe care n-ar
 * avea ce compara. Vocabularul e o listă, nu o cale de acces.
 */

/**
 * Cele trei grupe în care se împart cele șapte stări ale unei constatări.
 *
 * Operatorul a cerut „ce e rezolvat, ce nu e aplicat". Vocabularul are însă
 * șapte valori, iar două dintre ele nu intră în niciuna:
 *
 *   * `accepted_risk` și `false_positive` sunt ÎNCHISE FĂRĂ REPARAȚIE. Puse la
 *     „rezolvate", pagina ar pretinde o reparație care n-a existat — chiar clasa
 *     de raport după care e numit depozitul. Puse la „neaplicate", ar bate la cap
 *     cu lucruri închise deliberat, iar o listă care conține zgomot deliberat e
 *     una pe care operatorul încetează s-o citească.
 *
 * De-aia sunt TREI grupe, nu două. A treia e mică și tăcută, dar există.
 *
 * `resolved` singur înseamnă reparat ȘI verificat — `patch_executions` are
 * `post_verification_passed`, iar starea nu ajunge aici fără el.
 */
export const GROUPS = {
  neaplicate: ["open", "patch_planned", "patching", "deferred"],
  rezolvate: ["resolved"],
  inchise: ["accepted_risk", "false_positive"],
} as const;

export type FindingGroup = keyof typeof GROUPS;

export function isGroup(value: string | null): value is FindingGroup {
  return value !== null && Object.prototype.hasOwnProperty.call(GROUPS, value);
}
