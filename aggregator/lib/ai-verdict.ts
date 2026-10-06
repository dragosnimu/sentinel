/**
 * Verdictul modelului despre un incident, citit din `incidents.ai_verdict` (blob JSON).
 *
 * Într-un fișier al lui, nu în `lib/data/incidents.ts`: aici nu se citește nimic din bază și
 * nu se aplică niciun drept, iar `tests/data-scope-coverage.test.ts` numără orice funcție
 * exportată din `lib/data/` ca pe una care trebuie să primească un domeniu de instanțe.
 */

/**
 * Cele cinci acțiuni pe care `triage._clean` le poate stoca în `recommended_action`
 * (`triage._ACTION_ENUM`; `tests/unit/test_ai_content_badge.py` compară cele două liste).
 *
 * Ce nu e exact unul dintre ele nu e un răspuns al modelului, ci o urmă a unei stricăciuni: pe
 * 6 oct 2026, din 791 de verdicte stocate, 415 purtau o secvență de ASCII în locul
 * diacriticii (șase caractere: backslash, „u", „0103" — „blocheaz" urmat de ele), iar `unknown` (răspunsul pe care normalizatorul n-a știut să-l așeze,
 * cu originalul aruncat) era cel mai frecvent dintre cele noi. A le scrie sub eticheta „AI content"
 * sub forma „Acțiune sugerată: unknown" ar certifica gunoiul drept părerea modelului.
 *
 * Comparația e exactă, fără normalizare și fără a repara: un `investigheaza` fără diacritice
 * nu e transformat în `investighează` aici — repararea datelor nu e treaba afișării.
 */
export const AI_ACTIONS: readonly string[] = [
  "monitorizează", "blochează", "investighează", "ignoră", "patch",
];

/**
 * Ce a scris modelul despre un incident (`incidents.ai_verdict`, blob JSON). Câmpurile sunt
 * cele din `sentinel/ai/triage.py:_clean`; unul lipsă e `null`, nu o valoare inventată.
 *
 * `recommendedAction` e `null` și când blobul are un text care NU e una din `AI_ACTIONS`
 * (`unknown`, o formă cu diacritice rupte, orice altceva): cine o afișează omite rândul, nu scrie
 * „—" și nu scrie textul stricat. Textul brut nu se păstrează aici — nu are ce căuta pe ecran.
 */
export type AiVerdict = {
  summaryRo: string | null;
  recommendedAction: string | null;
  isFalsePositive: boolean | null;
  promptInjectionDetected: boolean;
};

/**
 * Verdictul modelului, din coloana JSON. Trei rezultate, nu două — vezi `IncidentDetail.aiVerdict`.
 *
 * Driverul întoarce o coloană `JSON` de MariaDB ca ȘIR (e `LONGTEXT` cu `JSON_VALID`), dar un
 * driver sau un dublu o poate da deja parsată; ambele se acceptă. Orice altceva decât un
 * obiect — ghilimele, un tablou, text care nu e JSON — e `"unreadable"`, NU un verdict gol.
 */
export function readAiVerdict(raw: unknown): AiVerdict | "unreadable" | null {
  if (raw === null || raw === undefined) return null;
  let value: unknown = raw;
  if (typeof raw === "string") {
    try {
      value = JSON.parse(raw);
    } catch {
      return "unreadable";
    }
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return "unreadable";
  const v = value as Record<string, unknown>;
  const str = (x: unknown): string | null => (typeof x === "string" && x !== "" ? x : null);
  const action = (x: unknown): string | null =>
    typeof x === "string" && AI_ACTIONS.includes(x) ? x : null;
  return {
    summaryRo: str(v.summary_ro),
    recommendedAction: action(v.recommended_action),
    isFalsePositive: typeof v.is_false_positive === "boolean" ? v.is_false_positive : null,
    promptInjectionDetected: v.prompt_injection_detected === true,
  };
}
