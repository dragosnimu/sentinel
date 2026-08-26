/**
 * Verificarea semnalului și judecata asupra lui.
 *
 * Partea asta e singura care decide dacă sună telefonul, deci e scrisă ca să
 * poată fi citită de cineva care se întreabă „de ce m-a sunat la 3 dimineața?".
 */

import crypto from "crypto";
import type { Beat, InstanceState } from "./store";

export const SIGNATURE_HEADER = "x-sentinel-signature";

/**
 * Payload-ul iese din contractul de semnare.
 *
 * Cine o prinde ratează operația; nu are rost reluată, aceiași octeți vor eșua
 * la fel. Geamănul e `CanonicalError` din `sentinel/report/signing.py`.
 */
export class CanonicalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalError";
  }
}

/** Limita întregilor exacți din IEEE-754. Peste ea, cele două capete diverg. */
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;

/** Cât de adânc se acceptă imbricarea. Identic cu `MAX_DEPTH` din signing.py. */
const MAX_DEPTH = 32;

/**
 * Scurtăturile de escape, ca listă închisă. Restul controlelor C0 ies `\u00xx`
 * cu hexa MINUSCULĂ; DEL (0x7f) nu se escapează.
 */
const ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

/**
 * Forma canonică peste care se calculează semnătura.
 *
 * Trebuie să fie IDENTICĂ, la octet, cu `canonical()` din
 * `sentinel/report/signing.py` — acolo e scris contractul întreg și de ce arată
 * așa. Pe scurt: chei `str` din ASCII tipăribil sortate pe puncte de cod, fără
 * spații, doar întregi exacți (fără float, fără `NaN`/`Infinity`), fără surogați
 * neîmperecheați, imbricare cel mult 32.
 *
 * ## De ce nu mai e `JSON.stringify(sortDeep(...))`
 *
 * Fiindcă nu era geamăn, și E1 a măsurat exact unde. Trei cauze, toate din
 * limbaj, niciuna reparabilă din partea Python:
 *
 *   1. **`Object.fromEntries` anula sortarea.** Obiectele JavaScript reașază
 *      cheile de tip index în ordine numerică indiferent de ordinea de inserare,
 *      deci `{"2":…,"10":…}` ieșea cu `"2"` primul, iar Python scria `"10"`.
 *      Se repara și imbricat, și la rădăcină — două intrări din patru.
 *      Acum nu se mai reconstruiește niciun obiect: se scriu octeții direct.
 *   2. **`Array.sort()` compară unități UTF-16**, nu puncte de cod, deci un
 *      emoji și un caracter din zona privată ieșeau invers față de Python. Acum
 *      cheile sunt ASCII prin contract ȘI se sortează cu un comparator explicit
 *      pe puncte de cod — al doilea, ca o relaxare viitoare a primului să nu
 *      reintroducă tăcut divergența.
 *   3. **`JSON.stringify` scrie numerele cu alt algoritm** decât `json.dumps`:
 *      `1e-7` vs `1e-07`, `60` vs `60.0`. Acum se acceptă doar întregi exacți,
 *      pentru care `String(n)` și `str(n)` coincid pe tot intervalul.
 *
 * Contractul nu poate fi „le facem să fie de acord": ține până când adaugă
 * cineva un câmp. Refuzul e ce ține.
 */
export function canonical(payload: Record<string, unknown>): string {
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new CanonicalError(
      `$: payload-ul de semnat trebuie să fie un obiect, nu ${describe(payload)}`,
    );
  }
  const out: string[] = [];
  emit(payload, out, "$", 0);
  return out.join("");
}

/**
 * O singură parcurgere: validează ȘI scrie.
 *
 * Nu două funcții, dinadins — un validator separat de emitent e încă o pereche
 * de implementări care pot să nu fie de acord, adică fix problema pe care
 * modulul o rezolvă între limbaje, reintrodusă înăuntrul unuia singur.
 */
function emit(value: unknown, out: string[], path: string, depth: number): void {
  if (value === null) {
    out.push("null");
    return;
  }
  const t = typeof value;
  if (t === "boolean") {
    out.push(value ? "true" : "false");
    return;
  }
  if (t === "number") {
    // `Number.isSafeInteger` acoperă dintr-o dată patru refuzuri: NaN, ±Infinity,
    // orice cu parte fracționară, și orice peste ±2^53-1.
    if (!Number.isSafeInteger(value)) {
      throw new CanonicalError(
        `${path}: doar întregi exacți se pot semna, nu ${String(value)} — cele ` +
          `două capete îl scriu diferit`,
      );
    }
    // `String(-0)` dă "0", la fel ca Python; `-0` nu are cum să producă octeți
    // pe care celălalt capăt să nu îi scrie la fel.
    out.push(String(value));
    return;
  }
  if (t === "string") {
    out.push(emitString(value as string, path));
    return;
  }
  if (Array.isArray(value)) {
    checkDepth(path, depth);
    out.push("[");
    for (let i = 0; i < value.length; i++) {
      if (i) out.push(",");
      emit(value[i], out, `${path}[${i}]`, depth + 1);
    }
    out.push("]");
    return;
  }
  if (t === "object" && isPlainObject(value)) {
    checkDepth(path, depth);
    const keys = sortedKeys(value as Record<string, unknown>, path);
    out.push("{");
    for (let i = 0; i < keys.length; i++) {
      if (i) out.push(",");
      out.push(emitString(keys[i], path));
      out.push(":");
      emit((value as Record<string, unknown>)[keys[i]], out, `${path}.${keys[i]}`, depth + 1);
    }
    out.push("}");
    return;
  }
  throw new CanonicalError(
    `${path}: tip neacceptat (${describe(value)}). Contractul acceptă null, ` +
      `boolean, întreg exact, string, tablou și obiect simplu`,
  );
}

/**
 * Doar obiecte simple.
 *
 * `typeof new Date() === "object"` și `Object.keys(new Date())` e `[]`, deci
 * fără verificarea asta o dată ar fi ieșit `{}` — un câmp care dispare tăcut
 * din octeții peste care se semnează.
 */
function isPlainObject(value: unknown): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "tablou";
  const t = typeof value;
  return t === "object" ? (value as object).constructor?.name || "object" : t;
}

function checkDepth(path: string, depth: number): void {
  if (depth >= MAX_DEPTH) {
    throw new CanonicalError(`${path}: imbricare peste ${MAX_DEPTH} niveluri`);
  }
}

/** Comparație pe PUNCTE DE COD, nu pe unități UTF-16. Vezi cauza 2 de mai sus. */
function compareCodePoints(a: string, b: string): number {
  const ca = Array.from(a, (c) => c.codePointAt(0) as number);
  const cb = Array.from(b, (c) => c.codePointAt(0) as number);
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) {
    if (ca[i] !== cb[i]) return ca[i] - cb[i];
  }
  return ca.length - cb.length;
}

function sortedKeys(value: Record<string, unknown>, path: string): string[] {
  const keys = Object.keys(value);
  for (const key of keys) {
    for (const ch of key) {
      const cp = ch.codePointAt(0) as number;
      if (cp < 0x20 || cp > 0x7e) {
        throw new CanonicalError(
          `${path}: cheia ${JSON.stringify(key)} conține U+` +
            cp.toString(16).toUpperCase().padStart(4, "0") +
            `; cheile trebuie să fie ASCII tipăribil (U+0020-U+007E)`,
        );
      }
    }
  }
  return keys.sort(compareCodePoints);
}

function emitString(text: string, path: string): string {
  let out = '"';
  // `for…of` peste un șir iterează PUNCTE DE COD: o pereche de surogați validă
  // vine ca un singur caracter, iar un surogat rămas singur vine ca el însuși —
  // care e exact distincția de care are nevoie verificarea de mai jos.
  for (const ch of text) {
    const escape = ESCAPES[ch];
    if (escape !== undefined) {
      out += escape;
      continue;
    }
    const cp = ch.codePointAt(0) as number;
    if (cp < 0x20) {
      out += "\\u" + cp.toString(16).padStart(4, "0");
    } else if (cp >= 0xd800 && cp <= 0xdfff) {
      // Python nu poate codifica un surogat neîmperecheat în UTF-8, JavaScript
      // îl scrie ca `\udXXX`. Singura formă de șir pe care cele două capete nu o
      // pot scrie la fel, deci nu intră în contract.
      throw new CanonicalError(
        `${path}: surogat neîmperecheat U+` +
          cp.toString(16).toUpperCase().padStart(4, "0") +
          `; cele două capete nu îl pot scrie la fel`,
      );
    } else {
      out += ch;
    }
  }
  return out + '"';
}

/** Comparație în timp constant: o comparație obișnuită scurge lungimea prefixului comun. */
export function signatureValid(body: string, signature: string, secret: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(body, "utf8").digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signature || "", "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export type Verdict = {
  /** `null` înseamnă „totul e în regulă". */
  kind: null | "silent" | "stalled" | "replay" | "selfcheck" | "forged";
  severity: "critical" | "high" | "info";
  message: string;
};

const OK: Verdict = { kind: null, severity: "info", message: "" };

/**
 * Cât timp de tăcere înseamnă alarmă.
 *
 * Trei intervale, nu unul: o repornire de serviciu, o reîncercare de rețea sau
 * o secundă de întârziere nu au voie să te trezească. Trei ratări consecutive
 * nu mai sunt o coincidență.
 */
export const MISSED_BEATS_BEFORE_ALARM = 3;

/**
 * Cât pot sta contoarele pe loc cu semnalul sosind normal.
 *
 * Ăsta e modul de eșec pe care un „sunt viu" simplu nu îl vede niciodată:
 * procesul răspunde, deci pare că merge, iar ingestia e moartă de o oră. Pe o
 * gazdă expusă la internet, `last_event_id` nu stă pe loc 15 minute decât dacă
 * ceva e rupt.
 */
export const STALL_SECONDS = 15 * 60;

/**
 * Verdictul pentru O instanță.
 *
 * Judecata e per instanță și nu se agregă aici: „unul dintre servere tace" e o
 * concluzie de rută, nu de funcție. Dacă funcția asta ar primi toată starea, ar
 * trebui să aleagă un singur verdict pentru N mașini, iar alegerea aia ascunde
 * întotdeauna ceva.
 */
export function judge(state: InstanceState, now: Date): Verdict {
  const last = state.last;
  if (!last) {
    // Niciun semnal încă. Nu e o alarmă: martorul tocmai a fost instalat, sau
    // expeditorul nu e încă pornit. A alerta aici ar însemna să suni la fiecare
    // instalare.
    return OK;
  }

  const receivedAt = new Date(last.received_at).getTime();
  const silentFor = (now.getTime() - receivedAt) / 1000;
  const allowance = Math.max(last.interval_s || 60, 30) * MISSED_BEATS_BEFORE_ALARM;

  if (silentFor > allowance) {
    return {
      kind: "silent",
      severity: "critical",
      message:
        `Niciun semnal de la Sentinel de ${Math.round(silentFor / 60)} minute ` +
        `(ultimul: ${last.received_at}). Serviciile pot fi oprite, gazda căzută ` +
        `sau rețeaua tăiată. Verifică serverul direct, nu prin panou.`,
    };
  }

  const movedAt = new Date(state.counters_moved_at || last.received_at).getTime();
  const stalledFor = (now.getTime() - movedAt) / 1000;
  if (stalledFor > STALL_SECONDS) {
    return {
      kind: "stalled",
      severity: "critical",
      message:
        `Sentinel trimite semnale, dar contoarele nu au mai avansat de ` +
        `${Math.round(stalledFor / 60)} minute. Procesul trăiește și conducta e ` +
        `moartă: ingestia sau detecția nu mai consumă nimic.`,
    };
  }

  if (last.selfcheck.worst !== "ok" && last.selfcheck.worst !== "unknown") {
    return {
      kind: "selfcheck",
      severity: last.selfcheck.worst === "down" ? "critical" : "high",
      message:
        `Autodiagnosticul Sentinel raportează „${last.selfcheck.worst}": ` +
        `${last.selfcheck.bad} din ${last.selfcheck.checks} verificări au eșuat.`,
    };
  }

  return OK;
}

/** Contoarele au avansat față de semnalul anterior? */
export function countersAdvanced(prev: Beat | undefined, next: Beat): boolean {
  if (!prev) return true;
  return (
    next.last_event_id > prev.last_event_id ||
    next.detect_cursor > prev.detect_cursor ||
    next.audit_head !== prev.audit_head
  );
}
