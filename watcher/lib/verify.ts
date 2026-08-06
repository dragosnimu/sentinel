/**
 * Verificarea semnalului și judecata asupra lui.
 *
 * Partea asta e singura care decide dacă sună telefonul, deci e scrisă ca să
 * poată fi citită de cineva care se întreabă „de ce m-a sunat la 3 dimineața?".
 */

import crypto from "crypto";
import type { Beat, State } from "./store";

export const SIGNATURE_HEADER = "x-sentinel-signature";

/**
 * Forma canonică peste care se calculează semnătura.
 *
 * Trebuie să fie IDENTICĂ cu `canonical()` din sentinel/report/beacon.py:
 * chei sortate, fără spații. Dacă cele două capete serializează diferit,
 * semnătura nu se verifică niciodată, iar eroarea arată ca o cheie greșită —
 * pierzi o zi căutând în locul nepotrivit.
 */
export function canonical(payload: Record<string, unknown>): string {
  return JSON.stringify(sortDeep(payload));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .map((k) => [k, sortDeep((value as Record<string, unknown>)[k])]),
    );
  }
  return value;
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

export function judge(state: State, now: Date): Verdict {
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
