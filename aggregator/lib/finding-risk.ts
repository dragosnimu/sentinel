/**
 * Semaforul unei constatări, așa cum îl citește agregatorul.
 *
 * Perechea în TypeScript a lui `sentinel/scan/risk_view.py`. Culoarea înseamnă
 * același lucru pe cele trei suprafețe (Telegram, panoul serverului, aici), dar
 * ele nu poartă aceeași cantitate de text: botul are câteva rânduri pe un
 * telefon, panoul unui server are un tabel, iar agregatorul vede mai multe
 * servere și arată pe fiecare rând doar CE e culoarea și DE ce, într-o linie.
 * Explicația cu cele patru puncte de decizie rămâne pe server și în bot.
 *
 * Formatarea probabilității EPSS și textele „de ce e gri" sunt aceleași la
 * ambele capete, iar `tests/unit/test_risk_view_parity.py` rulează ambele
 * implementări pe aceleași intrări și le compară. Două scrieri independente ale
 * aceluiași text sunt felul în care „roșu" și „galben" ajung să descrie același
 * rând pe două ecrane.
 *
 * ## Ce NU face
 *
 *   * nu calculează nimic: culoarea, decizia și scorul vin gata calculate de pe
 *     server. Replica afișează ce a decis serverul, ca la `priority`;
 *   * nu amestecă gazdele. Fiecare rând aparține unei singure instanțe, iar
 *     culoarea lui e verdictul ACELEI gazde (cu criticitatea, expunerea și
 *     repornirea ei). O vulnerabilitate reparată pe o gazdă și nu pe cealaltă
 *     apare ca două rânduri cu două stări, fiecare la gazda lui; niciun rând nu
 *     „se vindecă" pe baza altuia;
 *   * nu are încredere în `risk`: JSON-ul vine de pe sârmă. Se citesc doar
 *     câmpurile cunoscute, cu tipurile așteptate, iar o culoare necunoscută
 *     devine GRI — niciodată verde.
 */

export const COLORS = ["red", "amber", "green", "grey"] as const;
export type RiskColor = (typeof COLORS)[number];

/** Ordinea în liste: roșu, galben, gri, verde — gri deasupra lui verde. */
export const COLOR_ORDER: Record<RiskColor, number> = {
  red: 0, amber: 1, grey: 2, green: 3,
};

export const COLOR_LABEL_RO: Record<RiskColor, string> = {
  red: "roșu", amber: "galben", green: "verde", grey: "gri",
};

const COLOR_EMOJI: Record<RiskColor, string> = {
  red: "🔴", amber: "🟡", green: "🟢", grey: "⚪",
};

export const DECISION_LABEL_RO: Record<string, string> = {
  act: "Act — acum",
  attend: "Attend — accelerat",
  track_star: "Track* — de urmărit",
  track: "Track — ciclul obișnuit",
};
const NO_DECISION_RO = "fără date";

/**
 * Eticheta pusă lângă o culoare urcată de regula Sentinel (`risk.py`, suprapunerea
 * EPSS): aceeași ca `risk_view.OVERLAY_TAG_RO`, pe orice ecran.
 */
const OVERLAY_TAG_RO = "regula Sentinel, nu SSVC";
const OVERLAY_REASON_RO = "regula Sentinel (EPSS)";

const SOURCE_RO: Record<string, string> = {
  redhat: "Red Hat", osv: "OSV", trivy: "trivy",
};

const MISSING_RO: Record<string, string> = {
  cvss: "niciun scor CVSS",
  cvss_vector: "vectorul CVSS",
  epss: "EPSS (nu există încă pentru acest CVE)",
  epss_stale: "EPSS (valoarea e prea veche)",
  cve: "CVE (fără el nu există EPSS sau KEV)",
  kev_mirror: "lista CISA KEV (oglinda lipsește sau e veche)",
  vulnrichment: "punctele CISA (CVE-ul nu a fost încă întrebat)",
  exploitation_unpublished: "exploatarea (CISA n-a evaluat CVE-ul)",
  assessment_error: "evaluarea a eșuat",
};

const ONE_LINER_MISSING: Record<string, string> = {
  cvss: "fără CVSS", cvss_vector: "fără vector", epss: "fără EPSS",
  epss_stale: "EPSS vechi", cve: "fără CVE", kev_mirror: "KEV nelegibil",
  vulnrichment: "fără date CISA", exploitation_unpublished: "CISA n-a evaluat",
};

/** O culoare primită de pe sârmă; orice nu e una din cele patru e GRI. */
export function toColor(value: unknown): RiskColor {
  return typeof value === "string" && (COLORS as readonly string[]).includes(value)
    ? (value as RiskColor) : "grey";
}

export type RiskView = {
  color: RiskColor;
  decision: string | null;
  /** „Act — acum", „fără date". */
  headline: string;
  /** Un singur motiv scurt: „KEV", „EPSS 92,0%", „fără EPSS". */
  oneLiner: string;
  /** Doar pentru gri: „lipsește …; ar putea fi între Track și Act". */
  greyReason: string | null;
  /** „CVSS 7,5 (Red Hat)" sau „fără CVSS". */
  cvss: string;
  /** „0,45% (percentila 37)" sau „fără EPSS". */
  epss: string;
  rebootPending: boolean;
};

function obj(v: unknown): Record<string, unknown> | null {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>) : null;
}

function numOrNull(v: unknown): number | null {
  if (v === null || v === undefined || typeof v === "boolean" || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function decRo(value: number, places: number): string {
  return value.toFixed(places).replace(".", ",");
}

/**
 * Rotunjire „la jumătate în sus", la fel ca `risk_view._half_up` din Python.
 *
 * `toFixed` rotunjește pe valoarea binară (`(0.125).toFixed(2)` e "0.13" dar
 * `(1.005).toFixed(2)` e "1.00"), iar `format()` din Python rotunjește la pereche
 * pe jumătățile exacte. Aici valoarea se curăță întâi la 12 cifre semnificative,
 * ca `12.249999999999998` să fie `12.25`, apoi se rotunjește în sus. Testul de
 * paritate le rulează pe jumătăți reale (`0.1225`, `0.00125`).
 */
function halfUp(value: number, places: number): string {
  const scale = 10 ** places;
  const scaled = Number((value * scale).toPrecision(12));
  return (Math.floor(scaled + 0.5) / scale).toFixed(places).replace(".", ",");
}

/** Același text ca `risk_view.fmt_epss`. */
export function fmtEpss(p: unknown, percentile: unknown = null): string {
  const prob = numOrNull(p);
  if (prob === null) return "fără EPSS";
  const pct = Number((prob * 100).toPrecision(12));
  let text: string;
  if (pct < 0.01) text = "<0,01%";
  else if (pct < 1) text = halfUp(pct, 2) + "%";
  else text = halfUp(pct, 1) + "%";
  const ptile = numOrNull(percentile);
  if (ptile !== null) text += ` (percentila ${halfUp(ptile * 100, 0)})`;
  return text;
}

export function fmtCvss(cvss: unknown): string {
  const c = obj(cvss);
  if (c === null) return "fără CVSS";
  const score = numOrNull(c.score);
  const source = typeof c.source === "string" ? SOURCE_RO[c.source] : undefined;
  if (score === null) {
    return c.estimated
      ? "CVSS fără scor numeric (importanță estimată din severitate)"
      : "fără CVSS";
  }
  return `CVSS ${decRo(score, 1)}` + (source ? ` (${source})` : "");
}

/** `risk` din coloana JSON (text pe sârmă) ca obiect, sau `null` dacă nu se poate citi. */
export function parseRisk(raw: unknown): Record<string, unknown> | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "string") {
    try {
      return obj(JSON.parse(raw));
    } catch {
      return null;
    }
  }
  return obj(raw);
}

/**
 * `risk.overlay` dacă culoarea afișată E cea urcată de regula Sentinel. Ca în
 * Python (`risk_view.overlay_of`): la o culoare care nu e galbenă înregistrarea
 * se ignoră, ca eticheta „regula Sentinel" să nu ajungă pe un verde.
 */
function overlayOf(risk: Record<string, unknown> | null, color: RiskColor): Record<string, unknown> | null {
  if (risk === null || color !== "amber") return null;
  const o = obj(risk.overlay);
  return o !== null && o.basis === "epss_overlay" ? o : null;
}

export function headline(
  color: RiskColor, decision: string | null, risk: Record<string, unknown> | null = null,
): string {
  const label = decision !== null && decision in DECISION_LABEL_RO
    ? DECISION_LABEL_RO[decision] : NO_DECISION_RO;
  const tag = decision === "attend" && overlayOf(risk, color) !== null
    ? ` (${OVERLAY_TAG_RO})` : "";
  return `${COLOR_EMOJI[color]} ${label}${tag}`;
}

export function greyReason(risk: Record<string, unknown> | null): string | null {
  if (risk === null || Object.keys(risk).length === 0) return "încă neevaluată";
  if (risk.decision !== null && risk.decision !== undefined) return null;
  const missing = Array.isArray(risk.missing) ? risk.missing : [];
  const parts = missing.map((m) => MISSING_RO[String(m)] ?? String(m));
  let text = parts.length > 0 ? "lipsește " + parts.join(", ") : "decizia nu se poate lua";
  const possible = risk.possible;
  if (Array.isArray(possible) && possible.length === 2) {
    const [low, high] = possible.map(
      (p) => (DECISION_LABEL_RO[String(p)] ?? String(p)).split(" ")[0]);
    text += low === high ? `; oricum ar fi ${low}` : `; ar putea fi între ${low} și ${high}`;
  }
  return text;
}

export function oneLiner(color: RiskColor, risk: Record<string, unknown> | null): string {
  if (risk === null || Object.keys(risk).length === 0) return "neevaluat";
  if (color === "grey") {
    const missing = Array.isArray(risk.missing) ? risk.missing : [];
    return ONE_LINER_MISSING[String(missing[0])] ?? "fără date";
  }
  const pts = obj(risk.points);
  const expl = pts === null ? null : obj(pts.exploitation);
  const basis = expl === null ? null : expl.basis;
  const reboot = risk.reboot_pending === true ? " 🔁" : "";
  if (color === "amber" && overlayOf(risk, color) !== null) return OVERLAY_REASON_RO + reboot;
  if (basis === "kev") return "KEV" + reboot;
  if (basis === "vulnrichment" && expl !== null && expl.value === "active") {
    return "CISA: exploatat" + reboot;
  }
  const epss = obj(risk.epss);
  if (epss !== null && epss.p !== null && epss.p !== undefined) {
    return "EPSS " + fmtEpss(epss.p) + reboot;
  }
  return "—" + reboot;
}

/**
 * Tot ce arată o linie a agregatorului despre semafor, dintr-un rând al replicii.
 * Un rând fără `risk_color` (sosit înainte de migrație) e GRI, cu motivul „încă
 * neevaluată": „nu se știe" nu devine „în regulă".
 */
export function riskView(row: {
  risk_color?: unknown; risk_decision?: unknown; risk?: unknown;
  epss?: unknown; epss_percentile?: unknown;
}): RiskView {
  const color = toColor(row.risk_color);
  const risk = parseRisk(row.risk);
  const decision = typeof row.risk_decision === "string" ? row.risk_decision : null;
  // Culoarea și decizia vin din două coloane; dacă nu se potrivesc (un rând
  // stricat), culoarea cade pe gri în loc să creadă una din ele.
  const consistent = decision === null ? color === "grey"
    : (decision === "act" ? color === "red"
      : decision === "attend" ? color === "amber"
        : (decision === "track" || decision === "track_star") ? color === "green" : false);
  const safeColor: RiskColor = consistent ? color : "grey";
  const safeDecision = consistent ? decision : null;
  return {
    color: safeColor,
    decision: safeDecision,
    headline: headline(safeColor, safeDecision, risk),
    oneLiner: oneLiner(safeColor, risk),
    greyReason: safeColor === "grey" ? greyReason(risk) ?? "decizia nu se poate lua" : null,
    cvss: fmtCvss(risk === null ? null : risk.cvss),
    epss: fmtEpss(row.epss, row.epss_percentile),
    rebootPending: risk !== null && risk.reboot_pending === true,
  };
}

/** Numărătoarea pe culori a unei liste de rânduri. Culorile cu zero rămân în obiect. */
export function countColors(rows: { risk_color?: unknown }[]): Record<RiskColor, number> {
  const out: Record<RiskColor, number> = { red: 0, amber: 0, green: 0, grey: 0 };
  for (const r of rows) out[toColor(r.risk_color)] += 1;
  return out;
}
