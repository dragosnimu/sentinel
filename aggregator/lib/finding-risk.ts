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

/**
 * Eticheta spune ce are de făcut cel care citește, nu numele din arborele CISA
 * (`risk.DECISION_LABEL_RO`): „Attend — accelerat" urmat de „KEV" nu se citea ca o
 * propoziție. Numele SSVC rămân în `DECISION_SSVC_NAME`, pentru tooltip.
 */
export const DECISION_LABEL_RO: Record<string, string> = {
  act: "Acum",
  attend: "Curând",
  track_star: "De urmărit*",
  track: "Ciclul obișnuit",
};
const NO_DECISION_RO = "Nedecis";

/** Numele deciziei în vocabularul CISA SSVC (`risk.DECISION_SSVC_NAME`). */
const DECISION_SSVC_NAME: Record<string, string> = {
  act: "Act", attend: "Attend", track_star: "Track*", track: "Track",
};

/** Culoarea fiecărei decizii (`ssvc.COLOR_OF`). */
const DECISION_COLOR: Record<string, RiskColor> = {
  act: "red", attend: "amber", track_star: "green", track: "green",
};

/**
 * Marcajul pus lângă o culoare urcată de regula Sentinel (`risk.py`, suprapunerea
 * EPSS): același ca `risk_view.OVERLAY_TAG_RO`, pe orice ecran.
 */
const OVERLAY_TAG_RO = "regula Sentinel";

/**
 * Sub ce EPSS un verde nu mai are nimic de spus despre EPSS pe rândul lui. Egal cu
 * `risk.OVERLAY_MIN_EPSS` (0,5), ca în `risk_view.NOTEWORTHY_EPSS`: paritatea îl
 * ține la același loc cu cazuri de-o parte și de alta a pragului.
 */
const NOTEWORTHY_EPSS = 0.5;

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

/** Ce lipsește, în două-trei cuvinte: textul unui gri într-o celulă de tabel. */
const MISSING_SHORT_RO: Record<string, string> = {
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
  /** „🔴 Acum", „⚪ Nedecis", „🟡 Curând · regula Sentinel". */
  headline: string;
  /**
   * A doua linie a celulei „Risc": „exploatat activ (KEV)", „EPSS 92,0%", sau `null`
   * când n-ar spune nimic (un verde cu EPSS mic: cifra e în coloana EPSS). Pentru un
   * gri e `greyReason`, mereu. Fără 🔁 — semnul vine din `rebootPending`.
   */
  reason: string | null;
  /** Doar pentru gri, pe scurt: „fără CVE". */
  greyReason: string | null;
  /** Tooltip-ul celulei: ce nu încape în ea (ce lipsește la un gri, a cui e decizia). */
  detail: string | null;
  /** „CVSS 7,5 (Red Hat)" sau „fără CVSS". */
  cvss: string;
  /** „0,45% (percentila 37)" sau „fără EPSS". */
  epss: string;
  /** „da — 2026-10-12", „nu", sau „nu se știe" (vezi `fmtKev`). */
  kev: string;
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
    ? ` · ${OVERLAY_TAG_RO}` : "";
  return `${COLOR_EMOJI[color]} ${label}${tag}`;
}

/** Numele SSVC al unei decizii („Attend"), sau `null` fără decizie ori una necunoscută. */
export function ssvcName(decision: unknown): string | null {
  return typeof decision === "string" ? own(DECISION_SSVC_NAME, decision) ?? null : null;
}

/**
 * Numele unei STĂRI, unul singur pe orice ecran (`risk_view.COLOR_STATE_RO`): eticheta
 * deciziei, nu numele culorii și nu o descriere a cauzei. „Roșu", „fără date" și „Nedecis"
 * erau trei nume ale aceleiași stări, la trei clicuri una de alta. Cuvintele de culoare
 * rămân doar ca argument de filtru (`?culoare=gri`) și în titlul unei pastile. Verdele are
 * două decizii, deci grupa lui poartă ambele etichete.
 */
export const COLOR_STATE_RO: Record<RiskColor, string> = {
  red: DECISION_LABEL_RO.act,
  amber: DECISION_LABEL_RO.attend,
  green: `${DECISION_LABEL_RO.track} / ${DECISION_LABEL_RO.track_star}`,
  grey: NO_DECISION_RO,
};

/** Numele SSVC ale deciziilor unei culori („Track / Track*"), sau `null` la gri. */
function ssvcNamesOf(color: RiskColor): string | null {
  const names = (["track", "track_star", "attend", "act"] as const)
    .filter((d) => DECISION_COLOR[d] === color).map((d) => DECISION_SSVC_NAME[d]);
  return names.length > 0 ? names.join(" / ") : null;
}

/** Ca `risk_view.state_with_ssvc`: „Acum (Act)", „Nedecis". */
export function stateWithSsvc(color: RiskColor): string {
  const ssvcNames = ssvcNamesOf(color);
  return ssvcNames === null ? COLOR_STATE_RO[color] : `${COLOR_STATE_RO[color]} (${ssvcNames})`;
}

/** Ca `risk_view.pill_title`: tooltip-ul unei pastile de culoare. */
export function pillTitle(color: RiskColor): string {
  const ssvcNames = ssvcNamesOf(color);
  const what = ssvcNames === null ? "nu se poate decide: lipsesc date"
    : `decizia CISA SSVC: ${ssvcNames}`;
  return `${COLOR_LABEL_RO[color]} · ${what}`;
}

/**
 * Legenda stărilor, din aceleași etichete pe care le scrie `headline` (ca
 * `risk_view.legend_states`): o legendă scrisă de mână se poate abate de la ele fără ca
 * nimic să se strice la vedere.
 */
export function legendStates(): string {
  const parts = (["act", "attend", "track", "track_star"] as const).map((d) =>
    `${COLOR_EMOJI[DECISION_COLOR[d]]} ${DECISION_LABEL_RO[d]} (${DECISION_SSVC_NAME[d]})`);
  parts.push(`${COLOR_EMOJI.grey} ${NO_DECISION_RO} (lipsesc date)`);
  return parts.join(" · ");
}

/** Ca `risk_view.counts_ro`: „Acum 1 · Curând 3 · Nedecis 27"; Nedecis apare mereu. */
export function countsRo(red: number, amber: number, grey: number): string {
  return `${COLOR_STATE_RO.red} ${red} · ${COLOR_STATE_RO.amber} ${amber} · `
    + `${COLOR_STATE_RO.grey} ${grey}`;
}

/**
 * De ce celula KEV poate spune „nu se știe" (`risk_view.KEV_UNKNOWN_NOTE_RO`). Fără „a eșuat":
 * `scan-age.test.ts` caută cuvântul în toată pagina ca să prindă o scanare în curs anunțată
 * ca eșec, iar legenda l-ar fi aprins.
 */
export const KEV_UNKNOWN_NOTE_RO = "nu s-a căutat: lista KEV n-a putut fi citită, rândul n-are CVE, "
  + "evaluarea lui s-a oprit cu o eroare sau încă n-a fost făcută";

/**
 * Valoarea unei chei PROPRII a vocabularului. `MAP["constructor"]` e funcția lui `Object`,
 * nu `undefined`: un cod „ce lipsește" cu un astfel de nume ar fi ajuns în pagină ca
 * textul funcției. Python n-are problema (`dict.get`), deci paritatea o dovedește.
 */
function own(map: Record<string, string>, key: string): string | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

/**
 * Se poate spune „nu e în KEV"? Nu, dacă lista n-a putut fi citită, dacă rândul n-are
 * CVE, dacă n-a fost evaluat niciodată sau dacă evaluarea a căzut (`assessment_error`:
 * `kev` e atunci valoarea veche, nu o căutare de azi). Ca `risk_view._kev_unknown`.
 */
function kevUnknown(risk: Record<string, unknown> | null): boolean {
  if (risk === null || Object.keys(risk).length === 0) return true;
  return Array.isArray(risk.missing)
    && risk.missing.some((m) => ["cve", "kev_mirror", "assessment_error"].includes(String(m)));
}

/**
 * Celula KEV: „da — 2026-10-12", „nu", sau „nu se știe". „nu" se scrie numai când s-a
 * căutat: un rând fără CVE, cu oglinda KEV lipsă ori veche sau a cărui evaluare a căzut nu
 * poate fi „în afara" listei, iar un „nu" acolo ar liniști despre exact ce nu s-a verificat. Același text ca
 * `risk_view.fmt_kev`.
 */
export function fmtKev(
  kev: boolean, due: unknown, risk: Record<string, unknown> | null,
): string {
  if (kev) {
    return "da" + (due !== null && due !== undefined && String(due) !== "" ? ` — ${String(due)}` : "");
  }
  return kevUnknown(risk) ? "nu se știe" : "nu";
}

/** Tot ce se știe despre un gri, într-o propoziție — textul lung, pentru tooltip. Ca
 * `risk_view.grey_detail`. */
export function greyDetail(risk: Record<string, unknown> | null): string | null {
  if (risk === null || Object.keys(risk).length === 0) return "încă neevaluată";
  if (risk.decision !== null && risk.decision !== undefined) return null;
  const missing = Array.isArray(risk.missing) ? risk.missing : [];
  const parts = missing.map((m) => own(MISSING_RO, String(m)) ?? String(m));
  let text = parts.length > 0 ? "lipsește " + parts.join(", ") : "decizia nu se poate lua";
  const possible = risk.possible;
  if (Array.isArray(possible) && possible.length === 2) {
    const [low, high] = possible.map((p) => ssvcName(p) ?? String(p));
    text += low === high ? `; oricum ar fi ${low}` : `; ar putea fi între ${low} și ${high}`;
  }
  return text;
}

/** Ce lipsește, pe scurt — „fără CVE". Ca `risk_view.grey_reason`. */
export function greyReason(risk: Record<string, unknown> | null): string | null {
  if (risk === null || Object.keys(risk).length === 0) return "încă neevaluată";
  if (risk.decision !== null && risk.decision !== undefined) return null;
  const missing = Array.isArray(risk.missing) ? risk.missing : [];
  const parts: string[] = [];
  for (const m of missing) {
    const text = own(MISSING_SHORT_RO, String(m)) || (own(MISSING_RO, String(m)) ?? String(m));
    if (!parts.includes(text)) parts.push(text);
  }
  return parts.length > 0 ? parts.join(", ") : "decizia nu se poate lua";
}

/** „EPSS 99,2%, CISA veche" — faptul din spatele unui galben al regulii Sentinel. Ca
 * `risk_view.overlay_reason`. */
function overlayReason(overlay: Record<string, unknown>): string {
  const epss = numOrNull(overlay.epss) !== null ? "EPSS " + fmtEpss(overlay.epss) : "EPSS mare";
  const asOf = overlay.observation_as_of;
  const dated = typeof asOf === "string" && asOf !== ""
    && numOrNull(overlay.observation_age_days) !== null;
  return `${epss}, CISA ${dated ? "veche" : "nedatată"}`;
}

/**
 * A doua linie a celulei „Risc", sau `null` când n-ar spune nimic: un verde al cărui
 * singur motiv ar fi un EPSS mic nu primește linie (cifra e în coloana EPSS). Ca
 * `risk_view.reason_line`. Un gri primește mereu linie: griul fără motiv ar citi „în
 * regulă".
 */
export function reasonLine(color: RiskColor, risk: Record<string, unknown> | null): string | null {
  if (color === "grey") return greyReason(risk) ?? "decizia nu se poate lua";
  if (risk === null || Object.keys(risk).length === 0) return "neevaluat";
  const overlay = overlayOf(risk, color);
  if (overlay !== null) return overlayReason(overlay);
  const pts = obj(risk.points);
  const expl = pts === null ? null : obj(pts.exploitation);
  const basis = expl === null ? null : expl.basis;
  if (basis === "kev") return "exploatat activ (KEV)";
  if (basis === "vulnrichment" && expl !== null && expl.value === "active") {
    return "exploatat activ (CISA)";
  }
  const epss = obj(risk.epss);
  const p = epss === null ? null : numOrNull(epss.p);
  if (p !== null && (color !== "green" || p >= NOTEWORTHY_EPSS)) {
    return "EPSS " + fmtEpss(epss === null ? null : epss.p);
  }
  return null;
}

/**
 * Tooltip-ul celulei „Risc": ce nu încape în ea. Agregatorul n-are un ecran de detaliu
 * (cele patru puncte de decizie rămân pe server și în bot), deci aici stau doar a cui e
 * decizia și, la un gri, tot ce lipsește. La un galben al regulii Sentinel NU se scrie
 * „Attend": arborele a dat altceva, și asta se spune.
 */
function detailOf(
  color: RiskColor, decision: string | null, risk: Record<string, unknown> | null,
): string | null {
  if (color === "grey") return greyDetail(risk);
  const overlay = decision === "attend" ? overlayOf(risk, color) : null;
  if (overlay !== null) {
    return "Urcat de regula Sentinel, nu decis de CISA SSVC; SSVC singur ar fi dat "
      + (ssvcName(overlay.ssvc_decision) ?? "altceva");
  }
  const name = ssvcName(decision);
  return name === null ? null : `Decizie CISA SSVC: ${name}`;
}

/**
 * Tot ce arată o linie a agregatorului despre semafor, dintr-un rând al replicii.
 * Un rând fără `risk_color` (sosit înainte de migrație) e GRI, cu motivul „încă
 * neevaluată": „nu se știe" nu devine „în regulă".
 */
export function riskView(row: {
  risk_color?: unknown; risk_decision?: unknown; risk?: unknown;
  epss?: unknown; epss_percentile?: unknown; kev?: unknown; kev_due_date?: unknown;
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
    reason: reasonLine(safeColor, risk),
    greyReason: safeColor === "grey" ? greyReason(risk) ?? "decizia nu se poate lua" : null,
    detail: detailOf(safeColor, safeDecision, risk),
    cvss: fmtCvss(risk === null ? null : risk.cvss),
    epss: fmtEpss(row.epss, row.epss_percentile),
    // `=== 1`, nu adevăr: coloana e `TINYINT(1)` și `Boolean("0")` e ADEVĂRAT.
    kev: fmtKev(Number(row.kev) === 1, row.kev_due_date, risk),
    rebootPending: risk !== null && risk.reboot_pending === true,
  };
}

/** Numărătoarea pe culori a unei liste de rânduri. Culorile cu zero rămân în obiect. */
export function countColors(rows: { risk_color?: unknown }[]): Record<RiskColor, number> {
  const out: Record<RiskColor, number> = { red: 0, amber: 0, green: 0, grey: 0 };
  for (const r of rows) out[toColor(r.risk_color)] += 1;
  return out;
}
