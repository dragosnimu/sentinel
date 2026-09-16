/**
 * Cifrele, seriile și clasamentele de pe pagina de rezumat.
 *
 * Ce alimentează panoul serverului monitorizat și ce alimentează panoul ăsta nu
 * sunt aceleași date, iar diferența e o consecință directă a graniței de date
 * din `docs/PLAN-arhitectura-distribuita.md`:
 *
 *   * **se poate**: evenimente pe oră și pe sursă (`event_rollup_1h`), detecții
 *     cu `src_ip` și `rule_id`, incidente pe severitate, constatări, blocări;
 *   * **nu se poate încă**: originea pe țară și pe operator de rețea — vine din
 *     `actors`, flux nedeclarat la niciun capăt; și istoricul de disponibilitate
 *     al serviciilor, care ar veni din `availability_rollup`.
 *
 * Ce nu se poate NU se aproximează. Un panou care desenează o hartă din ce are
 * la îndemână arată la fel de convingător ca unul care o desenează din date
 * reale, iar cine se uită n-are cum să deosebească.
 *
 * ## De ce o singură funcție, și de ce se însumează AICI
 *
 * Cinci citiri mărginite, șase derivări. Fiecare rând de detecție hrănește și
 * clasamentul de atacatori, și pe cel de reguli, și cronologia; fiecare rând de
 * agregat hrănește și graficul, și clasamentul de surse. Citite separat, ar fi
 * zece interogări peste aceleași rânduri, la momente ușor diferite — iar un
 * grafic și un clasament care nu sunt de acord se citesc ca un defect.
 *
 * Ce se cere de aici e probat în `tests/overview.test.ts`.
 *
 * Însumarea se face în TypeScript, ca în `lib/data/rollups.ts`. Motivul nu e
 * gustul: `SUM(CASE WHEN …)` și `COUNT(DISTINCT CASE WHEN …)` n-ar putea fi
 * duse prin dublul din `tests/auth-harness.ts` fără să-i crească o gramatică
 * SQL adevărată — iar un dublu care ajunge motor SQL nu mai probează codul
 * livrat, ci pe el însuși.
 *
 * Prețul e o citire mărginită: peste `MAX_ROWS_READ` rânduri, ce urmează e
 * TĂIAT, iar tăierea se raportează în `truncated` și se scrie pe pagină. Un
 * plafon tăcut arată exact ca „atât a fost".
 *
 * `instanceId` e un FILTRU peste domeniu, nu un domeniu; vezi nota lungă din
 * `lib/data/detections.ts`.
 */

import { scopePlaceholders, seesNothing } from "../auth/scope";
import type { AuthDb } from "../auth/db";
import type { InstanceScope } from "../auth/scope";

/** O pereche „acum / înainte", din care iese tendința. */
export type Trend = { now: number; before: number };

export type Overview = {
  /** Adrese distincte care au produs detecții în fereastră. */
  attackers: Trend;
  /** Detecții în fereastră — ce a văzut motorul, nu tot ce s-a întâmplat. */
  detections: Trend;
  /** Evenimente numărate de colectori, din contorul orar. */
  events: Trend;
  incidentsOpen: number;
  incidentsSevere: number;
  findingsOpen: number;
  blocksActive: number;
  /** Incidentele deschise, pe severitate, cu cele grave întâi. */
  bySeverity: { severity: string; count: number }[];
};

/** O oră, cu evenimentele despărțite pe sursă. */
export type SourceHour = { bucket: number; bySource: Record<string, number> };

export type Ranked = { key: string; count: number; extra: string };

export type Rankings = {
  attackers: Ranked[];
  rules: Ranked[];
  sources: Ranked[];
};

export type ActivityItem = {
  at: number;
  kind: "detection" | "block";
  title: string;
  detail: string;
  severity: string;
};

export type Summary = {
  overview: Overview;
  series: SourceHour[];
  rankings: Rankings;
  activity: ActivityItem[];
  /** Ce citire a atins plafonul. Gol când niciuna n-a atins. */
  truncated: string[];
};

/** Fereastra cifrelor de sus. Aceeași ca pe panoul serverului. */
export const WINDOW_HOURS = 24;

/** Câte ore intră în graficul stivuit. */
export const SERIES_HOURS = 48;

/** Câte intrări are un clasament înainte de coada lungă. */
export const RANK_LIMIT = 7;

/** Câte rânduri are cronologia. */
export const ACTIVITY_LIMIT = 14;

/**
 * Plafonul fiecărei citiri.
 *
 * Aceeași valoare ca în `lib/data/rollups.ts`, și din același motiv: un panou
 * care citește nemărginit dintr-o bază partajată e o pană de găzduire în
 * așteptare. Atins, se SPUNE — vezi `truncated`.
 */
export const MAX_ROWS_READ = 5000;

const EMPTY: Summary = {
  overview: {
    attackers: { now: 0, before: 0 }, detections: { now: 0, before: 0 },
    events: { now: 0, before: 0 }, incidentsOpen: 0, incidentsSevere: 0,
    findingsOpen: 0, blocksActive: 0, bySeverity: [],
  },
  series: [], rankings: { attackers: [], rules: [], sources: [] },
  activity: [], truncated: [],
};

/** Ordinea în care se citesc severitățile: ce e grav, întâi. */
const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/** Constatările care încă cer ceva de la operator. */
const FINDING_OPEN = new Set(["open", "patch_planned", "patching", "deferred"]);

const HOUR_MS = 3_600_000;

function num(v: unknown): number {
  // Driverul întoarce `count(*)` și `SUM()` ca ȘIRURI când sunt mari. `"9" > "10"`
  // pe șiruri, iar o adunare devine concatenare — greșeli care nu pică nimic.
  return Number(v ?? 0);
}

/** `YYYY-MM-DD HH:MM:SS[.ffffff]` — cum scrie MariaDB un `DATETIME(6)` ca text. */
const BARE_DATETIME = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?$/;

/**
 * Un moment, ca milisecunde.
 *
 * Trei forme, fiindcă driverul chiar întoarce trei: `Date`, număr, și ȘIR fără
 * fus orar. A treia e capcana. `new Date("2026-08-16 10:00:00")` citește ora ca
 * fiind LOCALĂ, iar coloanele astea sunt UTC prin construcție — pe o gazdă pe
 * fusul României, fiecare moment ar aluneca cu două-trei ore.
 *
 * Simptomul n-ar fi o eroare: cronologia ar fi în ordinea corectă, doar cu ore
 * greșite, iar detecțiile de la marginea ferestrei ar trece dintr-o jumătate în
 * alta. Prins de dublu, care formatează exact ca MariaDB.
 */
function ms(v: unknown): number {
  if (v instanceof Date) return v.getTime();
  if (typeof v === "number") return v;
  const s = String(v);
  const m = BARE_DATETIME.exec(s);
  if (m === null) return new Date(s).getTime();
  const frac = (m[7] ?? "").padEnd(3, "0").slice(0, 3);
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
                  Number(m[4]), Number(m[5]), Number(m[6]), Number(frac));
}

function text(v: unknown): string | null {
  return v === null || v === undefined ? null : String(v);
}

type Tally = { n: number; extra: Set<string> };

function bump(into: Map<string, Tally>, key: string, n: number, extra: string | null) {
  const slot = into.get(key) ?? { n: 0, extra: new Set<string>() };
  slot.n += n;
  if (extra !== null) slot.extra.add(extra);
  into.set(key, slot);
}

function ranked(counts: Map<string, Tally>, unit: string): Ranked[] {
  return [...counts.entries()]
    .sort((a, b) => (b[1].n - a[1].n) || (a[0] < b[0] ? -1 : 1))
    .slice(0, RANK_LIMIT)
    .map(([key, v]) => ({ key, count: v.n, extra: `${v.extra.size} ${unit}` }));
}

/**
 * Tot ce desenează pagina de rezumat, dintr-o singură trecere.
 *
 * Ferestrele se taie în SQL, deci pe ceasul BAZEI, iar despărțirea
 * „acum / înainte" se face cu ACELAȘI ceas, citit o dată. Prima versiune folosea
 * ceasul procesului pentru a doua jumătate; între gazda de web și cea de bază
 * derapajul e real, iar simptomul ar fi fost o tendință de „−100%" pe un trafic
 * care n-a scăzut deloc.
 */
export async function summary(
  db: AuthDb, allowedInstanceIds: InstanceScope, instanceId: string,
): Promise<Summary> {
  if (seesNothing(allowedInstanceIds)) return EMPTY;

  const scope = scopePlaceholders(allowedInstanceIds);
  const ids = [...allowedInstanceIds.allowedInstanceIds, instanceId];
  const truncated: string[] = [];

  // --- detecții: două ferestre, două clasamente, jumătate din cronologie -----
  const detections = await db.all(
    "SELECT ts, rule_id, severity, src_ip FROM detection_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND suppressed = 0 ` +
    "   AND ts >= UTC_TIMESTAMP(6) - INTERVAL ? HOUR " +
    " ORDER BY ts DESC LIMIT ?",
    [...ids, WINDOW_HOURS * 2, MAX_ROWS_READ]);
  if (detections.length >= MAX_ROWS_READ) truncated.push("detecții");

  // --- contorul orar: graficul stivuit, clasamentul de surse, evenimentele ---
  const hours = await db.all(
    "SELECT bucket, source, n FROM event_rollup_1h_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? ` +
    "   AND bucket >= UTC_TIMESTAMP(6) - INTERVAL ? HOUR " +
    " ORDER BY bucket DESC LIMIT ?",
    [...ids, Math.max(SERIES_HOURS, WINDOW_HOURS * 2), MAX_ROWS_READ]);
  if (hours.length >= MAX_ROWS_READ) truncated.push("contorul orar");

  const incidents = await db.all(
    "SELECT severity FROM incident_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? AND status = 'open' ` +
    " LIMIT ?",
    [...ids, MAX_ROWS_READ]);
  if (incidents.length >= MAX_ROWS_READ) truncated.push("incidente");

  const findings = await db.all(
    "SELECT status FROM finding_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? LIMIT ?`,
    [...ids, MAX_ROWS_READ]);
  if (findings.length >= MAX_ROWS_READ) truncated.push("constatări");

  const blocks = await db.all(
    "SELECT ip, reason, blocked_at, active FROM blocklist_entries " +
    ` WHERE instance_id IN (${scope}) AND instance_id = ? ` +
    " ORDER BY blocked_at DESC LIMIT ?",
    [...ids, MAX_ROWS_READ]);
  if (blocks.length >= MAX_ROWS_READ) truncated.push("blocări");

  // --------------------------------------------------------------------------
  // UN singur ceas. Ferestrele de mai sus sunt tăiate de bază; despărțirea
  // „acum / înainte" se face cu ACELAȘI ceas, citit o dată. Cu ceasul
  // procesului, un derapaj de câteva minute între gazda de web și cea de bază ar
  // muta ore întregi dintr-o jumătate în alta — iar simptomul ar fi o tendință
  // de „−100%" pe un trafic care n-a scăzut deloc.
  const [clock] = await db.all("SELECT UTC_TIMESTAMP(6) AS acum", []);
  const acum = ms(clock?.acum);
  const cut = acum - WINDOW_HOURS * HOUR_MS;
  const seriesFrom = acum - SERIES_HOURS * HOUR_MS;

  const attNow = new Set<string>();
  const attBefore = new Set<string>();
  let detNow = 0;
  let detBefore = 0;
  const byAttacker = new Map<string, Tally>();
  const byRule = new Map<string, Tally>();

  for (const r of detections) {
    const at = ms(r.ts);
    const ip = text(r.src_ip);
    const rule = String(r.rule_id);
    if (at < cut) {
      detBefore += 1;
      if (ip !== null) attBefore.add(ip);
      continue;
    }
    detNow += 1;
    if (ip !== null) {
      attNow.add(ip);
      bump(byAttacker, ip, 1, rule);
    }
    bump(byRule, rule, 1, ip);
  }

  let evNow = 0;
  let evBefore = 0;
  const bySource = new Map<string, Tally>();
  const byBucket = new Map<number, Record<string, number>>();

  for (const r of hours) {
    const at = ms(r.bucket);
    const source = String(r.source);
    const n = num(r.n);
    if (at >= cut) {
      evNow += n;
      // Ora, ca „din câte ore a venit sursa asta": o sursă cu 900 de evenimente
      // într-o oră și una cu 900 împrăștiate pe douăzeci nu sunt același lucru.
      bump(bySource, source, n, String(at));
    } else {
      evBefore += n;
    }
    if (at >= seriesFrom) {
      const slot = byBucket.get(at) ?? {};
      slot[source] = (slot[source] ?? 0) + n;
      byBucket.set(at, slot);
    }
  }

  const sev = new Map<string, number>();
  for (const r of incidents) {
    const s = String(r.severity);
    sev.set(s, (sev.get(s) ?? 0) + 1);
  }
  const bySeverity = [...sev.entries()]
    .map(([severity, count]) => ({ severity, count }))
    .sort((a, b) => {
      const ia = SEVERITY_ORDER.indexOf(a.severity);
      const ib = SEVERITY_ORDER.indexOf(b.severity);
      // O severitate necunoscută merge la coadă, nu în față: inventată de o
      // versiune viitoare, n-are voie să se prezinte drept cea mai gravă.
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });

  const activity: ActivityItem[] = [
    ...detections.slice(0, ACTIVITY_LIMIT).map((r) => ({
      at: ms(r.ts), kind: "detection" as const,
      title: String(r.rule_id),
      detail: text(r.src_ip) ?? "",
      severity: String(r.severity ?? "info"),
    })),
    ...blocks.slice(0, ACTIVITY_LIMIT).map((r) => ({
      at: ms(r.blocked_at), kind: "block" as const,
      title: "IP blocat", detail: String(r.ip),
      severity: text(r.reason) ?? "",
    })),
  ];
  activity.sort((a, b) => b.at - a.at);

  return {
    overview: {
      attackers: { now: attNow.size, before: attBefore.size },
      detections: { now: detNow, before: detBefore },
      events: { now: evNow, before: evBefore },
      incidentsOpen: incidents.length,
      incidentsSevere: bySeverity
        .filter((s) => s.severity === "critical" || s.severity === "high")
        .reduce((a, s) => a + s.count, 0),
      findingsOpen: findings.filter((r) => FINDING_OPEN.has(String(r.status))).length,
      blocksActive: blocks.filter((r) => Number(r.active) === 1).length,
      bySeverity,
    },
    series: [...byBucket.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([bucket, sources]) => ({ bucket, bySource: sources })),
    rankings: {
      attackers: ranked(byAttacker, "reguli"),
      rules: ranked(byRule, "IP"),
      sources: ranked(bySource, "ore"),
    },
    activity: activity.slice(0, ACTIVITY_LIMIT),
    truncated,
  };
}
