/**
 * Grafice desenate pe server, ca SVG. Fără bibliotecă, fără `<script>`.
 *
 * ## De ce nu se poate altfel aici
 *
 * CSP-ul panoului e `default-src 'none'` cu `style-src 'self'`, livrat prin
 * meta-tag fiindcă CDN-ul găzduirii înlocuiește antetul (vezi `lib/csp.ts`).
 * Deci: niciun script, și niciun `style="height:…"` — browserul aruncă
 * atributele de stil inline sub politica asta. Un grafic desenat cu ele nu se
 * vede deloc, iar ce se vede în loc arată exact ca „nu s-a întâmplat nimic".
 *
 * `x`, `y`, `width`, `height` sunt atribute de PREZENTARE SVG, nu CSS, deci
 * trec. Culoarea vine din clase, din `panel.css`.
 *
 * ## Ce face graficul ăsta și panoul serverului nu
 *
 * **O oră fără măsurătoare nu e o oră cu zero.** Sărită, linia se închide peste
 * ea și o pană arată ca liniște. Desenată ca bară de zero, arată ca o oră în
 * care chiar nu s-a întâmplat nimic. Aici e a treia stare, marcată vizibil, cu
 * legenda scrisă sub grafic — pe o gazdă care are trafic în fiecare oră,
 * absența unei ore înseamnă că nu s-a măsurat, iar aia e o informație.
 *
 * ## Axa pleacă de la zero, întotdeauna
 *
 * O axă tăiată face dintr-o creștere de 3% un munte. Pe un panou de securitate,
 * unde cifra se citește în trei secunde și se acționează pe ea, asta e chiar
 * felul în care un grafic minte fără să scrie nimic fals.
 */

/** O oră din serie. `value === null` înseamnă „nu s-a măsurat", nu „zero". */
export type Point = {
  /** Eticheta intervalului, exact cum vine din bază. */
  bucket: string;
  value: number | null;
  /** Ce se arată la hover. Gata scris, ca geometria să nu știe despre limbă. */
  title: string;
};

export type Bar = {
  x: number; y: number; w: number; h: number;
  title: string;
  /** `true` pentru o oră fără măsurătoare: se desenează altfel. */
  missing: boolean;
};

export type Tick = { x: number; label: string };

export type BarGeometry = {
  width: number;
  height: number;
  /** Linia de zero, în coordonate SVG. */
  baseline: number;
  /** Cea mai mare valoare din serie — capătul de sus al axei. */
  peak: number;
  bars: Bar[];
  ticks: Tick[];
  /** Liniile de grilă orizontale, cu eticheta lor. */
  grid: { y: number; label: string }[];
  /** `true` când seria n-are nicio valoare măsurată. */
  empty: boolean;
};

export const CHART_W = 720;
export const CHART_H = 180;
const PAD_L = 44;
const PAD_R = 6;
const PAD_T = 10;
const PAD_B = 26;

/** Câte etichete de timp încap fără să se calce. */
const MAX_TICKS = 8;

/**
 * Rotunjește capătul de sus la ceva ce se citește: 1, 2, 5 × 10^n.
 *
 * O axă care se termină la 1743 cere cititorului să facă împărțiri în cap.
 * Una care se termină la 2000 se citește dintr-o privire, iar barele îți spun
 * la fel de mult.
 */
export function niceCeiling(value: number): number {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const magnitude = Math.pow(10, Math.floor(Math.log10(value)));
  for (const step of [1, 2, 5, 10]) {
    const candidate = step * magnitude;
    if (candidate >= value) return candidate;
  }
  return 10 * magnitude;
}

/** Numere lungi, scurtate: `1.7k`, `2.3M`. Cifrele mari nu încap pe axă. */
export function shortNumber(n: number): string {
  const abs = Math.abs(n);
  if (abs >= 1_000_000) return `${(n / 1_000_000).toFixed(abs >= 10_000_000 ? 0 : 1)}M`;
  if (abs >= 1_000) return `${(n / 1_000).toFixed(abs >= 10_000 ? 0 : 1)}k`;
  return String(Math.round(n));
}

/**
 * Geometria unui grafic cu bare. Funcție PURĂ: numere în, numere afară.
 *
 * Separată de randare din același motiv pentru care e separată și pe server:
 * forma unui grafic se poate proba fără browser și fără bază, iar un test care
 * ar avea nevoie de amândouă nu se scrie niciodată.
 */
export function barGeometry(points: Point[], labelOf: (p: Point) => string): BarGeometry {
  const inner = { w: CHART_W - PAD_L - PAD_R, h: CHART_H - PAD_T - PAD_B };
  const baseline = PAD_T + inner.h;
  const measured = points.filter((p) => p.value !== null) as { value: number }[];
  const empty = measured.length === 0;

  // Capătul de sus vine din date, dar NICIODATĂ sub 1: o serie numai de zerouri
  // împărțită la zero ar da bare de înălțime `NaN`, iar `NaN` într-un atribut
  // SVG e o bară care nu se desenează — adică date care dispar în tăcere.
  const peak = niceCeiling(empty ? 1 : Math.max(...measured.map((m) => m.value)));

  const slot = points.length > 0 ? inner.w / points.length : inner.w;
  const gap = Math.min(2, slot * 0.18);
  const barW = Math.max(1, slot - gap);

  const bars: Bar[] = points.map((p, i) => {
    const x = PAD_L + i * slot + gap / 2;
    if (p.value === null) {
      // Toată înălțimea, ca semn de „nu s-a măsurat" — nu o bară de zero, care
      // ar spune altceva. Se desenează cu altă clasă, definită în `panel.css`.
      return { x, y: PAD_T, w: barW, h: inner.h, title: p.title, missing: true };
    }
    const h = peak > 0 ? (p.value / peak) * inner.h : 0;
    return { x, y: baseline - h, w: barW, h, title: p.title, missing: false };
  });

  const every = Math.max(1, Math.ceil(points.length / MAX_TICKS));
  const ticks: Tick[] = points
    .map((p, i) => ({ i, p }))
    .filter(({ i }) => i % every === 0)
    .map(({ i, p }) => ({ x: PAD_L + i * slot + barW / 2, label: labelOf(p) }));

  // Trei linii de grilă: jos, mijloc, sus. Mai multe pe 180 de pixeli devin
  // hașură, iar o grilă pe care n-o poți citi e doar zgomot peste date.
  const grid = [0, 0.5, 1].map((frac) => ({
    y: baseline - frac * inner.h,
    label: shortNumber(peak * frac),
  }));

  return { width: CHART_W, height: CHART_H, baseline, peak, bars, ticks, grid, empty };
}

/** O bară orizontală dintr-un clasament — „din ce vine traficul". */
export type RankRow = { label: string; value: number; title: string };

export type RankGeometry = {
  rows: { label: string; title: string; value: string; pct: number }[];
  total: number;
};

/**
 * Clasamentul, ca procente din cel mai mare — nu din total.
 *
 * Din total, o listă cu douăzeci de surse dă douăzeci de bare aproape
 * invizibile și nu se compară nimic cu nimic. Din maxim, prima e plină și
 * restul se citesc față de ea, care e chiar întrebarea: „cât de departe e a
 * doua de prima".
 *
 * Lățimea NU se pune în `style` — vezi capul modulului. Ajunge în marcaj ca
 * atribut `width` pe un `<rect>` SVG.
 */
export function rankGeometry(rows: RankRow[]): RankGeometry {
  const peak = rows.reduce((a, r) => Math.max(a, r.value), 0);
  return {
    total: rows.reduce((a, r) => a + r.value, 0),
    rows: rows.map((r) => ({
      label: r.label,
      title: r.title,
      value: shortNumber(r.value),
      // Minim 1%, ca o sursă cu o singură apariție să rămână vizibilă. Zero ar
      // face-o să dispară, iar o intrare care există dar nu se vede e mai rea
      // decât una absentă: pare că n-ai date.
      pct: peak > 0 ? Math.max(1, Math.round((r.value / peak) * 100)) : 0,
    })),
  };
}

/**
 * Momentul unui interval orar, ca număr — din text, fără `new Date(string)`.
 *
 * `new Date("2026-08-21 13:00:00")` e interpretat ca oră LOCALĂ de Node și ca
 * `Invalid Date` de alte motoare. Bucket-urile vin din bază în UTC, iar o
 * conversie greșită ar muta tot graficul cu câteva ore — o formă de minciună pe
 * care n-ar semnala-o nimic, fiindcă barele ar arăta perfect normale.
 */
export function hourEpoch(bucket: string): number | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):/.exec(bucket);
  if (!m) return null;
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]));
}

const HOUR_MS = 3_600_000;

/** Eticheta unei ore pe axă: `21.08 13`. */
export function hourLabel(epoch: number): string {
  const d = new Date(epoch);
  const zi = String(d.getUTCDate()).padStart(2, "0");
  const luna = String(d.getUTCMonth() + 1).padStart(2, "0");
  const ora = String(d.getUTCHours()).padStart(2, "0");
  return `${zi}.${luna} ${ora}`;
}

/**
 * Seria continuă de ore, cu GOLURILE păstrate.
 *
 * Asta e jumătatea care contează. Datele vin doar pentru orele care au rânduri;
 * desenate una lângă alta, o pană de șase ore se închide fără urmă și graficul
 * arată ca o gazdă liniștită. Aici fiecare oră lipsă devine un punct cu
 * `value === null`, iar `barGeometry` îl desenează ca „nu s-a măsurat".
 *
 * Se ancorează în CEA MAI RECENTĂ oră primită, nu în `now()`: ceasul
 * agregatorului și cel al serverului monitorizat sunt două ceasuri, iar un
 * decalaj între ele ar produce o coadă de goluri care nu există.
 */
export function hourSeries(
  entries: { bucket: string; value: number; title: string }[],
  span: number,
): Point[] {
  const byEpoch = new Map<number, { value: number; title: string }>();
  for (const e of entries) {
    const epoch = hourEpoch(e.bucket);
    if (epoch !== null) byEpoch.set(epoch, { value: e.value, title: e.title });
  }
  if (byEpoch.size === 0) return [];

  const newest = Math.max(...byEpoch.keys());
  const oldest = Math.min(...byEpoch.keys());
  // Cât acoperă datele, dar nu mai mult decât `span`: o gazdă instalată ieri
  // n-are voie să arate un grafic pe jumătate gol, fiindcă golul ăla ar spune
  // „n-am măsurat" despre ore în care agregatorul nici nu exista.
  const start = Math.max(oldest, newest - (span - 1) * HOUR_MS);

  const points: Point[] = [];
  for (let t = start; t <= newest; t += HOUR_MS) {
    const hit = byEpoch.get(t);
    points.push(hit === undefined
      ? { bucket: String(t), value: null, title: `${hourLabel(t)} — nu s-a măsurat` }
      : { bucket: String(t), value: hit.value, title: hit.title });
  }
  return points;
}

// ---------------------------------------------------------------------------
// Graficul STIVUIT: aceleasi ore, despartite pe sursa
// ---------------------------------------------------------------------------
/** O ora din seria stivuita. `bySource` gol inseamna «nu s-a masurat». */
export type StackHour = { epoch: number; bySource: Record<string, number> };

export type Segment = {
  y: number; h: number;
  /** Indicele sursei in `sources` — devine clasa de culoare la randare. */
  slot: number;
  source: string;
  value: number;
};

export type Column = {
  x: number; w: number;
  epoch: number;
  total: number;
  /** `true` pentru o ora fara nicio masuratoare. */
  missing: boolean;
  segments: Segment[];
};

export type StackGeometry = {
  width: number; height: number; baseline: number; peak: number;
  columns: Column[];
  ticks: Tick[];
  grid: { y: number; label: string }[];
  /** Sursele desenate, in ordinea legendei. Ultima poate fi `ALTELE`. */
  sources: string[];
  empty: boolean;
};

/**
 * Cate surse capata culoare proprie.
 *
 * Peste atat, ochiul nu mai deosebeste nuantele, iar o legenda de doisprezece
 * randuri nu se citeste. Restul se aduna intr-o singura banda, NUMITA — o coada
 * taiata tacut ar face inaltimea stivei sa nu mai fie totalul orei.
 */
export const STACK_SOURCES = 5;

/** Numele benzii in care se aduna sursele din afara primelor `STACK_SOURCES`. */
export const ALTELE = "altele";

/**
 * Umple orele lipsa si asaza sursele intr-o ordine stabila.
 *
 * Ordinea vine din TOTALUL pe toata fereastra, nu din prima ora: sortata pe ora,
 * culoarea unei surse ar sari de la o coloana la alta, iar un grafic in care
 * verdele inseamna altceva la fiecare bara nu se poate citi.
 */
export function stackSeries(hours: StackHour[], span: number): {
  columns: StackHour[]; sources: string[];
} {
  if (hours.length === 0) return { columns: [], sources: [] };

  const byEpoch = new Map<number, Record<string, number>>();
  for (const h of hours) byEpoch.set(h.epoch, h.bySource);

  const newest = Math.max(...byEpoch.keys());
  const oldest = Math.min(...byEpoch.keys());
  // Ca la `hourSeries`: se ancoreaza in cea mai recenta ora PRIMITA, nu in
  // `now()`. Ceasul agregatorului si cel al serverului sunt doua ceasuri, iar un
  // decalaj ar produce o coada de goluri care nu exista.
  const start = Math.max(oldest, newest - (span - 1) * HOUR_MS);

  const totals = new Map<string, number>();
  const columns: StackHour[] = [];
  for (let t = start; t <= newest; t += HOUR_MS) {
    const hit = byEpoch.get(t);
    columns.push({ epoch: t, bySource: hit ?? {} });
    for (const [source, n] of Object.entries(hit ?? {})) {
      totals.set(source, (totals.get(source) ?? 0) + n);
    }
  }

  const ordered = [...totals.entries()]
    .sort((a, b) => (b[1] - a[1]) || (a[0] < b[0] ? -1 : 1))
    .map(([source]) => source);
  const named = ordered.slice(0, STACK_SOURCES);
  const rest = ordered.slice(STACK_SOURCES);
  if (rest.length === 0) return { columns, sources: named };

  // Coada se ADUNA, nu se arunca: altfel inaltimea stivei ar fi mai mica decat
  // totalul orei, iar cine compara graficul cu cartonasul ar gasi o diferenta
  // pe care nimic n-o explica.
  const restSet = new Set(rest);
  const merged = columns.map((c) => {
    const out: Record<string, number> = {};
    let altele = 0;
    for (const [source, n] of Object.entries(c.bySource)) {
      if (restSet.has(source)) altele += n; else out[source] = n;
    }
    if (altele > 0) out[ALTELE] = altele;
    return { epoch: c.epoch, bySource: out };
  });
  return { columns: merged, sources: [...named, ALTELE] };
}

/**
 * Geometria graficului stivuit. Functie PURA: numere in, numere afara.
 *
 * Axa porneste de la zero, ca la `barGeometry`, si din acelasi motiv: o axa
 * taiata face dintr-o crestere de 3% un munte.
 */
export function stackGeometry(hours: StackHour[], sources: string[]): StackGeometry {
  const inner = { w: CHART_W - PAD_L - PAD_R, h: CHART_H - PAD_T - PAD_B };
  const baseline = PAD_T + inner.h;

  const totalOf = (h: StackHour) =>
    Object.values(h.bySource).reduce((a, n) => a + n, 0);
  const measured = hours.filter((h) => Object.keys(h.bySource).length > 0);
  const empty = measured.length === 0;
  // Niciodata sub 1: o serie numai de zerouri impartita la zero ar da inaltimi
  // `NaN`, iar `NaN` intr-un atribut SVG e o bara care nu se deseneaza — date
  // care dispar in tacere.
  const peak = niceCeiling(empty ? 1 : Math.max(...measured.map(totalOf)));

  const slot = hours.length > 0 ? inner.w / hours.length : inner.w;
  const gap = Math.min(2, slot * 0.18);
  const barW = Math.max(1, slot - gap);

  const columns: Column[] = hours.map((h, i) => {
    const x = PAD_L + i * slot + gap / 2;
    const total = totalOf(h);
    if (Object.keys(h.bySource).length === 0) {
      return { x, w: barW, epoch: h.epoch, total: 0, missing: true, segments: [] };
    }
    let top = baseline;
    const segments: Segment[] = [];
    // Se stivuieste in ORDINEA LEGENDEI, de jos in sus. Ordonate dupa valoare pe
    // fiecare coloana, benzile ar schimba locul de la o ora la alta, iar ochiul
    // ar citi miscarea aia ca pe o schimbare in date.
    for (const [slotIndex, source] of sources.entries()) {
      const value = h.bySource[source];
      if (value === undefined || value <= 0) continue;
      const seg = (value / peak) * inner.h;
      top -= seg;
      segments.push({ y: top, h: seg, slot: slotIndex, source, value });
    }
    return { x, w: barW, epoch: h.epoch, total, missing: false, segments };
  });

  const every = Math.max(1, Math.ceil(hours.length / MAX_TICKS));
  const ticks: Tick[] = hours
    .map((h, i) => ({ i, h }))
    .filter(({ i }) => i % every === 0)
    .map(({ i, h }) => ({ x: PAD_L + i * slot + barW / 2, label: hourLabel(h.epoch) }));

  const grid = [0, 0.5, 1].map((frac) => ({
    y: baseline - frac * inner.h,
    label: shortNumber(peak * frac),
  }));

  return {
    width: CHART_W, height: CHART_H, baseline, peak,
    columns, ticks, grid, sources, empty,
  };
}

// ---------------------------------------------------------------------------
// Banda de proportii: incidentele deschise, pe severitate
// ---------------------------------------------------------------------------
export type Slice = { x: number; w: number; key: string; value: number; share: number };

/** Latimea minima a unei felii, in unitatile benzii. */
export const MIN_SLICE = 2;

/**
 * O banda intreaga impartita pe categorii.
 *
 * Proportii, nu valori absolute: intrebarea e «cat din ce e deschis e grav», iar
 * aia se citeste dintr-o banda, nu din patru numere alaturate.
 *
 * Fiecare felie primeste cel putin `MIN_SLICE` daca are macar o unitate. Un
 * `critical` singur, intr-o mie, ar avea o latime subpixel si AR DISPAREA —
 * exact felia care nu are voie sa dispara.
 */
export function shareBar(entries: { key: string; value: number }[],
                         width: number): Slice[] {
  const total = entries.reduce((a, e) => a + e.value, 0);
  if (total <= 0) return [];
  const raw = entries.map((e) => e.value <= 0
    ? 0
    : Math.max(MIN_SLICE, (e.value / total) * width));

  // Latimile ridicate la minim nu mai incap: se scade din cea mai lata, singura
  // care isi poate permite, ca suma sa ramana exact `width`.
  const over = raw.reduce((a, w) => a + w, 0) - width;
  if (over > 0) {
    let biggest = 0;
    for (let i = 1; i < raw.length; i += 1) if (raw[i] > raw[biggest]) biggest = i;
    raw[biggest] = Math.max(MIN_SLICE, raw[biggest] - over);
  }

  let x = 0;
  const out: Slice[] = [];
  for (const [i, e] of entries.entries()) {
    if (raw[i] <= 0) continue;
    out.push({ x, w: raw[i], key: e.key, value: e.value, share: e.value / total });
    x += raw[i];
  }
  return out;
}
