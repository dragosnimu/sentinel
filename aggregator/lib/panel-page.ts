/**
 * Panoul, ca HTML. Piesa pe care `lib/auth/render.ts` o numește „piesa 3".
 *
 * Portează paginile de CITIRE ale panoului de pe serverul monitorizat
 * (`sentinel/web/routers/`), fără niciuna dintre comenzi. Cele cinci `POST`-uri
 * de acolo — schimbarea stării unui incident, închiderea în masă, deblocarea,
 * dry-run-ul și respingerea unui plan de patch — nu au corespondent aici și nu
 * vor avea: agregatorul e o replică, iar canalul de comandă rămâne Telegram.
 * `/account` lipsește din același motiv, e o pagină de comenzi.
 *
 * ## De ce tot un șir, și nu React
 *
 * Politica de conținut (`lib/auth/http.ts`) n-are `unsafe-inline`, iar o pagină
 * Next randată pe server emite șase elemente `<script>` INLINE chiar și când nu
 * există nicio componentă de client — măsurat pe 18 august 2026, pe pagina
 * martorului. Deci React ar cere un nonce, iar `witness-page.ts` scrie de ce
 * nonce-ul pe un CDN se termină cu `unsafe-inline` adăugat sub presiune.
 *
 * ## Un singur server pe ecran
 *
 * Selecția vine din `?instanta=<id>` și e purtată prin fiecare legătură. Nu e o
 * autorizație: stratul de date o aplică drept FILTRU peste domeniul citit din
 * `user_instances`, deci un identificator inventat în URL nu lărgește nimic.
 * Vezi nota lungă din `lib/data/detections.ts`.
 *
 * Din URL, nu dintr-un cookie și nu din sesiune, pentru două motive: pagina
 * devine partajabilă și pusă la favorite cu tot cu serverul la care se referă,
 * iar starea ascunsă care decide CE date vezi e chiar felul în care doi oameni
 * se uită la același ecran și văd altceva.
 *
 * ## Escaparea
 *
 * TOT ce vine din bază trece prin `escapeHtml`. Titlurile incidentelor,
 * `rule_id`-urile și motivele de suprimare sunt text produs din trafic — adică
 * valori alese de un atacator.
 */

import { CSP_META_TAG } from "./csp";
import type { HourRow } from "./data/rollups";
import {
  ALTELE, STACK_SOURCES, barGeometry, hourLabel, hourSeries, rankGeometry,
  shareBar, shortNumber, stackGeometry, stackSeries,
} from "./chart";
import type {
  BarGeometry, RankGeometry, StackGeometry, StackHour,
} from "./chart";
import type { Ranked, Summary, Trend } from "./data/overview";
import { MAX_ROWS_READ, SERIES_HOURS, WINDOW_HOURS } from "./data/overview";
import type { ScanHealth } from "./data/scans";
import { escapeHtml } from "./auth/render";
import type { Arrival } from "./data/arrivals";
import type { BlockSummary } from "./data/blocklist";
import type { DetectionSummary } from "./data/detections";
import type { FindingSummary } from "./data/findings";
import {
  COLORS, COLOR_STATE_RO, KEV_UNKNOWN_NOTE_RO, countsRo, legendStates, pillTitle,
} from "./finding-risk";
import { GROUPS } from "./finding-groups";
import type { RiskColor } from "./finding-risk";
import type { PlanSummary } from "./data/patch-plans";
import type { CheckState } from "./data/selfcheck";
import type { LoginSession, SessionDetail } from "./data/logins";
import { COMMANDS_SHOWN, SESSIONS_SHOWN } from "./data/logins";
import type { IncidentDetail, IncidentSummary, Timeline } from "./data/incidents";
import type { VisibleInstance } from "./data/instances";

/** O pagină din meniu: adresa ei, numele ei, și fluxul de care depinde. */
export type Nav = {
  href: string;
  label: string;
  /**
   * Fluxul fără de care pagina n-are ce arăta, sau `null` pentru cele care se
   * construiesc din mai multe. Numele sunt cele de pe sârmă
   * (`sentinel/report/shipper.py`), nu numele tabelelor de aici.
   */
  stream: string | null;
};

export const PAGES: readonly Nav[] = Object.freeze([
  { href: "/panel", label: "Rezumat", stream: null },
  { href: "/panel/incidente", label: "Incidente", stream: "incidents" },
  { href: "/panel/detectii", label: "Detecții", stream: "detections" },
  { href: "/panel/vulnerabilitati", label: "Vulnerabilități", stream: "findings" },
  { href: "/panel/blocari", label: "Blocări", stream: "blocklist" },
  { href: "/panel/patch-uri", label: "Patch-uri", stream: "patch_plans" },
  { href: "/panel/rapoarte", label: "Rapoarte", stream: "event_rollup_1h" },
  { href: "/panel/sesiuni", label: "Sesiuni", stream: "login_sessions" },
  { href: "/panel/servicii", label: "Servicii", stream: "selfcheck_state" },
]);

export type Chrome = {
  username: string;
  csrfToken: string;
  instances: VisibleInstance[];
  /** Instanța aleasă. `null` când contul nu vede niciuna. */
  selected: string | null;
  /** `href`-ul paginii curente, ca meniul să știe pe care s-o marcheze. */
  active: string;
  arrivals: Map<string, Arrival>;
};

function shell(title: string, body: string): string {
  return [
    "<!doctype html>\n",
    '<html lang="ro">\n<head>\n',
    // PRIMUL in <head>: guverneaza tot ce urmeaza dupa el.
    CSP_META_TAG,
    '<meta charset="utf-8">\n',
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
    `<title>${escapeHtml(title)}</title>\n`,
    '<link rel="stylesheet" href="/panel.css">\n',
    "</head>\n<body>\n", body, "</body>\n</html>\n",
  ].join("");
}

/** Adresa unei pagini, cu serverul ales purtat mai departe. */
export function withInstance(href: string, instance: string | null): string {
  if (instance === null) return href;
  return `${href}?instanta=${encodeURIComponent(instance)}`;
}

/**
 * Antetul: cine ești, ce server privești, meniul, și ieșirea.
 *
 * Selectorul e un formular `GET`, nu JavaScript: politica interzice scripturile,
 * iar un `<select>` într-un formular care se trimite cu un buton funcționează
 * fără niciunul. Butonul e obligatoriu tocmai de-aia — fără JS, schimbarea
 * opțiunii nu trimite nimic singură, iar un selector care pare să facă ceva și
 * nu face e mai rău decât unul cu buton.
 */
function chrome(view: Chrome): string {
  const parts: string[] = ['<header class="bara">\n'];
  parts.push(`<a class="marca" href="${withInstance("/panel", view.selected)}">` +
             "Sentinel</a>\n");

  if (view.instances.length > 0) {
    parts.push('<form class="alege" method="get" action="', escapeHtml(view.active), '">\n');
    parts.push('<label for="instanta">Server</label>\n');
    parts.push('<select id="instanta" name="instanta">\n');
    for (const inst of view.instances) {
      const chosen = inst.instanceId === view.selected ? " selected" : "";
      const name = inst.label ?? inst.instanceId;
      parts.push(`<option value="${escapeHtml(inst.instanceId)}"${chosen}>` +
                 `${escapeHtml(name)}</option>\n`);
    }
    parts.push("</select>\n<button type=\"submit\">Arată</button>\n</form>\n");
  }

  parts.push(`<span class="cine">${escapeHtml(view.username)}</span>\n`);
  parts.push('<form method="post" action="/logout">\n');
  parts.push(`<input type="hidden" name="csrf_token" value="${escapeHtml(view.csrfToken)}">\n`);
  parts.push('<button type="submit">Ieși</button>\n</form>\n</header>\n');

  parts.push('<nav class="meniu">\n');
  for (const page of PAGES) {
    const here = page.href === view.active ? ' class="aici" aria-current="page"' : "";
    parts.push(`<a href="${withInstance(page.href, view.selected)}"${here}>` +
               `${escapeHtml(page.label)}</a>\n`);
  }
  parts.push("</nav>\n");
  return parts.join("");
}

/** Momentul, scurtat la minut. Valoarea din bază e UTC; antetul o spune o dată. */
function moment(value: string | null): string {
  if (!value) return "—";
  return value.replace("T", " ").slice(0, 16);
}

function severityClass(severity: string): string {
  const known = ["critical", "high", "medium", "low", "info"];
  return known.includes(severity) ? `sev-${severity}` : "sev-alta";
}

function severityCell(severity: string): string {
  return `<td><span class="sev ${severityClass(severity)}">` +
         `${escapeHtml(severity)}</span></td>`;
}

/**
 * Eticheta „AI content": același element, aceeași formă, peste tot unde ce se vede a fost scris
 * sau judecat de model — verdictul unui incident, un plan de patch. Un singur loc care o scrie,
 * ca două pagini să nu ajungă s-o scrie diferit: o etichetă care arată altfel de la un loc la
 * altul nu mai spune „aici e modelul".
 *
 * Textul e al operatorului, în engleză, și IDENTIC cu cel de pe panoul serverului
 * (`sentinel/web/templates/_ai.html`); `tests/unit/test_ai_content_badge.py` compară cele două
 * la octet. Se pune DOAR lângă conținut produs de model: un câmp măsurat nu o primește, iar
 * „modelul n-a judecat" nu se scrie cu ea.
 */
export function aiBadge(): string {
  return '<span class="ai-badge" title="Text sau scor produs de modelul AI — nu e o măsurătoare.">' +
         "AI content</span>";
}

/** Încrederea din bază (`"0.85"`) ca procent întreg; ce nu se poate citi e „—", nu 0%. */
function confidencePct(value: string | null): string {
  if (value === null) return "—";
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 && n <= 1 ? `${Math.round(n * 100)}%` : "—";
}

/**
 * Celula „Analiză AI" a unui incident: eticheta, ce a judecat modelul și când — sau „—".
 *
 * „Judecat" = `aiAnalyzedAt` setat (vezi `IncidentSummary`). Un incident pe care modelul nu l-a
 * văzut rămâne cu „—": fără etichetă și fără niciun cuvânt care să sugereze că a fost evaluat.
 */
function aiCell(inc: IncidentSummary): string {
  if (inc.aiAnalyzedAt === null) return '<td class="gol-ai">—</td>';
  return `<td class="ai-cell">${aiBadge()}<br>` +
         `${escapeHtml(inc.aiSeverity ?? "—")} &middot; ${escapeHtml(confidencePct(inc.aiConfidence))}` +
         `<br><span class="id">${escapeHtml(moment(inc.aiAnalyzedAt))} UTC</span></td>`;
}

/**
 * Ce se scrie în locul unei pagini care n-are date — și de ce sunt DOUĂ mesaje.
 *
 * „Nimic de arătat" e o informație despre server: nu s-a întâmplat nimic.
 * „Fluxul n-a sosit niciodată" e una despre conductă, iar reparația e cu totul
 * alta. Confundate, cine se uită la o pagină goală de blocări crede că nu e
 * nimeni blocat, când de fapt nimeni nu i-a trimis lista.
 *
 * Verdictul se citește din `sync_cursors` — un fapt observabil despre ce a
 * sosit —, nu dintr-o listă scrisă de mână care ar rămâne în urmă. Vezi
 * `lib/data/arrivals.ts`.
 */
export function absent(stream: string | null, arrivals: Map<string, Arrival>): string {
  if (stream === null) return "";
  const seen = arrivals.get(stream);
  if (seen === undefined) {
    return '<p class="lipsa"><strong>Fluxul <code>' + escapeHtml(stream) +
           "</code> nu a fost expediat niciodată de serverul ăsta.</strong><br>" +
           "Pagina nu e goală fiindcă nu s-a întâmplat nimic — e goală fiindcă " +
           "datele nu pleacă încă de pe gazdă. Se pornește declarând fluxul la " +
           "ambele capete și livrând serverul.</p>\n";
  }
  if (seen.rowsIngested === 0) {
    return '<p class="gol">Fluxul curge (primul lot: ' +
           escapeHtml(moment(seen.firstSeenAt)) +
           " UTC), dar n-a adus niciun rând.</p>\n";
  }
  return "";
}

function table(head: string, rows: string[], gol: string, cls = ""): string {
  if (rows.length === 0) return `<p class="gol">${escapeHtml(gol)}</p>\n`;
  return `<table${cls === "" ? "" : ` class="${cls}"`}>\n<thead><tr>${head}</tr></thead>\n<tbody>\n` +
         rows.join("") + "</tbody>\n</table>\n";
}

/**
 * `mainClass`: o pagină al cărei conținut nu încape în lățimea de proză a lui `main`
 * (`72rem`) își cere o clasă, iar foaia o scoate din ea (`main.wide`). Fără clasă marcajul e
 * exact cel de dinainte: lățimea nu se schimbă pe pagini care n-au cerut-o.
 */
function page(view: Chrome, title: string, body: string, mainClass = ""): string {
  const open = mainClass === "" ? "<main>" : `<main class="${mainClass}">`;
  return shell(`${title} — Sentinel`, chrome(view) + open + "\n" + body + "</main>\n");
}

// ---------------------------------------------------------------------------
// Rezumat
// ---------------------------------------------------------------------------
export type SummaryView = Chrome & {
  incidents: IncidentSummary[];
  /** Tot ce desenează rezumatul, dintr-o singură trecere. */
  sumar: Summary;
};

/** Cate ore intra in graficul de evenimente. Doua zile: destul cat sa se vada
 *  un tipar zilnic, putin cat sa ramana citibil pe un telefon. */
const ORE_IN_GRAFIC = SERIES_HOURS;

/** Latimea benzii de proportii, in unitatile ei de desen. */
const BANDA = 720;

// ---------------------------------------------------------------------------
// Grafice
//
// SVG generat aici, cu geometria din `lib/chart.ts`. Niciun `<script>`, niciun
// `style=` — vezi capul lui `chart.ts` pentru de ce nu se poate altfel sub
// CSP-ul paginii, si ce s-ar intampla daca cineva incearca.
// ---------------------------------------------------------------------------

/** Un grafic cu bare, gata de pus in pagina. */
function barsSvg(geo: BarGeometry, aria: string): string {
  const parts: string[] = [];
  parts.push(`<svg class="grafic" viewBox="0 0 ${geo.width} ${geo.height}" ` +
             `width="100%" height="${geo.height}" role="img" ` +
             `aria-label="${escapeHtml(aria)}" preserveAspectRatio="none">\n`);

  for (const g of geo.grid) {
    parts.push(`<line class="g-grila" x1="44" y1="${g.y}" x2="${geo.width - 6}" ` +
               `y2="${g.y}"></line>\n`);
    parts.push(`<text class="g-axa" x="40" y="${g.y + 4}" text-anchor="end">` +
               `${escapeHtml(g.label)}</text>\n`);
  }

  for (const b of geo.bars) {
    const cls = b.missing ? "g-lipsa" : "g-bara";
    parts.push(`<rect class="${cls}" x="${b.x.toFixed(2)}" y="${b.y.toFixed(2)}" ` +
               `width="${b.w.toFixed(2)}" height="${Math.max(0, b.h).toFixed(2)}">` +
               `<title>${escapeHtml(b.title)}</title></rect>\n`);
  }

  for (const t of geo.ticks) {
    parts.push(`<text class="g-axa" x="${t.x.toFixed(2)}" y="${geo.height - 8}" ` +
               `text-anchor="middle">${escapeHtml(t.label)}</text>\n`);
  }

  parts.push("</svg>\n");
  return parts.join("");
}

/** Clasamentul, ca bare orizontale. Latimea e atribut, nu stil. */
function rankSvg(geo: RankGeometry): string {
  const RAND = 22;
  const LATIME = 720;
  const ETICHETA = 150;
  const inaltime = Math.max(RAND, geo.rows.length * RAND);
  const parts: string[] = [];
  parts.push(`<svg class="grafic" viewBox="0 0 ${LATIME} ${inaltime}" width="100%" ` +
             `height="${inaltime}" role="img" aria-label="Cele mai active surse" ` +
             `preserveAspectRatio="none">\n`);
  geo.rows.forEach((r, i) => {
    const y = i * RAND;
    const w = ((LATIME - ETICHETA - 60) * r.pct) / 100;
    parts.push(`<text class="g-axa" x="${ETICHETA - 8}" y="${y + 15}" ` +
               `text-anchor="end">${escapeHtml(r.label)}</text>\n`);
    parts.push(`<rect class="g-bara" x="${ETICHETA}" y="${y + 4}" ` +
               `width="${w.toFixed(2)}" height="14">` +
               `<title>${escapeHtml(r.title)}</title></rect>\n`);
    parts.push(`<text class="g-val" x="${ETICHETA + w + 6}" y="${y + 15}">` +
               `${escapeHtml(r.value)}</text>\n`);
  });
  parts.push("</svg>\n");
  return parts.join("");
}

// ---------------------------------------------------------------------------
// Cartonasele de sus
// ---------------------------------------------------------------------------
/**
 * Tendinta, ca text scurt si ca stare.
 *
 * Trei reguli, fiecare pentru o minciuna pe care o spune un procent naiv:
 *
 *   * de la ZERO nu exista procent. `(5-0)/0` e `Infinity`, iar «+∞%» pe un
 *     panou de securitate arata ca o eroare de cod, nu ca o informatie;
 *   * pe numere mici, procentul e zgomot: 1 → 3 e «+200%» si nu inseamna nimic.
 *     Sub `PRAG_TENDINTA` se scrie diferenta bruta;
 *   * o crestere nu e automat rea si o scadere nu e automat buna, dar pe un
 *     panou de atacuri asa se citesc. Deci semnul da CULOAREA, nu verdictul.
 */
const PRAG_TENDINTA = 10;

function trend(t: Trend): { text: string; cls: string } {
  const delta = t.now - t.before;
  if (delta === 0) return { text: "la fel ca ieri", cls: "t-egal" };
  const semn = delta > 0 ? "+" : "−";
  const cls = delta > 0 ? "t-sus" : "t-jos";
  if (t.before < PRAG_TENDINTA) {
    return { text: `${semn}${Math.abs(delta)} fata de ieri`, cls };
  }
  const pct = Math.round((Math.abs(delta) / t.before) * 100);
  return { text: `${semn}${pct}% fata de ieri`, cls };
}

function card(eticheta: string, valoare: string, sub: string, cls = ""): string {
  return `<div class="card${cls === "" ? "" : ` ${cls}`}">` +
    `<div class="card-eticheta">${escapeHtml(eticheta)}</div>` +
    `<div class="card-nr">${escapeHtml(valoare)}</div>` +
    `<div class="card-sub">${escapeHtml(sub)}</div></div>\n`;
}

/**
 * Sub-linia cardului de vulnerabilități: câte sunt Acum, Curând și Nedecis — numele
 * stărilor, aceleași ca pe pastile și pe rânduri (`countsRo`), nu numele culorilor.
 *
 * Nedecis apare mereu, ca și pe pagina serverului: „Nedecis 0" e un fapt, iar un
 * card care ar tăcea despre el ar arăta curat tocmai când nu se știe. Verdele nu
 * se enumeră: e restul, adică „ciclul obișnuit de actualizare".
 */
function findingsCardSub(o: Summary["overview"]): string {
  const c = o.findingsByColor;
  return countsRo(c.red, c.amber, c.grey);
}

function cards(s: Summary): string {
  const o = s.overview;
  const att = trend(o.attackers);
  const det = trend(o.detections);
  const ev = trend(o.events);
  return '<div class="carduri">\n' +
    `<div class="card"><div class="card-eticheta">Adrese distincte</div>` +
    `<div class="card-nr">${o.attackers.now}</div>` +
    `<div class="card-sub ${att.cls}">${escapeHtml(att.text)}</div></div>\n` +
    `<div class="card"><div class="card-eticheta">Detectii</div>` +
    `<div class="card-nr">${o.detections.now}</div>` +
    `<div class="card-sub ${det.cls}">${escapeHtml(det.text)}</div></div>\n` +
    `<div class="card"><div class="card-eticheta">Evenimente</div>` +
    `<div class="card-nr">${escapeHtml(shortNumber(o.events.now))}</div>` +
    `<div class="card-sub ${ev.cls}">${escapeHtml(ev.text)}</div></div>\n` +
    card("Incidente deschise", String(o.incidentsOpen),
         `${o.incidentsSevere} grave`,
         o.incidentsSevere > 0 ? "card-alarma" : "") +
    card("Vulnerabilitati", String(o.findingsOpen), findingsCardSub(o),
         o.findingsByColor.red > 0 ? "card-alarma" : "") +
    card("Blocari active", String(o.blocksActive), "in vigoare acum") +
    "</div>\n" +
    `<p class="nota">Ferestrele: ${WINDOW_HOURS} de ore, comparate cu cele ` +
    `${WINDOW_HOURS} dinaintea lor. Incidentele, vulnerabilitatile si blocarile ` +
    "sunt stari de ACUM, nu numarate pe fereastra — o vulnerabilitate deschisa " +
    "de trei saptamani e tot deschisa azi.</p>\n";
}

// ---------------------------------------------------------------------------
// Graficul stivuit
// ---------------------------------------------------------------------------
/** Graficul cu bare stivuite pe sursa, plus legenda lui. */
function stackSvg(geo: StackGeometry): string {
  const parts: string[] = [];
  parts.push(`<svg class="grafic" viewBox="0 0 ${geo.width} ${geo.height}" ` +
             `width="100%" height="${geo.height}" role="img" ` +
             `aria-label="Evenimente pe ora, despartite pe sursa" ` +
             `preserveAspectRatio="none">\n`);

  for (const g of geo.grid) {
    parts.push(`<line class="g-grila" x1="44" y1="${g.y}" x2="${geo.width - 6}" ` +
               `y2="${g.y}"></line>\n`);
    parts.push(`<text class="g-axa" x="40" y="${g.y + 4}" text-anchor="end">` +
               `${escapeHtml(g.label)}</text>\n`);
  }

  for (const c of geo.columns) {
    if (c.missing) {
      // Toata inaltimea, cu alta clasa: o ora nemasurata NU e o ora cu zero
      // evenimente, iar desenata ca bara de zero ar spune exact asta.
      parts.push(`<rect class="g-lipsa" x="${c.x.toFixed(2)}" y="10" ` +
                 `width="${c.w.toFixed(2)}" height="${(geo.baseline - 10).toFixed(2)}">` +
                 `<title>${escapeHtml(`${hourLabel(c.epoch)} — nu s-a masurat`)}` +
                 "</title></rect>\n");
      continue;
    }
    for (const s of c.segments) {
      const titlu = `${hourLabel(c.epoch)} — ${s.source}: ${s.value} din ${c.total}`;
      parts.push(`<rect class="g-s${s.slot}" x="${c.x.toFixed(2)}" ` +
                 `y="${s.y.toFixed(2)}" width="${c.w.toFixed(2)}" ` +
                 `height="${Math.max(0.5, s.h).toFixed(2)}">` +
                 `<title>${escapeHtml(titlu)}</title></rect>\n`);
    }
  }

  for (const tick of geo.ticks) {
    parts.push(`<text class="g-axa" x="${tick.x.toFixed(2)}" y="${geo.height - 8}" ` +
               `text-anchor="middle">${escapeHtml(tick.label)}</text>\n`);
  }

  parts.push("</svg>\n");
  return parts.join("");
}

function legenda(sources: string[]): string {
  if (sources.length === 0) return "";
  const items = sources.map((s, i) =>
    `<span class="leg"><span class="leg-pata g-s${i}"></span>` +
    `${escapeHtml(s)}</span>`);
  items.push('<span class="leg"><span class="leg-pata g-lipsa"></span>' +
             "ora nemasurata</span>");
  return `<p class="legenda">${items.join("")}</p>\n`;
}

// ---------------------------------------------------------------------------
// Banda de severitati
// ---------------------------------------------------------------------------
function severitySvg(s: Summary): string {
  const felii = shareBar(
    s.overview.bySeverity.map((x) => ({ key: x.severity, value: x.count })), BANDA);
  if (felii.length === 0) {
    return '<p class="gol">Niciun incident deschis.</p>\n';
  }
  const parts: string[] = [];
  parts.push(`<svg class="banda" viewBox="0 0 ${BANDA} 26" width="100%" height="26" ` +
             'role="img" aria-label="Incidentele deschise, pe severitate" ' +
             'preserveAspectRatio="none">\n');
  for (const f of felii) {
    const pct = Math.round(f.share * 100);
    parts.push(`<rect class="banda-${severityClass(f.key)}" x="${f.x.toFixed(2)}" ` +
               `y="0" width="${f.w.toFixed(2)}" height="26">` +
               `<title>${escapeHtml(`${f.key}: ${f.value} (${pct}%)`)}</title>` +
               "</rect>\n");
  }
  parts.push("</svg>\n");
  parts.push('<p class="legenda">' + s.overview.bySeverity.map((x) =>
    `<span class="leg"><span class="leg-pata banda-${severityClass(x.severity)}">` +
    `</span>${escapeHtml(x.severity)} &middot; ${x.count}</span>`).join("") +
    "</p>\n");
  return parts.join("");
}

// ---------------------------------------------------------------------------
// Clasamente si cronologie
// ---------------------------------------------------------------------------
function clasament(titlu: string, randuri: Ranked[], gol: string,
                   unitate: string): string {
  if (randuri.length === 0) {
    return `<h2>${escapeHtml(titlu)}</h2>\n<p class="gol">${escapeHtml(gol)}</p>\n`;
  }
  const geo = rankGeometry(randuri.map((r) => ({
    label: r.key, value: r.count,
    title: `${r.key}: ${r.count} ${unitate}, ${r.extra}`,
  })));
  return `<h2>${escapeHtml(titlu)}</h2>\n` + rankSvg(geo);
}

function cronologie(s: Summary): string {
  if (s.activity.length === 0) {
    return '<p class="gol">Nimic in ultimele ore.</p>\n';
  }
  const randuri = s.activity.map((a) => {
    const cand = moment(new Date(a.at).toISOString());
    const semn = a.kind === "block" ? "blocare" : "detectie";
    const stare = a.kind === "block"
      ? `<span class="sev sev-alta">${escapeHtml(a.severity || "blocat")}</span>`
      : `<span class="sev ${severityClass(a.severity)}">` +
        `${escapeHtml(a.severity)}</span>`;
    return `<tr class="cron-${semn}"><td>${escapeHtml(cand)}</td>` +
      `<td>${stare}</td>` +
      `<td><code>${escapeHtml(a.title)}</code></td>` +
      `<td>${escapeHtml(a.detail)}</td></tr>\n`;
  });
  return table("<th>Cand (UTC)</th><th>Severitate</th><th>Ce</th><th>Cine</th>",
               randuri, "nimic recent");
}

/** Sectiunea de grafice a rezumatului. */
function charts(view: SummaryView): string {
  const s = view.sumar;
  const parts: string[] = [];

  parts.push(cards(s));

  if (s.truncated.length > 0) {
    // Un plafon TACUT arata exact ca «atat a fost». Spus, cine se uita stie ca
    // cifrele de mai sus sunt un minim, nu un total.
    parts.push('<p class="lipsa"><strong>Citire taiata de plafon: ' +
               escapeHtml(s.truncated.join(", ")) +
               ".</strong><br>Cifrele si graficele de mai jos sunt un MINIM: " +
               `s-au citit primele ${MAX_ROWS_READ} de randuri, iar restul ` +
               "n-au fost numarate.</p>\n");
  }

  const { columns, sources } = stackSeries(
    s.series.map((h): StackHour => ({ epoch: h.bucket, bySource: h.bySource })),
    ORE_IN_GRAFIC);

  parts.push("<h1>Evenimente pe ora</h1>\n");
  if (columns.length === 0) {
    parts.push('<p class="gol">Niciun contor orar sosit inca, deci n-are ce fi ' +
               "desenat. Se umple dupa prima ora incheiata de dupa pornirea " +
               "fluxului.</p>\n");
  } else {
    parts.push(stackSvg(stackGeometry(columns, sources)));
    parts.push(legenda(sources));
    parts.push(`<p class="nota">Ultimele ${columns.length} ore incheiate, ` +
               "calculate PE SERVER si despartite pe sursa. Ora in curs nu " +
               "apare: un contor trimis la jumatatea orei lui s-ar citi ca o " +
               "cadere de trafic care nu s-a intamplat. Peste " +
               `${STACK_SOURCES} surse, restul se aduna in banda ` +
               `„${ALTELE}” &mdash; adunate, nu taiate, ca inaltimea stivei sa ` +
               "ramana totalul orei.</p>\n");
  }

  parts.push("<h1>Incidente deschise, pe severitate</h1>\n");
  parts.push(severitySvg(s));

  parts.push("<h1>Cine si cu ce</h1>\n");
  parts.push('<div class="doua">\n');
  parts.push(clasament("Cele mai active adrese", s.rankings.attackers,
                       "nicio detectie cu adresa in fereastra", "detectii"));
  parts.push(clasament("Regulile care se declanseaza", s.rankings.rules,
                       "nicio detectie in fereastra", "detectii"));
  parts.push("</div>\n");
  parts.push(clasament("Din ce vine traficul", s.rankings.sources,
                       "nicio sursa in fereastra", "evenimente"));
  parts.push('<p class="nota">Originea pe tara si pe operatorul de retea nu se ' +
             "poate arata inca: vine din fluxul <code>actors</code>, care nu se " +
             "expediaza. O adresa e mai putin decat o harta, dar e MASURATA.</p>\n");

  parts.push("<h1>Ce s-a intamplat</h1>\n");
  parts.push(cronologie(s));

  return parts.join("");
}

export function summaryPage(view: SummaryView): string {
  const parts: string[] = [];

  if (view.instances.length === 0) {
    // Starea normală a unui cont proaspăt, nu o eroare — și arată identic cu
    // „agregatorul e gol", deși reparația celor două e complet diferită.
    parts.push('<p class="lipsa"><strong>Contul nu are drept pe nicio instanță.</strong>' +
               "<br>Se dă de operator: <code>npm run user -- grant</code>.</p>\n");
    return page(view, "Rezumat", parts.join(""));
  }

  parts.push(charts(view));
  parts.push("<h1>Servere</h1>\n");
  parts.push(table(
    "<th>Server</th><th>Stare</th><th>Rol</th><th>Ultimul lot (UTC)</th>",
    view.instances.map((inst) => {
      // `aria-current` lângă clasă, nu în locul ei: clasa desenează dunga,
      // atributul o SPUNE. Un marcaj pur vizual nu ajunge la cine folosește un
      // cititor de ecran, iar regula foii de stil e că nicio culoare nu e
      // singurul semn. `"true"` și nu `"page"`: rândul nu e o legătură către
      // pagina curentă, e elementul ales din setul afișat — `page` e pentru
      // navigație, `true` e cazul generic, singurul corect pentru un `<tr>`.
      const aici = inst.instanceId === view.selected
        ? ' class="aici" aria-current="true"' : "";
      return `<tr${aici}>` +
        `<td>${escapeHtml(inst.label ?? inst.instanceId)}<br>` +
        `<code class="id">${escapeHtml(inst.instanceId)}</code></td>` +
        `<td>${inst.enabled ? "activ" : "<strong>oprit</strong>"}</td>` +
        `<td>${escapeHtml(inst.role)}</td>` +
        `<td>${escapeHtml(moment(inst.lastBatchAt))}</td></tr>\n`;
    }),
    "niciun server"));

  parts.push("<h1>Ce a sosit de la serverul ales</h1>\n");
  parts.push(table(
    "<th>Flux</th><th>Rânduri</th><th>Primul lot (UTC)</th><th>Ultimul (UTC)</th>",
    PAGES.filter((p) => p.stream !== null).map((p) => {
      const seen = view.arrivals.get(p.stream as string);
      const stare = seen === undefined
        ? '<td colspan="3" class="lipsa-cell">nu se expediază încă</td>'
        : `<td class="nr">${seen.rowsIngested}</td>` +
          `<td>${escapeHtml(moment(seen.firstSeenAt))}</td>` +
          `<td>${escapeHtml(moment(seen.updatedAt))}</td>`;
      return `<tr><td><code>${escapeHtml(p.stream as string)}</code></td>${stare}</tr>\n`;
    }),
    "niciun flux"));

  parts.push("<h1>Incidente recente</h1>\n");
  parts.push(absent("incidents", view.arrivals));
  parts.push(incidentRows(view.incidents, view.selected));

  return page(view, "Rezumat", parts.join(""));
}

// ---------------------------------------------------------------------------
// Incidente
// ---------------------------------------------------------------------------
function incidentRows(incidents: IncidentSummary[], selected: string | null): string {
  return table(
    "<th>Severitate</th><th>Incident</th><th>Stare</th><th>Detecții</th>" +
    "<th>Analiză AI</th><th>Ultima detecție (UTC)</th>",
    incidents.map((inc) =>
      "<tr>" + severityCell(inc.severity) +
      `<td><a href="${withInstance(`/panel/incidente/${inc.id}`, selected)}">` +
      `${escapeHtml(inc.title)}</a></td>` +
      `<td>${escapeHtml(inc.status)}</td>` +
      `<td class="nr">${inc.detectionCount}</td>` +
      aiCell(inc) +
      `<td>${escapeHtml(moment(inc.lastDetectionAt))}</td></tr>\n`),
    "niciun incident");
}

export type IncidentsView = Chrome & { incidents: IncidentSummary[] };

export function incidentsPage(view: IncidentsView): string {
  return page(view, "Incidente",
    "<h1>Incidente</h1>\n" + absent("incidents", view.arrivals) +
    incidentRows(view.incidents, view.selected));
}

export type IncidentView = Chrome & { incident: IncidentDetail; timeline: Timeline };

/**
 * Ce a judecat modelul despre un incident, cu eticheta „AI content" la titlu — sau NIMIC.
 *
 * Fără `aiAnalyzedAt` nu se scrie nicio secțiune: nici etichetă, nici „neevaluat", fiindcă un
 * rând care vorbește despre model într-un loc unde modelul n-a spus nimic se citește ca „a fost
 * evaluat și n-a găsit nimic". Severitatea deterministă rămâne mai sus, în lista de fapte, fără
 * etichetă: e măsurată, nu judecată.
 *
 * Un verdict stocat dar necitibil se spune: severitatea și ora sunt coloane și se arată, iar
 * lipsa textului e o frază, nu o secțiune goală.
 */
function aiBlock(inc: IncidentDetail): string {
  if (inc.aiAnalyzedAt === null) return "";
  const verdict = inc.aiVerdict;
  const facts: [string, string][] = [
    ["Evaluat la (UTC)", moment(inc.aiAnalyzedAt)],
    ["Severitate AI", inc.aiSeverity ?? "—"],
    ["Încredere", confidencePct(inc.aiConfidence)],
  ];
  if (verdict !== null && verdict !== "unreadable") {
    facts.push(["Fals-pozitiv?",
                verdict.isFalsePositive === null ? "—" : (verdict.isFalsePositive ? "DA" : "nu")]);
    // Doar una din cele cinci acțiuni canonice (`readAiVerdict`); altfel rândul LIPSEȘTE — nici „—",
    // nici „unknown": o etichetă „AI content" lângă un text stricat l-ar da drept răspunsul modelului.
    if (verdict.recommendedAction !== null) {
      facts.push(["Acțiune sugerată", verdict.recommendedAction]);
    }
  }

  const parts: string[] = [`<h2>Analiză AI ${aiBadge()}</h2>\n`, '<dl class="detaliu">\n'];
  for (const [key, value] of facts) {
    parts.push(`<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>\n`);
  }
  if (verdict !== null && verdict !== "unreadable" && verdict.promptInjectionDetected) {
    parts.push("<dt>Atenție</dt><dd>tentativă de prompt-injection detectată în dovezile " +
               "incidentului</dd>\n");
  }
  parts.push("</dl>\n");

  if (verdict === "unreadable") {
    parts.push('<p class="lipsa"><strong>Textul verdictului nu a putut fi citit.</strong><br>' +
               "Severitatea, încrederea și ora de mai sus sunt coloane și s-au citit; " +
               "blobul JSON din care vine textul nu are forma așteptată.</p>\n");
  } else if (verdict === null) {
    parts.push('<p class="gol">Gazda n-a trimis textul verdictului pentru acest incident.</p>\n');
  } else if (verdict.summaryRo !== null) {
    parts.push(`<p>${escapeHtml(verdict.summaryRo)}</p>\n`);
  }
  parts.push(`<p class="nota">Verdict deterministic: <strong>${escapeHtml(inc.severity)}</strong>. ` +
             "AI-ul comentează, nu suprascrie.</p>\n");
  return parts.join("");
}

export function incidentPage(view: IncidentView): string {
  const inc = view.incident;
  const parts: string[] = [];
  parts.push(`<p><a href="${withInstance("/panel/incidente", view.selected)}">` +
             "← înapoi la incidente</a></p>\n");
  parts.push(`<h1>${escapeHtml(inc.title)}</h1>\n`);

  parts.push('<dl class="detaliu">\n');
  const rows: [string, string][] = [
    ["Severitate", inc.severity],
    ["Stare", inc.status],
    ["Detecții", String(inc.detectionCount)],
    ["Prima detecție (UTC)", moment(inc.firstDetectionAt)],
    ["Ultima detecție (UTC)", moment(inc.lastDetectionAt)],
    ["Actor", inc.actorKey ?? "—"],
    ["Confirmat de", inc.acknowledgedBy ?? "—"],
    ["Rezolvat la (UTC)", moment(inc.resolvedAt)],
    ["Amprentă", inc.fingerprint],
    ["Server", inc.instanceId],
  ];
  for (const [key, value] of rows) {
    parts.push(`<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(value)}</dd>\n`);
  }
  parts.push("</dl>\n");

  if (inc.summary) parts.push(`<h2>Rezumat</h2>\n<p>${escapeHtml(inc.summary)}</p>\n`);
  parts.push(aiBlock(inc));
  if (inc.resolutionNote) {
    parts.push(`<h2>Notă de rezolvare</h2>\n<p>${escapeHtml(inc.resolutionNote)}</p>\n`);
  }

  parts.push("<h2>Cronologie</h2>\n");
  parts.push(absent("incident_timeline", view.arrivals));
  parts.push(table(
    "<th>Când (UTC)</th><th>Ce</th><th>Cine</th>",
    view.timeline.entries.map((e) =>
      `<tr><td>${escapeHtml(moment(e.at))}</td>` +
      `<td>${escapeHtml(e.kind)}</td>` +
      `<td>${escapeHtml(e.actor ?? "—")}</td></tr>\n`),
    "nicio intrare"));
  // Obligatoriu, nu decorativ: `lib/data/incidents.ts` scrie explicit că cine
  // afișează lista TREBUIE să spună când e tăiată. O cronologie trunchiată tăcut
  // se citește ca „asta a fost tot ce s-a întâmplat".
  if (view.timeline.truncated) {
    parts.push('<p class="taiat">Cronologia are mai multe intrări decât se ' +
               "afișează aici; restul nu a fost citit.</p>\n");
  }

  return page(view, inc.title, parts.join(""));
}

// ---------------------------------------------------------------------------
// Detecții — pagina care ține locul lui `/events`
// ---------------------------------------------------------------------------
function detectionRows(detections: DetectionSummary[]): string {
  return table(
    "<th>Severitate</th><th>Când (UTC)</th><th>Regulă</th><th>Sursă</th>" +
    "<th>Port</th><th>Stare</th>",
    detections.map((d) =>
      "<tr>" + severityCell(d.severity) +
      `<td>${escapeHtml(moment(d.ts))}</td>` +
      `<td><code>${escapeHtml(d.ruleId)}</code><br>` +
      `<span class="id">${escapeHtml(d.ruleFamily)}</span></td>` +
      `<td>${escapeHtml(d.srcIp ?? d.actorKey ?? "—")}</td>` +
      `<td class="nr">${d.dstPort === null ? "—" : d.dstPort}</td>` +
      `<td>${d.suppressed
        ? `suprimată${d.suppressReason ? ` — ${escapeHtml(d.suppressReason)}` : ""}`
        : "activă"}</td></tr>\n`),
    "nicio detecție");
}

export type DetectionsView = Chrome & { detections: DetectionSummary[] };

export function detectionsPage(view: DetectionsView): string {
  return page(view, "Detecții",
    "<h1>Detecții</h1>\n" +
    // Spus o dată, pe pagină, nu doar în comentarii: cine se uită aici trebuie
    // să știe că NU vede evenimente brute. O detecție e o interpretare a mai
    // multor evenimente, iar pagina asta ține locul lui `/events` de pe server
    // fără să fie același lucru.
    '<p class="nota">Panoul serverului răsfoiește evenimentele brute; aici nu ' +
    "există. <code>raw_events</code> nu pleacă în bloc de pe gazdă — e decizia " +
    "de graniță din 12 august 2026. Ce vezi mai jos sunt DETECȚII: interpretări " +
    "ale evenimentelor, nu evenimentele.</p>\n" +
    absent("detections", view.arrivals) + detectionRows(view.detections));
}

// ---------------------------------------------------------------------------
// Paginile ale căror fluxuri nu se expediază încă
// ---------------------------------------------------------------------------
/**
 * O pagină care există, are meniu și selector, și spune de ce e goală.
 *
 * Nu e un substitut provizoriu: în ziua în care fluxul ei începe să curgă,
 * mesajul dispare singur — `absent()` citește `sync_cursors`, nu o listă scrisă
 * de mână. Ce rămâne de făcut atunci e tabelul, nu curățenia.
 */
export function pendingPage(view: Chrome, title: string, stream: string,
                            explica: string): string {
  return page(view, title,
    `<h1>${escapeHtml(title)}</h1>\n` +
    `<p class="nota">${escapeHtml(explica)}</p>\n` +
    absent(stream, view.arrivals) +
    '<p class="gol">Tabelul apare aici când fluxul aduce rânduri.</p>\n');
}

// ---------------------------------------------------------------------------
// Vulnerabilități
// ---------------------------------------------------------------------------
export type FindingsView = Chrome & {
  findings: FindingSummary[];
  counts: Record<string, number> & { total: number };
  group: string | null;
  /** Filtrul pe culoare, sau `null`. Vine validat din rută (vocabular închis). */
  color: RiskColor | null;
  /** Pastilele de culoare, numărate în aceeași grupă ca tabelul. */
  colors: Record<RiskColor, number>;
  /** Starea scanarii care produce cifrele. Vezi `scanAge`. */
  scan: ScanHealth;
};

/**
 * Varsta cifrei, si — daca e cazul — ca ultima incercare de a o improspata a
 * ESUAT.
 *
 * Fara randul asta, pagina arata un numar fara moment. Masurat pe 21 august
 * 2026: operatorul a vazut 31 de vulnerabilitati neaplicate si nimic de
 * actualizat pe server. Numarul era masurat la 03:23, pachetele reparate la
 * 09:14, iar scanarea de la 10:33 — cea care le-ar fi inchis — esuase cu
 * `timeout`. Nimic din toate astea nu era vizibil.
 *
 * Esecul se scrie MAI TARE decat varsta, si e o alegere: o cifra veche de sase
 * ore poate fi in regula, dar o cifra veche FIINDCA masuratoarea cade e alta
 * situatie, iar cele doua nu au acelasi remediu.
 */
function scanAge(view: FindingsView): string {
  const { lastGood, latest } = view.scan;
  const parts: string[] = [];

  if (latest !== null && latest.status !== "completed" && latest.status !== "running") {
    parts.push('<p class="lipsa"><strong>Ultima scanare a esuat</strong> (' +
               escapeHtml(moment(latest.startedAt)) + " UTC" +
               (latest.error ? ", " + escapeHtml(latest.error) : "") +
               "). Cifrele de mai jos sunt de la masuratoarea dinainte, deci " +
               "pot fi vechi — o vulnerabilitate reparata intre timp apare in " +
               "continuare ca deschisa.</p>\n");
  }

  if (lastGood === null) {
    parts.push('<p class="gol">Nicio scanare incheiata cu bine nu a ajuns aici, ' +
               "deci cifrele n-au varsta cunoscuta.</p>\n");
  } else {
    parts.push('<p class="nota">Masurat la <strong>' +
               escapeHtml(moment(lastGood.finishedAt ?? lastGood.startedAt)) +
               " UTC</strong>, de scanerul <code>" + escapeHtml(lastGood.scanner) +
               "</code>. Cifrele nu se schimba intre scanari: ce repari pe server " +
               "apare aici dupa urmatoarea rulare.</p>\n");
  }
  return parts.join("");
}

/**
 * Filtrele de grupa, ca LEGATURI - nu ca formular si nu ca JavaScript.
 *
 * Fiecare poarta NUMARUL ei. Un filtru fara numar e o intrebare: „daca apas,
 * vad ceva?". Cu numar, intrebarea nu se pune, iar restanta se citeste dintr-o
 * privire.
 *
 * Suma celor trei poate fi mai mica decat totalul, si e corect: o stare pe care
 * serverul o inventeaza maine nu cade tacut in nicio grupa. Diferenta se vede
 * chiar aici, ca „Toate" mai mare decat suma - un semn ca vocabularul s-a
 * miscat, nu o clasificare inventata.
 */
function groupFilters(view: FindingsView): string {
  const items: [string | null, string, number][] = [
    [null, "Toate", view.counts.total],
    ["neaplicate", "Neaplicate", view.counts.neaplicate ?? 0],
    ["rezolvate", "Rezolvate", view.counts.rezolvate ?? 0],
    ["inchise", "Inchise fara reparatie", view.counts.inchise ?? 0],
  ];
  const parts = ['<nav class=\"filtre\">\n'];
  for (const [group, label, n] of items) {
    const base = withInstance("/panel/vulnerabilitati", view.selected);
    const href = group === null ? base
      : `${base}${base.includes("?") ? "&" : "?"}grupa=${group}`;
    const here = (view.group ?? null) === group
      ? ' class=\"aici\" aria-current=\"page\"' : "";
    parts.push(`<a href=\"${href}\"${here}>${escapeHtml(label)} ` +
               `<span class=\"nr\">${n}</span></a>\n`);
  }
  parts.push("</nav>\n");
  return parts.join("");
}

/**
 * Filtrele de culoare, ca LEGĂTURI, cu numărul fiecăreia, în ordinea listei: roșu,
 * galben, gri, verde — dar pastila poartă NUMELE STĂRII (Acum, Curând, Nedecis, Ciclul
 * obișnuit / De urmărit*), același cu cel al rândurilor pe care le aduce; cuvântul culorii
 * și numele din arborele CISA stau în `title`. Nedecis apare MEREU, chiar cu zero: „nimic
 * nedecis" e un fapt, iar o pastilă lipsă ar fi tăcere despre exact ce nu se știe.
 *
 * Numără doar constatările NEAPLICATE (culoarea nu se calculează pentru cele
 * rezolvate), iar o pastilă restrânge lista la grupa „neaplicate": nu poartă
 * `?grupa=`, fiindcă ar putea fi una în care culoarea nu are înțeles. Păstrează
 * serverul ales.
 */
function colorFilters(view: FindingsView): string {
  const base = withInstance("/panel/vulnerabilitati", view.selected);
  const sep = base.includes("?") ? "&" : "?";
  const keepGroup = "";
  const joiner = sep;
  const glyphs: Record<RiskColor, string> = {
    red: "🔴", amber: "🟡", grey: "⚪", green: "🟢",
  };
  const parts = ['<nav class="filtre" aria-label="Culoare">\n'];
  const total = COLORS.reduce((acc, c) => acc + view.colors[c], 0);
  parts.push(`<a href="${base}${keepGroup}"` +
             `${view.color === null ? ' class="aici" aria-current="page"' : ""}>` +
             `Neaplicate, toate culorile <span class="nr">${total}</span></a>\n`);
  for (const color of COLORS) {
    const href = `${base}${keepGroup}${joiner}culoare=${color}`;
    const here = view.color === color ? ' class="aici" aria-current="page"' : "";
    parts.push(`<a href="${href}" title="${escapeHtml(pillTitle(color))}"${here}>` +
               `${glyphs[color]} ${escapeHtml(COLOR_STATE_RO[color])} ` +
               `<span class="nr">${view.colors[color]}</span></a>\n`);
  }
  parts.push("</nav>\n");
  return parts.join("");
}

/** Stările în care serverul încă evaluează o constatare. */
const OPEN_STATUSES: ReadonlySet<string> = new Set(GROUPS.neaplicate);

/**
 * Celula „Risc": culoarea, decizia, și — numai dacă spune ceva — UN motiv scurt.
 *
 * Agregatorul vede mai multe servere, așa că aici stă doar ce trebuie ca să
 * decizi unde te uiți mai departe: de ce e culoarea asta într-o linie („exploatat
 * activ (KEV)", „EPSS 99,2%, CISA veche", „fără CVE"). Ce nu încape într-o celulă — ce
 * lipsește la un gri, a cui e decizia — e în `title`; cele patru puncte de decizie, cu
 * sursa fiecăruia și justificarea furnizorului, rămân pe serverul însuși și în bot.
 *
 * Semnul 🔁 (reparația e instalată, lipsește o repornire) vine din `rebootPending`, ca pe
 * serverul însuși: motivul nu-l mai poartă, iar un verde cu EPSS mic n-are motiv deloc.
 */
function riskCell(f: FindingSummary): string {
  // O constatare închisă nu mai e evaluată pe server: culoarea ei e cea implicită
  // (gri) sau una veche, iar a o desena ar spune „Nedecis" despre ceva rezolvat.
  if (!OPEN_STATUSES.has(f.status)) {
    return `<td><span class="id">— (${escapeHtml(f.status)})</span></td>`;
  }
  const r = f.risk;
  const strong = r.color === "red" || r.color === "amber";
  const label = `<span class="risc-eticheta">${escapeHtml(r.headline)}</span>`;
  const head = strong ? `<strong>${label}</strong>` : label;
  const reboot = r.rebootPending
    ? ' <span title="Reparația e instalată, lipsește o repornire">🔁</span>' : "";
  const why = r.greyReason ?? r.reason;
  const title = r.detail === null ? "" : ` title="${escapeHtml(r.detail)}"`;
  return `<td class="risc"${title}>${head}${reboot}` +
         (why === null ? "" : `<br><span class="id">${escapeHtml(why)}</span>`) + "</td>";
}

/**
 * Celula KEV. Un rând rezolvat sau închis nu mai e evaluat de server: `risk` îi e cel
 * vechi sau gol, deci „nu se știe" ar fi scris pe fiecare dintre cele ~6.700 de rânduri
 * rezolvate o neîncredere care nu mai întreabă pe nimeni. Un rând aflat în catalog rămâne
 * „da" oricare ar fi starea lui.
 */
function kevCell(f: FindingSummary): string {
  if (f.kev) return `<strong>${kevText(f.risk.kev)}</strong>`;
  return OPEN_STATUSES.has(f.status) ? escapeHtml(f.risk.kev) : "—";
}

/**
 * „da — 2026-08-30”: data stă într-un `nowrap`, „da —” rămâne liber. Pe server întreaga
 * celulă e `nowrap` (132 px), dar aici tabelul are 1112 px indiferent de ecran și nu-și
 * permite 132 px pentru două rânduri: celula se poate rupe LA spațiul dintre „da —” și dată,
 * nu în dată — fără asta data se rupea la cratime („2026-” / „08-30”). Textul vine din
 * `risk.kev` (aceeași sursă ca pe celelalte ecrane); un text fără „ — ” rămâne cum e.
 */
function kevText(kev: string): string {
  const sep = " — ";
  const at = kev.indexOf(sep);
  if (at < 0) return escapeHtml(kev);
  return escapeHtml(kev.slice(0, at + sep.length)) + nowrap(kev.slice(at + sep.length));
}

/**
 * Starea, cu un loc de rupere după fiecare „_”: `patch_planned` e un singur cuvânt fără spații
 * și, cum Pachet, Fix, CVE și KEV nu se mai rup, ar ține coloana la 109 px în loc de 72 (măsurat
 * în Edge, tabelul cu stări `patching`/`deferred`/`patch_planned`). E vocabular închis
 * (`finding-groups.ts`), nu un identificator pe care operatorul îl copiază.
 */
function statusText(status: string): string {
  return escapeHtml(status).replace(/_/g, "_<wbr>");
}

/** Un text pe care o linie nu-l poate rupe: identificatorul rămâne întreg sau trece întreg pe rândul următor. */
function nowrap(text: string): string {
  return `<span class="nowrap">${escapeHtml(text)}</span>`;
}

/**
 * Numele pachetului: fiecare segment dintre „/” e un `nowrap`, iar între ele stă un `<wbr>`,
 * singurul loc unde se rupe. Fără asta `symfony/http-foundation` se rupe la cratimă
 * („http-” / „foundation”), iar numele citit așa e alt nume.
 */
function packageParts(name: string | null): string {
  if (name === null || name === "") return "—";
  const parts = name.split("/");
  return parts.map((p, i) => nowrap(i < parts.length - 1 ? `${p}/` : p)).join("<wbr>");
}

/**
 * `fixed_version`, o versiune pe `nowrap`, despărțite prin „, ”: celula se rupe doar între
 * versiuni. Scanerul scrie versiunile separate prin virgulă (până la 19 pe producție,
 * 135 de caractere), iar o versiune ruptă la cratimă („15.6.0-” / „canary.59”) se citește
 * ca altă versiune.
 */
function fixVersions(fixed: string | null): string {
  const versions = (fixed ?? "").split(",").map((v) => v.trim()).filter((v) => v !== "");
  return versions.length === 0 ? "—" : versions.map(nowrap).join(", ");
}

export function findingsPage(view: FindingsView): string {
  return page(view, "Vulnerabilitati",
    "<h1>Vulnerabilitati</h1>\n" + scanAge(view) + groupFilters(view) + colorFilters(view) +
    // Ordinea e a serverului, și se spune: cine se uită la o listă sortată
    // altfel decât crede trage concluzii greșite despre ce e urgent.
    '<p class="nota">Culoarea e decizia CISA SSVC calculată pe serverul fiecărui ' +
    `rând (${legendStates()}; „De urmărit*” e ciclul obișnuit, dar cu o privire mai deasă), ` +
    "din exploatare " +
    "(KEV, valorile publicate de CISA), vector CVSS și criticitatea activului — nu un prag. " +
    "<strong>Singura excepție, a Sentinel și nu a SSVC:</strong> un rând galben marcat " +
    "„regula Sentinel” a fost urcat acolo fiindcă EPSS ≥ 50% stă lângă o evaluare CISA de " +
    "peste 180 de zile; SSVC singur l-ar fi lăsat mai jos. " +
    "<strong>⚪ Nedecis înseamnă că lipsesc date, nu că e în regulă.</strong> " +
    `<strong>KEV „nu se știe”</strong> înseamnă că ${KEV_UNKNOWN_NOTE_RO} — ` +
    "nu e același lucru cu „nu”. Neaplicatele primele, apoi " +
    "ordonate după stare (culoare), apoi după probabilitate × impact; în galben, un rând decis de " +
    "arborele CISA stă înaintea unuia urcat de regula Sentinel (decizia CISA, înaintea " +
    "estimării EPSS). Replica nu recalculează " +
    "nimic și nu amestecă serverele: culoarea unui rând e verdictul gazdei lui.</p>\n" +
    absent("findings", view.arrivals) +
    table(
      // Aceeași ordine și aceleași nume ca în panoul serverului (`findings.html`): semnalele
      // — risc, severitate, CVE, CVSS, EPSS, KEV — la stânga, una lângă alta, ca să se
      // citească împreună; ce identifică rândul (pachet, fix) după ele.
      "<th>Risc</th><th>Severitate</th><th>CVE</th><th>CVSS</th><th>EPSS</th><th>KEV</th>" +
      "<th>Pachet</th><th>Fix</th><th>Stare</th>",
      view.findings.map((f) =>
        "<tr>" + riskCell(f) + severityCell(f.severity) +
        `<td>${nowrap(f.cve ?? "—")}<br>` +
        `<span class="id">${escapeHtml(f.scanner)}</span></td>` +
        `<td class="nr">${escapeHtml(f.risk.cvss)}</td>` +
        `<td class="nr">${escapeHtml(f.risk.epss)}</td>` +
        `<td>${kevCell(f)}</td>` +
        `<td>${packageParts(f.packageName)}<br>` +
        `<span class="id nowrap">${escapeHtml(f.installedVersion ?? "—")}</span></td>` +
        `<td>${fixVersions(f.fixedVersion)}</td>` +
        `<td>${statusText(f.status)}</td></tr>\n`),
      "nicio constatare", "findings"),
    // Nouă coloane cu identificatori nerupți nu încap în 72rem — vezi `main.wide` în `panel.css`.
    "wide");
}

// ---------------------------------------------------------------------------
// Blocări
// ---------------------------------------------------------------------------
export type BlocklistView = Chrome & { blocks: BlockSummary[] };

export function blocklistPage(view: BlocklistView): string {
  return page(view, "Blocări",
    "<h1>Blocări</h1>\n" +
    '<p class="nota">Deblocarea nu se face de aici: panoul e doar de citire, iar ' +
    "canalul de comandă rămâne Telegram. <code>Lovituri</code> e citit din " +
    "contorul nftables de pe gazdă — o blocare cu zero lovituri n-a oprit nimic, " +
    "și ăsta e singurul răspuns cinstit la întrebarea dacă a folosit la ceva.</p>\n" +
    absent("blocklist", view.arrivals) +
    table(
      "<th>Stare</th><th>Adresă</th><th>Motiv</th><th>Lovituri</th>" +
      "<th>Blocat la (UTC)</th><th>Expiră (UTC)</th><th>De</th>",
      view.blocks.map((b) =>
        "<tr>" +
        `<td>${b.active ? "<strong>activă</strong>" : "expirată"}</td>` +
        `<td><code>${escapeHtml(b.ip)}${b.prefixLen === null ? "" : `/${b.prefixLen}`}</code></td>` +
        `<td>${escapeHtml(b.reason)}${b.ruleId
          ? `<br><span class="id">${escapeHtml(b.ruleId)}</span>` : ""}</td>` +
        `<td class="nr">${b.hitCount}</td>` +
        `<td>${escapeHtml(moment(b.blockedAt))}</td>` +
        `<td>${escapeHtml(moment(b.expiresAt))}</td>` +
        `<td>${escapeHtml(b.createdBy)}</td></tr>\n`),
      "nicio blocare"));
}

// ---------------------------------------------------------------------------
// Patch-uri
// ---------------------------------------------------------------------------
export type PlansView = Chrome & { plans: PlanSummary[] };

export function patchPlansPage(view: PlansView): string {
  return page(view, "Patch-uri",
    "<h1>Patch-uri</h1>\n" +
    // Spus pe pagină, nu doar în cod: cine se uită aici trebuie să știe ce NU
    // vede, altfel „planul e aplicat" pare să însemne că a văzut execuția.
    '<p class="nota">Lista planurilor și starea lor. Execuțiile și pașii lor NU ' +
    "sunt aici: <code>patch_steps.argv</code> e un tablou, iar protocolul nu " +
    "poartă încă sub-rânduri. Dry-run-ul și respingerea nu se portează — sunt " +
    "comenzi, iar agregatorul nu execută niciodată nimic dintr-un plan.</p>\n" +
    // Ce poartă eticheta, și ce înseamnă: un plan are un model scris în rând (`patch_plans.model`)
    // doar dacă l-a redactat modelul; unul introdus de mână n-o primește. Riscul, repornirea,
    // reversibilitatea și indisponibilitatea sunt ale lui — estimări de model, nu măsurători.
    '<p class="nota">Planurile cu eticheta „AI content” au fost redactate de model: ' +
    "riscul, repornirea, reversibilitatea și indisponibilitatea sunt estimările lui, " +
    "nu măsurători făcute pe gazdă.</p>\n" +
    absent("patch_plans", view.arrivals) +
    table(
      "<th>Stare</th><th>Risc</th><th>Plan</th><th>Repornire</th>" +
      "<th>Reversibil</th><th>Indisponibilitate</th><th>Creat (UTC)</th>",
      view.plans.map((p) =>
        "<tr>" +
        `<td>${escapeHtml(p.status)}${p.rejectedReason
          ? `<br><span class="id">${escapeHtml(p.rejectedReason)}</span>` : ""}</td>` +
        `<td>${escapeHtml(p.riskLevel ?? "—")}</td>` +
        `<td><code class="id">${escapeHtml(p.planUuid)}</code>${p.model === null
          ? "" : ` ${aiBadge()}`}${p.blastRadius
          ? `<br>${escapeHtml(p.blastRadius)}` : ""}</td>` +
        `<td>${p.requiresReboot ? "<strong>da</strong>" : "nu"}</td>` +
        `<td>${p.reversible ? "da" : "<strong>NU</strong>"}</td>` +
        `<td class="nr">${p.estimatedDowntimeS === null
          ? "—" : `${p.estimatedDowntimeS} s`}</td>` +
        `<td>${escapeHtml(moment(p.createdAt))}</td></tr>\n`),
      "niciun plan"));
}

// ---------------------------------------------------------------------------
// Servicii — autodiagnosticul
// ---------------------------------------------------------------------------
export type ServicesView = Chrome & { checks: CheckState[] };

export type SessionsView = Chrome & {
  sessions: LoginSession[];
  /** Sesiunea deschisă, dacă s-a cerut una. */
  detail: SessionDetail | null;
  /** `true` când se arată și sesiunile de automatizare. */
  showingAll: boolean;
};

/** Cât a durat o sesiune, citit de om. */
function durata(session: LoginSession): string {
  if (!session.openedAt || !session.closedAt) return "—";
  const de_la = Date.parse(session.openedAt.replace(" ", "T") + "Z");
  const pana = Date.parse(session.closedAt.replace(" ", "T") + "Z");
  if (!Number.isFinite(de_la) || !Number.isFinite(pana)) return "—";
  const minute = Math.max(0, Math.round((pana - de_la) / 60000));
  return minute >= 60 ? `${Math.floor(minute / 60)}h ${minute % 60}m` : `${minute}m`;
}

export function sessionsPage(view: SessionsView): string {
  const parts: string[] = [];

  parts.push("<h1>Sesiuni de login</h1>\n");
  parts.push(absent("login_sessions", view.arrivals));

  // Comutatorul dintre „numai oameni" și „tot". Legătură, nu formular: politica
  // paginii n-are scripturi, iar un `<select>` fără buton nu trimite nimic.
  const alt = withInstance("/panel/sesiuni", view.selected)
    + (view.showingAll ? "" : (view.selected === null ? "?" : "&") + "toate=1");
  parts.push('<p class="nota">' + (view.showingAll
    ? `Se arată <strong>toate</strong> sesiunile, inclusiv cele fără terminal — `
      + `deploy, rsync, diagnostic. Măsurat pe gazdă, sunt de aproape douăzeci de `
      + `ori mai multe decât cele de om. `
      + `<a href="${escapeHtml(withInstance("/panel/sesiuni", view.selected))}">`
      + `Arată numai sesiunile cu terminal</a>.`
    : `Se arată numai sesiunile <strong>cu terminal</strong> — cele în care a fost `
      + `cineva la tastatură. Automatizările (deploy, rsync, diagnostic) sunt `
      + `înregistrate, dar nu apar aici. `
      + `<a href="${escapeHtml(alt)}">Arată-le și pe acelea</a>.`)
    + "</p>\n");

  parts.push(table(
    "<th>Deschisă (UTC)</th><th>Cont</th><th>De la</th><th>Terminal</th>" +
    "<th>Durată</th><th>Comenzi</th><th>Privilegiate</th>",
    view.sessions.map((s) => {
      const href = withInstance("/panel/sesiuni", view.selected)
        + (view.selected === null ? "?" : "&") + `sesiune=${s.sourceId}`;
      // Închiderea PRESUPUSĂ se marchează. „S-a deconectat la 14:32" și „n-am
      // mai auzit nimic de ea după 14:32" sunt afirmații diferite, iar un panou
      // care le arată identic minte liniștit.
      const semn = s.closedAt === null
        ? ' <span class="sev sev-info">deschisă</span>'
        : (s.closedInferred ? ' <span class="sev sev-alta">presupus</span>' : "");
      return "<tr>" +
        `<td><a href="${escapeHtml(href)}">${escapeHtml(moment(s.openedAt))}</a>` +
        `${semn}</td>` +
        `<td>${escapeHtml(s.username ?? "necunoscut")}</td>` +
        `<td><code>${escapeHtml(s.srcIp ?? "local")}</code></td>` +
        `<td><code>${escapeHtml(s.terminal ?? "—")}</code></td>` +
        `<td>${escapeHtml(durata(s))}</td>` +
        // Contorul e CHIAR legătura spre comenzi: până pe 5 octombrie 2026 era
        // text, iar singura cale spre detaliu era data deschiderii — pe care
        // nimic nu o arăta ca pe un buton.
        `<td class="nr"><a href="${escapeHtml(href)}" ` +
        `title="Arată comenzile sesiunii">${s.commandCount}</a></td>` +
        `<td class="nr">${s.sudoCount}</td></tr>\n`;
    }),
    view.showingAll ? "nicio sesiune" : "nicio sesiune cu terminal"));

  if (view.sessions.length >= SESSIONS_SHOWN) {
    parts.push(`<p class="nota">Se arată primele ${SESSIONS_SHOWN}; sunt și mai `
               + "vechi, netăiate din bază.</p>\n");
  }

  if (view.detail !== null) parts.push(sessionCommands(view, view.detail));
  return page(view, "Sesiuni", parts.join(""));
}

/** Legătura spre o pagină anume a comenzilor unei sesiuni. */
function sessionPageHref(view: SessionsView, sourceId: number, pagina: number): string {
  return withInstance("/panel/sesiuni", view.selected)
    + (view.selected === null ? "?" : "&") + `sesiune=${sourceId}`
    + (pagina > 1 ? `&pagina=${pagina}` : "")
    + (view.showingAll ? "&toate=1" : "");
}

/** «Pagina 3 din 45», cu cele patru legături. Nimic când e o singură pagină. */
function pager(view: SessionsView, detail: SessionDetail, sourceId: number): string {
  if (detail.pages <= 1) return "";
  const link = (pagina: number, eticheta: string, activ: boolean): string =>
    activ
      ? `<a href="${escapeHtml(sessionPageHref(view, sourceId, pagina))}">${eticheta}</a>`
      : `<span class="id">${eticheta}</span>`;
  return '<p class="nota">' +
    `Pagina <strong>${detail.page}</strong> din ${detail.pages} · comenzile ` +
    `${detail.from}–${detail.to} din ${detail.stored} · ` +
    link(1, "« prima", detail.page > 1) + " · " +
    link(detail.page - 1, "‹ înapoi", detail.page > 1) + " · " +
    link(detail.page + 1, "înainte ›", detail.page < detail.pages) + " · " +
    link(detail.pages, "ultima »", detail.page < detail.pages) +
    "</p>\n";
}

/** Comenzile unei sesiuni. */
function sessionCommands(view: SessionsView, detail: SessionDetail): string {
  if (detail.session === null) {
    return '<p class="gol">Sesiunea cerută nu există pe serverul ales.</p>\n';
  }
  const s = detail.session;
  const parts: string[] = [];
  parts.push(`<h1>Ce s-a rulat · sesiunea <code>${escapeHtml(s.sessionKey)}</code>`
             + `</h1>\n`);
  parts.push(`<p class="nota">Cont <code>${escapeHtml(s.username ?? "necunoscut")}`
             + `</code>, de la <code>${escapeHtml(s.srcIp ?? "local")}</code>, `
             + `${s.commandCount} comenzi, ${s.sudoCount} privilegiate.</p>\n`);

  // `commandCount` e câte rânduri are GAZDA; curățarea de aici șterge din
  // arhivă și nu atinge cifra aia. Fără rândul următor, o sesiune de deploy
  // curățată ar arăta «558 079 comenzi» deasupra unui tabel gol — adică fix
  // eșecul pentru care există contorul.
  if (s.commandsPurged > 0) {
    parts.push('<p class="lipsa"><strong>'
               + `${s.commandsPurged} comenzi ale sesiunii au fost șterse `
               + "din arhiva asta</strong> ca zgomot de automatizare.<br>"
               + "Numărul de deasupra e cât a rulat sesiunea pe gazdă; "
               + "tabelul de mai jos arată ce a mai rămas aici.</p>\n");
  }

  // Ce lipsește FĂRĂ să fie curățare: gazda a numărat mai multe comenzi decât
  // are replica. Spus cu cifre și cu cauza atât cât se știe — «nu știu» e un
  // răspuns, iar un tabel mai scurt decât numărul de deasupra, fără nicio
  // explicație, arată ca «atât s-a rulat».
  if (detail.missing > 0) {
    const cauza = detail.missingWhy === "retention"
      ? `Sesiunea e mai veche decât fereastra de retenție a replicii pentru ` +
        `sesiunile ${s.interactive ? "cu" : "fără"} terminal ` +
        `(${detail.retentionDays} de zile): comenzile ei au fost tăiate de ea. ` +
        "Pe gazdă rămân toate."
      : "Cauza nu se poate stabili de aici: pot fi tăiate de curățarea " +
        "automatizărilor, pot să nu fi ajuns încă pe replică (fluxul vine în " +
        "loturi) sau n-au putut fi legate de sesiune. Pe gazdă sunt toate.";
    parts.push('<p class="lipsa"><strong>'
               + `${detail.missing} din ${s.commandCount} comenzi nu sunt în arhiva `
               + "asta.</strong><br>" + escapeHtml(cauza) + "</p>\n");
  }

  parts.push('<p class="nota">' + (detail.stored === 0
    ? "Arhiva asta nu are nicio comandă a sesiunii."
    : `În arhivă: <strong>${detail.stored}</strong> comenzi` +
      (detail.pages > 1
        ? `, pe pagini de ${COMMANDS_SHOWN}; aici sunt ${detail.from}–${detail.to}.`
        : ", toate pe pagina asta.")) + "</p>\n");

  parts.push(pager(view, detail, s.sourceId));

  parts.push(table(
    "<th>Când (UTC)</th><th>Binar</th><th>Linia de comandă</th><th>Rezultat</th>",
    detail.commands.map((c) => {
      const stare = c.success === null
        ? "—"
        : (c.success ? "ok" : '<span class="sev sev-medium">eșec</span>');
      return "<tr>" +
        `<td>${escapeHtml(moment(c.ts))}</td>` +
        `<td><code>${escapeHtml((c.exe ?? "").split("/").pop() ?? "")}</code></td>` +
        `<td><code>${escapeHtml(c.argv)}</code></td>` +
        `<td>${stare}</td></tr>\n`;
    }),
    "nicio comandă înregistrată pentru sesiunea asta"));

  parts.push(pager(view, detail, s.sourceId));

  parts.push('<p class="nota">Liniile de comandă sosesc <strong>redactate</strong>: '
             + "valorile care arată a secret sunt tăiate pe gazdă, la colectare. "
             + "Redactarea e o listă de tipare, nu o garanție — vezi "
             + "<code>docs/SECURITATE.md</code>.</p>\n");
  return parts.join("");
}


export function servicesPage(view: ServicesView): string {
  return page(view, "Servicii",
    "<h1>Servicii</h1>\n" +
    '<p class="nota">Rezultatul autodiagnosticului de pe server, replicat. ' +
    "Ordonate cu ce e rupt întâi. <code>Vechi</code> înseamnă că ultima rulare a " +
    "verificării a fost incompletă și cifra arătată e ultima știută — nu că " +
    "verificarea a trecut.</p>\n" +
    absent("selfcheck_state", view.arrivals) +
    table(
      "<th>Stare</th><th>Verificare</th><th>Detaliu</th>" +
      "<th>Din (UTC)</th><th>Ultima rulare (UTC)</th>",
      view.checks.map((c) =>
        "<tr>" +
        `<td><span class="sev ${statusClass(c.status)}">${escapeHtml(c.status)}</span>` +
        `${c.stale ? '<br><span class="id">vechi</span>' : ""}</td>` +
        `<td>${escapeHtml(c.title)}<br>` +
        `<code class="id">${escapeHtml(c.checkKey)}</code></td>` +
        `<td>${escapeHtml(c.detail)}</td>` +
        `<td>${escapeHtml(moment(c.since))}</td>` +
        `<td>${escapeHtml(moment(c.lastSeen))}</td></tr>\n`),
      "nicio verificare"));
}

/**
 * Culoarea unei stări de autodiagnostic.
 *
 * Vocabularul e altul decât al severităților — `down` nu e `critical` —, deci
 * are propria hartă. Refolosită, o stare necunoscută ar fi căzut pe clasa
 * „altă severitate" și ar fi arătat ca o informație neutră, când de fapt e o
 * stare pe care panoul n-o cunoaște.
 */
function statusClass(status: string): string {
  const known: Record<string, string> = {
    down: "sev-critical", degraded: "sev-high",
    unknown: "sev-medium", ok: "sev-info",
  };
  return known[status] ?? "sev-alta";
}

// ---------------------------------------------------------------------------
// Rapoarte
// ---------------------------------------------------------------------------

export type ReportsView = Chrome & { hours: HourRow[] };

/** Octeti in ceva ce se citeste dintr-o privire. */
function bytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "?";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) { value /= 1024; i += 1; }
  return `${value < 10 && i > 0 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

export function reportsPage(view: ReportsView): string {
  return page(view, "Rapoarte",
    "<h1>Rapoarte</h1>\n" +
    '<p class="nota">Contorul orar, calculat PE SERVER si replicat aici. ' +
    "Agregatorul nu recalculeaza nimic: <code>uniq_src</code> e un maxim peste " +
    "minute, nu o suma, iar o recalculare de aici ar da alt numar fara ca nimic " +
    "sa spuna care e bun. Ora IN CURS nu apare — un contor trimis la jumatatea " +
    "orei lui s-ar citi pe grafic ca o cadere de trafic care nu s-a intamplat." +
    "</p>\n" +
    absent("event_rollup_1h", view.arrivals) +
    table(
      "<th>Ora (UTC)</th><th>Evenimente</th><th>Surse</th>" +
      "<th>Intrare</th><th>Iesire</th><th>Din ce</th>",
      view.hours.map((h) =>
        "<tr>" +
        `<td>${escapeHtml(moment(h.bucket))}</td>` +
        `<td class="nr">${h.events}</td>` +
        `<td class="nr">${h.uniqSources}</td>` +
        `<td class="nr">${escapeHtml(bytes(h.bytesIn))}</td>` +
        `<td class="nr">${escapeHtml(bytes(h.bytesOut))}</td>` +
        // Sursele unei ore, UNA LÂNGĂ ALTA (`.din-ce`), nu una sub alta: măsurat pe cele 48 de ore
        // reale ale producției, tabelul are nevoie de 582 px (min-content 459), iar la 72rem avea
        // 1112 — lățimea nu e ce lipsește pe pagina asta, înălțimea e: patru surse stivuite dau
        // rânduri de 107 px și o pagină de 5173 px pentru 48 de ore. Pe o singură linie, lățimea
        // lui `main.wide` e folosită de ce o merită, iar rândul scade la un sfert.
        `<td><div class="din-ce">${h.top.map((t) =>
          '<span class="sursa">' +
          `<code class="id">${escapeHtml(t.source)}/${escapeHtml(t.action)}</code>` +
          ` ${t.events}</span>`).join("") || "&mdash;"}</div></td>` +
        "</tr>\n"),
      "nicio ora incheiata inca"),
    // Vezi `main.wide` și măsurătorile din `panel.css`.
    "wide");
}
