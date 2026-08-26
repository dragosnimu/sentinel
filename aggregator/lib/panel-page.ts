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

function table(head: string, rows: string[], gol: string): string {
  if (rows.length === 0) return `<p class="gol">${escapeHtml(gol)}</p>\n`;
  return `<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n` +
         rows.join("") + "</tbody>\n</table>\n";
}

function page(view: Chrome, title: string, body: string): string {
  return shell(`${title} — Sentinel`, chrome(view) + "<main>\n" + body + "</main>\n");
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
    card("Vulnerabilitati", String(o.findingsOpen), "neaplicate inca") +
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
      const aici = inst.instanceId === view.selected ? ' class="aici"' : "";
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
    "<th>Ultima detecție (UTC)</th>",
    incidents.map((inc) =>
      "<tr>" + severityCell(inc.severity) +
      `<td><a href="${withInstance(`/panel/incidente/${inc.id}`, selected)}">` +
      `${escapeHtml(inc.title)}</a></td>` +
      `<td>${escapeHtml(inc.status)}</td>` +
      `<td class="nr">${inc.detectionCount}</td>` +
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

export function incidentPage(view: IncidentView): string {
  const inc = view.incident;
  const parts: string[] = [];
  parts.push(`<p><a href="${withInstance("/panel/incidente", view.selected)}">` +
             "← înapoi la incidente</a></p>\n");
  parts.push(`<h1>${escapeHtml(inc.title)}</h1>\n`);

  parts.push('<dl class="detaliu">\n');
  const rows: [string, string][] = [
    ["Severitate", inc.severity],
    ["Severitate AI", inc.aiSeverity ?? "—"],
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

export function findingsPage(view: FindingsView): string {
  return page(view, "Vulnerabilitati",
    "<h1>Vulnerabilitati</h1>\n" + scanAge(view) + groupFilters(view) +
    // Ordinea e a serverului, și se spune: cine se uită la o listă sortată
    // altfel decât crede trage concluzii greșite despre ce e urgent.
    '<p class="nota">Ordonate după <code>priority</code>, scorul calculat pe ' +
    "server din severitate, EPSS și apartenența la catalogul KEV. Replica nu " +
    "recalculează nimic — CVSS-ul singur prezice prost ce se atacă efectiv.</p>\n" +
    absent("findings", view.arrivals) +
    table(
      "<th>Severitate</th><th>CVE</th><th>Pachet</th><th>Fix</th>" +
      "<th>EPSS</th><th>KEV</th><th>Prioritate</th><th>Stare</th>",
      view.findings.map((f) =>
        "<tr>" + severityCell(f.severity) +
        `<td>${escapeHtml(f.cve ?? "—")}<br>` +
        `<span class="id">${escapeHtml(f.scanner)}</span></td>` +
        `<td>${escapeHtml(f.packageName ?? "—")}<br>` +
        `<span class="id">${escapeHtml(f.installedVersion ?? "—")}</span></td>` +
        `<td>${escapeHtml(f.fixedVersion ?? "—")}</td>` +
        `<td class="nr">${escapeHtml(f.epss ?? "—")}</td>` +
        `<td>${f.kev
          ? `<strong>da</strong>${f.kevDueDate ? ` — ${escapeHtml(f.kevDueDate)}` : ""}`
          : "nu"}</td>` +
        `<td class="nr">${f.priority}</td>` +
        `<td>${escapeHtml(f.status)}</td></tr>\n`),
      "nicio constatare"));
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
    absent("patch_plans", view.arrivals) +
    table(
      "<th>Stare</th><th>Risc</th><th>Plan</th><th>Repornire</th>" +
      "<th>Reversibil</th><th>Indisponibilitate</th><th>Creat (UTC)</th>",
      view.plans.map((p) =>
        "<tr>" +
        `<td>${escapeHtml(p.status)}${p.rejectedReason
          ? `<br><span class="id">${escapeHtml(p.rejectedReason)}</span>` : ""}</td>` +
        `<td>${escapeHtml(p.riskLevel ?? "—")}</td>` +
        `<td><code class="id">${escapeHtml(p.planUuid)}</code>${p.blastRadius
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
        `<td class="nr">${s.commandCount}</td>` +
        `<td class="nr">${s.sudoCount}</td></tr>\n`;
    }),
    view.showingAll ? "nicio sesiune" : "nicio sesiune cu terminal"));

  if (view.sessions.length >= SESSIONS_SHOWN) {
    parts.push(`<p class="nota">Se arată primele ${SESSIONS_SHOWN}; sunt și mai `
               + "vechi, netăiate din bază.</p>\n");
  }

  if (view.detail !== null) parts.push(sessionCommands(view.detail));
  return page(view, "Sesiuni", parts.join(""));
}

/** Comenzile unei sesiuni. */
function sessionCommands(detail: SessionDetail): string {
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

  if (detail.truncated) {
    // Un plafon TĂCUT arată exact ca «atât s-a rulat». Diferența dintre „n-a mai
    // făcut nimic" și „restul nu ți l-am arătat" e chiar întrebarea.
    parts.push('<p class="lipsa"><strong>Listă tăiată la '
               + `${COMMANDS_SHOWN} de comenzi.</strong><br>Sesiunea a rulat `
               + `${s.commandCount} în total. Un shell de login pornește singur `
               + "câteva sute de procese; restul se citește din baza de pe "
               + "gazdă.</p>\n");
  }

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
        `<td>${h.top.map((t) =>
          `<code class="id">${escapeHtml(t.source)}/${escapeHtml(t.action)}</code>` +
          ` ${t.events}`).join("<br>") || "&mdash;"}</td>` +
        "</tr>\n"),
      "nicio ora incheiata inca"));
}
