/**
 * Pagina martorului: mai trăiește Sentinel?
 *
 * Răspunde de pe telefon, fără autentificare, fără VPN, fără să deschizi
 * panoul. Asta e tot ce trebuie să facă.
 *
 * ## Ce arată public și ce nu
 *
 * Public: dacă semnalul e proaspăt și de când, pentru fiecare instanță. Un
 * atacator care încarcă pagina află că serverele sunt monitorizate — ceea ce
 * oricum presupunea — și nimic despre ce anume s-a detectat.
 *
 * Identificatorul instanței NU e public. Nu e un secret criptografic (călătorește
 * într-un antet), dar e cheia de căutare a semnalului și n-are de ce să stea la
 * vedere. Public se arată eticheta, dacă instanța a trimis una, altfel un
 * fragment din identificator — destul cât să deosebești două rânduri, prea
 * puțin cât să numeri sau să numești serverele cuiva.
 *
 * Cu `?key=<SENTINEL_CHECK_SECRET>`: identificatorul întreg și contoarele. Câte
 * incidente sunt deschise și câte adrese sunt blocate spun ceva despre ce se
 * întâmplă pe server, deci nu stau la vedere.
 *
 * ## De ce e un ȘIR de HTML și nu o componentă React
 *
 * Pagina asta a fost o componentă cât timp martorul era o aplicație separată, cu
 * politica lui de conținut. Pe agregator nu mai poate fi: `securityHeaders()`
 * din `lib/auth/http.ts` emite `script-src 'self'`, identic cu vhostul
 * serverului monitorizat, iar egalitatea aia e ținută de
 * `tests/unit/test_aggregator_csp_parity.py`.
 *
 * Măsurat pe 17 august 2026, ca să nu rămână o presupunere: o pagină Next 15
 * randată EXCLUSIV pe server, fără niciun marcaj de client, emite unsprezece
 * elemente de script — cinci cu `src` de aceeași origine și ȘASE INLINE. Cele
 * inline sunt exact ce refuză `script-src 'self'`, deci pagina ar fi ajuns pe
 * telefonul operatorului ruptă, nu doar neanimată.
 *
 * Cele două ieșiri erau: un nonce per răspuns, sau HTML. Nonce-ul are pe un CDN
 * modul de eșec descris în `lib/auth/render.ts` — o pagină din cache poartă un
 * nonce expirat, se strică pentru toată lumea deodată, iar reparația evidentă
 * sub presiune e slăbirea politicii, adică se pierde exact în ziua în care e
 * nevoie de ea. Deci HTML, pe același drum ca paginile de autentificare.
 *
 * Ce se păstrează totuși e ASPECTUL: `style-src 'self'` permite o foaie de stil
 * de la aceeași origine, iar `public/martor.css` e chiar cea de dinainte. O
 * pagină de stare citită de pe telefon la 3 dimineața nu e locul în care se
 * economisește lizibilitate.
 *
 * ## Escaparea, care aici e OPT-IN
 *
 * În JSX, textul se escapa singur. Aici nu: tot ce nu e literal în fișierul ăsta
 * trece prin `escapeHtml`, iar lista de valori din afară e mai lungă decât pare.
 * Identificatorii vin din configurație și trec `ID_PATTERN`, deci sunt inofensivi
 * — dar `label`, `selfcheck.worst` și `verdict.message` NU sunt: primele două vin
 * dintr-un payload semnat pe o mașină care poate fi compromisă, iar al treilea
 * interpolează `received_at` citit dintr-un fișier de stare pe care
 * `asInstanceState` îl verifică doar ca tip. Un caracter de marcaj scăpat de
 * acolo nu urâțește pagina, o rescrie.
 *
 * Se folosește `escapeHtml` din `lib/auth/render.ts` — cel care acoperă și
 * ghilimelele —, NU cel din `lib/telegram.ts`, care escapează doar cele trei
 * caractere cerute de Telegram. Sunt două funcții cu același nume în aplicația
 * asta și fac lucruri diferite; alegerea greșită aici lasă ghilimelele întregi,
 * iar ele sunt tot ce desparte un atribut de următorul.
 */

import { CSP_META_TAG } from "./csp";
import { escapeHtml } from "./auth/render";
import { DEFAULT_INSTANCE } from "./beat-keys";
import type { Beat, InstanceState, State } from "./store";
import { judge } from "./verify";

function age(iso: string | undefined): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 90) return `${s} secunde`;
  if (s < 5400) return `${Math.round(s / 60)} minute`;
  if (s < 172800) return `${Math.round(s / 3600)} ore`;
  return `${Math.round(s / 86400)} zile`;
}

const EXPLAIN: Record<string, string> = {
  silent:
    "Semnalul s-a oprit. Serviciile pot fi oprite, gazda căzută sau rețeaua tăiată. " +
    "Verifică serverul direct — nu prin panou, fiindcă panoul e pe el.",
  stalled:
    "Semnalul sosește, dar contoarele nu mai avansează. Procesul trăiește și " +
    "conducta e moartă: nu se mai colectează sau nu se mai detectează nimic.",
  selfcheck: "Sentinel raportează singur o problemă. Vezi /autoverificare pe Telegram.",
};

// Un titlu per verdict, fiindcă „a amuțit" și „raportează o problemă internă"
// sunt situații complet diferite pentru cel care citește.
//
// Toate trei purtau înainte „Sentinel nu răspunde". Prima dată când pagina a
// arătat asta pentru un autodiagnostic cu 32 din 33 de verificări trecute,
// concluzia cititorului a fost că serverul e căzut — pentru un serviciu care
// trimitea semnal la fiecare 60 de secunde. O pagină care există ca să spună
// adevărul despre o tăcere nu are voie să inventeze una.
const HEADLINE: Record<string, string> = {
  silent: "nu răspunde",
  stalled: "trăiește, dar nu mai colectează",
  selfcheck: "raportează o problemă",
  replay: "semnal refuzat: secvență reluată",
  forged: "semnal refuzat: semnătură invalidă",
};

/** Numele arătat fără cheie. Nu conține identificatorul întreg, dinadins. */
function publicName(id: string, inst: InstanceState): string {
  const label = inst.last?.label?.trim();
  if (label) return label;
  if (id === DEFAULT_INSTANCE) return "Sentinel";
  return `${id.slice(0, 8)}…`;
}

/** Un rând din tabelul unui card. Ambele capete escapate, fără excepție. */
function row(label: string, value: string): string {
  return `        <div class="row"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>
`;
}

/**
 * Rândurile care se arată DOAR cu `?key=<SENTINEL_CHECK_SECRET>`.
 *
 * Funcție separată, iar numele ei se citește din afară:
 * `tests/unit/test_force_step_list.py` taie fișierul aici ca să afle ce vede
 * operatorul FĂRĂ cheie. O procedură care îi cere să citească un număr ascuns în
 * spatele cheii se termină într-un ecran gol exact în clipa în care verifică
 * dacă beaconul a supraviețuit unei rotiri de secret.
 */
function detailedRows(last: Beat): string {
  return [
    row("Incidente deschise", String(last.incidents_open)),
    row("Adrese blocate", String(last.blocklist_size)),
    row("Ultimul eveniment", `#${last.last_event_id.toLocaleString("ro-RO")}`),
    row("Cursor detecție", `#${last.detect_cursor.toLocaleString("ro-RO")}`),
    row("Semnal nr.", last.seq.toLocaleString("ro-RO")),
  ].join("");
}

function card(status: string, headline: string, lede: string, rows: string): string {
  return `      <section class="card ${escapeHtml(status)}">
        <h2 class="verdict"><span class="dot" aria-hidden="true"></span>${escapeHtml(headline)}</h2>
        <p class="lede">${escapeHtml(lede)}</p>
${rows}      </section>
`;
}

function instanceCard(id: string, inst: InstanceState, now: Date, detailed: boolean): string {
  const verdict = judge(inst, now);
  const last = inst.last;
  const status = !last ? "unknown" : verdict.kind === null ? "ok" : "bad";
  const name = detailed ? id : publicName(id, inst);
  const headline =
    status === "unknown" ? "niciun semnal încă"
      : status === "ok" ? "e în viață"
        : HEADLINE[verdict.kind ?? ""] ?? "raportează o problemă";
  const lede =
    status === "unknown"
      ? "Instanța e cunoscută, dar nu a trimis încă niciun semnal."
      : status === "ok"
        ? `Ultimul semnal acum ${age(last?.received_at)}.`
        : EXPLAIN[verdict.kind ?? ""] ?? verdict.message;

  const rows =
    `        <div class="rows">
` +
    row("Ultimul semnal", last ? age(last.received_at) : "—") +
    row("Autodiagnostic", last
      ? `${last.selfcheck.worst} · ${last.selfcheck.checks - last.selfcheck.bad}/${last.selfcheck.checks}`
      : "—") +
    (detailed && last ? detailedRows(last) : "") +
    `        </div>
`;

  return card(status, `${name} ${headline}`, lede, rows);
}

export type PageView = {
  state: State;
  now: Date;
  /** `?key=` a fost dat ȘI se potrivește cu `SENTINEL_CHECK_SECRET`. */
  detailed: boolean;
  /** Rezultatul lui `stateIsVolatile()`, citit de apelant. */
  volatileState: boolean;
};

export function witnessPage(view: PageView): string {
  const ids = Object.keys(view.state.instances).sort();
  const parts: string[] = [];

  // Primul lucru de pe pagină, fiindcă schimbă înțelesul a tot ce urmează: dacă
  // starea se pierde la publicare, un server care alarmează azi va fi uitat
  // mâine și va apărea ca „niciun semnal încă", adică verde-ish. Nu e ascuns în
  // spatele lui `?key=`: e o defecțiune de configurare, nu o dată despre ce s-a
  // detectat, iar operatorul trebuie să o vadă de pe telefon.
  if (view.volatileState) {
    parts.push(card(
      "bad",
      "Starea se pierde la următoarea publicare",
      "Martorul își scrie starea în directorul aplicației, iar acela se rescrie la " +
      "fiecare publicare. La următoarea, tot ce alarmează acum e uitat: un server " +
      "căzut redevine „niciun semnal încă” și nu mai alertează nimeni. Pune " +
      "SENTINEL_STATE_PATH pe o cale din afara directorului aplicației — de exemplu " +
      "în directorul home, deasupra lui public_html — și repornește aplicația.",
      "",
    ));
  }

  if (ids.length === 0 && view.state.unreadable.length === 0) {
    parts.push(card(
      "unknown",
      "Niciun semnal încă",
      "Nicio instanță nu are cheie configurată, deci martorul nu are pe cine să " +
      "urmărească. Verifică SENTINEL_BEACON_SECRET și SENTINEL_INSTANCE_SECRETS " +
      "în panoul găzduirii.",
      "",
    ));
  }

  for (const id of ids) {
    parts.push(instanceCard(id, view.state.instances[id], view.now, view.detailed));
  }

  // Starea ilizibilă e o a treia situație, nu una dintre celelalte două: nu știm
  // dacă serverul e viu, iar asta se spune.
  for (const id of view.state.unreadable) {
    parts.push(card(
      "unknown",
      `${view.detailed ? id : "O instanță"} — stare necitibilă`,
      "Martorul are un fișier de stare pentru instanța asta, dar nu îl poate citi. " +
      "Nu se poate spune nici că e vie, nici că a tăcut. Verifică serverul direct " +
      "și, dacă e în regulă, șterge fișierul de stare al instanței — următorul " +
      "semnal îl scrie la loc.",
      "",
    ));
  }

  return `<!doctype html>
<html lang="ro">
<head>
${CSP_META_TAG}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Martor Sentinel</title>
<link rel="stylesheet" href="/martor.css">
</head>
<body>
  <main class="stack">
    <h1 class="eyebrow">Martor extern · în afara serverului monitorizat</h1>
${parts.join("")}    <p class="note">
      Pagina asta rulează pe altă mașină decât serverele monitorizate. Dacă
      cineva oprește Sentinel pe unul dintre ele, semnalul lui dispare și
      martorul alertează pe Telegram — de aici, nu de pe serverul oprit.
    </p>
  </main>
</body>
</html>
`;
}
