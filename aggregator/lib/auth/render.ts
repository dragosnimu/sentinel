/**
 * Paginile de autentificare, randate pe server. HTML, nu React.
 *
 * ## De ce un șir de HTML și nu o componentă
 *
 * Aplicația n-are încă niciun `app/layout.tsx` și niciun `page.tsx` — panoul
 * propriu-zis e piesa 3. Ce cer rutele astea acum e o pagină cu un formular și
 * ZERO JavaScript, iar diferența nu e de stil:
 *
 *   * un Route Handler se poate chema ca funcție dintr-un test și întoarce un
 *     `Response` REAL, cu antetele lui. Antetele — CSP, `no-store`, `Set-Cookie`
 *     — sunt jumătate din ce livrează piesa asta, iar planul cere să fie citite
 *     dintr-un răspuns, nu dintr-o configurație. O componentă randată ar cere
 *     un server pornit ca să se poată afirma ceva despre ele;
 *   * React în pagină ar aduce un bundle de client, adică `<script src=…>`.
 *     Politica de conținut (`lib/auth/http.ts`) n-are `unsafe-inline`, iar
 *     bootstrap-ul lui Next pune date inline. Alternativa e un nonce, adică
 *     exact modul de eșec descris în plan: o pagină din cache poartă un nonce
 *     expirat, pagina se strică, și cineva „repară" adăugând `unsafe-inline`.
 *
 * Deci: text, escapat, fără niciun `<script>` și fără niciun `style=`. Ce se
 * pierde e aspectul — paginile sunt HTML gol, fără foaie de stil. E o alegere
 * conștientă pentru DOUĂ pagini care se văd o dată pe zi, nu un tipar pentru
 * panou: piesa 3 poate servi o foaie de stil de la aceeași origine
 * (`style-src 'self'`) fără să atingă politica.
 *
 * ## Escaparea
 *
 * Tot ce vine din cerere trece prin `escapeHtml`. Singura valoare din cerere
 * care ajunge în pagină e numele de utilizator (reafișat ca să nu-l retasteze
 * cineva după o greșeală de parolă), dar regula e scrisă pentru câmpul următor,
 * nu pentru ăsta.
 */

import { CSP_META_TAG } from "../csp";

const ESCAPES: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
};

/**
 * Textul, în siguranță în HTML.
 *
 * `&` se înlocuiește PRIMUL prin însăși ordinea din clasa de caractere — dacă
 * s-ar face separat, la urmă, ar re-escapa entitățile produse de ceilalți și ar
 * afișa `&amp;lt;`. Ghilimelele simple sunt și ele acolo fiindcă un atribut
 * scris cu ele e o greșeală ușor de făcut mai târziu.
 */
export function escapeHtml(value: string): string {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ESCAPES[ch]);
}

function page(title: string, body: string): string {
  return "<!doctype html>\n" +
    '<html lang="ro">\n<head>\n' +
    // PRIMUL in <head>: guverneaza tot ce urmeaza dupa el.
    CSP_META_TAG +
    '<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    // Panoul nu are ce căuta într-un index, iar un rezultat de căutare care duce
    // la un formular de autentificare e o invitație la scanare.
    '<meta name="robots" content="noindex, nofollow">\n' +
    `<title>${escapeHtml(title)}</title>\n` +
    // ACEEAȘI foaie ca panoul, nu una a ei. Pagina asta n-avea niciuna:
    // fundal alb de browser, câmpuri nestilizate — prima impresie despre un
    // panou de securitate era că nu seamănă cu el însuși. O foaie separată
    // ar fi fost două locuri în care se scriu aceleași culori, iar tema
    // întunecată s-ar fi despărțit de a panoului la prima schimbare.
    '<link rel="stylesheet" href="/panel.css">\n' +
    "</head>\n<body class=\"poarta\">\n" + body + "</body>\n</html>\n";
}

function errorBlock(error: string | null | undefined): string {
  if (!error) return "";
  // `role="alert"` ca un cititor de ecran să anunțe mesajul: pe pagina asta,
  // mesajul e singurul lucru care s-a schimbat după un POST.
  return `<p role="alert"><strong>${escapeHtml(error)}</strong></p>\n`;
}

export type LoginPage = {
  csrfToken: string;
  error?: string | null;
  username?: string;
};

export function loginPage(view: LoginPage): string {
  return page("Autentificare — Sentinel", [
    '<main class=\"carte\">\n',
    "<h1>Sentinel — agregator</h1>\n",
    errorBlock(view.error),
    '<form method="post" action="/login">\n',
    `<input type="hidden" name="csrf_token" value="${escapeHtml(view.csrfToken)}">\n`,
    '<p><label for="username">Utilizator</label><br>\n',
    '<input id="username" name="username" type="text" maxlength="64" ' +
    'autocomplete="username" autocapitalize="off" autocorrect="off" required ' +
    `value="${escapeHtml(view.username ?? "")}"></p>\n`,
    '<p><label for="password">Parolă</label><br>\n',
    // `maxlength` e o comoditate pentru cine tastează, NU o apărare: ce
    // mărginește cu adevărat câmpul e plafonul de octeți din `lib/auth/http.ts`,
    // fiindcă un client care nu e un browser nu citește atributul ăsta.
    '<input id="password" name="password" type="password" maxlength="1024" ' +
    'autocomplete="current-password" required></p>\n',
    '<p><button type="submit">Intră</button></p>\n',
    "</form>\n",
      "</main>\n",
  ].join(""));
}

export type TotpPage = {
  csrfToken: string;
  username: string;
  error?: string | null;
};

export function totpPage(view: TotpPage): string {
  return page("Al doilea factor — Sentinel", [
    '<main class=\"carte\">\n',
    "<h1>Al doilea factor</h1>\n",
    `<p>Cont: <strong>${escapeHtml(view.username)}</strong></p>\n`,
    errorBlock(view.error),
    '<form method="post" action="/totp">\n',
    `<input type="hidden" name="csrf_token" value="${escapeHtml(view.csrfToken)}">\n`,
    '<p><label for="code">Cod din aplicația de autentificare</label><br>\n',
    // `inputmode="numeric"` și `autocomplete="one-time-code"` sunt ce face
    // telefonul să propună codul singur. Fără JavaScript, astea sunt tot ce se
    // poate face pentru cel care tastează.
    '<input id="code" name="code" type="text" inputmode="numeric" ' +
    'pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" required></p>\n',
    '<p><button type="submit">Confirmă</button></p>\n',
    "</form>\n",
    // Ieșirea dintr-o autentificare pe jumătate făcută. Fără ea, cine a greșit
    // contul așteaptă cinci minute până expiră sesiunea în așteptare.
    '<form method="post" action="/logout">\n',
    `<input type="hidden" name="csrf_token" value="${escapeHtml(view.csrfToken)}">\n`,
    '<p><button type="submit">Renunță</button></p>\n',
    "</form>\n",
      "</main>\n",
  ].join(""));
}
