/**
 * Politica de securitate a conținutului, și felul în care ajunge CHIAR la browser.
 *
 * ## De ce nu e (doar) un antet HTTP
 *
 * Antetul e declarat și în `next.config.mjs`, dar măsurat pe 21 august 2026 el nu
 * ajunge: CDN-ul găzduirii (`Server: hcdn`) îl ÎNLOCUIEȘTE cu al lui,
 * `upgrade-insecure-requests`, care nu restrânge nicio sursă de script. Dovada că
 * nu e o problemă de configurație a aplicației: `Strict-Transport-Security`,
 * declarat în același loc și în același fel, trece — fiindcă platforma nu-l pune
 * pe ăla. Deci nu antetul e greșit; e revendicat de altcineva.
 *
 * Meta-tagul e a doua cale prevăzută de standard, iar pe ea o controlăm noi:
 * paginile sunt randate ca ȘIRURI, deci ce scriem aici ajunge neatins. Pus PRIMUL
 * în `<head>`, guvernează tot ce urmează.
 *
 * ## Ce se pierde pe calea asta, și cine acoperă
 *
 * Într-un meta-tag, `frame-ancestors`, `report-uri` și `sandbox` sunt ignorate
 * prin specificație. Singura care conta e `frame-ancestors`, iar ea e acoperită
 * de `X-Frame-Options: DENY` — antet care CHIAR trece, măsurat. De aceea rămâne
 * în listă doar la antet, nu și aici: o directivă scrisă unde e ignorată e o
 * apărare pe hârtie.
 *
 * ## Ce cuprinde
 *
 * `default-src 'none'` și de acolo în sus doar ce s-a măsurat că e folosit: în
 * `lib/` și `app/` nu există niciun `<script>`, niciun `<style>`, niciun
 * `onclick` și nicio origine externă — singurele resurse sunt `/panel.css` și
 * `/martor.css`, de pe aceeași origine. `tests/security-headers.test.ts` scanează
 * sursele la fiecare rulare și pică dacă cineva adaugă ceva ce politica ar bloca.
 */

/** Directivele care au efect ÎNTR-UN META-TAG. Vezi nota de mai sus. */
export const CSP_META_DIRECTIVES: readonly string[] = [
  "default-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
];

/** Politica pentru meta-tag. */
export const CSP_META = CSP_META_DIRECTIVES.join("; ");

/**
 * Meta-tagul gata de pus în `<head>`, PRIMUL.
 *
 * Fără ghilimele de escapat: valorile sunt literale scrise aici, nu date.
 */
export const CSP_META_TAG =
  `<meta http-equiv="Content-Security-Policy" content="${CSP_META}">
`;
