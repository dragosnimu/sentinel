/**
 * Configurația agregatorului.
 *
 * Configurația unei singure aplicații: panoul, ingestia de loturi și martorul.
 * Forma vine de la martor, care avea până pe 18 august 2026 fișierul lui —
 * `no-store` pe tot, fără antet de framework.
 *
 * Antetul de `no-store` e pus AICI, global, deși fiecare rută îl scrie și
 * singură. Nu e o dublare inutilă — sunt două mecanisme pentru două eșecuri
 * diferite: ruta îl scrie ca să nu depindă de configurație, configurația îl
 * scrie ca o rută viitoare care uită să-l pună să nu ajungă tăcut în cache-ul
 * CDN-ului. Pe un panou autentificat (E3), o pagină din cache e un bug de
 * CONFIDENȚIALITATE; pe ruta de ingestie, un răspuns din cache e un ecou vechi
 * peste un filigran nou, adică rânduri pierdute.
 *
 * `output: "standalone"` rămâne comentat: produce un pachet care
 * rulează fără `npm install`, dar validatorul de proiect al unor găzduiri
 * respinge structura ca nestandard.
 */
/**
 * Politica de securitate a conținutului. `default-src 'none'` și de acolo în sus
 * doar ce se poate arăta că e chiar folosit.
 *
 * Panoul e randat pe server ca ȘIRURI, nu ca pagini Next, tocmai ca să nu aibă
 * nevoie de `unsafe-inline` — Next emite șase `<script>` inline chiar și pentru
 * o pagină pur server-side, iar un nonce servit prin CDN are un mod de eșec
 * propriu: o pagină din cache poartă un nonce expirat, pagina se strică, și
 * cineva „repară" adăugând `unsafe-inline`. Munca aia era deja făcută; până pe
 * 21 august 2026 lipsea doar antetul care o valorifică, iar singurul CSP care
 * ajungea la browser era un `upgrade-insecure-requests` pus de găzduire, care nu
 * restrânge nicio sursă de script.
 *
 * Măsurat înainte de a fi scris, nu presupus: în `lib/` și `app/` nu există
 * niciun `<script>`, niciun `<style>`, niciun `onclick` și nicio origine
 * externă. Singurele resurse sunt `/panel.css` și `/martor.css`, ambele de pe
 * aceeași origine — de unde `style-src 'self'` și nimic altceva.
 *
 * `form-action 'self'` contează în mod deosebit aici: fără el, o injecție care
 * ar reuși să pună un `<form>` în pagină ar putea trimite sesiunea sau
 * credențialele către alt server.
 */
const CSP = [
  "default-src 'none'",
  "style-src 'self'",
  "img-src 'self'",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

/**
 * Un an, cu subdomenii, FĂRĂ `preload`.
 *
 * `preload` e o listă din care ieșirea durează luni și nu depinde de noi; e o
 * promisiune pentru tot domeniul, luată de pe un subdomeniu. Restul e simplu:
 * agregatorul e deja numai HTTPS, iar fără HSTS prima cerere a unei sesiuni noi
 * poate fi interceptată pe drum.
 */
const HSTS = "max-age=31536000; includeSubDomains";

const nextConfig = {
  // output: "standalone",
  // Nu expunem versiunea framework-ului. Un antet care spune ce rulezi e un
  // cadou gratuit pentru cine face recunoaștere.
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, no-cache, must-revalidate, max-age=0" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Content-Security-Policy", value: CSP },
          { key: "Strict-Transport-Security", value: HSTS },
        ],
      },
    ];
  },
};

export default nextConfig;
