/**
 * Configurația martorului.
 *
 * `standalone` produce un director care se poate copia pe găzduire fără
 * `node_modules` — pornește cu `node server.js`. E modul care merge pe cele mai
 * multe planuri de Node hosting, inclusiv cele fără acces la npm pe server.
 */
const nextConfig = {
  output: "standalone",
  // Nu expunem versiunea framework-ului. Un antet care spune ce rulezi e un
  // cadou gratuit pentru cine face recunoaștere.
  poweredByHeader: false,
  reactStrictMode: true,
  async headers() {
    return [
      {
        // Nimic din aplicația asta nu are voie să fie pus în cache. E o singură
        // regulă pentru tot, fiindcă o excepție uitată aici ar face martorul să
        // raporteze la nesfârșit ultima stare bună — exact minciuna pe care
        // există ca să o prevină.
        source: "/:path*",
        headers: [
          { key: "Cache-Control", value: "no-store, no-cache, must-revalidate, max-age=0" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};

export default nextConfig;
