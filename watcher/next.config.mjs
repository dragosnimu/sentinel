/**
 * Configurația martorului.
 *
 * `output: "standalone"` NU e activat implicit. Produce un pachet care rulează
 * cu `node server.js` fără npm install, ceea ce e util pe unele găzduiri — dar
 * validatorul de proiect al altora se uită la config și respinge structura ca
 * fiind nestandard. Pornirea obișnuită, `npm run build && npm start`, merge
 * peste tot.
 *
 * Dacă ai nevoie de pachetul autonom, decomentează linia și rulează build-ul;
 * README-ul explică ce se copiază.
 */
const nextConfig = {
  // output: "standalone",
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
