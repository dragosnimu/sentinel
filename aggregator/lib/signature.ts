/**
 * Verificarea semnăturii unui lot.
 *
 * ## A DOUA verificare de semnătură din aceeași aplicație — și de ce încă e
 *
 * Fișierul ăsta a fost copiat din `watcher/lib/verify.ts` pe vremea când
 * martorul era o aplicație separată, cu argumentul că el n-are voie să depindă
 * de una mult mai mare. **Argumentul acela a murit pe 18 august 2026**, odată cu
 * mutarea martorului aici: sunt un singur proiect, publicat o dată, iar două
 * implementări ale aceleiași verificări în același proiect sunt exact perechea
 * care poate să nu fie de acord.
 *
 * Nu s-au contopit, și motivul e că NU sunt aceeași funcție:
 *
 *   * aici corpul e `Buffer` — HMAC peste octeții primiți, oricare ar fi ei;
 *   * în `lib/verify.ts` corpul e `string` — HMAC peste UTF-8-ul rezultat din
 *     decodarea lor, fiindcă ruta de heartbeat decodează întâi (vezi `asText`
 *     din `app/api/sentinel/beat/route.ts` și nota lui despre BOM).
 *
 * Pe un corp care e UTF-8 valid cele două dau același rezultat. Pe unul care nu
 * e, NU: cel de aici verifică octeții trimiși, celălalt verifică U+FFFD-urile.
 * Contopirea lor schimbă deci ce ACCEPTĂ una dintre rute, pe o cale de
 * autentificare — nu e o curățenie, e o decizie, și e a operatorului. Până
 * atunci, faptul că sunt două se scrie aici, nu se ascunde într-un „copiat
 * dinadins" care nu mai e adevărat.
 *
 * ## Ce NU e aici, și de ce contează
 *
 * `canonical()`. Ruta de loturi **nu** recalculează forma canonică a
 * payload-ului: semnătura se verifică peste OCTEȚII BRUȚI ai corpului, exact ca
 * la `app/api/sentinel/beat/route.ts`. Două consecințe, amândouă dorite:
 *
 *   * adăugarea unui câmp în payload nu strică verificarea, deci cele două
 *     capete nu trebuie actualizate în lockstep;
 *   * nu apare o A TREIA implementare a formei canonice, de ținut în acord cu
 *     celelalte două. `sentinel/report/signing.py` argumentează pe o pagină că
 *     acordul dintre două serializatoare ține până când adaugă cineva un câmp;
 *     un al treilea ar fi aceeași pariere, cu șanse mai mici.
 *
 * Ce se pierde: ruta de loturi nu poate verifica dacă payload-ul RESPECTĂ
 * contractul de semnare (chei ASCII, fără float). Nu are nevoie: contractul
 * există ca cele două capete să producă aceiași octeți, iar aici octeții sosesc
 * gata făcuți. Ce contează pentru bază — tipuri, lungimi, forma timpilor — se
 * verifică în `lib/ingest.ts`, pe valori, nu pe reprezentare.
 */

import crypto from "node:crypto";

/** Numele antetului, minuscule: `Headers.get` e insensibil la majuscule, dar
 *  constanta se compară și cu alte locuri, iar acolo nu e. */
export const SIGNATURE_HEADER = "x-sentinel-signature";

/**
 * `true` doar dacă HMAC-SHA256 peste octeții primiți dă exact semnătura primită.
 *
 * Corpul e `Buffer`, NU `string`: `req.text()` decodează UTF-8, iar un corp care
 * nu e UTF-8 valid ar trece prin U+FFFD și ar produce alți octeți decât cei
 * trimiși. Diferența nu schimbă verdictul (o semnătură validă e peste octeți
 * valizi), dar face verificarea să fie chiar ce spune că e.
 *
 * Comparație în timp constant: una obișnuită scurge lungimea prefixului comun.
 */
export function signatureValid(body: Buffer, signature: string, secret: string): boolean {
  const expected = crypto.createHmac("sha256", secret).update(body).digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(signature || "", "utf8");
  // `timingSafeEqual` ARUNCĂ pe lungimi diferite, deci verificarea de lungime nu
  // e o optimizare: fără ea, o semnătură scurtă ar fi o excepție, adică un 500
  // acolo unde trebuie să fie un 401.
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
