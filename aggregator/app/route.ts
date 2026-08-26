/**
 * Rădăcina domeniului: pagina martorului.
 *
 * Stă la `/` fiindcă acolo a stat mereu: agregatorul se publică pe CHIAR
 * domeniul pe care îl are azi martorul. Dacă pagina s-ar fi mutat sub un prefix,
 * singura suprafață pe care operatorul o deschide de pe telefon ar fi devenit un
 * 404, iar un 404 nu se deosebește de „aplicația e căzută".
 *
 * ## De ce un Route Handler și nu `app/page.tsx`
 *
 * Argumentul întreg e în `lib/witness-page.ts`: politica de conținut a
 * agregatorului n-are `unsafe-inline`, iar o pagină Next randată pe server emite
 * șase elemente de script INLINE. Aici HTML-ul e un șir, deci nu există niciunul.
 *
 * Al doilea motiv, la fel de practic: un Route Handler se cheamă ca funcție
 * dintr-un test și întoarce un `Response` REAL, cu antetele lui. Antetele sunt
 * jumătate din ce livrează pagina asta — politica, `no-store` — iar o componentă
 * randată ar cere un server pornit ca să se poată afirma ceva despre ele. Același
 * raționament ca la `lib/auth/render.ts`.
 *
 * ## `?key=` deschide contoarele, și nimic altceva
 *
 * Cheia e `SENTINEL_CHECK_SECRET`, aceeași cu a lui `/api/sentinel/check`.
 * Comparația cere ca variabila să fie SETATĂ: fără condiția aia, pe o instalare
 * neterminată `?key=` gol s-ar fi comparat cu `undefined` și ar fi deschis
 * contoarele oricui.
 */

import { readAll, stateIsVolatile } from "@/lib/store";
import { witnessPage } from "@/lib/witness-page";
import { htmlResponse } from "@/lib/auth/http";

// Citește stare care se schimbă la fiecare minut. Randată static, ar arăta
// pentru totdeauna momentul în care a fost construită aplicația.
export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET(req: Request): Promise<Response> {
  const key = new URL(req.url).searchParams.get("key");
  const expected = process.env.SENTINEL_CHECK_SECRET;
  const detailed = Boolean(key && expected && key === expected);

  const state = await readAll();
  return htmlResponse(witnessPage({
    state,
    now: new Date(),
    detailed,
    // Se citește AICI și se dă mai departe, nu în pagină: pagina nu are voie să
    // atingă discul, iar `/api/sentinel/status` pune același rezultat în corpul
    // lui. Două suprafețe care citesc aceeași funcție nu se pot contrazice.
    volatileState: stateIsVolatile(),
  }));
}
