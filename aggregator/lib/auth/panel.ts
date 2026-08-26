/**
 * Cine întreabă, și ce are voie să vadă — pentru rutele de date ale panoului.
 *
 * Un singur loc, fiindcă fiecare rută de panou are nevoie de exact aceiași trei
 * pași, în exact ordinea asta:
 *
 *   1. **sesiunea**, din cookie, prin `sessionByToken` — care e cea care
 *      verifică expirarea și revocarea;
 *   2. **contul**, recitit la fiecare cerere. Nu din sesiune: un cont
 *      dezactivat între două cereri trebuie să piardă accesul la următoarea, nu
 *      la următoarea autentificare. Sesiunile lui trăiesc 12 ore;
 *   3. **drepturile**, tot la fiecare cerere, din `user_instances`. Un drept
 *      retras trebuie să dispară la fel de repede. Copiate în sesiune la
 *      autentificare, ar fi rămas valabile o zi de lucru după ce operatorul a
 *      crezut că le-a luat.
 *
 * Trei citiri per cerere e prețul, și e scris aici ca să nu fie „optimizat"
 * fără să se știe ce se cumpără cu el: cache-ul de drepturi are ca preț
 * întârzierea cu care se aplică o retragere de drepturi.
 *
 * ## De ce NU e un `middleware.ts`
 *
 * În Next.js apărarea unui panou ajunge de obicei în `middleware.ts`, la
 * rădăcina proiectului. Aici nu, din două motive care se adună:
 *
 *   * un middleware decide pe CALE (`/api/panel/*`), iar o rută nouă pusă în
 *     altă parte scapă tăcut. Verificarea în handler nu poate fi uitată de
 *     jumătate: fără ea nu există `allowedInstanceIds`, iar fără domeniu nicio
 *     funcție de acces la date nu compilează;
 *   * middleware-ul rulează pe runtime-ul Edge, unde `mysql2` nu există. Ce ar
 *     putea verifica acolo e forma cookie-ului, nu existența sesiunii — adică
 *     o poartă care lasă să treacă un cookie inventat, cu aparența unei porți.
 *
 * ## `pending_totp` e un refuz, nu o jumătate de acces
 *
 * O sesiune care a trecut doar de parolă ajunge la `/totp` și nicăieri
 * altundeva. Aici e tratată exact ca lipsa unei sesiuni; altfel al doilea
 * factor ar fi ocolibil cerând direct datele.
 */

import {
  SESSION_COOKIE, jsonResponse, readCookie, redirectResponse,
} from "./http";
import { findById } from "./users";
import { scopeForUser } from "./scope";
import { sessionByToken } from "./session";
import type { AuthDb } from "./db";
import type { AuthUser } from "./users";
import type { InstanceScope } from "./scope";
import type { Session } from "./session";

export type PanelUser = {
  session: Session;
  user: AuthUser;
  /** Instanțele pe care le vede contul. Se dă mai departe, explicit, fiecărei
   *  funcții de acces la date. */
  allowedInstanceIds: InstanceScope;
};

export type PanelAuth =
  | { ok: true; who: PanelUser }
  | { ok: false; response: Response };

/**
 * Un singur text pentru „fără cookie", „sesiune expirată", „cont dezactivat" și
 * „al doilea factor nedat".
 *
 * Ca `BAD_CREDENTIALS` din `lib/auth/login.ts`, și din același motiv: fiecare
 * diferență dintre ele e o informație despre ce există, dată cuiva care n-a
 * dovedit că are voie s-o afle.
 */
const UNAUTHENTICATED = { error: "unauthenticated" };

/**
 * Forma refuzului, aleasă de cel care cheamă.
 *
 * `json` e pentru rutele de date: un client care așteaptă JSON și primește o
 * redirectare n-are cum să deosebească „sesiune expirată" de un răspuns stricat.
 * `redirect` e pentru PAGINI, unde cel care citește e un om cu un browser, iar
 * un 401 cu corp JSON e un ecran gol fără nicio cale înainte.
 *
 * Implicitul rămâne `json`, ca rutele scrise înainte de 19 august 2026 să nu-și
 * schimbe purtarea fiindcă s-a adăugat o pagină.
 */
export type Refusal = "json" | "redirect";

export async function requirePanelUser(
  req: Request, db: AuthDb, refusal: Refusal = "json",
): Promise<PanelAuth> {
  const refuse = (): PanelAuth => ({
    ok: false,
    response: refusal === "redirect"
      ? redirectResponse("/login?e=expired")
      : jsonResponse(UNAUTHENTICATED, { status: 401 }),
  });

  const token = readCookie(req, SESSION_COOKIE);
  if (!token) return refuse();

  const session = await sessionByToken(db, token);
  if (session === null || session.pendingTotp) return refuse();

  const user = await findById(db, session.userId);
  if (user === null || user.disabled) return refuse();

  return {
    ok: true,
    who: { session, user, allowedInstanceIds: await scopeForUser(db, user.id) },
  };
}
