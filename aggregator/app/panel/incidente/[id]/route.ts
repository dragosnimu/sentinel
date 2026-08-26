/**
 * `GET /panel/incidente/<id>` — un incident, cu cronologia lui.
 *
 * ## 404, nu 403, și corpul identic
 *
 * Un incident care există pe o instanță pe care contul n-o vede întoarce EXACT
 * ce întoarce un id care nu există nicăieri. Un 403 ar confirma existența, iar
 * confirmarea aia e chiar informația pe care autorizarea o apără: cine numără
 * id-urile ar afla câte incidente are celălalt server. `incidentById` întoarce
 * deja `null` pentru amândouă cazurile, fiindcă interogarea nu le poate
 * deosebi — pagina doar nu strică proprietatea.
 *
 * ## De ce cronologia se cere cu `sourceId`, nu cu id-ul din URL
 *
 * Id-ul din URL e al RÂNDULUI din agregator. Cronologia se leagă de incident
 * prin id-ul DE PE SERVER, iar cele două nu coincid niciodată. Se trece deci
 * întâi prin `incidentById` — care e și cel care aplică drepturile — și abia
 * perechea (instanță, `sourceId`) întoarsă de el ajunge la cronologie.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse, textResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { incidentById, incidentTimeline } from "@/lib/data/incidents";
import { incidentPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

/** Textul lui 404, într-un singur loc: două formulări ar fi două răspunsuri
 *  distinse între ele, adică exact ce nu are voie să difere. */
const NU_EXISTA = "Incidentul nu există.";

export async function GET(
  req: Request, context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/incidente/[id]", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const { id: raw } = await context.params;
    // `Number.parseInt` ar accepta „12abc" ca 12, iar atunci două adrese
    // diferite ar duce la același incident. Un id care nu e strict numeric nu e
    // un id, deci e 404 — același 404 ca al unuia inexistent.
    const id = /^[0-9]+$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isSafeInteger(id)) return textResponse(NU_EXISTA, 404);

    const { allowedInstanceIds } = auth.who;
    const incident = await incidentById(db, allowedInstanceIds, id);
    if (incident === null) return textResponse(NU_EXISTA, 404);

    // Antetul se construiește DUPĂ ce incidentul s-a dovedit vizibil: altfel o
    // pagină de 404 ar face două interogări în plus pentru un ecran pe care
    // nimeni nu-l vede, iar cele două refuzuri — inexistent și nepermis — ar
    // putea ajunge să difere prin cât durează.
    const chrome = await buildChrome(req, db, auth.who, "/panel/incidente");

    return htmlResponse(incidentPage({
      ...chrome,
      incident,
      timeline: await incidentTimeline(db, allowedInstanceIds, {
        instanceId: incident.instanceId, sourceId: incident.sourceId,
      }),
    }));
  });
}
