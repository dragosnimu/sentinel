/**
 * `GET /api/panel/incidents/<id>` — un incident, cu cronologia lui.
 *
 * ## 404, niciodată 403 — și identic la octet
 *
 * Un cont cu drept pe instanța A care cere un incident al instanței B primește
 * EXACT răspunsul pe care l-ar primi pentru un id care nu există nicăieri:
 * același cod, același corp, aceleași antete. Un 403 ar fi confirmat că
 * incidentul există; iar un 404 cu alt text — „nu ai acces" undeva într-un
 * mesaj — ar fi același oracol, doar mai discret. Cine cere id-uri la rând ar
 * afla astfel câte incidente are celălalt server și când apar, fără să vadă
 * niciun rând.
 *
 * Egalitatea nu e ținută de disciplină, ci de structură: `incidentById`
 * întoarce `null` în amândouă cazurile fiindcă filtrul e ÎN `WHERE`, iar ruta
 * are un singur `notFound()`. Nu există în fișierul ăsta o ramură care să știe
 * că incidentul există pe altă instanță — deci nu există nici ce s-o scape.
 * `tests/panel-authz.test.ts` compară cele două răspunsuri pe OCTEȚI, nu pe
 * formă.
 *
 * Un id malformat (`abc`, `0`, `-3`, `9e99`) primește tot 404, nu 400: un 400
 * ar deosebi „id nevalid" de „id valid, dar nu al tău", iar mulțimea id-urilor
 * valide e chiar informația care se apără.
 *
 * ## Cronologia e MĂRGINITĂ, iar tăierea se spune
 *
 * `incidentTimeline` citește cel mult `MAX_TIMELINE` rânduri, iar răspunsul
 * poartă `timelineTruncated`. Un incident de forță brută are cronologia cât
 * detecțiile lui; fără plafon, o singură cerere autentificată ar materializa
 * zeci de mii de rânduri în memoria procesului de pe găzduire. Fanionul pleacă
 * și când e fals, ca panoul să nu poată afișa tăcut o listă din care lipsește
 * sfârșitul.
 *
 * Azi însă `timeline` e ÎNTOTDEAUNA gol pe gazdă, și nu fiindcă s-ar fi stricat
 * ceva: `incident_timeline_entries` n-are niciun flux care s-o umple — vezi
 * secțiunea din capul lui `lib/data/incidents.ts`. Incidentul în schimb e real,
 * fluxul lui există. Cine se uită la un panou cu cronologia goală caută defectul
 * unde nu e.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { jsonResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { incidentById, incidentTimeline } from "@/lib/data/incidents";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

/** Singurul răspuns „nu există" al rutei. Un al doilea ar fi un al doilea corp. */
function notFound(): Response {
  return jsonResponse({ error: "not_found" }, { status: 404 });
}

export async function GET(
  req: Request, context: { params: Promise<{ id: string }> },
): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /api/panel/incidents/<id>", async () => {
    const auth = await requirePanelUser(req, db);
    if (!auth.ok) return auth.response;

    const { id } = await context.params;
    // `Number("")` e 0 și `Number(" 12 ")` e 12; `incidentById` cere un întreg
    // pozitiv și refuză restul, deci conversia de aici n-are voie să repare
    // nimic — doar să treacă valoarea mai departe.
    const incident = await incidentById(db, auth.who.allowedInstanceIds, Number(id));
    if (incident === null) return notFound();

    const timeline = await incidentTimeline(db, auth.who.allowedInstanceIds, {
      instanceId: incident.instanceId, sourceId: incident.sourceId,
    });
    // `timelineTruncated` pleacă și când e fals, dinadins: un câmp care apare
    // doar la tăiere e un câmp pe care panoul îl uită, iar atunci o cronologie
    // tăiată arată exact ca una întreagă. Vezi `MAX_TIMELINE`.
    return jsonResponse({ incident, timeline: timeline.entries,
                          timelineTruncated: timeline.truncated });
  }, "json");
}
