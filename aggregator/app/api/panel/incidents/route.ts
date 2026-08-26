/**
 * `GET /api/panel/incidents` — incidentele instanțelor pe care contul le vede.
 *
 *     ?limit=<n>   cel mult `MAX_PAGE`; ce e mai mare se strânge, nu se refuză
 *
 * Filtrul nu e aici și nu are cum să fie aici: `listIncidents` cere domeniul ca
 * al doilea parametru și îl pune în `WHERE instance_id IN (…)`. Un filtru
 * aplicat DUPĂ interogare — în rută sau, mai rău, într-o componentă — ar
 * însemna că rândurile celuilalt server au fost deja citite din bază și au
 * trecut prin proces; de acolo până la un răspuns care le conține e o singură
 * scăpare de refactor.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { jsonResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { listIncidents } from "@/lib/data/incidents";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /api/panel/incidents", async () => {
    const auth = await requirePanelUser(req, db);
    if (!auth.ok) return auth.response;

    // `Number("")` e 0 și `Number(null)` tot 0, iar 0 ar fi „nicio linie".
    // `listIncidents` respinge orice nu e întreg pozitiv și cade pe implicit,
    // deci ce se dă mai jos e valoarea citită, nu una reparată aici.
    const asked = new URL(req.url).searchParams.get("limit");
    const limit = asked === null ? undefined : Number(asked);

    return jsonResponse({
      incidents: await listIncidents(db, auth.who.allowedInstanceIds, { limit }),
    });
  }, "json");
}
