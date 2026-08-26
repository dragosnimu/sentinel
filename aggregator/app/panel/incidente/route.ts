/**
 * `GET /panel/incidente` — incidentele, doar citire.
 *
 * Poartă a lui `/incidents` din panoul serverului monitorizat. Comenzile de acolo nu se
 * portează: agregatorul e o replică, iar canalul de comandă rămâne Telegram.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listIncidents } from "@/lib/data/incidents";
import { incidentsPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/incidente", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/incidente");
    return htmlResponse(incidentsPage({
      ...chrome,
      incidents: chrome.selected === null ? [] : await listIncidents(
        db, auth.who.allowedInstanceIds, { instanceId: chrome.selected }),
    }));
  });
}
