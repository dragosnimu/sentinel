/**
 * `GET /panel/rapoarte` — rapoartele, doar citire.
 *
 * Poarta lui `/reports` din panoul serverului monitorizat. Pana pe 21 august
 * 2026 pagina spunea ca fluxul care o alimenteaza n-a sosit niciodata, si era
 * adevarat: `event_rollup_1h` se calcula pe server la fiecare rulare de
 * mentenanta si nu pleca nicaieri. Acum curge.
 *
 * Ce nu are corespondent aici, si nici nu va avea: drill-down-ul liber pe
 * evenimente. `raw_events` nu pleaca in bloc de pe gazda — e granita de date,
 * nu o lipsa.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { reportsPage } from "@/lib/panel-page";
import { listHours } from "@/lib/data/rollups";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/rapoarte", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/rapoarte");
    return htmlResponse(reportsPage({
      ...chrome,
      // `selected === null` inseamna „nicio instanta vizibila", nu „toate": un
      // domeniu gol nu se largeste niciodata intr-unul plin.
      hours: chrome.selected === null ? [] : await listHours(
        db, auth.who.allowedInstanceIds, chrome.selected),
    }));
  });
}
