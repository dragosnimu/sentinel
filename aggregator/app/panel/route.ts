/**
 * `GET /panel` — rezumatul, și pagina în care intri după autentificare.
 *
 * Rădăcina domeniului rămâne a martorului; motivul e în `app/route.ts`. Panoul
 * stă sub `/panel` fiindcă a doua pagină — cea la care te uiți când crezi că
 * serverul a murit — n-are voie să depindă de faptul că te poți autentifica.
 *
 * Refuzul e o REDIRECTARE, nu un 401 cu corp JSON: aici cititorul e un om cu un
 * browser, iar un 401 e un ecran gol fără nicio cale înainte. Vezi `Refusal`.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listIncidents } from "@/lib/data/incidents";
import { summary } from "@/lib/data/overview";
import type { Summary } from "@/lib/data/overview";
import { summaryPage } from "@/lib/panel-page";

/** Rezumatul gol al unui cont care nu vede nicio instanta. */
const EMPTY_SUMMARY: Summary = {
  overview: {
    attackers: { now: 0, before: 0 }, detections: { now: 0, before: 0 },
    events: { now: 0, before: 0 }, incidentsOpen: 0, incidentsSevere: 0,
    findingsOpen: 0, blocksActive: 0, bySeverity: [],
  },
  series: [], rankings: { attackers: [], rules: [], sources: [] },
  activity: [], truncated: [],
};

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel");
    const scope = auth.who.allowedInstanceIds;
    const only = chrome.selected;

    return htmlResponse(summaryPage({
      ...chrome,
      // `selected === null` inseamna „nicio instanta vizibila", nu „toate": un
      // domeniu gol nu se largeste. `summary` intoarce oricum gol pe un domeniu
      // gol; ramura de aici scuteste drumul pana la baza.
      sumar: only === null ? EMPTY_SUMMARY : await summary(db, scope, only),
      incidents: only === null
        ? []
        : await listIncidents(db, scope, { instanceId: only, limit: 10 }),
    }));
  });
}
