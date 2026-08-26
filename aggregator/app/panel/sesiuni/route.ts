/**
 * `GET /panel/sesiuni` — cine s-a logat pe server, și ce a rulat.
 *
 * Pagină fără corespondent în panoul serverului: acolo istoricul se citește
 * direct din bază, aici e replica lui. Doar citire, ca tot panoul.
 *
 * `?sesiune=<source_id>` deschide comenzile unei sesiuni; `?toate=1` arată și
 * sesiunile de automatizare, care sunt de douăzeci de ori mai multe decât cele
 * de om.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listSessions, sessionDetail } from "@/lib/data/logins";
import { sessionsPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/sesiuni", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/sesiuni");
    const scope = auth.who.allowedInstanceIds;
    const only = chrome.selected;

    const url = new URL(req.url);
    const toate = url.searchParams.get("toate") === "1";
    // `Number.parseInt` și nu `Number`: un `?sesiune=abc` trebuie să dea `NaN`,
    // nu `0`, iar `0` ar fi un identificator care s-ar putea căuta.
    const cerut = Number.parseInt(url.searchParams.get("sesiune") ?? "", 10);

    const detail = (only !== null && Number.isSafeInteger(cerut) && cerut > 0)
      ? await sessionDetail(db, scope, only, cerut)
      : null;

    return htmlResponse(sessionsPage({
      ...chrome,
      sessions: only === null ? [] : await listSessions(db, scope, only,
                                                        { onlyHumans: !toate }),
      detail,
      showingAll: toate,
    }));
  });
}
