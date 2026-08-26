/**
 * `GET /panel/detectii` — detecțiile, doar citire.
 *
 * Poartă a lui `/events` din panoul serverului monitorizat. Comenzile de acolo nu se
 * portează: agregatorul e o replică, iar canalul de comandă rămâne Telegram.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listDetections } from "@/lib/data/detections";
import { detectionsPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/detectii", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/detectii");
    return htmlResponse(detectionsPage({
      ...chrome,
      detections: chrome.selected === null ? [] : await listDetections(
        db, auth.who.allowedInstanceIds, chrome.selected),
    }));
  });
}
