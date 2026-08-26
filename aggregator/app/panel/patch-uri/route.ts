/**
 * `GET /panel/patch-uri` - patch-urile, doar citire.
 *
 * Poarta lui `/patches` din panoul serverului monitorizat. Comenzile de acolo nu se
 * porteaza: agregatorul e o replica, iar canalul de comanda ramane Telegram.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listPlans } from "@/lib/data/patch-plans";
import { patchPlansPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/patch-uri", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/patch-uri");
    return htmlResponse(patchPlansPage({
      ...chrome,
      plans: chrome.selected === null ? [] : await listPlans(
        db, auth.who.allowedInstanceIds, chrome.selected),
    }));
  });
}
