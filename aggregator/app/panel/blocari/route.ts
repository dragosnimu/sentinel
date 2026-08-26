/**
 * `GET /panel/blocari` - blocarile, doar citire.
 *
 * Poarta lui `/blocklist` din panoul serverului monitorizat. Comenzile de acolo nu se
 * porteaza: agregatorul e o replica, iar canalul de comanda ramane Telegram.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listBlocks } from "@/lib/data/blocklist";
import { blocklistPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/blocari", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/blocari");
    return htmlResponse(blocklistPage({
      ...chrome,
      blocks: chrome.selected === null ? [] : await listBlocks(
        db, auth.who.allowedInstanceIds, chrome.selected),
    }));
  });
}
