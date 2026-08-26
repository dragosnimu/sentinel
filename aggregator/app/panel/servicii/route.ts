/**
 * `GET /panel/servicii` — autodiagnosticul, doar citire.
 *
 * Poarta lui `/services` din panoul serverului monitorizat. Pagina a fost un
 * substituent până pe 20 august 2026, cu motivul scris pe ea: `selfcheck_state`
 * are cheie text, iar filigranul de pe sârmă trebuia să fie un întreg. Filigranul
 * text a închis blocajul — vezi `migrations/0011_text_watermark.sql`.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { listChecks } from "@/lib/data/selfcheck";
import { servicesPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/servicii", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/servicii");
    return htmlResponse(servicesPage({
      ...chrome,
      checks: chrome.selected === null ? [] : await listChecks(
        db, auth.who.allowedInstanceIds, chrome.selected),
    }));
  });
}
