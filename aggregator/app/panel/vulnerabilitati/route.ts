/**
 * `GET /panel/vulnerabilitati` — constatările scanerelor, doar citire.
 *
 * Poarta lui `/findings` din panoul serverului monitorizat.
 *
 * ## Grupa vine din URL, și e validată aici
 *
 * `?grupa=` e ales de client. Trecut mai departe ca șir, ar ajunge într-un
 * `IN (...)` construit din el; validat aici cu `isGroup`, ce ajunge la stratul
 * de date e o cheie a unui vocabular închis, iar lista de stări se ia din
 * declarație. O grupă necunoscută nu e o eroare: se ignoră și se arată tot,
 * fiindcă o legătură veche către o grupă redenumită trebuie să ducă la pagină,
 * nu la un ecran mort.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { countByGroup, listFindings } from "@/lib/data/findings";
import { isGroup } from "@/lib/finding-groups";
import { scanHealth } from "@/lib/data/scans";
import { findingsPage } from "@/lib/panel-page";

export const dynamic = "force-dynamic";
export const revalidate = 0;
export const runtime = "nodejs";

export async function GET(req: Request): Promise<Response> {
  const built = authContext(req);
  if (!built.ok) return built.response;
  const { db } = built.context;

  return await guarded("GET /panel/vulnerabilitati", async () => {
    const auth = await requirePanelUser(req, db, "redirect");
    if (!auth.ok) return auth.response;

    const chrome = await buildChrome(req, db, auth.who, "/panel/vulnerabilitati");
    const cerut = new URL(req.url).searchParams.get("grupa");
    const group = isGroup(cerut) ? cerut : undefined;
    const scope = auth.who.allowedInstanceIds;
    const only = chrome.selected;

    return htmlResponse(findingsPage({
      ...chrome,
      group: group ?? null,
      // Starea scanarii care a produs cifrele: cand a masurat, si daca ultima
      // incercare a esuat. Fara ea, pagina arata un numar fara varsta.
      scan: only === null
        ? { lastGood: null, latest: null }
        : await scanHealth(db, scope, only),
      counts: only === null
        ? { neaplicate: 0, rezolvate: 0, inchise: 0, total: 0 }
        : await countByGroup(db, scope, only),
      findings: only === null ? [] : await listFindings(db, scope, only, { group }),
    }));
  });
}
