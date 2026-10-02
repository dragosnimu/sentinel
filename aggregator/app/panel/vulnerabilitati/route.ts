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
 *
 * `?culoare=` urmează aceeași regulă, cu vocabularul `COLORS` (roșu, galben, gri,
 * verde): ajunge în SQL ca parametru, după ce a fost comparat cu lista închisă.
 *
 * Culoarea e a constatărilor NEAPLICATE: serverul nu mai evaluează o constatare
 * rezolvată, deci cererea unei culori restrânge lista la grupa „neaplicate"
 * (peste orice `?grupa=`), și așa se vede pe pagină.
 */

import { authContext, guarded } from "@/lib/auth/context";
import { htmlResponse } from "@/lib/auth/http";
import { requirePanelUser } from "@/lib/auth/panel";
import { buildChrome } from "@/lib/panel-chrome";
import { countByColor, countByGroup, listFindings } from "@/lib/data/findings";
import { isGroup } from "@/lib/finding-groups";
import { COLORS } from "@/lib/finding-risk";
import type { RiskColor } from "@/lib/finding-risk";
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
    const asked = isGroup(cerut) ? cerut : undefined;
    const culoare = new URL(req.url).searchParams.get("culoare");
    const color = (COLORS as readonly string[]).includes(culoare ?? "")
      ? (culoare as RiskColor) : undefined;
    const group = color !== undefined ? "neaplicate" : asked;
    const scope = auth.who.allowedInstanceIds;
    const only = chrome.selected;

    return htmlResponse(findingsPage({
      ...chrome,
      group: group ?? null,
      color: color ?? null,
      colors: only === null
        ? { red: 0, amber: 0, green: 0, grey: 0 }
        : await countByColor(db, scope, only),
      // Starea scanarii care a produs cifrele: cand a masurat, si daca ultima
      // incercare a esuat. Fara ea, pagina arata un numar fara varsta.
      scan: only === null
        ? { lastGood: null, latest: null }
        : await scanHealth(db, scope, only),
      counts: only === null
        ? { neaplicate: 0, rezolvate: 0, inchise: 0, total: 0 }
        : await countByGroup(db, scope, only),
      findings: only === null ? [] : await listFindings(db, scope, only, { group, color }),
    }));
  });
}
