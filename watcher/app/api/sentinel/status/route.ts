/**
 * Starea, ca număr de răspuns HTTP.
 *
 * 200 când semnalul e proaspăt, 503 când nu. Asta o face utilizabilă de orice
 * monitor de uptime — inclusiv unul gratuit — fără să scriem noi alertarea.
 *
 * E plasa de siguranță pentru cazul în care găzduirea nu are cron: monitorul
 * întreabă, iar propria lui alertare devine escaladarea noastră.
 *
 * Nu cere autentificare și nu expune nimic: doar dacă e viu și de când. Un
 * atacator care o interoghează află că e monitorizat, ceea ce oricum
 * presupunea.
 */

import { NextResponse } from "next/server";
import { read } from "@/lib/store";
import { judge } from "@/lib/verify";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export async function GET() {
  const state = await read();
  const verdict = judge(state, new Date());
  const ok = verdict.kind === null;
  return NextResponse.json(
    {
      status: ok ? "ok" : verdict.kind,
      last_seen: state.last?.received_at ?? null,
      age_s: state.last
        ? Math.round((Date.now() - new Date(state.last.received_at).getTime()) / 1000)
        : null,
    },
    { status: ok ? 200 : 503, headers: { "Cache-Control": "no-store, no-cache, must-revalidate" } },
  );
}
