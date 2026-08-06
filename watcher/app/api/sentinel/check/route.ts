/**
 * Întreabă „a tăcut prea mult?" și alertează dacă da.
 *
 * Ruta asta există fiindcă o rută API se execută doar când primește o cerere,
 * iar un martor care rulează doar la cerere nu poate observa o ABSENȚĂ. Cineva
 * trebuie să întrebe periodic. Cine anume — cron pe găzduire, sau un monitor
 * extern care lovește /status — e o decizie de instalare, nu de cod.
 *
 * Protejată cu un secret propriu, diferit de cel al semnalului: altfel oricine
 * o poate declanșa, iar cine o declanșează poate consuma starea de „am alertat
 * deja" și te poate lăsa fără a doua alertă.
 */

import { NextResponse } from "next/server";
import { read, write } from "@/lib/store";
import { judge } from "@/lib/verify";
import { alert } from "@/lib/telegram";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

// După cât timp se repetă o alertă care persistă. Patru ore: destul cât să nu
// devină zgomot, destul de des cât să nu uiți că serverul e încă jos.
const REALERT_MS = 4 * 60 * 60 * 1000;

export async function GET(req: Request) {
  const expected = process.env.SENTINEL_CHECK_SECRET;
  const given = new URL(req.url).searchParams.get("key")
    || req.headers.get("x-sentinel-check-key");
  if (!expected || given !== expected) {
    return NextResponse.json({ error: "refuzat" }, { status: 401, headers: NO_STORE });
  }

  const state = await read();
  const now = new Date();
  const verdict = judge(state, now);

  if (verdict.kind === null) {
    // Dacă tocmai ne-am întors dintr-o alertă, spunem și asta. O alertă care nu
    // se închide niciodată lasă operatorul să se întrebe dacă s-a rezolvat.
    if (state.alerted) {
      await alert(
        `✅ <b>Sentinel a revenit</b>\n\n` +
        `Semnalul a reînceput. Problema anterioară: ${state.alerted.kind}, ` +
        `semnalată la ${state.alerted.at}.`,
      );
      await write({ ...state, alerted: undefined });
    }
    return NextResponse.json(
      { ok: true, last_seq: state.last?.seq ?? null, last_seen: state.last?.received_at ?? null },
      { headers: NO_STORE },
    );
  }

  const already = state.alerted?.kind === verdict.kind
    && now.getTime() - new Date(state.alerted.at).getTime() < REALERT_MS;

  if (!already) {
    const icon = verdict.severity === "critical" ? "🔴" : "🟡";
    const sent = await alert(
      `${icon} <b>Sentinel — ${verdict.kind}</b>\n\n${verdict.message}\n\n` +
      (state.last
        ? `<i>Ultimul semnal: seq ${state.last.seq}, ${state.last.received_at}. ` +
          `Incidente deschise: ${state.last.incidents_open}. ` +
          `Blocate: ${state.last.blocklist_size}.</i>`
        : `<i>Niciun semnal primit vreodată.</i>`),
    );
    // Marcăm ca alertat doar dacă chiar a plecat. Altfel o cădere temporară a
    // API-ului Telegram ar consuma singura alertă.
    if (sent) {
      await write({ ...state, alerted: { kind: verdict.kind, at: now.toISOString() } });
    }
  }

  return NextResponse.json(
    { ok: false, kind: verdict.kind, severity: verdict.severity, alerted: !already },
    { headers: NO_STORE },
  );
}
