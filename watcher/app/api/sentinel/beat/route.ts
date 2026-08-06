/**
 * Primește semnalul de la Sentinel.
 *
 * Nu judecă nimic — doar verifică autenticitatea, respinge reluările și
 * înregistrează. Judecata e în /api/sentinel/check, fiindcă întrebarea „a tăcut
 * prea mult?" nu poate fi pusă de o rută care se execută doar când sosește un
 * semnal.
 */

import { NextResponse } from "next/server";
import { read, write, type Beat } from "@/lib/store";
import { SIGNATURE_HEADER, canonical, signatureValid, countersAdvanced } from "@/lib/verify";

// Obligatoriu. Site-ul e servit prin CDN, iar o rută de heartbeat pusă în cache
// ar întoarce vesel ultimul răspuns bun ore în șir — exact minciuna pe care
// mecanismul ăsta există ca să o prevină.
export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

export async function POST(req: Request) {
  const secret = process.env.SENTINEL_BEACON_SECRET;
  if (!secret) {
    console.error("[watcher] SENTINEL_BEACON_SECRET nu e setat");
    return NextResponse.json({ error: "nu sunt configurat" }, { status: 500, headers: NO_STORE });
  }

  // Corpul brut, nu obiectul reparsat: semnătura e peste octeții trimiși, iar o
  // re-serializare poate schimba ordinea cheilor sau formatul numerelor.
  const raw = await req.text();
  const signature = req.headers.get(SIGNATURE_HEADER) || "";
  if (!signatureValid(raw, signature, secret)) {
    // Deliberat sărac în detalii: nu spunem dacă a fost semnătura, formatul sau
    // altceva. Un endpoint care explică de ce a refuzat ajută la ghicit.
    console.warn("[watcher] semnătură invalidă");
    return NextResponse.json({ error: "refuzat" }, { status: 401, headers: NO_STORE });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw);
  } catch {
    return NextResponse.json({ error: "refuzat" }, { status: 400, headers: NO_STORE });
  }

  // Verificarea semnăturii dovedește autenticitatea, nu prospețimea. Fără
  // fereastra asta, un semnal valid capturat o dată poate fi reluat la
  // nesfârșit, iar martorul ar vedea „viu" pe o mașină oprită de o săptămână.
  const sentAt = new Date(String(payload.sent_at || ""));
  const maxAge = Number(payload.max_age_s || 120);
  const age = (Date.now() - sentAt.getTime()) / 1000;
  if (!Number.isFinite(age) || Math.abs(age) > maxAge) {
    console.warn("[watcher] semnal prea vechi sau din viitor", age);
    return NextResponse.json({ error: "refuzat" }, { status: 400, headers: NO_STORE });
  }

  const state = await read();
  const seq = Number(payload.seq || 0);
  if (state.last && seq <= state.last.seq) {
    // Reluare, sau două expeditoare care trimit în paralel. Ambele sunt
    // anormale și niciuna nu are voie să treacă drept semnal proaspăt.
    console.warn("[watcher] seq nu a crescut", seq, state.last.seq);
    return NextResponse.json({ error: "refuzat" }, { status: 409, headers: NO_STORE });
  }

  const beat: Beat = {
    seq,
    sent_at: String(payload.sent_at),
    received_at: new Date().toISOString(),
    last_event_id: Number(payload.last_event_id || 0),
    detect_cursor: Number(payload.detect_cursor || 0),
    incidents_open: Number(payload.incidents_open || 0),
    blocklist_size: Number(payload.blocklist_size || 0),
    audit_head: String(payload.audit_head || ""),
    interval_s: Number(payload.interval_s || 60),
    selfcheck: (payload.selfcheck as Beat["selfcheck"]) || {
      worst: "unknown", checks: 0, bad: 0, ran_at: null,
    },
  };

  await write({
    ...state,
    last: beat,
    // Momentul în care contoarele s-au mișcat ultima dată, nu cel în care a
    // sosit ultimul semnal. Diferența dintre ele E detecția de conductă moartă.
    counters_moved_at: countersAdvanced(state.last, beat)
      ? beat.received_at
      : state.counters_moved_at || beat.received_at,
  });

  return NextResponse.json({ ok: true, seq }, { headers: NO_STORE });
}
