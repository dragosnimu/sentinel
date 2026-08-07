/**
 * Singura pagină a martorului: mai trăiește Sentinel?
 *
 * Răspunde de pe telefon, fără autentificare, fără VPN, fără să deschizi
 * panoul. Asta e tot ce trebuie să facă.
 *
 * ## Ce arată public și ce nu
 *
 * Public: dacă semnalul e proaspăt și de când. Un atacator care încarcă pagina
 * află că serverul e monitorizat — ceea ce oricum presupunea — și nimic despre
 * ce anume s-a detectat.
 *
 * Cu `?key=<SENTINEL_CHECK_SECRET>`: și contoarele. Câte incidente sunt
 * deschise și câte adrese sunt blocate spun ceva despre ce se întâmplă pe
 * server, deci nu stau la vedere.
 */

import { read } from "@/lib/store";
import { judge } from "@/lib/verify";

// Citește stare care se schimbă la fiecare minut. Randată static, ar arăta
// pentru totdeauna momentul în care a fost construită aplicația.
export const dynamic = "force-dynamic";
export const revalidate = 0;

function age(iso: string | undefined): string {
  if (!iso) return "—";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 90) return `${s} secunde`;
  if (s < 5400) return `${Math.round(s / 60)} minute`;
  if (s < 172800) return `${Math.round(s / 3600)} ore`;
  return `${Math.round(s / 86400)} zile`;
}

const EXPLAIN: Record<string, string> = {
  silent:
    "Semnalul s-a oprit. Serviciile pot fi oprite, gazda căzută sau rețeaua tăiată. " +
    "Verifică serverul direct — nu prin panou, fiindcă panoul e pe el.",
  stalled:
    "Semnalul sosește, dar contoarele nu mai avansează. Procesul trăiește și " +
    "conducta e moartă: nu se mai colectează sau nu se mai detectează nimic.",
  selfcheck: "Sentinel raportează singur o problemă. Vezi /autoverificare pe Telegram.",
};

export default async function Page({
  searchParams,
}: {
  searchParams: Promise<{ key?: string }>;
}) {
  const { key } = await searchParams;
  const state = await read();
  const verdict = judge(state, new Date());
  const last = state.last;

  const detailed = Boolean(
    key && process.env.SENTINEL_CHECK_SECRET && key === process.env.SENTINEL_CHECK_SECRET,
  );

  const status = !last ? "unknown" : verdict.kind === null ? "ok" : "bad";

  // Un titlu per verdict, fiindcă „a amuțit" și „raportează o problemă internă"
  // sunt situații complet diferite pentru cel care citește.
  //
  // Toate trei purtau înainte „Sentinel nu răspunde". Prima dată când pagina a
  // arătat asta pentru un autodiagnostic cu 32 din 33 de verificări trecute,
  // concluzia cititorului a fost că serverul e căzut — pentru un serviciu care
  // trimitea semnal la fiecare 60 de secunde. O pagină care există ca să spună
  // adevărul despre o tăcere nu are voie să inventeze una.
  const HEADLINE: Record<string, string> = {
    silent: "Sentinel nu răspunde",
    stalled: "Sentinel trăiește, dar nu mai colectează",
    selfcheck: "Sentinel raportează o problemă",
    replay: "Semnal refuzat: secvență reluată",
    forged: "Semnal refuzat: semnătură invalidă",
  };
  const headline =
    status === "unknown" ? "Niciun semnal încă"
      : status === "ok" ? "Sentinel e în viață"
        : HEADLINE[verdict.kind ?? ""] ?? "Sentinel raportează o problemă";

  return (
    <main className={`card ${status}`}>
      <p className="eyebrow">Martor extern · în afara serverului monitorizat</p>

      <h1 className="verdict">
        <span className="dot" aria-hidden="true" />
        {headline}
      </h1>

      <p className="lede">
        {status === "unknown"
          ? "Martorul e instalat, dar nu a primit niciun semnal. Verifică dacă serviciul sentinel-beacon e pornit și configurat."
          : status === "ok"
            ? `Ultimul semnal acum ${age(last?.received_at)}.`
            : EXPLAIN[verdict.kind ?? ""] ?? verdict.message}
      </p>

      <div className="rows">
        <div className="row">
          <span>Ultimul semnal</span>
          <b>{last ? age(last.received_at) : "—"}</b>
        </div>
        <div className="row">
          <span>Autodiagnostic</span>
          <b>
            {last
              ? `${last.selfcheck.worst} · ${last.selfcheck.checks - last.selfcheck.bad}/${last.selfcheck.checks}`
              : "—"}
          </b>
        </div>
        {detailed && last && (
          <>
            <div className="row">
              <span>Incidente deschise</span>
              <b>{last.incidents_open}</b>
            </div>
            <div className="row">
              <span>Adrese blocate</span>
              <b>{last.blocklist_size}</b>
            </div>
            <div className="row">
              <span>Ultimul eveniment</span>
              <b>#{last.last_event_id.toLocaleString("ro-RO")}</b>
            </div>
            <div className="row">
              <span>Cursor detecție</span>
              <b>#{last.detect_cursor.toLocaleString("ro-RO")}</b>
            </div>
            <div className="row">
              <span>Semnal nr.</span>
              <b>{last.seq.toLocaleString("ro-RO")}</b>
            </div>
          </>
        )}
      </div>

      <p className="note">
        Pagina asta rulează pe altă mașină decât serverul monitorizat. Dacă
        cineva oprește Sentinel, semnalul dispare și martorul alertează pe
        Telegram — de aici, nu de pe serverul oprit.
      </p>
    </main>
  );
}
