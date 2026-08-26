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
 *
 * ## Doar un semnal proaspăt e „ok". Restul, oricare ar fi, nu e.
 *
 * Cinci feluri de a nu ști, toate 503, fiecare cu numele lui în corp:
 *
 *   `unconfigured`   — nicio instanță nu are cheie configurată;
 *   `no-beat`        — instanța e cunoscută și nu a trimis niciodată nimic;
 *   `unreadable`     — are fișier de stare și nu se poate citi;
 *   `unknown`        — s-a cerut `?instance=<id>` pentru un id necunoscut —
 *                      inclusiv unul RETRAS, vezi mai jos;
 *   `state-volatile` — starea se scrie unde o șterge următoarea publicare, deci
 *                      martorul e pe cale să UITE ce alarmează acum.
 *
 * Ruta asta e citită de un monitor care nu poate deosebi altfel: un 200 pe o
 * stare pe care nu am citit-o e chiar contopirea dintre „nu știu" și „e bine"
 * pe care sistemul ăsta există ca să o prevină.
 *
 * ## `no-beat` se VEDE, dar nu se NUMĂRĂ
 *
 * „Configurată, aștept primul semnal" și „trimitea, acum tace" sunt stări
 * diferite și nu au voie să împartă un verdict. O instanță care n-a trimis
 * niciodată nu intră în calculul agregat: apare în listă, dar nu poate face
 * răspunsul roșu.
 *
 * Fără regula asta, `SENTINEL_BEACON_SECRET` — variabilă permanentă, după
 * `watcher/.env.example` — ținea instanța `default` în registru pentru totdeauna, iar
 * din clipa în care fiecare server își trimite propriul `instance_id`, ea nu
 * mai primea niciodată vreun semnal. Rezultatul: trei servere sănătoase și o
 * plasă de siguranță blocată pe 503 la nesfârșit. O alarmă care nu se oprește e
 * o alarmă pe care operatorul o oprește.
 *
 * Excepția, tot din regulă: dacă TOATE instanțele sunt `no-beat`, nu există
 * nimic de numărat, iar răspunsul e 503 `no-beat`. Ăsta e martorul proaspăt
 * instalat — roșu până la primul semnal, deci câteva minute, și se rezolvă
 * singur. Alternativa — verde până sosește primul semnal, adică și dacă nu
 * sosește niciodată — e exact eșecul tăcut.
 *
 * ## O identitate RETRASĂ e `unknown`, nu o stare proprie
 *
 * `SENTINEL_RETIRED_INSTANCES` scoate identitatea din registru (vezi
 * `lib/beat-keys.ts`), deci `?instance=<retrasă>` cade pe ramura obișnuită de
 * necunoscut: 503 `unknown`. Verde nu e o opțiune — cine întreabă despre un id
 * anume a declarat că se așteaptă să existe, iar un 200 ar face un monitor verde
 * pe un server care nu mai e monitorizat de nimeni.
 *
 * Nici un nume propriu — `retired` — nu e o opțiune: ruta e publică și nu cere
 * nimic ca să întrebe, iar un nume distinct ar confirma că identificatorul a
 * existat cândva AICI. E aceeași scurgere pentru care `/beat` răspunde 401 și nu
 * 404 unei instanțe necunoscute. Iar „necunoscută" nu e un eufemism: după
 * retragere, martorul chiar nu mai știe de ea.
 *
 * Ce NU acoperă: `no-beat` nu are margine de timp. O instanță poate sta acolo
 * la nesfârșit fără să alarmeze — inclusiv una care ALARMA și în care martorul
 * a recăzut fiindcă și-a pierdut starea. Drumul obișnuit către asta e o
 * publicare a martorului cu starea în directorul aplicației; de-aia există
 * `state-volatile`. Detaliul complet e în docstring-ul din `lib/store.ts`.
 *
 * ## Ce face `/check` cu aceleași stări, și de ce nu la fel
 *
 * Niciuna dintre ele nu produce vreodată un mesaj pe Telegram: `/check` e ruta
 * care sună, iar „nu s-a observat niciodată vie" și „nu pot citi starea" nu
 * sunt lucruri pentru care se sună un om la 3 dimineața.
 *
 * În CORPUL lui `/check` însă cele două se despart, și diferența e deliberată:
 *
 *   `unreadable` → `ok: false`. Am un fișier și nu-l pot citi: e o defecțiune a
 *                  martorului însuși, și nu are voie să treacă drept sănătate.
 *   `no-beat`    → NU intră în calcul, deci `/check` poate răspunde `ok: true`
 *                  cu o instanță `no-beat` în listă. E aceeași regulă care a
 *                  reparat blocajul pe roșu de mai sus: o cheie rămasă în
 *                  configurație n-are voie să înroșească un panou pe care toate
 *                  serverele reale sunt sănătoase.
 *
 * `/status` e mai strict pe `no-beat` doar la instalare, când NU există nicio
 * instanță care să fi trimis vreodată — atunci nu e nimic de numărat și
 * răspunsul e roșu până la primul semnal.
 *
 * (Comentariul de aici a susținut o vreme că `/check` raportează `ok: false` și
 * pentru `no-beat`. Nu o făcea. Un comentariu care descrie altceva decât codul
 * e felul în care următorul om „repară" codul ca să se potrivească cu el.)
 *
 * ## Compromisul semnalului agregat
 *
 * Fără parametru, ruta întoarce 503 dacă ORICARE instanță tace. E un singur bit
 * pentru N servere, deci ascunde ceva prin construcție: cât timp A e jos,
 * răspunsul rămâne 503 chiar dacă B tocmai și-a revenit, iar monitorul nu are
 * cum să observe revenirea lui B. Acceptabil pentru ce e ruta asta — o plasă de
 * siguranță care trebuie doar să nu spună „e bine" când nu e. Inacceptabil ca
 * singură vedere: pentru „care anume", există `?instance=<id>`, corpul
 * răspunsului cu toate instanțele, alerta de pe Telegram și pagina.
 */

import { NextResponse } from "next/server";
import { readAll, stateIsVolatile, type InstanceState } from "@/lib/store";
import { judge } from "@/lib/verify";
import { own } from "@/lib/beat-keys";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

type Entry = {
  instance: string;
  status: string;
  last_seen: string | null;
  age_s: number | null;
};

function entryFor(id: string, inst: InstanceState, now: number): Entry {
  if (!inst.last) {
    // `judge()` întoarce „în regulă" aici, și are dreptate pentru ce decide EA:
    // pe cineva care n-a trimis niciodată nu-l suni. Dar un monitor de uptime nu
    // întreabă „să sun?", ci „e viu?", iar răspunsul e că nu știm. Pagina
    // arăta deja „niciun semnal încă" pentru aceeași înregistrare; ruta spunea
    // „ok". Două suprafețe care citesc un fișier și ajung la verdicte opuse e
    // felul în care operatorul învață să nu creadă niciuna.
    return { instance: id, status: "no-beat", last_seen: null, age_s: null };
  }
  const verdict = judge(inst, new Date(now));
  return {
    instance: id,
    status: verdict.kind === null ? "ok" : verdict.kind,
    last_seen: inst.last.received_at,
    age_s: Math.round((now - new Date(inst.last.received_at).getTime()) / 1000),
  };
}

/** Are fișier de stare și nu se poate citi. Nu e nici bine, nici tăcere. */
function unreadableEntry(id: string): Entry {
  return { instance: id, status: "unreadable", last_seen: null, age_s: null };
}

export async function GET(req: Request) {
  const state = await readAll();
  const now = Date.now();
  const wanted = new URL(req.url).searchParams.get("instance");

  if (wanted) {
    if (state.unreadable.includes(wanted)) {
      const entry = unreadableEntry(wanted);
      return NextResponse.json(
        { ...entry, instances: [entry] },
        { status: 503, headers: NO_STORE },
      );
    }
    const inst = own(state.instances, wanted);
    if (!inst) {
      // 503, nu 200 și nu 404. Cine întreabă despre o instanță anume a declarat
      // că se așteaptă să existe; dacă nu există, ori identificatorul din
      // monitor e greșit, ori serverul n-a trimis niciodată — și ambele trebuie
      // să fie roșu. Un 200 aici înseamnă un monitor verde pe un server care nu
      // a existat vreodată, adică exact felul în care o gardă nu prinde nimic
      // fără să spună.
      const entry: Entry = {
        instance: wanted, status: "unknown", last_seen: null, age_s: null,
      };
      return NextResponse.json(
        { ...entry, instances: [entry] },
        { status: 503, headers: NO_STORE },
      );
    }
    const entry = entryFor(wanted, inst, now);
    // Volatilitatea se aplică și aici: altfel un monitor îndreptat spre o
    // singură instanță ar vedea 200 în timp ce ruta agregată spune 503, iar
    // două suprafețe care se contrazic sunt cum se pierde încrederea în
    // amândouă.
    const volatileState = stateIsVolatile();
    const ok = entry.status === "ok" && !volatileState;
    return NextResponse.json(
      {
        ...entry,
        status: entry.status !== "ok" ? entry.status
          : volatileState ? "state-volatile" : "ok",
        state_volatile: volatileState,
        instances: [entry],
      },
      { status: ok ? 200 : 503, headers: NO_STORE },
    );
  }

  const entries = [
    ...Object.keys(state.instances).sort().map((id) => entryFor(id, state.instances[id], now)),
    ...state.unreadable.map(unreadableEntry),
  ].sort((a, b) => a.instance.localeCompare(b.instance));

  // Instanțele care n-au trimis niciodată se văd, dar nu se numără.
  //
  // `counted.length > 0` e jumătatea care contează: fără ea, `every` pe o listă
  // goală întoarce `true`, deci o stare pe care nu am putut-o citi deloc ar
  // ieși 200 „ok". A ieșit — vezi docstring-ul de mai sus.
  const counted = entries.filter((e) => e.status !== "no-beat");
  const instancesOk = counted.length > 0 && counted.every((e) => e.status === "ok");

  // Starea scrisă într-un director pe care o publicare îl șterge nu e o eroare
  // vizibilă nicăieri altundeva: efectul ei e UITAREA, iar o instanță uitată
  // recade din `silent` în `no-beat` și tace. Deci martorul refuză să pară
  // sănătos până când calea e mutată. Vezi `stateIsVolatile()`.
  const volatileState = stateIsVolatile();
  const ok = instancesOk && !volatileState;

  // Rezumatul din vârf descrie o instanță anume, aleasă în ordinea asta:
  // întâi una cu probleme, apoi cea cu semnalul cel mai vechi. Ordinea contează
  // — un rezumat ales doar după vechime poate spune „ok" în timp ce codul HTTP
  // e 503, fiindcă o instanță blocată (`stalled`) are semnalul proaspăt.
  //
  // O instanță care n-a trimis niciodată nu intră în comparația pe vechime: ar
  // ieși mereu prima și ar lăsa `age_s` null la nesfârșit, iar `age_s` e chiar
  // valoarea cu care se dovedește că CDN-ul nu pune ruta în cache.
  //
  // Când răspunsul e verde, reprezentantul se alege dintre instanțele NUMĂRATE:
  // altfel una care n-a trimis niciodată ar câștiga (are `age_s` nul, deci pare
  // cea mai veche) și ar lăsa `age_s` nul la nesfârșit — exact valoarea cu care
  // se dovedește că CDN-ul nu pune ruta în cache.
  const pool = instancesOk ? counted : entries;
  const rank = (e: Entry) => (e.status === "ok" ? 0 : e.status === "no-beat" ? 1 : 2);
  const worst = pool.reduce<Entry | undefined>((acc, e) => {
    if (acc === undefined) return e;
    if (rank(e) !== rank(acc)) return rank(e) > rank(acc) ? e : acc;
    return (e.age_s ?? -1) > (acc.age_s ?? -1) ? e : acc;
  }, undefined);

  return NextResponse.json(
    {
      // Fără nicio instanță în registru: nu e „nu știu despre serverul ăsta", e
      // „nu am niciun server". Numele diferit e ce deosebește o cheie
      // neconfigurată de o stare pe care n-am putut-o citi.
      // O problemă a unei instanțe bate configurația: dacă un server tace,
      // asta trebuie să scrie în vârf, nu faptul că starea e volatilă.
      status: !instancesOk ? (worst?.status ?? "unconfigured")
        : volatileState ? "state-volatile" : "ok",
      /**
       * Adevărat = starea se pierde la următoarea publicare, deci instanțele
       * care alarmează acum vor recădea tăcut în `no-beat`. Câmp propriu, ca un
       * monitor să poată deosebi asta de un server căzut.
       */
      state_volatile: volatileState,
      last_seen: worst?.last_seen ?? null,
      age_s: worst?.age_s ?? null,
      instances: entries,
    },
    { status: ok ? 200 : 503, headers: NO_STORE },
  );
}
