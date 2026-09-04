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
 *
 * ## Fiecare instanță e judecată separat
 *
 * Un singur verdict pentru N servere ar însemna că al doilea care cade nu mai
 * produce nimic, fiindcă „e deja alertat". Deci: verdict propriu, dedublare
 * proprie, și mesajul NUMEȘTE instanța — o alertă care spune doar „Sentinel nu
 * răspunde" pe un panou cu cinci servere te trimite să le verifici pe toate.
 */

import { NextResponse } from "next/server";
import {
  readAll, retiredWithOpenAlert, updateInstance, type InstanceState,
} from "@/lib/store";
import { judge, principalAlreadyDelivered, type Verdict } from "@/lib/verify";
import { alert, escapeHtml } from "@/lib/telegram";

export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

// După cât timp se repetă o alertă care persistă. Patru ore: destul cât să nu
// devină zgomot, destul de des cât să nu uiți că serverul e încă jos.
const REALERT_MS = 4 * 60 * 60 * 1000;

type Reported = {
  id: string;
  label: string;
  /**
   * `"no-beat"` și `"unreadable"` nu vin din `judge()`.
   *
   * Sunt stările despre care NU alertăm, dar care nici nu au voie să treacă
   * drept „în regulă": configurată și fără niciun semnal vreodată, respectiv
   * fișier de stare care nu se poate citi.
   */
  kind: Verdict["kind"] | "no-beat" | "unreadable" | "retired-closed";
  severity: Verdict["severity"] | null;
  /** Un mesaj despre o problemă chiar A PLECAT spre Telegram în runda asta. */
  alerted: boolean;
  /**
   * Scrierea de stare care trebuia să urmeze chiar S-A FĂCUT.
   *
   * Separat de `alerted` fiindcă cele două chiar se pot despărți: mesajul
   * pleacă, iar scrierea e refuzată dacă fișierul a devenit între timp
   * necitibil. A raporta o scriere care nu s-a întâmplat ca și cum s-ar fi
   * întâmplat e chiar tiparul după care e numit depozitul ăsta.
   */
  recorded: boolean;
};

/** Numele sub care apare instanța în alertă. Eticheta e cosmetică; id-ul e adevărul. */
function nameOf(id: string, inst: InstanceState): string {
  const label = inst.last?.label?.trim();
  return label ? `${label} (${id})` : id;
}

export async function GET(req: Request) {
  const expected = process.env.SENTINEL_CHECK_SECRET;
  const given = new URL(req.url).searchParams.get("key")
    || req.headers.get("x-sentinel-check-key");
  if (!expected || given !== expected) {
    return NextResponse.json({ error: "refuzat" }, { status: 401, headers: NO_STORE });
  }

  const state = await readAll();
  const now = new Date();
  const instances = state.instances;
  const reported: Reported[] = [];

  // Sortat, ca ordinea din răspuns să nu depindă de ordinea în care au sosit
  // semnalele — altfel două rulări identice arată diferit și par să se schimbe.
  for (const id of Object.keys(instances).sort()) {
    const inst = instances[id];

    if (!inst.last) {
      // Configurată, dar n-a trimis niciodată nimic. NU se alertează — un
      // martor instalat înaintea expeditorului n-are voie să sune, și asta e
      // chiar cazul obișnuit în primele minute de după instalare. Se raportează
      // însă, fiindcă „încă niciun semnal" nu e „în regulă".
      reported.push({
        id, label: "", kind: "no-beat", severity: null, alerted: false, recorded: false,
      });
      continue;
    }

    const verdict = judge(inst, now);
    const name = escapeHtml(nameOf(id, inst));

    if (verdict.kind === null) {
      // Dacă tocmai ne-am întors dintr-o alertă, spunem și asta. O alertă care nu
      // se închide niciodată lasă operatorul să se întrebe dacă s-a rezolvat.
      let recorded = false;
      if (inst.alerted) {
        // Simetric cu suprimarea de la intrare, mai jos: dacă principalul a
        // anunțat el însuși revenirea pentru FELUL de alertă pe care noi l-am
        // avut deschis, martorul tace și la revenire — cerința operatorului o
        // spune explicit. Se verifică felul PĂSTRAT în `inst.alerted` (alerta
        // pe care AM trimis-o), nu verdictul curent, care e deja `null` aici.
        const principalAnnouncedRecovery =
          principalAlreadyDelivered(inst.alerted.kind, inst.last);
        if (!principalAnnouncedRecovery) {
          await alert(
            `✅ <b>${name} — Sentinel a revenit</b>\n\n` +
            `Semnalul a reînceput. Problema anterioară: ${escapeHtml(inst.alerted.kind)}, ` +
            `semnalată la ${escapeHtml(inst.alerted.at)}.`,
          );
        }
        // Se șterge indiferent dacă mesajul a plecat SAU a fost suprimat: o
        // stare „alertat" rămasă în urmă ar face ca o recădere de același fel,
        // în următoarele patru ore, să fie înghițită ca duplicat.
        //
        // Se scrie prin `updateInstance`, care RECITEȘTE fișierul instanței
        // înainte de scriere: între citirea de la începutul rutei și punctul
        // ăsta a trecut un apel către Telegram, timp în care poate să fi sosit
        // un semnal. Fără recitire, semnalul acela s-ar pierde, iar instanța ar
        // părea tăcută încă o rundă de cron.
        recorded = await updateInstance(id, (previous) => ({ ...previous, alerted: undefined }));
      }
      reported.push({
        id, label: inst.last.label ?? "", kind: null, severity: null,
        alerted: false, recorded,
      });
      continue;
    }

    if (principalAlreadyDelivered(verdict.kind, inst.last)) {
      // Regula operatorului: alerta de pe martor pleacă doar dacă principalul
      // n-a livrat CONFIRMAT același fel de mesaj recent — vezi
      // `sentinel/report/beacon.py`, „Alertele duble". Martorul tace, dar NU
      // marchează `alerted`: dacă ar face-o, când verdictul se rezolvă mai
      // târziu ramura de mai sus ar anunța „a revenit" pentru o alarmă pe care
      // martorul n-a dat-o niciodată — a doua formă de mesaj fals, nu o
      // reparație. Fără `alerted` scris, mașina de stări rămâne exact ce era
      // înainte de rundă: „nimic în picioare aici".
      reported.push({
        id, label: inst.last?.label ?? "", kind: verdict.kind, severity: verdict.severity,
        alerted: false, recorded: false,
      });
      continue;
    }

    const already = inst.alerted?.kind === verdict.kind
      && now.getTime() - new Date(inst.alerted.at).getTime() < REALERT_MS;

    let sent = false;
    let recorded = false;
    if (!already) {
      const icon = verdict.severity === "critical" ? "🔴" : "🟡";
      sent = await alert(
        `${icon} <b>${name} — ${verdict.kind}</b>\n\n${escapeHtml(verdict.message)}\n\n` +
        (inst.last
          ? `<i>Ultimul semnal: seq ${inst.last.seq}, ${escapeHtml(inst.last.received_at)}. ` +
            `Incidente deschise: ${inst.last.incidents_open}. ` +
            `Blocate: ${inst.last.blocklist_size}.</i>`
          : `<i>Niciun semnal primit vreodată de la instanța asta.</i>`),
      );
      // Marcăm ca alertat doar dacă chiar a plecat. Altfel o cădere temporară a
      // API-ului Telegram ar consuma singura alertă.
      if (sent) {
        // Verdictul se copiază într-o variabilă locală: înăuntrul unei funcții
        // de apel, TypeScript nu mai poate ști că `verdict.kind` a rămas cel
        // verificat mai sus.
        const kind = verdict.kind;
        recorded = await updateInstance(id, (previous) => ({
          ...previous,
          alerted: { kind, at: now.toISOString() },
        }));
      }
    }

    reported.push({
      id,
      label: inst.last?.label ?? "",
      kind: verdict.kind,
      severity: verdict.severity,
      // Ce s-a întâmplat CU ADEVĂRAT, nu ce am hotărât să facem: `!already`
      // spunea „am alertat" și când Telegram refuzase mesajul, și când scrierea
      // de dedublare fusese refuzată.
      alerted: sent,
      recorded,
    });
  }

  // Alarmele rămase deschise pe identități RETRASE. Retragerea le scoate din
  // enumerare, deci bucla de mai sus nu ajunge niciodată la ele — iar mesajul
  // roșu deja trimis n-ar mai fi urmat de nimic. Operatorul rămâne cu o alarmă
  // care, din locul lui, nu s-a închis niciodată.
  //
  // Mesajul NU spune „a revenit", și diferența nu e de politețe: nu s-a
  // întors nimic. Alarma se închide fiindcă identitatea a fost scoasă din
  // registru, iar cele două confundate ar fi chiar tiparul după care e numit
  // depozitul — un raport care descrie intenția în locul efectului.
  for (const { id, alerted: was } of await retiredWithOpenAlert()) {
    await alert(
      `⚪ <b>${escapeHtml(id)} — retrasă, alarma se închide</b>\n\n` +
      "Identitatea a ieșit din registru și nu mai e urmărită. Alarma anterioară " +
      `(${escapeHtml(was.kind)}, semnalată la ${escapeHtml(was.at)}) se închide ` +
      "prin retragere, NU fiindcă s-ar fi rezolvat ceva.",
    );
    // Se șterge indiferent dacă mesajul a plecat, ca pe ramura de revenire: un
    // steag rămas în urmă ar retrimite închiderea la fiecare rundă de cron.
    const recorded = await updateInstance(id, (previous) => ({
      ...previous, alerted: undefined,
    }));
    reported.push({
      id, label: "", kind: "retired-closed", severity: null,
      alerted: false, recorded,
    });
  }

  // Instanțele al căror fișier nu se poate citi se raportează, dar NU se
  // alertează. Nu din indulgență: starea de dedublare („am alertat deja") stă
  // chiar în fișierul ilizibil, deci o alertă de aici ar pleca la fiecare rundă
  // de cron, la nesfârșit — iar o alarmă care nu se oprește e o alarmă pe care
  // operatorul o oprește. Se vede în corpul răspunsului și în jurnal.
  for (const id of state.unreadable) {
    console.error("[watcher] nu pot citi starea unei instanțe la verificare");
    reported.push({
      id, label: "", kind: "unreadable", severity: null, alerted: false, recorded: false,
    });
  }

  // Aceleași două reguli ca în `/status`, din aceleași motive: instanțele care
  // n-au trimis niciodată se VĂD dar nu se NUMĂRĂ, iar `every` pe o listă goală
  // întoarce `true`, deci fără verificarea de lungime un registru gol ar fi ieșit
  // `ok: true`. A nu ALERTA pe un registru gol e corect; a PUBLICA „e în regulă"
  // despre el e aceeași minciună reparată în ruta vecină.
  // `retired-closed` iese din numărătoare alături de `no-beat`, și din același
  // fel de motiv: nu e o stare de sănătate. E un eveniment administrativ care se
  // întâmplă o singură dată, iar numărat ar face runda aia să raporteze
  // `ok: false` — adică o retragere reușită ar arăta ca o verificare picată.
  const counted = reported.filter(
    (r) => r.kind !== "no-beat" && r.kind !== "retired-closed");
  return NextResponse.json(
    {
      ok: counted.length > 0 && counted.every((r) => r.kind === null),
      instances: reported.sort((a, b) => a.id.localeCompare(b.id)),
    },
    { headers: NO_STORE },
  );
}
