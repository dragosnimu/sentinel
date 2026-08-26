/**
 * Verificarea lanțului de hash-uri al jurnalului de audit.
 *
 * **Asta e proprietatea pentru care merită tot proiectul.** §5 din
 * `docs/PLAN-arhitectura-distribuita.md` scrie că sistemul „nu verifică
 * înlănțuirea și nici nu are cu ce". Conducta de sincronizare îi dă exact ce-i
 * lipsea: serverul expediază `id`, `prev_hash` și `entry_hash` neatinse, iar
 * aici se poate cere ca `prev_hash`-ul fiecărui rând să fie `entry_hash`-ul
 * celui dinainte — o dovadă pe care mașina monitorizată NU și-o poate da
 * singură, fiindcă root pe ea poate rescrie și jurnalul, și verificatorul.
 *
 * ## Ce prinde, și ce NU — scris înainte de orice cod
 *
 * Prinde: ȘTERGEREA unui rând, INSERAREA unuia și REORDONAREA — toate rup
 * legătura `prev_hash → entry_hash` într-un loc observabil.
 *
 * NU prinde: falsificarea informată. Cine are root pe serverul monitorizat poate
 * recalcula un lanț întreg, fals dar consistent, și îl poate expedia. §5 o spune
 * deja; nimic de aici nu pretinde mai mult.
 *
 * NU recalculează `entry_hash` din conținut. Serverul îl calculează peste un
 * `json.dumps(..., sort_keys=True, separators=(",", ":"), default=str)` din
 * Python (`sentinel/db/repo/audit.py::_entry_hash`) — adică exact perechea de
 * serializatoare de uz general despre care `sentinel/report/signing.py`
 * argumentează pe o pagină că nu poate fi făcută să coincidă între limbaje. Ce
 * se verifică aici e o proprietate STRUCTURALĂ, care nu are nevoie de acordul
 * ăla.
 *
 * ## Un GOL nu e o RUPTURĂ — și cum se deosebesc
 *
 * Un rând al cărui predecesor n-a ajuns ÎNCĂ arată exact ca unul al cărui
 * predecesor a fost ȘTERS. Confundate într-un sens, fiecare recuperare de
 * restanță dă o alarmă falsă și operatorul oprește alarma; în celălalt, o
 * rescriere reală de istorie trece în tăcere.
 *
 * Faptul care le separă e **filigranul confirmat** (`sync_cursors.last_source_id`):
 *
 *   * expeditorul trimite rândurile în ordinea `id`, fără să sară vreunul
 *     (`WHERE id > cursor ORDER BY id LIMIT n` în `shipper.py::collect_stream`);
 *   * ruta ecouă filigranul DOAR după ce a numărat toate rândurile lotului ca
 *     prezente, iar cursorul avansează doar pe ecou.
 *
 * Deci sub filigran nu mai poate exista niciun rând „pe drum": tot ce a trecut
 * pe acolo a fost scris. O legătură care nu se potrivește între două rânduri
 * aflate AMÂNDOUĂ sub filigran înseamnă rânduri care au fost în lanț și nu mai
 * sunt în copia noastră. Peste filigran, aceeași nepotrivire înseamnă „încă se
 * mișcă" și se raportează ca `unknown`, nu ca ruptură.
 *
 * **Golurile de numerotare nu contează deloc**, și e important de spus de ce: o
 * tranzacție anulată consumă un `id` din secvența Postgres fără să lase un rând,
 * deci `audit_log.id` POATE avea goluri. Verificarea nu se uită la continuitatea
 * numerelor — se uită la hash-uri. Două rânduri cu `id` 100 și 102 ale căror
 * hash-uri se leagă sunt vecine în lanț, și gata. O verificare construită pe
 * „id-urile trebuie să fie consecutive" ar fi dat alarme false exact pe purtarea
 * normală a bazei.
 *
 * ## Capătul de jos: pragul de backfill
 *
 * Primul rând pe care îl are agregatorul are un `prev_hash` care arată spre un
 * rând care poate să nu ajungă NICIODATĂ — `ship.max_backfill_days` lasă în urmă
 * tot ce e mai vechi (`shipper.py::_cursor_of`). Deci un capăt de jos
 * neverificabil e starea NORMALĂ, nu o ruptură.
 *
 * Se fixează totuși: prima verificare scrie `first_source_id` și
 * `first_prev_hash` în `audit_chain_state`, iar de atunci o schimbare a lor e o
 * TRUNCHIERE — cineva a șters de la început. Fără fixarea aia, ștergerea
 * primelor rânduri ar arăta pentru totdeauna ca un prag de backfill.
 *
 * Excepția fericită: dacă `prev_hash`-ul primului rând e chiar `GENESIS_HASH`,
 * capătul de jos e dovedit — ăla e începutul lanțului de pe server.
 */

import { streamFor } from "./streams";
import type { Db } from "./migrate";
import type { Stream } from "./streams";

/**
 * Fluxul cu lanț. Numele stă o dată, fiindcă e citit de două ori: ca să se
 * ia felul cursorului din registru și ca să se caute cursorul în bază. Două
 * șiruri scrise separat ar fi putut ajunge să vorbească despre fluxuri
 * diferite — verificarea felului ar fi trecut, iar numărul ar fi venit de la
 * altcineva.
 */
const CHAINED_STREAM = "audit_log";

/**
 * Poate agregatorul să știe o POZIȚIE confirmată pentru fluxul ăsta?
 *
 * Doar pentru fluxurile append-only. Acolo `sync_cursors.last_source_id` —
 * un maxim istoric al filigranelor — coincide cu poziția, fiindcă
 * filigranele cresc. Pe un flux mutabil filigranul e maximul DIN LOT, iar
 * loturile succesive pot scădea: același număr, alt înțeles, și nimic în el
 * care să arate diferența.
 *
 * `undefined` (flux necunoscut) e tot „nu pot ști": un registru din care a
 * dispărut fluxul nu e o dovadă că poziția lui e zero.
 */
export function positionIsKnowable(stream: Stream | undefined): boolean {
  return stream !== undefined && stream.cursor === "append-only";
}

/**
 * Poate fi verificat LANȚUL fluxului ăstuia?
 *
 * Două condiții, diferite între ele:
 *
 *   * `chained` — fluxul poartă `prev_hash`/`entry_hash`. Fără ele nu există lanț
 *     de verificat, iar interogările de mai jos ar cere coloane care nu există.
 *   * poziția confirmată se poate ști — vezi `positionIsKnowable`.
 *
 * Amândouă se cer pe fluxul PRIMIT, nu pe numele lui: al doilea flux cu lanț
 * (dovezile din E4) e prevăzut chiar în `lib/streams.ts`, iar cu numele fixat în
 * interogare ar fi citit filigranul lui `audit_log`.
 */
export function chainReadable(stream: Stream | undefined): boolean {
  return stream !== undefined && stream.chained && positionIsKnowable(stream);
}

/** Verdictul „nu pot ști", scris o dată: două intrări îl dau, pe același motiv. */
function cannotKnow(): ChainVerdict {
  return {
    status: "unknown", checkedLinks: 0, verifiedThrough: null,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null, fromLowEnd: false,
    detail: "nu pot citi filigranul confirmat, deci nu pot deosebi un gol de o ruptură",
  };
}

/**
 * `prev_hash`-ul primului rând din jurnalul serverului.
 *
 * Aceeași valoare ca `GENESIS_HASH` din `sentinel/db/repo/audit.py`, și e un
 * contract cu celălalt capăt: dacă diferă, începutul dovedit al lanțului nu se
 * mai recunoaște ca început, iar o instalare curată ar arăta veșnic cu un capăt
 * de jos neverificat. Acordul e ținut de
 * `tests/unit/test_aggregator_chain.py::test_the_two_ends_agree_on_the_genesis_hash`.
 */
export const GENESIS_HASH = "0".repeat(64);

/** Câte rânduri se citesc dintr-o dată la parcurgerea întregii arhive. */
const PAGE = 1000;

/** O verigă, așa cum e stocată. */
export type Link = {
  sourceId: number;
  prevHash: string | null;
  entryHash: string;
};

export type ChainVerdict = {
  /**
   * `ok` — toate legăturile verificabile se potrivesc.
   * `broken` — o legătură nu se potrivește sub filigranul confirmat.
   * `unknown` — nu s-a putut decide (nimic de verificat, sau capătul de sus se
   *             mișcă încă). NU e `ok`.
   */
  status: "ok" | "broken" | "unknown";
  /** Câte legături au fost comparate. Zero e o informație, nu un succes. */
  checkedLinks: number;
  /** Cel mai mare `source_id` până la care lanțul e legat fără întrerupere. */
  verifiedThrough: number | null;
  firstSourceId: number | null;
  firstPrevHash: string | null;
  breakSourceId: number | null;
  detail: string | null;
  /**
   * Verificarea a pornit de la CAPĂTUL DE JOS al copiei, nu din mijloc.
   *
   * E autoritatea verdictului, și de-aia stă pe el, nu pe apelant: o fereastră
   * care începe deasupra unei rupturi n-are cum s-o vadă, deci `ok`-ul ei e o
   * propoziție despre fereastră, nu despre lanț. Vezi `recordVerdict`.
   */
  fromLowEnd: boolean;
};

/**
 * Verdictul pentru o secvență de verigi ÎN ORDINE, cu un predecesor cunoscut.
 *
 * Funcție pură: primește ce s-a citit din bază și întoarce ce se poate spune
 * despre el. Toată decizia „gol sau ruptură" e aici, ca să poată fi probată fără
 * bază de date — și ca să fie un singur loc, nu unul pentru ingestie și altul
 * pentru cron.
 *
 * `predecessor` e ultima verigă dinaintea ferestrei (sau `null` dacă fereastra
 * începe la capătul de jos al copiei). `confirmedThrough` e
 * `sync_cursors.last_source_id`.
 */
export function verifyLinks(
  links: Link[], predecessor: Link | null, confirmedThrough: number,
  known?: { firstSourceId: number | null; firstPrevHash: string | null },
): ChainVerdict {
  const base: ChainVerdict = {
    status: "unknown", checkedLinks: 0, verifiedThrough: predecessor?.sourceId ?? null,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null, detail: null,
    fromLowEnd: predecessor === null,
  };

  if (!links.length) {
    return { ...base, detail: "nimic de verificat" };
  }

  let expected: string | null = predecessor?.entryHash ?? null;
  let checked = 0;
  let verifiedThrough: number | null = predecessor?.sourceId ?? null;
  let firstSourceId = predecessor === null ? links[0].sourceId : null;
  let firstPrevHash = predecessor === null ? links[0].prevHash : null;

  // Capătul de jos, când fereastra chiar începe acolo.
  if (predecessor === null) {
    const first = links[0];
    if (known?.firstSourceId != null) {
      // Capătul a fost fixat de o verificare anterioară. Contează DIRECȚIA în
      // care s-a mutat, și asta e tot:
      //
      //   * a URCAT — copia începe mai sus decât începea: rândurile de la început
      //     au dispărut. Un prag de backfill nu poate explica asta, fiindcă
      //     pragul se așază o singură dată, înaintea primei runde;
      //   * a COBORÂT — a sosit istorie mai VECHE. E o cale pe care serverul o
      //     recomandă singur: linia de WARNING din `shipper.py::_cursor_of` îi
      //     spune operatorului să mărească `ship.max_backfill_days` și să șteargă
      //     cursoarele `ship:*`, iar atunci rândurile de sub prag pleacă. Raportat
      //     ca ștergere, ar da o alarmă falsă exact la procedura scrisă în mesajul
      //     de ajutor — adică fix felul în care se învață cineva să ignore alarma;
      //   * a rămas pe loc, dar `prev_hash`-ul lui s-a schimbat — același rând,
      //     altă legătură în urmă: o rescriere, nu o sosire.
      const sameRow = known.firstSourceId === first.sourceId;
      if (first.sourceId > known.firstSourceId
          || (sameRow && known.firstPrevHash !== first.prevHash)) {
        return {
          ...base,
          status: "broken",
          checkedLinks: 0,
          breakSourceId: first.sourceId,
          firstSourceId: known.firstSourceId,
          firstPrevHash: known.firstPrevHash,
          detail: sameRow
            ? `capătul de jos e tot source_id ${first.sourceId}, dar prev_hash-ul ` +
              `lui s-a schimbat: același rând arată acum spre altceva în urmă. ` +
              `Nu e o sosire de istorie mai veche, e o rescriere.`
            : `capătul de jos al copiei a URCAT: era source_id ` +
              `${known.firstSourceId}, acum e ${first.sourceId}. Rândurile de la ` +
              `început au fost ȘTERSE — un prag de backfill nu poate urca, se ` +
              `așază o singură dată, înaintea primei runde.`,
        };
      }
    }
    if (first.prevHash === GENESIS_HASH) {
      // Capăt dovedit: ăsta e chiar începutul jurnalului de pe server.
      verifiedThrough = first.sourceId;
    }
    expected = first.entryHash;
    // Prima verigă nu se compară cu nimic; parcurgerea începe de la a doua.
    for (let i = 1; i < links.length; i++) {
      const verdict = step(links[i], expected, confirmedThrough, checked, verifiedThrough);
      if (verdict.stop) {
        return { ...base, ...verdict.result, firstSourceId, firstPrevHash };
      }
      checked = verdict.checked;
      verifiedThrough = verdict.verifiedThrough;
      expected = links[i].entryHash;
    }
  } else {
    for (const link of links) {
      const verdict = step(link, expected, confirmedThrough, checked, verifiedThrough);
      if (verdict.stop) {
        return { ...base, ...verdict.result, firstSourceId, firstPrevHash };
      }
      checked = verdict.checked;
      verifiedThrough = verdict.verifiedThrough;
      expected = link.entryHash;
    }
  }

  const last = links[links.length - 1];
  const pending = last.sourceId > confirmedThrough;
  return {
    // Zero legături comparate ȘI niciun capăt dovedit nu e „ok": e o bifă care
    // nu s-a uitat la nimic. Un singur rând stocat, cu un `prev_hash` pe care
    // nu-l putem verifica, nu dovedește nimic despre lanț.
    status: checked > 0 || verifiedThrough !== null ? "ok" : "unknown",
    checkedLinks: checked,
    verifiedThrough,
    firstSourceId,
    firstPrevHash,
    breakSourceId: null,
    fromLowEnd: predecessor === null,
    detail: pending
      ? `verificat până la ${verifiedThrough ?? "—"}; rândurile de peste ` +
        `filigranul ${confirmedThrough} încă se mișcă`
      : null,
  };
}

/** O singură legătură. Scoasă din buclă ca să nu existe două copii ale regulii. */
function step(
  link: Link, expected: string | null, confirmedThrough: number,
  checked: number, verifiedThrough: number | null,
): { stop: false; checked: number; verifiedThrough: number | null }
  | { stop: true; result: Partial<ChainVerdict> } {
  if (expected !== null && link.prevHash === expected) {
    return { stop: false, checked: checked + 1, verifiedThrough: link.sourceId };
  }

  // Nu se leagă. Singura întrebare care rămâne: mai poate veni ceva între ele?
  if (link.sourceId > confirmedThrough) {
    return {
      stop: true,
      result: {
        status: "unknown",
        checkedLinks: checked,
        verifiedThrough,
        breakSourceId: null,
        detail: `legătura dinaintea lui source_id ${link.sourceId} nu se poate ` +
                `verifica încă: rândul e peste filigranul confirmat ` +
                `(${confirmedThrough}), deci predecesorul lui poate fi pe drum.`,
      },
    };
  }

  return {
    stop: true,
    result: {
      status: "broken",
      checkedLinks: checked,
      verifiedThrough,
      breakSourceId: link.sourceId,
      detail: `source_id ${link.sourceId} are prev_hash ` +
              `${link.prevHash === null ? "NULL" : link.prevHash.slice(0, 12)} ` +
              `dar predecesorul lui stocat are entry_hash ` +
              `${expected === null ? "NULL" : expected.slice(0, 12)}. Ambele rânduri ` +
              `sunt sub filigranul confirmat (${confirmedThrough}), deci ce lipsește ` +
              `între ele NU mai poate sosi: a fost în lanț și nu mai e.`,
    },
  };
}

// ---------------------------------------------------------------------------
// Citirea din bază
// ---------------------------------------------------------------------------
function toLink(row: Record<string, unknown>): Link | null {
  const sourceId = Number(row.source_id);
  const entryHash = row.entry_hash;
  if (!Number.isFinite(sourceId) || typeof entryHash !== "string") return null;
  const prevHash = row.prev_hash;
  return {
    sourceId,
    prevHash: typeof prevHash === "string" ? prevHash : null,
    entryHash,
  };
}

/**
 * Filigranul confirmat al fluxului `audit_log`. `null` = nu se poate citi.
 *
 * ## CONSTRÂNGERE pentru cine îndreaptă verificarea spre alt flux
 *
 * Numărul ăsta nu e diagnostic: pe el stă discriminatorul GOL / RUPTURĂ. „Verigi
 * care au fost și nu mai sunt" față de „lanț care încă se mișcă" se deosebesc
 * doar prin el.
 *
 * `sync_cursors.last_source_id` e scris cu `GREATEST` (`lib/ingest.ts`,
 * `advanceCursor`), deci e MAXIMUL ISTORIC al filigranelor primite, nu poziția
 * fluxului. Pe `audit_log` cele două coincid — fluxul e append-only, filigranele
 * cresc —, și de-aia interogarea de aici e fixată pe numele lui.
 *
 * Pe un flux MUTABIL nu coincid, și nu e o scăpare: filigranul e cel mai mare
 * `id` DIN LOT, iar loturile succesive pot avea filigrane mai mici (un rând vechi
 * atins acum are un `id` mic). Poziția reală e `(updated_at, id)` și trăiește la
 * expeditor — agregatorul n-o primește. Deci:
 *
 *   * îndreptată spre un flux mutabil, funcția asta ar întoarce un maxim istoric
 *     citit ca poziție confirmată. Verigile sub el ar părea „confirmate și
 *     dispărute" → `broken` pe un lanț sănătos; cele de peste el n-ar fi
 *     niciodată confirmate → `unknown` pentru totdeauna;
 *   * la fel dacă `audit_log` capătă vreodată un filigran nemonoton.
 *
 * ## Ce s-a făcut cu constrângerea asta
 *
 * Nu s-a lărgit interogarea și nu s-a adăugat o coloană de poziție. S-a impus
 * echivalența pe care se sprijinea deja tăcut: fluxul verificat trebuie să fie
 * `append-only`, iar acolo maximul istoric CHIAR e poziția, fiindcă filigranele
 * cresc. Verificarea de mai jos e cea care o impune, la fiecare citire, iar
 * `tests/ingest.test.ts` cere ca orice flux cu lanț să fie append-only — deci nu
 * se poate ajunge aici cu altul nici măcar printr-o redeclarare.
 *
 * Îndreptată spre un flux mutabil, funcția întoarce `null` — «nu pot ști» —, iar
 * verificarea iese `unknown`. NU `broken`: un lanț sănătos declarat rupt fiindcă
 * s-a citit un număr greșit ar fi cea mai scumpă formă de minciună de aici.
 *
 * Cine mai citește coloana, măsurat — DOUĂ locuri, nu „un număr necunoscut":
 * funcția asta, care o citește ca poziție și e păzită, și `advanceCursor` din
 * `lib/ingest.ts`, care o recitește imediat după scriere ca să confirme că
 * mutarea s-a făcut. A doua NU e păzită, și e corect: compară valoarea cu
 * filigranul tocmai cerut, nu o citește ca poziție a fluxului. Nicio altă cale
 * din depozit n-o atinge.
 *
 * Ce s-a RESPINS: o coloană nouă (`confirmed_through`) scrisă doar pentru
 * fluxurile append-only. Ar fi ținut aceeași valoare ca `last_source_id` pentru
 * singurul flux care o poate avea, adică o a doua copie a aceluiași fapt, care
 * poate diverge. Ziua în care un flux mutabil chiar are nevoie de o poziție
 * confirmată pe agregator, coloana aia se adaugă atunci, cu întrebarea ei
 * proprie: ce înseamnă „confirmat" când filigranele nu cresc.
 */
async function confirmedThrough(
  db: Db, instanceId: string, stream: Stream | undefined,
): Promise<number | null> {
  // Fluxul verificat trebuie să fie append-only. Pe altul, `last_source_id` e un
  // maxim istoric, nu o poziție, iar diferența nu se vede în număr: arată la fel.
  if (!positionIsKnowable(stream)) return null;

  // Numele vine din fluxul DAT, nu din constanta modulului. Cu numele fixat,
  // paza verifica un flux si interogarea citea altul: un al doilea flux
  // append-only ar fi primit filigranul lui `audit_log` — mai avansat, deci
  // verigi inca in zbor ar fi fost judecate ca fiind sub filigran, iar verdictul
  // ar fi iesit `broken` pe un lant sanatos.
  const rows = await db.all(
    "SELECT last_source_id FROM sync_cursors WHERE instance_id = ? AND stream = ?",
    [instanceId, (stream as Stream).name]);
  if (!rows.length || rows[0] == null) return null;
  const raw = rows[0].last_source_id;
  // Aceeași regulă ca peste tot: `Number(null)` e 0, iar 0 ar fi o AFIRMAȚIE —
  // „nimic nu e confirmat" — făcută pe o valoare pe care n-am citit-o.
  if (raw === undefined || raw === null) return null;
  const value = Number(raw);
  return Number.isFinite(value) ? value : null;
}

/** O pagină de verigi, în ordinea `source_id`, strict peste `after`. */
async function page(
  db: Db, table: string, instanceId: string, after: number | null,
): Promise<Link[] | null> {
  const rows = after === null
    ? await db.all(
      `SELECT source_id, prev_hash, entry_hash FROM ${table} ` +
      "WHERE instance_id = ? ORDER BY source_id LIMIT " + PAGE, [instanceId])
    : await db.all(
      `SELECT source_id, prev_hash, entry_hash FROM ${table} ` +
      "WHERE instance_id = ? AND source_id > ? ORDER BY source_id LIMIT " + PAGE,
      [instanceId, after]);
  const links: Link[] = [];
  for (const row of rows) {
    const link = toLink(row);
    // Un rând din care nu iese o verigă nu se sare: nu se poate ști ce era, iar
    // sărirea lui ar face lanțul să pară legat peste el.
    if (link === null) return null;
    links.push(link);
  }
  return links;
}

/** Veriga dinaintea lui `sourceId`, sau `null` dacă nu există niciuna stocată. */
async function predecessorOf(
  db: Db, table: string, instanceId: string, sourceId: number,
): Promise<{ found: Link | null } | null> {
  const rows = await db.all(
    `SELECT source_id, prev_hash, entry_hash FROM ${table} ` +
    "WHERE instance_id = ? AND source_id < ? ORDER BY source_id DESC LIMIT 1",
    [instanceId, sourceId]);
  if (!rows.length) return { found: null };
  const link = toLink(rows[0]);
  return link === null ? null : { found: link };
}

/**
 * Verifică TOT ce e stocat pentru o instanță, în pagini.
 *
 * Parcurgerea completă la fiecare rulare programată, nu de la
 * `verified_through`: reluarea de acolo ar însemna să credem pe cuvânt
 * rezultatul rulării anterioare, iar o ruptură introdusă ÎN URMA ei — de
 * altcineva decât conducta, care e chiar cazul pentru care există verificarea
 * programată — n-ar mai fi găsită niciodată.
 */
export async function verifyStoredChain(
  db: Db, instanceId: string,
  known?: { firstSourceId: number | null; firstPrevHash: string | null },
  // Fluxul verificat, ca PARAMETRU cu valoare implicită. Apelanții reali nu-l
  // dau niciodată; există ca refuzul de mai jos să se poată vedea în suită, nu
  // doar sub o mutație. O gardă a cărei declanșare nu s-a văzut e o gardă
  // despre care nu se știe pe ce pică.
  stream: Stream | undefined = streamFor(CHAINED_STREAM),
): Promise<ChainVerdict> {
  if (!chainReadable(stream)) return cannotKnow();
  const table = (stream as Stream).table;
  const cursor = await confirmedThrough(db, instanceId, stream);
  if (cursor === null) {
    return {
      status: "unknown", checkedLinks: 0, verifiedThrough: null,
      firstSourceId: null, firstPrevHash: null, breakSourceId: null, fromLowEnd: false,
      detail: "nu pot citi filigranul confirmat, deci nu pot deosebi un gol de o ruptură",
    };
  }

  let after: number | null = null;
  let predecessor: Link | null = null;
  let total: ChainVerdict | null = null;

  for (;;) {
    const links = await page(db, table, instanceId, after);
    if (links === null) {
      return {
        status: "unknown", checkedLinks: total?.checkedLinks ?? 0,
        verifiedThrough: total?.verifiedThrough ?? null,
        firstSourceId: total?.firstSourceId ?? null,
        firstPrevHash: total?.firstPrevHash ?? null,
        breakSourceId: null, fromLowEnd: total?.fromLowEnd ?? false,
        detail: "un rând stocat nu se poate citi ca verigă",
      };
    }
    if (!links.length) break;

    const verdict = verifyLinks(links, predecessor, cursor,
                                total === null ? known : undefined);
    total = merge(total, verdict);
    if (verdict.status !== "ok") return total;

    predecessor = links[links.length - 1];
    after = predecessor.sourceId;
    if (links.length < PAGE) break;
  }

  return total ?? {
    status: "unknown", checkedLinks: 0, verifiedThrough: null,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null, fromLowEnd: true,
    detail: "instanța nu are niciun rând stocat",
  };
}

/**
 * Verifică fereastra abia sosită, ÎMPREUNĂ cu joncțiunea dinaintea ei.
 *
 * Joncțiunea e locul în care ar tăia cineva: o verificare care se uită doar în
 * interiorul lotului ratează exact legătura dintre ultimul rând al lotului N și
 * primul al lotului N+1.
 *
 * Se citește din BAZĂ, nu din payload: ce contează e ce a rămas stocat, nu ce
 * s-a trimis. Aceeași regulă ca la numărarea rândurilor din `lib/ingest.ts` —
 * efectul, nu intenția.
 */
export async function verifyIngestedWindow(
  db: Db, instanceId: string, fromSourceId: number,
  known?: { firstSourceId: number | null; firstPrevHash: string | null },
  // Ca la `verifyStoredChain`: implicit fluxul cu lanț, injectabil pentru probă.
  stream: Stream | undefined = streamFor(CHAINED_STREAM),
): Promise<ChainVerdict> {
  if (!chainReadable(stream)) return cannotKnow();
  const table = (stream as Stream).table;
  const cursor = await confirmedThrough(db, instanceId, stream);
  if (cursor === null) {
    return {
      status: "unknown", checkedLinks: 0, verifiedThrough: null,
      firstSourceId: null, firstPrevHash: null, breakSourceId: null, fromLowEnd: false,
      detail: "nu pot citi filigranul confirmat, deci nu pot deosebi un gol de o ruptură",
    };
  }
  const before = await predecessorOf(db, table, instanceId, fromSourceId);
  if (before === null) {
    return {
      status: "unknown", checkedLinks: 0, verifiedThrough: null,
      firstSourceId: null, firstPrevHash: null, breakSourceId: null, fromLowEnd: false,
      detail: "predecesorul lotului nu se poate citi ca verigă",
    };
  }

  let after: number | null = before.found ? before.found.sourceId : null;
  let predecessor = before.found;
  let total: ChainVerdict | null = null;
  for (;;) {
    const links = await page(db, table, instanceId, after);
    if (links === null) {
      return {
        status: "unknown", checkedLinks: total?.checkedLinks ?? 0,
        verifiedThrough: total?.verifiedThrough ?? null,
        firstSourceId: null, firstPrevHash: null, breakSourceId: null,
        fromLowEnd: total?.fromLowEnd ?? false,
        detail: "un rând stocat nu se poate citi ca verigă",
      };
    }
    if (!links.length) break;
    const verdict = verifyLinks(links, predecessor, cursor,
                                total === null ? known : undefined);
    total = merge(total, verdict);
    if (verdict.status !== "ok") return total;
    predecessor = links[links.length - 1];
    after = predecessor.sourceId;
    if (links.length < PAGE) break;
  }
  return total ?? {
    status: "unknown", checkedLinks: 0, verifiedThrough: null,
    firstSourceId: null, firstPrevHash: null, breakSourceId: null,
    fromLowEnd: before.found === null,
    detail: "nimic de verificat",
  };
}

/** Adună verdictul unei pagini peste ce s-a strâns până acum. */
function merge(total: ChainVerdict | null, page: ChainVerdict): ChainVerdict {
  if (total === null) return page;
  return {
    status: page.status,
    checkedLinks: total.checkedLinks + page.checkedLinks,
    verifiedThrough: page.verifiedThrough ?? total.verifiedThrough,
    firstSourceId: total.firstSourceId,
    firstPrevHash: total.firstPrevHash,
    breakSourceId: page.breakSourceId,
    detail: page.detail,
    // Autoritatea e a PRIMEI pagini: de acolo a pornit parcurgerea.
    fromLowEnd: total.fromLowEnd,
  };
}

// ---------------------------------------------------------------------------
// Consemnarea
// ---------------------------------------------------------------------------
/**
 * Scrie verdictul în `audit_chain_state` — dar numai ce are dreptul să scrie.
 *
 * ## Cine are autoritatea, și peste ce
 *
 * `status` e o propoziție despre TOT lanțul stocat, nu despre fereastra care
 * tocmai a sosit. Cele două sunt lucruri diferite, iar amestecarea lor a fost un
 * defect real: o verificare de la ingestie pornește deasupra unei rupturi vechi,
 * nu are cum s-o vadă, iese `ok` — și, scriind necondiționat, ștergea ruptura
 * consemnată. Loturile sosesc la `ship.interval_s` (implicit 60 s), deci o
 * ruptură reală rămânea consemnată cel mult un minut, apoi arhiva rupta arăta
 * `ok` până la următoarea trecere de cron.
 *
 * Deci autoritatea vine din verdict, nu din apelant: `fromLowEnd` spune dacă
 * parcurgerea a început chiar de la capătul de jos al copiei. Trei drumuri, cu
 * trei instrucțiuni diferite — nu un `IF` înăuntrul unui `ON DUPLICATE KEY
 * UPDATE`, fiindcă distincția e despre CINE VORBEȘTE, iar aia se citește în
 * TypeScript, nu într-o expresie SQL:
 *
 *   1. **ruptură** — oricine o vede o poate consemna. O fereastră E parte din
 *      lanț: o legătură ruptă în ea e o legătură ruptă în lanț;
 *   2. **`ok` de la capătul de jos** — singurul drum care poate SPUNE `ok` și
 *      curăța `break_source_id`. A citit totul, de jos până sus;
 *   3. **`ok` sau `unknown` dintr-o fereastră** — nu atinge `status` deloc. Mută
 *      doar `verified_through` (în sus, monoton) și momentul ultimei rulări.
 *
 * ## Se poate „vindeca" o ruptură?
 *
 * Da, dar numai prin (2): o trecere completă care nu mai găsește ruptura. Ce
 * NU se șterge niciodată e `broken_at` — „copia asta a fost văzută ruptă
 * odată" e un fapt permanent despre ea, iar o arhivă care a fost ruptă nu are
 * voie să arate din nou nouă. Cele două împreună se citesc exact: `status='ok'`
 * cu `broken_at` nenul înseamnă „acum se leagă, dar a fost ruptă atunci".
 *
 * Ceasul e AL BAZEI peste tot (`UTC_TIMESTAMP(6)`). O versiune anterioară scria
 * `last_run_at` cu ceasul bazei și `broken_at` cu al agregatorului, deci două
 * câmpuri ale aceluiași rând puteau spune ore diferite despre același moment.
 */
export async function recordVerdict(
  db: Db, instanceId: string, verdict: ChainVerdict, kind: "ingest" | "scheduled",
): Promise<void> {
  if (verdict.status === "broken") {
    await db.run(
      "INSERT INTO audit_chain_state " +
      "(instance_id, status, checked_links, verified_through, first_source_id, " +
      " first_prev_hash, break_source_id, break_detail, broken_at, last_run_at, " +
      " last_run_kind) " +
      "VALUES (?, 'broken', ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), ?) " +
      "ON DUPLICATE KEY UPDATE " +
      "  status = 'broken', checked_links = ?, verified_through = ?, " +
      "  break_source_id = ?, break_detail = ?, " +
      // Prima observație, nu ultima: ea spune ce interval trebuie cercetat.
      "  broken_at = COALESCE(broken_at, UTC_TIMESTAMP(6)), " +
      "  last_run_at = UTC_TIMESTAMP(6), last_run_kind = ?",
      [instanceId, verdict.checkedLinks, verdict.verifiedThrough,
       verdict.firstSourceId, verdict.firstPrevHash, verdict.breakSourceId,
       verdict.detail, kind,
       verdict.checkedLinks, verdict.verifiedThrough,
       verdict.breakSourceId, verdict.detail, kind]);
    return;
  }

  if (verdict.status === "ok" && verdict.fromLowEnd) {
    // Capătul de jos se scrie ca atare, nu prin `COALESCE`: drumul ăsta a citit
    // chiar începutul copiei, iar dacă a coborât (a sosit istorie mai veche)
    // valoarea NOUĂ e cea adevărată. O urcare n-ajunge aici — `verifyLinks` o
    // întoarce ca ruptură.
    await db.run(
      "INSERT INTO audit_chain_state " +
      "(instance_id, status, checked_links, verified_through, first_source_id, " +
      " first_prev_hash, break_source_id, break_detail, last_run_at, last_run_kind) " +
      "VALUES (?, 'ok', ?, ?, ?, ?, NULL, NULL, UTC_TIMESTAMP(6), ?) " +
      "ON DUPLICATE KEY UPDATE " +
      "  status = 'ok', checked_links = ?, verified_through = ?, " +
      "  first_source_id = ?, first_prev_hash = ?, " +
      "  break_source_id = NULL, break_detail = NULL, " +
      "  last_run_at = UTC_TIMESTAMP(6), last_run_kind = ?",
      [instanceId, verdict.checkedLinks, verdict.verifiedThrough,
       verdict.firstSourceId, verdict.firstPrevHash, kind,
       verdict.checkedLinks, verdict.verifiedThrough,
       verdict.firstSourceId, verdict.firstPrevHash, kind]);
    return;
  }

  // O fereastră care n-a pornit de jos, sau un verdict nedecis. NU atinge
  // `status`, `break_source_id` sau capătul de jos: n-a citit nimic despre ele.
  // `GREATEST` ca peste tot unde un cursor nu are voie să scadă.
  await db.run(
    "INSERT INTO audit_chain_state " +
    "(instance_id, status, checked_links, verified_through, last_run_at, last_run_kind) " +
    "VALUES (?, 'unknown', ?, ?, UTC_TIMESTAMP(6), ?) " +
    "ON DUPLICATE KEY UPDATE " +
    "  checked_links = ?, " +
    "  verified_through = GREATEST(COALESCE(verified_through, 0), COALESCE(?, 0)), " +
    "  last_run_at = UTC_TIMESTAMP(6), last_run_kind = ?",
    [instanceId, verdict.checkedLinks, verdict.verifiedThrough, kind,
     verdict.checkedLinks, verdict.verifiedThrough, kind]);
}

/**
 * Verificarea de după ingestie: citește ce s-a consemnat, verifică, consemnează.
 *
 * ## De ce lotul NU se refuză când lanțul e rupt
 *
 * Varianta refuzului e tentantă: rândurile n-ar intra, cursorul expeditorului
 * n-ar avansa, `ship:lag` ar crește pe server, iar operatorul ar vedea prin
 * canalul care există deja. E respinsă, și motivul e mai important decât
 * comoditatea:
 *
 * **ar transforma o detecție într-o pârghie de negare a dovezilor.** Cine poate
 * rupe lanțul o dată — adică exact atacatorul împotriva căruia există toată
 * arhitectura — ar opri prin asta TOATE expedierile viitoare. Detecția ruperii
 * ar deveni instrumentul prin care nu mai iese nimic de pe gazdă, iar arhiva de
 * dovezi s-ar opri fix în momentul în care începe să conteze.
 *
 * Deci rândurile se preiau, filigranul se ecouă, iar ruptura se CONSEMNEAZĂ. O
 * arhivă completă cu o ruptură marcată e strict mai bună decât o arhivă oprită.
 *
 * Consecința care rămâne, scrisă ca să nu pară livrată: agregatorul nu are
 * canal de alertare (martorul are Telegram, ăsta nu), deci consemnarea NU ajunge
 * azi la operator singură. Vezi `README.md`, secțiunea despre verificarea
 * lanțului.
 */
export async function verifyAfterIngest(
  db: Db, instanceId: string, fromSourceId: number,
): Promise<ChainVerdict> {
  const known = await readState(db, instanceId);
  const verdict = await verifyIngestedWindow(db, instanceId, fromSourceId, known ?? undefined);
  await recordVerdict(db, instanceId, verdict, "ingest");
  return verdict;
}

/** Ce s-a consemnat despre o instanță. `null` = NICIODATĂ verificată. */
export async function readState(
  db: Db, instanceId: string,
): Promise<{ status: string; firstSourceId: number | null; firstPrevHash: string | null;
            breakSourceId: number | null; verifiedThrough: number | null;
            lastRunAt: string | null } | null> {
  const rows = await db.all(
    "SELECT status, first_source_id, first_prev_hash, break_source_id, " +
    "verified_through, last_run_at FROM audit_chain_state WHERE instance_id = ?",
    [instanceId]);
  if (rows.length !== 1) return null;
  const row = rows[0];
  const num = (value: unknown): number | null =>
    value === null || value === undefined ? null : Number(value);
  return {
    status: String(row.status),
    firstSourceId: num(row.first_source_id),
    firstPrevHash: row.first_prev_hash === null || row.first_prev_hash === undefined
      ? null : String(row.first_prev_hash),
    breakSourceId: num(row.break_source_id),
    verifiedThrough: num(row.verified_through),
    lastRunAt: row.last_run_at === null || row.last_run_at === undefined
      ? null : String(row.last_run_at),
  };
}
