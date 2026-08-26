/**
 * Primește un lot de rânduri de la o instanță Sentinel.
 *
 *     POST /api/sentinel/sync
 *     X-Sentinel-Instance: <instance_id>
 *     X-Sentinel-Signature: <hmac-sha256 hexa peste octeții corpului>
 *
 *     { "instance_id": "...", "batch_seq": 4471, "sent_at": "...", "max_age_s": 300,
 *       "cursors": { "audit_log": 91233 },
 *       "rows":    { "audit_log": [...] } }
 *
 * Răspuns: `{ "ok": true, "accepted": { "audit_log": 91233 }, "instance": "..." }`
 *
 * Corpul poate sosi și împachetat pentru transport (`gzip` + `base64` într-un
 * plic JSON) — vezi `lib/envelope.ts` pentru marginea cu WAF care a cerut-o.
 * Ruta acceptă amândouă formele în timpul rulării, fără comutator, fiindcă se
 * publică ÎNAINTEA gazdei. Plicul e transport: semnătura rămâne peste octeții
 * canonici dinăuntru, iar antetele rămân în afara lui.
 *
 * ## Ordinea verificării, și de ce toate trei sunt necesare
 *
 *   1. antetul X-Sentinel-Instance → caută cheia   (necunoscut → 401)
 *   2. (dacă e plic) se deschide, mărginit          (bombă → 413, stricat → 400)
 *   3. verifică HMAC peste OCTEȚII SEMNAȚI          (eșec → 401)
 *   4. cere payload.instance_id === valoarea din antet  (eșec → 401)
 *
 * Pasul 2 e ÎNTRE 1 și 3, și nu poate fi altundeva: cheia se caută după antet,
 * iar HMAC-ul e peste ce iese din plic. Pe calea în clar pasul 2 nu atinge nimic
 * — octeții primiți SUNT octeții semnați.
 *
 * Aceeași proprietate ca la martor (`app/api/sentinel/beat/route.ts`) și
 * din același motiv: fără pasul 3, cine deține cheia lui A trimite un payload
 * care pretinde că e B, semnat cu cheia lui A, cu antetul lui A — și e
 * înregistrat ca B. Aici consecința e mai mare decât un contor greșit: rândurile
 * lui A ar intra în lanțul de audit al lui B, iar un lanț făcut din două istorii
 * arată RUPT pentru totdeauna. Verificarea din E2.4b ar raporta atunci o
 * falsificare pe două servere sănătoase.
 *
 * Spre deosebire de martor, **nu există instanță implicită**. Toleranța de acolo
 * există fiindcă expeditorul de heartbeat aflat în producție nu trimite antetul;
 * ruta asta e nouă la ambele capete, iar un `default` aici ar amesteca istoriile
 * a două servere sub o singură identitate — exact ce nu trebuie.
 *
 * 404 pentru o instanță necunoscută ar fi și el o greșeală: ar confirma care
 * identificatori există, pe o rută care nu cere nimic ca să întrebe.
 *
 * ## Filigranul: ce înseamnă un 200 de aici
 *
 * `sentinel/report/shipper.py` avansează cursorul unui flux **numai** dacă
 * răspunsul conține `accepted.<flux>` exact egal cu filigranul trimis. Deci un
 * `accepted` scris de ruta asta e o promisiune verificabilă: *rândurile de până
 * la id-ul ăsta sunt în arhivă*. Regulile care ies din asta:
 *
 *   * `cursors.<flux>` trebuie să fie chiar cel mai mare `id` din
 *     `rows.<flux>`. Un filigran mai mare ar cere expeditorului să treacă peste
 *     rânduri pe care nu le-a trimis nimeni;
 *   * un flux care nu a intrat — necunoscut, prea mare, stricat, sau al cărui
 *     efect nu s-a putut confirma — **lipsește din `accepted`**. Nu primește un
 *     filigran gol, nu primește unul inventat, și nu e ecouat „optimist";
 *   * dacă NIMIC nu a intrat, răspunsul nu e 200. Un 200 cu `accepted: {}` ar fi
 *     tot un refuz, dar scris în singurul dialect pe care un edge CDN sau un
 *     vhost greșit rutat îl poate imita.
 *
 * ## De ce un flux necunoscut NU respinge tot lotul
 *
 * Prima versiune a rutei ăsteia refuza lotul întreg cu 400 dacă apărea un flux
 * necunoscut, ca „am înțeles jumătate" să nu împartă un cod de stare cu „am
 * înțeles tot". Argumentul era greșit, și e important de spus de ce, ca să nu
 * fie reintrodus:
 *
 *   * capul lui `shipper.py:12-31` scrie pe o pagină întreagă că **un 200 nu
 *     dovedește nimic**, iar singurul discriminator e ECOUL. Un refuz care se
 *     sprijină pe codul de stare importă înapoi exact criteriul declarat
 *     nedemn de încredere;
 *   * `accepted_watermarks` iterează pe FLUX, nu pe lot, tocmai ca să
 *     supraviețuiască acceptării parțiale. Respingerea totală face funcția aia
 *     inutilă;
 *   * 400 e deja codul pentru rând stricat, lot vechi și filigran greșit, deci
 *     nu poartă distincția nici acum;
 *   * `shipper.py:337-351` cere explicit direcția opusă la celălalt capăt: „try
 *     per flux, fluxul stricat rămâne pe loc, restul pleacă". Izolarea per flux
 *     la expeditor e inutilă dacă receptorul respinge tot POST-ul.
 *
 * Consecința concretă a variantei vechi: în ziua în care E3 adaugă `detections`
 * pe serverul monitorizat înainte ca agregatorul să primească migrația,
 * `audit_log` — singura copie a lanțului de audit pe care root pe mașina
 * monitorizată n-o poate șterge — s-ar fi oprit complet din cauza altui flux.
 * Ambele variante sunt sigure pentru cursor; numai una păstrează disponibilitatea.
 *
 * ## Cât de vorbăreț e un refuz
 *
 * Înainte de verificarea semnăturii: nimic. `{"error":"refuzat"}`, fiindcă cine
 * primește răspunsul nu a dovedit că e cineva, iar un refuz care explică ajută la
 * ghicit.
 *
 * După ea: mesajul întreg, cu numele câmpului. Cine a trecut de semnătură are
 * cheia, deci nu află nimic ce nu știa — iar `shipper.py` scrie primii 200 de
 * octeți ai corpului în jurnalul de pe server, care e singurul diagnostic pe care
 * îl are operatorul când loturile nu intră. Un „refuzat" opac acolo ar fi o
 * pană tăcută cu un cod de stare pe ea.
 *
 * Excepția e `500 nu sunt configurat`: se dă ÎNAINTE de semnătură, fiindcă
 * altfel n-ar putea fi dat deloc — fără cheie nu se poate verifica nimic. E
 * diferența dintre „nu sunt configurat" și „te-am refuzat", adică exact ce
 * citește cel care instalează, printr-un `curl`, fără acces la jurnale.
 */

import { NextResponse } from "next/server";

import { CryptoConfigError, SecretBox } from "@/lib/crypto";
import { ConfigError, readMasterSecret } from "@/lib/env";
import { getPool, queryableDb } from "@/lib/db";
import { MAX_WIRE_BYTES, unwrap } from "@/lib/envelope";
import { INSTANCE_HEADER, lookupInstanceKey } from "@/lib/ship-keys";
import {
  MAX_BODY_BYTES, MAX_ROWS_PER_BATCH, ingestStream, noteBatch,
} from "@/lib/ingest";
import { verifyAfterIngest } from "@/lib/chain";
import { applyPrune, checkPruneList } from "@/lib/prune";
import { SIGNATURE_HEADER, signatureValid } from "@/lib/signature";
import { knownStreamNames, streamFor } from "@/lib/streams";
import type { Db } from "@/lib/migrate";

/**
 * Cache: obligatoriu oprit, dar NEDOVEDIT de aici.
 *
 * Aplicația e servită printr-un CDN, iar un răspuns de ingestie pus în cache ar
 * întoarce un ecou vechi peste un filigran nou — adică ar face expeditorul să
 * avanseze cursorul peste rânduri care n-au ajuns niciodată. Motivul e cel din
 * `app/api/sentinel/beat/route.ts`, pasul 6.
 *
 * Ce NU dovedește nimic de aici: `next build` marchează ruta `ƒ` (dinamică) și
 * cu, și fără liniile astea — un Route Handler POST e dinamic oricum. Deci
 * exportul se păstrează fiindcă e declarația explicită care supraviețuiește unei
 * rute viitoare cu GET, nu fiindcă l-am văzut având vreun efect. Ce se poate
 * dovedi e antetul de pe răspuns, și aia e probată de
 * `tests/sync.route.test.ts`, testul „răspunsul poartă no-store — un ecou din
 * cache e un filigran vechi".
 */
export const dynamic = "force-dynamic";
export const revalidate = 0;

/**
 * Runtime-ul, scris pe față — și ăsta CHIAR e păzit de build.
 *
 * Măsurat: mutat pe `"edge"`, `next build` iese cu 1 și tipărește
 * `Import trace: node:module -> ./lib/db.ts`, fiindcă acolo nu există nici
 * driverul de MySQL, nici `node:crypto` cu HMAC. E singura dintre declarațiile
 * astea pe care o greșeală o face zgomotoasă la construire, nu tăcută în
 * producție.
 */
export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

/** Deliberat sărac: un endpoint care explică de ce a refuzat ajută la ghicit. */
const REFUSED = { error: "refuzat" };

/** Prospețimea implicită a lotului, în secunde. Mai mare decât cei 120 s ai
 *  beaconului fiindcă loturile pot fi mari (§E2 din plan). */
const DEFAULT_MAX_AGE_S = 300;

/**
 * Cea mai mare fereastră de prospețime acceptată.
 *
 * `max_age_s` vine din payload, deci e semnat: nu poate fi umflat de cineva din
 * afară. Ce apără plafonul e o greșeală de configurație — un `ship.max_age_s`
 * pus din neatenție la o valoare uriașă ar face verificarea de prospețime o
 * formalitate, tăcut, iar un lot capturat ar putea fi reluat oricând.
 *
 * Numărul e ACELAȘI cu bornele din `sentinel/config.py`, care refuză la
 * încărcare orice `ship.max_age_s` peste el. Fără perechea aia, plafonul de aici
 * ar fi o constrângere nouă pusă pe configurația expeditorului, pe care
 * expeditorul n-o cunoaște și n-o poate descoperi: `ship_once` tratează orice
 * non-2xx la fel și nu citește corpul, deci fluxul s-ar opri definitiv pe o
 * valoare pe care `config-check` o declară validă. Acordul e ținut de
 * `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`.
 */
const MAX_AGE_CEILING_S = 86_400;

/** Codul de stare al fiecărui fel de eșec pe flux, și cât de „grav" e când
 *  trebuie ales unul singur pentru un lot din care n-a intrat nimic. */
const STREAM_STATUS = { invalid: 400, oversize: 413, incomplete: 500, unavailable: 503 };
const STREAM_RANK = { invalid: 0, oversize: 1, incomplete: 2, unavailable: 3 };
type ProblemKind = keyof typeof STREAM_STATUS;
type StreamProblem = { stream: string; kind: ProblemKind; detail: string };

function refuse(): NextResponse {
  return NextResponse.json(REFUSED, { status: 401, headers: NO_STORE });
}

function reject(status: number, error: string): NextResponse {
  return NextResponse.json({ error }, { status, headers: NO_STORE });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Corpul, mărginit — citit în bucăți, nu bufferizat întreg și măsurat după.
 *
 * Vezi `MAX_BODY_BYTES` pentru ce apără. `content-length` se verifică întâi
 * fiindcă e gratuit, dar nu e o garanție: e scris de client. Plafonul care
 * contează e cel de pe flux, care oprește citirea la depășire.
 *
 * Plafonul de AICI e `MAX_WIRE_BYTES`, nu `MAX_BODY_BYTES`, și diferența e o
 * reparație, nu o relaxare: corpul primit poate fi un plic, iar un plic e
 * base64 peste gzip. Pe un corp pe care gzip nu-l poate comprima — text de
 * entropie mare, iar `argv` și `params` sunt nemărginite la sursă și
 * influențate de cine are shell pe gazda monitorizată — plicul iese cu ~10%
 * mai MARE decât conținutul. Cu plafonul de conținut pus aici, un lot care azi
 * pleacă neîmpachetat ar fi refuzat definitiv după împachetare, iar cauza s-ar
 * vedea ca un agregator căzut. Plafonul pe CONȚINUT rămâne, dar se aplică
 * octeților semnați, după deschiderea plicului — vezi `POST`.
 */
async function readBody(req: Request): Promise<Buffer | "too-large"> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_WIRE_BYTES) return "too-large";

  const stream = req.body;
  if (!stream) return Buffer.alloc(0);
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_WIRE_BYTES) {
      // Se oprește ACUM. Restul nu se mai citește și nu se mai alocă.
      await reader.cancel();
      return "too-large";
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

export async function POST(req: Request) {
  // Configurația proprie, înaintea oricărei citiri: fără secretul principal nu
  // se poate deschide nicio cheie de instanță, deci nu se poate verifica nimic.
  let box: SecretBox;
  let db: Db;
  try {
    box = new SecretBox(readMasterSecret());
    db = queryableDb(getPool());
  } catch (err) {
    if (err instanceof ConfigError || err instanceof CryptoConfigError) {
      console.error("[aggregator] configurație lipsă sau invalidă:", (err as Error).message);
      return reject(500, "nu sunt configurat");
    }
    throw err;
  }

  // Pasul 1. Fără antet nu există instanță implicită — vezi capul modulului.
  //
  // Căutarea cheii e ÎNAINTEA citirii corpului, dinadins: o cerere de la o
  // identitate pe care n-o cunoaștem se refuză fără să i se aloce nimic.
  const instanceId = req.headers.get(INSTANCE_HEADER)?.trim() || "";
  let key;
  try {
    key = await lookupInstanceKey(db, instanceId, box);
  } catch (err) {
    // O bază care nu răspunde NU e „instanță necunoscută". Confundate, toate
    // serverele sănătoase ar primi 401 iar operatorul ar căuta o cheie greșită.
    console.error("[aggregator] nu pot citi instanțele:", (err as Error).message);
    return reject(503, "baza de date nu răspunde");
  }
  if (!key.ok) {
    if (key.reason === "unconfigured") {
      console.error("[aggregator] instanță fără cheie de expediere instalată");
      return reject(500, "nu sunt configurat");
    }
    if (key.reason === "unreadable") {
      // Altă linie în jurnal decât cea de sus, fiindcă reacția e alta: ori
      // SENTINEL_AGGREGATOR_SECRET a fost rotit, ori rândul a fost umblat.
      console.error("[aggregator] cheia unei instanțe nu se poate descifra");
      return reject(500, "nu sunt configurat");
    }
    // Fără identificator în mesaj: valoarea vine din antet, adică e text ales de
    // cine trimite. `console.warn`, nu `console.error`, ca la martor — oricine
    // poate provoca linia asta trimițând un antet, iar un contor de erori umplut
    // de un scanner e un contor pe care nu se mai uită nimeni.
    console.warn(`[aggregator] lot refuzat (${key.reason})`);
    return refuse();
  }

  // Pasul 2. Octeții bruți, nu obiectul reparsat: semnătura e peste ce s-a
  // trimis. Bucăți, nu `arrayBuffer()`: vezi `readBody`.
  const raw = await readBody(req);
  if (raw === "too-large") {
    console.warn("[aggregator] corp peste plafon, oprit la citire");
    return reject(413,
      `corpul depășește ${MAX_WIRE_BYTES} de octeți și a fost oprit la citire. ` +
      "Nimic nu a fost scris; micșorează ship.max_rows_per_batch pe expeditor.");
  }

  // Plicul de transport, ÎNTRE identitate și semnătură — și nicăieri altundeva.
  //
  // Ordinea e cerută de protocol, nu de comoditate: antetul se citește ca să se
  // găsească cheia (pasul 1, deja făcut), semnătura e peste octeții SEMNAȚI, iar
  // ăia sunt cei dinăuntrul plicului. Deci plicul se deschide aici, iar de la
  // linia următoare încolo nimic din rută nu mai știe că a existat: `signed` e
  // ce s-ar fi primit oricum pe calea în clar.
  //
  // Amândouă formele se acceptă în timpul rulării, fără comutator: agregatorul
  // se publică ÎNAINTEA gazdei, deci trebuie să fie tolerant întâi. Vezi
  // `lib/envelope.ts` pentru pana care a cerut plicul și pentru plafoanele de
  // decomprimare. Un corp care nu e plic se întoarce neatins.
  const opened = await unwrap(raw);
  if (!opened.ok) {
    // Înaintea semnăturii, deci `console.warn` și nu `error`: oricine cunoaște
    // un identificator de instanță poate provoca linia asta, iar un contor de
    // erori umplut de un scanner e un contor pe care nu se mai uită nimeni.
    console.warn(`[aggregator] plic refuzat: ${opened.detail}`);
    // Mesajul e explicit, deși e înaintea semnăturii. Aceeași alegere ca la
    // 413-ul de mai sus și din același motiv: singurul diagnostic pe care îl are
    // operatorul gazdei sunt primii 200 de octeți ai corpului, scriși de
    // `ship_once` în jurnal la orice non-2xx. Un „refuzat" opac aici ar fi o
    // pană tăcută cu un cod de stare pe ea.
    return reject(opened.status, opened.detail);
  }
  const signed = opened.body;

  // Plafonul pe CONȚINUT, aplicat octeților semnați — o singură regulă pentru
  // amândouă formele: *corpul semnat nu are voie să treacă de `MAX_BODY_BYTES`,
  // oricum ar fi călătorit*. Pe calea cu plic e deja adevărat (decomprimarea se
  // oprește acolo), deci linia asta apără calea în clar, unde citirea se oprește
  // abia la plafonul de sârmă. Scrisă o dată, ca cele două căi să nu poată
  // accepta lucruri diferite.
  if (signed.length > MAX_BODY_BYTES) {
    console.warn("[aggregator] corp semnat peste plafon");
    return reject(413,
      `corpul depășește ${MAX_BODY_BYTES} de octeți. ` +
      "Nimic nu a fost scris; micșorează ship.max_rows_per_batch pe expeditor.");
  }

  if (!signatureValid(signed, req.headers.get(SIGNATURE_HEADER) || "", key.secret)) {
    console.warn("[aggregator] semnătură invalidă");
    return refuse();
  }

  let payload: unknown;
  try {
    payload = JSON.parse(signed.toString("utf8"));
  } catch {
    return reject(400, "corpul nu e JSON");
  }
  if (!isPlainObject(payload)) return reject(400, "corpul nu e un obiect JSON");

  // Pasul 3. Niciun `?? default`: identitatea din payload trebuie să fie scrisă
  // și să fie exact cea din antet.
  if (typeof payload.instance_id !== "string" || payload.instance_id !== instanceId) {
    console.warn("[aggregator] identitatea din payload nu se potrivește cu antetul");
    return refuse();
  }

  // Prospețimea. Semnătura dovedește autenticitatea, nu că lotul e de acum: fără
  // fereastra asta, o cerere capturată o dată poate fi reluată la nesfârșit.
  const maxAge = readMaxAge(payload.max_age_s);
  if (maxAge === null) {
    return reject(400, `max_age_s trebuie să fie un întreg între 1 și ${MAX_AGE_CEILING_S}`);
  }
  if (typeof payload.sent_at !== "string") return reject(400, "sent_at lipsește");
  const age = (Date.now() - Date.parse(payload.sent_at)) / 1000;
  if (!Number.isFinite(age) || Math.abs(age) > maxAge) {
    // `Math.abs`: și un lot din viitor e refuzat. Un ceas plecat înainte pe
    // expeditor ar face altfel fereastra de reluare arbitrar de lungă.
    console.warn("[aggregator] lot prea vechi sau din viitor", age);
    return reject(400, `sent_at e la ${Math.round(age)} s de acum, iar max_age_s e ${maxAge}`);
  }

  const batchSeq = payload.batch_seq;
  if (typeof batchSeq !== "number" || !Number.isSafeInteger(batchSeq) || batchSeq <= 0) {
    return reject(400, "batch_seq trebuie să fie un întreg pozitiv exact");
  }

  // Fluxurile. `rows` și `cursors` descriu același lot, deci trebuie să vorbească
  // despre exact aceleași fluxuri: un filigran fără rânduri ar cere avansarea
  // cursorului peste un gol, iar rânduri fără filigran n-ar putea fi confirmate.
  // Asta e o malformare a LOTULUI, nu a unui flux, deci oprește tot.
  if (!isPlainObject(payload.rows)) return reject(400, "rows lipsește sau nu e un obiect");
  if (!isPlainObject(payload.cursors)) return reject(400, "cursors lipsește sau nu e un obiect");
  const rows = payload.rows;
  const cursors = payload.cursors;
  const names = Object.keys(rows);
  if (names.length === 0) return reject(400, "lotul nu conține niciun flux");

  const cursorNames = Object.keys(cursors);
  if (cursorNames.length !== names.length
      || !names.every((name) => Object.prototype.hasOwnProperty.call(cursors, name))) {
    return reject(400, `rows și cursors nu vorbesc despre aceleași fluxuri ` +
                       `(rows: ${names.join(", ")}; cursors: ${cursorNames.join(", ")})`);
  }

  // Ingestia, FLUX CU FLUX. Un flux care nu intră nu-i oprește pe ceilalți și
  // nu primește filigran — vezi „De ce un flux necunoscut NU respinge tot lotul".
  const accepted: Record<string, number | string> = {};
  const problems: StreamProblem[] = [];
  /** Cel mai mic `source_id` preluat, per flux cu lanț. */
  const chained: number[] = [];

  for (const name of names) {
    const stream = streamFor(name);
    if (stream === undefined) {
      problems.push({ stream: name, kind: "invalid",
        detail: `fluxul "${name}" nu e cunoscut de agregator (cunoscute: ` +
                `${knownStreamNames().join(", ")}); are nevoie de o migrație a ` +
                "agregatorului. Rândurile lui NU au fost preluate." });
      continue;
    }
    const list = rows[name];
    if (!Array.isArray(list)) {
      problems.push({ stream: name, kind: "invalid", detail: `rows.${name} nu e un tablou` });
      continue;
    }
    if (list.length > MAX_ROWS_PER_BATCH) {
      problems.push({ stream: name, kind: "oversize",
        detail: `rows.${name} are ${list.length} rânduri, limita e ${MAX_ROWS_PER_BATCH}. ` +
                "Nimic nu a fost scris și nimic nu a fost trunchiat; micșorează " +
                "ship.max_rows_per_batch pe expeditor." });
      continue;
    }
    const watermark = cursors[name];
    // Felul cerut vine din DECLARAȚIA fluxului, nu din ce a sosit. Acceptat
    // după forma valorii, un flux întreg căruia i-ar sosi un șir ar trece mai
    // departe și s-ar scrie în cealaltă coloană de cursor — iar `lib/chain.ts`,
    // care citește `last_source_id` ca poziție confirmată, ar vedea un cursor
    // care nu se mai mișcă.
    //
    // Marginea de 190 e lățimea coloanei `last_source_key`. Refuzată aici, cu
    // numele câmpului; lăsată să treacă, o bază pornită fără modul strict ar
    // tăia-o tăcut la scriere, iar filigranul stocat n-ar mai fi cel trimis —
    // deci ecoul n-ar mai potrivi NICIODATĂ, pe un lot perfect valid.
    const wantsText = stream.watermarkKind === "text";
    //
    // ASCII imprimabil, și e o restricție DELIBERATĂ, nu o lene. Trei locuri
    // trebuie să aleagă același maxim: Python compară șirurile pe puncte de cod,
    // JavaScript pe unități UTF-16, MariaDB pe octeți. Pentru orice caracter din
    // afara planului de bază, JavaScript ordonează ALTFEL decât celelalte două —
    // iar dezacordul se vede ca un cursor care nu mai avansează niciodată, pe un
    // lot valid. Pe ASCII, toate trei sunt provabil aceeași ordine.
    const badWatermark = wantsText
      ? typeof watermark !== "string" || watermark === "" || watermark.length > 190
        || !/^[\x20-\x7E]+$/.test(watermark)
      : typeof watermark !== "number" || !Number.isSafeInteger(watermark) || watermark <= 0;
    if (badWatermark) {
      problems.push({ stream: name, kind: "invalid",
        detail: `cursors.${name} trebuie să fie ` +
                (wantsText ? "un șir nevid, ASCII imprimabil, de cel mult 190 de caractere"
                           : "un întreg pozitiv exact") });
      continue;
    }

    const result = await ingestStream(db, instanceId, stream, list,
                                     watermark as number | string, batchSeq);
    if (result.ok) {
      accepted[name] = result.watermark;
      if (stream.chained) chained.push(result.lowest);
      continue;
    }
    problems.push({ stream: name, kind: result.kind, detail: result.detail });
  }

  // Verificarea lanțului, DUPĂ ce rândurile sunt dovedit stocate și ÎNAINTE de
  // răspuns. Se uită și la joncțiunea cu lotul anterior, fiindcă acolo ar tăia
  // cineva; citește din bază, nu din payload — vezi `lib/chain.ts`.
  //
  // Nu schimbă verdictul lotului: o ruptură se consemnează, nu refuză preluarea.
  // Argumentul (negarea dovezilor) e scris la `verifyAfterIngest`.
  //
  // Într-un `try` propriu: rândurile sunt deja dovedite în arhivă, iar o
  // verificare care nu poate rula n-are voie să anuleze un ecou meritat. Ce nu
  // are voie e să treacă TĂCUT, deci eșecul se scrie în jurnal.
  for (const lowest of chained) {
    try {
      const verdict = await verifyAfterIngest(db, instanceId, lowest);
      if (verdict.status === "broken") {
        console.error(`[aggregator] LANȚ RUPT pentru ${instanceId}: ${verdict.detail}`);
      }
    } catch (err) {
      console.error(`[aggregator] lot preluat, dar lanțul nu s-a putut verifica ` +
                    `pentru ${instanceId}: ${(err as Error).message}`);
    }
  }

  for (const problem of problems) {
    // Instanța e autentificată aici, deci identificatorul din jurnal e o valoare
    // verificată, nu text ales de cine trimite. `error` doar pentru ce e al
    // nostru — un lot stricat e al expeditorului și n-are voie să umple contorul
    // de erori al agregatorului.
    const line = `[aggregator] ${instanceId}/${problem.stream}: ${problem.detail}`;
    if (problem.kind === "invalid" || problem.kind === "oversize") console.warn(line);
    else console.error(line);
  }

  if (Object.keys(accepted).length === 0) {
    // Nimic nu a intrat. Aici NU se răspunde 200: un `accepted` gol e tot un
    // refuz, dar scris în singurul dialect pe care un CDN îl poate imita.
    const worst = problems.reduce((a, b) => STREAM_RANK[b.kind] > STREAM_RANK[a.kind] ? b : a);
    return reject(STREAM_STATUS[worst.kind],
                  problems.map((p) => p.detail).join(" · "));
  }

  // Reconcilierea, DUPĂ ce rândurile au intrat. Ordinea contează: un rând care
  // sosește în lotul ăsta e deja în tabel când se compară cu lista, deci nu
  // poate fi șters de propria lui sosire.
  //
  // Refuzul nu oprește lotul — rândurile sunt treaba, reconcilierea e igienă —
  // dar ajunge în `refused`, ca motivul să apară în jurnalul de pe server.
  const pruned: Record<string, number> = {};
  if (payload.prune !== undefined) {
    if (!isPlainObject(payload.prune)) {
      problems.push({ stream: "prune", kind: "invalid",
        detail: "prune nu e un obiect" });
    } else {
      for (const [name, value] of Object.entries(payload.prune)) {
        const verdict = checkPruneList(streamFor(name), name, value);
        if (!verdict.ok) {
          problems.push({ stream: name, kind: "invalid", detail: verdict.detail });
          console.warn(`[aggregator] listă de reconciliere refuzată pentru ` +
                       `${instanceId}: ${verdict.detail}`);
          continue;
        }
        try {
          const gone = await applyPrune(db, streamFor(name)!, instanceId,
                                        verdict.keys);
          if (gone > 0) {
            pruned[name] = gone;
            // La nivel de informare, nu de eroare: e purtarea corectă a
            // mecanismului. Dar se SCRIE, fiindcă e o ștergere, iar o ștergere
            // care nu lasă urmă e una pe care n-o poate explica nimeni.
            console.warn(`[aggregator] reconciliere ${name} pentru ${instanceId}: ` +
                         `${gone} rânduri șterse la sursă au fost șterse și aici`);
          }
        } catch (err) {
          console.error(`[aggregator] reconcilierea ${name} pentru ${instanceId} ` +
                        `a eșuat: ${(err as Error).message}`);
        }
      }
    }
  }

  // Contabilitate, DUPĂ ce ecoul e deja meritat. Un `UPDATE` de diagnostic care
  // eșuează nu are voie să blocheze un flux: rândurile sunt dovedit în arhivă,
  // iar refuzul ecoului aici ar opri sincronizarea din cauza unei coloane pe
  // care nu se uită nimeni în timp real.
  try {
    await noteBatch(db, instanceId, batchSeq);
  } catch (err) {
    console.error(`[aggregator] lot preluat, dar contabilitatea instanței ` +
                  `${instanceId} nu s-a scris: ${(err as Error).message}`);
  }

  // `refused` nu e cerut de protocol și `shipper.py` nu se uită la el — ce
  // citește el e absența fluxului din `accepted`, care e deja acolo. Există ca
  // motivul să ajungă în jurnalul de pe server (primii 200 de octeți ai
  // corpului), fiindcă altfel un flux care nu avansează n-are nicio explicație
  // pe partea pe care se uită operatorul.
  //
  // `instance` se ecouă ca la martor (`beat/route.ts:193-197`): e singurul mod
  // în care cel care instalează vede, dintr-un `curl`, sub ce identitate a
  // intrat lotul.
  const body: Record<string, unknown> = { ok: true, accepted, instance: instanceId };
  // Informativ, ca `refused`: expeditorul nu se uită la el, dar operatorul care
  // dă un `curl` vede că o ștergere chiar a avut loc.
  if (Object.keys(pruned).length) body.pruned = pruned;
  if (problems.length) {
    body.refused = Object.fromEntries(problems.map((p) => [p.stream, p.detail]));
  }
  return NextResponse.json(body, { headers: NO_STORE });
}

/**
 * Fereastra de prospețime cerută de lot, sau `null` dacă e scrisă greșit.
 *
 * Absentă → implicitul. Prezentă și nevalidă → EROARE, niciodată căderea tăcută
 * pe implicit: aceeași regulă ca la numerele din `lib/env.ts`, fiindcă „am
 * schimbat fereastra" / „nu s-a schimbat nimic" e chiar tiparul din `CLAUDE.md`.
 *
 * Un `Number(payload.max_age_s || 300)` ar fi avut o gaură mai urâtă: pe o
 * valoare care nu e număr, `Number(...)` dă `NaN`, iar `Math.abs(age) > NaN` e
 * FALS — adică orice vechime ar fi trecut.
 */
function readMaxAge(raw: unknown): number | null {
  if (raw === undefined || raw === null) return DEFAULT_MAX_AGE_S;
  if (typeof raw !== "number" || !Number.isSafeInteger(raw)
      || raw < 1 || raw > MAX_AGE_CEILING_S) {
    return null;
  }
  return raw;
}
