/**
 * Primește semnalul de la Sentinel.
 *
 * Nu judecă nimic — doar verifică autenticitatea, respinge reluările și
 * înregistrează. Judecata e în /api/sentinel/check, fiindcă întrebarea „a tăcut
 * prea mult?" nu poate fi pusă de o rută care se execută doar când sosește un
 * semnal.
 *
 * ## Ordinea verificării, și de ce toate cinci sunt necesare
 *
 *   1. antetul X-Sentinel-Instance → identitatea pretinsă
 *   2. CORPUL, mărginit la MAX_BODY_BYTES, pentru oricine  (peste → 413)
 *   3. caută cheia după antet                              (necunoscut → 401)
 *   4. verifică HMAC peste OCTEȚII BRUȚI                   (eșec → 401)
 *   5. identitatea RETRASĂ se refuză AICI, după semnătură  (→ 401)
 *   6. cere payload.instance_id === valoarea din antet     (eșec → 401)
 *
 * Pasul 2 e înaintea căutării cheii, iar asta e o alegere, nu ordinea evidentă —
 * motivul întreg e lângă el. Pe scurt: cu corpul mărginit, citirea lui pentru
 * oricine costă cel mult 8 KiB și face ca refuzurile de la pașii 3 și 5 să fie
 * nedistinse din afară, ceea ce nu erau. Nedistinse, nu identice: drumul
 * necunoscutului se întoarce înaintea lui HMAC, iar reziduul măsurat e ~10 µs,
 * față de 19 ms înainte de plafon.
 *
 * Pasul 5 e după pasul 4, nu înainte, și asta e o reparație, nu o scăpare.
 * Retragerea rămâne o revocare — refuzul e același 401 în ambele ordini — dar
 * ceea ce se schimbă e ÎNȚELESUL liniei de jurnal. `lib/beat-keys.ts` declară
 * linia aia „singura urmă a unei retrageri făcute din greșeală", iar o
 * identitate retrasă din greșeală tace fără să alarmeze. Cu refuzul înaintea
 * semnăturii, linia se scria pentru ORICE cerere cu antetul potrivit — un
 * scanner de internet o producea la fel de bine ca serverul viu — deci nu putea
 * deosebi „mașina mea mai bate sub identitatea asta" de „nu s-a întâmplat
 * nimic". Mecanismul avea deja dovada în mână și o arunca: un beat semnat corect
 * nu poate veni decât de la deținătorul cheii.
 *
 * Pasul 6 e cel care se uită ușor și e cel care contează la mai multe instanțe:
 * fără el, cine deține cheia lui A trimite un payload care pretinde că e B,
 * semnat cu cheia lui A, cu antetul lui A — și martorul îl înregistrează sub B.
 * Rezultatul e că un server compromis poate ține verde un server pe care tocmai
 * l-a oprit, ceea ce e chiar minciuna împotriva căreia există tot mecanismul.
 *
 * 404 pentru o instanță necunoscută ar fi și el o greșeală: ar confirma care
 * identificatori există și care nu, pe o rută care nu cere nimic ca să întrebe.
 */

import { NextResponse } from "next/server";
import { readInstance, writeInstance, type Beat, type InstanceState } from "@/lib/store";
import { SIGNATURE_HEADER, signatureValid, countersAdvanced } from "@/lib/verify";
import { DEFAULT_INSTANCE, INSTANCE_HEADER, lookupInstanceKey } from "@/lib/beat-keys";

// Obligatoriu. Site-ul e servit prin CDN, iar o rută de heartbeat pusă în cache
// ar întoarce vesel ultimul răspuns bun ore în șir — exact minciuna pe care
// mecanismul ăsta există ca să o prevină.
export const dynamic = "force-dynamic";
export const revalidate = 0;

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" };

/** Deliberat sărac în detalii: un endpoint care explică de ce a refuzat ajută la ghicit. */
const REFUSED = { error: "refuzat" };

/** Cât din eticheta primită păstrăm. Un nume, nu un canal de date. */
const MAX_LABEL = 64;

/**
 * Cel mai mare corp de semnal care se citește.
 *
 * Ruta e publică și nu cere nimic ca să întrebe, deci fără plafon oricine de pe
 * internet putea face procesul martorului să tamponeze date arbitrare. Măsurat
 * pe 15 august 2026, înainte de plafon: 16 MiB acceptați și hashuiți în 19 ms.
 * Nu e o gaură de autentificare — corpul e refuzat oricum la semnătură — dar
 * martorul e singura mașină pe care un atacator cu root pe serverul monitorizat
 * NU o controlează, iar memoria lui e cea care nu are voie să fie a lui.
 *
 * Numărul nu e ales din instinct. Un semnal maximal — etichetă de 64 de
 * caractere cu diacritice, `audit_head` de 64, toate contoarele la nouă cifre —
 * are 576 de octeți, măsurat. 8 KiB e de paisprezece ori atât: destul cât un
 * câmp nou adăugat în protocol să nu fie refuzat tăcut, destul de puțin cât să
 * nu conteze că se citește pentru oricine.
 *
 * Un semnal care ar depăși vreodată plafonul NU e tăcut la capătul monitorizat:
 * `send_once` scrie codul și primii 200 de octeți ai corpului în jurnalul de pe
 * gazdă, iar corpul de mai jos numește limita.
 *
 * Geamănul e `MAX_BODY_BYTES` din `lib/ingest.ts`, cu aceeași purtare
 * — verificare pe `content-length`, oprire în flux, 413 — dar NU cu aceeași
 * valoare: acolo plafonul e derivat din câte rânduri încape un lot, aici dintr-un
 * obiect cu formă fixă. Sunt două numere care măsoară lucruri diferite, deci
 * n-au de ce să fie egale și nimic din suită nu le compară unul cu celălalt.
 */
const MAX_BODY_BYTES = 8_192;

/**
 * Corpul, mărginit — citit în bucăți, nu bufferizat întreg și măsurat după.
 *
 * `content-length` se verifică întâi fiindcă e gratuit, dar nu e o garanție: e
 * scris de client, și o cerere în bucăți (`Transfer-Encoding: chunked`) nu îl
 * are deloc. Plafonul care contează e cel de pe flux, care oprește citirea la
 * depășire cu `reader.cancel()`.
 *
 * Se întoarce `Buffer`, nu `string`, ca sentinela `"too-large"` să nu poată fi
 * confundată cu un corp care conține chiar textul ăla.
 */
async function readBody(req: Request): Promise<Buffer | "too-large"> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return "too-large";

  const stream = req.body;
  if (!stream) return Buffer.alloc(0);
  const reader = stream.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      // Ce oprește citirea e `return`-ul: nu se mai emite niciun `read()`, deci
      // sursa nu mai e trasă. `cancel()` nu e paza — măsurat, scos, suita rămâne
      // verde — ci înștiințarea: îi spune SURSEI, care într-un server adevărat e
      // socketul, că nu mai citește nimeni. Ordinea contează doar pentru claritate.
      await reader.cancel();
      return "too-large";
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/**
 * Octeții primiți, ca text, exact cum îi dădea `req.text()`.
 *
 * `TextDecoder`, nu `Buffer.toString("utf8")`: primul scoate un BOM de la
 * început, ca `Response.text()`, al doilea nu. Se alege cel care păstrează
 * purtarea de dinainte, ca schimbarea de la `req.text()` la citirea mărginită să
 * fie doar despre plafon.
 *
 * Cu o notă onestă, fiindcă altfel rândul de mai sus pare păzit și nu e: mutația
 * la `Buffer.toString("utf8")` trece VERDE pe toată suita martorului, măsurat pe
 * 15 august 2026. Nu e o gaură de acoperire, e o echivalență — singura diferență
 * dintre cele două e un BOM la început, octeți pe care niciun expeditor nu-i
 * semnează, iar un corp care îi are e refuzat oricum: cu BOM păstrat cade la
 * semnătură (401), cu BOM scos cade la `JSON.parse` (400). Nu există intrare pe
 * care alegerea asta să o facă acceptată, deci nu există test care s-o fixeze.
 * Pentru restul octeților — inclusiv UTF-8 stricat — cele două decodări dau
 * aceiași U+FFFD.
 */
function asText(body: Buffer): string {
  return new TextDecoder().decode(body);
}

/**
 * Fereastra de prospețime folosită când semnalul nu declară una.
 *
 * Aceeași valoare ca `beacon.max_age_s` din `sentinel/config.py`. Expeditorul o
 * trimite la fiecare rundă, dar protocolul o are opțională: un implicit e
 * singurul mod în care un expeditor mai vechi nu cade pe o fereastră de zero,
 * adică pe „tot ce trimiți e deja vechi".
 */
const DEFAULT_MAX_AGE_S = 120;

/**
 * Cea mai mare fereastră de prospețime acceptată.
 *
 * `max_age_s` vine din payload, deci e semnat: nu poate fi umflat de cineva din
 * afară. Ce apără plafonul e o greșeală de configurație — un `beacon.max_age_s`
 * pus din neatenție la o valoare uriașă ar transforma verificarea de prospețime
 * într-o formalitate, tăcut, iar un semnal captat ar putea fi reluat oricând.
 *
 * Numărul e ACELAȘI cu `MAX_AGE_CEILING_S` din
 * `app/api/sentinel/sync/route.ts`, ca cele două receptoare ale
 * aceleiași instalări să nu ceară lucruri diferite.
 *
 * ## Perechea de pe gazda monitorizată
 *
 * `beacon.max_age_s` e refuzat la ÎNCĂRCAREA configurației peste valoarea asta
 * (`sentinel/config.py`), iar acordul dintre cele două fișiere e ținut de
 * `tests/unit/test_beacon.py::test_the_two_ends_agree_on_the_beat_freshness_ceiling`,
 * care citește CHIAR fișierul ăsta și pică dacă vreunul dintre capete se mută.
 *
 * Perechea a lipsit până pe 15 august 2026, iar argumentul cu care lipsea era
 * că refuzul de aici e „zgomotos din ambele părți". **E fals**, și e fals exact
 * unde contează — pe o instanță NOUĂ, adică fix momentul în care cineva scrie
 * `beacon.max_age_s`. Măsurat cu `beacon.max_age_s: 100000` (o confuzie
 * milisecunde/secunde e plauzibilă; implicitul e 120):
 *
 *   beat            → 400, corpul numește câmpul
 *   /status agregat → 200 „ok", cu instanța nouă drept `no-beat`
 *
 * `no-beat` nu se numără și nu alarmează NICIODATĂ (vezi `status/route.ts`) —
 * dinadins, fiindcă altfel o cheie rămasă în configurație ar ține panoul roșu la
 * nesfârșit. Pe o instalare care a bătut deja, argumentul cu zgomotul ține
 * (instanța trece în `silent` și sună); pe una nouă nu ținea deloc.
 *
 * Deci plafonul de aici apără ce a apărat mereu — fără el, un `1e9` semnat
 * corect e o fereastră de reluare de treizeci și unu de ani, tăcută și
 * exploatabilă — dar **nu se mai justifică prin „refuzul se aude"**. Zgomotul
 * depinde de dacă instanța a bătut vreodată, adică de ceva ce receptorul nu
 * controlează și nu poate ști în clipa în care operatorul greșește.
 *
 * Regula, scrisă ca să nu se mai repete: **fiecare plafon la RECEPTOR primește o
 * margine la încărcarea configurației plus un test care citește ambele
 * fișiere.** Aici asta există acum; `ship` o avea deja.
 *
 * Iar capătul monitorizat nu mai tace nici el: `sentinel/report/beacon.py`
 * scrie rezultatul fiecărei runde în `beacon:delivered` / `beacon:refused`, de
 * unde `check_beacon_delivery` din `sentinel/selfcheck/checks.py` raportează
 * „martorul nu a acceptat NICIO bătaie". Fără el, o gazdă nouă refuzată la
 * fiecare rundă rămânea verde pe toate suprafețele deodată.
 */
const MAX_AGE_CEILING_S = 86_400;

/**
 * Fereastra de prospețime cerută de semnal, sau `null` dacă e scrisă greșit.
 *
 * Absentă → implicitul. Prezentă și nevalidă → REFUZ, niciodată căderea tăcută
 * pe implicit.
 *
 * Ce era scris aici: `Number(payload.max_age_s || 120)`. Pe orice valoare care
 * nu e număr — un șir, un obiect — `Number(...)` dă `NaN`, iar
 * `Math.abs(age) > NaN` e **fals**. Comparația nu eșua, TRECEA: fereastra de
 * reluare devenea practic nemărginită, adică verificarea de prospețime exista și
 * nu verifica nimic — chiar tiparul din CLAUDE.md, o gardă care raportează
 * „nimic în neregulă" fiindcă nu potrivește niciodată.
 *
 * Nu e o gaură de autentificare: semnătura se verifică înainte, deci ca s-o
 * folosești îți trebuie deja cheia HMAC. E pierderea apărării împotriva reluării
 * exact pentru scenariul pentru care există martorul — root pe mașina
 * monitorizată care retrimite un semnal captat ca să spună „sunt viu" despre o
 * mașină oprită de ore.
 *
 * Plafonul acoperă cealaltă jumătate, care nu e `NaN`: un `1e9` semnat perfect
 * corect e o fereastră de treizeci și unu de ani, la fel de tăcută.
 *
 * `Number.isSafeInteger` respinge dintr-o dată `NaN`, `±Infinity`, fracțiile și
 * orice peste 2^53-1 — aceeași verificare pe care o face `lib/verify.ts` la
 * semnare, deci un număr pe care expeditorul nu-l poate semna nu e nici aici o
 * fereastră validă.
 */
function readMaxAge(raw: unknown): number | null {
  if (raw === undefined || raw === null) return DEFAULT_MAX_AGE_S;
  if (typeof raw !== "number" || !Number.isSafeInteger(raw)
      || raw < 1 || raw > MAX_AGE_CEILING_S) {
    return null;
  }
  return raw;
}

/**
 * Caractere care nu au voie să ajungă într-o etichetă.
 *
 * `\p{Cc}` — caractere de control, care rup formatarea mesajului Telegram.
 * `\p{Cs}` — surogate NEPERECHEATE (cu fanionul `u`, o pereche validă e un
 * singur punct de cod și nu se potrivește aici). Un surogat singuratic e text
 * imposibil de codificat în UTF-8; ajuns în corpul cererii către Telegram, e
 * genul de caracter pentru care API-ul respinge TOT mesajul — adică oprește
 * alerta, nu o urâțește. Tăierea la `MAX_LABEL` se face înaintea curățării,
 * fiindcă tocmai tăierea poate rupe o pereche validă în două.
 */
const UNSAFE_LABEL_CHARS = /[\p{Cc}\p{Cs}]/gu;

export async function POST(req: Request) {
  // Pasul 1. Lipsa antetului NU e o eroare: expeditorul aflat azi în producție
  // nu îl trimite, iar martorul se actualizează înaintea serverului.
  const instanceId = req.headers.get(INSTANCE_HEADER)?.trim() || DEFAULT_INSTANCE;

  // Pasul 2. Corpul, mărginit, ÎNAINTEA oricărui refuz — inclusiv al celui
  // pentru o identitate necunoscută. Ordinea asta e o schimbare, și e opusul
  // celei din `app/api/sentinel/sync/route.ts`, deci merită scris de
  // ce.
  //
  // Cât timp corpul nu avea plafon, refuzul timpuriu al unei identități
  // necunoscute era singurul mod de a nu tampona date arbitrare pentru cineva
  // fără nicio cheie. Prețul lui era o deosebire măsurabilă din afară: refuzul
  // de retragere e DUPĂ verificarea semnăturii, deci o identitate retrasă ajunge
  // pe calea care citește corpul și una necunoscută nu — 19,0 ms față de 0,2 ms
  // pe un corp de 16 MiB.
  //
  // Cu plafon, refuzul timpuriu nu mai apără mare lucru și strică mai mult decât
  // repară: un corp peste plafon ar primi 413 pentru o identitate cunoscută și
  // 401 pentru una necunoscută, adică un oracol de existență pe CODUL de stare —
  // mai curat și mai ieftin decât cel pe timp pe care îl elimină. Citit pentru
  // toți, plafonul costă cel mult 8 KiB per cerere și face ca refuzurile să fie
  // din nou nedistinse: același cod, același corp, aceeași cale.
  //
  // Ce rămâne deosebibil, spus fără menajamente: un corp peste plafon primește
  // 413 indiferent de identitate, deci se poate afla că ruta ARE un plafon și
  // cam unde e. Aia nu spune nimic despre ce identificatori există.
  const body = await readBody(req);
  if (body === "too-large") {
    console.warn("[watcher] corp peste plafon, oprit la citire");
    return NextResponse.json(
      { error: `corpul depășește ${MAX_BODY_BYTES} de octeți și a fost oprit la citire` },
      { status: 413, headers: NO_STORE },
    );
  }

  const key = lookupInstanceKey(instanceId);

  // Cheia cu care se verifică semnătura, și dacă identitatea e retrasă. Cele
  // două se despart aici fiindcă o identitate retrasă ARE de obicei cheia încă
  // citibilă (`SENTINEL_BEACON_SECRET` nu se poate șterge de pe gazdă), iar
  // cheia aia e singurul mod de a dovedi CINE a trimis. `retired` nu autorizează
  // nimic — vezi pasul 5.
  let secret: string | undefined;
  let retired = false;
  if (key.ok) {
    secret = key.secret;
  } else if (key.reason === "retired") {
    retired = true;
    secret = key.secret;
  } else if (key.reason === "unconfigured") {
    // 500, nu 401. Diferența dintre „nu sunt configurat" și „te-am refuzat" e
    // exact ce citește cel care instalează, prin curl, fără acces la jurnale.
    console.error("[watcher] nicio cheie de instanță configurată");
    return NextResponse.json({ error: "nu sunt configurat" }, { status: 500, headers: NO_STORE });
  }

  if (secret === undefined) {
    // Instanță necunoscută — sau retrasă ȘI fără cheie citibilă, ceea ce e
    // exact același lucru din toate punctele de vedere: nu avem cu ce verifica
    // nimic, deci nu putem afirma nimic. Aceeași linie, dinadins. `/status`
    // numește deja starea asta `unknown` și explică de ce nu e un eufemism:
    // după retragere martorul chiar nu mai știe de identitatea aia.
    console.warn("[watcher] instanță necunoscută");
    return NextResponse.json(REFUSED, { status: 401, headers: NO_STORE });
  }

  // Pasul 4. Corpul brut, nu obiectul reparsat: semnătura e peste octeții
  // trimiși, iar o re-serializare poate schimba ordinea cheilor sau formatul
  // numerelor. Tot de aici vine și faptul că adăugarea unui câmp nou în payload
  // nu strică verificarea — nu e nevoie de lockstep între cele două capete.
  const raw = asText(body);
  const signature = req.headers.get(SIGNATURE_HEADER) || "";
  if (!signatureValid(raw, signature, secret)) {
    console.warn("[watcher] semnătură invalidă");
    return NextResponse.json(REFUSED, { status: 401, headers: NO_STORE });
  }

  // Pasul 5. Retragerea, DUPĂ semnătură. Refuzul e același 401, dar acum se știe
  // cine l-a provocat: semnătura e validă, deci expeditorul deține cheia unei
  // mașini scoase din uz. Ori mașina aia e vie și încă bate — adică o retragere
  // făcută din greșeală, iar tăcerea ei nu mai alarmează pe nimeni — ori cineva
  // i-a păstrat cheia. Amândouă cer un om.
  //
  // De-aia `console.error` și nu `console.warn`: nivelul urmează cine poate
  // produce linia. Celelalte refuzuri de aici sunt avertismente fiindcă le
  // provoacă orice scanner cu un antet; asta nu se poate provoca fără cheie, și
  // e singura urmă a unei retrageri greșite. Nivelul s-a mutat odată cu ordinea,
  // nu în locul ei.
  //
  // Fără identificator în mesaj, ca la orice refuz: valoarea vine din antetul
  // cererii, adică e text ales de cine trimite.
  //
  // Codul rămâne 401, ca pentru o instanță necunoscută. Un cod propriu — 410
  // „Gone" — ar spune unui necunoscut că identificatorul a existat cândva AICI,
  // adică exact scurgerea pentru care refuzul e 401 și nu 404.
  //
  // Codul de stare și corpul sunt identice cu ale unui refuz obișnuit, iar
  // corpul se citește și se mărginește la fel pentru amândouă: pasul 2 e
  // înaintea căutării cheii, deci nimeni nu mai poate afla din COMPORTAMENTUL
  // rutei dacă un identificator există.
  //
  // Ce NU se poate spune, și s-a spus aici o zi: că e „aceeași cale". Nu e.
  // Drumul identității necunoscute se întoarce înaintea lui `signatureValid`,
  // deci sare peste HMAC. Măsurat de verificator pe 15 august 2026, 300 de
  // repetări intercalate pe un corp de 8000 de octeți: rezidual stabil de ~10 µs.
  // Înainte de plafon diferența era 19,0 ms față de 0,2 ms, deci e o reducere de
  // ~1900×, iar 10 µs stau cu trei ordine de mărime sub jitterul oricărei rețele.
  // „Nedistinse din afară" e adevărat; „aceeași cale" ar fi fost încă o afirmație
  // mai mare decât măsurătoarea, adică exact ce s-a corectat aici înainte.
  //
  // Ce verifică `retired.test.ts`: codul, corpul, și că ambele refuzuri trec
  // prin plafon (un corp peste el dă 413 în ambele cazuri). Timpul nu se poate
  // asserta stabil într-un test și nu e promis nicăieri.
  if (retired) {
    console.error("[watcher] semnal SEMNAT CORECT de la o identitate retrasă");
    return NextResponse.json(REFUSED, { status: 401, headers: NO_STORE });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(raw);
  } catch {
    return NextResponse.json(REFUSED, { status: 400, headers: NO_STORE });
  }

  // Pasul 6. Un payload fără `instance_id` e al instanței implicite — asta e
  // toleranța care ține serverul de azi funcțional. Orice ALTĂ nepotrivire e un
  // refuz, fiindcă înseamnă că cineva semnează cu o cheie și pretinde alt nume.
  //
  // Tipul se verifică înainte de conversie: `String({toString: "x"})` ARUNCĂ,
  // iar un payload ostil dar semnat corect ar transforma un refuz într-un 500.
  // Nu e o ocolire — cine îl trimite are deja cheia și își strică propriul
  // semnal — dar o rută care crapă în loc să refuze e mai greu de diagnosticat.
  const raw_id = payload.instance_id;
  const claimed = raw_id === undefined || raw_id === null || raw_id === ""
    ? DEFAULT_INSTANCE
    : typeof raw_id === "string" ? raw_id : null;
  if (claimed === null || claimed !== instanceId) {
    console.warn("[watcher] identitatea din payload nu se potrivește cu antetul");
    return NextResponse.json(REFUSED, { status: 401, headers: NO_STORE });
  }

  // Verificarea semnăturii dovedește autenticitatea, nu prospețimea. Fără
  // fereastra asta, un semnal valid capturat o dată poate fi reluat la
  // nesfârșit, iar martorul ar vedea „viu" pe o mașină oprită de o săptămână.
  const maxAge = readMaxAge(payload.max_age_s);
  if (maxAge === null) {
    // Corpul NUMEȘTE câmpul, spre deosebire de celelalte refuzuri de aici.
    // Regula „sărac în detalii" apără împotriva ghicitului, iar la punctul ăsta
    // nu mai e nimic de ghicit: se ajunge doar cu semnătura verificată. Cine
    // primește răspunsul e chiar expeditorul, care scrie codul și primii 200 de
    // octeți ai corpului în jurnalul de pe serverul monitorizat — singura
    // suprafață pe care o greșeală de configurație se poate citi, fiindcă
    // jurnalul găzduirii martorului nu ajunge la operator.
    console.warn("[watcher] max_age_s nu e un întreg în intervalul acceptat");
    return NextResponse.json(
      { error: `max_age_s trebuie să fie un întreg între 1 și ${MAX_AGE_CEILING_S}` },
      { status: 400, headers: NO_STORE },
    );
  }
  const sentAt = new Date(String(payload.sent_at || ""));
  const age = (Date.now() - sentAt.getTime()) / 1000;
  if (!Number.isFinite(age) || Math.abs(age) > maxAge) {
    console.warn("[watcher] semnal prea vechi sau din viitor", age);
    return NextResponse.json(REFUSED, { status: 400, headers: NO_STORE });
  }

  const previous: InstanceState = (await readInstance(instanceId)) ?? {};
  const seq = Number(payload.seq || 0);
  if (previous.last && seq <= previous.last.seq) {
    // Reluare, sau două expeditoare care trimit în paralel SUB ACEEAȘI
    // IDENTITATE. Ambele sunt anormale și niciuna nu are voie să treacă drept
    // semnal proaspăt.
    //
    // Anomalia s-a restrâns odată cu instanțele, nu a dispărut. Ce s-a
    // restrâns e ce ține fiecare instanță: secvența, ca și restul stării, se
    // citește și se scrie DOAR din fișierul instanței (`lib/store.ts`), deci
    // două servere diferite nu se pot atinge nici prin secvență, nici prin
    // înregistrare. Două procese care împart același `instance_id` și aceeași
    // cheie rămân exact la fel de anormale ca înainte — de obicei o gazdă
    // clonată dintr-un backup, adică fix cazul pentru care identitatea nu e
    // nici hostname, nici machine-id — și tot aici sunt prinse.
    console.warn("[watcher] seq nu a crescut", seq, previous.last.seq);
    return NextResponse.json(REFUSED, { status: 409, headers: NO_STORE });
  }

  const label = String(payload.instance_label ?? "")
    .trim().slice(0, MAX_LABEL).replace(UNSAFE_LABEL_CHARS, "");
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
    ...(label ? { label } : {}),
    selfcheck: (payload.selfcheck as Beat["selfcheck"]) || {
      worst: "unknown", checks: 0, bad: 0, ran_at: null,
    },
  };

  // Se scrie DOAR fișierul instanței ăsteia. Nicio altă instanță nu e citită și
  // rescrisă pe drumul ăsta, deci un semnal simultan de la alt server nu are ce
  // să piardă.
  await writeInstance(instanceId, {
    ...previous,
    last: beat,
    // Momentul în care contoarele s-au mișcat ultima dată, nu cel în care a
    // sosit ultimul semnal. Diferența dintre ele E detecția de conductă
    // moartă, iar comparația se face cu semnalul ANTERIOR AL ACESTEI
    // instanțe — cu un singur contor global, două servere care alternează
    // semnalele ar arăta veșnic ca și cum ar avansa amândouă.
    counters_moved_at: countersAdvanced(previous.last, beat)
      ? beat.received_at
      : previous.counters_moved_at || beat.received_at,
  });

  // Identitatea sub care a fost înregistrat semnalul se întoarce înapoi: e
  // singurul mod în care cel care instalează vede, dintr-un curl, că antetul a
  // ajuns unde credea. Un antet scris greșit ar crea altfel tăcut o a doua
  // instanță, verde, în timp ce prima moare.
  return NextResponse.json({ ok: true, seq, instance: instanceId }, { headers: NO_STORE });
}
