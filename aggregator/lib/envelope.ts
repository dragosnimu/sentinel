/**
 * Plicul de transport, văzut din partea care îl deschide.
 *
 * Geamănul care îl închide e `sentinel/report/envelope.py`, iar acolo e scris de
 * ce există: marginea găzduirii ăsteia are un WAF cu punctaj care inspectează
 * corpul JSON, `session_commands` e singurul flux al cărui conținut e format din
 * linii de comandă, iar patru–șase apariții ale unei comenzi banale („trei
 * treceri, șase picate", măsurat pe gazdă) urcă scorul peste prag și cererea
 * primește `403` de la margine. Cursorul avansează doar pe ecoul filigranului,
 * deci lotul se retrimite la infinit și tot ce vine după stă în spate.
 *
 * ## Ce NU se schimbă
 *
 * **Semnătura e peste octeții DINĂUNTRU.** `lib/signature.ts` primește ce a ieșit
 * de aici, nu ce a sosit pe sârmă, și rămâne HMAC peste forma canonică din
 * `sentinel/report/signing.py` — geamăna lui `lib/verify.ts`, identică la octet.
 * Plicul e transport, nu conținut semnat. Cine ar verifica semnătura peste
 * octeții plicului ar rupe contractul acela, iar simptomul ar fi 401 la fiecare
 * lot, adică exact ce arată o cheie greșită.
 *
 * **Ordinea din protocol rămâne:** antet `X-Sentinel-Instance` → se caută cheia
 * → HMAC peste octeții semnați → `payload.instance_id === antet`. Plicul se
 * deschide între pasul întâi și al doilea, fiindcă pasul al doilea are nevoie de
 * octeții dinăuntru; antetele nu intră niciodată în el.
 *
 * ## Amândouă formele, în timpul rulării
 *
 * Agregatorul se publică separat de gazdă și ÎNAINTEA ei — aceeași ordine ca la
 * martor în `docs/PLAN-arhitectura-distribuita.md`. Deci ruta trebuie să accepte
 * și JSON în clar (expeditorul de azi) și plic (expeditorul de mâine), fără
 * comutator și fără configurație: un comutator ar fi o a doua sursă de adevăr
 * despre ce e pe sârmă, iar dezacordul ei cu realitatea se vede ca 401.
 *
 * Discriminatorul e PREFIXUL, comparat în timp constant, nu o analiză JSON a
 * corpului: o analiză ar muta parsarea unui corp de până la `MAX_BODY_BYTES`
 * înaintea verificării semnăturii. Forma canonică începe întotdeauna cu
 * `{"batch_seq":` (cheile se emit sortate pe puncte de cod), deci nu poate fi
 * confundată cu un plic. Prețul e că ordinea câmpurilor din plic face parte din
 * contract; de-aia prefixul e o constantă la ambele capete, legată de un test.
 *
 * ## Plafonul la decomprimare
 *
 * Ruta e publică pentru cine cunoaște un identificator de instanță, iar
 * decomprimarea are loc ÎNAINTE de verificarea semnăturii — nu poate fi altfel,
 * fiindcă semnătura e peste ce iese din ea. Deci un plic mic care se desface în
 * gigaocteți e o cerere nesemnată care consumă memoria agregatorului.
 *
 * Două plafoane, și fac lucruri diferite:
 *
 *   * **`MAX_INFLATED_BYTES`** — cât are voie să iasă, în absolut. E chiar
 *     `MAX_BODY_BYTES`, adică exact cât acceptă și calea în clar: plicul nu
 *     lărgește nimic, poartă același corp pe alt drum. Se aplică ÎN TIMPUL
 *     decomprimării, nu după: verificat după, gigaoctetul e deja alocat, iar
 *     refuzul e o formalitate peste o mașină care a căzut.
 *   * **`MAX_INFLATE_RATIO`** — de câte ori are voie corpul semnat să fie mai
 *     mare decât plicul primit. Primul nu-l acoperă: un plic de 8 KB care se
 *     desface în 8 MB costă atacatorul de o mie de ori mai puțin decât munca pe
 *     care o provoacă.
 *
 * **De ce raportul NU e un filtru peste ce poate produce gzip**, fiindcă asta e
 * prima idee și e greșită: măsurat pe corpuri reale, un lot LEGITIM atinge orice
 * raport pe care îl atinge o bombă. `argv` e nemărginit la sursă și călătorește
 * neatins, deci un singur rând cu o linie de comandă lungă și repetitivă dă 992,
 * în timp ce 8 MB din același octet dau 1026 (tabelul întreg e în
 * `sentinel/report/envelope.py`). Un plafon sub 992 ar opri un lot valid pentru
 * totdeauna și ar da oricui are shell pe gazda monitorizată o comandă prin care
 * oprește arhiva externă — fix proprietatea pentru care există arhiva.
 *
 * Deci raportul e o inegalitate pe care EXPEDITORUL o respectă prin construcție,
 * umplând plicul până când e destul de mare, iar partea asta doar o verifică.
 * Plafonul nu poate opri un lot valid, iar amplificarea rămâne mărginită.
 */

import zlib from "node:zlib";

import { MAX_BODY_BYTES } from "./ingest";

/** Transformarea pe care o poartă plicul. Geamăna: `ENVELOPE_ENCODING` din
 *  `sentinel/report/envelope.py`. */
export const ENVELOPE_ENCODING = "gzip+base64";

/** Versiunea plicului. O versiune necunoscută se REFUZĂ cu mesaj, nu se citește
 *  „cât se poate": un plic v2 citit ca v1 ar produce alți octeți sub aceeași
 *  semnătură. */
export const ENVELOPE_VERSION = 1;

/**
 * Octeții după care se recunoaște un plic.
 *
 * Comparație pe prefix, nu analiză JSON — vezi capul modulului. Expeditorul
 * emite exact șirul ăsta la începutul corpului, iar acordul e ținut de
 * `tests/unit/test_transport_envelope.py`.
 */
export const ENVELOPE_PREFIX = '{"enc":"gzip+base64"';

/**
 * Cât are voie să iasă din decomprimare, în absolut.
 *
 * Scris ca `MAX_BODY_BYTES`, nu ca un număr propriu, fiindcă asta E afirmația:
 * plicul poartă același corp pe alt drum, deci acceptă exact cât acceptă calea
 * în clar. Un număr propriu ar putea diverge, iar divergența s-ar vedea ca un
 * flux oprit pe un lot pe care `config-check` îl declară legal.
 */
export const MAX_INFLATED_BYTES = MAX_BODY_BYTES;

/** De câte ori are voie corpul semnat să fie mai mare decât plicul primit.
 *  Geamăna: `MAX_INFLATE_RATIO` din `sentinel/report/envelope.py`. */
export const MAX_INFLATE_RATIO = 64;

/**
 * Cât are voie să aibă corpul PRIMIT, care poate fi un plic.
 *
 * Nu e o relaxare a plafonului de conținut, e condiția ca plicul să nu accepte
 * mai puțin decât calea pe care o înlocuiește. Un plic e base64 (`×4/3`) peste
 * gzip, iar gzip nu comprimă nimic pe un text de entropie mare — `argv` și
 * `params` sunt nemărginite la sursă și influențate de cine are shell pe gazda
 * monitorizată. Măsurat pe corpuri de entropie maximă, plicul iese cu până la
 * ~10% MAI MARE decât conținutul. Cu `MAX_BODY_BYTES` pus la citire, un lot care
 * azi pleacă neîmpachetat ar fi refuzat definitiv după împachetare — iar de pe
 * gazdă asta arată ca un agregator căzut, fiindcă `ship_once` nu deosebește un
 * non-2xx de altul.
 *
 * Derivat, nu ales: expansiunea maximă a lui gzip pe date necomprimabile e sub
 * 0,1% (blocuri stocate, 5 octeți la 65 535) plus antetul, iar base64 e exact
 * `ceil(n/3)*4`. Cei 4 KiB acoperă antetul plicului și rotunjirile.
 *
 * Plafonul pe CONȚINUT nu dispare: se aplică octeților semnați, în `POST`, o
 * singură dată pentru amândouă formele.
 */
export const MAX_WIRE_BYTES = Math.ceil(MAX_INFLATED_BYTES * 4 / 3) + 4096;

/**
 * Cât scoate zlib într-o bucată.
 *
 * Scris pe față fiindcă e marginea de eroare a opririi: decomprimarea se oprește
 * la prima bucată care trece de plafon, deci se pot produce cel mult
 * `plafon + INFLATE_CHUNK` octeți. Un test se sprijină pe numărul ăsta ca să
 * dovedească EFECTUL opririi — nu că plafonul e scris în cod, ci că octeții nu
 * s-au produs.
 */
export const INFLATE_CHUNK = 16 * 1024;

export type Inflated =
  | { ok: true; body: Buffer; produced: number }
  | { ok: false; kind: "over-cap" | "corrupt"; produced: number; detail: string };

/**
 * Decomprimare cu plafon aplicat ÎN TIMPUL ei.
 *
 * `produced` e numărul de octeți care CHIAR au ieșit din zlib înainte de a se
 * opri — nu mărimea reală a conținutului, pe care refuzul o face necunoscută.
 * E acolo ca să se poată proba efectul: un plafon verificat după decomprimare ar
 * întoarce același verdict, dar `produced` ar fi mărimea întreagă.
 *
 * Nu se folosește `gunzipSync(..., { maxOutputLength })`: face același lucru,
 * dar aruncă, deci nu poate spune câți octeți s-au produs — iar atunci singura
 * dovadă că oprirea e devreme ar fi citirea codului.
 */
export function inflateBounded(packed: Buffer, cap: number): Promise<Inflated> {
  return new Promise<Inflated>((resolve) => {
    const gunzip = zlib.createGunzip({ chunkSize: INFLATE_CHUNK });
    const chunks: Buffer[] = [];
    let produced = 0;
    let settled = false;
    const settle = (result: Inflated) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    gunzip.on("data", (chunk: Buffer) => {
      produced += chunk.length;
      if (produced > cap) {
        // ACUM, nu la sfârșit. `destroy()` oprește decomprimarea; restul
        // conținutului nu se mai produce și nu se mai alochează.
        gunzip.destroy();
        settle({ ok: false, kind: "over-cap", produced,
                 detail: `decomprimarea a depășit ${cap} de octeți` });
        return;
      }
      chunks.push(chunk);
    });
    gunzip.on("end", () => settle({ ok: true, body: Buffer.concat(chunks), produced }));
    gunzip.on("error", (err: Error) => settle({
      ok: false, kind: "corrupt", produced,
      // `destroy()` de mai sus produce și el un `error` („premature close"),
      // dar `settled` e deja pus, deci nu poate rescrie verdictul.
      detail: err.message,
    }));
    gunzip.end(packed);
  });
}

export type Unwrapped =
  | { ok: true; body: Buffer; wrapped: boolean }
  | { ok: false; status: number; detail: string };

/** `true` dacă octeții primiți încep cu prefixul plicului. */
export function looksWrapped(raw: Buffer): boolean {
  return raw.length >= ENVELOPE_PREFIX.length
    && raw.subarray(0, ENVELOPE_PREFIX.length).toString("latin1") === ENVELOPE_PREFIX;
}

/** Base64 strict: alfabetul standard, umplutura la locul ei, lungime multiplu de 4.
 *
 *  `Buffer.from(s, "base64")` e ÎNGĂDUITOR — sare peste ce nu recunoaște —, deci
 *  fără verificarea asta un corp stricat pe drum ar produce tăcut alți octeți,
 *  iar refuzul ar veni de la gzip sau de la semnătură, cu alt nume. */
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Octeții peste care se verifică semnătura, oricare ar fi forma de pe sârmă.
 *
 * Un corp care nu e plic se întoarce NEATINS: e chiar el corpul semnat. Asta e
 * jumătatea „acceptă amândouă formele", și e o ramură fără nicio prelucrare
 * tocmai ca să nu poată schimba nimic pentru expeditorul aflat azi în producție.
 */
export async function unwrap(raw: Buffer): Promise<Unwrapped> {
  if (!looksWrapped(raw)) return { ok: true, body: raw, wrapped: false };

  let outer: unknown;
  try {
    outer = JSON.parse(raw.toString("utf8"));
  } catch {
    return { ok: false, status: 400, detail: "plicul de transport nu e JSON valid" };
  }
  if (outer === null || typeof outer !== "object" || Array.isArray(outer)) {
    return { ok: false, status: 400, detail: "plicul de transport nu e un obiect JSON" };
  }
  const env = outer as Record<string, unknown>;

  if (env.enc !== ENVELOPE_ENCODING) {
    return { ok: false, status: 400,
             detail: `plic cu enc="${String(env.enc)}"; agregatorul cunoaște ` +
                     `"${ENVELOPE_ENCODING}"` };
  }
  if (env.v !== ENVELOPE_VERSION) {
    // Refuz explicit, nu „citește cât poți": un plic de altă versiune citit cu
    // regulile ăstea ar produce alți octeți sub aceeași semnătură.
    return { ok: false, status: 400,
             detail: `plic de versiunea ${String(env.v)}; agregatorul cunoaște ` +
                     `versiunea ${ENVELOPE_VERSION} și are nevoie de o publicare` };
  }
  if (typeof env.body !== "string" || env.body === ""
      || env.body.length % 4 !== 0 || !BASE64.test(env.body)) {
    // Lungimea multiplu de 4 se cere separat de alfabet: `Buffer.from` ar
    // decoda și un șir trunchiat, tăcut, iar octeții rezultați ar fi alții
    // decât cei semnați — refuzul ar veni de la gzip sau de la semnătură, cu
    // alt nume decât cauza.
    return { ok: false, status: 400,
             detail: "câmpul `body` al plicului nu e base64 valid" };
  }

  const packed = Buffer.from(env.body, "base64");
  // Plafonul care se aplică e cel mai mic dintre cele două, ca decomprimarea să
  // se oprească la primul depășit; care anume a fost se spune în mesaj, fiindcă
  // reacția e alta — unul cere un lot mai mic pe expeditor, celălalt e un defect
  // al împachetării.
  const byRatio = raw.length * MAX_INFLATE_RATIO;
  const cap = Math.min(MAX_INFLATED_BYTES, byRatio);
  const out = await inflateBounded(packed, cap);
  if (!out.ok) {
    if (out.kind === "corrupt") {
      return { ok: false, status: 400,
               detail: `plicul nu se poate decomprima: ${out.detail}` };
    }
    return {
      ok: false, status: 413,
      detail: byRatio < MAX_INFLATED_BYTES
        ? `plicul are ${raw.length} octeți și se desface în peste ${cap}; ` +
          `raportul acceptat e ${MAX_INFLATE_RATIO}. Nimic nu a fost citit din ` +
          "el. Expeditorul umple plicul tocmai ca inegalitatea asta să fie " +
          "adevărată, deci un refuz aici e un defect de împachetare, nu un lot " +
          "prea mare."
        : `plicul se desface în peste ${MAX_INFLATED_BYTES} de octeți, adică ` +
          "peste plafonul de corp al agregatorului. Nimic nu a fost citit din " +
          "el; micșorează ship.max_rows_per_batch pe expeditor.",
    };
  }
  return { ok: true, body: out.body, wrapped: true };
}
