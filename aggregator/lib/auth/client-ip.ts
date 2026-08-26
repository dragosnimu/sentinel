/**
 * Adresa clientului — și de ce, pe găzduirea asta, e o întrebare deschisă.
 *
 * ## Ce se știe, măsurat, și ce NU se știe
 *
 * Aplicația e servită printr-un CDN: `watcher/INCARCARE-HOSTINGER.md` notează
 * antetul `Server: hcdn` văzut pe răspunsuri. CDN-ul TERMINĂ conexiunea, deci
 * procesul Node nu vede niciodată adresa clientului: o vede pe a CDN-ului.
 * Singura sursă de adresă e un ANTET, iar în Next 15 nici măcar `NextRequest.ip`
 * nu mai există.
 *
 * Ce NU s-a putut măsura de aici: **ce antet pune Hostinger și dacă îl
 * CURĂȚĂ la margine.** Nu există acces la marginea CDN-ului, iar o cerere de
 * probă ar spune doar ce vede aplicația, nu dacă valoarea a fost înlocuită sau
 * doar transmisă mai departe. Diferența e totul: dacă antetul e transmis,
 * atunci el e o valoare aleasă de client.
 *
 * ## Consecința, scrisă ca regulă
 *
 * **Un antet pe care clientul îl poate scrie nu poate purta o decizie.** Și nu
 * doar fiindcă atacatorul l-ar putea ocoli rotind valori — asta ar face
 * limitarea per IP inutilă, adică teatru. Mai rău: ar face-o o ARMĂ. Cine
 * trimite douăzeci de încercări eșuate cu antetul pus pe adresa operatorului
 * blochează operatorul, din afară, fără să știe nicio parolă.
 *
 * Deci implicitul aici e „nu am adresa clientului”, iar consecințele lui sunt
 * duse până la capăt în `lib/auth/ratelimit.ts`:
 *
 *   * stratul per IP **nu se aplică** (nu se aplică „mai slab", nu se aplică
 *     pe o valoare pusă de client);
 *   * plafonul per utilizator devine mai STRICT, ca să compenseze — vezi
 *     `maxFailedLogins`;
 *   * plafonul global rămâne singurul strat care nu depinde de identitatea
 *     sursei.
 *
 * Ce se scrie în coloanele `INET6` când adresa nu e de încredere: **NULL**, nu
 * valoarea pretinsă. O coloană tipată care conține o adresă aleasă de atacator
 * nu e o urmă de audit, e o minciună cu index pe ea; `login_attempts.detail`
 * poartă valoarea pretinsă, marcată ca atare, unde nimeni n-o poate confunda cu
 * un fapt.
 *
 * ## Cum devine de încredere
 *
 * Operatorul pune `AGGREGATOR_CLIENT_IP_HEADER` cu numele antetului pe care
 * l-a MĂSURAT ca fiind scris de margine (procedura e în
 * `aggregator/README.md`). Variabila nu e în `lib/env.ts` cu celelalte fiindcă
 * absența ei nu e o eroare de configurare: e starea implicită, și e singura
 * stare pe care o putem justifica fără o măsurătoare pe gazdă.
 *
 * Și atunci se verifică EFECTUL, nu declarația: dacă antetul pe care operatorul
 * l-a declarat „curățat la margine" sosește cu o LISTĂ (`a, b`), asta e dovadă
 * că marginea l-a adăugat la ce era, nu că l-a înlocuit — deci nu e curățat, și
 * nu se are încredere în el, oricât ar spune configurația. Un antet care se
 * transmite mai departe e chiar cazul în care clientul își alege adresa.
 *
 * ## Forma adresei: IPv4 se scrie mapat
 *
 * Coloanele sunt `INET6` (`migrations/0008_auth.sql`). Că MariaDB acceptă un
 * literal IPv4 punctat direct într-un `INET6` **nu s-a măsurat** — nu există
 * bază de date aici. Forma mapată `::ffff:192.0.2.1` e IPv6 valid în orice
 * lectură, deci e acceptată în ambele lumi; alegerea costă un pic de lizibilitate
 * în urma de audit și scutește o autentificare care s-ar opri cu o eroare de
 * inserare pe care nimeni n-ar lega-o de un tip de coloană.
 */

import { isIP } from "node:net";

/** Numele variabilei prin care operatorul declară antetul măsurat. */
export const CLIENT_IP_HEADER_ENV = "AGGREGATOR_CLIENT_IP_HEADER";

/**
 * Antetele citite DOAR pentru urma de audit, când nu există unul de încredere.
 *
 * Nimic nu se decide din ele. Sunt aici fiindcă „cineva a pretins că vine de
 * la X" e mai mult decât nimic într-o investigație, atâta timp cât e scris ca
 * pretenție.
 */
const CLAIMED_HEADERS = ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"];

/** Cât din valoarea pretinsă intră în `detail`. Coloana are 255 în total. */
const CLAIMED_MAX_CHARS = 64;

export type IpTrustReason =
  /** Antet declarat de operator, sosit ca o singură adresă validă. */
  | "trusted"
  /** Nu s-a declarat niciun antet: starea implicită. */
  | "unconfigured"
  /** Antetul declarat lipsește din cerere. */
  | "missing"
  /** Antetul declarat a sosit ca listă, deci marginea nu-l înlocuiește. */
  | "list"
  /** Antetul declarat a sosit cu ceva ce nu e adresă. */
  | "not-an-address";

export type ClientIp = {
  /** Adresa care are voie să atingă o coloană `INET6` și o decizie. `null` =
   *  nu se știe, și „nu se știe" nu e „0.0.0.0". */
  address: string | null;
  /** Se poate sprijini o decizie pe `address`? */
  trusted: boolean;
  /** Ce a pretins clientul, când nu se poate avea încredere. Doar pentru urmă. */
  claimed: string | null;
  reason: IpTrustReason;
};

/**
 * Adresa în forma care se poate scrie într-o coloană `INET6`, sau `null`.
 *
 * `net.isIP` e validatorul platformei, nu unul scris aici: un IPv6 corect are
 * destule forme (`::`, grupuri comprimate, IPv4 încorporat) cât o expresie
 * regulată scrisă de mână să accepte ceva ce baza refuză, sau invers.
 */
export function normalizeAddress(value: string): string | null {
  const candidate = (value ?? "").trim();
  // Identificatorul de zonă (`fe80::1%eth0`) e ACCEPTAT de `net.isIP` — măsurat
  // pe Node 24, întoarce 6. Aici e refuzat: partea de după `%` numește o
  // interfață a mașinii care a scris antetul, deci adresa n-are înțeles la noi,
  // iar că `INET6` o primește nu s-a măsurat. O adresă legată de rețeaua locală
  // a altcuiva n-are ce căuta într-o urmă de audit oricum.
  if (candidate.includes("%")) return null;
  const kind = isIP(candidate);
  if (kind === 4) return `::ffff:${candidate}`;
  if (kind === 6) return candidate.toLowerCase();
  return null;
}

function claimedFrom(headers: Headers): string | null {
  for (const name of CLAIMED_HEADERS) {
    const raw = headers.get(name);
    if (raw && raw.trim()) return raw.trim().slice(0, CLAIMED_MAX_CHARS);
  }
  return null;
}

/**
 * Adresa clientului și cât de mult se poate sprijini pe ea.
 *
 * Nu aruncă niciodată: o configurație greșită a antetului nu are voie să oprească
 * autentificarea, fiindcă atunci un câmp scris greșit într-un panou web ar
 * închide panoul. Ce face în schimb e să spună limpede că nu știe.
 */
export function readClientIp(
  headers: Headers, env: Record<string, string | undefined> = process.env,
): ClientIp {
  const name = (env[CLIENT_IP_HEADER_ENV] ?? "").trim().toLowerCase();
  if (!name) {
    return { address: null, trusted: false, claimed: claimedFrom(headers),
             reason: "unconfigured" };
  }

  const raw = headers.get(name);
  if (raw === null || !raw.trim()) {
    return { address: null, trusted: false, claimed: claimedFrom(headers),
             reason: "missing" };
  }
  if (raw.includes(",")) {
    // Marginea a ADĂUGAT la ce era, deci n-a înlocuit. Vezi capul modulului.
    return { address: null, trusted: false, claimed: raw.trim().slice(0, CLAIMED_MAX_CHARS),
             reason: "list" };
  }

  const address = normalizeAddress(raw);
  if (address === null) {
    return { address: null, trusted: false, claimed: raw.trim().slice(0, CLAIMED_MAX_CHARS),
             reason: "not-an-address" };
  }
  return { address, trusted: true, claimed: null, reason: "trusted" };
}

/** Ce se scrie în `login_attempts.detail` despre sursă. `null` = nimic de spus. */
export function ipNote(ip: ClientIp): string | null {
  if (ip.trusted) return null;
  if (ip.claimed) return `ip-pretins(${ip.reason})=${ip.claimed}`;
  return `ip-necunoscut(${ip.reason})`;
}
