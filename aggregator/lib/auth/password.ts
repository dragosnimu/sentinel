/**
 * Parolele panoului agregator: Argon2id, cu EXACT parametrii serverului.
 *
 * Geamănul e `sentinel/web/security.py:73-84`. Nu e o inspirație, e un contract:
 * aceleași costuri, aceeași lungime de sare și de hash, același tip. Acordul e
 * ținut de `tests/unit/test_aggregator_auth_parity.py` — care nu compară numere
 * scrise în două locuri, ci pune verificatorul REAL al serverului
 * (`security.verify_password`) în fața unui hash produs AICI și cere să-l
 * accepte fără să ceară re-hash. Dacă vreun parametru se mișcă la un capăt,
 * `check_needs_rehash` o vede și testul pică.
 *
 * ## De ce contează că sunt aceiași
 *
 * `docs/PLAN-arhitectura-distribuita.md` §1.2 enumeră ce apără panoul DE PE
 * SERVER — Argon2id, TOTP obligatoriu, CSRF, CSP strict, limitare de rată,
 * `IPAddressDeny=any` pe proces — și spune că o rescriere pornește de la zero
 * teste. Găzduirea partajată n-are niciuna dintre ele: nici sandbox systemd,
 * nici SELinux, nici un fail2ban pe care să-l controlezi, iar personalul
 * furnizorului are acces la baza de date. Autentificarea asta e singurul
 * control, și de-aia cerința e scrisă ca „acești parametri exacți", nu ca
 * „hashing bun" — vezi §7, punctul 4, unde e scrisă ca decizie deschisă.
 *
 * ## Memoria: 64 MiB per verificare simultană, și de-aia există un semafor
 *
 * `security.py` spune limpede ce trebuie recalculat când se mută codul:
 * memoria e constrângerea, 64 MiB se alocă per verificare concurentă, iar pe
 * server aritmetica e ținută de rate-limit-ul nginx (5/min) plus blocarea per
 * cont. Pe găzduirea Hostinger nu există niciuna dintre ele, iar plafonul de
 * memorie al planului **nu a fost măsurat** — vezi `docs/PLAN-arhitectura-
 * distribuita.md` §7, punctul 4, unde întrebarea e scrisă ca decizie deschisă.
 *
 * Ce S-A măsurat, aici, pe Node 24, cu chiar parametrii livrați (rss al
 * procesului, verificări pornite simultan):
 *
 * | simultane | timp    | rss   |
 * |---|---|---|
 * | 1  |  135 ms | 130 MiB (pornire) |
 * | 2  |  269 ms | 194 MiB |
 * | 8  | 1071 ms | 578 MiB |
 * | 16 | 2203 ms | 1091 MiB |
 *
 * Memoria crește liniar cu concurența (~64 MiB per verificare) ȘI timpul crește
 * tot liniar (2203 ≈ 16 × 135): calculul e o singură bucată de WASM care ține
 * bucla de evenimente, deci concurența NU cumpără debit, doar memorie. Pe
 * găzduirea partajată același proces Node servește și `/api/sentinel/sync`, așa
 * că o rafală de POST-uri pe `/login` — cereri care nu au nevoie de niciun cont
 * — ar omorî ingestia arhivei de dovezi a tuturor instanțelor, prin plafonul de
 * memorie al planului.
 *
 * Parametrul NU se coboară: planul o interzice explicit și cere ca lipsa
 * măsurătorii să fie raportată ca o constatare. Ce se plafonează e CONCURENȚA
 * (`MAX_CONCURRENT_ARGON2`), și se plafonează AICI, nu în ruta de login:
 * modulul ăsta e singurul loc prin care trec toate apelurile de Argon2, oricine
 * le-ar chema. Limitarea de rată din piesa 2 e o a doua apărare, nu asta —
 * ea numără cereri, nu octeți, și nu poate ști câte verificări sunt în zbor.
 *
 * Dacă găzduirea refuză totuși alocarea, simptomul rămâne o eroare la hashing
 * sau un proces omorât, nu o autentificare mai slabă — un eșec zgomotos, care e
 * forma corectă a acestui necunoscut.
 *
 * ## De ce `hash-wasm` și nu `@node-rs/argon2`
 *
 * Planul le dă pe amândouă, cu ordinea decisă de o măsurătoare care nu s-a
 * făcut: „module native, dacă lipsesc pe găzduire — `hash-wasm`". Fără
 * măsurătoare, un modul nativ e un pariu pe ABI-ul și pe libc-ul unei gazde pe
 * care nu le cunoaștem, iar eșecul lui e la ÎNCĂRCARE: panoul întreg nu
 * pornește, nu doar autentificarea. WASM-ul rulează pe orice Node.
 *
 * Prețul e viteza, și e mic: măsurat pe mașina de dezvoltare (Node 24), un hash
 * la `t=3, m=65536, p=2` costă ~140 ms — chiar fereastra pe care o descrie
 * `security.py` („100-200 ms"). Formatul rezultat e PHC codificat, identic cu ce
 * produce `argon2-cffi`, deci trecerea la modulul nativ, dacă vreodată se
 * măsoară că merită, e o schimbare de import: hashurile existente rămân valide.
 */

import { randomBytes } from "node:crypto";

import { argon2id, argon2Verify } from "hash-wasm";

// ---------------------------------------------------------------------------
// Parametrii. Identici cu `security.py:73-80`.
// ---------------------------------------------------------------------------
export const ARGON2_TIME_COST = 3;
export const ARGON2_MEMORY_KIB = 65536;   // 64 MiB
export const ARGON2_PARALLELISM = 2;
export const ARGON2_HASH_BYTES = 32;
export const ARGON2_SALT_BYTES = 16;

/**
 * Lungimea, singura regulă. Ca pe server, și pentru același motiv scris acolo:
 * regulile de compoziție („o majusculă, un simbol") împing oamenii spre
 * `Password1!` și nu mai sunt recomandate de NIST din 2017. Plafonul de sus e
 * o măsură de disponibilitate: o intrare enormă ar fi CPU ars în Argon2.
 *
 * Minimul a fost coborât de la 12 la 8 pe 19 august 2026, la cererea
 * operatorului, în aceeași zi în care al doilea factor a devenit opțional. Cele
 * două schimbări se compun, și ăsta e faptul de reținut: pe găzduirea partajată
 * parola e acum SINGURUL control, iar plafonul global de încercări
 * (`GLOBAL_FAILURE_LIMIT`, 200 la 15 minute) e ce mai mărginește ghicitul. Patru
 * caractere în minus înseamnă un spațiu de căutare cu ordine de mărime mai mic,
 * nu puțin mai mic. Nu e o valoare de coborât mai departe fără să se ridice
 * altceva în loc.
 */
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 1024;

export class PasswordPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PasswordPolicyError";
  }
}

// ---------------------------------------------------------------------------
// Semaforul. Vezi „Memoria" din capul modulului pentru măsurătoare.
// ---------------------------------------------------------------------------

/**
 * Câte calcule Argon2 pot fi în zbor deodată. UNU, și e o cifră măsurată.
 *
 * Un al doilea permis ar costa încă 64 MiB și n-ar cumpăra nimic: măsurat,
 * timpul crește liniar cu concurența (16 simultane = 16 × una singură), fiindcă
 * WASM-ul calculează sincron și ține bucla de evenimente. Nici împotriva unui
 * calcul blocat nu ajută — dacă ăla ține bucla, tot procesul e oprit, nu doar
 * ruta de login. Deci al doilea permis ar fi memorie cheltuită degeaba, pe o
 * gazdă al cărei plafon nu e măsurat (§7.4 din plan).
 */
export const MAX_CONCURRENT_ARGON2 = 1;

/**
 * Câte cereri așteaptă la rând înainte ca următoarea să fie REFUZATĂ.
 *
 * O coadă nemărginită e tot un mod de a rămâne fără memorie, doar mai lent: cine
 * așteaptă ține în viață cererea HTTP, corpul ei și continuarea rutei. Și, mai
 * rău, ține operatorul în spatele unei cozi de atacatori pe care nimic n-o
 * golește.
 *
 * Cifra vine din timp, nu din memorie: la ~140 ms per verificare, ultimul din
 * coadă așteaptă ~2,3 s. Peste atât, un refuz imediat e un răspuns mai bun decât
 * o pagină care se încarcă un minut.
 *
 * O margine unde plafonul ăsta NU se aplică, scrisă ca s-o știe cine citește:
 * în primele ~140 ms de viață ale procesului, cererile așteaptă calculul
 * hashului-fantomă, nu semaforul, deci pot fi oricâte. Nu e o gaură de memorie —
 * niciuna dintre ele n-a alocat încă nimic în Argon2 —, e doar coadă de
 * promisiuni; dar dacă vreodată se măsoară altceva la pornire, aici e explicația.
 */
export const MAX_QUEUED_ARGON2 = 16;

/**
 * Coada e plină. NU e „parolă greșită" și NU e o eroare de program.
 *
 * Ruta care o prinde (piesa 2) trebuie să răspundă **503 cu `Retry-After`**, nu
 * 401 și nu 500: un 401 ar spune „credențiale greșite" despre o parolă pe care
 * nimeni n-a verificat-o, iar un 500 ar trimite pe cineva să caute un defect.
 * Refuzul se produce ÎNAINTE de orice ramificare pe existența utilizatorului,
 * deci nu spune nimic despre ce conturi există.
 */
export class PasswordBusyError extends Error {
  constructor() {
    super("prea multe verificări de parolă în așteptare; încearcă din nou");
    this.name = "PasswordBusyError";
  }
}

let running = 0;
const waiting: (() => void)[] = [];

/**
 * Un permis, sau o excepție dacă e coadă prea lungă.
 *
 * Permisul se PREDĂ de la cel care iese la primul din coadă (`running` nu scade
 * între ei), în loc să fie recâștigat prin recitirea contorului. Diferența nu e
 * stilistică: între rezolvarea promisiunii celui care așteaptă și repornirea lui
 * efectivă trece o microactivitate, iar un apel nou sosit în intervalul ăla ar
 * vedea contorul liber și ar intra — după care ar intra și cel trezit, doi în
 * zbor cu plafonul pe unu. Adică exact plafonul care raportează că e respectat
 * fără să fie.
 *
 * Și cine găsește coada nevidă se așază la coadă chiar dacă există permis liber:
 * fără asta, un flux de cereri noi ar putea trece mereu peste cei care așteaptă.
 */
async function acquire(): Promise<void> {
  if (running < MAX_CONCURRENT_ARGON2 && waiting.length === 0) {
    running++;
    return;
  }
  if (waiting.length >= MAX_QUEUED_ARGON2) throw new PasswordBusyError();
  await new Promise<void>((resolve) => waiting.push(resolve));
  // Permisul e deja al nostru: `release` l-a predat fără să scadă `running`.
}

function release(): void {
  const next = waiting.shift();
  if (next) next();
  else running--;
}

/** Câte calcule sunt în zbor și câți așteaptă. Pentru teste și diagnostic. */
export function argon2Load(): { running: number; waiting: number } {
  return { running, waiting: waiting.length };
}

/**
 * Orice calcul Argon2 din procesul ăsta trece pe aici.
 *
 * Nu doar verificarea: `hashPassword` alocă aceiași 64 MiB, iar un plafon care
 * acoperă o singură cale nu e un plafon — o schimbare de parolă concomitentă cu
 * un login ar dubla vârful pe care semaforul pretinde că îl ține.
 */
async function gated<T>(work: () => Promise<T>): Promise<T> {
  await acquire();
  try {
    return await work();
  } finally {
    release();
  }
}

export function validatePasswordStrength(password: string): void {
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordPolicyError(
      `parola trebuie să aibă cel puțin ${MIN_PASSWORD_LENGTH} caractere`);
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new PasswordPolicyError(
      `parola trebuie să aibă cel mult ${MAX_PASSWORD_LENGTH} caractere`);
  }
}

async function argonHash(password: string): Promise<string> {
  return await gated(() => argon2id({
    password,
    salt: randomBytes(ARGON2_SALT_BYTES),
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_TIME_COST,
    memorySize: ARGON2_MEMORY_KIB,
    hashLength: ARGON2_HASH_BYTES,
    outputType: "encoded",
  }));
}

/**
 * Hashul-fantomă: o verificare completă când utilizatorul nu există.
 *
 * Fără el, un nume necunoscut costă zero, iar un nume existent costă ~140 ms.
 * Diferența se vede dintr-un `curl` și enumerarea de utilizatori e primul pas al
 * fiecărui atac pe credențiale. E ușor de omis într-o rescriere; de-aia planul îl
 * cere explicit, și de-aia e probată printr-o MĂSURĂTOARE, nu prin citirea
 * codului, în `tests/auth-password.test.ts`.
 *
 * Se așteaptă pe AMBELE ramuri, nu doar pe cea fără utilizator. E singura formă
 * în care egalitatea ține și pentru prima cerere de după pornirea procesului:
 * calculul lui costă un hash întreg, iar dacă l-ar aștepta doar ramura fără
 * utilizator, primul login din viața procesului ar fi cu un hash mai lent exact
 * pentru numele care nu există.
 *
 * Parola din care se derivă e aleatoare la fiecare pornire și nu se scrie
 * nicăieri: nu e un hash real, deci nu poate fi potrivit de nimeni.
 */
const ghost: Promise<string> = argonHash(randomBytes(32).toString("base64url"));
// Fără asta, o eroare de încărcare a WASM-ului ar fi o respingere de promisiune
// neurmărită, adică un proces oprit de Node cu un mesaj despre promisiuni.
// Eroarea reală trebuie să iasă la `verifyPassword`, unde are un apelant.
ghost.catch(() => undefined);

export async function hashPassword(password: string): Promise<string> {
  validatePasswordStrength(password);
  return await argonHash(password);
}

export type VerifyResult = {
  ok: boolean;
  /** Parametrii din hash diferă de cei de mai sus, deci hashul se poate ridica
   *  la următorul login reușit — fără să ceară nimănui o resetare. */
  needsRehash: boolean;
};

/**
 * Verifică o parolă. `storedHash === null` înseamnă „utilizator necunoscut", iar
 * atunci se verifică hashul-fantomă, ca munca făcută să fie aceeași.
 */
export async function verifyPassword(
  storedHash: string | null, password: string,
): Promise<VerifyResult> {
  // Înainte de orice ramificare: vezi comentariul lui `ghost`.
  const dummy = await ghost;
  const target = storedHash ?? dummy;

  let matched = false;
  try {
    matched = await gated(() => argon2Verify({ password, hash: target }));
  } catch (err) {
    // Coada plină nu e un hash stricat, deci nu se înghite aici: un refuz de
    // supraîncărcare întors ca „parolă greșită" ar bloca un cont care n-a greșit
    // nimic, iar operatorul ar căuta o compromitere care nu există.
    if (err instanceof PasswordBusyError) throw err;
    // Hash nedecodabil (rând umblat, coloană tăiată, alt algoritm). Nu e o
    // excepție care are voie să dea 500 pe /login; e un refuz.
    return { ok: false, needsRehash: false };
  }

  if (storedHash === null) {
    // Fantoma s-a potrivit, ceea ce cere ghicirea a 32 de octeți aleatori.
    // Rămâne refuz oricum: aici nu există niciun utilizator de autentificat.
    return { ok: false, needsRehash: false };
  }
  if (!matched) return { ok: false, needsRehash: false };
  return { ok: true, needsRehash: needsRehash(storedHash) };
}

/**
 * Parametrii din hash NU mai sunt cei de mai sus?
 *
 * Un hash pe care nu-l pot citi întoarce `true`, nu `false`: „nu recunosc forma
 * asta" nu e „e la zi". Consecința e inofensivă — hashul se rescrie la
 * următoarea autentificare reușită, iar o autentificare reușită înseamnă că
 * parola a fost verificată cu succes contra lui.
 */
export function needsRehash(encoded: string): boolean {
  const parsed = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(encoded ?? "");
  if (!parsed) return true;
  return Number(parsed[1]) !== ARGON2_MEMORY_KIB
      || Number(parsed[2]) !== ARGON2_TIME_COST
      || Number(parsed[3]) !== ARGON2_PARALLELISM;
}
