/**
 * Politica de autentificare a panoului: cine intră, cine nu, și cu ce cod.
 *
 * Geamănul e `sentinel/web/security.py:252-488` (`Authenticator`). Rutele din
 * `app/login`, `app/totp` și `app/logout` nu iau nicio decizie: ele citesc
 * cererea, cheamă de aici și scriu răspunsul. Motivul separării e cel de pe
 * server — politica și transportul se revizuiesc separat — plus unul propriu:
 * **codul de stare e parte din politică**, nu din randare. Un `PasswordBusyError`
 * întors ca 401 ar fi o decizie de securitate luată din greșeală într-un `catch`
 * de rută.
 *
 * ## Ordinea, și de ce fiecare pas e unde e
 *
 *   1. **straturile de limitare** (per sursă, global), înaintea ORICĂREI alte
 *      ramuri;
 *   2. **forma cererii** — nume gol, nume non-ASCII, parolă goală, parolă peste
 *      plafon. `verifyPassword` NU aplică `MAX_PASSWORD_LENGTH` (doar
 *      `hashPassword` cheamă `validatePasswordStrength`), deci plafonul parolei e
 *      al nostru sau al nimănui;
 *   3. **verificarea**, cu hash-fantomă pentru un nume necunoscut, ca munca să
 *      fie aceeași;
 *   4. **fereastra contului**, citită O DATĂ, imediat după ce parola s-a dovedit
 *      corectă;
 *   5. **dezactivat**, **al doilea factor** — amândouă DUPĂ parolă.
 *
 * Pasul 5 e ordinea serverului și nu e cosmetică: „cont dezactivat" e un mesaj
 * care spune că un cont EXISTĂ. Spus înainte de verificarea parolei, ar fi un
 * oracol de enumerare pentru oricine; spus după, îl aude doar cine avea deja
 * parola, adică cineva care știa oricum.
 *
 * ## Ce are voie să hrănească un plafon
 *
 * `login_attempts` nu e o urmă, e STAREA celor trei limitatoare: toate numără
 * rânduri din ea cu `result <> 'ok'`. Deci întrebarea la fiecare scriere nu e
 * „e util rândul ăsta în urmă?", ci **„cât îl costă pe cel care îl produce?"**.
 * Un rând ieftin e combustibil: plafonul atins se prelungește singur cât timp
 * atacatorul mai trimite o cerere din când în când, iar panoul n-are ieșire de
 * urgență — e o aplicație pe găzduire partajată.
 *
 * Regula are două jumătăți, și amândouă s-au învățat prin sondă, nu prin
 * raționament:
 *
 *   1. **Un rând numărat cere o parolă VERIFICATĂ.** Cele patru refuzuri de
 *      formă de la pasul 2 nu verifică nimic — nici Argon2, nici măcar o
 *      căutare de cont. Măsurat pe 17 august 2026, prin ruta reală: cu ramura
 *      de nume gol scriind, 200 de cereri fără cont și fără parolă armau
 *      plafonul global, iar apoi 1 cerere la 3 secunde îl ținea armat la
 *      nesfârșit — operatorul cu parola CORECTĂ primea 503 la fiecare
 *      încercare. Mutarea limitatorului mai sus NU a reparat asta: ramurile au
 *      trecut să scrie DUPĂ poartă, tot pe gratis, cu exact același efect
 *      pentru operator. Ce repară e regula asta. Refuzurile de formă merg azi
 *      în jurnalul procesului, unde nu numără nimic.
 *   2. **Un rând `locked` se scrie cel mult `limit` per nume, per fereastră.**
 *      Ramurile „cont dezactivat" și „al doilea factor neînrolat" vin după o
 *      parolă corectă, deci costă un Argon2 — dar rezultatul lor e FIX pentru
 *      toată fereastra, iar repetat, rândul nu adaugă nimic în urmă și adaugă
 *      tot ce trebuie ca să închidă panoul pentru altcineva. Măsurat: 12 cereri
 *      cu parola corectă pe un cont dezactivat scriau 12 rânduri numărate de
 *      toate cele trei ferestre. Cine poate face asta e exact cine știe parola
 *      unui cont pe care operatorul tocmai l-a dezactivat.
 *
 * Ce NU se mărginește, spus pe față: **o parolă greșită scrie mereu.** Rândul ei
 * e singurul semnal că cineva ghicește, iar plafonul global pe care îl hrănește
 * e chiar mecanismul care mărginește ghicitul. Cine repetă aceeași parolă
 * greșită de două sute de ori produce tot combustibil, iar codul de aici nu
 * poate deosebi asta de două sute de ghiciri distincte fără să țină minte
 * ghicirile — deci nu pretinde că poate.
 *
 * Un refuz de LIMITARE — per sursă, global, sau coada de Argon2 plină — nu intră
 * nici el în `login_attempts`. E o abatere conștientă de la `security.py`, și e o
 * abatere de la un DEFECT CONFIRMAT, nu de la o presupunere: sonda de pe gazdă
 * arată că `sentinel/web/security.py:265-278` scrie un rând `locked` pentru sursa
 * limitată, iar `sentinel/db/repo/users.py:247` îl numără cu `result <> 'ok'`.
 * (Reparația de acolo e a gazdei monitorizate și e pe listă separat; aici e doar
 * motivul pentru care nu se copiază.)
 *
 * ## Ce costă în continuare, cu cifre
 *
 * Plafonul global rămâne o pârghie de negare de serviciu — un plafon care nu se
 * aplică nu e un plafon, iar regula de mai sus nu-l face nehrănibil. RITMUL nici
 * el nu se schimbă: `GLOBAL_FAILURE_LIMIT` rânduri la fiecare
 * `FAILURE_WINDOW_MINUTES` înseamnă tot un rând la ~4,5 secunde. Ce se schimbă e
 * PREȚUL fiecărui rând: acum cere o verificare Argon2 SERIALIZATĂ
 * (`MAX_CONCURRENT_ARGON2 = 1`), nu o inserare.
 *
 * Cifrele, cu sursa lor, fiindcă un ordin de mărime scris fără sursă e o
 * afirmație: ~140 ms per verificare aici, pe mașina de dezvoltare (măsurat în
 * piesa 1 și confirmat de suită — 24 de autentificări în 3,3 s); ~170 ms în
 * sonda verificatorului; ~0,8 ms per cerere fără nicio verificare, prin ruta
 * reală, cu dublul de bază de date (220 de cereri în 182 ms). Deci cea mai
 * ieftină cale de hrănire costă azi cu ordine de mărime mai mult decât ieri, iar
 * pe gazdă diferența e mai MICĂ decât atât, fiindcă acolo și inserarea costă.
 * Ce s-a scos e „gratuit", nu „posibil": „1 cerere la 3 secunde, fără nicio
 * credențială, la nesfârșit" nu mai e cumpărătura.
 *
 * ## Fereastra per cont NU refuză o parolă corectă
 *
 * Decizie de operator, luată pe 17 august 2026, după ce jumătatea 1 de mai sus a
 * fost reparată. Motivul: cât timp fereastra refuza și o parolă corectă, oricine
 * putea scrie `limit` eșecuri pe numele operatorului și ținea operatorul afară
 * cu ~20 de cereri pe oră. Ce se pierde, scris pe față: un atacator care tocmai
 * a ghicit parola n-o mai lasă „la coadă" o fereastră, o poate folosi imediat —
 * dar tot are nevoie de al doilea factor, iar ghicirile lui de COD sunt
 * mărginite la `limit` per fereastră, la etapa a doua. Argumentul cu care
 * schimbarea a fost propusă prima oară („elimină ultima pârghie de negare
 * permanentă") era FALS și nu se repetă: plafonul global e o pârghie și rămâne.
 */

import {
  MAX_PASSWORD_LENGTH, PasswordBusyError, hashPassword, needsRehash, verifyPassword,
} from "./password";
import {
  createSession, promoteSession, revokeSession,
} from "./session";
import { TotpCipher, consumeTotpCounter, verifyCode } from "./totp";
import {
  assertAsciiUsername, UsernamePolicyError, detailOf, findById, findByUsername,
  logAttempt, normalizeUsername, recordSuccess, setPasswordHash,
} from "./users";
import {
  FAILURE_WINDOW_MINUTES, THROTTLE_RETRY_AFTER_S, accountWindow, checkThrottles,
} from "./ratelimit";
import { ipNote } from "./client-ip";
import type { AccountWindow } from "./ratelimit";
import type { AuthDb } from "./db";
import type { AuthUser } from "./users";
import type { ClientIp } from "./client-ip";
import type { Session } from "./session";
import type { ThrottlePass } from "./gate";

/**
 * Cât trăiește o sesiune întreagă. 12 ore: o zi de lucru, nu o săptămână.
 *
 * Expirarea e ABSOLUTĂ, nu glisantă (`migrations/0008_auth.sql`): o expirare
 * împinsă la fiecare cerere înseamnă că un cookie furat rămâne valabil exact cât
 * îl folosește hoțul.
 */
export const SESSION_TTL_S = 12 * 3600;

/**
 * Cât i se spune să aștepte celui care a picat pe coada de Argon2.
 *
 * Aritmetica e a piesei 1: `MAX_QUEUED_ARGON2 = 16` la ~140 ms fiecare înseamnă
 * ~2,3 s până se golește coada. 5 s e peste, cu loc de mișcare, și rămâne un
 * număr pe care un om îl acceptă ca „revino imediat". Aritmetica asta ține însă
 * doar cât ține și cei ~140 ms: pe mașina de dezvoltare s-au măsurat și ~375 ms
 * per verificare, iar acolo coada se golește în ~6 s — un client care chiar
 * ascultă `Retry-After` revine devreme și mai primește un 503.
 */
export const BUSY_RETRY_AFTER_S = 5;

/**
 * Forma unui hash Argon2id PHC pe care îl putem citi.
 *
 * `needsRehash` întoarce `true` și pentru un hash ilizibil, și pentru unul doar
 * cu alți parametri, deci nu poate deosebi cele două. Aici se cere DOAR forma:
 * ce nu se potrivește nu e o parolă greșită, e un rând stricat — și trebuie să
 * ajungă la operator ca atare. Vezi `noteBrokenHash`.
 */
const ARGON2ID_PHC = /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$/;

export type LoginOutcome =
  | "needs_totp" | "ok" | "bad_credentials" | "locked" | "disabled" | "throttled"
  | "busy" | "username_policy" | "totp_undecryptable" | "totp_unconfirmed";

export type LoginResult = {
  outcome: LoginOutcome;
  /** Codul de stare, decis AICI. Vezi capul modulului. */
  status: number;
  /** Textul arătat operatorului, în română. */
  message: string;
  sessionToken?: string;
  retryAfterS?: number;
};

export type LoginRequest = {
  username: string;
  password: string;
  ip: ClientIp;
  userAgent: string | null;
};

/** Un singur text pentru „nu există" și „parolă greșită". Orice diferență între
 *  ele predă lista de utilizatori, o ghicire pe rând. */
const BAD_CREDENTIALS = "Utilizator sau parolă incorectă.";

export class Authenticator {
  private readonly db: AuthDb;
  private readonly cipher: TotpCipher;

  constructor(db: AuthDb, sessionSecret: string) {
    this.db = db;
    this.cipher = new TotpCipher(sessionSecret);
  }

  // -------------------------------------------------------------------------
  // Etapa întâi: numele și parola
  // -------------------------------------------------------------------------
  async login(request: LoginRequest): Promise<LoginResult> {
    const { ip, userAgent } = request;
    const username = normalizeUsername(request.username);
    const source = ipNote(ip);

    // Straturile de limitare, ÎNAINTEA oricărei alte ramuri — nu doar înaintea
    // muncii scumpe. Permisul pe care îl întoarce e singurul lucru cu care se
    // poate scrie apoi în `login_attempts`; de-aia refuzurile de mai jos n-au ce
    // să scrie chiar dacă cineva ar încerca.
    const verdict = await checkThrottles(this.db, ip);
    if (!verdict.allowed) {
      console.warn(`[aggregator] autentificare refuzată de stratul „${verdict.layer}”`);
      return verdict.layer === "ip"
        ? { outcome: "throttled", status: 429, retryAfterS: verdict.retryAfterS,
            message: "Prea multe încercări din rețeaua asta. Reîncearcă mai târziu." }
        : { outcome: "throttled", status: 503, retryAfterS: verdict.retryAfterS,
            message: "Panoul e sub o rafală de încercări de autentificare și a " +
                     "oprit temporar verificarea parolelor. Reîncearcă mai târziu." };
    }
    const pass = verdict.pass;

    // Cele patru refuzuri de FORMĂ. Niciunul nu verifică vreo parolă, deci
    // niciunul nu scrie un rând numărat — vezi „Ce are voie să hrănească un
    // plafon". Permisul e purtat mai departe pentru ramurile care CHIAR scriu.
    if (username === "") {
      this.unverified("nume gol", source);
      return { outcome: "bad_credentials", status: 401, message: BAD_CREDENTIALS };
    }

    try {
      assertAsciiUsername(username);
    } catch (err) {
      if (!(err instanceof UsernamePolicyError)) throw err;
      // Mesaj propriu, nu cel generic: un nume non-ASCII nu POATE exista în
      // `users.username` (coloana e `ascii`), deci refuzul nu spune nimic despre
      // ce conturi există — și, spus limpede, scutește pe cineva de zece
      // încercări cu o diacritică invizibilă în câmp.
      this.unverified("nume non-ASCII", source);
      return { outcome: "username_policy", status: 400, message: err.message };
    }

    // Parola goală și parola peste plafon: refuzate ÎNAINTE de Argon2 și înainte
    // chiar de căutarea contului.
    //
    // Goală fiindcă `argon2Verify` ARUNCĂ pe ea, iar `verifyPassword` înghite
    // excepția ca „parolă greșită" — singura intrare controlată de client care
    // face asta (măsurat în piesa 1). Peste plafon fiindcă `verifyPassword` nu
    // aplică `MAX_PASSWORD_LENGTH`, deci nimeni n-o face dacă n-o facem noi.
    // Răspunsul e identic cu al unei parole greșite: cine trimite știe ce a
    // trimis, deci nu află nimic din faptul că a fost mai ieftin.
    //
    // Și niciuna nu se numără ca încercare eșuată. Nu e o scutire de dragul
    // simetriei: o parolă peste `MAX_PASSWORD_LENGTH` nu poate fi parola nimănui
    // (`hashPassword` aplică plafonul la punere), deci nu e o ghicire — e un
    // rând la preț de o inserare într-o tabelă care e starea a trei plafoane.
    if (request.password === "" || request.password.length > MAX_PASSWORD_LENGTH) {
      this.unverified(request.password === "" ? "parolă goală" : "parolă peste plafon",
                      source);
      return { outcome: "bad_credentials", status: 401, message: BAD_CREDENTIALS };
    }

    const user = await findByUsername(this.db, username);
    const stored = this.readableHash(user, username);

    let verified: { ok: boolean; needsRehash: boolean };
    try {
      verified = await verifyPassword(stored, request.password);
    } catch (err) {
      if (!(err instanceof PasswordBusyError)) throw err;
      // Coada de Argon2 e plină. NU e o parolă greșită și NU e un defect:
      // refuzul se produce înainte de orice ramificare pe existența contului,
      // deci nu spune nimic despre ce conturi există. Un 401 aici ar transforma
      // chiar plafonul cozii în oracolul de enumerare pe care hashul-fantomă
      // există să-l închidă; un 500 ar trimite pe cineva să caute un bug.
      //
      // Și nu se numără ca încercare eșuată: nimeni n-a verificat nicio parolă.
      console.warn("[aggregator] verificare de parolă refuzată: coada Argon2 e plină");
      return { outcome: "busy", status: 503, retryAfterS: BUSY_RETRY_AFTER_S,
               message: "Panoul e ocupat cu verificări de parolă. Reîncearcă în " +
                        "câteva secunde." };
    }

    if (!verified.ok) {
      return await this.refuse(pass, user, username, ip, userAgent, source);
    }
    // `user` e sigur nenul aici: `verifyPassword` întoarce `ok: false` pe ramura
    // fantomă, oricât de improbabil ar fi ghicit cei 32 de octeți.
    const account = user as AuthUser;

    // Fereastra contului, citită O DATĂ, aici: deasupra AMÂNDUROR ramurilor care
    // scriu `locked`, ca niciuna să nu poată scrie mai mult de `limit` rânduri
    // per fereastră. Citită mai jos, ramura de deasupra ei ar rămâne nemărginită
    // — și chiar a fost: 12 cereri cu parola corectă pe un cont dezactivat
    // scriau 12 rânduri numărate de toate cele trei ferestre.
    //
    // Ce NU face: nu refuză cererea. Un cont dezactivat aude „Cont dezactivat."
    // și a suta oară, fiindcă ăsta e adevărul; ce se oprește e combustibilul,
    // nu răspunsul. Iar pe drumul bun — parolă corectă, cont sănătos — rândul e
    // `ok`, pe care nu-l numără niciun plafon, deci fereastra n-are ce refuza.
    // Vezi „Fereastra per cont NU refuză o parolă corectă" în capul modulului.
    //
    // Etapa asta numără doar eșecurile ei (`stage = 'password'`): altfel un
    // atacator care umple fereastra cu parole greșite ar închide etapa a doua
    // pentru operatorul care tocmai a trecut de parolă.
    const perAccount = await accountWindow(this.db, account.username, ip.trusted,
                                           "password");

    if (account.disabled) {
      await this.noteBounded(perAccount, pass, username, ip, userAgent,
                             detailOf("cont dezactivat", source));
      return { outcome: "disabled", status: 403, message: "Cont dezactivat." };
    }

    if (verified.needsRehash) await this.upgradeHash(account, request.password);

    // Al doilea factor e OPȚIONAL de pe 19 august 2026, cerut de operator.
    // Decizia se ia PER CONT, din ce e în bază, iar starea din bază are TREI
    // valori, nu două:
    //
    //   secret lipsă              -> intră cu parola singură
    //   secret prezent, neconfirmat -> REFUZ, ca înainte
    //   secret prezent, confirmat -> etapa a doua, ca înainte
    //
    // Mijlocul e cel care contează. Cine a cerut `--totp` și a greșit codul de
    // trei ori nu are voie să cadă tăcut înapoi pe parolă: atunci al doilea
    // factor ar fi opțional în alt sens decât cel cerut, iar contul ar părea
    // protejat fără să fie. Nu există nici comutator global — unul s-ar putea
    // uita pornit, și atunci un cont care CHIAR are al doilea factor l-ar pierde.
    //
    // Ce s-a pierdut prin schimbarea asta, scris aici ca să nu se redescopere
    // într-o pană: pe găzduirea partajată nu există nftables, fail2ban pe care
    // să-l controlăm, sandbox systemd sau SELinux. Pentru un cont fără al doilea
    // factor, parola e SINGURUL control, iar plafonul global de încercări e tot
    // ce mărginește ghicitul.
    if (account.totpSecretEnc && !account.totpConfirmed) {
      await this.noteBounded(perAccount, pass, username, ip, userAgent,
                             detailOf("înrolare neconfirmată", source));
      return {
        outcome: "totp_unconfirmed", status: 403,
        message: "Contul are o înrolare începută și neconfirmată. Se termină pe " +
                 "gazdă, de operator: `npm run user -- enroll-totp <utilizator>`.",
      };
    }

    if (!account.totpSecretEnc) {
      const single = await createSession(this.db, {
        userId: account.id, ip: ip.trusted ? ip.address : null, userAgent,
        ttlS: SESSION_TTL_S, pendingTotp: false,
      });
      // `recordSuccess` NU se sare pe calea asta. Fără el `last_login_at` ar
      // rămâne la ultima intrare cu doi factori, iar panoul ar arăta o dată
      // veche fără ca nimic să pară stricat — exact felul de greșeală tăcută
      // pentru care există regula din CLAUDE.md.
      await recordSuccess(this.db, account.id, ip.trusted ? ip.address : null);
      await this.note(pass, username, ip, userAgent, "ok", "password",
                      detailOf("fără al doilea factor", source), single.session.id);
      return {
        outcome: "ok", status: 303, message: "", sessionToken: single.token,
      };
    }

    const created = await createSession(this.db, {
      userId: account.id, ip: ip.trusted ? ip.address : null, userAgent,
      ttlS: SESSION_TTL_S, pendingTotp: true,
    });
    await this.note(pass, username, ip, userAgent, "ok", "password",
                    detailOf("așteaptă al doilea factor", source), created.session.id);
    return {
      outcome: "needs_totp", status: 303, message: "",
      sessionToken: created.token,
    };
  }

  // -------------------------------------------------------------------------
  // Etapa a doua: codul
  // -------------------------------------------------------------------------
  async verifySecondFactor(request: {
    session: Session; code: string; ip: ClientIp; userAgent: string | null;
  }): Promise<LoginResult> {
    const { session, ip, userAgent } = request;
    const source = ipNote(ip);

    // Aceleași straturi ca la etapa întâi, și din același motiv: etapa asta
    // scrie și ea în `login_attempts`, deci fără permis n-ar avea cu ce. O
    // scutire aici („are deja o sesiune, deci e de-ai casei") ar fi o a doua ușă
    // pe lângă limitator, adică exact ce s-a reparat la etapa întâi.
    const verdict = await checkThrottles(this.db, ip);
    if (!verdict.allowed) {
      console.warn(`[aggregator] al doilea factor refuzat de stratul „${verdict.layer}”`);
      return verdict.layer === "ip"
        ? { outcome: "throttled", status: 429, retryAfterS: verdict.retryAfterS,
            message: "Prea multe încercări din rețeaua asta. Reîncearcă mai târziu." }
        : { outcome: "throttled", status: 503, retryAfterS: verdict.retryAfterS,
            message: "Panoul e sub o rafală de încercări de autentificare și a " +
                     "oprit temporar verificarea. Reîncearcă mai târziu." };
    }
    const pass = verdict.pass;

    const user = await findById(this.db, session.userId);
    if (user === null || user.disabled) {
      await revokeSession(this.db, session.id, "totp-invalid-user");
      return { outcome: "bad_credentials", status: 401, message: "Sesiune invalidă." };
    }

    // Fereastra contului, citită O DATĂ, înainte de orice scriere a cererii
    // ăsteia: aceeași valoare decide și refuzul de mai jos, și numărul din
    // mesajul de jurnal. Recitită după scriere, ar număra chiar rândul curent.
    //
    // `stage = 'totp'`: aici se mărginește ghicitul de COD, iar codurile se
    // ghicesc doar de cine a trecut deja de parolă. Numărate laolaltă cu
    // eșecurile de parolă — cum era până pe 17 august 2026 —, `limit` parole
    // greșite scrise de oricine pe numele operatorului îi revocau operatorului
    // sesiunea imediat după ce tastase parola CORECTĂ, cu mesajul „Sesiune
    // invalidă". Adică aceeași negare permanentă, mutată cu un pas mai încolo.
    const perAccount = await accountWindow(this.db, user.username, ip.trusted, "totp");
    if (perAccount.over) {
      await revokeSession(this.db, session.id, "totp-invalid-user");
      return { outcome: "bad_credentials", status: 401, message: "Sesiune invalidă." };
    }

    const secret = user.totpSecretEnc === null ? null
      : this.cipher.decrypt(user.totpSecretEnc, user.id);
    if (secret === null) {
      // Nu e un cod greșit și nu e o sesiune expirată: secretul stocat nu se mai
      // poate descifra, deci `SENTINEL_SESSION_SECRET` s-a schimbat sub el.
      // Nicio reîncercare nu va reuși vreodată, iar dacă i s-ar spune „cod
      // greșit" operatorul ar da roată formularului până l-ar limita ceva.
      await revokeSession(this.db, session.id, "totp-undecryptable");
      console.error(
        `[aggregator] secretul TOTP al lui ${user.username} nu se poate descifra; ` +
        "SENTINEL_SESSION_SECRET a fost rotit sau rândul a fost umblat");
      return {
        outcome: "totp_undecryptable", status: 401,
        message: "Secretul celui de-al doilea factor nu mai poate fi descifrat — " +
                 "cheia de sesiune a agregatorului s-a schimbat. Contul trebuie " +
                 "reînrolat pe gazdă; niciun cod nu va funcționa până atunci.",
      };
    }

    const counter = verifyCode(secret, request.code);
    if (counter === null) {
      const attempt = perAccount.failures + 1;
      await this.note(pass, user.username, ip, userAgent, "bad_totp", "totp",
                      detailOf(`încercarea ${attempt}/${perAccount.limit}`, source),
                      session.id);
      if (attempt >= perAccount.limit) {
        // Sesiunea se revocă, deci următoarea încercare cere din nou parola —
        // iar acolo fereastra e plină. Se golește singură, fără nimic pe gazdă.
        await revokeSession(this.db, session.id, "locked");
        return { outcome: "locked", status: 429, retryAfterS: THROTTLE_RETRY_AFTER_S,
                 message: "Prea multe încercări eșuate pe contul ăsta. Fereastra " +
                          `e de ${FAILURE_WINDOW_MINUTES} minute și se golește ` +
                          "singură." };
      }
      return { outcome: "bad_credentials", status: 401, message: "Cod incorect." };
    }

    if (!await consumeTotpCounter(this.db, user.id, counter)) {
      // Contorul era deja consumat: același cod, a doua oară, în aceeași
      // fereastră de 30 s. Nu e un cod greșit, deci nu revocă sesiunea — dar
      // rândul lui intră în fereastră, ca orice rând care nu e `ok`. Așa era și
      // înainte pentru straturile per sursă și global; ce se schimbă e că acum îl
      // vede și cel per cont. O reluare din reîncărcarea paginii costă o
      // încercare din cinci, nu blochează pe nimeni singură.
      await this.note(pass, user.username, ip, userAgent, "bad_totp", "totp",
                      detailOf("cod reluat", source), session.id);
      return { outcome: "bad_credentials", status: 401,
               message: "Cod deja folosit. Așteaptă următorul cod." };
    }

    const rotated = await promoteSession(this.db, session.id, SESSION_TTL_S);
    if (rotated === null) {
      // Nimic n-a fost promovat: sesiunea a fost revocată sau promovată între
      // timp. Nu se fabrică un jeton pentru o promovare care nu s-a dovedit.
      await revokeSession(this.db, session.id, "promote-failed");
      return { outcome: "bad_credentials", status: 401, message: "Sesiune invalidă." };
    }

    await recordSuccess(this.db, user.id, ip.trusted ? ip.address : null);
    await this.note(pass, user.username, ip, userAgent, "ok", "totp", source, session.id);
    return { outcome: "ok", status: 303, message: "", sessionToken: rotated };
  }

  async logout(session: Session): Promise<void> {
    await revokeSession(this.db, session.id, "logout");
  }

  // -------------------------------------------------------------------------
  // Ajutoare
  // -------------------------------------------------------------------------
  /**
   * Hashul stocat, sau `null` dacă nu are forma pe care o putem citi.
   *
   * `verifyPassword` înghite un hash stricat ca „parolă greșită" — `hash-wasm`
   * raportează „Invalid hash" și o alocare eșuată prin același `Error`, deosebite
   * doar prin mesaj. Consecința pentru operator ar fi „parolă greșită" cu parola
   * corectă, la nesfârșit, fără nimic în jurnal.
   *
   * Ce se poate deosebi de aici e forma rândului, și se deosebește: un hash care
   * nu e Argon2id PHC produce o linie de EROARE care numește contul, iar
   * verificarea se face pe fantomă (deci costul rămâne același, deci nici ăsta
   * nu devine un oracol).
   *
   * Ce NU se poate deosebi de aici, spus pe față: o alocare refuzată de gazdă.
   * `verifyPassword` întoarce `false` pentru ea, iar modulul nu dă apelantului
   * niciun mijloc s-o vadă. Atenuarea e cea din piesa 1 (`MAX_CONCURRENT_ARGON2 = 1`,
   * arena WASM alocată o dată la pornire și refolosită), nu ceva ce se poate
   * repara aici.
   */
  private readableHash(user: AuthUser | null, username: string): string | null {
    if (user === null) return null;
    if (ARGON2ID_PHC.test(user.passwordHash)) return user.passwordHash;
    console.error(
      `[aggregator] hashul de parolă al contului ${username} nu are forma ` +
      "Argon2id PHC. NU e o parolă greșită: rândul e stricat sau a fost scris de " +
      "altceva. Autentificarea lui va eșua până e rescris.");
    return null;
  }

  /** Costul s-a schimbat de când s-a pus parola. Se ridică tăcut, la o
   *  autentificare REUȘITĂ — alternativa e să ceri tuturor o resetare. */
  private async upgradeHash(user: AuthUser, password: string): Promise<void> {
    try {
      const fresh = await hashPassword(password);
      // Verificare de EFECT, nu de intenție: dacă noul hash tot n-ar fi la zi,
      // scrierea ar fi doar o rundă de Argon2 arsă la fiecare autentificare.
      if (needsRehash(fresh)) {
        throw new Error("hashul nou tot nu are parametrii curenți");
      }
      await setPasswordHash(this.db, user.id, fresh);
    } catch (err) {
      // O ridicare eșuată nu are voie să oprească o autentificare valabilă:
      // parola a fost deja verificată corect contra hashului vechi.
      console.error(
        `[aggregator] hashul lui ${user.username} nu a putut fi ridicat la ` +
        `parametrii curenți: ${(err as Error).message}`);
    }
  }

  /**
   * Refuzul comun: același text, aceeași muncă, indiferent dacă numele există.
   *
   * Se ajunge aici DOAR după o verificare de parolă care chiar a rulat (fantomă
   * pentru un nume necunoscut), deci rândul e plătit cu un Argon2 — condiția din
   * „Ce are voie să hrănească un plafon". Se scrie MEREU, și nemărginit: e
   * singurul semnal că cineva ghicește, iar plafonul global pe care îl hrănește
   * e chiar mecanismul care mărginește ghicitul.
   *
   * Fereastra se citește pentru numărul din `detail`, pe numele TASTAT — același
   * pe care îl numără `countFailuresForUser`. Pentru un nume necunoscut era
   * sărită înainte, deci rândurile alea nu spuneau a câta încercare sunt; nimic
   * din decizie nu depinde de ea aici.
   */
  private async refuse(
    pass: ThrottlePass, user: AuthUser | null, username: string, ip: ClientIp,
    userAgent: string | null, detail: string | null,
  ): Promise<LoginResult> {
    const perAccount = await accountWindow(this.db, username, ip.trusted, "password");
    await this.note(pass, username, ip, userAgent,
                    user === null ? "unknown_user" : "bad_password", "password",
                    detailOf(`încercarea ${perAccount.failures + 1}/${perAccount.limit}`,
                             detail));
    return { outcome: "bad_credentials", status: 401, message: BAD_CREDENTIALS };
  }

  /**
   * Un refuz care nu a verificat NICIO parolă: în jurnalul procesului, nicăieri
   * altundeva.
   *
   * Nu e o urmă pierdută, e o urmă mutată acolo unde nu numără nimic — vezi capul
   * modulului. Numele TASTAT nu intră în linia asta dinadins: e un șir ales de
   * cine trimite cererea, iar într-un jurnal de proces ar putea purta linii noi,
   * adică ar putea fabrica intrări. În coloana `login_attempts.username` ajunge
   * ca PARAMETRU, unde nu poate fabrica nimic — dar acolo, azi, nu mai ajunge.
   */
  private unverified(why: string, source: string | null): void {
    console.warn(
      `[aggregator] autentificare refuzată fără verificare de parolă (${why})` +
      `${source ? `; ${source}` : ""}. Nu se numără: nimeni n-a verificat nicio ` +
      "parolă, iar un rând ieftin într-o tabelă care e starea a trei plafoane e " +
      "combustibil.");
  }

  /**
   * Un rând `locked`, dar cel mult `limit` per nume, per fereastră.
   *
   * Ramurile care ajung aici („cont dezactivat", „al doilea factor neînrolat")
   * spun de fiecare dată același lucru despre o stare care nu se schimbă în
   * fereastră. Al șaselea rând nu adaugă nimic în urmă și adaugă tot ce trebuie
   * ca să închidă panoul pentru altcineva; deci se oprește rândul, nu răspunsul.
   */
  private async noteBounded(
    perAccount: AccountWindow, pass: ThrottlePass, username: string, ip: ClientIp,
    userAgent: string | null, detail: string | null,
  ): Promise<void> {
    if (perAccount.over) {
      console.warn(
        `[aggregator] rând „locked” nescris: ${perAccount.failures}/` +
        `${perAccount.limit} eșecuri pe contul ăsta în ultimele ` +
        `${FAILURE_WINDOW_MINUTES} minute. Răspunsul nu se schimbă; ce se ` +
        "oprește e hrănirea plafoanelor cu o stare care nu se schimbă.");
      return;
    }
    await this.note(pass, username, ip, userAgent, "locked", "password", detail);
  }

  /** Un rând în registru. Adresa intră în coloană DOAR dacă e de încredere. */
  private async note(
    pass: ThrottlePass, username: string, ip: ClientIp, userAgent: string | null,
    result: "ok" | "bad_password" | "bad_totp" | "locked" | "unknown_user",
    stage: "password" | "totp", detail: string | null, sessionId?: string,
  ): Promise<void> {
    await logAttempt(this.db, pass, {
      username: username || null,
      ip: ip.trusted ? ip.address : null,
      userAgent,
      result,
      stage,
      sessionId: sessionId ?? null,
      detail,
    });
  }
}
