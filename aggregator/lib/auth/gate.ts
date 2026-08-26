/**
 * Permisul fără de care nu se scrie niciun rând în `login_attempts`.
 *
 * ## Regula, într-o propoziție
 *
 * **Nimeni nu scrie în `login_attempts` pe o cale care n-a trecut de
 * `checkThrottles`.**
 *
 * ## De ce e o regulă și nu o convenție
 *
 * Toate cele trei straturi de limitare NUMĂRĂ rânduri din `login_attempts`
 * (`result <> 'ok'`, vezi `lib/auth/users.ts`). Deci o cale care scrie acolo
 * fără să fi trecut de limitator hrănește chiar numărătoarea care ar fi trebuit
 * s-o oprească: plafonul, o dată atins, se prelungește singur, iar
 * autentificarea rămâne închisă pentru operator cât timp atacatorul mai trimite
 * o cerere din când în când. Nu e o ipoteză, e un defect livrat de două ori:
 *
 *   * pe serverul monitorizat, `sentinel/web/security.py:265-278` scrie un rând
 *     `locked` la un refuz per sursă, iar `sentinel/db/repo/users.py:247` îl
 *     numără cu `result <> 'ok'`. Confirmat prin sondă, nu presupus;
 *   * aici, ramura cu nume gol și cea non-ASCII din `Authenticator.login`
 *     scriau un rând ȘI se întorceau înainte de `checkThrottles`. Cu plafonul
 *     global presaturat, un nume gol încă mai adăuga un rând: ~1 cerere la 4,5
 *     secunde ținea panoul la 503 pentru totdeauna, fără niciun cont și fără
 *     nicio parolă.
 *
 * ## De ce un obiect, și nu un comentariu
 *
 * Fiindcă piesa 3 aduce rute noi care vor vrea să logheze, iar o regulă scrisă
 * doar în proză se rupe la prima dintre ele fără ca nimic să pice. Permisul o
 * face executabilă în două feluri, care prind lucruri diferite:
 *
 *   * la COMPILARE — `logAttempt` cere un `ThrottlePass`, iar singurul loc de
 *     unde se poate obține e ramura care PERMITE a lui `checkThrottles`. Ramura
 *     care refuză nu poartă niciun permis, deci de pe ea nu se poate scrie;
 *   * la EXECUȚIE — un obiect fabricat (`{} as ThrottlePass`, orice trecut
 *     printr-un `any`) nu e în registrul de mai jos, iar `logAttempt` aruncă. Un
 *     cast nu e o dovadă; registrul e faptul observabil.
 *
 * ## Ce NU dovedește permisul, spus pe față
 *
 * Că a fost emis pentru CEREREA asta. Registrul e per proces, nu per cerere: un
 * permis ținut într-o variabilă de modul și refolosit trece — măsurat, un modul
 * livrat care cheamă `checkThrottles` o dată și păstrează permisul a scris 500
 * de rânduri cu el.
 *
 * Golul ăsta e acoperit de garda din `tests/auth-attempts-writers.test.ts`, dar
 * NUMAI în forma pe care garda o numără chiar: recensământul fișierelor livrate
 * care ating `grantThrottlePass`, al celor care ating `logAttempt`, și al celor
 * care numesc tabela dintr-o instrucțiune. Un modul nou care ține un permis și
 * scrie prin `logAttempt` e prins fiindcă apare în al doilea recensământ, nu
 * fiindcă permisul l-ar refuza. Fraza asta a fost o vreme mai largă decât
 * garda — spunea că golul e acoperit, când garda nu pomenea nici
 * `grantThrottlePass` din perspectiva apelantului, nici `logAttempt` deloc —, și
 * o afirmație mai largă decât mecanismul e felul în care cineva scoate
 * mecanismul.
 *
 * Ce rămâne neacoperit, cu numele: un permis refolosit ÎN fișierele deja
 * declarate. `lib/auth/login.ts` cheamă `checkThrottles` la fiecare cerere și
 * poartă permisul pe stivă, deci azi nu se întâmplă; dar dacă cineva l-ar muta
 * într-o variabilă de modul acolo, nicio gardă nu l-ar prinde. Pentru asta ar
 * trebui ca permisul să poarte identitatea cererii, iar cererea n-are azi
 * niciun obiect care să trăiască exact cât ea.
 *
 * TypeScript n-are vizibilitate de pachet, deci cine are voie să emită și cine
 * are voie să scrie sunt proprietăți ale DEPOZITULUI, ținute de recensăminte, nu
 * ale limbajului.
 */

/**
 * Permisele emise. `WeakSet`, deci un permis dispare odată cu cererea care l-a
 * primit; nimic nu crește cu traficul.
 */
const issued = new WeakSet<object>();

/**
 * Dovada că straturile de limitare au rulat ȘI au lăsat cererea să treacă.
 *
 * Câmpul nu e citit de nimeni: valoarea e IDENTITATEA obiectului, verificată în
 * registru. E acolo ca tipul să nu fie structural gol — `{}` se potrivește cu
 * orice, deci un tip gol n-ar cere nimic nici la compilare.
 */
export type ThrottlePass = { readonly gate: "checkThrottles" };

/** Emite un permis. Se cheamă DINTR-UN SINGUR LOC — vezi garda care numără. */
export function grantThrottlePass(): ThrottlePass {
  const pass: ThrottlePass = { gate: "checkThrottles" };
  issued.add(pass);
  return pass;
}

/** Permisul ăsta a fost chiar emis aici, sau doar arată ca unul? */
export function isThrottlePass(value: unknown): value is ThrottlePass {
  return typeof value === "object" && value !== null && issued.has(value as object);
}
