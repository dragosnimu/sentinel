/**
 * Ingestia unui flux: validare, inserare idempotentă, și DOVADA efectului.
 *
 * ## Regula pe care stă totul, văzută din partea asta
 *
 * Expeditorul (`sentinel/report/shipper.py`) avansează cursorul unui flux
 * **numai** dacă răspunsul îi ecouă exact filigranul trimis. Deci un filigran
 * ecouat aici e o promisiune: *rândurile de până la `id`-ul ăsta sunt în arhivă*.
 * Ecoul dat pe altceva decât pe fapt — pe un cod de retur, pe „instrucțiunea nu a
 * aruncat" — face expeditorul să treacă mai departe peste rânduri care nu există,
 * definitiv și în tăcere, fiindcă un cursor nu se întoarce niciodată.
 *
 * De-aia funcția de mai jos NU se uită la ce a întors `INSERT`-ul. Se uită la
 * câte rânduri sunt PREZENTE după el.
 *
 * ## Forma de scriere se alege după TIPUL CURSORULUI
 *
 * Nu există o formă bună pentru toate fluxurile; sunt două, și se exclud.
 * `writeSql` alege, iar `lib/streams.ts` declară. Pe scurt:
 *
 *   * **`append-only` → `INSERT IGNORE`.** Obligatoriu, nu preferat: pe
 *     `audit_entries` ramura de UPDATE a lui `ON DUPLICATE KEY` declanșează
 *     triggerul de append-only, deci lotul MOARE la primul rând deja prezent —
 *     adică la fiecare retrimitere, care e cazul normal, nu cel excepțional.
 *   * **`mutable` / `rollup` → `ON DUPLICATE KEY UPDATE`.** Un incident care se
 *     închide pe server TREBUIE să se suprascrie aici; cu `INSERT IGNORE` ar
 *     rămâne deschis în panou, iar expeditorul, primind filigranul ecouat, ar
 *     trece peste el definitiv. Tabelele astea nu au trigger de append-only.
 *
 * `INSERT IGNORE` dă idempotența cerută, dar cu un preț care trebuie plătit
 * explicit: **înghite în tăcere și alte erori**. Trei forme, toate măsurabile în
 * consecințe:
 *
 *   * cheie duplicată → rândul se sare. E chiar ce vrem.
 *   * `NULL` într-o coloană `NOT NULL` → devine valoarea implicită (`''`), cu
 *     avertisment. Rândul e PREZENT și GREȘIT.
 *   * șir mai lung decât coloana → se TRUNCHIAZĂ, cu avertisment. Rândul e
 *     PREZENT și TĂIAT — iar un rând tăiat arată identic cu unul falsificat
 *     atunci când se verifică lanțul (E2.4b).
 *
 * Numărarea rândurilor prinde doar prima formă. Celelalte două se prind numai
 * ÎNAINTE, pe valori: de-aia `lib/streams.ts` poartă marginile reale ale
 * coloanelor și de-aia `prepareRows` refuză în loc să repare.
 *
 * ## Primul scris câștigă — DOAR pe fluxurile append-only
 *
 * Pe ele, un rând retrimis cu alt conținut sub aceeași identitate e IGNORAT, nu
 * suprascris. Nu e o scăpare, e definiția arhivei: `audit_entries` e
 * append-only, impus prin trigger, iar „replica își corectează istoria după ce
 * i-o rescrie sursa" ar fi chiar proprietatea pe care agregatorul o are ca să nu
 * o piardă. Divergența de conținut e o întrebare pentru verificarea lanțului, nu
 * pentru ingestie.
 *
 * Pe un flux `mutable` regula e exact pe dos, și trebuie să fie: acolo sursa ARE
 * dreptul să-și schimbe rândul, iar replica îl urmează. Cele două nu se pot
 * amesteca — de-aia tipul cursorului e declarat, nu ghicit.
 *
 * ## Fără tranzacție, și de data asta MĂSURAT
 *
 * `Db` vine din pool, deci două interogări pot merge pe conexiuni diferite —
 * motivul pentru care runner-ul de migrații cere o sesiune singură. Un
 * `BEGIN`/`COMMIT` trimis prin `Db` ar deschide tranzacția pe o conexiune și ar
 * scrie pe alta, deci NU e disponibil aici: interfața `Db` (`lib/migrate.ts`) are
 * două metode, `all` și `run`, iar docstring-ul ei spune pe față că runner-ul „nu
 * trebuie să poată deschide tranzacții". Căutat în tot `aggregator/`: nu există
 * niciun `BEGIN`, `COMMIT`, `beginTransaction` sau `getConnection`. Deci nu e
 * „folosită și nu se vede", e ABSENTĂ, iar ce urmează e scris ca să nu aibă
 * nevoie de ea.
 *
 * Pentru rândurile părinte, argumentul e cel dintâi: fiecare `INSERT` se comite
 * singur, iar numărătoarea de după vede ce s-a comis, indiferent de conexiune. Un
 * lot întrerupt la jumătate lasă jumătate de lot în arhivă, filigranul NU se
 * ecouă, iar retrimiterea îl completează — fiindcă ce e deja acolo e o cheie
 * duplicată, adică o operație nulă.
 *
 * ## Sub-rândurile: ordinea plus NUMĂRĂTOAREA țin locul tranzacției (#62)
 *
 * Un flux cu sub-rânduri scrie în patru pași, iar ordinea lor e chiar decizia:
 *
 *   1. **părintele** — upsert (sau `INSERT IGNORE`, după felul cursorului);
 *   2. **numărarea părinților** — câți dintre ei sunt PREZENȚI. Nu toți → ieșire
 *      `incomplete`, înainte ca vreun sub-rând să fie scris;
 *   3. **copiii, ADITIV** — se inserează sub-rândurile sosite;
 *   4. **curățarea** — se șterg sub-rândurile de sub părinții ăștia care NU sunt
 *      în lot.
 *
 * Ordinea „evidentă" — ștergi întâi, apoi inserezi — e cea care are nevoie de
 * tranzacție: o cădere între cei doi pași lasă un actor cu ZERO adrese, iar ăla
 * nu e un rând care lipsește, e o afirmație FALSĂ.
 *
 * A doua variantă — COPIII ÎNAINTEA PĂRINTELUI — a fost prima formă de aici, și
 * e greșită dintr-un motiv care nu se vede din interiorul unui singur lot: un
 * copil scris înaintea părintelui poate rămâne ATÂRNAT DE NIMIC. Cădere între
 * pasul copiilor și cel al părintelui, pe un părinte NOU: sub-rândurile sunt în
 * arhivă, rândul de care atârnă nu există, iar starea asta sursa n-a avut-o
 * niciodată. Nu e o mulțime învechită, e una pe care a inventat-o replica.
 *
 * Și nu se mai șterge de nicăieri. Singurul `DELETE` din tot agregatorul e
 * curățarea de la pasul 4, iar ea atinge doar părinții DINTR-UN LOT. Un copil al
 * cărui părinte nu mai vine în niciun lot nu e vizitat de nimic, niciodată —
 * exact propoziția scrisă mai jos, la `deleteSql`, despre ce lasă contopirea.
 *
 * De-aia părintele e primul. Dar ordinea singură nu ține invariantul, iar
 * greșeala de a crede că-l ține a fost făcută aici de două ori; cele două
 * bucăți se cumpără SEPARAT:
 *
 *   * **ordinea cumpără căderea cu EXCEPȚIE.** Dacă vreo bucată de părinți
 *     aruncă, excepția iese din funcție și pasul copiilor nici nu începe. Atât.
 *     O excepție e singurul fel de eșec pe care îl vede o instrucțiune despre
 *     care nu s-a întrebat nimic după aceea.
 *   * **numărătoarea de la pasul 2 cumpără RESPINGEREA TĂCUTĂ.** `INSERT IGNORE`
 *     — chiar forma pentru care există modulul ăsta — nu aruncă atunci când
 *     rândul e respins din alt motiv decât cheia duplicată: nicio eroare, niciun
 *     rând. Ordinea nu vede asta, fiindcă nimeni n-a aruncat, iar copiii ar
 *     pleca sub un părinte care nu e în replică. De-aia părinții se NUMĂRĂ
 *     înainte de pasul 3, iar un lot în care nu sunt toți se oprește acolo.
 *
 * Împreună dau invariantul: **niciun sub-rând scris fără rândul de care atârnă.**
 * Numărătoarea nu costă un dus-întors în plus — e chiar cea care se făcea oricum,
 * la capătul funcției, adică după copii și după curățare, unde orfanii erau deja
 * pe disc când îi descoperea.
 *
 * CE NU cumpără niciuna: numărătoarea e adevărată despre clipa în care a răspuns
 * baza. Fără tranzacție, un părinte care ar dispărea între pasul 2 și pasul 3 ar
 * lăsa iar copii atârnați. Nimic din agregator nu șterge rânduri părinte —
 * singurul `DELETE` e curățarea de la pasul 4, pe tabelele de legătură —, deci
 * fereastra aia n-are azi cine s-o deschidă; dar asta e o proprietate a codului
 * din jur, nu una impusă de aici.
 *
 * CE PLĂTESC amândouă, spus pe față: o oprire între pasul 1 și pasul 3 — fie
 * excepție, fie respingere tăcută — lasă părinții care AU aterizat cu mulțimea
 * veche sau goală, iar un actor fără adrese arată exact ca un actor care n-are
 * adrese. E tot o afirmație falsă — dar una ANCORATĂ: părintele EXISTĂ,
 * filigranul nu s-a ecouat, cursorul n-a avansat, deci lotul se retrimite, iar
 * retrimiterea îl vizitează din nou și îi pune mulțimea la loc. Starea lăsată de
 * copii-întâi nu e ancorată de nimic: părintele nu există, deci e în afara razei
 * oricărei curățări, acum și pe viitor.
 *
 * Asimetria asta e tot argumentul, și nu se sprijină pe „se repară singur
 * întotdeauna". Ce NU se repară în NICIUNA dintre ordini e rândul șters la SURSĂ
 * înainte ca o retrimitere să reușească: `shipper.py` recitește din sursă pe
 * cursor, nu retrimite un lot memorat, deci ce nu mai e acolo nu mai vine. Cu
 * părinte-întâi rămâne atunci un părinte real cu o mulțime veche sau goală —
 * vizibil în panou, legat de un rând care există; cu copii-întâi rămâneau rânduri
 * sub un părinte care nu e nicăieri.
 *
 * Cazul care nu e ipotetic, fiindcă e chiar forma datelor: rândurile părinte
 * poartă blobs (`evidence`, `ai_verdict`, `params`), sub-rândurile sunt
 * minuscule. O bucată de părinți care lovește `max_allowed_packet` eșuează la
 * fiecare reluare, identic. Cu părinte-întâi, în urma ei rămân părinții bucăților
 * dinainte, fără copii — ancorați, reparați de prima reluare care trece. Cu
 * copii-întâi rămâneau copiii TUTUROR părinților din lot, inclusiv ai celor care
 * n-au intrat niciodată: `detection_events` care cer dovezi pentru o detecție ce
 * nu e în replică.
 *
 * De ce nu se ecouă: efectul se numără de DOUĂ ori pentru fiecare tablou, iar
 * cele două împreună sunt egalitatea de mulțimi, nu doar prezența.
 *
 *   * **câte dintre sub-rândurile TRIMISE sunt acolo** — trebuie să fie toate.
 *     Prinde un copil înghițit tăcut de `INSERT IGNORE`, exact ca la părinți;
 *   * **câte sub-rânduri sunt SUB PĂRINȚII ĂȘTIA, cu totul** — trebuie să fie
 *     exact câte s-au trimis. Prinde curățarea care n-a rulat, sau a rulat
 *     parțial.
 *
 * Prima singură ar declara complet un lot în care ștergerea a eșuat (mulțimea
 * trimisă e prezentă, plus gunoiul). A doua singură ar declara complet un lot în
 * care un copil a fost înghițit și altul, vechi, a rămas (numerele ies, mulțimile
 * nu). Împreună: trimis ⊆ prezent și |prezent| = |trimis|, deci prezent = trimis.
 *
 * Asta se probează prin `SELECT`, nu prin forma instrucțiunii — un actor care
 * pierde un IP chiar nu-l mai are la receptor.
 *
 * ## Coloanele CALCULATE aici (#66)
 *
 * `actor_attrs.value_hash` nu vine de pe sârmă: e SHA-256 peste `value`,
 * calculat la ingestie, fiindcă unicitatea nu încape peste un `TEXT`. Pentru
 * modulul ăsta consecința e că digestul intră în IDENTITATE — deci în
 * dedublare, în numărătoarea de efect și în clauza `NOT IN` a curățării — la fel
 * ca orice coloană sosită.
 *
 * Ce trebuie să rămână adevărat e determinismul: același `value` dă același
 * digest la fiecare lot. Altfel retrimiterea — cazul normal, nu cel excepțional
 * — ar insera un al doilea rând, iar curățarea l-ar șterge pe primul, la
 * nesfârșit. Rețeta și motivele ei stau la `HashedColumn` din `lib/streams.ts`,
 * fiindcă acolo se declară; aici se aplică.
 */

import { createHash } from "node:crypto";

import type { Db } from "./migrate";
import type { ChildStream, Column, Stream } from "./streams";

/**
 * Cel mai mare lot acceptat, în rânduri.
 *
 * **Același număr cu plafonul lui `ship.max_rows_per_batch` din
 * `sentinel/config.py`, și cu implicitul lui.** Diferența dintre cele două
 * capete e tot ce contează: `ship_once` tratează orice răspuns non-2xx la fel și
 * nu citește niciodată corpul, iar nimic nu micșorează un lot care a fost
 * refuzat. Deci un `max_rows_per_batch` pe care config.py îl acceptă și
 * agregatorul îl refuză oprește `audit_log` DEFINITIV, cu backoff până la o oră.
 *
 * De ce 2000 și nu mai mult: costul unui lot mare nu e memoria, sunt DUS-
 * ÎNTORSURILE. Ingestia scrie și apoi NUMĂRĂ, în bucăți de `CHUNK`, deci un lot
 * de 2000 de rânduri e deja vreo 34 de instrucțiuni către MariaDB înăuntrul unui
 * singur `ship.timeout_s`; 20000 ar fi vreo 304, cu o latență per instrucțiune
 * pe care n-a măsurat-o nimeni. Iar mărimea lotului nu e oricum levierul pentru
 * o restanță: `DRAIN_PAUSE_S` face ca loturile pline să plece la o secundă
 * distanță, adică 2000 de rânduri pe secundă susținut.
 *
 * Ținut în acord de
 * `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits`,
 * care pică dacă vreunul dintre capete se mișcă.
 *
 * Un lot mai mare decât plafonul NU se trunchiază: se refuză cu un mesaj care
 * spune ce s-a întâmplat, fiindcă tăiat tăcut ar însemna un filigran ecouat
 * peste rânduri care n-au intrat.
 */
export const MAX_ROWS_PER_BATCH = 2_000;

/**
 * Cât se acceptă, în octeți, pentru un rând — în MEDIE, pe tot lotul.
 *
 * Nu e o margine per rând și nu se verifică pe rând: e felul în care plafonul de
 * corp de mai jos rămâne legat de numărul de rânduri, în loc să fie a treia
 * limită pe care cele două capete o văd diferit. Un rând de `audit_log` realist
 * are câteva sute de octeți; 4 KiB e o marjă de aproximativ zece ori.
 */
export const MAX_ROW_BYTES = 4_096;

/**
 * Plafonul corpului unei cereri.
 *
 * Route Handlers din Next 15 NU au o limită implicită (`bodySizeLimit` e doar
 * pentru Server Actions), deci fără plafonul ăsta corpul se bufferizează întreg
 * înainte de orice verificare de mărime. Pe o găzduire partajată, cine deține o
 * cheie de expediere — adică exact atacatorul cu root pe mașina monitorizată —
 * poate opri agregatorul la cerere.
 *
 * LIMITA CARE RĂMÂNE, și de ce se rămâne la ea: `params` și `detail` sunt
 * nemărginite la sursă, deci un singur rând legitim de câțiva megaocteți poate
 * depăși plafonul, iar expeditorul nu cunoaște numărul ăsta. Atunci fluxul se
 * oprește vizibil (413 + `ship:lag`), nu tăcut — dar se oprește.
 *
 * Decizia operatorului (august 2026) e să NU se mărginească la expeditor. Motivul
 * nu e comoditatea: o margine acolo ar da codului de pe mașina MONITORIZATĂ un
 * cuvânt de spus despre ce anume din propria istorie are voie să plece de acolo,
 * adică exact proprietatea pe care toată arhitectura o refuză. Un rând care nu
 * încape blochează fluxul până când operatorul mărește plafonul AICI — o
 * operație pe agregator, nu pe gazda monitorizată.
 *
 * Consecința e scrisă și acolo unde se uită operatorul gazdei Sentinel, nu doar
 * aici: `check_ship_lag` din `sentinel/selfcheck/checks.py` o numește în mesajul
 * de rămânere în urmă, iar numărul de acolo e ținut în acord cu ăsta de
 * `tests/unit/test_shipper.py`.
 */
export const MAX_BODY_BYTES = MAX_ROWS_PER_BATCH * MAX_ROW_BYTES;

/**
 * Câte rânduri intră într-o singură instrucțiune.
 *
 * Nu tot lotul: un `INSERT` cu mii de rânduri care duc fiecare un `params` de
 * câțiva kilobytes trece de `max_allowed_packet`, iar eroarea aia nu spune nimic
 * despre cauză. Bucăți mai mici înseamnă mai multe dus-întorsuri și zero
 * pierdere de corectitudine: o bucată care intră și una care nu lasă lotul
 * incomplet, filigranul nu se ecouă, iar retrimiterea completează.
 */
const CHUNK = 200;

/**
 * Câte sub-rânduri poate purta UN rând părinte.
 *
 * Nu e o limită tehnică, e una care trebuie să lase să treacă ce e normal. Cea
 * mai mare mulțime pe care o putem numi azi e `actors.member_ips` al unui cluster
 * — o grupare pe /24 are 254 de adrese, una pe ASN poate avea mai multe. O mie e
 * o marjă de vreo patru ori peste forma cea mai mare pe care o știm, iar un actor
 * cu multe adrese e normal, nu patologic.
 *
 * Ce se întâmplă peste: un REFUZ care numește fluxul, rândul, câmpul și numărul —
 * nu o eroare de driver despre prea mulți parametri, și nu un 413 despre corp,
 * care n-ar arăta spre rândul vinovat. Consecința e aceeași ca la
 * `MAX_BODY_BYTES`: fluxul se oprește vizibil până când operatorul mărește
 * plafonul AICI, pe agregator. Un rând părinte nu se poate tăia — sub-rândurile
 * lui sunt mulțimea lui, iar o mulțime tăiată tăcut ar face `DELETE`-ul de mai
 * jos să șteargă exact ce n-a încăput.
 */
export const MAX_CHILDREN_PER_ROW = 1_000;

/**
 * Câte sub-rânduri poate purta un LOT întreg, peste toate tabelele de legătură.
 *
 * Plafonul de rânduri părinte nu mai mărginește singur munca unui lot: 2000 de
 * părinți cu câte 100 de copii sunt 200 000 de rânduri scrise. Ce mărginește
 * numărul ăsta sunt DUS-ÎNTORSURILE, exact argumentul de la `MAX_ROWS_PER_BATCH`:
 * fiecare bucată de `CHUNK` sub-rânduri e o scriere plus două numărători, deci
 * 6000 de sub-rânduri sunt vreo 90 de instrucțiuni în plus înăuntrul unui singur
 * `ship.timeout_s`. Nemăsurat pe MariaDB, ca și celelalte praguri de aici; ce se
 * știe e că 6000 e de trei ori lotul de părinți, nu de o sută de ori.
 *
 * NU e încă un contract cu expeditorul, fiindcă niciun flux cu sub-rânduri nu e
 * înregistrat. Cine înregistrează primul flux cu copii trebuie să pună numărul
 * ăsta în acord cu ce alege expeditorul — la fel ca `MAX_ROWS_PER_BATCH`, ținut
 * de `tests/unit/test_shipper.py::test_the_two_ends_agree_on_the_batch_limits` —,
 * altfel un lot pe care config-check îl declară legal se refuză aici pentru
 * totdeauna.
 */
export const MAX_CHILD_ROWS_PER_BATCH = 3 * MAX_ROWS_PER_BATCH;

/**
 * Cel mai mare număr de parametri pe care îl legăm într-un `DELETE` de curățare.
 *
 * Protocolul acceptă 65535; bugetul de aici e mult sub el fiindcă instrucțiunea
 * crește cu PRODUSUL dintre părinți și copiii lor, iar un plafon larg ar face ca
 * marginea să fie descoperită de un lot real, nu de o socoteală.
 */
const DELETE_PARAM_BUDGET = 8_000;

/**
 * Sub-rândurile unui SINGUR rând părinte.
 *
 * Un părinte care sosește cu tabloul GOL are un grup la fel ca ceilalți, cu zero
 * identități. Fără el, „actorul ăsta nu mai are nicio adresă" n-ar avea cum să se
 * aplice: curățarea se face pe părinții din lot, nu pe copiii lor.
 */
export type ChildGroup = {
  /** Valorile de legătură ale părintelui, în ordinea din `ChildStream.link`. */
  parent: unknown[];
  /** Identitatea fiecărui sub-rând al lui, FĂRĂ `instance_id`. */
  identities: unknown[][];
};

/** Sub-rândurile unui tablou, verificate și puse în ordinea parametrilor. */
export type PreparedChildren = {
  child: ChildStream;
  /** Un grup per rând părinte din lot, în ordinea rândurilor. */
  groups: ChildGroup[];
  /** Identitățile tuturor sub-rândurilor lotului, aplatizate — pentru numărat. */
  identities: unknown[][];
  /** Parametrii de inserare, în ordinea coloanelor emise. */
  values: unknown[][];
};

export type Prepared =
  | {
      ok: true;
      /** Valorile coloanei de filigran, în ordinea rândurilor. */
      keys: (number | string)[];
      /** Identitatea fiecărui rând, FĂRĂ `instance_id` — el se leagă o dată. */
      identities: unknown[][];
      values: unknown[][];
      /** Sub-rândurile, o intrare per tablou declarat. Gol dacă fluxul n-are. */
      children: PreparedChildren[];
    }
  | { ok: false; detail: string };

export type IngestResult =
  | { ok: true; watermark: number | string; inserted: number; lowest: number }
  /** Lotul e greșit — vina e a expeditorului. → 400 */
  | { ok: false; kind: "invalid"; detail: string }
  /** Lotul e bun, dar efectul nu e cel cerut. NU se ecouă nimic. → 500 */
  | { ok: false; kind: "incomplete"; detail: string }
  /** Nu se poate ști ce s-a întâmplat: baza n-a răspuns. → 503 */
  | { ok: false; kind: "unavailable"; detail: string };

// ---------------------------------------------------------------------------
// Valori
// ---------------------------------------------------------------------------
/** Citire de proprietate PROPRIE. `rând["constructor"]` întoarce o funcție pe
 *  orice obiect, deci fără asta un rând fără `actor` ar părea că are unul. */
function own(row: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(row, key);
}

/**
 * Timpul, din ISO 8601 cu decalaj în `DATETIME(6)` UTC.
 *
 * Conversia se face AICI, cu regexp și aritmetică pe componente, nu prin `new
 * Date(...)`. Motivul e microsecunda: `Date` ține milisecunde, deci
 * `…:00.123456+03:00` ar ajunge în bază ca `…:00.123`. Trei cifre pierdute nu
 * par nimic, dar coloana e o replică a unui `timestamptz` cu precizie de
 * microsecundă, iar regula din capul lui `migrations/0001_core.sql` e că nimic
 * nu se trunchiază aici.
 *
 * Decalajul e OBLIGATORIU. Un timp fără el nu e „UTC", e „nu se știe în ce fus",
 * iar presupunerea mută tăcut istoricul cu câteva ore. `datetime.isoformat()` pe
 * un `timestamptz` din Postgres îl scrie întotdeauna.
 */
export function toUtcDatetime(text: string): { ok: true; value: string } | { ok: false; why: string } {
  const m = /^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|z|[+-]\d{2}:?\d{2}|[+-]\d{2})$/
    .exec(text);
  if (!m) {
    return { ok: false, why: "nu e ISO 8601 cu decalaj (ex. 2026-08-15T09:00:00.123456+00:00)" };
  }
  const [, ys, mos, ds, hs, mis, ss, frac, zone] = m;
  const year = Number(ys), month = Number(mos), day = Number(ds);
  const hour = Number(hs), minute = Number(mis), second = Number(ss);
  if (month < 1 || month > 12 || day < 1 || day > 31
      || hour > 23 || minute > 59 || second > 59) {
    return { ok: false, why: "componentă de timp în afara intervalului" };
  }
  // Mai multe cifre decât ține coloana. NU se taie: vezi regula de mai sus.
  if (frac !== undefined && frac.length > 6) {
    return { ok: false, why: `${frac.length} cifre de fracțiune; coloana ține 6, iar aici nu se trunchiază` };
  }

  const local = Date.UTC(year, month - 1, day, hour, minute, second);
  // `Date.UTC` NORMALIZEAZĂ: 31 februarie devine 3 martie, tăcut. Verificarea
  // de mai jos e singurul mod în care o dată imposibilă rămâne o eroare în loc
  // să devină alt moment decât cel trimis.
  const check = new Date(local);
  if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1
      || check.getUTCDate() !== day) {
    return { ok: false, why: "dată inexistentă în calendar" };
  }

  let offsetMinutes = 0;
  if (zone !== "Z" && zone !== "z") {
    const sign = zone[0] === "-" ? -1 : 1;
    const digits = zone.slice(1).replace(":", "");
    const oh = Number(digits.slice(0, 2));
    const om = digits.length > 2 ? Number(digits.slice(2, 4)) : 0;
    if (oh > 23 || om > 59) return { ok: false, why: "decalaj imposibil" };
    offsetMinutes = sign * (oh * 60 + om);
  }

  const utc = new Date(local - offsetMinutes * 60_000);
  const y = utc.getUTCFullYear();
  // Intervalul lui DATETIME în MariaDB. În afara lui, un `INSERT IGNORE` scrie
  // data zero și avertizează — adică un rând prezent cu un timp inventat.
  if (y < 1000 || y > 9999) return { ok: false, why: "an în afara intervalului DATETIME" };

  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const micro = (frac ?? "").padEnd(6, "0");
  return {
    ok: true,
    value: `${p(y, 4)}-${p(utc.getUTCMonth() + 1)}-${p(utc.getUTCDate())} ` +
           `${p(utc.getUTCHours())}:${p(utc.getUTCMinutes())}:${p(utc.getUTCSeconds())}.${micro}`,
  };
}

/**
 * Un octet zecimal de IPv4, în forma pe care o scrie sursa.
 *
 * Zerourile din față se REFUZĂ, nu se normalizează: `010` e opt pentru un parser
 * care citește octal și zece pentru unul care citește zecimal, iar dintre cele
 * două nu se poate alege de aici. Postgres nu le scrie niciodată — deci o
 * valoare cu zerouri în față nu vine de la `inet`, și atunci întrebarea nu mai e
 * cum se citește, ci de unde a venit.
 */
function isIpv4(text: string): boolean {
  const parts = text.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part)
                               && (part === "0" || part[0] !== "0")
                               && Number(part) <= 255);
}

/**
 * O adresă IPv6, cu coada IPv4 acceptată (`::ffff:192.0.2.1`).
 *
 * Scris ca numărătoare de grupuri, nu ca un singur regexp: un regexp de IPv6
 * corect are șaptezeci de caractere pe care nimeni nu le mai citește, iar unul
 * greșit acceptă `1:2:3:4:5:6:7:8:9` fără ca cineva să observe.
 *
 * `::` înseamnă „unul sau mai multe grupuri de zerouri", deci restul trebuie să
 * fie STRICT sub opt; fără el, exact opt. Aceeași regulă ca `ipaddress` din
 * Python, adică cea care a produs valoarea la celălalt capăt.
 */
function isIpv6(text: string): boolean {
  const skip = text.indexOf("::");
  let groups: string[];
  if (skip !== -1) {
    // Un al doilea `::` face adresa ambiguă — nu se știe câte zerouri sunt de
    // fiecare parte —, deci nu e „aproape validă", e altceva.
    if (skip !== text.lastIndexOf("::")) return false;
    const head = text.slice(0, skip);
    const tail = text.slice(skip + 2);
    groups = [...(head === "" ? [] : head.split(":")),
              ...(tail === "" ? [] : tail.split(":"))];
  } else {
    groups = text.split(":");
  }

  let count = groups.length;
  const last = groups[groups.length - 1];
  if (last !== undefined && last.includes(".")) {
    if (!isIpv4(last)) return false;
    // Un IPv4 în coadă ocupă DOUĂ grupuri de 16 biți, nu unul.
    count += 1;
    groups = groups.slice(0, -1);
  }
  if (!groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) return false;
  return skip !== -1 ? count < 8 : count === 8;
}

/**
 * Adresa, exact în forma în care se poate scrie într-o coloană `INET6`.
 *
 * Ce se REFUZĂ dinadins, deși seamănă cu o adresă:
 *
 *   * prefixul (`203.0.113.0/24`) — e o PLAJĂ, nu o adresă. Pe server tipul ăla
 *     e `cidr`, iar cartografierea lui e alta (limite precalculate,
 *     `migrations/0003_entities.sql`). Tăiat aici la adresă, ar deveni tăcut o
 *     gazdă anume;
 *   * zona (`fe80::1%eth0`) — are înțeles doar pe mașina care a scris-o;
 *   * șirul gol și spațiile din jur — „nu se știe" se trimite ca `null`, care e
 *     o valoare, nu ca un șir care arată a valoare.
 */
export function isCanonicalIp(text: string): boolean {
  // Marginea e a formei, nu a coloanei: 45 de caractere e cea mai lungă adresă
  // cu putință (IPv6 cu coadă IPv4). Peste atât nu se mai despică nimic.
  if (text.length === 0 || text.length > 45) return false;
  return text.includes(":") ? isIpv6(text) : isIpv4(text);
}

/**
 * Un surogat neîmperecheat într-un șir.
 *
 * `JSON.parse('"\\ud800"')` îl produce fără să se plângă. Trimis driverului, e
 * codificat cu un caracter de înlocuire — deci rândul ajunge în arhivă
 * SCHIMBAT, tăcut. `sentinel/report/signing.py` îl refuză deja la celălalt
 * capăt; refuzul de aici acoperă cazul în care corpul nu vine de acolo.
 */
function hasLoneSurrogate(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function checkString(value: unknown, column: Column, where: string): { ok: true; value: string } | { ok: false; detail: string } {
  if (typeof value !== "string") {
    return { ok: false, detail: `${where}: aștept un șir, am primit ${describe(value)}` };
  }
  if (hasLoneSurrogate(value)) {
    return { ok: false, detail: `${where}: surogat neîmperecheat; ar ajunge în arhivă schimbat` };
  }
  const bytes = Buffer.byteLength(value, "utf8");
  if (column.maxBytes !== undefined && bytes > column.maxBytes) {
    // Refuz, nu tăiere. `INSERT IGNORE` ar fi tăiat cu un avertisment pe care
    // nu-l citește nimeni, iar rândul rezultat s-ar fi numărat drept bun.
    return {
      ok: false,
      detail: `${where}: ${bytes} octeți, coloana ține ${column.maxBytes}; ` +
              "aici nu se trunchiază nimic",
    };
  }
  return { ok: true, value };
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "tablou";
  return typeof value;
}

/**
 * O identitate, scrisă pentru OM.
 *
 * `String(buffer)` decodează octeții ca UTF-8, deci o coloană derivată — un
 * digest de 32 de octeți oarecare — ar ieși în jurnal ca mizerie, iar mesajul
 * care spune „sub-rândul ăsta apare de două ori" n-ar mai numi care. Hexa e
 * lizibilă și, spre deosebire de decodare, e injectivă.
 */
function showIdentity(values: unknown[]): string {
  return values.map((v) => (Buffer.isBuffer(v) ? v.toString("hex") : String(v))).join(", ");
}

/**
 * Digestul unei coloane derivate: SHA-256 peste octeții UTF-8 ai valorii.
 *
 * Trei linii, dar scrise o dată și numite: rețeta asta E identitatea rândului la
 * receptor (`actor_attrs` e unică pe `value_hash`, nu pe `value`), iar ce se
 * hash-uiește, ce NU se normalizează și ce se presupune despre coliziuni sunt la
 * `HashedColumn` din `lib/streams.ts`.
 */
function digestOf(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/** Valoarea unei coloane, verificată. `null` e o valoare, nu o absență. */
function checkColumn(raw: unknown, column: Column, where: string): { ok: true; value: unknown } | { ok: false; detail: string } {
  if (raw === null) {
    if (column.nullable) return { ok: true, value: null };
    return { ok: false, detail: `${where}: NULL într-o coloană care nu-l acceptă` };
  }

  switch (column.kind) {
    case "id": {
      if (typeof raw !== "number" || !Number.isSafeInteger(raw) || raw <= 0) {
        return { ok: false, detail: `${where}: aștept un întreg pozitiv exact, am ${describe(raw)}` };
      }
      return { ok: true, value: raw };
    }
    case "int": {
      if (typeof raw !== "number" || !Number.isSafeInteger(raw)) {
        return { ok: false, detail: `${where}: aștept un întreg exact, am ${describe(raw)}` };
      }
      return { ok: true, value: raw };
    }
    case "bool": {
      // STRICT: doar `true` și `false`, niciodată 0/1 sau "true".
      //
      // Coloana e `TINYINT(1)`, iar MariaDB primește bucuroasă orice se poate
      // converti — inclusiv șirul "0", care în JavaScript e adevărat
      // (`Boolean("0") === true`). Aceeași capcană e numită în `lib/data/…`
      // pentru `pending_totp` și în `listAccounts` pentru `disabled`, unde
      // citirea se face cu `Number(x) === 1` tocmai ca s-o evite.
      //
      // Aici se închide pe partea de SCRIERE: expeditorul trimite un boolean
      // adevărat (`encode_value` lasă `bool` să treacă neatins), deci orice
      // altceva înseamnă că valoarea a trecut printr-o conversie pe drum, iar o
      // conversie pe drum e chiar lucrul pe care fluxul îl interzice.
      if (typeof raw !== "boolean") {
        return {
          ok: false,
          detail: `${where}: aștept adevărat sau fals, am ${describe(raw)}; ` +
                  "coloana e TINYINT(1), iar o valoare convertită pe drum — 1, " +
                  '"0", "true" — ar fi scrisă tăcut ca ceva ce nu s-a trimis',
        };
      }
      return { ok: true, value: raw };
    }
    case "decimal": {
      // Șir, nu număr: `Decimal` pleacă de pe server prin `str()`, iar un
      // `number` aici ar însemna că cineva a trecut valoarea printr-un float pe
      // drum — adică exact pierderea pe care forma de text o evită.
      if (typeof raw !== "string" || !/^-?\d+(\.\d+)?$/.test(raw) || raw.length > 40) {
        return {
          ok: false,
          detail: `${where}: aștept un zecimal canonic ca șir (ex. "0.85"), am ` +
                  `${describe(raw)}; coloana e DECIMAL, iar un șir stricat ar fi ` +
                  "refuzat abia de server, cu un mesaj despre tipuri",
        };
      }
      return { ok: true, value: raw };
    }
    case "inet": {
      // A doua excepție de aceeași formă ca `decimal`, și din același motiv: un
      // tip pe care Postgres îl are și JSON-ul nu pleacă de acolo ca text
      // (`encode_value`), iar forma se verifică la sosire, unde refuzul poate
      // numi câmpul. Coloana e `INET6`; ce face `INSERT IGNORE` cu un șir care
      // nu e adresă — rând pierdut sau rând prezent cu altceva — nu s-a probat
      // pe MariaDB, și nici nu trebuie să conteze: ambele sunt invizibile de la
      // expeditor, care nu citește corpul unui răspuns.
      if (typeof raw !== "string" || !isCanonicalIp(raw)) {
        return {
          ok: false,
          detail: `${where}: aștept o adresă IP ca șir — IPv4 sau IPv6, fără ` +
                  `prefix și fără zonă —, am ${describe(raw)}` +
                  (typeof raw === "string" ? ` (${JSON.stringify(raw.slice(0, 60))})` : "") +
                  "; coloana e INET6, iar o valoare care nu e adresă n-ar mai " +
                  "produce nicăieri un mesaj care să numească câmpul",
        };
      }
      return { ok: true, value: raw };
    }
    case "timestamp": {
      if (typeof raw !== "string") {
        return { ok: false, detail: `${where}: aștept un timp ISO 8601, am ${describe(raw)}` };
      }
      const converted = toUtcDatetime(raw);
      if (!converted.ok) return { ok: false, detail: `${where}: ${converted.why}` };
      return { ok: true, value: converted.value };
    }
    case "date": {
      // O ZI, nu un moment. Coloana e `DATE`, iar expeditorul trimite
      // `date.isoformat()` — „2026-08-20", fără oră și fără fus.
      //
      // NU se trece prin `toUtcDatetime`: aia ar accepta și un moment întreg,
      // iar MariaDB ar tăia tăcut ora la scriere într-o coloană `DATE`. Un
      // termen KEV mutat cu o zi de o conversie de fus e o dată greșită pe care
      // n-o semnalează nimic — `findings.kev_due_date` spune până când trebuie
      // reparat ceva ce se exploatează activ.
      if (typeof raw !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
        return {
          ok: false,
          detail: `${where}: aștept o zi în forma AAAA-LL-ZZ, am ${describe(raw)}` +
                  "; coloana e DATE, iar un moment întreg ar fi tăiat tăcut la scriere",
        };
      }
      return { ok: true, value: raw };
    }
    case "hash": {
      if (typeof raw !== "string" || !/^[0-9a-fA-F]{64}$/.test(raw)) {
        return {
          ok: false,
          detail: `${where}: aștept 64 de caractere hexa (coloana e VARCHAR(64) ascii, ` +
                  "iar orice altceva ar fi tăiat sau stricat tăcut la scriere)",
        };
      }
      return { ok: true, value: raw };
    }
    case "bytes": {
      // O coloană BINARĂ nu se poate scrie DIN LOT, iar refuzul ăsta e corect
      // prin proiectare, nu o funcție nescrisă. Trei fapte, în ordinea în care
      // contează:
      //
      //   * nu există formă de sârmă pentru octeți. `encode_value` din
      //     `sentinel/report/shipper.py` întoarce `None`, `bool`, `int`, `str`,
      //     `datetime` și `Decimal`, și ARUNCĂ (`ShipEncodingError`) pe orice
      //     altceva — dinadins, ca să nu apară un al doilea serializator pe care
      //     celălalt capăt nu-l cunoaște;
      //   * singura coloană de felul ăsta din schemă — `actor_attrs.value_hash`,
      //     `BINARY(32)` — NU vine de acolo: `migrations/0003_entities.sql` o dă
      //     drept „calculat la ingestie", agregatorul ESTE ingestia, iar de la
      //     #66 chiar o calculează — din `value`, prin `ChildStream.hashed`
      //     (`lib/streams.ts`), unde stă și rețeta, și motivul ei;
      //   * deci ce trece pe drumul ăsta e o DECLARAȚIE greșită, nu un lot
      //     greșit: `value_hash` pus între coloanele de pe sârmă în loc de
      //     `hashed`. Ramura asta e garda care o prinde, și o prinde înainte de
      //     bază.
      //
      // CE SE STRICĂ FĂRĂ REFUZUL ĂSTA, fiindcă asta era forma dinainte: coloana
      // era declarată `hash`, adică 64 de caractere hexa, iar șirul pleca spre
      // driver ca ȘIR. 64 de octeți într-o coloană de 32: `INSERT IGNORE`
      // TRUNCHIAZĂ cu un avertisment, rândul e PREZENT și altul decât cel
      // trimis, iar numărătoarea de identitate compară apoi cei 32 de octeți
      // stocați cu parametrul de 64 — nu potrivește niciodată, deci lotul e
      // `incomplete` la nesfârșit, cu un mesaj care numără rânduri în loc să
      // arate spre coloană. Groapa rămâne luminată: refuzul iese `invalid`, iar
      // `app/api/sentinel/sync/route.ts` îl scrie cu `console.warn`, cu detaliul
      // cu tot, plus `ship:lag` la celălalt capăt.
      const width = column.byteLength;
      return {
        ok: false,
        detail: `${where}: coloana e binară${width === undefined ? "" : ` (${width} octeți)`}` +
                ", iar octeții n-au formă de sârmă: `encode_value` din shipper.py " +
                "refuză orice nu e None/bool/int/str/datetime/Decimal. Singura " +
                "coloană binară din schemă se calculează LA INGESTIE, din altă " +
                "coloană a aceluiași rând, și se declară în `ChildStream.hashed` " +
                "— nu între coloanele care sosesc",
      };
    }
    case "json": {
      const checked = checkString(raw, column, where);
      if (!checked.ok) return checked;
      try {
        JSON.parse(checked.value);
      } catch {
        // Coloana `JSON` a MariaDB e `LONGTEXT` + `CHECK (json_valid(...))`, iar
        // sub `INSERT IGNORE` acel CHECK face rândul să dispară fără să spună
        // nimic. Refuzul de aici numește câmpul.
        return { ok: false, detail: `${where}: nu e JSON valid` };
      }
      return { ok: true, value: checked.value };
    }
    case "text": {
      const checked = checkString(raw, column, where);
      if (!checked.ok) return checked;
      return { ok: true, value: checked.value };
    }
  }
}

/**
 * Rândurile primite, verificate și puse în ordinea parametrilor.
 *
 * Nu repară nimic. Un validator care repară e un al doilea codificator, iar
 * atunci arhiva nu mai e o replică a nimic — același argument ca la
 * `sentinel/report/signing.py`.
 */
export function prepareRows(
  stream: Stream, rows: unknown[], instanceId: string, batchSeq: number,
): Prepared {
  if (rows.length === 0) {
    // Un flux fără rânduri, dar cu filigran, ar cere ecoul unui filigran pentru
    // rânduri care n-au fost trimise niciodată — adică fix avansarea cursorului
    // peste un gol. Expeditorul nu trimite așa ceva (`ship_once` sare fluxurile
    // goale); dacă totuși vine, e o eroare, nu o operație nulă.
    return { ok: false, detail: `rows.${stream.name}: lot gol` };
  }
  if (rows.length > MAX_ROWS_PER_BATCH) {
    return {
      ok: false,
      detail: `rows.${stream.name}: ${rows.length} rânduri, limita e ${MAX_ROWS_PER_BATCH}. ` +
              "Lotul NU a fost tăiat și nimic nu a fost scris; micșorează " +
              "ship.max_rows_per_batch pe expeditor.",
    };
  }

  // Câmpurile CUNOSCUTE sunt coloanele fluxului PLUS tablourile de sub-rânduri.
  // Un tablou ajuns aici fără să fie declarat rămâne „câmp necunoscut", adică un
  // refuz zgomotos — nu o listă aruncată tăcut, care ar fi chiar pierderea
  // definitivă pe care regula câmpurilor necunoscute o previne.
  const childSpecs = stream.children ?? [];
  const known = new Set([...stream.columns.map((c) => c.source),
                         ...childSpecs.map((c) => c.source)]);
  const keyColumns = stream.identity.filter((column) => column !== "instance_id");
  const keys: (number | string)[] = [];
  const identities: unknown[][] = [];
  const seen = new Set<string>();
  const values: unknown[][] = [];
  const children: PreparedChildren[] = childSpecs.map((child) => ({
    child, groups: [], identities: [], values: [],
  }));
  const seenChildren = childSpecs.map(() => new Set<string>());
  let childRows = 0;

  for (let i = 0; i < rows.length; i++) {
    const raw = rows[i];
    const where = `rows.${stream.name}[${i}]`;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      return { ok: false, detail: `${where}: aștept un obiect, am ${describe(raw)}` };
    }
    const row = raw as Record<string, unknown>;

    // Un câmp pe care nu-l cunoaștem înseamnă că sursa a crescut o coloană pe
    // care replica nu o are. Ignorat, s-ar pierde DEFINITIV: cursorul ar trece
    // peste rând, iar rândul nu se mai retrimite niciodată. Deci se refuză, iar
    // fluxul stă pe loc până când agregatorul primește migrația — vizibil în
    // `ship:lag`, nu tăcut în arhivă.
    for (const field of Object.keys(row)) {
      if (!known.has(field)) {
        return {
          ok: false,
          detail: `${where}: câmpul necunoscut "${field}"; fluxul ${stream.name} ` +
                  "are nevoie de o migrație a agregatorului înainte să poată fi acceptat",
        };
      }
    }

    const tuple: unknown[] = [instanceId];
    const byTarget = new Map<string, unknown>();
    // Valoarea filigranului aşa cum a SOSIT, înainte de orice conversie.
    //
    // Filigranul e un jeton de ecou: trebuie să fie calculabil identic la
    // ambele capete DIN CONŢINUTUL LOTULUI. Citit din valoarea convertită,
    // depinde de conversia receptorului — iar pentru o coloană de timp aia
    // normalizează `2026-08-21T13:00:00+00:00` la `2026-08-21 13:00:00.000000`.
    // Ecoul n-ar mai potrivi niciodată, iar cursorul n-ar mai avansa pe un lot
    // perfect valid. Pentru fluxurile cu filigran întreg sau text simplu cele
    // două valori coincid, deci nimic nu se schimbă acolo.
    let watermarkRaw: unknown = undefined;
    for (const column of stream.columns) {
      if (!own(row, column.source)) {
        return { ok: false, detail: `${where}: lipsește câmpul "${column.source}"` };
      }
      const checked = checkColumn(row[column.source], column, `${where}.${column.source}`);
      if (!checked.ok) return { ok: false, detail: checked.detail };
      tuple.push(checked.value);
      byTarget.set(column.target, checked.value);
      if (column.target === stream.watermark) watermarkRaw = row[column.source];
    }
    tuple.push(batchSeq);

    // Identitatea, din coloanele DECLARATE, nu din poziție. O coloană de cheie
    // pe care fluxul n-o trimite nu e „nimic de verificat": ar face
    // numărătoarea să întrebe despre altceva decât s-a scris.
    const identity: unknown[] = [];
    for (const column of keyColumns) {
      if (!byTarget.has(column)) {
        return {
          ok: false,
          detail: `${where}: fluxul ${stream.name} nu trimite coloana de ` +
                  `identitate "${column}", deci efectul lui nu se poate număra`,
        };
      }
      identity.push(byTarget.get(column));
    }

    // Dedublarea e pe IDENTITATE, nu pe filigran. Două rânduri cu aceeași
    // identitate în același lot: `INSERT IGNORE` l-ar păstra pe primul și l-ar
    // arunca pe al doilea, iar numărătoarea ar ieși corectă — adică exact un
    // rând pierdut cu filigranul ecouat. Pe un flux cu cheie compusă
    // (`asset_tags`: aceeași sursă, etichete diferite) dedublarea pe filigran
    // respingea în schimb loturi PERFECT VALIDE, fiindcă acolo `source_id` se
    // repetă prin construcție.
    const fingerprint = JSON.stringify(identity);
    if (seen.has(fingerprint)) {
      return {
        ok: false,
        detail: `${where}: identitatea (${showIdentity(identity)}) apare de două ` +
                "ori în același lot",
      };
    }
    seen.add(fingerprint);

    const key = watermarkRaw;
    const wantsText = stream.watermarkKind === "text";
    if (wantsText ? typeof key !== "string" || key === "" : typeof key !== "number") {
      // Felul filigranului e declarat pe flux, iar `sentinel/report/shipper.py`
      // mai degrabă OPREȘTE fluxul (`ShipEncodingError`) decât să inventeze unul
      // de alt fel. Aceeași margine la ambele capete: dacă valoarea nu e de felul
      // declarat, nu există filigran, deci nu există nici ce ecoua.
      //
      // Șirul gol e refuzat separat de tipul greșit: e o valoare pe care
      // `GREATEST` ar alege-o ca minim tăcut, iar un cursor așezat pe el n-ar
      // mai avansa niciodată.
      return {
        ok: false,
        detail: `${where}: coloana de filigran "${stream.watermark}" nu poartă ` +
                `${wantsText ? "un șir nevid" : "un întreg"}, deci lotul n-are ce ` +
                "filigran să primească înapoi",
      };
    }
    keys.push(key as number | string);
    identities.push(identity);
    values.push(tuple);

    // Sub-rândurile, DUPĂ ce părintele e validat: legătura lor se ia din
    // `byTarget`, deci înainte n-ar avea de unde.
    for (let c = 0; c < childSpecs.length; c++) {
      const child = childSpecs[c];
      // Câmpul ABSENT e o eroare, tabloul GOL nu. Sunt lucruri diferite: „nu
      // mi-ai spus ce etichete are activul" e un lot stricat, iar „activul n-are
      // nicio etichetă" e un fapt care trebuie să ajungă la receptor, fiindcă
      // altfel etichetele lui de ieri rămân acolo pentru totdeauna.
      if (!own(row, child.source)) {
        return { ok: false, detail: `${where}: lipsește câmpul "${child.source}"` };
      }
      const list = row[child.source];
      if (!Array.isArray(list)) {
        return {
          ok: false,
          detail: `${where}.${child.source}: aștept un tablou de sub-rânduri pentru ` +
                  `${child.table}, am ${describe(list)}`,
        };
      }
      if (list.length > MAX_CHILDREN_PER_ROW) {
        return {
          ok: false,
          detail: `${where}.${child.source}: ${list.length} sub-rânduri, limita e ` +
                  `${MAX_CHILDREN_PER_ROW}. Nimic nu a fost scris și nimic nu a fost ` +
                  "tăiat — un tablou tăiat ar face curățarea să șteargă exact ce n-a " +
                  "încăput. Plafonul se mărește pe agregator.",
        };
      }
      childRows += list.length;
      if (childRows > MAX_CHILD_ROWS_PER_BATCH) {
        return {
          ok: false,
          detail: `rows.${stream.name}: peste ${MAX_CHILD_ROWS_PER_BATCH} sub-rânduri ` +
                  "în lot, peste toate tabelele de legătură. Nimic nu a fost scris; " +
                  "micșorează ship.max_rows_per_batch pe expeditor.",
        };
      }

      const linkValues: unknown[] = [];
      for (const link of child.link) {
        if (!byTarget.has(link.parent)) {
          return {
            ok: false,
            detail: `${where}: fluxul ${stream.name} nu trimite coloana "${link.parent}", ` +
                    `de care atârnă sub-rândurile din ${child.table}`,
          };
        }
        linkValues.push(byTarget.get(link.parent));
      }

      const group: ChildGroup = { parent: linkValues, identities: [] };
      children[c].groups.push(group);

      const childKnown = new Set(child.columns.map((cc) => cc.source));
      for (let j = 0; j < list.length; j++) {
        const rawChild = list[j];
        const at = `${where}.${child.source}[${j}]`;
        if (rawChild === null || typeof rawChild !== "object" || Array.isArray(rawChild)) {
          return { ok: false, detail: `${at}: aștept un obiect, am ${describe(rawChild)}` };
        }
        const childRow = rawChild as Record<string, unknown>;
        for (const field of Object.keys(childRow)) {
          if (!childKnown.has(field)) {
            // Aici cade și copilul care își aduce singur părintele: coloanele de
            // legătură NU sunt ale lui. Un sub-rând care ar putea să-și numească
            // părintele ar putea să-l numească greșit, iar rezultatul — o
            // etichetă atârnată de alt activ — nu se vede de nicăieri.
            return {
              ok: false,
              detail: `${at}: câmpul necunoscut "${field}"; sub-rândurile din ` +
                      `${child.table} poartă doar ${[...childKnown].join(", ")}, iar ` +
                      "legătura cu părintele vine din rândul în care stau",
            };
          }
        }

        const byChild = new Map<string, unknown>();
        child.link.forEach((link, k) => byChild.set(link.child, linkValues[k]));
        const childTuple: unknown[] = [instanceId, ...linkValues];
        for (const column of child.columns) {
          if (!own(childRow, column.source)) {
            return { ok: false, detail: `${at}: lipsește câmpul "${column.source}"` };
          }
          const checked = checkColumn(childRow[column.source], column, `${at}.${column.source}`);
          if (!checked.ok) return { ok: false, detail: checked.detail };
          childTuple.push(checked.value);
          byChild.set(column.target, checked.value);
        }

        // Coloanele CALCULATE, DUPĂ cele sosite: se derivă din ele, deci
        // înainte n-ar avea de unde. Rezultatul intră în `byChild`, ca
        // identitatea de mai jos să-l ia ca pe orice altă coloană — la
        // `actor_attrs` digestul chiar E o coloană de cheie.
        //
        // Ordinea în `childTuple` e ordinea din `childTarget`: legătura,
        // coloanele de pe sârmă, apoi cele calculate. Cele două se citesc
        // împreună sau deloc.
        for (const derived of child.hashed ?? []) {
          const source = byChild.get(derived.from);
          if (typeof source !== "string") {
            // Declarație greșită, nu lot greșit — dar tot un refuz, fiindcă
            // alternativa e un digest peste `String(altceva)`, adică o
            // identitate inventată de replică.
            const what = byChild.has(derived.from)
              ? `poartă ${describe(source)}`
              : "nu e o coloană a sub-rândului";
            return {
              ok: false,
              detail: `${at}: ${derived.target} se calculează din "${derived.from}", ` +
                      `care ${what}; un digest se ia peste TEXT`,
            };
          }
          const digest = digestOf(source);
          // Lățimea se verifică ÎNAINTE de bază, și nu e neîncredere în SHA-256
          // — care dă întotdeauna 32 de octeți —, ci în DECLARAȚIE:
          // `byteLength` e numărul din `BINARY(n)` al migrației, iar `BINARY(n)`
          // nu refuză nimic: completează cu zerouri ce e mai scurt și TAIE ce e
          // mai lung, tăcut. Dacă cele două s-au despărțit, rândul ar fi PREZENT
          // și altul decât cel scris, iar numărătoarea de identitate n-ar
          // potrivi niciodată — `incomplete` la fiecare reluare, cu un mesaj
          // care numără rânduri în loc să arate spre coloană.
          if (digest.length !== derived.byteLength) {
            return {
              ok: false,
              detail: `${at}: ${derived.target} a ieșit ${digest.length} octeți, iar ` +
                      `coloana e declarată BINARY(${derived.byteLength}); nu se scrie ` +
                      "nimic, fiindcă acolo n-ar fi refuzat, ar fi completat sau tăiat",
            };
          }
          childTuple.push(digest);
          byChild.set(derived.target, digest);
        }

        const childIdentity: unknown[] = [];
        for (const column of child.identity) {
          if (column === "instance_id") continue;
          if (!byChild.has(column)) {
            return {
              ok: false,
              detail: `${at}: ${child.table} e identificată și prin "${column}", pe care ` +
                      "sub-rândul nu-l scrie, deci efectul lui nu se poate număra",
            };
          }
          childIdentity.push(byChild.get(column));
        }

        // Dedublarea e pe tot LOTUL, nu pe rândul părinte: identitatea unui
        // sub-rând conține legătura, deci două sub-rânduri identice nu pot veni
        // decât de sub același părinte — iar `INSERT IGNORE` l-ar păstra pe
        // primul, cu numărătoarea ieșind corectă.
        const fingerprint = JSON.stringify(childIdentity);
        if (seenChildren[c].has(fingerprint)) {
          return {
            ok: false,
            detail: `${at}: sub-rândul (${showIdentity(childIdentity)}) apare de două ori ` +
                    "în același lot",
          };
        }
        seenChildren[c].add(fingerprint);
        group.identities.push(childIdentity);
        children[c].identities.push(childIdentity);
        children[c].values.push(childTuple);
      }
    }
  }

  return { ok: true, keys, identities, values, children };
}

// ---------------------------------------------------------------------------
// SQL. Identificatorii vin DOAR din `lib/streams.ts`, niciodată din cerere.
// ---------------------------------------------------------------------------
/**
 * CE se scrie, într-o formă din care `writeSql` poate deriva TOT.
 *
 * Un rând părinte și un sub-rând se scriu prin aceeași funcție fiindcă
 * diferențele dintre ele sunt DATE, nu ramuri pe nume de tabelă: are sau n-are
 * contabilitate proprie, refuză sau nu `UPDATE`.
 */
export type WriteTarget = {
  table: string;
  /** Coloanele scrise din rând, în ordinea parametrilor, fără `instance_id`. */
  columns: readonly string[];
  /** Cheia unică a tabelei, începând cu `instance_id`. */
  identity: readonly string[];
  /**
   * Rândul are contabilitate PROPRIE a sosirii: `received_at` + `batch_seq`.
   *
   * Derivat din DECLARAȚIE, nu dintr-o listă de nume de tabele. Un rând părinte e
   * o sosire, deci le are; un sub-rând e o parte a sosirii părintelui, deci nu.
   * O listă de excepții pe nume ar fi un recunoscător, iar un recunoscător rămâne
   * mereu cu o ortografie în urmă — a șasea tabelă de legătură ar primi tăcut
   * `received_at` într-o coloană care nu există, adică `Unknown column` la primul
   * lot.
   */
  accounted: boolean;
  /** Tabela refuză `UPDATE` printr-un trigger, deci upsertul ar omorî lotul. */
  appendOnly: boolean;
};

/** Ce se scrie pentru un rând PĂRINTE. */
export function parentTarget(stream: Stream): WriteTarget {
  return {
    table: stream.table,
    columns: stream.columns.map((c) => c.target),
    identity: stream.identity,
    accounted: true,
    appendOnly: stream.cursor === "append-only",
  };
}

/**
 * Ce se scrie pentru un SUB-RÂND.
 *
 * `appendOnly` e fals, și nu fiindcă am ales noi: singurele triggere din schemă
 * sunt cele două de pe `audit_entries` (`tests/schema.test.ts`, „triggerele de
 * append-only sunt amândouă acolo" plus garda care refuză un trigger pe orice
 * altă tabelă replicată). Deci ramura de UPDATE e disponibilă pe orice tabelă de
 * legătură — iar dacă n-are ce actualiza, `writeSql` alege oricum `INSERT IGNORE`.
 *
 * Sub-rândul NU moștenește felul cursorului părintelui, și e o decizie: felul
 * părintelui spune dacă RÂNDUL DE LA SURSĂ se schimbă, iar un sub-rând n-are
 * conținut care să se schimbe — e (aproape) numai identitate. Ce se schimbă la el
 * e dacă EXISTĂ, iar aia se face prin ștergere, nu prin actualizare.
 *
 * ORDINEA coloanelor e chiar ordinea în care `prepareRows` umple tuplul —
 * legătura, coloanele sosite, apoi cele CALCULATE (`hashed`). Cele două locuri
 * se citesc împreună sau deloc: o coloană mutată doar aici leagă valorile la
 * alte coloane, iar `INSERT IGNORE` s-ar plânge numai dacă se ceartă tipurile.
 *
 * Ce înseamnă o coloană derivată pentru ramura de actualizare, ca să nu pară o
 * scăpare: la `actor_attrs` digestul e în cheie, deci clauza `SET` rămâne
 * `value = VALUES(value)` — o atribuire care nu poate schimba nimic, fiindcă
 * două rânduri cu același `value_hash` au același `value` (mai puțin la o
 * coliziune SHA-256). E o consecință a cheii, nu o specializare pe tabelă:
 * instrucțiunea se derivă la fel pentru toți copiii.
 */
export function childTarget(child: ChildStream): WriteTarget {
  return {
    table: child.table,
    columns: [...child.link.map((l) => l.child), ...child.columns.map((c) => c.target),
              ...(child.hashed ?? []).map((h) => h.target)],
    identity: child.identity,
    accounted: false,
    appendOnly: false,
  };
}

/**
 * Instrucțiunea de scriere, derivată în întregime din `WriteTarget`.
 *
 * Nu e o optimizare, e corectitudine, și formele se exclud:
 *
 * * `append-only` → `INSERT IGNORE`. Primul scris câștigă, iar pe
 *   `audit_entries` e OBLIGATORIU: ramura de UPDATE a lui `ON DUPLICATE KEY`
 *   declanșează triggerul de append-only și omoară lotul la primul rând deja
 *   prezent — adică la fiecare retrimitere, care e cazul normal.
 * * `mutable` → `ON DUPLICATE KEY UPDATE`. Un incident care se închide TREBUIE
 *   să se suprascrie; cu `INSERT IGNORE` ar rămâne deschis în panou, iar
 *   expeditorul ar trece peste el definitiv. Tabelele astea nu au trigger de
 *   append-only, deci forma e disponibilă.
 * * **nimic de actualizat** → tot `INSERT IGNORE`. E cazul sub-rândurilor care
 *   sunt numai identitate, și nu e o preferință: `ON DUPLICATE KEY UPDATE` cu
 *   clauza goală nu e SQL valid.
 *
 * `VALUES(col)`, nu parametri legați a doua oară: MariaDB nu are forma cu alias
 * de rând (`AS new`) din MySQL 8.0.19+, iar legarea a doua oară ar dubla un
 * număr de parametri care e deja `rânduri × coloane`. Compromisul e că
 * `VALUES()` e depreciat în MySQL, nu și în MariaDB — care e serverul de aici.
 *
 * Ce se actualizează: TOATE coloanele scrise care nu sunt identitate, plus
 * `received_at` și `batch_seq` DACĂ rândul le are. Identitatea NU — ea a fost
 * cheia potrivirii. `received_at` înseamnă atunci „când a sosit VERSIUNEA asta",
 * ceea ce e chiar ce vrei să citești despre un rând care se schimbă.
 *
 * Coloanele de contabilitate NU se mai emit necondiționat (#62): patru tabele de
 * legătură din `0003_entities.sql` și una din `0005_patch.sql` nu le au deloc,
 * iar un `INSERT` care le numea murea cu „Unknown column 'received_at' in 'field
 * list'" — un mesaj care arată spre o coloană, nu spre decizia care lipsea.
 * Criteriul e `target.accounted`, adică declarația, nu o listă de nume de tabele.
 *
 * Identitatea e cheia unică din migrație, DECLARATĂ în `lib/streams.ts` și
 * verificată împotriva schemei — nu dedusă din tipul coloanelor. Motivul întreg e
 * acolo: mai multe tabele ale fazei sunt identificate prin text, ENUM,
 * `BINARY(32)` sau `INET6`, deci o deducție „coloana cu kind id" le-ar fi trecut
 * cheia în clauza `SET` fără ca nimic să spună ceva.
 *
 * O coloană uitată din clauza de actualizare ar rămâne pentru totdeauna la
 * valoarea primei sosiri, iar numărătoarea de după N-AR VEDEA — rândul e
 * prezent. De-aia clauza se construiește din specificație, nu scrisă de mână, iar
 * testul din `tests/ingest.test.ts` intitulat „clauza de actualizare e DERIVATĂ
 * din specificație" o compară pe cea generată cu mulțimea derivată din același
 * spec — nu cu o listă de nume, care ar lăsa neapărată orice coloană adăugată
 * după ce a fost scrisă.
 *
 * EXPORTATĂ pentru teste, dinadins: instrucțiunea E artefactul. O coloană de
 * cheie ajunsă în `SET` nu se vede nici în rândul stocat, nici în numărătoare —
 * numai în text.
 */
export function writeSql(target: WriteTarget, rowCount: number): string {
  // `received_at` se scrie explicit cu `UTC_TIMESTAMP(6)`, nu se lasă pe seama
  // lui `DEFAULT CURRENT_TIMESTAMP(6)`: acela dă ora LOCALĂ a sesiunii, iar
  // coloana e documentată ca UTC. Pe o gazdă pornită în alt fus, restanța
  // expeditorului — chiar diferența pentru care există coloana — ar fi citită
  // greșit cu câteva ore.
  const columns = ["instance_id", ...target.columns,
                   ...(target.accounted ? ["received_at", "batch_seq"] : [])];
  const placeholders = ["?", ...target.columns.map(() => "?"),
                        ...(target.accounted ? ["UTC_TIMESTAMP(6)", "?"] : [])];
  const tuple = `(${placeholders.join(", ")})`;
  const values = Array.from({ length: rowCount }, () => tuple).join(", ");

  const identity = new Set(target.identity);
  const updates = columns
    .filter((column) => !identity.has(column))
    .map((column) => column === "received_at"
      ? "received_at = UTC_TIMESTAMP(6)"
      : `${column} = VALUES(${column})`);

  // Zero atribuiri se întâmplă CHIAR: patru din cele cinci tabele de legătură
  // sunt numai identitate (`asset_tags` e `(instance_id, source_id, tag)`, și
  // atât). `ON DUPLICATE KEY UPDATE` cu clauza goală nici măcar nu e SQL valid,
  // iar un rând care nu are ce actualiza n-a pierdut nimic dacă e sărit — la el,
  // conținutul E identitatea.
  if (target.appendOnly || updates.length === 0) {
    return `INSERT IGNORE INTO ${target.table} (${columns.join(", ")}) VALUES ${values}`;
  }
  return `INSERT INTO ${target.table} (${columns.join(", ")}) VALUES ${values} ` +
         `ON DUPLICATE KEY UPDATE ${updates.join(", ")}`;
}

/**
 * Numărătoarea, pe IDENTITATEA declarată a fluxului.
 *
 * Aici stă singura dovadă de efect din tot sistemul, deci coloanele după care se
 * numără trebuie să fie exact cele care fac un rând să fie același rând. Scrisă
 * pe `source_id`, cum era, întreba despre altceva: pe `asset_tags`
 * — `(instance_id, source_id, tag)` — trei etichete ale aceluiași activ sunt trei
 * rânduri cu ACELAȘI `source_id`, deci numărătoarea ar fi zis „3 prezente" și
 * după ce două dintre ele s-ar fi pierdut. Ecoul s-ar fi emis pe o măsurătoare
 * care măsoară altceva.
 *
 * Două forme, dinadins:
 *
 *   * o singură coloană → `col IN (?, ?, …)`. E instrucțiunea care rulează AZI
 *     în producție pentru `audit_log`, singurul flux înregistrat, și rămâne
 *     neatinsă de o schimbare făcută pentru celelalte. Un refactor care rescrie
 *     dovada de efect a fluxului viu ca efect secundar e chiar tiparul din
 *     `CLAUDE.md`.
 *   * mai multe → `(a, b) IN ((?, ?), …)`, constructorul de rânduri al MariaDB.
 *     Alternativa, un `OR` de conjuncții, are aceiași parametri și un plan mai
 *     prost.
 *
 * Parametrii: `CHUNK` rânduri × coloanele cheii, plus instanța — 200 × 5 + 1
 * pentru cel mai lat flux de azi (`event_rollup_1h`), mult sub cele 65535 pe care
 * le acceptă protocolul. Bucata rămâne cea de la scriere, ca cele două să nu se
 * poată despărți tăcut.
 *
 * COSTUL, scris aici ca să nu fie căutat: MariaDB nu folosește întotdeauna
 * indexul pentru un `IN` cu constructori de rânduri, deci pe o tabelă mare
 * numărătoarea asta poate degrada la o parcurgere completă. E cost, nu
 * corectitudine — numărul rămâne adevărat —, dar e primul loc unde trebuie să se
 * uite cine vede ingestia încetinind. Nemăsurat: n-avem MariaDB unde se scrie
 * asta, deci nici planul, nici pragul de la care contează nu sunt cunoscute.
 */
const marks = (n: number) => Array.from({ length: n }, () => "?").join(", ");

/**
 * `col IN (…)` sau `(a, b) IN ((…), …)`, cu sau fără negare.
 *
 * NEGAREA are o capcană care nu se vede: `x NOT IN (…)` cu un `NULL` în listă e
 * UNKNOWN, deci nu potrivește NIMIC — o curățare care n-ar șterge nimic, tăcut.
 * De-aia coloanele de identitate ale unui sub-rând se cer `nullable: false`.
 * Regula e păzită de `tests/subrows.test.ts`, testul
 * „regula de declarare a unui copil se declanșează SINGURĂ".
 */
function inPredicate(columns: readonly string[], rowCount: number, negated = false): string {
  const not = negated ? "NOT " : "";
  return columns.length === 1
    ? `${columns[0]} ${not}IN (${marks(rowCount)})`
    : `(${columns.join(", ")}) ${not}IN ` +
      `(${Array.from({ length: rowCount }, () => `(${marks(columns.length)})`).join(", ")})`;
}

function countSql(table: string, columns: readonly string[], rowCount: number): string {
  return `SELECT COUNT(*) AS n FROM ${table} ` +
         `WHERE instance_id = ? AND ${inPredicate(columns, rowCount)}`;
}

/**
 * Ștergerea sub-rândurilor rămase pe dinafară: ce e sub părinții ăștia și NU e în
 * lot.
 *
 * Fără ea, un upsert de copii ar CONTOPI: un IP scos din `member_ips` ar rămâne
 * în `actor_ips` pentru totdeauna, iar panoul ar arăta un actor care folosește o
 * adresă pe care serverul nu i-o mai atribuie. Gunoiul ăla nu se mai șterge
 * niciodată de nicăieri — nimic nu-l mai vizitează.
 *
 * Când lotul n-are niciun sub-rând pentru părinții din bucată, clauza de excludere
 * LIPSEȘTE cu totul: `NOT IN ()` nu e SQL valid, iar înțelesul cerut e chiar
 * „șterge tot ce e sub ei".
 */
function deleteSql(child: ChildStream, parentCount: number, identityCount: number): string {
  const link = child.link.map((l) => l.child);
  const keys = child.identity.filter((column) => column !== "instance_id");
  const parts = ["instance_id = ?", inPredicate(link, parentCount)];
  if (identityCount > 0) parts.push(inPredicate(keys, identityCount, true));
  return `DELETE FROM ${child.table} WHERE ${parts.join(" AND ")}`;
}

/**
 * Bucățile în care se face curățarea: grupuri de părinți, mărginite ca PARAMETRI.
 *
 * Un grup nu se poate rupe — clauza de excludere trebuie să conțină TOȚI copiii
 * părinților din bucată, altfel ștergerea ar înghiți exact sub-rândurile care
 * n-au încăput în listă. Deci se taie ÎNTRE grupuri, iar bugetul se socotește pe
 * costul real: o legătură per părinte, o identitate per copil.
 */
function deleteChunks(child: ChildStream, groups: ChildGroup[]): ChildGroup[][] {
  const perParent = child.link.length;
  const perChild = child.identity.length - 1;
  const out: ChildGroup[][] = [];
  let current: ChildGroup[] = [];
  let params = 1;
  for (const group of groups) {
    const cost = perParent + group.identities.length * perChild;
    if (current.length && params + cost > DELETE_PARAM_BUDGET) {
      out.push(current);
      current = [];
      params = 1;
    }
    current.push(group);
    params += cost;
  }
  if (current.length) out.push(current);
  return out;
}

function chunks<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/**
 * Câte rânduri din tabelă potrivesc tuplurile astea, CHIAR ACUM. `null` = nu se
 * poate ști.
 *
 * `IN (...)` cu valorile exacte, nu `BETWEEN min AND max`: un interval ar număra
 * și rânduri sosite în alte loturi, iar atunci un lot cu goluri ar părea complet.
 * Numărul trebuie să fie despre RÂNDURILE ASTEA.
 *
 * Coloanele se dau, nu se deduc din flux, fiindcă se pun DOUĂ întrebări diferite
 * cu aceeași instrucțiune: „sunt identitățile astea acolo?" (coloanele cheii) și
 * „câte sub-rânduri sunt sub părinții ăștia?" (coloanele de legătură). A doua e
 * cea care deosebește înlocuirea de contopire, și fără ea un lot în care
 * curățarea a eșuat ar arăta identic cu unul curat.
 */
async function countPresent(
  db: Db, table: string, columns: readonly string[], instanceId: string,
  tuples: unknown[][],
): Promise<number | null> {
  let total = 0;
  for (const part of chunks(tuples, CHUNK)) {
    const rows = await db.all(countSql(table, columns, part.length),
                              [instanceId, ...part.flat()]);
    if (!rows.length || rows[0] == null) return null;
    // „Nu înțeleg răspunsul" nu e zero. Zero ar însemna „niciun rând nu e
    // acolo", iar diferența dintre asta și „n-am putut întreba" e diferența
    // dintre un lot pierdut și o bază care n-a răspuns.
    //
    // `null` și `undefined` se verifică ÎNAINTE de conversie, ca în
    // `guardPresent` (`lib/migrate.ts`): `Number(null)` e 0, adică exact
    // afirmația pe care n-avem dreptul s-o facem. `COUNT(*)` nu întoarce NULL în
    // SQL — dar o coloană citită de sub alt nume, sau un rând venit din altă
    // interogare decât credem, da.
    const raw = rows[0].n;
    if (raw === undefined || raw === null) return null;
    const n = Number(raw);
    if (!Number.isFinite(n)) return null;
    total += n;
  }
  return total;
}

// ---------------------------------------------------------------------------
// O rundă de ingestie, pentru UN flux
// ---------------------------------------------------------------------------
export async function ingestStream(
  db: Db, instanceId: string, stream: Stream, rows: unknown[],
  watermark: number | string, batchSeq: number,
): Promise<IngestResult> {
  const prepared = prepareRows(stream, rows, instanceId, batchSeq);
  if (!prepared.ok) return { ok: false, kind: "invalid", detail: prepared.detail };
  const { keys, identities, values, children } = prepared;
  const keyColumns = stream.identity.filter((column) => column !== "instance_id");

  // Cel mai mare filigran DIN LOT, nu cel mai mare de până acum. Pe un flux
  // mutabil cele două chiar diferă: un rând vechi atins acum vine cu un `id`
  // mic, deci lotul următor are un filigran mai mic — și e corect, fiindcă
  // filigranul nu e o poziție, e ce se cere înapoi prin ecou. Poziția stă la
  // expeditor, ca `(updated_at, id)`, și nu pleacă de acolo.
  // Maximul, cu comparația felului declarat. Pe text e cea pe octeți —
  // aceeași pe care o face `max()` din expeditor peste șiruri, și aceeași pe
  // care o face `GREATEST` pe o coloană cu colație binară. Trei locuri, o
  // singură ordine: dacă ar diverge, ecoul n-ar mai potrivi și cursorul n-ar mai
  // avansa niciodată pe un lot perfect valid.
  const highest = stream.watermarkKind === "text"
    ? (keys as string[]).reduce((a, b) => (b > a ? b : a))
    : Math.max(...(keys as number[]));
  if (watermark !== highest) {
    // Filigranul ESTE promisiunea care se ecouă. Un filigran mai mare decât cel
    // mai mare `id` trimis ar cere expeditorului să treacă peste rânduri care
    // n-au fost în lot; unul mai mic ar retrimite la nesfârșit ce e deja aici.
    // Expeditorul îl calculează ca `rows[-1].id`, deci nepotrivirea înseamnă că
    // lotul nu vine de acolo sau că s-a stricat pe drum.
    return {
      ok: false, kind: "invalid",
      detail: `cursors.${stream.name}=${watermark} nu e cel mai mare id din ` +
              `rows.${stream.name} (${highest})`,
    };
  }

  try {
    const before = await countPresent(db, stream.table, keyColumns, instanceId, identities);
    if (before === null) {
      return { ok: false, kind: "unavailable",
               detail: `${stream.name}: nu pot număra rândurile prezente înainte de inserare` };
    }

    // 1. PĂRINTELE, ÎNAINTEA COPIILOR. Ordinea ține locul tranzacției pe care
    //    `Db` n-o are — vezi capul modulului. Invers, o cădere aici ar lăsa
    //    sub-rânduri atârnate de un părinte care nu există în replică, iar pe
    //    alea nu le mai vizitează nimic: curățarea de la pasul 4 se face pe
    //    părinții DIN LOT.
    for (const part of chunks(values, CHUNK)) {
      await db.run(writeSql(parentTarget(stream), part.length), part.flat());
    }

    // 2. FAPTUL DESPRE PĂRINȚI, înaintea oricărui sub-rând. `run` aruncă
    //    rezultatul dinadins (`lib/db.ts`), deci nu există aici niciun
    //    `affectedRows` de crezut pe cuvânt — și nici n-ar ajuta: `INSERT IGNORE`
    //    raportează 0 și pentru un duplicat sărit, și pentru un rând respins din
    //    alt motiv. Pe un upsert e chiar mai înșelător: MariaDB întoarce 2 pentru
    //    o actualizare, 1 pentru o inserare și 0 pentru un rând trimis identic cu
    //    cel stocat — trei numere pentru trei feluri de succes.
    //
    //    DE CE AICI, și nu la capăt, unde stătea: ordinea de mai sus oprește
    //    pasul 3 numai dacă scrierea părinților a ARUNCAT. O respingere TĂCUTĂ —
    //    chiar forma pentru care există tot modulul — nu aruncă, deci ordinea n-o
    //    vede, iar copiii ar pleca sub un părinte care nu e în replică. Numărați
    //    la capăt, orfanii erau descoperiți corect, dar erau deja pe disc: nimic
    //    nu-i mai vizitează, fiindcă singurul `DELETE` se face pe părinții DINTR-UN
    //    LOT. Nu e un dus-întors în plus — e chiar numărătoarea de la capăt, mutată
    //    unde poate încă opri ceva.
    //
    //    Ce se numără e PREZENȚA, nu modificarea, și pentru un flux mutabil asta e
    //    alegerea care contează: un rând retrimis neschimbat nu modifică nimic și
    //    e corect că nu modifică. Numărând „rânduri atinse" ar fi ieșit `incomplete`
    //    pe un lot perfect valid, la fiecare retrimitere a unui bucket de rollup —
    //    adică exact pe drumul proiectat să se repete.
    //
    //    Ce NU dovedește prezența, spus pe față: că actualizarea chiar a cuprins
    //    toate coloanele. O coloană uitată din clauza `ON DUPLICATE KEY UPDATE` ar
    //    lăsa un câmp înghețat la prima sosire, iar rândul ar fi tot „prezent".
    //    Aia se apără la construirea instrucțiunii — vezi `writeSql` — și e probată
    //    în `tests/ingest.test.ts`, de testul
    //    „clauza de actualizare e DERIVATĂ din specificație".
    const after = await countPresent(db, stream.table, keyColumns, instanceId, identities);
    if (after === null) {
      return { ok: false, kind: "unavailable",
               detail: `${stream.name}: nu pot număra rândurile prezente după inserare` };
    }
    if (after !== identities.length) {
      return {
        ok: false, kind: "incomplete",
        detail: `${stream.name}: am trimis ${identities.length} rânduri, în tabelă sunt ${after}. ` +
                "Filigranul NU se ecouă, deci lotul se va retrimite.",
      };
    }

    // 3. Copiii, ADITIV. Aici se ajunge numai după ce părinții au fost NUMĂRAȚI,
    //    nu doar scriși fără să arunce.
    for (const sub of children) {
      const target = childTarget(sub.child);
      for (const part of chunks(sub.values, CHUNK)) {
        await db.run(writeSql(target, part.length), part.flat());
      }
    }

    // 4. Curățarea: ce era sub părinții ăștia și nu mai e în lot. Fără ea,
    //    mulțimile s-ar CONTOPI, iar un IP scos din `member_ips` ar rămâne la
    //    receptor pentru totdeauna.
    for (const sub of children) {
      for (const part of deleteChunks(sub.child, sub.groups)) {
        const parents = part.map((group) => group.parent);
        const stale = part.flatMap((group) => group.identities);
        await db.run(deleteSql(sub.child, parents.length, stale.length),
                     [instanceId, ...parents.flat(), ...stale.flat()]);
      }
    }

    // 5. Efectul SUB-RÂNDURILOR, în două numere. Împreună sunt egalitatea de
    //    mulțimi; fiecare singur ar lăsa să treacă exact ce prinde celălalt.
    for (const sub of children) {
      const child = sub.child;
      const where = `${stream.name}.${child.source}`;
      const childKeys = child.identity.filter((column) => column !== "instance_id");

      const present = await countPresent(db, child.table, childKeys, instanceId,
                                         sub.identities);
      if (present === null) {
        return { ok: false, kind: "unavailable",
                 detail: `${where}: nu pot număra sub-rândurile prezente în ${child.table}` };
      }
      if (present !== sub.identities.length) {
        return {
          ok: false, kind: "incomplete",
          detail: `${where}: am trimis ${sub.identities.length} sub-rânduri, în ` +
                  `${child.table} sunt ${present}. Filigranul NU se ecouă, deci lotul ` +
                  "se va retrimite.",
        };
      }

      const link = child.link.map((l) => l.child);
      const under = await countPresent(db, child.table, link, instanceId,
                                       sub.groups.map((group) => group.parent));
      if (under === null) {
        return { ok: false, kind: "unavailable",
                 detail: `${where}: nu pot număra sub-rândurile rămase sub părinți în ` +
                         `${child.table}` };
      }
      if (under !== sub.identities.length) {
        // Toate cele trimise sunt acolo (numărul de deasupra), dar sub părinți
        // sunt mai multe: curățarea n-a rulat, sau a rulat pe jumătate. Mulțimea
        // de la receptor NU e cea de la sursă, deci nu se ecouă nimic.
        return {
          ok: false, kind: "incomplete",
          detail: `${where}: sub părinții din lot sunt ${under} sub-rânduri în ` +
                  `${child.table}, iar lotul a trimis ${sub.identities.length}. ` +
                  "Înlocuirea nu s-a terminat; filigranul NU se ecouă.",
        };
      }
    }

    // `inserted` rămâne despre RÂNDURILE fluxului, nu despre sub-rândurile lor:
    // `sync_cursors.rows_ingested` e contorul fluxului, iar un actor cu
    // douăsprezece adrese e un rând, nu treisprezece.
    const inserted = after - before;
    const cursor = await advanceCursor(db, instanceId, stream, watermark, inserted, batchSeq);
    if (cursor === null) {
      return { ok: false, kind: "unavailable",
               detail: `${stream.name}: nu pot citi cursorul după scriere` };
    }
    // Comparat pe FELUL filigranului. Numeric pentru întregi, pe octeți
    // pentru text — aceeași ordine ca `GREATEST` din instrucțiune și ca `max()`
    // din expeditor. Comparate ca numere, două filigrane text ar da `NaN < NaN`,
    // adică fals, iar verificarea ar trece verde peste un cursor care n-a
    // avansat.
    const short = stream.watermarkKind === "text"
      ? String(cursor) < String(watermark)
      : Number(cursor) < Number(watermark);
    if (short) {
      // Scrierea a ieșit fără eroare și cursorul n-a ajuns unde i s-a cerut.
      // Rândurile SUNT în arhivă, dar contabilitatea agregatorului nu spune
      // asta, iar `sync_cursors` e chiar locul din care se citește mai târziu
      // cine a rămas în urmă. Nu se ecouă: retrimiterea e ieftină, o minciună în
      // registru nu e.
      return {
        ok: false, kind: "incomplete",
        detail: `${stream.name}: cursorul a rămas la ${cursor}, i s-a cerut ${watermark}`,
      };
    }

    // `lowest` are sens doar pe un flux cu chei întregi — îl citește numai
    // verificarea de lanț, care e a lui `audit_log`. Pe unul cu chei text nu
    // există „cel mai mic id", iar un `Math.min` peste șiruri ar da `NaN`, adică
    // un număr care arată ca o valoare și nu e.
    const lowest = stream.watermarkKind === "text"
      ? 0 : Math.min(...(keys as number[]));
    return { ok: true, watermark, inserted, lowest };
  } catch (err) {
    return {
      ok: false, kind: "unavailable",
      detail: `${stream.name}: ${(err as Error).message}`.slice(0, 300),
    };
  }
}

/**
 * Mută cursorul de flux și întoarce ce are baza DUPĂ mutare. `null` = nu se
 * poate citi.
 *
 * Se citește înapoi, nu se presupune — aceeași regulă ca `_advance` din
 * `sentinel/report/shipper.py`: un `UPDATE` care n-a potrivit niciun rând iese
 * cu succes.
 *
 * `GREATEST` face mutarea monotonă. Un lot reluat (același `batch_seq`, aceleași
 * rânduri) e o operație nulă și nu are voie să tragă cursorul înapoi.
 * `sync_cursors` n-are trigger de append-only, deci aici `ON DUPLICATE KEY
 * UPDATE` chiar se poate folosi.
 *
 * CE ESTE, DE FAPT, `last_source_id` — și de ce contează pentru piesa 2:
 * maximul istoric al filigranelor primite, nu poziția fluxului. Pe `audit_log`
 * cele două coincid, fiindcă filigranele lui cresc. Pe un flux mutabil nu:
 * filigranul e maximul DIN LOT, iar loturile succesive pot scădea. `GREATEST` ar
 * păstra atunci un număr care nu spune unde a ajuns nimic.
 *
 * Nu e doar contabilitate. `confirmedThrough` din `lib/chain.ts` CITEȘTE coloana
 * asta ca poziție confirmată, și pe ea stă discriminatorul gol/ruptură al
 * verificării de lanț — vezi constrângerea scrisă acolo, în întregime.
 */
async function advanceCursor(
  db: Db, instanceId: string, stream: Stream,
  watermark: number | string, inserted: number, batchSeq: number,
): Promise<number | string | null> {
  // Coloana se alege din DECLARAȚIE, nu din tipul valorii primite. Aleasă din
  // valoare, un flux întreg căruia i-ar sosi din greșeală un șir și-ar scrie
  // tăcut filigranul în cealaltă coloană, iar `lib/chain.ts` — care citește
  // `last_source_id` ca poziție confirmată — ar vedea un cursor care nu se mai
  // mișcă niciodată.
  const column = stream.watermarkKind === "text" ? "last_source_key" : "last_source_id";
  await db.run(
    "INSERT INTO sync_cursors " +
    `(instance_id, stream, ${column}, rows_ingested, last_batch_seq) ` +
    "VALUES (?, ?, ?, ?, ?) " +
    "ON DUPLICATE KEY UPDATE " +
    `  ${column} = GREATEST(${column}, ?), ` +
    "  rows_ingested = rows_ingested + ?, " +
    "  last_batch_seq = GREATEST(COALESCE(last_batch_seq, 0), ?)",
    [instanceId, stream.name, watermark, inserted, batchSeq,
     watermark, inserted, batchSeq]);

  const rows = await db.all(
    `SELECT ${column} FROM sync_cursors WHERE instance_id = ? AND stream = ?`,
    [instanceId, stream.name]);
  if (!rows.length || rows[0] == null) return null;
  // Exact aceeași regulă ca la `countPresent`, și pentru același motiv:
  // `Number(null)` e 0, iar 0 e o AFIRMAȚIE — „cursorul e la început" — făcută
  // pe o valoare pe care n-am citit-o. Direcția e sigură în ambele cazuri
  // (0 < filigran, deci nu se ecouă nimic), dar mesajul ar fi greșit: operatorul
  // ar căuta un cursor căzut la zero în loc de o coloană care nu se citește.
  const raw = rows[0][column];
  if (raw === undefined || raw === null) return null;
  // Pe un flux cu filigran text valoarea SE ÎNTOARCE CA ȘIR, neatinsă: un
  // `Number()` peste ea ar da `NaN`, iar `NaN` trecut prin verificarea de
  // „cursorul a rămas în urmă" nu e nici mai mic, nici mai mare — deci ar
  // trece verde peste un cursor care n-a avansat.
  if (stream.watermarkKind === "text") return String(raw);
  // BIGINT vine ca șir (`bigNumberStrings`), deci conversia e explicită.
  const value = Number(raw);
  return Number.isFinite(value) ? value : null;
}

/**
 * Contabilitatea instanței: când a venit ultimul lot, și al câtelea era.
 *
 * Separat de ingestie și tolerant la eșec, dinadins. Ce s-a promis prin ecou e
 * că RÂNDURILE sunt în arhivă, iar asta e deja dovedit când se ajunge aici; un
 * `UPDATE` de diagnostic care eșuează nu are voie să blocheze un flux la
 * nesfârșit. Eșecul se scrie în jurnal de apelant.
 *
 * `first_seen_at` prin `COALESCE`, nu printr-un `SELECT` urmat de `UPDATE`:
 * două loturi simultane ale aceleiași instanțe ar putea trece amândouă de
 * verificare, iar al doilea ar rescrie momentul primului.
 *
 * `last_source_ip` rămâne NULL, dinadins. Aplicația e servită printr-un CDN,
 * deci adresa clientului ar veni dintr-un antet pe care îl poate scrie oricine
 * (vezi avertismentul despre limitarea de rată din planul E2). O adresă
 * fabricată scrisă într-o coloană numită „de unde a venit ultimul lot" e mai
 * rea decât una lipsă: NULL înseamnă „nu se știe", iar asta e adevărat.
 */
export async function noteBatch(db: Db, instanceId: string, batchSeq: number): Promise<void> {
  await db.run(
    "UPDATE instances SET " +
    "  first_seen_at = COALESCE(first_seen_at, UTC_TIMESTAMP(6)), " +
    "  last_batch_at = UTC_TIMESTAMP(6), " +
    "  last_batch_seq = GREATEST(COALESCE(last_batch_seq, 0), ?) " +
    "WHERE instance_id = ?",
    [batchSeq, instanceId]);
}
