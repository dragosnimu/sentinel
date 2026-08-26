/**
 * Ce instanțe are voie să vadă un cont — citit din bază, niciodată dedus.
 *
 * ## Regula, într-o propoziție
 *
 * **Nicio funcție de acces la date nu citește un rând fără o listă de instanțe
 * permise, iar lista aia vine dintr-un `SELECT` peste `user_instances`.**
 *
 * ## De ce un obiect și nu un `string[]`
 *
 * Fiindcă un `string[]` se poate fabrica de oriunde, iar locul din care cineva
 * l-ar fabrica e chiar locul greșit: parametrul din URL, un câmp din formular,
 * o listă memorată într-o componentă React. Toate trei arată identic la
 * compilare cu lista adevărată. Deci lista poartă o identitate: obiectul e
 * înregistrat la emitere (`WeakSet`), iar `assertScope` cere ca obiectul primit
 * să fie chiar unul emis aici. Un cast (`{ ids: ["prod"] } as InstanceScope`)
 * trece de compilator și ARUNCĂ la execuție.
 *
 * E aceeași mecanică — și dinadins aceeași, ca să fie una singură de învățat —
 * ca `ThrottlePass` din `lib/auth/gate.ts`, plus ceva ce acolo n-avea ce păzi:
 * `ThrottlePass` e un semn gol, pe când domeniul ăsta CARĂ date, iar datele
 * cărate se pot rescrie după ce identitatea a fost recunoscută. De-aia obiectul
 * emis e și ÎNCHIS la emitere — vezi `register`.
 *
 * Ce dovedesc cele două împreună: că lista și rolurile din obiectul ăsta, așa
 * cum se citesc ACUM, sunt chiar ce a întors interogarea — nu doar că au fost
 * cândva. Ce NU dovedesc, spus pe față ca și acolo: că au fost citite pentru
 * UTILIZATORUL ăsta, în CEREREA asta. Registrul e per proces.
 *
 * ## Cât ține identitatea asta, și de unde încolo nu mai ține
 *
 * Ce oprește, și e chiar ce trebuia oprit, în două feluri care nu se acoperă
 * unul pe altul:
 *
 *   * un domeniu FABRICAT în afara fișierului ăstuia — o rută care „știe ce
 *     face" și își compune lista din parametrul de URL, o componentă care și-o
 *     ține pe a ei, un cast pus ca să treacă de compilator — ARUNCĂ la
 *     `assertScope`, fiindcă `issued` nu se poate atinge de nicăieri altundeva;
 *   * un domeniu EMIS aici și LĂRGIT pe urmă. Identitatea singură nu vedea asta,
 *     și textul de aici a spus până pe 18 august 2026 că „toate arată” — evadarea
 *     măsurată nu atingea `issued` deloc. Din `lib/data/instances.ts`, cod
 *     livrat, cu `tsc` la zero și suita verde:
 *
 *         (scope.allowedInstanceIds as string[]).push("prod-b");
 *         (scope.roles as Map<string, string>).set("prod-b", "owner");
 *
 *     iar un cont cu drept doar pe `prod-a` a primit din `visibleInstances`
 *     `["prod-a/viewer", "prod-b/owner"]` — al doilea server și un rol pe care
 *     nu i l-a dat nimeni, fără nicio excepție. Acum amândouă liniile ARUNCĂ.
 *
 * Închiderea asta e o proprietate a OBIECTULUI, deci ține din orice fișier
 * livrat și cu orice cast: `readonly` e o promisiune făcută compilatorului, pe
 * care un cast o retrage, pe când un obiect înghețat refuză scrierea la execuție.
 * Ce NU cumpără, ca să nu se creadă mai mult: nimic despre cererea în care
 * ajunge domeniul (mai jos), și nimic împotriva cuiva care rescrie chiar
 * `Object.freeze` din cod livrat încărcat mai devreme. Granița e aceeași ca la
 * `issued`: apără de cine CHEAMĂ de afară, nu de cine scrie în procesul ăsta.
 *
 * Ce NU oprește, măsurat pe 17 august 2026 și scris aici ca să nu se mai creadă
 * altceva: o a doua cale de emitere scrisă CHIAR ÎN FIȘIERUL ĂSTA. Două forme,
 * amândouă probate, amândouă cu suita verde:
 *
 *     const mint = issued;                  // alt nume pentru același registru
 *     export function scopeAnyone(ids) { … mint.add(forged); return forged; }
 *
 *     export function register …            // exportat; îl cheamă alt fișier livrat
 *
 * (a doua e scrisă fără paranteză dinadins: numărătoarea de mai jos e pe
 * `register` urmat de paranteză, iar o gardă care se înroșește la propria ei
 * explicație e o gardă pe care o șterge primul om care o citește — același
 * argument ca la `JOIN_MENTIONS`.)
 *
 * Amândouă produc un obiect pe care `assertScope` îl acceptă fără să se fi
 * atins nimeni de `user_instances`. Recensământul din `tests/panel-authz.test.ts`
 * e deci o gardă ORIENTATIVĂ: prinde o scurtătură scrisă din neatenție („îmi
 * trebuie un domeniu aici, îl fac"), nu una scrisă anume ca să treacă de ea.
 * Textul de aici a spus până acum că „o a doua cale nu se poate scrie în altă
 * parte" — adevărat despre alte fișiere, fals despre ăsta, și scris ca și cum ar
 * fi fost despre tot.
 *
 * Consecința practică: apărarea de aici e o singură treaptă, nu două.
 *
 * Golul dintâi — că domeniul nu poartă cererea — e închis tot de UN singur
 * mecanism, și e bine să nu se creadă că sunt două:
 * `lib/auth/panel.ts` reconstruiește domeniul din sesiunea cererii, la
 * FIECARE cerere, deci un domeniu al altcuiva n-are cum să ajungă în calea unei
 * cereri — n-are unde să supraviețuiască între ele. Proba e prin efect, în
 * `tests/panel-authz.test.ts`: un cache per proces în `panel.ts` înroșește opt
 * teste.
 *
 * `InstanceScope.userId` NU e a doua jumătate a apărării ăsteia, și textul de
 * aici a spus până pe 17 august 2026 că este. Câmpul se scrie și nu se compară
 * NICĂIERI; e descriptiv — cine se uită la un domeniu în depanare vede pentru
 * cine a fost citit. Cine ar vrea să-l facă portant trebuie să-l compare cu
 * identitatea cererii în locul în care cererea e cunoscută, iar acolo (în
 * `panel.ts`, imediat după `scopeForUser(db, user.id)`) comparația ar fi
 * tautologică. Un câmp descriptiv e în regulă; unul descris ca apărare nu.
 *
 * ## Absența unui rând înseamnă „nicio instanță"
 *
 * Nu „toate". Eșecul variantei inverse e tăcut: nimic nu pică, nimeni nu vede o
 * eroare, iar defectul se descoperă când persoana greșită vede serverul greșit.
 * De-aia lista goală NU e un caz special tratat cu „atunci nu filtrăm" — e
 * chiar cazul care trebuie să nu întoarcă nimic, iar interogarea nici măcar nu
 * se mai emite: `WHERE instance_id IN ()` e eroare de sintaxă în MariaDB, iar
 * reparația evidentă a acelei erori, sub presiune, e scoaterea filtrului.
 *
 * ## Rolul de pe instanță
 *
 * `user_instances.role` poate fi mai mic decât `users.role`, niciodată mai mare
 * (`migrations/0008_auth.sql`). Se citește aici fiindcă e al aceleiași
 * interogări; cine îl FOLOSEȘTE ca să permită o acțiune de scriere e panoul,
 * adică E3c. Aici nu decide nimic — dar nici nu se pierde, ca următorul care are
 * nevoie de el să nu adauge a doua interogare peste aceeași tabelă.
 */

import type { AuthDb } from "./db";

/** Vocabularul impus de `ck_user_instances_role`. */
export const INSTANCE_ROLES = ["owner", "operator", "viewer"] as const;
export type InstanceRole = (typeof INSTANCE_ROLES)[number];

/** Domeniile emise chiar aici. `WeakSet`, deci nimic nu crește cu traficul. */
const issued = new WeakSet<object>();

export type InstanceScope = {
  /** Contul pentru care s-a citit lista. DESCRIPTIV: nu se compară nicăieri, și
   *  nu e el cel care leagă domeniul de cerere — vezi capul fișierului. */
  readonly userId: number;
  /**
   * Instanțele permise. Lista GOALĂ înseamnă „niciuna", și e o stare normală
   * pentru un cont proaspăt creat — nu o eroare, și cu atât mai puțin „toate".
   */
  readonly allowedInstanceIds: readonly string[];
  /**
   * Rolul pe fiecare dintre ele. Aceleași chei ca lista de mai sus.
   *
   * NU e un `Map`, deși are forma lui: un `Map` emis de aici s-ar putea rescrie
   * din orice apelant, iar `readonly` de mai sus n-ar opri nimic — vezi
   * `readonlyRoles`. Cine îl citește nu vede diferența; cine ar vrea să-i scrie
   * primește un `TypeError`.
   */
  readonly roles: ReadonlyMap<string, string>;
};

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScopeError";
  }
}

/**
 * Lista de instanțe a unui cont, citită din `user_instances`.
 *
 * ARUNCĂ dacă interogarea nu se poate face — nu întoarce o listă goală. „Nu pot
 * citi drepturile" și „contul n-are drepturi" arată la fel în răspunsul final
 * (un panou gol), dar sunt lucruri diferite: primul e o defecțiune care trebuie
 * să ajungă la 503 și în jurnal, al doilea e starea corectă a unui cont nou.
 * Confundate, un panou gol de la o bază căzută s-ar citi ca „mi s-au luat
 * drepturile" — iar rezolvarea aia e o repartizare de drepturi care apoi rămâne.
 */
export async function scopeForUser(db: AuthDb, userId: number): Promise<InstanceScope> {
  if (!Number.isInteger(userId) || userId <= 0) {
    throw new ScopeError(
      `id de utilizator nevalid pentru citirea drepturilor: ${String(userId)}`);
  }
  const rows = await db.all(
    "SELECT instance_id, role FROM user_instances WHERE user_id = ?", [userId]);

  const allowedInstanceIds: string[] = [];
  const roles = new Map<string, string>();
  for (const row of rows) {
    if (!("instance_id" in row) || !("role" in row)) {
      // O coloană lipsă din `SELECT` ar deveni tăcut `undefined`, iar
      // `String(undefined)` e un identificator de instanță care nu se potrivește
      // cu nimic — adică drepturi pierdute fără nicio eroare.
      throw new ScopeError(
        "interogarea drepturilor nu a întors coloanele cerute; un drept citit pe " +
        "jumătate nu se completează cu presupuneri");
    }
    const id = String(row.instance_id);
    allowedInstanceIds.push(id);
    roles.set(id, String(row.role));
  }

  return register({ userId, allowedInstanceIds, roles });
}

/**
 * Singurul loc din tot depozitul care înregistrează un domeniu ca emis.
 *
 * A existat până pe 17 august 2026 și un al doilea, `scopeFromIds`, „pentru
 * teste": o funcție LIVRATĂ care fabrica un domeniu autorizat fără nicio citire
 * din `user_instances`, apărată doar de un recensământ pe șir. Nu o chema
 * nimeni — nici cod livrat, nici vreun test; proba care avea nevoie de un
 * domeniu fals folosește dinadins un cast, ca să treacă prin `assertScope`. A
 * fost scoasă: o scurtătură nefolosită spre autorizare e tot o scurtătură, iar
 * motivul scris pentru ea era fals despre suita livrată.
 *
 * Ce ține locul recensământului de atunci: `tests/panel-authz.test.ts` numără
 * înscrierile în registrul `issued` din tot codul livrat și cere să fie exact
 * una — asta de mai jos. Numărătoarea aia e ORIENTATIVĂ și atât: prinde a doua
 * cale scrisă pe față, în forma la care se uită, și NU prinde una scrisă anume
 * ca să treacă de ea — un alias al lui `issued`, sau `register` exportat și
 * chemat din alt fișier. Amândouă au fost probate; vezi capul fișierului.
 *
 * Ce ar face proprietatea structurală în loc de ortografică nu e o gardă în
 * plus, e o schimbare de proiectare: registrul să nu mai fie per proces, ci
 * creat per CERERE și ajuns la funcțiile de acces la date pe un drum pe care
 * apelantul nu-l poate înlocui — dacă poarta e un parametru obișnuit, o rută
 * care vrea să ocolească pasează pur și simplu alta. Practic asta înseamnă
 * `AsyncLocalStorage` în jurul fiecărei cereri de panou și rutele restructurate
 * în jurul lui. Se câștigă și legătura cu CEREREA, pe care fișierul ăsta scrie
 * mai sus că n-o are. Nu se câștigă imunitatea la o a doua cale scrisă tot aici:
 * cine editează fișierul ăsta ajunge oricum la registrul cererii curente. E o
 * decizie de operator, nu una de luat în treacăt într-o reparație.
 *
 * ## Emis înseamnă și ÎNCHIS
 *
 * Ce pleacă de aici e un obiect NOU, înghețat, cu o copie a listei și cu o hartă
 * de roluri fără scriitori — nu obiectul primit ca parametru. Trei lucruri, din
 * trei motive:
 *
 *   * **înghețat**, fiindcă altfel un domeniu emis se poate lărgi din orice
 *     apelant, iar `assertScope` îl acceptă mai departe: identitatea răspunde la
 *     „de unde vine obiectul", nu la „ce scrie în el acum". O purtare de
 *     specificație de care nu atârnă nimic aici, dar de care se lovește cine
 *     scrie: `Reflect.set` și `Reflect.defineProperty` întorc `false` TĂCUT pe
 *     un obiect înghețat — și pe domeniu, și pe tablou, și pe vederea de roluri
 *     —, în loc să arunce ca tot restul suprafeței. Nu lărgesc nimic, dar un
 *     fișier livrat scris cu `Reflect` primește o operație nulă fără zgomot;
 *   * **copiat**, fiindcă cine cheamă `register` rămâne cu o referință la ce a
 *     dat; dacă obiectul emis ar fi chiar acela, cel care l-a construit i-ar
 *     putea scrie în continuare. Copiile sunt AMÂNDOUĂ — tabloul de mai jos și
 *     `new Map(source)` din `readonlyRoles` —, și AMÂNDOUĂ își supraviețuiesc
 *     astăzi propriei ștergeri, verificat: `register` nu e exportat, iar
 *     structurile locale din `scopeForUser` nu sunt nici întoarse, nici
 *     capturate, deci niciun cod livrat nu mai ține referința prin care s-ar
 *     vedea diferența. Deci niciuna dintre ele n-are test, și e scris aici ca să
 *     nu se citească drept scăpare: un test ar trebui să fabrice chiar
 *     apelantul care lipsește. Ziua în care apare al doilea apelant e ziua în
 *     care amândouă devin portante — copierea e o proprietate a emiterii,
 *     neobservabilitatea ei de azi e a apelanților;
 *   * **fără scriitori la roluri**, fiindcă `Object.freeze` e superficial: un
 *     `Map` înghețat nu există — `set` merge mai departe prin prototip, iar
 *     rolul pe instanță e ce decide acțiunile de scriere în E3c.
 */
function register(scope: InstanceScope): InstanceScope {
  const emitted: InstanceScope = Object.freeze({
    userId: scope.userId,
    allowedInstanceIds: Object.freeze([...scope.allowedInstanceIds]),
    roles: readonlyRoles(scope.roles),
  });
  issued.add(emitted);
  return emitted;
}

/**
 * O hartă de roluri din care se poate CITI tot ce se citea dintr-un `Map`, și în
 * care nu se poate scrie deloc.
 *
 * Dintre cele trei forme cu care se putea închide jumătatea asta, aleasă e a
 * doua, și de ce nu celelalte:
 *
 *   * **o copie la fiecare acces** (`get roles() { return new Map(data); }`) ar
 *     fi lăsat `scope.roles.set(…)` să REUȘEASCĂ, pe o copie aruncată imediat.
 *     Adică o evadare care nu lărgește nimic dar nici nu se plânge — exact forma
 *     de eșec tăcut de care e plin depozitul ăsta. Plus o alocare per acces;
 *   * **o funcție de căutare** în locul structurii (`roleOn(id)`) ar fi fost cea
 *     mai mică suprafață, dar ar fi schimbat toți apelanții și, mai ales, ar fi
 *     rescris probele din `tests/data-scope-coverage.test.ts` care se uită la
 *     `roles.values()` — iar aia e garda care a prins „ia primul rol din hartă".
 *     O reparație de securitate care rescrie gărzile pe lângă care trece e o
 *     reparație pe care n-o mai verifică nimeni;
 *   * **asta**: un obiect înghețat care implementează `ReadonlyMap` peste o
 *     copie ținută în închidere. Citirile se comportă identic; `set`, `delete`
 *     și `clear` nu există, deci un cast la `Map` primește `TypeError` la apel,
 *     iar înghețul obiectului împiedică și adăugarea lor pe urmă.
 *
 * `Object.freeze(view)` de mai jos e PORTANT, nu decorativ, și până pe 18 august
 * 2026 propoziția de deasupra era singurul lucru care îl susținea — adică proză,
 * exact forma pe care depozitul ăsta o tot livrează. Măsurat cu el scos și cu
 * tot restul apărării la locul lui (înghețul exterior, al listei, copia din
 * închidere, `forEach`-ul nedelegat), `tsc` la zero și suita ÎNTREAGĂ verde:
 *
 *     Object.assign(scope.roles, { get: () => "owner" });
 *
 * — fără niciun cast, fiindcă înghețul exterior oprește înlocuirea lui
 * `scope.roles`, nu pe a lui `scope.roles.get` — a ridicat ce citește panoul din
 * `prod-a/viewer` în `prod-a/owner`. Îl ține acum, prin efect, testul
 * „nici câmpurile întregi nu se pot înlocui într-un domeniu emis" din
 * `tests/panel-authz.test.ts`.
 *
 * Și fiecare metodă de aici minte pe cont propriu: `size` e o valoare copiată la
 * emitere, iar `has`, `keys`, `values` și `entries` sunt cod scris de mână acolo
 * unde înainte era `Map.prototype`. Trei mutații puse una câte una, toate cu
 * suita ÎNTREAGĂ verde ATUNCI — acum înroșesc: `size: 0`,
 * `values: () => data.keys()`, `has: () => true`.
 * Niciuna nu e exploatabilă azi — singurul apelant livrat e `roles.get(id)` din
 * `lib/data/instances.ts` —, iar garda din `tests/data-scope-coverage.test.ts`
 * nu le deosebește: `new Set(roles.values()).size` dă 2 și pentru `keys()`,
 * fiindcă `prod-a` și `prod-b` sunt tot două șiruri distincte. De-aia adevărul
 * fiecărei metode se probează separat, pe un cont cu două instanțe și două
 * roluri diferite, în testul „vederea de roluri nu minte pe nicio metodă" din
 * `tests/panel-authz.test.ts`.
 *
 * Pe `size` proba s-a înșelat de TREI ori la rând, și de fiecare dată în același
 * fel: o fixtură ALEASĂ DE MÂNĂ închide clasa care tocmai s-a văzut și tace
 * despre restul.
 *
 *   * un singur cont cu două instanțe: și numărul cerut, și lungimea parcurgerii
 *     dau 2, deci un `size: 2` codificat trecea de amândouă;
 *   * o PERECHE de domenii, de 2 și de 1: închide literalii, și atât — un PLAFON
 *     rămâne invizibil, fiindcă `Math.min(n, 2) === n` pentru tot `n ∈ {1, 2}`.
 *     Măsurate atunci, fiecare pusă singură aici, toate cu suita ÎNTREAGĂ verde
 *     (524/524): `Math.min(data.size, 2)`, `data.size < 3 ? data.size : 2`,
 *     `new Set(data.values()).size` — adică rolurile DISTINCTE, care pe domeniile
 *     alea coincideau cu instanțele — și `data.size || 99`, care minte chiar pe
 *     domeniul GOL;
 *   * TREI domenii — de 2, de 3 și GOL: închid și plafonul la 2, și numărul
 *     rolurilor distincte, și implicitele pe gol, și lasă deschisă chiar clasa
 *     DINĂUNTRU. Măsurat pe 18 august 2026, cu `tsc` la zero și suita ÎNTREAGĂ
 *     verde, `data.size > 1 ? data.size : 0` raporta ZERO instanțe pentru un cont
 *     cu exact UNA — forma cea mai obișnuită de client al unui agregator —,
 *     fiindcă `size` nu se afirma pe niciun domeniu de 1.
 *
 * De-aia cardinalitatea nu mai e aleasă, e PARAMETRU. `tests/panel-authz.test.ts`
 * ține lista `CARDINALITIES` — 0, 1, 2, 3, 5, 11 — și citește câte un domeniu
 * pentru fiecare număr din ea, cu rolurile ALTERNATE și cu fiecare domeniu
 * ancorat întâi prin `entries()`, înainte de orice aserțiune pe un număr. O
 * dimensiune în plus costă o intrare în listă, nu un test nou.
 *
 * Măsurate pe 18 august 2026, fiecare pusă singură pe `size:` de mai jos, toate
 * ROȘII acum pe `tests/panel-authz.test.ts` + `tests/data-scope-coverage.test.ts`
 * (36 de teste): `0`, `2`, `3`, `Math.max(data.size, 1)`, `Math.min(data.size, 2)`,
 * `Math.min(data.size, 3)`, `Math.min(data.size, 10)`,
 * `data.size < 3 ? data.size : 2`, `new Set(data.values()).size`,
 * `data.size || 99`, `data.size > 1 ? data.size : 0`,
 * `data.size === 5 ? 4 : data.size` și `data.size & ~1`. Constantele, plafoanele
 * la orice înălțime, pragurile de jos, mulțimile de valori distincte, implicitele
 * pe gol și golurile interioare sunt toate în lista aia — fiecare prin cel puțin
 * o cardinalitate care o desparte.
 *
 * Ce rămâne, spus prin ce s-a măsurat, nu prin ce s-ar bănui: o listă de valori
 * probează pe valorile din ea. Un `size` construit anume ca să coincidă cu
 * `data.size` pe exact cele șase trece — `data.size % 12`, pus singur aici, a dat
 * 36/36 verde. Nu e o graniță (nu e „peste 11 nu se vede"), e forma oricărei
 * probe finite; ce o mută e o intrare în plus în `CARDINALITIES`.
 *
 * Dar aia mută doar minciunile de forma cardinalității. Mai e o clasă, care nu
 * se mișcă cu nicio intrare din listă: un predicat peste CONȚINUTUL rândurilor,
 * adevărat pentru fiecare rând al fixturii. Măsurat:
 * `[...data.values()].filter((r) => r === "viewer" || r === "owner").length`
 * a lăsat suita întreagă verde (530 de teste la măsurătoare — suita crește,
 * proprietatea nu), și rămâne verde și cu `12, 100` adăugate în
 * `CARDINALITIES` — fiindcă `alternatingRole` emite numai cele două roluri, la
 * orice `n`. Ce o mută e un rând care încalcă predicatul, nu o listă mai lungă.
 * Rolurile alternate fac totuși muncă reală: aceeași formă restrânsă la un
 * singur rol, `filter((r) => r === "viewer").length`, pică la n = 2, 3, 5, 11.
 * Clasa e plauzibilă, nu academică: un filtru defensiv care aruncă un rol din
 * afara lui `INSTANCE_ROLES` — după o migrație care adaugă al patrulea rol —
 * ar număra `size` în minus, tăcut.
 *
 * `forEach` NU se deleagă hărții din închidere: `Map.prototype.forEach` dă
 * callback-ului, ca al treilea argument, chiar harta pe care o parcurge — adică
 * ar fi împrumutat înapoi exact obiectul modificabil pe care îl ascunde aici.
 * Iteratorii (`keys`, `values`, `entries`) se pot delega: nu poartă harta cu ei.
 */
function readonlyRoles(source: ReadonlyMap<string, string>): ReadonlyMap<string, string> {
  const data = new Map(source);
  const view: ReadonlyMap<string, string> = Object.freeze({
    size: data.size,
    get: (key: string): string | undefined => data.get(key),
    has: (key: string): boolean => data.has(key),
    keys: () => data.keys(),
    values: () => data.values(),
    entries: () => data.entries(),
    [Symbol.iterator]: () => data[Symbol.iterator](),
    forEach(fn: (value: string, key: string, map: ReadonlyMap<string, string>) => void,
            thisArg?: unknown): void {
      for (const [key, value] of data) fn.call(thisArg, value, key, view);
    },
  });
  return view;
}

/**
 * Obiectul ăsta e chiar un domeniu emis aici, sau doar arată ca unul?
 *
 * ARUNCĂ, nu întoarce fals: fiecare apelant e o funcție de acces la date, iar
 * singura purtare corectă acolo e să nu răspundă deloc. Un `return []` ar fi
 * indistinct de „contul n-are nimic", adică o autorizare picată care arată ca
 * un cont nou.
 */
export function assertScope(value: unknown): asserts value is InstanceScope {
  if (typeof value !== "object" || value === null || !issued.has(value as object)) {
    throw new ScopeError(
      "funcția de acces la date a primit un domeniu de instanțe care nu a fost " +
      "citit din `user_instances`. Lista de instanțe permise vine DOAR din " +
      "`scopeForUser`; una fabricată — dintr-un parametru de URL, dintr-un câmp " +
      "de formular, dintr-o componentă — ar fi autorizare scrisă de cel care " +
      "cere. Vezi lib/auth/scope.ts.");
  }
}

/**
 * `?, ?, ?` — atâtea semne de întrebare câte instanțe.
 *
 * Lista se leagă ca PARAMETRI, niciodată lipită în text: identificatorii de
 * instanță ajung în bază și din rutele de înregistrare, iar un `IN ('a','b')`
 * construit prin concatenare e o injecție care așteaptă primul identificator cu
 * un apostrof în el.
 *
 * ARUNCĂ pe listă goală, ca nimeni să nu poată emite `IN ()`: MariaDB ar
 * răspunde cu o eroare de sintaxă, iar reparația evidentă a unei erori de
 * sintaxă e scoaterea clauzei — adică toate instanțele, pentru toată lumea.
 */
export function scopePlaceholders(scope: InstanceScope): string {
  assertScope(scope);
  if (scope.allowedInstanceIds.length === 0) {
    throw new ScopeError(
      "domeniu gol: nu se construiește `IN ()`. Cine interoghează pentru un cont " +
      "fără nicio instanță trebuie să se oprească ÎNAINTE de interogare — vezi " +
      "`seesNothing` mai jos.");
  }
  return scope.allowedInstanceIds.map(() => "?").join(", ");
}

/**
 * Contul ăsta nu vede nicio instanță.
 *
 * Verificat cu `assertScope` înainte, dinadins: dacă domeniul e fabricat, un
 * `false` de aici ar trimite mai departe spre interogare un obiect în care nu se
 * poate avea încredere, iar un `true` ar ascunde defectul într-un panou gol.
 * Amândouă sunt răspunsuri; ce trebuie e să nu existe niciun răspuns.
 */
export function seesNothing(scope: InstanceScope): boolean {
  assertScope(scope);
  return scope.allowedInstanceIds.length === 0;
}
