/**
 * Fluxurile pe care agregatorul le CUNOAȘTE, și forma fiecărei coloane.
 *
 * Geamănul lui `STREAMS` din `sentinel/report/shipper.py`: acolo se decide ce
 * pleacă, aici ce se acceptă. Cele două liste sunt separate dinadins — un flux
 * adăugat la expeditor și neadăugat aici trebuie să fie o RESPINGERE zgomotoasă,
 * nu o potrivire automată. Vezi `app/api/sentinel/sync/route.ts` pentru ce se
 * întâmplă cu un flux necunoscut și de ce nu poate fi un 200.
 *
 * ## De ce descrierea coloanelor stă aici, și nu în SQL
 *
 * Fiindcă ingestia foloseşte `INSERT IGNORE`, iar `INSERT IGNORE` **transformă
 * erorile în tăcere**: un șir mai lung decât coloana se TRUNCHIAZĂ cu un simplu
 * avertisment, un `NULL` într-o coloană `NOT NULL` devine valoarea implicită, iar
 * un `params` care nu e JSON valid face rândul să dispară. Primele două produc un
 * rând PREZENT și GREȘIT — pe care verificarea de efect (numărul de rânduri) îl
 * numără drept bun, fiindcă e chiar acolo.
 *
 * `INSERT IGNORE` nu e o alegere de stil: `migrations/0001_core.sql` scrie de ce
 * `ON DUPLICATE KEY UPDATE` nu e disponibil pe `audit_entries` (ramura de UPDATE
 * declanșează triggerul de append-only și lotul moare la primul rând deja
 * prezent). Deci marginile se verifică ÎNAINTE, aici, pe valori — un rând care
 * nu încape se REFUZĂ cu numele câmpului, nu se scurtează.
 *
 * Regula e cea din capul lui `migrations/0001_core.sql`: nimic nu se trunchiază.
 * Un rând tăiat arată identic cu unul falsificat când se verifică lanțul.
 *
 * ## De ce `Map` și nu un obiect
 *
 * `obiect["constructor"]` întoarce o funcție pe orice obiect obișnuit, deci un
 * flux numit așa ar părea cunoscut fără să-l fi declarat nimeni. `Map` n-are
 * proprietăți moștenite. Aceeași alegere ca `retiredInstanceIds` din
 * `lib/beat-keys.ts`.
 */

/**
 * Ce fel de valoare acceptă o coloană.
 *
 *   * `id`        — `BIGINT` pozitiv; identitatea rândului la sursă.
 *   * `timestamp` — ISO 8601 CU decalaj, convertit la UTC (vezi `lib/ingest.ts`).
 *   * `text`      — șir; marginea e a coloanei, nu inventată aici.
 *   * `json`      — șir care e JSON valid. Coloana `JSON` a MariaDB e
 *                   `LONGTEXT` + `CHECK (json_valid(...))`, iar sub `INSERT
 *                   IGNORE` acel CHECK doar face rândul să dispară.
 *   * `hash`      — 64 de caractere hexa. Coloana e `VARCHAR(64) ascii`: orice
 *                   altceva ar fi trunchiat sau stricat de conversia de set de
 *                   caractere, tăcut. Se potrivește DOAR peste o coloană de
 *                   text: cele 64 de caractere sunt 64 de octeți stocați. Peste
 *                   un `BINARY(32)` — care ține tot un SHA-256, dar în octeți —
 *                   ar fi chiar defectul pe care felul `bytes` de mai jos îl
 *                   oprește.
 *   * `bytes`     — o coloană BINARĂ de lățime fixă (`BINARY(n)`), cu lățimea
 *                   declarată în `byteLength`. Orice valoare pe drumul ăsta se
 *                   REFUZĂ, iar refuzul e CORECT PRIN PROIECTARE, nu o lipsă de
 *                   implementare: nu există formă de sârmă pentru octeți.
 *                   `encode_value` din `sentinel/report/shipper.py` acceptă
 *                   `None`, `bool`, `int`, `str`, `datetime` și `Decimal`, și
 *                   ARUNCĂ pe orice altceva — dinadins, ca să nu apară un al
 *                   doilea serializator —, iar singura coloană binară din
 *                   schemă, `actor_attrs.value_hash`, NU vine de pe sârmă: se
 *                   calculează la ingestie, din `value`, prin `hashed` de mai
 *                   jos (#66). Deci felul ăsta nu descrie o coloană care se
 *                   expediază, ci una care nu se poate expedia — e GARDA care
 *                   prinde declarația greșită (`value_hash` pus între
 *                   `columns`), și o prinde înainte de bază.
 *   * `int`       — întreg oarecare, cu semn. NU e `id`: un întreg care nu e
 *                   identitate nu poate fi filigran, iar regula „exact o coloană
 *                   `id`" există tocmai ca filigranul să fie neambiguu. Sub
 *                   `text` ar fi fost refuzat (un număr nu e un șir), iar sub
 *                   `id` ar fi făcut fluxul de neînregistrat.
 *   * `decimal`   — șir zecimal canonic (`-?cifre[.cifre]`), fiindcă `Decimal`
 *                   sosește ca TEXT: `encode_value` din
 *                   `sentinel/report/shipper.py` îl trece prin `str()`, care e
 *                   exact la dus-întors, spre deosebire de `float`. Verificat
 *                   AICI, nu lăsat pe seama coloanei `DECIMAL`: altfel un șir
 *                   stricat ar fi refuzat de MariaDB, cu un mesaj despre tipuri
 *                   în loc de unul care numește câmpul.
 *   * `inet`      — o adresă IP, ca ȘIR: IPv4 sau IPv6, fără prefix și fără
 *                   zonă. Coloana e `INET6` nativ (vezi cartografierea din
 *                   `migrations/0003_entities.sql`), deci se poate ordona și
 *                   compara ca adresă — dar numai dacă ce ajunge în ea CHIAR e
 *                   una.
 *
 *                   A DOUA excepție de aceeași formă ca `decimal`, iar asta e
 *                   partea care merită scrisă: nu e un caz special, e un TIPAR.
 *                   Un tip pe care Postgres îl are și JSON-ul nu — `numeric`,
 *                   `inet`, mâine `macaddr` — pleacă de pe server ca text
 *                   (`encode_value` din `sentinel/report/shipper.py`), fiindcă
 *                   textul e singura reprezentare pe care ambele capete o scriu
 *                   la fel, și se validează AICI, la sosire, unde refuzul poate
 *                   numi câmpul. Cine adaugă al treilea tip de-ăsta adaugă un
 *                   fel de coloană, nu un `text` cu o notă în comentariu.
 *
 *                   De ce nu `text`: sub `INSERT IGNORE`, o valoare care nu e
 *                   adresă nu se oprește la o eroare pe care s-o vadă cineva —
 *                   ori se pierde rândul, ori intră o valoare pe care n-a
 *                   trimis-o nimeni. Ce face exact serverul cu ea nu s-a probat
 *                   pe MariaDB de aici; și nici nu contează, fiindcă ambele
 *                   variante sunt invizibile de la expeditor, care vede doar un
 *                   non-2xx sau un ecou.
 */
export type ColumnKind =
  "id" | "int" | "bool" | "decimal" | "inet" | "timestamp" | "date" | "text"
  | "json" | "hash" | "bytes";

export type Column = {
  /** Numele câmpului în rândul primit (coloana de pe server). */
  source: string;
  /** Numele coloanei în care se scrie aici. */
  target: string;
  kind: ColumnKind;
  nullable: boolean;
  /** Marginea REALĂ a coloanei, în octeți. Absentă pentru `id` și `hash`. */
  maxBytes?: number;
  /**
   * Lățimea EXACTĂ a unei coloane binare, în octeți. Doar pentru `bytes`.
   *
   * Nu e o margine, e o egalitate: `BINARY(32)` nu trunchiază „la nevoie", ci
   * întotdeauna — completează cu zerouri ce e mai scurt și taie ce e mai lung.
   * Numărul stă aici ca refuzul să-l poată numi: cine decide mâine forma de
   * sârmă a octeților trebuie să nimerească exact lățimea asta, nu una
   * apropiată.
   *
   * Pata oarbă de la #66 s-a închis pe jumătate, și merită scris pe care:
   * `tests/sql-reading.ts` citește acum și TIPUL unei coloane dintr-un
   * `CREATE TABLE` (`columnType`), iar dublurile compară valorile prin `cell(…)`,
   * care scrie un `Buffer` în hexa — deci 32 de octeți nu mai arată ca 64 de
   * caractere. Pe `actor_attrs.value_hash` acordul dintre declarație și migrație
   * e chiar o aserțiune, în regula de declarare a unui copil din
   * `tests/subrows.test.ts`.
   *
   * Ce rămâne NEverificat e chiar câmpul ăsta: e `byteLength`-ul unei coloane
   * SOSITE, iar niciun flux înregistrat nu declară `bytes` — singura coloană
   * binară din schemă se calculează la ingestie (`HashedColumn`). Deci n-are ce
   * compara nimic cu migrația: ce apără câmpul e o formă pe care regula de
   * declarare o refuză deja. La fel rămân neverificate față de migrație
   * `actor_attrs.kind` (`ENUM`) și `availability_rollup_entries.day` (`DATE`):
   * acolo nimic nu pune încă tipul citit față în față cu ce declară fluxul.
   */
  byteLength?: number;
};

/**
 * Cum înaintează cursorul unui flux — și, prin asta, ce formă de scriere are voie
 * să folosească ingestia lui.
 *
 * Nu e o etichetă descriptivă: e decizia din care iese totul.
 *
 *   * `append-only` — ultimul `id` expediat. Monoton, fără goluri de conținut,
 *     independent de ceas. Rândul nu se schimbă niciodată la sursă, deci
 *     `INSERT IGNORE` e corect: o retrimitere e o operație nulă, iar pe
 *     `audit_entries` e chiar OBLIGATORIU, fiindcă ramura de UPDATE a lui
 *     `ON DUPLICATE KEY` declanșează triggerul de append-only și omoară lotul.
 *   * `mutable` — `(updated_at, id)`. Un incident se închide, un actor își schimbă
 *     scorul: rândul retrimis TREBUIE să se suprascrie. Aici `INSERT IGNORE` ar
 *     fi exact defectul — ar păstra tăcut versiunea veche, iar panoul ar arăta un
 *     incident deschis care pe server e rezolvat. Forma corectă e
 *     `ON DUPLICATE KEY UPDATE`, iar tabelele astea NU au trigger de append-only,
 *     deci se poate.
 *
 * ## De ce NU există un al treilea fel, `rollup`
 *
 * A existat, și n-a însemnat nimic. Un rollup retrimite bucketul curent, incomplet,
 * la fiecare rundă — dar pentru RECEPTOR aia e exact cazul mutabil: aceeași
 * identitate sosește din nou, cu valori noi, și trebuie să se suprascrie.
 * `writeSql` alegea aceeași ramură, numărătoarea făcea același lucru, iar nimic
 * din ingestie nu se uita vreodată la diferență.
 *
 * Un fel care nu deosebește nimic e o ETICHETĂ, iar depozitul ăsta a plătit deja
 * o dată pentru una: `CursorKind` a fost respins la revizuire fiindcă era o
 * etichetă, nu o gardă. Mai rău, eticheta era și o divergență: expeditorul are
 * două feluri (`CURSOR_KINDS` din `sentinel/report/shipper.py`), receptorul avea
 * trei, iar felul nu circulă pe sârmă — deci nimic nu le-ar fi pus vreodată față
 * în față.
 *
 * Ce s-a respins odată cu el: păstrarea lui ca documentare a intenției
 * („bucketul se retrimite dinadins"). Intenția aia e adevărată și se scrie unde
 * are efect — în migrație, la tabela de rollup, și în felul cum expeditorul își
 * alege rândurile. Un cuvânt în `CursorKind` care arată ca o gardă, fără să fie,
 * costă mai mult decât explică.
 *
 * Ce NU se schimbă odată cu forma scrierii: filigranul se ecouă doar după ce
 * efectul e verificat prin NUMĂRARE. `affectedRows` nu deosebește „am inserat"
 * de „am actualizat" de „n-am făcut nimic", iar pe un upsert e chiar mai
 * înșelător decât pe `INSERT IGNORE` (MariaDB întoarce 2 pentru o actualizare).
 * Numărarea rămâne singura dovadă.
 *
 * Primul flux `mutable` înregistrat e `incidents`, la AMÂNDOUĂ capetele
 * (`INCIDENT_STREAM` din `sentinel/report/shipper.py`). Un flux fără fel de
 * cursor declarat nu are voie să fie înregistrat: testul „fiecare flux declară
 * CUM înaintează cursorul lui" din `tests/ingest.test.ts` pică dacă apare unul.
 */
export type CursorKind = "append-only" | "mutable";

/**
 * Felurile de cursor, exact cele din `CURSOR_KINDS` al expeditorului.
 *
 * Nu circulă pe sârmă, deci nu sunt un contract în sensul strict — receptorul
 * își citește felul din registrul lui. Sunt scrise la fel ca să nu descrie doi
 * oameni același lucru în două vocabulare, iar `tests/ingest.test.ts` cere să
 * rămână exact astea două: un al treilea fel care nu schimbă nimic în ingestie
 * ar fi iar o etichetă.
 */
export const CURSOR_KINDS: readonly CursorKind[] =
  ["append-only", "mutable"] as const;

/**
 * Cum se leagă un sub-rând de părintele lui: coloana din tabela de legătură ←
 * coloana din tabela părinte.
 *
 * Valorile NU se trimit de sursă. Un sub-rând stă ÎNĂUNTRUL rândului părinte, în
 * tabloul lui, deci părintele lui e locul în care se află, nu un câmp pe care îl
 * poartă. Un copil care și-ar declara singur părintele ar putea să-l declare
 * greșit, iar rezultatul ar fi o etichetă atârnată de alt activ decât cel care a
 * trimis-o — o legătură inventată de replică, invizibilă de la expeditor.
 */
export type LinkColumn = { child: string; parent: string };

/**
 * O coloană CALCULATĂ la receptor, din altă coloană a aceluiași sub-rând (#66).
 *
 * Există una singură în toată schema, și tot mecanismul e scris pentru ea:
 * `actor_attrs.value_hash`, `BINARY(32)`, pe care `migrations/0003_entities.sql`
 * o dă drept „SHA-256 peste value; calculat la ingestie". Unicitatea nu se poate
 * pune pe `value` — un `user_agent` trece lejer de limita de cheie a InnoDB —,
 * deci cheia poartă DIGESTUL, iar `value` rămâne `TEXT`.
 *
 * Numai pe `ChildStream`, dinadins: singura coloană de felul ăsta din schemă e
 * pe o tabelă de legătură. Aceleași trei linii pe rândul părinte n-ar avea
 * niciun apelant, iar un mecanism fără apelant nu e probat de nimic.
 *
 * ## CE se hash-uiește, și de ce exact asta
 *
 * **Octeții UTF-8 ai valorii, exact cum a fost validată și exact cum se scrie în
 * `value`.** Fără normalizare: fără tăiat spații, fără schimbat registrul, fără
 * NFC. Trei motive, în ordinea în care contează:
 *
 *   * digestul e MEMBRU al cheii unice, deci la receptor EL e identitatea. Orice
 *     normalizare CONTOPEȘTE valori pe care sursa le ține distincte — două
 *     `user_agent` care diferă doar prin registru ar deveni un singur rând, iar
 *     panoul ar arăta pe care dintre ele a apucat să-l scrie primul lot.
 *     Contopirea nu se vede de nicăieri: nu e un rând care lipsește, e un rând
 *     care se pretinde întreg;
 *   * NFC depinde de versiunea de Unicode a mașinii care rulează. Cheia trebuie
 *     să însemne același lucru cât trăiește arhiva, iar cu normalizare o
 *     actualizare de Node ar putea schimba identitatea rândurilor deja scrise:
 *     retrimiterea aceluiași `value` ar insera un al doilea rând, curățarea l-ar
 *     șterge pe primul, și așa la fiecare lot. Octeții bruți sunt ficși pentru
 *     totdeauna;
 *   * digestul trebuie să poată fi RECALCULAT din ce e stocat. `value` se scrie
 *     neatins, deci „hash-ul ăsta e al valorii ăsteia?" are răspuns oricând. Cu
 *     o valoare normalizată în cheie și una brută în coloană, întrebarea n-ar
 *     mai avea răspuns fără să știi și versiunea normalizatorului.
 *
 * Octeții UTF-8 sunt bine definiți fiindcă `checkString` (`lib/ingest.ts`) refuză
 * deja surogații neîmperecheați: nu există valoare acceptată a cărei codificare
 * să strecoare un caracter de înlocuire.
 *
 * ## E o formă de sârmă în tot afară de nume
 *
 * Nu circulă nimic — expeditorul trimite `value`, atât —, dar rețeta asta decide
 * ce înseamnă „același rând" pentru toate rândurile deja scrise. Schimbată,
 * fiecare atribut din arhivă își schimbă identitatea deodată: retrimiterile ar
 * insera rânduri noi, iar curățarea le-ar șterge pe cele vechi, la nesfârșit.
 * Deci o schimbare de rețetă e o MIGRAȚIE (recalculare peste tabelă), nu un
 * refactor — scris aici ca să n-o descopere cine crede că mută o funcție.
 *
 * ## CE SE PRESUPUNE, fiindcă nu se verifică nicăieri
 *
 * Că două valori distincte nu dau același digest. Cheia e
 * `(instance_id, actor_key, kind, value_hash)` și NU conține `value`, deci o
 * coliziune ar contopi două atribute tăcut. Asta e rezistența la coliziuni a lui
 * SHA-256, nu o proprietate a codului de aici, și nimic din suită n-o poate
 * proba: o coliziune nu se poate construi ca s-o vezi picând.
 *
 * Ce se apără CHIAR, și e jumătatea care contează: o coliziune ÎNTR-UN LOT nu
 * contopește nimic. Dedublarea pe identitate din `prepareRows` vede două
 * sub-rânduri cu aceeași identitate și refuză lotul zgomotos. Adică drumul pe
 * care s-ar pierde un rând fără urmă e închis; ce rămâne e drumul pe care fluxul
 * se OPREȘTE, vizibil în `ship:lag`.
 */
export type HashedColumn = {
  /** Coloana în care se scrie digestul. NU e un câmp de pe sârmă. */
  target: string;
  /** `Column.target`-ul din care se calculează, din ACELAȘI sub-rând. */
  from: string;
  /**
   * Lățimea EXACTĂ a coloanei binare, în octeți — numărul din `BINARY(n)` al
   * migrației, nu unul apropiat.
   *
   * `BINARY(n)` nu refuză nimic: completează cu zerouri ce e mai scurt și TAIE
   * ce e mai lung. Deci un digest care nu are exact lățimea asta ar ajunge în
   * arhivă schimbat, iar numărătoarea de identitate — care compară ce s-a
   * stocat cu parametrul trimis — n-ar mai potrivi niciodată. De-aia se
   * verifică în `prepareRows`, ÎNAINTE de bază.
   */
  byteLength: number;
};

/**
 * Un tablou de pe rândul părinte, desfășurat într-o tabelă de legătură.
 *
 * ## De ce sunt SUB-RÂNDURI și nu fluxuri proprii (#62)
 *
 * `asset_tags`, `actor_ips`, `actor_attrs`, `detection_events` și
 * `patch_plan_findings` n-au nici `received_at`, nici `batch_seq`, iar lipsa lor
 * nu e o scăpare: **n-au contabilitate proprie fiindcă n-au sosire proprie.** Pe
 * server datele astea nici nu există separat — sunt tablouri pe rândul părinte
 * (`actors.member_ips inet[]`, `detections.event_ids bigint[]`,
 * `patch_plans.finding_ids bigint[]`) —, deci un flux propriu ar trebui să
 * inventeze un cursor, un filigran și o sosire pentru ceva ce la sursă n-are
 * niciuna dintre ele.
 *
 * Fluxul părinte le trimite ODATĂ cu părintele, în același lot. `received_at` și
 * `batch_seq` ale sub-rândului sunt cele ale părintelui, iar cine vrea să știe
 * când a sosit o etichetă se uită la rândul de care atârnă.
 *
 * ## Înlocuire, nu contopire
 *
 * Mulțimea de sub-rânduri a unui părinte se ÎNLOCUIEȘTE la fiecare sosire. Un
 * upsert simplu ar contopi: un IP scos din `member_ips` ar rămâne pe veci în
 * `actor_ips`, iar panoul ar arăta un actor care folosește o adresă pe care
 * serverul nu i-o mai atribuie. Cum se face și cum se DOVEDEȘTE — prin
 * numărătoare, nu prin forma instrucțiunii — e scris la `ingestStream`.
 */
export type ChildStream = {
  /**
   * Câmpul din rândul PĂRINTE care poartă tabloul. Un tablou de OBIECTE, nu de
   * scalari: `actor_attrs` are nevoie de două câmpuri per element (`kind`,
   * `value`), iar două forme de element ar fi două căi de validare, adică încă
   * un loc în care cele două capete pot să nu fie de acord.
   */
  source: string;
  /** Tabela de legătură în care se scriu sub-rândurile. */
  table: string;
  /**
   * Legătura cu părintele. Vezi `LinkColumn`.
   *
   * Coloanele de legătură trebuie să fie PARTE din `identity`. Altfel cheia nu
   * mai deosebește sub-rândurile a doi părinți, iar curățarea unei bucăți de
   * părinți poate șterge un rând pe care tocmai l-a revendicat alta —
   * `deleteChunks` taie ÎNTRE grupuri, iar clauza `NOT IN` a unei bucăți e
   * scrisă pe cheie. Păzit de `tests/subrows.test.ts`, testul
   * „regula de declarare a unui copil se declanșează SINGURĂ".
   */
  link: readonly LinkColumn[];
  /** Coloanele care vin din FIECARE element al tabloului. */
  columns: Column[];
  /**
   * Coloanele CALCULATE aici, din cele de mai sus. Vezi `HashedColumn`.
   *
   * Absent = sub-rândul n-are niciuna, care e cazul a patru din cele cinci
   * tabele de legătură.
   *
   * Numele lor NU sunt câmpuri de pe sârmă, și asta e dinadins: un element care
   * își aduce singur `value_hash` cade sub regula câmpurilor necunoscute și e
   * REFUZAT. Un digest calculat la sursă ar fi încă un loc în care cele două
   * capete pot să nu fie de acord — exact motivul pentru care migrația scrie
   * „calculat la ingestie".
   */
  hashed?: readonly HashedColumn[];
  /**
   * CHEIA UNICĂ a tabelei de legătură, în ordinea din migrație, începând cu
   * `instance_id`.
   *
   * Aceeași regulă ca la `Stream.identity`, cu același motiv: din ea iese și
   * potrivirea scrierii, și numărătoarea de efect, și lista de excludere a
   * curățării. Dezacordul cu migrația e păzit de `tests/subrows.test.ts`,
   * „regula de declarare a unui copil se declanșează SINGURĂ" — testul lui
   * `Stream.identity` din `tests/schema.test.ts` se uită doar la fluxuri, nu și
   * la copiii lor.
   */
  identity: readonly string[];
};

/**
 * Tabelele de legătură și PĂRINTELE fiecăreia.
 *
 * Registrul ăsta e un fapt despre SCHEMĂ, nu despre expediere: există și pentru
 * tabelele al căror flux părinte nu e încă înregistrat. De-aia nu stă în
 * declarația unui flux.
 *
 * La ce folosește, și de ce e o numărătoare și nu o listă de excepții: garda din
 * `tests/schema.test.ts` compară MULȚIMEA tabelelor replicate care n-au
 * `received_at`/`batch_seq` cu cheile de aici. Cine adaugă mâine o a șasea tabelă
 * de legătură și uită să-i declare părintele nu primește un avertisment despre un
 * nume pe care nu-l cunoaște nimeni — primește o numărătoare care nu mai iese.
 * Iar cine scrie aici o tabelă care nu există, sau un părinte care n-are
 * contabilitate proprie, pică aceeași gardă.
 */
const LINK_PARENTS = new Map<string, string>([
  ["asset_tags", "asset_entries"],
  ["actor_ips", "actor_entries"],
  ["actor_attrs", "actor_entries"],
  ["detection_events", "detection_entries"],
  ["patch_plan_findings", "patch_plan_entries"],
]);

/** Tabela părinte a unei tabele de legătură, sau `undefined` dacă tabela nu e
 *  una de legătură. */
export function linkParentTable(table: string): string | undefined {
  return LINK_PARENTS.get(table);
}

/** Toate tabelele de legătură declarate, cu părintele lor. */
export function linkTables(): [string, string][] {
  return [...LINK_PARENTS.entries()];
}

export type Stream = {
  name: string;
  table: string;
  cursor: CursorKind;
  columns: Column[];
  /**
   * Tablourile de pe rândul părinte, desfășurate în tabele de legătură.
   *
   * Absent = fluxul n-are sub-rânduri. NU se confundă cu un tablou gol: un flux
   * care declară un copil cere fiecărui rând să poarte câmpul, iar unul care nu
   * declară niciunul refuză câmpul ca necunoscut.
   */
  children?: readonly ChildStream[];
  /**
   * CHEIA UNICĂ a tabelei replicate, în ordinea din migrație, începând cu
   * `instance_id`. Din ea iese ce NU se atribuie într-un upsert.
   *
   * ## De ce e DECLARATĂ, nu dedusă
   *
   * Prima formă o deducea: `instance_id` plus coloana cu `kind: "id"`. Merge
   * pentru fluxurile cu `source_id`, și numai pentru ele. Patru din zece tabele
   * ale fazei sunt identificate altfel, iar niciuna dintre coloanele lor de cheie
   * nu poate fi un `id`:
   *
   *     asset_tags     (instance_id, source_id, tag)                  tag: text
   *     actor_entries  (instance_id, actor_key)                       actor_key: text
   *     actor_ips      (instance_id, actor_key, ip)                   ip: INET6
   *     actor_attrs    (instance_id, actor_key, kind, value_hash)     kind: ENUM,
   *                                                                   value_hash: BINARY(32)
   *
   * Cu deducția, `writeSql` ar fi pus `actor_key = VALUES(actor_key)` în clauza
   * `SET`. Pe MariaDB aia nu corupe date — la o potrivire de cheie, `VALUES()` pe
   * o coloană de cheie e chiar valoarea stocată, deci o auto-atribuire. Ce s-ar
   * fi stricat e mai rău: invariantul scris al modulului („o coloană de cheie
   * într-un SET e o capcană") ar fi devenit TĂCUT fals, iar testul care îl păzea
   * s-ar fi uitat după `source_id`, care se nimerea să fie identitatea singurului
   * flux înregistrat.
   *
   * ## De ce se verifică împotriva migrației
   *
   * O identitate declarată e tot o presupunere — doar mutată în alt fișier. Ce o
   * face un fapt e ACORDUL cu cheia unică din `migrations/`: dacă cele două
   * diferă, upsertul se potrivește după alte coloane decât cele pe care le
   * exclude din `SET`, iar rezultatul e un rând care fie se dublează, fie își
   * rescrie cheia. Acordul e ținut de testul din `tests/schema.test.ts` intitulat
   * „identitatea declarată a fiecărui flux e cheia unică din migrație", în
   * aceeași formă ca testul care ține `MAX_ROWS_PER_BATCH` egal la cele două
   * capete: două surse, o singură aserțiune care le compară.
   */
  identity: readonly string[];
  /**
   * Ce FEL de valoare e filigranul care circulă pe sârmă.
   *
   * `"int"` implicit, fiindcă e cazul fiecărui flux cu `source_id`. `"text"`
   * pentru cele a căror cheie nu e un număr — `selfcheck_state` (cheie `key`),
   * `actors` (cheie `actor_key`), rollup-urile (cheie compusă, fără `id`).
   *
   * Nu e o proprietate a rândului, e una a DECLARAȚIEI: un flux nu are niciodată
   * amândouă felurile, iar cursorul îl scrie în coloana care i se potrivește
   * (`last_source_id` sau `last_source_key`). De ce două coloane și nu una
   * lărgită e scris în `migrations/0011_text_watermark.sql`.
   *
   * Comparația care alege maximul din lot trebuie să fie ACEEAȘI la ambele
   * capete. Pe text e cea pe octeți — de-aia coloana are colație binară și de-aia
   * expeditorul folosește `max()` peste șiruri, care în Python compară tot pe
   * puncte de cod. O colație care ignoră registrul ar putea alege alt maxim
   * decât cel trimis, iar cursorul n-ar mai avansa niciodată pe un lot valid.
   */
  watermarkKind?: "int" | "text";
  /**
   * Coloana pe care o compară RECONCILIEREA, când sursa șterge rânduri.
   *
   * Absentă înseamnă „sursa nu șterge niciodată din tabelul ăsta", iar atunci o
   * listă de reconciliere sosită pentru el se REFUZĂ. Nu e prudență de prisos:
   * o listă acceptată din greșeală pentru `audit_log` ar șterge fiecare intrare
   * de audit care nu e în ea — adică exact arhiva pe care sistemul o ține tocmai
   * ca să nu poată fi ștearsă de pe mașina monitorizată.
   *
   * Există fiindcă ingestia e numai upsert: fără ea, un rând șters la sursă
   * rămâne aici pentru totdeauna, cu ultima lui stare. Măsurat pe 21 august
   * 2026, la o oră după ce fluxul a început să curgă: serverul avea 43 de
   * verificări, panoul 44, iar a 44-a era una ștearsă cu zile în urmă, arătată
   * în continuare ca o problemă deschisă.
   */
  pruneKey?: string;
  /**
   * Coloana din care iese FILIGRANUL de pe sârmă. Nu e identitatea, și cele două
   * nu trebuie confundate — sunt răspunsuri la întrebări diferite:
   *
   *   * identitatea spune „ăsta e ACELAȘI rând", și din ea iese dovada de efect
   *     (numărătoarea) și potrivirea upsertului;
   *   * filigranul spune „până aici am ajuns runda asta", și singurul lui rol e
   *     să se întoarcă prin ecou.
   *
   * `sentinel/report/shipper.py` a făcut deja despărțirea, sub alte nume:
   * `Batch.watermark` e ce pleacă pe sârmă — `max(id)` din lot, un întreg —, iar
   * `Batch.position` e unde a ajuns cursorul LOCAL, care pe un flux mutabil e
   * perechea `(updated_at, id)` și NU pleacă nicăieri. Poziția e a expeditorului;
   * agregatorul n-o vede și n-are ce face cu ea.
   *
   * Consecința care contează aici: pe un flux mutabil, filigranele SUCCESIVE nu
   * cresc. Un rând vechi atins acum are un `id` mic, deci lotul următor poate
   * avea un filigran mai mic decât cel dinainte — și e corect. Ce trebuie să
   * rămână adevărat e altceva, verificat la fiecare lot: filigranul e cel mai
   * mare `id` DIN LOTUL ĂSTA. Un filigran mai mare ar cere expeditorului să sară
   * peste rânduri care n-au fost trimise.
   *
   * De ce e declarată și nu dedusă („prima coloană"): fiindcă prima coloană e
   * `source_id` doar din obișnuință. Un flux al cărui filigran ar veni din altă
   * coloană ar fi trecut tăcut, cu filigranul luat din altceva decât crede
   * expeditorul.
   */
  watermark: string;
  /**
   * Fluxul poartă un lanț de hash-uri (`prev_hash` → `entry_hash`), deci se
   * poate verifica structural la ingestie și programat — vezi `lib/chain.ts`.
   *
   * E DATE, nu o ramură scrisă în rută pe numele fluxului: al doilea flux cu
   * lanț (dovezile din E4) îl primește adăugând un câmp aici, iar unul fără lanț
   * nu are nevoie de nicio excepție.
   */
  chained: boolean;
};

/** Marginile tipurilor MariaDB, în octeți. Scrise o dată, cu numele lor. */
const TEXT = 65_535;
const MEDIUMTEXT = 16_777_215;
const LONGTEXT = 4_294_967_295;

/**
 * `audit_log` → `audit_entries`.
 *
 * Coloanele sunt exact cele din `AUDIT_STREAM` (`sentinel/report/shipper.py`),
 * în aceeași ordine, iar `id` devine `source_id` fiindcă `id`-ul de aici e al
 * replicii. Regula 1 din capul lui `migrations/0001_core.sql`: identitatea reală
 * e `(instance_id, source_id)`.
 */
const AUDIT_LOG: Stream = {
  name: "audit_log",
  table: "audit_entries",
  // Append-only la sursă, impus acolo de un trigger care ridică excepție la
  // UPDATE și DELETE (`0002_response.sql`), și la fel aici.
  cursor: "append-only",
  chained: true,
  // `uk_audit_entries_source (instance_id, source_id)`, `0001_core.sql`.
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "at", target: "at", kind: "timestamp", nullable: false },
    { source: "actor", target: "actor", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "source", target: "source", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "operation", target: "operation", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "target", target: "target", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "params", target: "params", kind: "json", nullable: false, maxBytes: LONGTEXT },
    { source: "result", target: "result", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "detail", target: "detail", kind: "text", nullable: true, maxBytes: MEDIUMTEXT },
    { source: "prev_hash", target: "prev_hash", kind: "hash", nullable: true },
    { source: "entry_hash", target: "entry_hash", kind: "hash", nullable: false },
  ],
};

/**
 * `incidents` → `incident_entries`. PRIMUL FLUX MUTABIL, la ambele capete.
 *
 * Identitatea e `(instance_id, source_id)`, adică `uk_incident_entries_source`
 * din `0003_entities.sql`, iar pe server cheia primară e `id`. Indexul unic
 * PARȚIAL al serverului (`incidents_fingerprint_open_idx`, unic pe `fingerprint`
 * doar cât timp incidentul e deschis) NU se recreează aici și nu intră în
 * identitate: o amprentă închisă și redeschisă e istorie legitimă, iar unicitatea
 * ar refuza al doilea rând.
 *
 * Filigranul e `source_id`. Poziția fluxului — `(updated_at, id)` — rămâne la
 * expeditor și nu circulă; vezi câmpul `watermark` de mai sus.
 *
 * ## Coloanele, și ce NU pleacă
 *
 * Toate coloanele lui `incidents` de pe server, cu două excepții numite:
 *
 *   * `updated_at` PLEACĂ, obligatoriu: e coloana de ordonare a fluxului, iar
 *     `Stream.__post_init__` din expeditor refuză un flux mutabil care n-o are
 *     între coloane. Aici e `0006_incident_updated_at.sql`.
 *   * `ai_confidence` pleacă drept ȘIR: pe server e `numeric(3,2)`, deci
 *     `Decimal`, iar `encode_value` îl trece prin `str()`. De-aia felul coloanei
 *     e `decimal` și nu `text` — forma se verifică aici, nu la MariaDB.
 *
 * Acordul dintre cele două liste e ținut de
 * `tests/unit/test_aggregator_stream_columns.py`, care le compară pe amândouă
 * cele reale: o coloană adăugată doar la un capăt oprește fluxul la primul lot
 * (câmp necunoscut → refuz), iar aia nu se vede decât ca „expedierea s-a oprit".
 */
const INCIDENTS: Stream = {
  name: "incidents",
  table: "incident_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "fingerprint", target: "fingerprint", kind: "text", nullable: false, maxBytes: 190 },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "severity", target: "severity", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "ai_severity", target: "ai_severity", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "ai_verdict", target: "ai_verdict", kind: "json", nullable: true, maxBytes: LONGTEXT },
    { source: "ai_confidence", target: "ai_confidence", kind: "decimal", nullable: true },
    { source: "ai_analyzed_at", target: "ai_analyzed_at", kind: "timestamp", nullable: true },
    { source: "title", target: "title", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "summary", target: "summary", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "actor_key", target: "actor_key", kind: "text", nullable: true, maxBytes: 190 },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: true },
    { source: "detection_count", target: "detection_count", kind: "int", nullable: false },
    { source: "created_at", target: "created_at", kind: "timestamp", nullable: false },
    { source: "first_detection_at", target: "first_detection_at", kind: "timestamp", nullable: false },
    { source: "last_detection_at", target: "last_detection_at", kind: "timestamp", nullable: false },
    { source: "acknowledged_by", target: "acknowledged_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "acknowledged_at", target: "acknowledged_at", kind: "timestamp", nullable: true },
    { source: "resolved_at", target: "resolved_at", kind: "timestamp", nullable: true },
    { source: "resolution_note", target: "resolution_note", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "notified_at", target: "notified_at", kind: "timestamp", nullable: true },
    { source: "auto_action", target: "auto_action", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "auto_action_at", target: "auto_action_at", kind: "timestamp", nullable: true },
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * `incident_timeline` → `incident_timeline_entries`.
 *
 * Append-only la sursă — nimic din `sentinel/` nu face UPDATE pe tabela aia —
 * deci cursorul merge pe `id` și nu atinge niciun ceas. `chained: false`:
 * lanțul de hash-uri e o proprietate a lui `audit_log`, nu a oricărui flux
 * append-only, iar a-l cere aici ar refuza fiecare rând pentru lipsa unei
 * coloane care nu există la sursă.
 *
 * `incident_id` devine `incident_source_id`, și rămâne o referință SUSPENDATĂ:
 * nu există chei străine pe agregator, fiindcă fluxurile avansează independent
 * și o intrare de cronologie poate sosi legitim înaintea incidentului ei.
 * `lib/data/incidents.ts` citește cronologia filtrând pe
 * `(instance_id, incident_source_id)` — nu urmează nicio legătură, deci un
 * orfan temporar nu strică nimic; se completează la runda următoare.
 *
 * Geamănul e `TIMELINE_STREAM` din `sentinel/report/shipper.py`, iar egalitatea
 * listelor e ținută de `tests/unit/test_aggregator_stream_columns.py`.
 */
const INCIDENT_TIMELINE: Stream = {
  name: "incident_timeline",
  table: "incident_timeline_entries",
  cursor: "append-only",
  chained: false,
  // `uk_incident_timeline_source (instance_id, source_id)`, `0003_entities.sql`.
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "incident_id", target: "incident_source_id", kind: "int", nullable: false },
    { source: "at", target: "at", kind: "timestamp", nullable: false },
    { source: "kind", target: "kind", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "actor", target: "actor", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "detail", target: "detail", kind: "json", nullable: false, maxBytes: LONGTEXT },
  ],
};

/**
 * `detections` → `detection_entries`. Append-only, cursor pe `id`.
 *
 * ## Ce NU pleacă: `event_ids`
 *
 * Coloana `bigint[]` a serverului nu e declarată la niciun capăt, iar tabela
 * `detection_events` rămâne goală. Nu e o omisiune: un tablou are nevoie de
 * sub-rânduri, iar expeditorul nu trimite tablouri încă — `MAX_CHILDREN_PER_ROW`
 * și `MAX_CHILD_ROWS_PER_BATCH` sunt declarate „doar la receptor" tocmai
 * fiindcă niciun flux cu copii nu există la vreun capăt.
 *
 * Consecința se scrie aici ca să nu fie descoperită ca surpriză: `detection_events`
 * ESTE motorul expedierii de dovezi (E4). Fără el, o detecție ajunge la panou cu
 * tot ce are nevoie triajul — regulă, severitate, actor, adresă, scor, blobul de
 * `evidence` — dar rândurile brute din `raw_events` la care trimite nu pot fi
 * cerute. Aia e o fază separată, și începe cu protocolul, nu cu o declarație.
 *
 * ## Două feluri de coloană care se folosesc AICI prima dată
 *
 *   * `bool` pentru `suppressed`. Adăugat pe 20 august 2026, strict: doar
 *     `true`/`false`, fiindcă `Boolean("0")` e adevărat;
 *   * `inet` pentru `src_ip`. Felul exista la receptor din start, cu o notă care
 *     spunea că adresa „pleacă de la expeditor ca text" — era o anticipare, nu
 *     un fapt: `encode_value` n-avea ramură pentru adrese și ar fi refuzat
 *     rândul. Acum are.
 *
 * `score` e `numeric(6,2)`, deci sosește ca ȘIR, ca `ai_confidence`.
 */
const DETECTIONS: Stream = {
  name: "detections",
  table: "detection_entries",
  cursor: "append-only",
  chained: false,
  // `uk_detection_entries_source (instance_id, source_id)`, `0003_entities.sql`.
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "ts", target: "ts", kind: "timestamp", nullable: false },
    { source: "rule_id", target: "rule_id", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "rule_family", target: "rule_family", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "severity", target: "severity", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "score", target: "score", kind: "decimal", nullable: true },
    { source: "actor_key", target: "actor_key", kind: "text", nullable: true, maxBytes: 190 },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: true },
    { source: "incident_id", target: "incident_source_id", kind: "int", nullable: true },
    { source: "src_ip", target: "src_ip", kind: "inet", nullable: true },
    { source: "dst_port", target: "dst_port", kind: "int", nullable: true },
    { source: "evidence", target: "evidence", kind: "json", nullable: false, maxBytes: LONGTEXT },
    { source: "suppressed", target: "suppressed", kind: "bool", nullable: false },
    { source: "suppress_reason", target: "suppress_reason", kind: "text", nullable: true, maxBytes: TEXT },
  ],
  /**
   * DOVEZILE. Primul flux cu sub-rânduri din tot protocolul.
   *
   * `detections.event_ids` e `bigint[]` la sursă și devine `detection_events`
   * aici — tabela care ESTE motorul expedierii de dovezi. Fără ea, o detecție
   * ajunge cu tot ce cere triajul, dar rândurile brute la care trimite nu pot fi
   * cerute niciodată, iar proprietatea din plan — „ce a plecat de pe mașină nu
   * mai poate fi șters de pe ea" — nu e adevărată pentru dovezi.
   *
   * Elementul e un OBIECT cu un singur câmp, nu un întreg gol. Contractul cere o
   * singură formă de element fiindcă `actor_attrs` are nevoie de două câmpuri, iar
   * două forme ar fi două căi de validare — încă un loc în care capetele pot să
   * nu fie de acord.
   *
   * `link.parent` e coloana-ȚINTĂ a părintelui (`source_id`), nu cea de pe
   * server: ingestia o caută în rândul deja tradus. Și e PARTE din identitate,
   * cum cere regula — altfel cheia n-ar mai deosebi sub-rândurile a doi părinți,
   * iar curățarea unei bucăți ar putea șterge un rând revendicat de alta.
   */
  children: [{
    source: "event_ids",
    table: "detection_events",
    link: [{ child: "detection_source_id", parent: "source_id" }],
    columns: [
      { source: "event_id", target: "event_source_id", kind: "id", nullable: false },
    ],
    // `uk_detection_events (instance_id, detection_source_id, event_source_id)`.
    identity: ["instance_id", "detection_source_id", "event_source_id"],
  }],
};

/**
 * `findings` -> `finding_entries`. Flux MUTABIL: o constatare isi schimba starea
 * (acceptata, amanata, rezolvata) fara sa-si mute `id`-ul, deci un cursor pe
 * `id` n-ar mai vedea-o niciodata dupa prima sosire.
 *
 * `kev_due_date` e prima coloana `date` din tot protocolul - o ZI, nu un moment.
 * Felul de coloana `date` exista de aceea: trecuta prin `timestamp`, valoarea ar
 * putea sosi ca moment intreg, iar MariaDB ar taia tacut ora la scriere. Un
 * termen KEV mutat cu o zi e o data gresita pe care n-o semnaleaza nimic, si
 * spune pana cand trebuie reparat ceva ce se exploateaza ACTIV.
 *
 * `cvss` si `epss` sunt `numeric` la sursa, deci sosesc ca SIR, ca `ai_confidence`.
 */
const FINDINGS: Stream = {
  name: "findings",
  table: "finding_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "finding_key", target: "finding_key", kind: "text", nullable: false, maxBytes: 64 },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: true },
    { source: "scanner", target: "scanner", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "cve", target: "cve", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "advisory_id", target: "advisory_id", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "title", target: "title", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "description", target: "description", kind: "text", nullable: true, maxBytes: MEDIUMTEXT },
    { source: "severity", target: "severity", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "cvss", target: "cvss", kind: "decimal", nullable: true },
    { source: "cvss_vector", target: "cvss_vector", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "epss", target: "epss", kind: "decimal", nullable: true },
    { source: "kev", target: "kev", kind: "bool", nullable: false },
    { source: "kev_due_date", target: "kev_due_date", kind: "date", nullable: true },
    { source: "package", target: "package", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "installed_version", target: "installed_version", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "fixed_version", target: "fixed_version", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "location", target: "location", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "ecosystem", target: "ecosystem", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "priority", target: "priority", kind: "int", nullable: false },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "first_seen", target: "first_seen", kind: "timestamp", nullable: false },
    { source: "last_seen", target: "last_seen", kind: "timestamp", nullable: false },
    { source: "resolved_at", target: "resolved_at", kind: "timestamp", nullable: true },
    { source: "resolution", target: "resolution", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "deferred_until", target: "deferred_until", kind: "timestamp", nullable: true },
    { source: "accepted_by", target: "accepted_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "accepted_reason", target: "accepted_reason", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "requires_manual_intervention", target: "requires_manual_intervention", kind: "bool", nullable: false },
    { source: "scan_id", target: "scan_source_id", kind: "int", nullable: true },
    { source: "raw", target: "raw", kind: "json", nullable: false, maxBytes: LONGTEXT },
    { source: "ai_assessment", target: "ai_assessment", kind: "json", nullable: true, maxBytes: LONGTEXT },
    { source: "ai_assessed_at", target: "ai_assessed_at", kind: "timestamp", nullable: true },
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * `blocklist` -> `blocklist_entries`. Mutabil: o blocare se dezactiveaza, i se
 * numara loviturile, i se schimba termenul - toate fara `id` nou.
 *
 * Deblocarea NU se porteaza in panou si nu are cum: agregatorul e o replica,
 * `hit_count` de aici e citit din contorul nftables de pe gazda, iar canalul de
 * comanda ramane Telegram.
 *
 * `net_start_bin`, `net_end_bin` si `cidr_text` NU pleaca de pe server: sunt
 * derivate, calculate la ingestie din `ip` + `prefix_len`, fiindca MariaDB n-are
 * tipul `cidr` si nici operatorul de apartenenta. Migratia le declara nule
 * tocmai ca fluxul sa poata curge inainte ca derivarea sa existe.
 */
const BLOCKLIST: Stream = {
  name: "blocklist",
  table: "blocklist_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "ip", target: "ip", kind: "inet", nullable: false },
    { source: "prefix_len", target: "prefix_len", kind: "int", nullable: true },
    { source: "reason", target: "reason", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "rule_id", target: "rule_id", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "incident_id", target: "incident_source_id", kind: "int", nullable: true },
    { source: "actor_key", target: "actor_key", kind: "text", nullable: true, maxBytes: 190 },
    { source: "blocked_at", target: "blocked_at", kind: "timestamp", nullable: false },
    { source: "expires_at", target: "expires_at", kind: "timestamp", nullable: true },
    { source: "ttl_seconds", target: "ttl_seconds", kind: "int", nullable: true },
    { source: "hit_count", target: "hit_count", kind: "int", nullable: false },
    { source: "last_hit_at", target: "last_hit_at", kind: "timestamp", nullable: true },
    { source: "created_by", target: "created_by", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "active", target: "active", kind: "bool", nullable: false },
    { source: "unblocked_at", target: "unblocked_at", kind: "timestamp", nullable: true },
    { source: "unblocked_by", target: "unblocked_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "unblock_reason", target: "unblock_reason", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * `patch_plans` -> `patch_plan_entries`. Mutabil: un plan trece prin draft,
 * validat, aprobat, aplicat - cu acelasi `id`.
 *
 * ## Ce NU pleaca: `finding_ids`
 *
 * `bigint[]` la sursa, iar expeditorul nu trimite tablouri. Tabela de legatura
 * `patch_plan_findings` ramane goala pana cand protocolul capata sub-randuri,
 * exact ca `detection_events`. Consecinta: vezi planul si starea lui, dar nu
 * lista constatarilor pe care le repara.
 *
 * `plan_id` e `uuid` la sursa si `VARCHAR(36)` aici; `encode_value` il trimite
 * prin `str()`, forma canonica, drum dus-intors exact. Se redenumeste in
 * `plan_uuid` fiindca `plan_id` ar fi fost al TREILEA inteles al aceluiasi nume
 * in tabela - cheia primara, uuid-ul, si legatura din `patch_executions`.
 *
 * `plan` e planul intreg, ca JSON, doar pentru afisare. Agregatorul nu executa
 * niciodata nimic din el.
 */
const PATCH_PLANS: Stream = {
  name: "patch_plans",
  table: "patch_plan_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "plan_id", target: "plan_uuid", kind: "text", nullable: false, maxBytes: 36 },
    { source: "plan_hash", target: "plan_hash", kind: "text", nullable: false, maxBytes: 64 },
    { source: "plan", target: "plan", kind: "json", nullable: false, maxBytes: LONGTEXT },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: true },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "risk_level", target: "risk_level", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "blast_radius", target: "blast_radius", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "requires_reboot", target: "requires_reboot", kind: "bool", nullable: false },
    { source: "reversible", target: "reversible", kind: "bool", nullable: false },
    { source: "estimated_downtime_s", target: "estimated_downtime_s", kind: "int", nullable: true },
    { source: "estimated_backup_mb", target: "estimated_backup_mb", kind: "int", nullable: true },
    { source: "confidence", target: "confidence", kind: "decimal", nullable: true },
    { source: "validation_errors", target: "validation_errors", kind: "json", nullable: true, maxBytes: LONGTEXT },
    { source: "validation_attempts", target: "validation_attempts", kind: "int", nullable: false },
    { source: "generated_by", target: "generated_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "model", target: "model", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "prompt_version", target: "prompt_version", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "generation_ms", target: "generation_ms", kind: "int", nullable: true },
    { source: "created_at", target: "created_at", kind: "timestamp", nullable: false },
    { source: "approved_by", target: "approved_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "approved_at", target: "approved_at", kind: "timestamp", nullable: true },
    { source: "scheduled_for", target: "scheduled_for", kind: "timestamp", nullable: true },
    { source: "rejected_by", target: "rejected_by", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "rejected_reason", target: "rejected_reason", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * `selfcheck_state` → `selfcheck_state_entries`. PRIMUL FLUX CU FILIGRAN TEXT.
 *
 * Cheia e `key text` la sursă, deci fluxul ăsta nu se putea expedia deloc până
 * pe 20 august 2026: jetonul de ecou trebuia să fie un întreg pozitiv. Ce s-a
 * schimbat nu e o excepție pentru el — e `watermarkKind`, declarat pe flux.
 *
 * `key` devine `check_key` fiindcă `KEY` e cuvânt rezervat în MariaDB. Iar
 * identitatea nu are `source_id`: e `(instance_id, check_key)`, fiindcă tabela
 * de pe server ține O SINGURĂ stare per verificare — rândurile se compară, nu se
 * acumulează.
 *
 * `stale` e boolean: 1 înseamnă că ultima rulare a fost incompletă și cifra
 * arătată e ultima știută. Pe pagină diferența contează — „verificarea spune ok"
 * și „verificarea n-a putut rula și îți arăt ce știam" nu sunt același lucru.
 */
const SELFCHECK_STATE: Stream = {
  name: "selfcheck_state",
  table: "selfcheck_state_entries",
  cursor: "mutable",
  chained: false,
  // `uk_selfcheck_state_entries (instance_id, check_key)`, `0004_health.sql`.
  identity: ["instance_id", "check_key"],
  watermark: "check_key",
  watermarkKind: "text",
  // Singurul flux din care sursa chiar șterge: `selfcheck/runner.py` face
  // `DELETE … WHERE NOT (key = ANY($1))` după fiecare rulare completă.
  pruneKey: "check_key",
  columns: [
    { source: "key", target: "check_key", kind: "text", nullable: false, maxBytes: 190 },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "title", target: "title", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "detail", target: "detail", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "facts", target: "facts", kind: "json", nullable: false, maxBytes: LONGTEXT },
    { source: "since", target: "since", kind: "timestamp", nullable: false },
    { source: "last_seen", target: "last_seen", kind: "timestamp", nullable: false },
    { source: "last_alert_at", target: "last_alert_at", kind: "timestamp", nullable: true },
    { source: "stale", target: "stale", kind: "bool", nullable: false },
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * Contorul orar, calculat pe server.
 *
 * Fluxul asta umple pagina „Rapoarte" — pana pe 21 august 2026 ea exista si
 * spunea ca fluxul n-a sosit niciodata, ceea ce era adevarat: datele se
 * calculau pe server la fiecare rulare de mentenanta si nu plecau nicaieri.
 *
 * ## De ce `mutable` si nu un al treilea fel
 *
 * La expeditor cursorul e de felul `rollup`: un MOMENT singur, fiindca un
 * agregat n-are nici `id`, nici `updated_at`. Aici insa nu se schimba nimic:
 * ingestia e upsert pe identitate, iar filigranul e text — exact ca la
 * `selfcheck_state`. Un al treilea fel declarat aici ar fi o eticheta, si
 * `CURSOR_KINDS` spune pe fata ca astea nu se adauga.
 *
 * ## Ce NU se face aici
 *
 * Nicio reagregare. Ora vine gata insumata, iar `uniq_src` e un MAXIM peste
 * minute, nu o suma — o subestimare cunoscuta, aleasa pe server. Recalculata
 * aici din altceva, ar deveni un al doilea raspuns la aceeasi intrebare.
 *
 * Fara `pruneKey`: mentenanta taie agregatele vechi prin retentie, iar o lista
 * de reconciliere peste ele ar sterge din panou tocmai istoricul pentru care
 * exista pagina.
 */
const EVENT_ROLLUP_1H: Stream = {
  name: "event_rollup_1h",
  table: "event_rollup_1h_entries",
  cursor: "mutable",
  chained: false,
  // `uk_event_rollup_1h_entries`, `0004_health.sql`.
  identity: ["instance_id", "bucket", "asset_source_id", "source", "action"],
  watermark: "bucket",
  // Momentul, scris ISO. Se compara pe octeti, si e corect: un `isoformat()` cu
  // acelasi fus si latime fixa are ordinea lexicografica egala cu cea cronologica.
  watermarkKind: "text",
  columns: [
    { source: "bucket", target: "bucket", kind: "timestamp", nullable: false },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: false },
    { source: "source", target: "source", kind: "text", nullable: false, maxBytes: 190 },
    { source: "action", target: "action", kind: "text", nullable: false, maxBytes: 190 },
    { source: "n", target: "n", kind: "int", nullable: false },
    { source: "uniq_src", target: "uniq_src", kind: "int", nullable: false },
    { source: "bytes_in", target: "bytes_in", kind: "int", nullable: false },
    { source: "bytes_out", target: "bytes_out", kind: "int", nullable: false },
    { source: "p95_latency_ms", target: "p95_latency_ms", kind: "int", nullable: true },
    // Coloana pe care merge filigranul de cand un interval RECALCULAT trebuie sa
    // plece din nou. `0014_rollup_updated_at.sql` spune cat a costat lipsa ei.
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * Rularile de scanare. Fluxul care da paginii de vulnerabilitati VARSTA cifrei.
 *
 * Pe 21 august 2026 lipsa lui a costat: operatorul a vazut 31 de vulnerabilitati
 * neaplicate in panou si nimic de actualizat pe server. Numarul nu era gresit —
 * era masurat la 03:23, iar pachetele fusesera reparate la 09:14. Intre cele
 * doua a mai rulat o scanare, si A ESUAT cu `timeout`; reusita, ar fi inchis
 * toate cele 31. Esecul nu ajungea nicaieri, iar pagina nu spunea nici cand
 * masurase, nici ca incercarea de reimprospatare cazuse.
 *
 * MUTABIL: randul se scrie ca `running` si se completeaza la final. Un cursor pe
 * `id` l-ar prinde o singura data, in starea de atunci — adica ar arata
 * „ruleaza" pentru totdeauna si niciodata CUM s-a incheiat.
 *
 * Fara `pruneKey`: retentia de pe server taie rulari vechi, iar o lista de
 * reconciliere peste ele ar sterge din panou tocmai istoricul de scanari.
 */
const SCANS: Stream = {
  name: "scans",
  table: "scan_entries",
  cursor: "mutable",
  chained: false,
  // `uk_scan_entries_source`, `0005_patch.sql`.
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "scanner", target: "scanner", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "target", target: "target", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "asset_id", target: "asset_source_id", kind: "int", nullable: true },
    { source: "status", target: "status", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "started_at", target: "started_at", kind: "timestamp", nullable: false },
    { source: "finished_at", target: "finished_at", kind: "timestamp", nullable: true },
    { source: "duration_ms", target: "duration_ms", kind: "int", nullable: true },
    { source: "exit_code", target: "exit_code", kind: "int", nullable: true },
    { source: "findings_count", target: "findings_count", kind: "int", nullable: false },
    { source: "new_findings", target: "new_findings", kind: "int", nullable: false },
    { source: "resolved_findings", target: "resolved_findings", kind: "int", nullable: false },
    { source: "db_version", target: "db_version", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "error", target: "error", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "triggered_by", target: "triggered_by", kind: "text", nullable: false, maxBytes: TEXT },
    // Coloana pe care merge cursorul mutabil. `0013_scans_updated_at.sql`.
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};


/**
 * Sesiunile de login. Mutabil: o sesiune se deschide, adună comenzi, se închide
 * și se promovează la interactivă — patru schimbări pe același `id`.
 *
 * `unexpected` lipsește dinadins: e `text[]` pe gazdă, iar expeditorul nu trimite
 * tablouri. Panoul de aici vede că o sesiune a fost neobișnuită din severitatea
 * alertei care a plecat pe Telegram, nu din listă.
 */
const LOGIN_SESSIONS: Stream = {
  name: "login_sessions",
  table: "login_session_entries",
  cursor: "mutable",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    { source: "session_key", target: "session_key", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "username", target: "username", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "auid", target: "auid", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "src_ip", target: "src_ip", kind: "inet", nullable: true },
    { source: "terminal", target: "terminal", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "interactive", target: "interactive", kind: "bool", nullable: false },
    { source: "opened_at", target: "opened_at", kind: "timestamp", nullable: false },
    { source: "closed_at", target: "closed_at", kind: "timestamp", nullable: true },
    { source: "closed_inferred", target: "closed_inferred", kind: "bool", nullable: false },
    { source: "command_count", target: "command_count", kind: "int", nullable: false },
    { source: "sudo_count", target: "sudo_count", kind: "int", nullable: false },
    // Coloana pe care merge cursorul mutabil. `0015_login_history.sql`.
    { source: "updated_at", target: "updated_at", kind: "timestamp", nullable: false },
  ],
};

/**
 * Istoricul de comenzi. Append-only, cursor pe `id`.
 *
 * E fluxul cu cel mai mare volum din toate zece: măsurat pe gazdă pe 24 august
 * 2026, ~630 de comenzi pentru o singură logare interactivă și ~405 000 pentru un
 * deploy. 97 415 rânduri ocupau 22 MB, față de 83 MB cât avea toată baza asta.
 *
 * `argv` sosește DEJA REDACTAT. Redactarea se face pe gazdă, la colectare: aici
 * ar fi prea târziu — secretul ar fi deja în baza locală și în backup-urile ei,
 * iar doar copia externă ar fi curată.
 */
const SESSION_COMMANDS: Stream = {
  name: "session_commands",
  table: "session_command_entries",
  cursor: "append-only",
  chained: false,
  identity: ["instance_id", "source_id"],
  watermark: "source_id",
  columns: [
    { source: "id", target: "source_id", kind: "id", nullable: false },
    // `login_sessions.id` de pe INSTANȚĂ, nu id-ul local. Nicio cheie străină:
    // cursoarele avansează independent, deci o comandă poate ajunge legitim
    // înaintea sesiunii ei, iar o referință suspendată e o stare normală.
    { source: "session_id", target: "session_source_id", kind: "int", nullable: true },
    { source: "session_key", target: "session_key", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "ts", target: "ts", kind: "timestamp", nullable: false },
    { source: "username", target: "username", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "exe", target: "exe", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "argv", target: "argv", kind: "text", nullable: false, maxBytes: TEXT },
    { source: "cwd", target: "cwd", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "tty", target: "tty", kind: "text", nullable: true, maxBytes: TEXT },
    { source: "pid", target: "pid", kind: "int", nullable: true },
    { source: "ppid", target: "ppid", kind: "int", nullable: true },
    { source: "success", target: "success", kind: "bool", nullable: true },
  ],
};


const STREAMS = new Map<string, Stream>([[AUDIT_LOG.name, AUDIT_LOG],
                                         [INCIDENTS.name, INCIDENTS],
                                         [INCIDENT_TIMELINE.name, INCIDENT_TIMELINE],
                                         [DETECTIONS.name, DETECTIONS],
                                         [FINDINGS.name, FINDINGS],
                                         [BLOCKLIST.name, BLOCKLIST],
                                         [PATCH_PLANS.name, PATCH_PLANS],
                                         [SELFCHECK_STATE.name, SELFCHECK_STATE],
                                         [EVENT_ROLLUP_1H.name, EVENT_ROLLUP_1H],
                                         [SCANS.name, SCANS],
                                         [LOGIN_SESSIONS.name, LOGIN_SESSIONS],
                                         [SESSION_COMMANDS.name, SESSION_COMMANDS]]);

/** Fluxul cerut, sau `undefined` dacă nu e cunoscut. */
export function streamFor(name: string): Stream | undefined {
  return STREAMS.get(name);
}

/** Toate fluxurile înregistrate, pentru testele care le verifică pe fiecare. */
export function allStreams(): Stream[] {
  return [...STREAMS.values()];
}

/** Numele fluxurilor cunoscute. Intră în mesajul de refuz al unui flux
 *  necunoscut — cine instalează trebuie să vadă ce știe agregatorul, altfel
 *  refuzul e la fel de opac ca o acceptare tăcută. */
export function knownStreamNames(): string[] {
  return [...STREAMS.keys()].sort();
}
