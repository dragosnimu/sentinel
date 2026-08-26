/**
 * Cine e expeditorul și cu ce cheie se verifică.
 *
 * ## De ce chei separate per instanță
 *
 * O cheie comună pentru toate serverele înseamnă că root pe A poate fabrica
 * semnale pentru B — inclusiv „B e viu și contoarele avansează" în timp ce B e
 * oprit. Martorul există exact ca să nu poată fi mințit de mașina monitorizată,
 * deci o cheie partajată ar anula proprietatea pentru toate instanțele
 * simultan, nu doar pentru cea compromisă.
 *
 * ## De ce o singură variabilă cu hartă JSON, nu N variabile
 *
 * Variabilele de mediu se pun MANUAL în panoul găzduirii — nu există API pentru
 * ele (vezi watcher/INCARCARE-HOSTINGER.md). Cu `SENTINEL_INSTANCE_<ID>_SECRET`, o
 * literă greșită în NUMELE variabilei nu se vede nicăieri: instanța devine
 * necunoscută, semnalele ei sunt refuzate cu 401, iar dacă e o instanță nouă
 * care n-a apărut niciodată în stare, martorul nu are ce să declare tăcut. Un
 * eșec tăcut, adică fix tiparul din CLAUDE.md.
 *
 * O hartă JSON într-o singură variabilă mută eșecul acela în zgomot: dacă e
 * scrisă greșit, NU se poate citi nicio cheie, iar ruta răspunde 500
 * („nu sunt configurat"), nu 401 („te-am refuzat"). Adăugarea unei instanțe e o
 * singură valoare de editat.
 *
 * O versiune anterioară a comentariului ăstuia spunea că o hartă stricată „se
 * observă la prima probă de acceptanță". **E fals.** 500-ul ajunge la
 * EXPEDITORI, ale căror jurnale sunt pe partea monitorizată — adică exact
 * partea pe care un atacator o controlează; proba de acceptanță se rulează o
 * dată, la instalare; iar monitorul care întreabă în fiecare minut nu vede
 * nimic din toate astea.
 *
 * Ce o observă cu adevărat e tăcerea: fișierele de stare se identifică singure
 * (`lib/store.ts`), deci instanțele rămân membre chiar fără cheie, semnalele
 * lor sunt refuzate, iar după trei intervale ratate martorul sună. O virgulă
 * greșită într-un formular web nu mai șterge trei servere de pe hartă — le face
 * să alarmeze.
 *
 *   SENTINEL_INSTANCE_SECRETS={"a1b2c3":"<hex>","d4e5f6":"<hex>"}
 *
 * ## Când formatul JSON nu e disponibil — 14 august 2026
 *
 * Raționamentul de deasupra rămâne valabil ca intenție: o singură variabilă, o
 * singură valoare de editat, iar o greșeală în ea nu șterge instanțe, ci le face
 * să tacă și să alarmeze. Ce s-a schimbat e că pe găzduirea martorului formatul
 * JSON **nu poate fi scris deloc**: panoul ELIMINĂ `{`, `}` și `"` din valorile
 * variabilelor de mediu. Măsurat, nu presupus — o valoare importată dintr-un
 * fișier `.env` s-a regăsit în panou fără acolade și fără ghilimele, iar
 * jurnalul de execuție al aplicației scria la fiecare cerere că valoarea nu e
 * JSON valid (vezi watcher/INCARCARE-HOSTINGER.md). Costul: peste opt ore în care
 * serverul monitorizat trimitea, martorul răspundea 401 și nu înregistra nimic.
 *
 * Deci se acceptă și o codificare care nu conține niciunul dintre cele trei
 * caractere:
 *
 *   SENTINEL_INSTANCE_SECRETS=a1b2c3:<hex>,d4e5f6:<hex>
 *
 * Perechile se despart prin `,`, `;` sau newline — o clasă, nu un caracter
 * presupus, fiindcă un separator pe care parserul nu-l cunoaște ar face a doua
 * pereche să dispară în cheia primei, tăcut (vezi `PAIR_SEPARATORS`).
 *
 * Formatul se alege după PRIMUL caracter nespațiu: `{` înseamnă JSON, orice
 * altceva înseamnă perechi. JSON rămâne formatul de referință — e cel din
 * `watcher/.env.example` și din teste, se validează cu unelte obișnuite, și e singurul
 * rezonabil pe o gazdă care nu strică valorile. **Nu se „simplifică" înapoi la
 * JSON-only**: pe gazda asta, asta înseamnă martor mut, iar simptomul e 401 la
 * fiecare bătaie, adică exact tăcerea pe care martorul ar trebui s-o denunțe.
 *
 * Efect secundar util, dar care se confirmă doar prin efect, după publicare: o
 * hartă JSON din care se scot `{`, `}` și `"` ESTE deja forma de perechi.
 *
 * ## Toleranța pentru serverul deja în producție
 *
 * Ordinea de livrare e martorul întâi, serverul după. Expeditorul de azi nu
 * trimite nici antet, nici `instance_id`, deci ambele lipsuri înseamnă instanța
 * `default`, verificată cu `SENTINEL_BEACON_SECRET` — variabila care e deja
 * configurată. Fără asta, actualizarea martorului ar tăia semnalul serverului
 * existent, iar simptomul ar fi chiar alarma pe care martorul o dă când un
 * server moare.
 *
 * ## Retragerea unei identități — 15 august 2026
 *
 * Un server dezafectat lasă în urmă o identitate care tace pentru totdeauna, iar
 * tăcerea ei NU e `no-beat`: instanța a bătut cândva, deci e `silent`, iar
 * `silent` se numără în verdictul agregat. Măsurat în ziua aia, cu identitatea
 * moștenită pe care serverul real nu o mai folosește de când poartă
 * `instance_id`:
 *
 *   <instance_id>  ok      age_s 54
 *   default        silent  age_s 63967
 *   agregat: HTTP 503
 *
 * Adică plasa de siguranță roșie la nesfârșit și o alertă critică la fiecare
 * patru ore despre un server care nu există, în timp ce toate serverele reale
 * sunt sănătoase — exact alarma pe care operatorul o oprește.
 *
 * Reparația evidentă — „scoate variabila care ține identitatea în registru" —
 * NU e disponibilă. Măsurat pe gazda martorului în aceeași zi și confirmat de
 * operator: variabilele de mediu **nu se pot șterge** (ștergerea din formular nu
 * se propagă, variabila reapare) și **nu pot avea valoare goală** (panoul cere o
 * valoare). Retragerea nu se poate deci exprima prin absență și are nevoie de o
 * declarație proprie:
 *
 *   SENTINEL_RETIRED_INSTANCES=<id>,<id>
 *
 * Aceeași clasă de separatori ca la perechi (`PAIR_SEPARATORS`) și aceeași
 * validare (`ID_PATTERN`), din aceleași motive. Ce e DIFERIT e ce se întâmplă cu
 * o valoare din care nu iese nicio identitate: aici nu există `broken`. La chei,
 * eșecul de parsare e tăcut (401 pe o valoare care în panou arată corectă), deci
 * merită 500. Aici eșecul e zgomotos prin construcție — dacă nu se retrage
 * nimic, identitatea rămâne membră și continuă să alarmeze, adică fix ce vedea
 * operatorul înainte să scrie variabila. Un 500 ar opri în schimb înregistrarea
 * semnalelor pentru TOATE serverele sănătoase, din cauza unei propoziții despre
 * unul mort. Intrările nevalide se numără și se scriu în jurnal ca NUMĂR.
 *
 * ## Ce înseamnă retras — și de ce nu e același lucru cu „i s-a șters cheia"
 *
 * Retras înseamnă că identitatea nu mai există: iese din registru (deci tăcerea
 * ei nu mai intră în verdictul agregat și nu mai produce alerte), fișierul rămas
 * pe disc nu mai e al ei (`fileBelongsTo` în `lib/store.ts`), iar cheia ei nu
 * mai autentifică. Ultima parte e o REVOCARE și e obligatorie: altfel cine
 * deține cheia unei mașini scoase din uz păstrează o intrare validă la martor,
 * iar starea scrisă de el n-ar mai fi citită de nimeni.
 *
 * Ștergerea unei chei rămâne exact ce era: un server viu căruia i s-a șters
 * cheia rămâne membru prin fișierul care se identifică singur, tace și
 * alarmează. Cele două nu se pot confunda fiindcă vin din variabile diferite, și
 * fiindcă retragerea cere identitatea scrisă în litere — o valoare stricată nu
 * poate retrage din greșeală, iar o cheie lipsă nu retrage niciodată.
 *
 * Costul, scris ca să nu fie descoperit mai târziu: o identitate retrasă DIN
 * GREȘEALĂ — un identificator reciclat pentru o mașină nouă, tastat peste al
 * uneia vii, sau `default` retras cât timp un server neactualizat mai bate sub
 * ea — tace fără să alarmeze, fiindcă martorul nu o mai așteaptă. E prețul unei
 * declarații deliberate, iar singura urmă rămâne linia de jurnal scrisă de
 * `beat/route.ts`.
 *
 * Urma aia trebuie deci să însemne ceva. De-aia semnătura se verifică ÎNAINTEA
 * refuzului (vezi `KeyLookup` și `beat/route.ts`): un beat semnat corect sub o
 * identitate retrasă nu poate veni decât de la deținătorul cheii, deci e un
 * server viu, nu un scanner care a nimerit un antet. Cu ordinea inversă — refuz
 * înainte de semnătură — aceeași linie se scria pentru orice cerere de pe
 * internet, iar „singura urmă" nu putea deosebi un server viu de zgomot.
 *
 * Jurnalul găzduirii rămâne o suprafață slabă; asta e limita conștientă a
 * mecanismului. Ce s-a reparat e ca linia să fie un FAPT, nu un ecou.
 *
 * Contradicția — aceeași identitate ȘI în `SENTINEL_INSTANCE_SECRETS`, ȘI în
 * lista de retrase — se rezolvă în favoarea retragerii și NU e tratată ca
 * eroare. Motivul e tot gazda: cheia instanței implicite stă în
 * `SENTINEL_BEACON_SECRET`, care nu poate fi nici ștearsă, nici golită, deci
 * suprapunerea e starea NORMALĂ după o retragere, nu o greșeală. `broken`, ca la
 * identificatorul repetat, ar însemna 500 pentru toate serverele sănătoase din
 * cauza unei identități moarte; „cheia câștigă" ar face mecanismul inutil exact
 * în cazul pentru care există. Cheia rămasă nu mai deschide nimic, dar merită
 * rotită la sursă — vezi `watcher/.env.example`.
 */

export const INSTANCE_HEADER = "x-sentinel-instance";

/** Instanța sub care intră tot ce nu se declară altfel. */
export const DEFAULT_INSTANCE = "default";

/**
 * Ce forme de identificator sunt acceptate.
 *
 * Primul caracter trebuie să fie alfanumeric, ceea ce elimină din start
 * `__proto__` — un identificator care, folosit ca proprietate pe un obiect
 * obișnuit, nu ar deveni o intrare în hartă ci ar rescrie prototipul ei.
 * Restul clasei ține identificatorul folosibil într-un nume de fișier, într-un
 * parametru de URL și într-un mesaj Telegram fără escapare.
 */
const ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/;

export function isValidInstanceId(id: string): boolean {
  return ID_PATTERN.test(id);
}

/**
 * Citire de proprietate PROPRIE, niciodată moștenită.
 *
 * `harta["constructor"]` întoarce o funcție pe orice obiect obișnuit. Fără
 * verificarea asta, un identificator ales cu grijă ar face o instanță
 * necunoscută să pară configurată.
 */
export function own<T>(map: Record<string, T>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

export type KeyLookup =
  /** Am cheia instanței cerute. */
  | { ok: true; secret: string }
  /** Nu știu de instanța asta, sau identificatorul e malformat. → 401 */
  | { ok: false; reason: "unknown" }
  /**
   * Identitate retrasă de operator. `ok: false` — nu autentifică nimic,
   * niciodată; refuzul e tot 401, doar motivul e altul.
   *
   * `secret` e prezent când cheia identității retrase se mai poate citi din
   * configurație — de obicei chiar așa e, fiindcă `SENTINEL_BEACON_SECRET` nu se
   * poate șterge de pe gazda martorului. NU e o autorizare: e materialul cu care
   * ruta verifică semnătura ÎNAINTE de refuz, ca să poată deosebi „deținătorul
   * cheii unei mașini scoase din uz încă trimite" de „un scanner a trimis un
   * antet".
   *
   * Fără deosebirea asta, singura urmă a unei retrageri făcute din greșeală — o
   * linie în jurnal — poate fi produsă de oricine, deci nu înseamnă nimic. Vezi
   * ordinea din `beat/route.ts`, unde retragerea se aplică DUPĂ semnătură.
   *
   * Când cheia nu se poate citi, nimic nu e dovedibil despre expeditor, iar
   * cazul e din toate punctele de vedere identic cu `unknown`.
   */
  | { ok: false; reason: "retired"; secret?: string }
  /** Nu pot citi nicio cheie. Nu e un refuz, e o configurație lipsă. → 500 */
  | { ok: false; reason: "unconfigured" };

type ParsedMap = { map: Record<string, string>; broken: boolean };

/**
 * Harta se reparsează la fiecare cerere, dinadins.
 *
 * O valoare memorată la încărcarea modulului ar supraviețui corectării
 * variabilei în panou, iar operatorul ar vedea 401 după ce tocmai a reparat
 * cheia — și ar căuta problema în altă parte.
 */
function instanceSecrets(): ParsedMap {
  const raw = process.env.SENTINEL_INSTANCE_SECRETS;
  if (!raw || !raw.trim()) return { map: {}, broken: false };

  // Alegerea formatului se face pe primul caracter NESPAȚIU, nu pe `raw[0]`: un
  // panou web care adaugă un spațiu la început nu are voie să trimită o hartă
  // JSON validă la parserul de perechi, unde s-ar pierde toată.
  const trimmed = raw.trim();
  return trimmed.startsWith("{") ? parseJsonMap(trimmed) : parsePairsMap(trimmed);
}

/**
 * Separatorii de perechi, ca CLASĂ — nu un singur caracter presupus.
 *
 * Cu `split(",")` singur, o valoare scrisă cu newline sau cu `;` întoarce UN
 * segment: `indexOf(":")` taie la primul `:` și tot restul, inclusiv a doua
 * pereche, devine CHEIA primei. Nimic nu se numără, deci nimic nu ajunge în
 * jurnal, iar a doua instanță nu intră nici măcar în registru — deci nici
 * tăcerea ei nu alarmează, fiindcă nimeni n-o așteaptă. Rezultatul e 401 la
 * fiecare bătaie pe o valoare care în panou arată corectă, adică exact starea
 * pentru care există formatul ăsta, minus linia din jurnal care a făcut
 * diagnosticul posibil.
 *
 * Spațiul NU e separator, dinadins: e singurul caracter pe care un formular web
 * îl adaugă singur în jurul lui `:` și `,`, iar un spațiu n-are voie să însemne
 * „instanță necunoscută". Perechile despărțite prin spațiu se REFUZĂ zgomotos —
 * vezi `SECRET_CHARS` — nu se citesc pe jumătate.
 *
 * `\r` pe lângă `\n` nu e decorativ, deși la CRLF ar fi: acolo `\n` desparte
 * deja, iar `.trim()` mătură CR-ul rămas la capătul segmentului. Ce acoperă `\r`
 * singur e o valoare cu terminații de linie VECHI, fără `\n` după — și singura
 * operație care chiar schimbă o variabilă în panoul găzduirii e importul unui
 * fișier `.env` construit în altă parte (watcher/INCARCARE-HOSTINGER.md). Fără `\r` în
 * clasă, o astfel de valoare rămâne un singur segment, cheia primei instanțe
 * înghite un caracter care nu e de cheie, iar `SECRET_CHARS` face TOATĂ valoarea
 * `broken`: 500 la fiecare bătaie, de la toate serverele. Ținut în viață de
 * `tests/instances.route.test.ts`, ca să nu fie simplificată înapoi la un
 * singur caracter.
 */
const PAIR_SEPARATORS = /[,;\r\n]/;

/**
 * Din ce e făcută o cheie: alfabetul hexa, base64 și base64url, plus `:`.
 *
 * E o listă ÎNCHISĂ de caractere permise, nu o listă de separatori interziși,
 * fiindcă lista separatorilor pe care i-ar scrie un om e deschisă — `,`, `;`,
 * newline, spațiu, tab, `|`. Orice caracter din afara alfabetului ajuns într-o
 * cheie înseamnă că segmentul a înghițit altceva decât o cheie, iar atunci se
 * NUMĂRĂ ca intrare ignorată și se raportează. Nimic nu are voie să fie absorbit
 * tăcut într-o cheie.
 *
 * `+` la sfârșit, nu `*`: o cheie goală nu e o cheie, deci cade pe aceeași
 * ramură ca una imposibilă, fără o verificare separată care s-ar putea șterge.
 */
const SECRET_CHARS = /^[A-Za-z0-9+/=:._-]+$/;

/**
 * Numărul, nu intrările. „Am ignorat ceva" trebuie să se vadă; ce anume, nu.
 *
 * Numele variabilei e parametru fiindcă regula e aceeași pentru toate valorile
 * scrise de mână în panou, iar mesajul trebuie totuși să spună PE CARE dintre
 * ele a picat: două variabile care raportează la fel trimit operatorul să
 * corecteze valoarea greșită.
 */
function reportDropped(variable: string, dropped: number): void {
  if (dropped) {
    console.error(`[watcher] intrări ignorate din ${variable}`, dropped);
  }
}

/**
 * Identitățile RETRASE de operator.
 *
 * `Set`, nu obiect: pe un obiect obișnuit `harta["constructor"]` întoarce ceva
 * fără ca nimeni să fi scris acolo, iar o retragere fantomă ar scoate din
 * registru o instanță pe care nimeni nu a retras-o — adică tăcere în loc de
 * alarmă, direcția cea mai scumpă.
 *
 * Se reparsează la fiecare apel, ca și harta de chei: o valoare memorată la
 * încărcarea modulului ar supraviețui corectării variabilei în panou, iar
 * operatorul ar vedea vechiul comportament după ce tocmai a reparat valoarea.
 *
 * Nu există ramură `broken` aici, și e o alegere — motivul întreg e în
 * docstring-ul modulului: o listă din care nu iese nimic nu retrage nimic, deci
 * eșecul ei se vede ca alarma care continuă, nu ca tăcere.
 */
export function retiredInstanceIds(): Set<string> {
  const ids = new Set<string>();
  const raw = process.env.SENTINEL_RETIRED_INSTANCES;
  if (!raw || !raw.trim()) return ids;

  let dropped = 0;
  for (const segment of raw.split(PAIR_SEPARATORS)) {
    const item = segment.trim();
    // Segment gol: un separator în plus sau la capăt. NU se numără — n-a
    // dispărut nicio identitate, iar o linie de eroare la fiecare cerere pe o
    // configurație sănătoasă e felul în care jurnalul devine ilizibil.
    if (item === "") continue;
    if (!isValidInstanceId(item)) {
      dropped++;
      continue;
    }
    ids.add(item);
  }
  reportDropped("SENTINEL_RETIRED_INSTANCES", dropped);
  return ids;
}

function parseJsonMap(raw: string): ParsedMap {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // Fără detalii în jurnal: mesajul unui parser JSON conține fragmentul care
    // a eșuat, iar fragmentul ăla e o cheie.
    console.error("[watcher] SENTINEL_INSTANCE_SECRETS nu e JSON valid");
    return { map: {}, broken: true };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    console.error("[watcher] SENTINEL_INSTANCE_SECRETS nu e un obiect");
    return { map: {}, broken: true };
  }

  const map: Record<string, string> = {};
  let dropped = 0;
  for (const [id, secret] of Object.entries(parsed as Record<string, unknown>)) {
    if (!isValidInstanceId(id) || typeof secret !== "string" || secret === "") {
      dropped++;
      continue;
    }
    map[id] = secret;
  }
  reportDropped("SENTINEL_INSTANCE_SECRETS", dropped);
  // O hartă din care s-a pierdut tot nu e o hartă goală, e o hartă stricată.
  // `{}` scris dinadins NU intră aici: acolo nu s-a pierdut nimic, e o listă
  // goală declarată explicit, iar 500 ar fi o problemă inventată.
  return { map, broken: dropped > 0 && Object.keys(map).length === 0 };
}

/**
 * Forma `<id>:<cheie><separator><id>:<cheie>` — fără `{`, `}`, `"`.
 *
 * Reguli, și de ce fiecare:
 *
 *   * separatorul de perechi e o clasă, nu un caracter: `,`, `;`, newline. Vezi
 *     `PAIR_SEPARATORS` pentru ce se întâmplă fără asta — a doua pereche
 *     dispare în cheia primei, tăcut;
 *   * spațiile se ignoră în jurul separatorilor și la capete. Un formular web
 *     poate adăuga un spațiu, iar un spațiu n-are voie să însemne „instanță
 *     necunoscută", adică 401 la fiecare bătaie;
 *   * se împarte la PRIMUL `:`, restul segmentului e cheia. Cheile de azi sunt
 *     hexa, deci nu conțin `:`; forma n-are voie să se strice tăcut dacă mâine
 *     nu vor mai fi;
 *   * identitatea trece `ID_PATTERN`, iar cheia trece `SECRET_CHARS` — un
 *     alfabet închis, care refuză orice separator neanticipat în loc să-l
 *     înghită. Intrările care nu trec se NUMĂRĂ, nu se scriu — un mesaj de
 *     eroare care conține fragmentul stricat conține o cheie;
 *   * o valoare nevidă din care nu iese nicio pereche e `broken`, nu hartă
 *     goală. Cazul trăit pe 14 august 2026: câmpul conținea doar un
 *     identificator, fără `:` și fără cheie — arăta configurat și nu producea
 *     nimic. `broken` duce la 500 „nu sunt configurat", care e ce se vede
 *     dintr-un `curl` și e ce a permis în final diagnosticul; o hartă goală ar
 *     fi dat 401 „te-am refuzat", adică minciuna că valoarea a fost citită;
 *   * un identificator repetat strică TOATĂ valoarea. „Ultima câștigă" ar
 *     alege tăcut una din două chei pentru aceeași identitate — dacă alege
 *     greșit, instanța primește 401 la nesfârșit în timp ce valoarea din panou
 *     pare corectă. Un identificator scris de două ori e dovada că valoarea a
 *     fost editată greșit, iar atunci nici restul ei nu merită încredere: se
 *     întoarce hartă goală + `broken`, adică 500 pentru toți, care aduce omul
 *     imediat. Asimetria față de ramura JSON e reală și e o ALEGERE, nu o
 *     imposibilitate: `JSON.parse` colapsează cheile duplicate înainte să le
 *     vedem, deci cu el singur duplicatul nu se poate detecta — o parcurgere a
 *     șirului brut ÎNAINTE de parsare l-ar vedea. Nu se face, fiindcă ar
 *     însemna un al doilea parser JSON scris de mână, pentru formatul care pe
 *     gazda asta oricum nu supraviețuiește. Consecința nu se presupune: în
 *     JSON „ultima câștigă", tăcut, iar direcția e fixată de un test ca să nu
 *     se poată schimba în vreun sens fără ca cineva să observe.
 *
 * ## Limita care rămâne, scrisă ca să nu fie descoperită de operator
 *
 * Un separator ȘTERS fără să fie înlocuit cu nimic — `a:CHEIE1b:CHEIE2` — nu se
 * poate deosebi de o singură cheie care conține `:`, fiindcă `:` e permis în
 * cheie dinadins (regula de mai sus). Cele două forme sunt identice literă cu
 * literă, deci nu e o scăpare care se poate repara aici. Ce s-a măsurat pe 14
 * august 2026 e că panoul scoate `{`, `}` și `"`; despre ștergerea virgulei nu
 * există nicio măsurătoare. Dacă apare vreodată una, decizia e a operatorului:
 * interzicerea lui `:` în cheie face cazul vizibil (500 în loc de 401), cu
 * prețul unei chei viitoare care conține `:`.
 */
function parsePairsMap(raw: string): ParsedMap {
  const map: Record<string, string> = {};
  let dropped = 0;
  let duplicate = false;

  for (const segment of raw.split(PAIR_SEPARATORS)) {
    const item = segment.trim();
    // Segment gol: un separator în plus sau la capăt. NU se numără ca intrare
    // ignorată — nu s-a pierdut nicio identitate și nicio cheie, iar o linie de
    // eroare la fiecare cerere pe o configurație sănătoasă învață operatorul să
    // nu mai citească jurnalul, care e chiar suprafața pe care se
    // diagnostichează. Valoarea formată NUMAI din separatori rămâne prinsă: din
    // ea nu iese nicio pereche, deci intră pe ramura `broken` de mai jos.
    if (item === "") continue;
    const cut = item.indexOf(":");
    if (cut < 0) {
      dropped++;
      continue;
    }
    const id = item.slice(0, cut).trim();
    const secret = item.slice(cut + 1).trim();
    // `SECRET_CHARS`, nu `secret !== ""`: un segment care a înghițit o pereche
    // despărțită printr-un separator neanticipat are o cheie NEVIDĂ, deci
    // verificarea pe vid l-ar fi lăsat să treacă drept cheia primei instanțe.
    if (!isValidInstanceId(id) || !SECRET_CHARS.test(secret)) {
      dropped++;
      continue;
    }
    // `own`, nu `id in map`: pe un obiect obișnuit, `"constructor" in map` e
    // adevărat fără ca nimeni să fi scris ceva acolo.
    if (own(map, id) !== undefined) {
      duplicate = true;
      continue;
    }
    map[id] = secret;
  }

  reportDropped("SENTINEL_INSTANCE_SECRETS", dropped);
  if (duplicate) {
    console.error("[watcher] SENTINEL_INSTANCE_SECRETS repetă un identificator");
    return { map: {}, broken: true };
  }
  if (Object.keys(map).length === 0) {
    console.error("[watcher] SENTINEL_INSTANCE_SECRETS nu conține nicio pereche <id>:<cheie>");
    return { map: {}, broken: true };
  }
  return { map, broken: false };
}

/**
 * REGISTRUL instanțelor: cine există, după chei — nu după fișiere.
 *
 * O instanță există fiindcă are o cheie configurată, nu fiindcă există un
 * fișier cu numele ei. Diferența nu e teoretică: martorul își ține starea în
 * directorul home al operatorului (vezi watcher/INCARCARE-HOSTINGER.md), adică exact
 * locul în care cineva pune o copie înainte de o publicare. O căutare după
 * fișiere transforma `state.backup-2026-08-12.json` într-un server, iar o copie
 * are prin definiție un semnal vechi — deci martorul trimitea o alertă critică
 * despre o mașină care nu există și o repeta la fiecare patru ore, la nesfârșit.
 *
 * Un marcaj scris în fișier nu ar fi rezolvat-o: copia poartă și marcajul.
 * Registrul trebuie să fie în altă parte decât în lucrul copiat.
 *
 * Se potrivește și cu modelul de securitate: fără cheie nu poți trimite un
 * semnal, deci fără cheie nu ai voie nici să exiști.
 *
 * Retragerea scoate din registru, iar asta e singurul mod în care o identitate
 * poate ieși fără să dispară și cheia: pe gazda martorului variabilele nu se pot
 * șterge și nu pot fi goale, deci absența nu e o operație disponibilă.
 */
export function configuredInstanceIds(): string[] {
  const retired = retiredInstanceIds();
  const { map } = instanceSecrets();
  const ids = Object.keys(map).filter((id) => !retired.has(id));
  // Retragerea bate și variabila moștenită. Fără condiția asta, `default` — a
  // cărei cheie stă într-o variabilă care nu se poate șterge — nu ar putea fi
  // retrasă niciodată, adică exact cazul pentru care există mecanismul.
  if (process.env.SENTINEL_BEACON_SECRET
    && !retired.has(DEFAULT_INSTANCE)
    && !ids.includes(DEFAULT_INSTANCE)) {
    ids.push(DEFAULT_INSTANCE);
  }
  return ids.sort();
}

export function lookupInstanceKey(id: string): KeyLookup {
  const legacy = process.env.SENTINEL_BEACON_SECRET || "";
  const { map, broken } = instanceSecrets();

  // Cheia se caută ÎNTÂI, chiar pentru o identitate retrasă. Retragerea rămâne o
  // revocare — rezultatul e `ok: false` în ambele cazuri — dar cheia pleacă
  // odată cu refuzul, ca ruta să poată verifica semnătura înainte să scrie ceva
  // în jurnal. Vezi `KeyLookup` și ordinea din `beat/route.ts`: un refuz pe care
  // îl poate provoca oricine nu e un fapt, iar linia de jurnal e singura urmă a
  // unei retrageri făcute din greșeală.
  //
  // `Set.has` pe un identificator nevalidat e sigur: mulțimea conține doar
  // identificatori care au trecut deja `ID_PATTERN`, iar un `Set` nu are
  // proprietăți moștenite.
  const retired = retiredInstanceIds().has(id);

  if (isValidInstanceId(id)) {
    const fromMap = own(map, id);
    if (fromMap) {
      return retired ? { ok: false, reason: "retired", secret: fromMap } : { ok: true, secret: fromMap };
    }
    // `SENTINEL_BEACON_SECRET` e cheia instanței implicite, dar numai dacă harta
    // nu a definit-o deja: o intrare explicită bate o variabilă moștenită.
    if (id === DEFAULT_INSTANCE && legacy) {
      return retired ? { ok: false, reason: "retired", secret: legacy } : { ok: true, secret: legacy };
    }
  }

  // Retrasă, dar fără cheie citibilă: nu se poate dovedi nimic despre expeditor,
  // nici acum, nici vreodată. Se întoarce tot `retired`, ca apelantul să nu
  // trebuiască să ghicească; el decide că fără `secret` nu are ce fapt să scrie.
  if (retired) return { ok: false, reason: "retired" };

  // Aici nu avem cheia. Rămâne de spus DE CE, fiindcă cele două cauze cer
  // reacții diferite de la cel care instalează.
  //
  // Retragerea NU intră în socoteala asta: `unconfigured` înseamnă „nu pot citi
  // nicio cheie", iar o valoare citită perfect din care operatorul a retras tot
  // nu e o configurație lipsă, e un registru gol prin declarație. Registrul gol
  // se vede oricum, roșu, în `/status` (`unconfigured` acolo e altă socoteală:
  // zero instanțe, nu zero chei).
  if (broken) return { ok: false, reason: "unconfigured" };
  if (!legacy && Object.keys(map).length === 0) return { ok: false, reason: "unconfigured" };
  return { ok: false, reason: "unknown" };
}
