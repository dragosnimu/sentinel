/**
 * Starea martorului, în spatele unei interfețe minime.
 *
 * Abstracția există dintr-un motiv practic, nu din eleganță: nu știm încă ce
 * stocare persistentă are găzduirea. Implementarea pe fișier merge oriunde
 * există un disc scriibil; dacă se dovedește că discul nu supraviețuiește
 * redeployului, se înlocuiește doar fișierul ăsta.
 *
 * Cantitatea de stare e mică dinadins — ultimul semnal, câteva contoare și dacă
 * o alertă a fost deja trimisă, acum câte un set pentru fiecare instanță
 * monitorizată. Un martor care are nevoie de o bază de date ca să spună „a
 * tăcut" e un martor cu propriile moduri de a cădea. Argumentul rămâne valabil
 * la N instanțe: starea crește cu vreo două sute de octeți pe server, nu cu o
 * dependență.
 *
 * ## UN FIȘIER PER INSTANȚĂ, și de ce nu unul singur
 *
 * Prima variantă ținea toate instanțele într-un document, citit și rescris
 * întreg la fiecare semnal. Cu un singur expeditor, două scrieri simultane erau
 * o anomalie. Cu mai multe instanțe, sunt REGULA: N servere trimit pe intervale
 * independente, iar fereastra dintre citire și redenumire e de câteva
 * milisecunde. La cinci instanțe se nimerește cam zilnic, și continuu în ziua
 * în care toate au fost repornite de aceeași rulare de deploy — atunci fazele
 * lor sunt aliniate.
 *
 * Măsurat: din 25 de runde de câte trei semnale simultane, în 25 lipsea o
 * instanță din `/status`, iar 13 cereri semnate corect s-au întors cu 5xx.
 * Două mecanisme diferite: expeditorul care citea înaintea redenumirii celuilalt
 * scria înapoi un document fără instanța lui, ștergând-o; și amândoi foloseau
 * același nume de fișier temporar, deci cel care pierdea cursa redenumea un
 * fișier care nu mai exista.
 *
 * Nu s-a îngustat fereastra, s-a scos documentul comun: fiecare instanță are
 * fișierul ei, `<bază>.<id>.<ext>`, deci două instanțe nu ating aceiași octeți
 * și nu există citire-modificare-scriere ÎNTRE instanțe. Un blocaj în proces
 * n-ar fi fost de-ajuns — nu știm dacă găzduirea rulează mai mult de un proces
 * Node, iar un blocaj care presupune asta e o presupunere netestată exact acolo
 * unde contează.
 *
 * Ce RĂMÂNE o cursă, scris ca să nu fie descoperit ca surpriză: două scrieri
 * simultane pentru ACEEAȘI instanță. Ultima câștigă, iar cealaltă se pierde.
 * Nu mai poate strica altă instanță și nu mai poate arunca; numele fișierului
 * temporar e unic per scriere tocmai ca pierderea să rămână o pierdere, nu o
 * excepție.
 *
 * O versiune anterioară a comentariului ăstuia spunea că singura cauză sunt
 * „două expeditoare pe o singură identitate", adică o anomalie deja tratată cu
 * 409 în `beat/route.ts`. **E fals, și e important că e fals:** `/check` e un al
 * doilea scriitor pentru FIECARE instanță, pe cronul obișnuit al operatorului,
 * în funcționare perfect normală. Măsurat pe 40 de runde întrepătrunse în două
 * procese: semnale pierdute de scrierea lui `/check` — 0 din 40, fiindcă
 * `updateInstance` recitește; `alerted` murdar — 3 din 40, fiindcă scrierea
 * semnalului poate învia un `alerted` tocmai șters.
 *
 * Consecința reală e mărginită la `alerted`: un mesaj de revenire întârziat cu
 * o rundă de cron, sau o realertare înghițită în fereastra de patru ore care
 * există oricum. Niciodată `last`, deci niciodată o tăcere neobservată.
 *
 * ## Ce e o instanță — și de ce a trebuit reproiectat de două ori
 *
 * Întrebarea „cine există?" are două surse, și niciuna nu e suficientă singură:
 *
 * **Directorul** răspunde „cine a trimis vreodată", dar nu putea deosebi un
 * fișier scris de noi de unul care doar seamănă. O copie de siguranță pusă
 * lângă starea reală — exact ce face un om înainte de o publicare, în chiar
 * directorul recomandat de watcher/INCARCARE-HOSTINGER.md — devenea un server tăcut,
 * cu alertă critică repetată la nesfârșit despre o mașină care nu există.
 *
 * **Cheile configurate** răspund „cine are voie să se autentifice", ceea ce e o
 * întrebare DIFERITĂ. O intrare poate fi prezentă fără să fi trimis vreodată
 * ceva (și atunci ținea `/status` roșu pe veci), iar una poate lipsi în timp ce
 * serverul e foarte viu: o cheie ștearsă, sau o virgulă greșită într-un JSON
 * editat într-un formular web, ștergea de pe toate suprafețele niște servere
 * monitorizate și lăsa martorul să raporteze „ok". Aia e chiar pana pe care
 * mecanismul ăsta există ca să o prevină, produsă de mecanism.
 *
 * **Deci fișierele se identifică singure.** Fiecare fișier de stare poartă
 * `instance_id` înăuntru, scris de `writeInstance` (nu de apelant, ca să nu se
 * poată uita). Un fișier `<stem>.<id><ext>` e AL NOSTRU doar dacă identitatea
 * dinăuntru e chiar `<id>`. Membru e:
 *
 *   - orice fișier care se identifică pe sine — **inclusiv al unei instanțe
 *     căreia i s-a șters cheia**; aia tace și alarmează, nu dispare;
 *   - orice identificator configurat — chiar fără fișier; aia e „configurată,
 *     aștept primul semnal", stare vizibilă dar NECONTABILIZATĂ în verdictul
 *     agregat (vezi `status/route.ts`), ca să nu țină plasa de siguranță roșie
 *     la nesfârșit;
 *   - **nu** o copie: ea poartă identitatea ORIGINALULUI, care nu se potrivește
 *     cu numele ei nou;
 *   - **nu** o identitate RETRASĂ (`SENTINEL_RETIRED_INSTANCES`, vezi
 *     `lib/beat-keys.ts`). Retragerea trebuie să taie AMBELE surse: scoasă doar
 *     din chei, identitatea ar reintra imediat prin fișierul ei, care se
 *     identifică singur — cu semnalul lui vechi, deci `silent`, deci exact
 *     alarma de retras. Fișierul rămas pe disc se clasifică drept fișier
 *     străin: nu e al niciunei instanțe, fiindcă identitatea nu mai e una. NU
 *     ajunge `unreadable` nici dacă e stricat — aia e roșu, iar un fișier
 *     abandonat dinadins nu e o problemă a martorului.
 *
 * Migrarea: un fișier fără `instance_id` (scris înainte de schimbarea asta) e
 * al nostru doar dacă identificatorul din nume e configurat. Copia unui fișier
 * vechi are un nume care nu e configurat, deci nu intră pe ușa asta; iar prima
 * scriere îi pune identitatea și îl scoate din regimul de tranziție.
 *
 * ## Limita: `no-beat` nu are margine de timp, și se poate ajunge în el ÎNAPOI
 *
 * O instanță în `no-beat` nu alarmează niciodată, oricât ar sta acolo. Nu e
 * doar cazul „n-a trimis nimic vreodată": martorul poate UITA. Starea trăiește
 * în fișiere, iar dacă directorul lor dispare, o instanță care era `silent` —
 * deci alarma — recade în `no-beat`, care nu se numără. Măsurat:
 *
 *   înainte   /status 503 silent   [mort=silent, viu=ok]   telegram=1
 *   după      /status 503 no-beat  [mort=no-beat, viu=no-beat]  telegram=0
 *   după ce doar `viu` mai bate     /status 200 ok  [mort=no-beat, viu=ok]
 *
 * Adică tăcere în formă de sănătate, pentru un server mort.
 *
 * Cum se ajunge acolo, în ordinea probabilității: o PUBLICARE a martorului,
 * dacă `SENTINEL_STATE_PATH` nu e setat sau arată în directorul aplicației —
 * watcher/INCARCARE-HOSTINGER.md spune limpede că directorul ăla se rescrie la fiecare
 * publicare; ștergerea unui fișier de stare; o găzduire mutată. Nu e un colț
 * exotic, e actul obișnuit de a publica.
 *
 * De-aia `stateIsVolatile()` există și de-aia rezultatul lui apare în `/status`
 * și pe pagină, nu doar în jurnal. NU există un cronometru care să transforme
 * „`no-beat` de prea mult timp" în alarmă: ar avea nevoie de un reper de timp
 * păstrat exact în starea care tocmai s-a pierdut.
 *
 * ## Alte limite cunoscute
 *
 * Un fișier al cărui `instance_id` NU e șir (null, număr, tablou, obiect) cade
 * pe ramura de migrare și e adoptat dacă numele lui e un identificator
 * configurat. Ca să se întâmple, cineva trebuie și să strice câmpul, și să
 * redenumească fișierul peste un identificator configurat — două acte
 * deliberate, nu un accident.
 *
 * ## Migrarea stării existente
 *
 * Martorul din producție are un fișier în forma veche — un singur obiect, fără
 * nivel de instanțe — chiar la calea de bază. E citit ca instanța `default`, nu
 * aruncat. Dacă l-am ignora, `counters_moved_at` ar reporni de la zero și prima
 * alarmă reală de conductă moartă ar întârzia cu 15 minute după publicare; iar
 * `alerted` pierdut ar retrimite o alertă deja trimisă. Ambele arată ca un
 * martor care funcționează.
 *
 * Fișierul de bază rămâne pe disc și e doar o REZERVĂ: din clipa în care
 * instanța are fișier propriu, acela e adevărul. Nu se șterge — o ștergere e
 * ireversibilă, umbrirea nu.
 */

import { promises as fs } from "fs";
import { randomUUID } from "crypto";
import path from "path";

import {
  DEFAULT_INSTANCE, configuredInstanceIds, isValidInstanceId, own, retiredInstanceIds,
} from "./beat-keys";

export type Beat = {
  seq: number;
  sent_at: string;
  received_at: string;
  last_event_id: number;
  detect_cursor: number;
  incidents_open: number;
  blocklist_size: number;
  audit_head: string;
  interval_s: number;
  /** Nume cosmetic trimis de instanță. Niciodată cheie, niciodată de încredere. */
  label?: string;
  selfcheck: { worst: string; checks: number; bad: number; ran_at: string | null };
};

/** Tot ce știm despre O instanță. Forma pe care o judecă `judge()`. */
export type InstanceState = {
  last?: Beat;
  /** Ultima alertă trimisă, ca să nu repetăm la fiecare verificare. */
  alerted?: { kind: string; at: string };
  /** Când au avansat ultima dată contoarele, nu când a sosit ultimul semnal. */
  counters_moved_at?: string;
};

export type State = {
  instances: Record<string, InstanceState>;
  /**
   * Instanțe al căror fișier există dar nu se poate citi.
   *
   * Câmpul ăsta există fiindcă „n-am putut să mă uit" și „e în regulă" sunt
   * stări diferite. Fără el, o stare coruptă ar fi arătat identic cu o instanță
   * care n-a trimis încă niciun semnal — adică verde.
   */
  unreadable: string[];
};

/**
 * Calea se citește la fiecare apel, nu o dată la încărcarea modulului.
 *
 * Diferența contează pe o găzduire unde variabila se corectează din panou: cu o
 * constantă calculată la import, procesul ar continua să scrie la calea veche
 * până la o repornire pe care nimeni nu și-o amintește că trebuie făcută.
 */
function baseFile(): string {
  return process.env.SENTINEL_STATE_PATH
    || path.join(process.cwd(), ".sentinel-watcher.json");
}

/** Bucățile din care se compun numele fișierelor per instanță. */
function layout(): { dir: string; name: string; stem: string; ext: string } {
  const base = baseFile();
  const name = path.basename(base);
  const rawExt = path.extname(name);
  return {
    dir: path.dirname(base),
    name,
    stem: rawExt ? name.slice(0, name.length - rawExt.length) : name,
    ext: rawExt || ".json",
  };
}

/**
 * Starea se scrie într-un director pe care o publicare îl șterge?
 *
 * Implicit, calea de bază e în directorul de lucru al aplicației, iar acela e
 * rescris la fiecare publicare (watcher/INCARCARE-HOSTINGER.md). Configurația SIGURĂ e
 * documentată, dar cea NESIGURĂ e cea implicită — și consecința ei nu e o
 * eroare, e uitare: instanțele care alarmau recad în `no-beat` și tac.
 *
 * ## De ce se semnalează, în loc să se repare singur
 *
 * **Nu mutăm implicit starea în altă parte** (de exemplu în directorul home):
 * ar fi o ghicire despre o găzduire pe care nu o cunoaștem, iar dacă nimerește
 * greșit mută starea existentă fără ca cineva să ceară asta — adică produce
 * chiar pierderea pe care vrea să o prevină.
 *
 * **Nu refuzăm să pornim.** Ar opri și înregistrarea semnalelor, deci martorul
 * ar pierde tot, nu doar la publicare.
 *
 * Deci: primim semnalele ca de obicei, dar REFUZĂM să părem sănătoși. `/status`
 * răspunde `state-volatile` cu 503 și pagina poartă un avertisment. E o
 * defecțiune de configurare, reparabilă cu o singură variabilă, deci un semnal
 * care nu se oprește până la reparare e potrivit — spre deosebire de o alarmă
 * pentru ceva ce operatorul nu poate repara.
 *
 * Doar în jurnal nu era de-ajuns: jurnalul de pe găzduire e exact locul în care
 * s-a mai ascuns o dată un defect care ștergea servere de pe hartă.
 *
 * ## Două limite cunoscute, amândouă în direcția FALSULUI POZITIV
 *
 * **Legăturile simbolice nu se urmăresc.** `path.resolve` normalizează calea,
 * nu o rezolvă pe disc. Un director persistent legat simbolic în arborele
 * aplicației — tipar obișnuit pe găzduire partajată — se citește ca volatil,
 * deși e în siguranță. `fs.realpath` l-ar rezolva; nu se folosește fiindcă
 * verificarea asta rulează pe fiecare cerere către `/status` și nu are voie să
 * atingă discul de fiecare dată.
 *
 * **Presupunerea despre directorul de lucru.** Comparația e față de
 * `process.cwd()`, adică presupune că directorul de lucru al procesului E
 * directorul rescris la publicare. Dacă managerul de procese pornește
 * aplicația DIN directorul home — chiar cel recomandat pentru stare —
 * configurația corectă se raportează volatilă.
 *
 * Ambele greșesc în aceeași direcție, și asta e alegerea: un fals pozitiv dă
 * un 503 explicit, care numește variabila de schimbat și se repară dintr-o
 * singură setare; un fals negativ ar da înapoi gaura, tăcut. Prima probă de
 * acceptanță după publicare stabilește care e cazul —
 * watcher/INCARCARE-HOSTINGER.md spune ce se face dacă verificarea se înșală.
 */
export function stateIsVolatile(): boolean {
  const dir = path.resolve(layout().dir);
  const appDir = path.resolve(process.cwd());
  // `path.relative`, nu `dir.startsWith(appDir)`.
  //
  // Comparația pe șiruri spune că `/x/app-2026-08-12` e înăuntrul lui `/x/app`
  // — un director VECIN care începe cu același nume, adică fix cum arată o
  // copie datată sau un director de lansare lângă aplicație. Rezultatul ar fi
  // 503 `state-volatile` pentru totdeauna pe o configurație bună, adică o
  // alarmă pe care nimeni nu o poate opri. `path.relative` compară segmente.
  //
  // Forma `dir.startsWith(appDir + path.sep)` e ECHIVALENTĂ pe un sistem de
  // fișiere sensibil la majuscule — deci pe Linux, unde rulează martorul — și
  // niciun test nu o poate deosebi acolo. Se păstrează `path.relative` fiindcă
  // pe Windows, unde rulează suita, comparația de căi e insensibilă la
  // majuscule, iar forma cu prefix ar rata `C:\App` vs `C:\app\...`, adică ar
  // greși în direcția periculoasă: volatil raportat drept sigur.
  const rel = path.relative(appDir, dir);
  // Șir gol = chiar directorul aplicației. Orice cale care nu iese din el
  // (`..`) și nu e absolută (alt volum) e înăuntru.
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/** `<bază>.<id>.<ext>`. Identificatorul e validat, deci nu poate ieși din director. */
export function instanceFile(id: string): string {
  const { dir, stem, ext } = layout();
  return path.join(dir, `${stem}.${id}${ext}`);
}

async function readJson(file: string): Promise<unknown | undefined> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Înregistrarea unei instanțe, cu „nu există" ȘI „există și nu se poate citi"
 * ca răspunsuri DIFERITE.
 *
 * Fără distincția asta, `readInstance` și `readAll` ajungeau la concluzii opuse
 * despre același fișier stricat: una cădea pe înregistrarea moștenită din
 * fișierul de bază și o dădea drept curentă, cealaltă o marca ilizibilă. Două
 * căi de citire care nu sunt de acord despre aceiași octeți sunt un bug care
 * așteaptă un apelant.
 */
type Record_ = {
  present: boolean;
  state?: InstanceState;
  /** Identitatea scrisă ÎN fișier. `undefined` = fișier dinaintea schimbării. */
  embedded?: string;
};

/** Cheia sub care fiecare fișier de stare își scrie propria identitate. */
const ID_FIELD = "instance_id";

async function readRecord(file: string): Promise<Record_> {
  let text: string;
  try {
    text = await fs.readFile(file, "utf8");
  } catch (err) {
    // Doar „nu există" înseamnă absent. Un director cu numele ăsta, sau drepturi
    // lipsă, înseamnă prezent-și-necitibil — altfel ar trece drept „încă niciun
    // semnal", care e o stare mult mai liniștitoare decât adevărul.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return { present: false };
    return { present: true };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { present: true };
  }
  const state = asInstanceState(parsed);
  if (!state) return { present: true };
  const raw = parsed as Record<string, unknown>;
  const embedded = typeof raw[ID_FIELD] === "string" ? (raw[ID_FIELD] as string) : undefined;
  // Identitatea e metadată de fișier, nu stare de instanță: apelanții primesc
  // starea curată, iar `writeInstance` o pune la loc de fiecare dată.
  const clean = { ...state } as Record<string, unknown>;
  delete clean[ID_FIELD];
  return { present: true, state: clean as InstanceState, embedded };
}

/**
 * Fișierul de la `<stem>.<id><ext>` e al instanței `id`?
 *
 * Regula care deosebește o copie de un original: copia poartă identitatea
 * originalului, iar aia nu se potrivește cu numele ei nou. Un fișier fără
 * identitate scrisă e dinaintea schimbării și se acceptă doar dacă numele lui e
 * un identificator configurat — copia unui fișier vechi are alt nume, deci nu
 * intră nici pe acolo.
 *
 * O identitate RETRASĂ nu are fișier al ei, oricât de bine s-ar identifica
 * acela. Regula stă aici, nu în apelanți, fiindcă întrebarea „al cui e fișierul
 * ăsta?" are un singur răspuns pentru toată magazia: dacă instanța nu mai
 * există, fișierul nu e al nimănui.
 */
function fileBelongsTo(
  id: string,
  embedded: string | undefined,
  configured: Set<string>,
  retired: Set<string>,
): boolean {
  if (retired.has(id)) return false;
  if (embedded !== undefined) return embedded === id;
  return configured.has(id);
}

function isObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

/**
 * Verificarea de formă la intrare, nu la folosire.
 *
 * Un `last` care nu e un semnal — fișier editat de mână, disc corupt, publicare
 * pe jumătate — făcea `judge()` să arunce, deci `/status` și `/check` răspundeau
 * 500 la fiecare cerere. Un martor care nu mai poate răspunde nu mai poate nici
 * să spună de ce. Aici, o înregistrare care nu are forma corectă e respinsă și
 * instanța e raportată drept ILIZIBILĂ, ceea ce e adevărat și e vizibil.
 */
function asInstanceState(v: unknown): InstanceState | undefined {
  if (!isObject(v)) return undefined;
  if (v.last !== undefined) {
    const b = v.last;
    if (!isObject(b)) return undefined;
    if (typeof b.received_at !== "string" || typeof b.sent_at !== "string") return undefined;
    if (typeof b.audit_head !== "string") return undefined;
    for (const n of ["seq", "last_event_id", "detect_cursor", "incidents_open",
      "blocklist_size", "interval_s"]) {
      if (typeof b[n] !== "number" || !Number.isFinite(b[n] as number)) return undefined;
    }
    if (!isObject(b.selfcheck) || typeof b.selfcheck.worst !== "string") return undefined;
    if (b.label !== undefined && typeof b.label !== "string") return undefined;
  }
  if (v.alerted !== undefined) {
    if (!isObject(v.alerted)) return undefined;
    if (typeof v.alerted.kind !== "string" || typeof v.alerted.at !== "string") return undefined;
  }
  if (v.counters_moved_at !== undefined && typeof v.counters_moved_at !== "string") {
    return undefined;
  }
  return v as InstanceState;
}

/**
 * Ce se poate scoate din fișierul de bază, oricare i-ar fi forma.
 *
 * Întoarce de fiecare dată un obiect NOU. O versiune anterioară întorcea o
 * constantă de modul pentru cazul gol, deci „nu știu" era un obiect comun pe
 * tot procesul: cine îl modifica din greșeală îl modifica pentru toți apelanții
 * de după.
 */
function adoptBase(parsed: unknown): Record<string, InstanceState> {
  const out: Record<string, InstanceState> = {};
  if (!isObject(parsed)) return out;

  /**
   * Identitatea se curăță și pe calea asta, nu doar în `readRecord`.
   *
   * Migrarea trece pe AICI, iar de aici starea ajunge în `updateInstance`, care
   * o scrie înapoi. Un `instance_id` rămas în ea devenea astfel identitatea
   * fișierului rescris — adică fix drumul prin care un fișier ajungea să
   * pretindă că e al altcuiva.
   */
  const clean = (v: unknown): InstanceState | undefined => {
    const st = asInstanceState(v);
    if (!st) return undefined;
    const copy = { ...st } as Record<string, unknown>;
    delete copy[ID_FIELD];
    return copy as InstanceState;
  };

  const nested = parsed.instances;
  if (isObject(nested)) {
    for (const [id, value] of Object.entries(nested)) {
      const st = clean(value);
      // `isValidInstanceId` de aici nu mai are efect OBSERVABIL de când
      // enumerarea vine din registru: singurele chei căutate vreodată în
      // rezultat sunt identificatori configurați, iar aceia sunt deja validați
      // la parsarea hărții. Se păstrează fiindcă funcția asta citește un fișier
      // pe care nu l-a scris neapărat ea, și fiindcă un `out["__proto__"] = …`
      // nu e genul de linie pe care vrei să o descoperi mai târziu. Scris aici
      // ca să nu caute nimeni testul care o acoperă: nu poate exista.
      if (isValidInstanceId(id) && st) out[id] = st;
    }
    return out;
  }

  // Forma veche: un singur obiect, fără nivel de instanțe. Devine `default` —
  // aceeași instanță pe care o presupune un expeditor care nu se declară.
  if ("last" in parsed || "alerted" in parsed || "counters_moved_at" in parsed) {
    const st = clean(parsed);
    if (st) out[DEFAULT_INSTANCE] = st;
  }
  return out;
}

async function baseInstances(): Promise<Record<string, InstanceState>> {
  return adoptBase(await readJson(baseFile()));
}

/**
 * Identificatorii pentru care există un fișier care ARATĂ ca al nostru.
 *
 * NU e lista instanțelor — aia vine din chei. Se folosește doar ca să putem
 * spune în jurnal că am găsit fișiere pe care le ignorăm.
 */
async function scanDirIds(): Promise<string[]> {
  const { dir, name, stem, ext } = layout();
  let files: string[];
  try {
    files = await fs.readdir(dir);
  } catch {
    return [];
  }
  const ids: string[] = [];
  for (const f of files) {
    if (f === name || !f.startsWith(`${stem}.`) || !f.endsWith(ext)) continue;
    const id = f.slice(stem.length + 1, f.length - ext.length);
    if (isValidInstanceId(id)) ids.push(id);
  }
  return ids.sort();
}

/**
 * Ultima listă de fișiere străine raportată.
 *
 * Memoria asta există ca să nu scriem o linie de jurnal la fiecare cerere:
 * `/status` e interogat de un monitor de uptime la fiecare minut, iar un
 * avertisment repetat de 1440 de ori pe zi e zgomot, adică fix felul în care un
 * avertisment util devine invizibil.
 */
let lastForeignReported: string | null = null;

async function reportForeignFiles(foreign: string[]): Promise<void> {
  const key = foreign.slice().sort().join(",");
  if (key === lastForeignReported) return;
  lastForeignReported = key;
  if (foreign.length) {
    // Numărul, nu numele: numele unui fișier străin e ales de cine l-a pus
    // acolo, iar jurnalul martorului nu e locul în care să ajungă text ales de
    // altcineva. Regula asta are test — altfel un refactor o pierde gratis.
    console.error("[watcher] fișiere de stare ignorate, nu sunt ale niciunei instanțe",
      foreign.length);
  }
}

/**
 * Starea unei singure instanțe.
 *
 * `undefined` înseamnă „nu am o înregistrare bună" — fie nu există fișier, fie
 * există și nu se poate citi. Pentru ruta de semnal cele două sunt echivalente:
 * în ambele cazuri nu are cu ce compara secvența, iar semnalul următor scrie
 * oricum un fișier bun.
 */
export async function readInstance(id: string): Promise<InstanceState | undefined> {
  if (!isValidInstanceId(id)) return undefined;
  // O identitate retrasă nu are stare a ei. `fileBelongsTo` acoperă fișierul
  // propriu; verificarea de aici închide și cealaltă cale — rezerva din fișierul
  // de bază, pe care `readAll` nu o atinge decât pentru identificatori din
  // registru, dar pe care funcția asta o citește pentru orice identificator.
  if (retiredInstanceIds().has(id)) return undefined;
  const rec = await readRecord(instanceFile(id));
  if (rec.present) {
    // Fișierul propriu e autoritativ CHIAR ȘI când e stricat: dacă există și nu
    // se poate citi, nu ne întoarcem la înregistrarea veche din fișierul de
    // bază. Vechiul prezentat ca actual e chiar minciuna. `readAll` face la fel.
    if (!rec.state) return undefined;
    // Iar dacă fișierul spune că e al altcuiva, nu e al nostru: altfel secvența
    // unei copii ar decide dacă semnalul instanței ăsteia e o reluare.
    if (!fileBelongsTo(id, rec.embedded, new Set(configuredInstanceIds()), retiredInstanceIds())) {
      return undefined;
    }
    return rec.state;
  }
  // Fără fișier propriu: poate e o instanță migrată din fișierul de bază.
  return own(await baseInstances(), id);
}

/**
 * Coduri pentru care redenumirea se mai încearcă o dată.
 *
 * Pe Linux — unde rulează martorul — `rename(2)` peste un fișier existent e
 * atomic și nu eșuează fiindcă altcineva redenumește în același timp. Pe
 * Windows, `MoveFileEx` cu înlocuire poate întoarce EPERM/EACCES exact în cazul
 * ăla, iar suita de teste rulează pe Windows: două scrieri simultane pentru
 * aceeași instanță o produceau de fiecare dată.
 *
 * S-a reparat, nu s-a slăbit testul: eroarea aia ar fi ajuns la expeditor ca
 * 500 pe un semnal semnat corect, adică exact ce trebuia să dispară odată cu
 * numele temporar comun. Reîncercarea nu ascunde nimic — dacă tot nu reușește,
 * apelantul primește eroarea.
 */
const RENAME_RETRY_CODES = new Set(["EPERM", "EACCES", "EBUSY"]);
const RENAME_ATTEMPTS = 5;

/**
 * Identitățile RETRASE care au rămas cu o alarmă deschisă.
 *
 * Există pentru un singur lucru, iar `/check` e singurul care o cheamă:
 * retragerea scoate identitatea din enumerare, deci bucla nu mai ajunge
 * niciodată la ea — iar dacă avea steagul `alerted` pus, alarma aia nu se mai
 * închide NICIODATĂ. Operatorul rămâne cu un mesaj roșu pe Telegram și cu
 * tăcere după el.
 *
 * S-a întâmplat exact așa pe 19 august 2026: `default` a fost retrasă cât timp
 * era în alertă, iar operatorul a întrebat de ce n-a primit mesajul de
 * închidere. Comentariul de pe ramura de revenire din `/check` spunea deja
 * principiul — „o alertă care nu se închide niciodată lasă operatorul să se
 * întrebe dacă s-a rezolvat" — dar calea retragerii îl ocolea.
 *
 * ## De ce nu se lărgește în schimb `readAll`
 *
 * Fiindcă retragerea trebuie să rămână ce spune că e: identitatea nu mai e
 * membră, nu intră în verdict, nu produce alerte. O identitate retrasă care
 * reapare în enumerare ca să poată fi închisă ar fi chiar retragerea desfăcută.
 * Funcția asta nu întoarce stare de sănătate și nu poate fi folosită ca să se
 * judece ceva: întoarce numai identitatea și alarma rămasă în urmă.
 */
export async function retiredWithOpenAlert(): Promise<
  { id: string; alerted: { kind: string; at: string } }[]
> {
  const out: { id: string; alerted: { kind: string; at: string } }[] = [];
  // Sortat, din același motiv ca bucla din `/check`: două rulări identice n-au
  // voie să arate diferit.
  for (const id of [...retiredInstanceIds()].sort()) {
    const rec = await readRecord(instanceFile(id));
    // Fișierul propriu e autoritativ chiar și când e stricat, ca peste tot în
    // modulul ăsta. Stricat = nu știm dacă era o alarmă acolo, iar a inventa
    // una ar trimite un mesaj de închidere pentru ceva ce n-a fost deschis.
    const state = rec.present
      ? rec.state
      : own(await baseInstances(), id);
    const alerted = state?.alerted;
    if (alerted) out.push({ id, alerted });
  }
  return out;
}

export async function writeInstance(id: string, state: InstanceState): Promise<void> {
  if (!isValidInstanceId(id)) throw new Error("identificator de instanță invalid");
  const file = instanceFile(id);
  // Scriere atomică: o întrerupere la mijloc ar lăsa un JSON trunchiat, iar
  // martorul ar porni de la zero exact când e mai puțin potrivit.
  //
  // Numele temporar e UNIC per scriere. Cu un nume comun, două scrieri
  // simultane pentru aceeași instanță se termină cu o redenumire peste un
  // fișier deja mutat — ENOENT, adică o eroare la o operație perfect corectă.
  const tmp = `${file}.${process.pid}.${randomUUID()}.tmp`;
  // Identitatea se scrie AICI, nu de apelant: e singurul loc prin care trece
  // fiecare scriere, deci singurul în care nu se poate uita. Un fișier fără ea
  // ar fi indistinct de o copie, iar o copie e o alarmă falsă permanentă.
  //
  // Ordinea contează și a fost greșită: cu identitatea PRIMA, o stare care
  // poartă din greșeală `instance_id` o suprascria, iar comentariul ăsta
  // descria exact opusul a ce făcea codul. Fișierul ajungea cu identitatea
  // altcuiva, se clasifica străin la citirea următoare, instanța cădea la
  // `no-beat`, iar `no-beat` nu se numără — deci un server tăcut de o oră
  // ieșea 200 „ok". Identitatea se pune ULTIMA: aici nu se negociază.
  const onDisk = { ...state, [ID_FIELD]: id };
  try {
    await fs.writeFile(tmp, JSON.stringify(onDisk, null, 2), "utf8");
    for (let attempt = 1; ; attempt++) {
      try {
        await fs.rename(tmp, file);
        break;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code ?? "";
        if (attempt >= RENAME_ATTEMPTS || !RENAME_RETRY_CODES.has(code)) throw err;
        await new Promise((resolve) => setTimeout(resolve, attempt * 5));
      }
    }
  } catch (err) {
    // Un temporar rămas în urmă nu se citește niciodată (nu se termină în
    // `<ext>`), dar s-ar aduna la nesfârșit pe o eroare care se repetă.
    await fs.rm(tmp, { force: true }).catch(() => undefined);
    throw err;
  }
}

/**
 * Citește, modifică și scrie O instanță, recitind imediat înainte de scriere.
 *
 * Ruta de verificare schimbă doar `alerted`, dar între citirea ei și scriere
 * poate sosi un semnal care schimbă `last`. Recitirea aici nu elimină cursa —
 * fără blocaj între procese nu se poate — dar o strânge de la „cât durează o
 * verificare, inclusiv apelul către Telegram" la câteva microsecunde.
 *
 * Întoarce `false` și NU scrie nimic dacă fișierul a devenit între timp
 * necitibil. Altfel, apelantul ar fi construit modificarea peste un `{}` și ar
 * fi instalat o înregistrare fără niciun semnal — adică o instanță care arată
 * proaspăt instalată la nesfârșit, pentru o mașină care poate fi moartă. E
 * fereastra dintre `readAll()` din `/check` și recitirea de aici.
 */
export async function updateInstance(
  id: string,
  change: (previous: InstanceState) => InstanceState,
): Promise<boolean> {
  const rec = await readRecord(instanceFile(id));
  if (rec.present && !rec.state) {
    console.error("[watcher] nu suprascriu o stare devenită necitibilă");
    return false;
  }
  const previous = rec.present
    ? (rec.state as InstanceState)
    : (own(await baseInstances(), id) ?? {});
  await writeInstance(id, change(previous));
  return true;
}

export async function readAll(): Promise<State> {
  const configured = new Set(configuredInstanceIds());
  // Retrasele se citesc o singură dată pentru toată enumerarea: altfel fiecare
  // fișier ar reparsa variabila, iar o valoare stricată ar scrie o linie de
  // jurnal per fișier găsit.
  const retired = retiredInstanceIds();
  const base = await baseInstances();
  const instances: Record<string, InstanceState> = {};
  const unreadable: string[] = [];
  const foreign: string[] = [];

  // Sursa 1: fișierele care se identifică pe ele însele. Aici stau instanțele
  // vii cărora li s-a șters cheia — cele care, într-o versiune anterioară,
  // dispăreau de pe toate suprafețele în loc să tacă și să alarmeze.
  for (const id of await scanDirIds()) {
    const rec = await readRecord(instanceFile(id));
    if (!rec.present) continue;
    if (!rec.state) {
      // Nu putem citi identitatea, deci nu putem ști dacă e al nostru. E al
      // nostru doar dacă numele lui e configurat — altfel o copie stricată ar
      // deveni o instanță „ilizibilă", adică o problemă inventată.
      //
      // O identitate retrasă nu e în `configured` (a fost scoasă din registru la
      // sursă), deci fișierul ei stricat cade aici pe ramura de fișier străin.
      // Dinadins: `unreadable` e roșu, iar un fișier abandonat de operator nu e
      // o defecțiune a martorului.
      if (configured.has(id)) {
        unreadable.push(id);
        console.error("[watcher] stare ilizibilă pentru o instanță");
      } else {
        foreign.push(id);
      }
      continue;
    }
    if (!fileBelongsTo(id, rec.embedded, configured, retired)) {
      // Un fișier care nu e al instanței de la calea lui. Dacă instanța aia e
      // CONFIGURATĂ, e o problemă a ei, nu un fișier oarecare: cineva a pus
      // altceva exact la calea ei. Raportat `unreadable`, care e roșu — altfel
      // ar cădea pe „configurată, fără fișier", adică `no-beat`, care nu se
      // numără, și un server tăcut ar ieși verde. Se repară singur la primul
      // semnal, care rescrie fișierul cu identitatea corectă.
      //
      // Sub un nume NEconfigurat rămâne ce era: o copie, ignorată în tăcere.
      // Tot pe acolo iese și fișierul unei identități retrase — `fileBelongsTo`
      // spune că nu mai e al nimănui, iar numele lui nu mai e în registru.
      if (configured.has(id)) {
        unreadable.push(id);
        console.error("[watcher] fișierul unei instanțe poartă altă identitate");
      } else {
        foreign.push(id);
      }
      continue;
    }
    instances[id] = rec.state;
  }

  // Sursa 2: identificatorii configurați. Cei fără fișier sunt „configurat,
  // aștept primul semnal" — o stare reală, vizibilă, dar necontabilizată în
  // verdictul agregat.
  for (const id of configured) {
    // `own`, nu `id in instances`: pe un obiect obișnuit `"constructor" in obj`
    // e adevărat fără ca nimeni să fi scris acolo, iar `ID_PATTERN` acceptă
    // `constructor`, `toString`, `valueOf`. Cu `in`, o instanță configurată cu
    // un astfel de nume și fără fișier propriu ar fi sărită aici — deci ar lipsi
    // din `/status` și de pe pagină până la prima ei bătaie, exact când
    // operatorul verifică dacă cheia pusă în panou a ajuns.
    if (own(instances, id) !== undefined || unreadable.includes(id)) continue;
    instances[id] = own(base, id) ?? {};
  }

  await reportForeignFiles(foreign);
  return { instances, unreadable };
}
