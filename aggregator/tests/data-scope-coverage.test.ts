/**
 * Fiecare funcție de acces la date e CONDUSĂ de un cont cu două instanțe și două
 * roluri diferite — și cine adaugă una nouă fără o astfel de probă face suita
 * roșie PRIN LIPSĂ.
 *
 * ## De ce există fișierul ăsta, și de ce nu e încă un test
 *
 * Regula — „orice probă de autorizare care poate fi făcută cu un cont cu două
 * instanțe se face așa" — era scrisă în proză, în capul lui
 * `tests/panel-authz.test.ts`, și aplicată în două puncte. De TREI ori clasa
 * asta de defecte a fost găsită de altcineva, cu o mutație, la o funcție
 * distanță de locul în care tocmai se scrisese regula:
 *
 *     visibleInstances: rows.map(…)          → rows.slice(0, 1).map(…)   486 verzi
 *     visibleInstances: roles.get(id)        → [...roles.values()][0]    486 verzi
 *     visibleInstances: " ORDER BY …"        → ""                        486 verzi
 *
 * Cauza e mereu aceeași: **cu o singură instanță în cont, „caută rolul după id"
 * și „ia primul rol" sunt aceeași funcție**, iar „toate rândurile" și „primul
 * rând" sunt același rezultat. O regulă scrisă în proză nu se aplică singură.
 *
 * Ce se strică pentru operator, la fiecare dintre ele: panoul unui cont cu N
 * servere arată UN server, fără nicio eroare și fără nimic în jurnal — lista
 * pare completă fiindcă nu există cu ce s-o compare; sau rolul afișat pe serverul
 * B e rolul de pe A, iar `lib/auth/scope.ts` scrie că rolul pe instanță e ce va
 * decide acțiunile de scriere în E3c, deci greșeala se livrează înaintea
 * consumatorului ei.
 *
 * ## Cum se aplică singură
 *
 * Lista funcțiilor de păzit NU e scrisă de mână: se citește din module, iar
 * lista MODULELOR se compară cu ce e pe disc în `lib/data/`. Deci o funcție nouă
 * într-un fișier existent și un fișier nou în director înroșesc amândouă primul
 * test de mai jos, prin absența probei — nu prin recunoașterea vreunui tipar.
 *
 * Fiecare probă e apoi condusă de o singură mașinărie, care cere trei lucruri
 * prin EFECT, nu prin declarație:
 *
 *   1. **domeniul cu două instanțe chiar a ajuns la bază** — se caută în
 *      instrucțiunile plecate una care poartă amândoi identificatorii ca
 *      parametri. O probă care ar chema funcția cu alt domeniu decât cel primit
 *      pică aici;
 *   2. **restricția e fidelă** — rândurile întoarse pentru un cont care vede A
 *      ȘI B sunt exact reuniunea celor întoarse pentru un cont care vede numai A
 *      cu cele pentru un cont care vede numai B. Asta e aserțiunea care prinde
 *      și tăierea listei, și rolul luat de pe alt rând: cele două conturi cu o
 *      singură instanță sunt martorul pe care un cont cu una singură nu-l are;
 *   3. **nu e vidă** — apelul cu două instanțe trebuie să întoarcă măcar un rând.
 *      O probă care nu întoarce nimic ar face aserțiunea de mai sus adevărată
 *      degeaba, adică exact o listă parametrizată ieșită goală.
 *
 * Rolurile de pe cele două instanțe sunt DIFERITE, dinadins: cu roluri identice,
 * „ia primul rol" rămâne invizibilă.
 *
 * ## Ce NU face garda asta
 *
 * Nu înlocuiește probele prin rute din `tests/panel-authz.test.ts` și nu
 * pretinde să acopere tot ce poate greși o funcție de acces la date — reuniunea
 * de mai sus e insensibilă la ORDINE, de pildă, iar ordonarea se probează în
 * `also` la fiecare funcție care declară una. Ce garantează e un PLANȘEU: nicio
 * funcție de acolo nu mai poate fi livrată fără să fi fost condusă măcar o dată
 * de un cont care vede două servere.
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import * as arrivalsModule from "../lib/data/arrivals";
import * as blocklistModule from "../lib/data/blocklist";
import * as findingsModule from "../lib/data/findings";
import * as patchPlansModule from "../lib/data/patch-plans";
import * as selfcheckModule from "../lib/data/selfcheck";
import * as detectionsModule from "../lib/data/detections";
import * as incidentsModule from "../lib/data/incidents";
import * as instancesModule from "../lib/data/instances";
import { grantInstance } from "../lib/auth/accounts";
import { scopeForUser } from "../lib/auth/scope";
import { incidentById, incidentTimeline, listIncidents } from "../lib/data/incidents";
import { visibleInstances } from "../lib/data/instances";
import { arrivalsFor } from "../lib/data/arrivals";
import { listDetections } from "../lib/data/detections";
import { listBlocks } from "../lib/data/blocklist";
import { countByGroup, listFindings } from "../lib/data/findings";
import { listPlans } from "../lib/data/patch-plans";
import { listChecks } from "../lib/data/selfcheck";
import * as loginsModule from "../lib/data/logins";
import { listSessions, sessionDetail } from "../lib/data/logins";
import * as overviewModule from "../lib/data/overview";
import { summary } from "../lib/data/overview";
import * as rollupsModule from "../lib/data/rollups";
import * as scansModule from "../lib/data/scans";
import { scanHealth } from "../lib/data/scans";
import { listHours } from "../lib/data/rollups";
import {
  captureError, captureWarn, forgetAuthServer, useAuthServer,
} from "./auth-routes-harness";
import { shippedFiles } from "./shipped-files";
import type { Fixture } from "./auth-routes-harness";
import type { FakeAuthDb } from "./auth-harness";
import type { AuthDb } from "../lib/auth/db";
import type { InstanceScope } from "../lib/auth/scope";
import type { VisibleInstance } from "../lib/data/instances";

/**
 * Modulele de acces la date, cu numele lor de fișier.
 *
 * Că lista e ÎNTREAGĂ nu se crede pe cuvânt: primul test o compară cu ce e pe
 * disc în `lib/data/`. Importurile sunt statice fiindcă un `import()` dinamic
 * s-ar transforma în `require` sub `tsx` și ar depinde de forma căii — iar ce
 * trebuie derivat din cod e lista FUNCȚIILOR, care se citește din modulul chiar
 * încărcat, nu din textul lui.
 */
const DATA_MODULES: Record<string, Record<string, unknown>> = {
  "lib/data/arrivals.ts": arrivalsModule as unknown as Record<string, unknown>,
  "lib/data/blocklist.ts": blocklistModule as unknown as Record<string, unknown>,
  "lib/data/findings.ts": findingsModule as unknown as Record<string, unknown>,
  "lib/data/patch-plans.ts": patchPlansModule as unknown as Record<string, unknown>,
  "lib/data/selfcheck.ts": selfcheckModule as unknown as Record<string, unknown>,
  "lib/data/detections.ts": detectionsModule as unknown as Record<string, unknown>,
  "lib/data/incidents.ts": incidentsModule as unknown as Record<string, unknown>,
  "lib/data/instances.ts": instancesModule as unknown as Record<string, unknown>,
  "lib/data/logins.ts": loginsModule as unknown as Record<string, unknown>,
  "lib/data/overview.ts": overviewModule as unknown as Record<string, unknown>,
  "lib/data/rollups.ts": rollupsModule as unknown as Record<string, unknown>,
  "lib/data/scans.ts": scansModule as unknown as Record<string, unknown>,
};

const INSTANCE_A = "prod-a";
const INSTANCE_B = "prod-b";
/** Roluri DIFERITE. Cu două roluri egale, „rolul lui B" și „primul rol din
 *  hartă" sunt aceeași valoare, iar mutația care le confundă rămâne verde. */
const ROLE_A = "owner";
const ROLE_B = "viewer";

/** Contul care vede AMÂNDOUĂ instanțele, și cele două care văd câte una. Cele
 *  două din urmă sunt martorul: fără ele, „a întors tot" n-are cu ce fi comparat. */
const USER_BOTH = 1;
const USER_ONLY_A = 2;
const USER_ONLY_B = 3;

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();

  // Înregistrate în ordinea INVERSĂ celei sortate, dinadins. Cu `prod-a` primul,
  // ordinea de inserare și `ORDER BY instance_id` coincid, deci ordonarea se
  // poate șterge din interogare fără ca nimic să se vadă — iar pe MariaDB o
  // interogare fără `ORDER BY` nu promite nicio ordine, deci lista de servere a
  // panoului s-ar rearanja de la o cerere la alta.
  fixture.db.addInstance(INSTANCE_B, { label: "Serverul B" });
  fixture.db.addInstance(INSTANCE_A, { label: "Serverul A" });

  fixture.db.addUser(USER_ONLY_A, { username: "doar-a" });
  fixture.db.addUser(USER_ONLY_B, { username: "doar-b" });

  for (const [username, instanceId, role] of [
    ["operator", INSTANCE_A, ROLE_A], ["operator", INSTANCE_B, ROLE_B],
    ["doar-a", INSTANCE_A, ROLE_A], ["doar-b", INSTANCE_B, ROLE_B],
  ] as const) {
    const granted = await grantInstance(fixture.db, username, instanceId, role);
    assert.equal(granted.ok, true,
                 `pregătirea a eșuat: ${granted.ok ? "" : granted.detail}`);
  }
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

// ---------------------------------------------------------------------------
// Probele
// ---------------------------------------------------------------------------
type Rows = Record<string, unknown>[];

type ScopeProbe = {
  /** Ce trebuie să existe în bază ca apelul să întoarcă rânduri. Ce întoarce
   *  ajunge la `call` — id-urile semănate nu se pot ghici. */
  seed(db: FakeAuthDb): unknown;
  /** Apelul. Domeniul primit e singurul care are voie să plece mai departe. */
  call(db: AuthDb, scope: InstanceScope, seeded: unknown): Promise<unknown>;
  /** Rândurile din ce s-a întors. Lipsa unui rând e o listă goală. */
  rows(result: unknown): Rows;
  /** Ce mai are de spus proba în afară de restricție — ordonare, cartografieri. */
  also?(result: unknown): void;
};

const PROBES: Record<string, ScopeProbe> = {
  "lib/data/instances.ts::visibleInstances": {
    seed: () => null,
    call: (db, scope) => visibleInstances(db, scope),
    rows: (result) => result as unknown as Rows,
    also(result) {
      const rows = result as VisibleInstance[];
      // Ordonarea, prin EFECT: instanțele sunt înregistrate invers față de cum
      // se sortează, deci un `ORDER BY` scos se vede aici și nu în reuniune,
      // care e insensibilă la ordine.
      assert.deepEqual(rows.map((row) => row.instanceId), [INSTANCE_A, INSTANCE_B],
                       "instanțele nu vin ordonate după `instance_id`; pe MariaDB " +
                       "asta înseamnă o listă de servere care se rearanjează de la " +
                       "o cerere la alta");
      // Și rolul e al FIECĂREI instanțe, nu al primeia. Reuniunea prinde deja
      // confuzia; aserțiunea asta îi spune numele.
      assert.equal(rows.find((row) => row.instanceId === INSTANCE_A)?.role, ROLE_A);
      assert.equal(rows.find((row) => row.instanceId === INSTANCE_B)?.role, ROLE_B,
                   "rolul de pe a doua instanță e cel de pe prima: `roles.get(id)` " +
                   "a devenit „primul rol din hartă”");
    },
  },

  "lib/data/findings.ts::countByGroup": {
    seed(db) {
      // Numaratorile sunt tot date: o suma care include serverul celuilalt
      // spune „ai 40 de vulnerabilitati" cand ai 12, iar cifra aia ajunge pe
      // filtrele paginii, unde nimeni n-o pune la indoiala.
      db.addFinding(INSTANCE_A, { source_id: 11, status: "open" });
      db.addFinding(INSTANCE_B, { source_id: 22, status: "open" });
      db.addFinding(INSTANCE_B, { source_id: 23, status: "resolved" });
      return null;
    },
    call: async (db, scope) => {
      const counts = await countByGroup(db, scope, INSTANCE_A);
      // Aplatizat cu instanta pusa la loc, ca recensamantul sa poata judeca
      // randul: un total care contine randurile lui B ar trece altfel neobservat,
      // fiindca o cifra n-are instanta scrisa pe ea.
      //
      // ZERO inseamna NICIUN RAND, nu un rand cu zero: recensamantul cere ca ce
      // vede un cont cu drept pe amandoua sa fie REUNIUNEA a ce vad doua conturi
      // cu cate unul. Un rand de zerouri pentru contul care nu vede A ar strica
      // reuniunea — ar aparea un rand pe care celalalt nu-l are. Absenta lui e
      // chiar afirmatia corecta: contul ala n-are ce numara aici.
      if (counts.total === 0) return [];
      return [{ instance_id: INSTANCE_A, total: counts.total,
                neaplicate: counts.neaplicate, rezolvate: counts.rezolvate }];
    },
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/findings.ts::listFindings": {
    seed(db) {
      // Aceeasi constatare, ca forma, pe amandoua serverele. Filtrul cazut ar
      // arata operatorului lui A ce pachete invechite are B - adica o harta a
      // suprafetei de atac a altcuiva.
      db.addFinding(INSTANCE_A, { source_id: 11, cve: "CVE-A" });
      db.addFinding(INSTANCE_B, { source_id: 22, cve: "CVE-B" });
      return null;
    },
    call: (db, scope) => listFindings(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/blocklist.ts::listBlocks": {
    seed(db) {
      db.addBlock(INSTANCE_A, { source_id: 11, ip: "203.0.113.10" });
      db.addBlock(INSTANCE_B, { source_id: 22, ip: "198.51.100.20" });
      return null;
    },
    call: (db, scope) => listBlocks(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/patch-plans.ts::listPlans": {
    seed(db) {
      db.addPlan(INSTANCE_A, { source_id: 11 });
      db.addPlan(INSTANCE_B, { source_id: 22 });
      return null;
    },
    call: (db, scope) => listPlans(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/scans.ts::scanHealth": {
    seed(db) {
      // Aceeasi ora pe amandoua serverele. Filtrul cazut nu s-ar vedea ca un
      // rand in plus — ar arata VARSTA masuratorii altui server ca fiind a ta,
      // adica exact intrebarea la care pagina exista sa raspunda.
      db.addScan(INSTANCE_A, { source_id: 1, target: "al-lui-A" });
      db.addScan(INSTANCE_B, { source_id: 2, target: "al-lui-B" });
      return null;
    },
    call: (db, scope) => scanHealth(db, scope, INSTANCE_A),
    rows: (result) => {
      const h = result as unknown as { lastGood: unknown; latest: unknown };
      return [h.lastGood, h.latest].filter(Boolean) as unknown as Rows;
    },
  },

  "lib/data/logins.ts::listSessions": {
    seed(db) {
      // Aceeași cheie de sesiune pe amândouă serverele — `ses` se renumerotează
      // de la zero la fiecare pornire, deci `432` există pe oricâte gazde.
      // Filtrul căzut n-ar arăta un rând în plus: ar arăta cine s-a logat pe
      // SERVERUL ALTUIA, sub numele serverului tău.
      db.addLoginSession(INSTANCE_A, { session_key: "432", username: "al-lui-A" });
      db.addLoginSession(INSTANCE_B, { session_key: "432", username: "al-lui-B" });
      return null;
    },
    call: (db, scope) => listSessions(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
    also: (result) => {
      const s = result as unknown as { username: string | null }[];
      assert.deepEqual(s.map((x) => x.username), ["al-lui-A"],
                       "sesiunea celuilalt server apare în lista ta");
    },
  },

  "lib/data/logins.ts::sessionDetail": {
    seed(db) {
      // `source_id` e id-ul de pe INSTANȚĂ, deci se repetă între gazde: ambele
      // au o sesiune 1 și o comandă 1. Fără filtru, ai citi comenzile rulate pe
      // serverul celuilalt — adică exact conținutul cel mai sensibil din toată
      // replica.
      db.addLoginSession(INSTANCE_A, { source_id: 1, username: "al-lui-A" });
      db.addLoginSession(INSTANCE_B, { source_id: 1, username: "al-lui-B" });
      db.addSessionCommand(INSTANCE_A, { source_id: 1, session_source_id: 1,
                                         argv: "comanda-lui-A" });
      db.addSessionCommand(INSTANCE_B, { source_id: 1, session_source_id: 1,
                                         argv: "comanda-lui-B" });
      return null;
    },
    call: (db, scope) => sessionDetail(db, scope, INSTANCE_A, 1),
    // Comenzile SUNT rândurile: sunt singura listă, iar reuniunea peste două
    // conturi cu drept pe câte un server trebuie să dea exact ce vede unul cu
    // drept pe amândouă.
    rows: (result) => (result as { commands: Rows }).commands,
    also: (result) => {
      const d = result as unknown as {
        session: { username: string | null } | null;
        commands: { argv: string }[];
        truncated: boolean;
      };
      assert.equal(d.session?.username, "al-lui-A",
                   "s-a citit sesiunea celuilalt server");
      assert.deepEqual(d.commands.map((c) => c.argv), ["comanda-lui-A"],
                       "comenzile celuilalt server apar în cronologia ta");
      assert.equal(d.truncated, false,
                   "o listă de o comandă a raportat că a fost tăiată");
    },
  },

  "lib/data/overview.ts::summary": {
    seed(db) {
      // Aceleași forme pe amândouă serverele, cu numere care nu se pot confunda.
      // Filtrul căzut nu s-ar vedea ca un rând în plus — s-ar vedea ca un
      // CONTOR mai mare pe cartonașul de sus, adică atacurile altui server
      // adunate peste ale tale, fără nimic care să spună.
      //
      // Regulile și adresele se REPETĂ între mașini: fiecare are un
      // `auth.ssh_bruteforce`, un `nginx`. Deci se dau nume distincte, altfel un
      // clasament amestecat ar arăta exact ca unul corect, cu numere mai mari.
      db.addIncident(INSTANCE_A, { severity: "critical", status: "open" });
      db.addIncident(INSTANCE_B, { severity: "low", status: "open" });
      db.addDetection(INSTANCE_A, { src_ip: "203.0.113.1", rule_id: "a.regula" });
      db.addDetection(INSTANCE_B, { src_ip: "198.51.100.1", rule_id: "b.regula" });
      db.addRollupHour(INSTANCE_A, { source: "al-lui-A", n: "10" });
      db.addRollupHour(INSTANCE_B, { source: "al-lui-B", n: "999" });
      db.addFinding(INSTANCE_A, { status: "open" });
      db.addFinding(INSTANCE_B, { status: "open" });
      db.addBlock(INSTANCE_A, { ip: "203.0.113.1", active: 1 });
      db.addBlock(INSTANCE_B, { ip: "198.51.100.1", active: 1 });
      return null;
    },
    call: (db, scope) => summary(db, scope, INSTANCE_A),
    // Rândurile comparate ca mulțime sunt CRONOLOGIA: singura listă în care
    // intră și detecțiile, și blocările, deci singura în care se vede dacă un
    // rând al celuilalt server s-a strecurat pe undeva. Restul — contoare,
    // serii, clasamente — se verifică în `also`, cu valori numite: mașinăria de
    // mai jos compară mulțimi, iar un contor nu e o mulțime.
    rows: (result) => (result as { activity: Rows }).activity,
    also: (result) => {
      const s = result as unknown as {
        overview: {
          incidentsOpen: number; incidentsSevere: number; blocksActive: number;
          findingsOpen: number; events: { now: number }; attackers: { now: number };
          bySeverity: { severity: string }[];
        };
        series: { bySource: Record<string, number> }[];
        rankings: { attackers: { key: string }[]; rules: { key: string }[];
                    sources: { key: string }[] };
        truncated: string[];
      };
      const o = s.overview;
      assert.equal(o.incidentsOpen, 1,
                   "incidentul deschis al celuilalt server e numărat aici");
      assert.equal(o.incidentsSevere, 1, "`critical` nu e numărat ca grav");
      assert.deepEqual(o.bySeverity.map((x) => x.severity), ["critical"],
                       "severitatea celuilalt server apare în defalcare");
      assert.equal(o.blocksActive, 1, "blocarea celuilalt server e numărată aici");
      assert.equal(o.findingsOpen, 1, "constatarea celuilalt server e numărată aici");
      assert.equal(o.events.now, 10,
                   "evenimentele s-au adunat peste ale celuilalt server (999 " +
                   "sunt ale lui B) — sau s-au CONCATENAT ca șiruri");
      assert.equal(o.attackers.now, 1,
                   "adresa celuilalt server e numărată ca atacator al tău");
      assert.deepEqual(
        s.series.flatMap((h) => Object.keys(h.bySource)), ["al-lui-A"],
        "sursa celuilalt server a intrat în stiva orei tale");
      assert.deepEqual(s.rankings.attackers.map((x) => x.key), ["203.0.113.1"],
                       "clasamentul de atacatori amestecă cele două servere");
      assert.deepEqual(s.rankings.rules.map((x) => x.key), ["a.regula"],
                       "clasamentul de reguli amestecă cele două servere");
      assert.deepEqual(s.rankings.sources.map((x) => x.key), ["al-lui-A"],
                       "clasamentul de surse amestecă cele două servere");
      assert.deepEqual(s.truncated, [],
                       "o citire de zece rânduri a raportat că a atins plafonul");
    },
  },

  "lib/data/rollups.ts::listHours": {
    seed(db) {
      // Aceeasi ORA pe amandoua serverele, cu numere diferite. Filtrul cazut nu
      // s-ar vedea ca un rand in plus — s-ar vedea ca un TOTAL mai mare, adica
      // traficul altui server adunat peste al tau, fara nimic care sa spuna.
      db.addRollupHour(INSTANCE_A, { source: "al-lui-A", n: "10" });
      db.addRollupHour(INSTANCE_B, { source: "al-lui-B", n: "999" });
      return null;
    },
    call: (db, scope) => listHours(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/selfcheck.ts::listChecks": {
    seed(db) {
      // Aceeasi cheie pe amandoua serverele: `check_key` se repeta intre
      // masini — fiecare are un `web`, un `db`. Filtrul cazut ar arata starea
      // serverului celuilalt sub numele tau.
      db.addCheck(INSTANCE_A, { check_key: "web", title: "al lui A" });
      db.addCheck(INSTANCE_B, { check_key: "web", title: "al lui B" });
      return null;
    },
    call: (db, scope) => listChecks(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/detections.ts::listDetections": {
    seed(db) {
      // Aceeași detecție, ca formă, pe amândouă serverele. Dacă filtrul de
      // instanță ar cădea, contul lui A ar vedea regula lui B — iar `rule_id`
      // spune ce anume caută cineva pe serverul celuilalt.
      db.addDetection(INSTANCE_A, { source_id: 11, rule_id: "a.regula" });
      db.addDetection(INSTANCE_B, { source_id: 22, rule_id: "b.regula" });
      return null;
    },
    call: (db, scope) => listDetections(db, scope, INSTANCE_A),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/arrivals.ts::arrivalsFor": {
    seed(db) {
      db.addArrival(INSTANCE_A, "incidents", 3);
      db.addArrival(INSTANCE_B, "blocklist", 5);
      return null;
    },
    call: async (db, scope) => {
      const map = await arrivalsFor(db, scope, INSTANCE_A);
      // Harta se aplatizează cu `instanceId` pus la loc: recensământul verifică
      // rânduri, iar un rând fără instanță n-ar putea fi judecat. Fluxul lui B
      // ajuns aici ar însemna că filtrul a căzut.
      return [...map.values()].map((a) => ({ ...a, instance_id: INSTANCE_A }));
    },
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/incidents.ts::listIncidents": {
    seed(db) {
      db.addIncident(INSTANCE_A, { source_id: 11, title: "al lui A" });
      db.addIncident(INSTANCE_B, { source_id: 22, title: "al lui B" });
      return null;
    },
    call: (db, scope) => listIncidents(db, scope),
    rows: (result) => result as unknown as Rows,
  },

  "lib/data/incidents.ts::incidentById": {
    seed(db) {
      // Același `source_id` pe amândouă instanțele: id-ul de pe SERVER se repetă
      // între servere, iar rândul din agregator e altul.
      const mine = db.addIncident(INSTANCE_A, { source_id: 11, title: "al meu" });
      db.addIncident(INSTANCE_B, { source_id: 11, title: "al lui B" });
      return { id: mine.id };
    },
    call: (db, scope, seeded) =>
      incidentById(db, scope, (seeded as { id: number }).id),
    rows: (result) => (result === null ? [] : [result as Record<string, unknown>]),
  },

  "lib/data/incidents.ts::incidentTimeline": {
    seed(db) {
      db.addIncident(INSTANCE_A, { source_id: 11 });
      db.incidentTimelineEntries.push({
        id: 1, instance_id: INSTANCE_A, source_id: 1, incident_source_id: 11,
        at: db.nowMs, kind: "detection", actor: null,
      });
      // Aceeași cronologie, cu ACELAȘI `incident_source_id`, pe celălalt server.
      db.incidentTimelineEntries.push({
        id: 2, instance_id: INSTANCE_B, source_id: 1, incident_source_id: 11,
        at: db.nowMs, kind: "action", actor: "al lui B",
      });
      return null;
    },
    call: (db, scope) =>
      incidentTimeline(db, scope, { instanceId: INSTANCE_A, sourceId: 11 }),
    rows: (result) => (result as { entries: Rows }).entries,
  },
};

// ---------------------------------------------------------------------------
// Recensământul: lista de păzit se citește din cod, nu din capul cuiva
// ---------------------------------------------------------------------------
/** `fișier::funcție` pentru fiecare funcție exportată din `lib/data/`. */
function exportedDataFunctions(): string[] {
  const found: string[] = [];
  for (const [file, module] of Object.entries(DATA_MODULES)) {
    for (const [name, value] of Object.entries(module)) {
      if (typeof value === "function") found.push(`${file}::${name}`);
    }
  }
  return found.sort();
}

test("fiecare funcție exportată din `lib/data/` are o probă cu DOUĂ instanțe", () => {
  // Eșecul pe care îl previne: o funcție nouă de acces la date, livrată fără să
  // fi fost vreodată condusă de un cont care vede mai mult de un server. Trei
  // defecte din clasa asta au trecut deja de suita întreagă, verzi, fiindcă
  // regula era scrisă în proză și aplicată de mână.
  const onDisk = shippedFiles().filter((file) => file.startsWith("lib/data/"));
  assert.ok(onDisk.length > 0,
            "niciun fișier în `lib/data/`: recensământul ar trece pe gol");
  assert.deepEqual(onDisk, Object.keys(DATA_MODULES).sort(),
                   "fișierele din `lib/data/` nu sunt exact modulele din " +
                   "DATA_MODULES; unul nou nu e păzit de nimic de aici");

  assert.deepEqual(exportedDataFunctions(), Object.keys(PROBES).sort(),
                   "o funcție exportată din `lib/data/` nu are probă cu două " +
                   "instanțe (sau o probă numește o funcție care nu mai există). " +
                   "Cu un cont cu o singură instanță, „toate rândurile” și " +
                   "„primul rând” sunt același rezultat — vezi capul fișierului");
});

// ---------------------------------------------------------------------------
// Mașinăria comună: aceleași trei cerințe pentru fiecare probă
// ---------------------------------------------------------------------------
async function scopeOf(userId: number): Promise<InstanceScope> {
  return await scopeForUser(fixture.db, userId);
}

/** Rânduri comparabile ca MULȚIME, cu valorile lor cu tot. */
function asSet(rows: Rows): string[] {
  return rows.map((row) => JSON.stringify(row)).sort();
}

for (const [key, probe] of Object.entries(PROBES)) {
  test(`${key} — condusă de un cont cu două instanțe și două roluri`, async () => {
    const seeded = probe.seed(fixture.db);

    const both = await scopeOf(USER_BOTH);
    assert.equal(both.allowedInstanceIds.length, 2,
                 "domeniul de probă n-are două instanțe, deci nu deosebește nimic");
    assert.equal(new Set(both.roles.values()).size, 2,
                 "cele două instanțe au același rol, deci „rolul lui B” și „primul " +
                 "rol din hartă” sunt aceeași valoare");

    fixture.db.statements.length = 0;
    const resultBoth = await probe.call(fixture.db, both, seeded);

    // 1. Domeniul cu două instanțe chiar a ajuns la bază — prin efect, nu pentru
    //    că așa scrie proba.
    const carried = fixture.db.statements.find(
      (stmt) => stmt.params.includes(INSTANCE_A) && stmt.params.includes(INSTANCE_B));
    assert.ok(carried,
              `${key}: nicio interogare n-a plecat cu amândoi identificatorii ca ` +
              "parametri, deci funcția n-a fost condusă cu domeniul primit");

    // 3. Și nu e vidă: o probă care nu întoarce nimic face aserțiunea următoare
    //    adevărată degeaba.
    const rowsBoth = probe.rows(resultBoth);
    assert.ok(rowsBoth.length > 0,
              `${key}: apelul cu două instanțe n-a întors niciun rând, deci ` +
              "comparația de mai jos ar fi „gol = gol”");

    // 2. Restricția e fidelă: A∪B = A + B, cu valorile fiecărui rând cu tot.
    const rowsA = probe.rows(await probe.call(fixture.db, await scopeOf(USER_ONLY_A),
                                              seeded));
    const rowsB = probe.rows(await probe.call(fixture.db, await scopeOf(USER_ONLY_B),
                                              seeded));
    assert.deepEqual(asSet(rowsBoth), asSet([...rowsA, ...rowsB]),
                     `${key}: ce vede un cont cu drept pe amândouă serverele nu e ` +
                     "reuniunea a ce văd două conturi cu drept pe câte unul. Fie " +
                     "lipsesc rânduri (o listă tăiată care arată completă), fie un " +
                     "câmp e luat de pe rândul altui server");

    probe.also?.(resultBoth);
  });
}
