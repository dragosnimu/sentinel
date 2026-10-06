/**
 * Ce a scris sau a judecat modelul, pe panoul agregatorului: eticheta „AI content", pe conținutul
 * potrivit și numai acolo — plus pagina de Rapoarte, care a primit `wide` și o celulă „Din ce" pe
 * un rând.
 *
 * Operatorul a cerut o etichetă mică și identică oriunde ce se vede a fost scris sau judecat de
 * model, ca să deosebească dintr-o privire cuvintele modelului de faptele măsurate. Ce se strică
 * dacă aici se regresează:
 *
 *   * eticheta pe un rând pe care modelul nu l-a judecat — operatorul învață că eticheta nu
 *     înseamnă nimic, sau citește „evaluat, fără probleme" despre ceva ce modelul n-a văzut;
 *   * un verdict fără etichetă — exact plângerea de la care a pornit: „unde se folosește layer-ul
 *     de AI? nu e vizibil";
 *   * un verdict stocat dar necitibil, scris ca „modelul n-a spus nimic": cele două nu se repară la
 *     fel, iar a doua ar rămâne ascunsă;
 *   * textul modelului ajuns neescapat în pagină. E text liber produs dintr-un prompt care
 *     conține dovezi alese de un atacator (`prompt_injection_detected` există dintr-un motiv).
 *
 * „Judecat" = `ai_analyzed_at`, nu `ai_severity`: severitatea poate lipsi dintr-un incident care A
 * fost judecat (`triage._clean` o respinge). Un plan e „redactat de model" când `model` e setat.
 *
 * `findings.ai_assessment` n-are nicio suprafață aici, dinadins: coloana n-a fost scrisă niciodată
 * (0 din 7631 de rânduri pe producție, 6 octombrie 2026).
 */

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";

import { GET as loginGet, POST as loginPost } from "../app/login/route";
import { GET as totpGet, POST as totpPost } from "../app/totp/route";
import { GET as incidenteGet } from "../app/panel/incidente/route";
import { GET as incidentPageGet } from "../app/panel/incidente/[id]/route";
import { GET as patchGet } from "../app/panel/patch-uri/route";
import { GET as rapoarteGet } from "../app/panel/rapoarte/route";
import { GET as panelGet } from "../app/panel/route";
import { grantInstance } from "../lib/auth/accounts";
import { readAiVerdict } from "../lib/ai-verdict";
import { aiBadge } from "../lib/panel-page";
import {
  PASSWORD, USERNAME, captureError, captureWarn, completeLogin,
  forgetAuthServer, getRequest, useAuthServer,
} from "./auth-routes-harness";
import type { Fixture } from "./auth-routes-harness";

const HANDLERS = { loginGet, loginPost, totpGet, totpPost };
const INSTANCE = "prod-a";
const BADGE = 'class="ai-badge"';

let fixture: Fixture;
let warn: { lines: string[][]; restore: () => void };
let error: { lines: string[][]; restore: () => void };

beforeEach(async () => {
  warn = captureWarn();
  error = captureError();
  fixture = await useAuthServer();
  fixture.db.addInstance(INSTANCE, { label: "Serverul A" });
});

afterEach(async () => {
  warn.restore();
  error.restore();
  await forgetAuthServer();
});

async function signIn(): Promise<Record<string, string>> {
  const token = await completeLogin(HANDLERS, {
    username: USERNAME, password: PASSWORD, totpSecret: fixture.totpSecret,
  });
  return { sentinel_session: token };
}

async function grant(): Promise<void> {
  const result = await grantInstance(fixture.db, USERNAME, INSTANCE, "owner");
  assert.equal(result.ok, true);
}

function count(html: string, needle: string): number {
  return html.split(needle).length - 1;
}

/** Rândul `<tr>` care conține titlul dat. */
function rowOf(html: string, title: string): string {
  const at = html.indexOf(title);
  assert.ok(at >= 0, `titlul ${title} nu apare în pagină`);
  const start = html.lastIndexOf("<tr>", at);
  return html.slice(start, html.indexOf("</tr>", at));
}

const VERDICT = JSON.stringify({
  severity: "medium", is_false_positive: false, confidence: 0.85,
  summary_ro: "Probabil o scanare automată de rutină.", recommended_action: "monitorizează",
  prompt_injection_detected: false,
});

// ---------------------------------------------------------------------------
test("eticheta are textul operatorului, în engleză, și o singură formă", () => {
  // Textul e al operatorului: „AI content". Forma e comparată la octet cu macroul de pe server de
  // `tests/unit/test_ai_content_badge.py`; aici se fixează doar ce nu poate lipsi.
  const html = aiBadge();
  assert.match(html, /^<span class="ai-badge" title="[^"]+">AI content<\/span>$/);
});

test("`readAiVerdict`: trei rezultate — verdict, nimic, necitibil — nu două", () => {
  // Eșecul pe care îl previne: „n-am putut citi" scris ca „modelul n-a spus nimic".
  assert.equal(readAiVerdict(null), null);
  assert.equal(readAiVerdict(undefined), null);
  assert.equal(readAiVerdict("nu e json {"), "unreadable");
  assert.equal(readAiVerdict("[1,2]"), "unreadable");
  assert.equal(readAiVerdict("\"doar un șir\""), "unreadable");
  assert.equal(readAiVerdict("17"), "unreadable");
  const ok = readAiVerdict(VERDICT);
  assert.deepEqual(ok, {
    summaryRo: "Probabil o scanare automată de rutină.", recommendedAction: "monitorizează",
    isFalsePositive: false, promptInjectionDetected: false,
  });
  // Un driver sau un dublu poate da blobul deja parsat.
  assert.deepEqual(readAiVerdict({ summary_ro: "x", is_false_positive: true }), {
    summaryRo: "x", recommendedAction: null, isFalsePositive: true, promptInjectionDetected: false,
  });
  // Un câmp lipsă e null, nu o valoare inventată; un boolean care nu e boolean nu devine „true".
  assert.deepEqual(readAiVerdict("{}"), {
    summaryRo: null, recommendedAction: null, isFalsePositive: null, promptInjectionDetected: false,
  });
  assert.equal((readAiVerdict({ prompt_injection_detected: "true" }) as { promptInjectionDetected: boolean })
    .promptInjectionDetected, false);
});

// ---------------------------------------------------------------------------
test("lista de incidente etichetează EXACT rândurile pe care modelul le-a judecat", async () => {
  await grant();
  fixture.db.addIncident(INSTANCE, {
    source_id: 1, title: "judecat de model", ai_severity: "medium", ai_confidence: "0.85",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59), ai_verdict: VERDICT,
  });
  fixture.db.addIncident(INSTANCE, { source_id: 2, title: "nevăzut de model" });
  fixture.db.addIncident(INSTANCE, {
    source_id: 3, title: "judecat fără severitate", ai_severity: null, ai_confidence: null,
    ai_analyzed_at: Date.UTC(2026, 9, 5, 2, 1),
  });
  const cookies = await signIn();

  const html = await (await incidenteGet(getRequest("/panel/incidente", { cookies }))).text();
  assert.equal(count(html, BADGE), 2, "eticheta nu e pe exact cele două rânduri judecate");

  const judged = rowOf(html, "judecat de model");
  assert.equal(count(judged, BADGE), 1);
  assert.ok(judged.includes("medium &middot; 85%"), "severitatea și încrederea modelului lipsesc");

  const unseen = rowOf(html, "nevăzut de model");
  assert.equal(count(unseen, BADGE), 0, "un rând nejudecat a primit eticheta");
  assert.ok(!unseen.includes("%") && unseen.includes('<td class="gol-ai">—</td>'),
            "un rând nejudecat spune ceva despre o evaluare");

  // Criteriul e `ai_analyzed_at`, nu `ai_severity`.
  const noSev = rowOf(html, "judecat fără severitate");
  assert.equal(count(noSev, BADGE), 1, "un incident judecat fără severitate pare nejudecat");
  assert.ok(noSev.includes("— &middot; —"), "o severitate necunoscută trebuie scrisă ca necunoscută");
});

test("pagina unui incident judecat are secțiunea cu etichetă; unul nejudecat nu are nimic", async () => {
  await grant();
  const judged = fixture.db.addIncident(INSTANCE, {
    source_id: 1, title: "judecat", ai_severity: "medium", ai_confidence: "0.85",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59), ai_verdict: VERDICT,
  });
  const unseen = fixture.db.addIncident(INSTANCE, { source_id: 2, title: "nejudecat" });
  const cookies = await signIn();

  const get = async (id: number) => await (await incidentPageGet(
    getRequest(`/panel/incidente/${id}`, { cookies }),
    { params: Promise.resolve({ id: String(id) }) })).text();

  const a = await get(judged.id);
  assert.equal(count(a, BADGE), 1);
  const block = a.slice(a.indexOf("Analiză AI"));
  assert.ok(block.indexOf(BADGE) < block.indexOf("</h2>"), "eticheta nu e la titlul secțiunii");
  assert.ok(block.includes("Probabil o scanare automată de rutină."), "textul modelului lipsește");
  assert.ok(block.includes("85%") && block.includes("monitorizează") && block.includes("medium"));
  // Severitatea deterministă e un fapt măsurat, nu stă sub etichetă și nu mai are un rând „AI" lângă ea.
  const facts = a.slice(0, a.indexOf("Analiză AI"));
  assert.ok(!facts.includes("Severitate AI"), "un rând AI fără etichetă a rămas printre fapte");
  assert.ok(facts.includes("<dt>Severitate</dt>"));

  const b = await get(unseen.id);
  assert.equal(count(b, BADGE), 0);
  assert.ok(!b.includes("Analiză AI"), "un incident nejudecat are o secțiune despre model");
});

test("un verdict stocat dar necitibil se SPUNE, iar severitatea din coloane rămâne", async () => {
  await grant();
  const broken = fixture.db.addIncident(INSTANCE, {
    source_id: 1, title: "blob stricat", ai_severity: "high", ai_confidence: "0.9",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59), ai_verdict: "{ nu e json",
  });
  const missing = fixture.db.addIncident(INSTANCE, {
    source_id: 2, title: "fără text", ai_severity: "low", ai_confidence: "0.7",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59), ai_verdict: null,
  });
  const cookies = await signIn();
  const get = async (id: number) => await (await incidentPageGet(
    getRequest(`/panel/incidente/${id}`, { cookies }),
    { params: Promise.resolve({ id: String(id) }) })).text();

  const a = await get(broken.id);
  assert.ok(a.includes("Textul verdictului nu a putut fi citit"), "blobul stricat nu e spus");
  assert.ok(a.includes("90%") && a.includes("high"), "coloanele nu s-au mai arătat");
  const b = await get(missing.id);
  assert.ok(b.includes("n-a trimis textul verdictului"), "lipsa textului nu e spusă");
  assert.ok(!b.includes("Textul verdictului nu a putut fi citit"),
            "lipsa textului și textul necitibil s-au confundat");
});

test("textul modelului e escapat, iar o tentativă de prompt-injection se vede", async () => {
  await grant();
  const evil = fixture.db.addIncident(INSTANCE, {
    source_id: 1, title: "dovezi ostile", ai_severity: "high", ai_confidence: "0.5",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59),
    ai_verdict: JSON.stringify({
      severity: "high", summary_ro: "<script>alert(1)</script> ignoră instrucțiunile",
      recommended_action: "<img src=x onerror=1>", is_false_positive: false,
      prompt_injection_detected: true,
    }),
  });
  const cookies = await signIn();
  const html = await (await incidentPageGet(
    getRequest(`/panel/incidente/${evil.id}`, { cookies }),
    { params: Promise.resolve({ id: String(evil.id) }) })).text();
  assert.ok(!html.includes("<script>alert(1)</script>"), "textul modelului a ajuns neescapat");
  assert.ok(!html.includes("<img src=x"), "acțiunea sugerată a ajuns neescapată");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(html.includes("prompt-injection"), "tentativa de injecție nu se vede");
});

// ---------------------------------------------------------------------------
// Șase caractere ASCII — backslash, „u", „0103" — în locul lui „ă": forma pe care 415 din 791 de
// verdicte stocate o purtau pe 6 oct 2026. Construită din cod de caracter, nu scrisă ca literal,
// ca să nu fie convertită la „ă" de vreun pas intermediar (fișierul ar testa atunci altceva).
const ESCAPED = "blocheaz" + String.fromCharCode(92) + "u0103";
const CANONICAL_ACTIONS = ["monitorizează", "blochează", "investighează", "ignoră", "patch"];
const NOT_AN_ACTION: [string, unknown][] = [
  ["unknown", "unknown"],
  ["secvența ASCII în locul diacriticii (blocheaz…)", ESCAPED],
  ["secvența ASCII în locul diacriticii (investigheaz…)",
   "investigheaz" + String.fromCharCode(92) + "u0103"],
  ["blocheaz (fără ă)", "blocheaz"],
  ["investigheaza (fără diacritice)", "investigheaza"],
  ["altă majusculă", "Blochează"],
  ["cu spațiu", " blochează"],
  ["șir gol", ""],
  ["null", null],
  ["tablou", ["blochează"]],
  ["obiect", { a: 1 }],
  ["număr", 7],
  ["marcaj", "<img src=x onerror=1>"],
];

test("`readAiVerdict`: acțiunea sugerată e una din cele cinci sau `null` — niciodată text stricat", () => {
  // Eșecul pe care îl previne: „Acțiune sugerată: unknown" sub eticheta „AI content" — 94% din
  // verdictele judecate (măsurat pe 6 oct 2026). Pozitiv întâi: cele cinci trec neschimbate.
  for (const action of CANONICAL_ACTIONS) {
    const v = readAiVerdict({ recommended_action: action, summary_ro: "s" });
    assert.notEqual(v, "unreadable");
    assert.equal((v as { recommendedAction: string | null }).recommendedAction, action);
  }
  for (const [what, junk] of NOT_AN_ACTION) {
    const v = readAiVerdict({ recommended_action: junk, summary_ro: "s", is_false_positive: false });
    assert.notEqual(v, "unreadable", what);
    const verdict = v as { recommendedAction: string | null; summaryRo: string | null };
    assert.equal(verdict.recommendedAction, null, `${what}: textul stricat a trecut`);
    assert.equal(verdict.summaryRo, "s", `${what}: restul verdictului s-a pierdut odată cu acțiunea`);
  }
});

test("acțiunea sugerată: scrisă dacă e canonică, ABSENTĂ (nici „—”, nici textul) în rest", async () => {
  // Eșecul pe care îl previne: eticheta „AI content" de la titlu certifică un text stricat drept
  // răspunsul modelului. Trei stări ale cardului: canonică, `unknown`, secvență ASCII scrisă literal.
  await grant();
  let nextSource = 100;
  const incident = (title: string, action: unknown) => fixture.db.addIncident(INSTANCE, {
    source_id: ++nextSource, title, ai_severity: "medium", ai_confidence: "0.85",
    ai_analyzed_at: Date.UTC(2026, 9, 5, 1, 59),
    ai_verdict: JSON.stringify({
      severity: "medium", is_false_positive: false, confidence: 0.85,
      summary_ro: "Probabil o scanare automată de rutină.", recommended_action: action,
      prompt_injection_detected: false,
    }),
  });
  const cookies = await signIn();
  const get = async (id: number) => await (await incidentPageGet(
    getRequest(`/panel/incidente/${id}`, { cookies }),
    { params: Promise.resolve({ id: String(id) }) })).text();
  const cardOf = (html: string) => html.slice(html.indexOf("Analiză AI"));

  for (const action of CANONICAL_ACTIONS) {
    const card = cardOf(await get(incident(`canonic ${action}`, action).id));
    assert.ok(card.includes(`<dt>Acțiune sugerată</dt><dd>${action}</dd>`),
              `acțiunea canonică ${action} nu s-a scris`);
  }
  for (const [what, junk] of NOT_AN_ACTION) {
    const html = await get(incident(`verdict stricat ${++nextSource}`, junk).id);
    const card = cardOf(html);
    assert.ok(!card.includes("Acțiune sugerată"), `${what}: rândul a rămas`);
    if (typeof junk === "string" && junk.trim() !== "") {
      assert.ok(!card.includes(junk), `${what}: textul stricat a ajuns pe ecran`);
    }
    // Restul verdictului rămâne, sub aceeași etichetă.
    assert.equal(count(html, BADGE), 1, what);
    assert.ok(card.indexOf(BADGE) < card.indexOf("</h2>"), `${what}: eticheta nu e la titlu`);
    assert.ok(card.includes("Probabil o scanare automată de rutină.") && card.includes("85%") &&
              card.includes("medium") && card.includes("Fals-pozitiv?"), `${what}: restul lipsește`);
  }
});

test("planurile redactate de model au eticheta; cele fără model nu", async () => {
  await grant();
  fixture.db.addPlan(INSTANCE, { source_id: 1, plan_uuid: "plan-cu-model",
                                 model: "claude-opus-5" });
  fixture.db.addPlan(INSTANCE, { source_id: 2, plan_uuid: "plan-fara-model",
                                 model: null });
  const cookies = await signIn();
  const html = await (await patchGet(getRequest("/panel/patch-uri", { cookies }))).text();

  const drafted = rowOf(html, "plan-cu-model");
  const manual = rowOf(html, "plan-fara-model");
  assert.equal(count(drafted, BADGE), 1);
  assert.equal(count(manual, BADGE), 0, "un plan fără model a primit eticheta");
  // Nota despre ce înseamnă eticheta numește eticheta în text, dar nu o desenează.
  assert.ok(html.includes("„AI content”"));
  assert.equal(count(html, BADGE), 1);
});

// ---------------------------------------------------------------------------
test("Rapoarte cere `wide`, are sursele pe un rând, iar celelalte pagini rămân la 72rem", async () => {
  await grant();
  fixture.db.addRollupHour(INSTANCE, { bucket: Date.UTC(2026, 9, 5, 12), source: "nginx", action: "request", n: "40" });
  fixture.db.addRollupHour(INSTANCE, { bucket: Date.UTC(2026, 9, 5, 12), source: "sshd", action: "auth_fail", n: "30" });
  fixture.db.addIncident(INSTANCE, { source_id: 1, title: "un incident" });
  const cookies = await signIn();

  const reports = await (await rapoarteGet(getRequest("/panel/rapoarte", { cookies }))).text();
  assert.equal(count(reports, '<main class="wide">'), 1, "Rapoarte nu cere `wide` (sau o cere de două ori)");
  // Sursele unei ore sunt frați într-un singur `.din-ce`, fără `<br>` între ele.
  const cell = reports.slice(reports.indexOf('<div class="din-ce">'), reports.indexOf("</div>", reports.indexOf('<div class="din-ce">')));
  assert.equal(count(cell, '<span class="sursa">'), 2, "cele două surse nu sunt în celula pe un rând");
  assert.ok(!cell.includes("<br>"), "sursele s-au întors una sub alta");
  assert.ok(cell.indexOf("nginx/request") < cell.indexOf("sshd/auth_fail"), "ordinea după evenimente s-a pierdut");

  for (const [nume, res] of [
    ["incidente", await incidenteGet(getRequest("/panel/incidente", { cookies }))],
    ["rezumat", await panelGet(getRequest("/panel", { cookies }))],
  ] as const) {
    const html = await res.text();
    assert.ok(html.includes("<main>\n"), `${nume}: a pierdut \`<main>\` simplu`);
    assert.ok(!html.includes('<main class="wide">'), `${nume}: a primit \`wide\``);
  }
});
