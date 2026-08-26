/**
 * Schela testelor martorului.
 *
 * ## De ce se importă ÎNAINTE de orice altceva
 *
 * `lib/store.ts` decide unde scrie starea citind `SENTINEL_STATE_PATH`. Fișierul
 * ăsta îl setează la o cale temporară proprie fiecărui proces de test, iar
 * modulele ES se evaluează în ordinea importurilor: `import "./witness-harness"` pus
 * primul înseamnă că variabila e setată înainte ca `store` să fie evaluat.
 *
 * Nu ne bazăm însă pe ordinea aia ca pe o garanție. `tests/store.test.ts`
 * verifică prin EFECT că scrierea ajunge în fișierul temporar — dacă vreodată
 * ordinea se rupe, testele scriu în directorul de lucru și aserțiunea aia pică,
 * în loc să treacă verde peste starea altcuiva.
 */

import { promises as fs } from "fs";
import { randomUUID } from "crypto";
import os from "os";
import path from "path";

/**
 * Director propriu per proces de test: `node --test` rulează fișierele în
 * paralel, iar starea nu mai e un singur fișier ci unul per instanță, lângă
 * calea de bază. Un director separat ține fiecare fișier de test în cutia lui.
 */
export const STATE_DIR = path.join(os.tmpdir(), `sentinel-watcher-test-${randomUUID()}`);
export const STATE_FILE = path.join(STATE_DIR, "state.json");
process.env.SENTINEL_STATE_PATH = STATE_FILE;

/**
 * Forma pe care o are corpul JSON al oricărei rute a martorului.
 *
 * `instances` e numit fiindcă fiecare rută îl întoarce și fiindcă e singurul
 * câmp pe care testele îl PARCURG; restul se citesc ca `unknown` și se compară,
 * ceea ce e destul — un test care afirmă tipul unui câmp în loc de valoarea lui
 * nu verifică nimic despre rută.
 */
export type ResponseBody =
  { instances: Array<Record<string, unknown>> } & Record<string, unknown>;

/**
 * Corpul JSON al unui răspuns.
 *
 * E o CONVERSIE, scrisă o dată aici în loc de cincizeci de ori în teste.
 * `Response.json()` întoarce `unknown` sub tipurile lui Node; martorul îl vedea
 * ca `any` fiindcă avea `lib: ["dom"]` în tsconfig-ul lui, iar agregatorul NU îl
 * are — dinadins, altfel `document` și `window` ar deveni tipuri valide într-o
 * aplicație care rulează doar pe server, și un cod care le atinge ar trece de
 * `tsc` în loc să pice.
 *
 * Conversia nu verifică nimic la execuție și nu se preface că o face: ce
 * dovedește forma răspunsului sunt aserțiunile de dedesubt.
 */
export async function bodyOf<T = ResponseBody>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

/** Valori de test, scurte și evident false. Nimic din ele nu seamănă cu un secret real. */
export const BEACON_KEY = "cheie-beacon-test";
export const CHECK_KEY = "cheie-check-test";

/** Variabilele pe care rutele le citesc. Setate la fiecare test, nu o dată. */
export function setEnv(vars: Record<string, string | undefined>): void {
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

/**
 * Mediu curat: doar cheile de bază, fără hartă de instanțe, fără Telegram.
 *
 * `SENTINEL_RETIRED_INSTANCES` se ȘTERGE aici, nu doar se ignoră: variabilele
 * trăiesc în proces, deci o retragere setată de un test ar rămâne în picioare
 * pentru toate testele de după el din același fișier — iar simptomul ar fi un
 * test care trece verde fiindcă instanța pe care o verifică nu mai există.
 */
export function baseEnv(): void {
  setEnv({
    SENTINEL_STATE_PATH: STATE_FILE,
    SENTINEL_BEACON_SECRET: BEACON_KEY,
    SENTINEL_CHECK_SECRET: CHECK_KEY,
    SENTINEL_INSTANCE_SECRETS: undefined,
    SENTINEL_RETIRED_INSTANCES: undefined,
    TELEGRAM_BOT_TOKEN: "1:test",
    TELEGRAM_CHAT_ID: "1",
  });
}

/**
 * Configurează EXACT instanțele date, și niciuna în plus.
 *
 * O instanță există fiindcă are cheie, nu fiindcă are fișier — deci un test
 * care scrie starea unei instanțe trebuie să declare și că instanța aia
 * există. Fără asta, testul ar verifica un fișier pe care martorul îl ignoră.
 */
export function configureInstances(ids: string[]): void {
  const map: Record<string, string> = {};
  for (const id of ids) if (id !== "default") map[id] = keyFor(id);
  setEnv({
    SENTINEL_BEACON_SECRET: ids.includes("default") ? BEACON_KEY : undefined,
    SENTINEL_INSTANCE_SECRETS: Object.keys(map).length ? JSON.stringify(map) : undefined,
  });
}

export function keyFor(id: string): string {
  return id === "default" ? BEACON_KEY : `cheie-${id}-test`;
}

/**
 * Face directorul de stare să pară că e ÎNĂUNTRUL directorului aplicației.
 *
 * Se mută `process.cwd()`, nu starea: alternativa ar fi să scriem fișiere de
 * test chiar în depozit, iar un test care lasă gunoi în arbore e un test care
 * într-o zi îl comite.
 */
export function pretendStateIsInsideApp(): () => void {
  return pretendCwd(path.dirname(STATE_DIR));
}

/** Mută directorul de lucru al procesului, doar cât ține testul. */
export function pretendCwd(dir: string): () => void {
  const original = process.cwd;
  process.cwd = () => dir;
  return () => { process.cwd = original; };
}

export async function removeState(): Promise<void> {
  await fs.rm(STATE_DIR, { recursive: true, force: true });
  await fs.mkdir(STATE_DIR, { recursive: true });
}

/** Tot ce e în directorul de stare. Folosit ca să vedem ce a rămas în urmă. */
export async function stateDirEntries(): Promise<string[]> {
  try {
    return (await fs.readdir(STATE_DIR)).sort();
  } catch {
    return [];
  }
}

/** Fișiere temporare rămase după o scriere. Trebuie să fie mereu zero. */
export async function leftoverTempFiles(): Promise<string[]> {
  return (await stateDirEntries()).filter((f) => f.endsWith(".tmp"));
}

/**
 * Scrie fișierul de bază ca text brut.
 *
 * E fișierul din forma veche, cel care există chiar acum în producție — testele
 * de migrare au nevoie să-l producă exact, nu prin API-ul curent.
 */
export async function writeRawState(text: string): Promise<void> {
  await fs.mkdir(STATE_DIR, { recursive: true });
  await fs.writeFile(STATE_FILE, text, "utf8");
}

/** Scrie fișierul unei instanțe ca text brut, inclusiv text care nu e JSON. */
export async function writeRawInstance(id: string, text: string): Promise<void> {
  await fs.mkdir(STATE_DIR, { recursive: true });
  await fs.writeFile(path.join(STATE_DIR, `state.${id}.json`), text, "utf8");
}

export async function stateFileExists(file = STATE_FILE): Promise<boolean> {
  try {
    await fs.stat(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Un semnal cu forma pe care o trimite `sentinel/report/beacon.py` azi.
 *
 * Fără `instance_id`: exact ce trimite serverul aflat în producție acum, ca
 * testele să demonstreze că martorul actualizat îl acceptă în continuare.
 */
export function beatPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sent_at: new Date().toISOString(),
    max_age_s: 120,
    interval_s: 60,
    seq: 1,
    last_event_id: 1000,
    detect_cursor: 990,
    incidents_open: 0,
    blocklist_size: 0,
    audit_head: "a".repeat(64),
    selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: "2026-08-12T09:00:00+00:00" },
    ...over,
  };
}

/**
 * Cererea POST către /beat, semnată corect.
 *
 * Semnătura se calculează peste EXACT octeții trimiși, nu peste obiect
 * reserializat — la fel ca în beacon.py, și e singurul mod în care testul chiar
 * dovedește ceva despre calea de verificare.
 */
export async function beatRequest(opts: {
  payload?: Record<string, unknown>;
  raw?: string;
  key?: string;
  instance?: string | null;
  signature?: string;
}): Promise<Request> {
  const { canonical } = await import("@/lib/verify");
  const crypto = await import("crypto");
  const raw = opts.raw ?? canonical(opts.payload ?? beatPayload());
  const key = opts.key ?? BEACON_KEY;
  const signature =
    opts.signature
    ?? crypto.createHmac("sha256", key).update(raw, "utf8").digest("hex");

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Sentinel-Signature": signature,
  };
  if (opts.instance) headers["X-Sentinel-Instance"] = opts.instance;

  return new Request("https://exemplu.ro/api/sentinel/beat", {
    method: "POST",
    body: raw,
    headers,
  });
}

/**
 * Adună ce se scrie în jurnal.
 *
 * Avertismentul despre fișierele străine e singura urmă pe care o lasă o copie
 * pusă lângă stare, iar regulile lui — că apare, și că NU conține numele
 * fișierului — sunt afirmații pe care doar un test le poate ține în viață.
 */
export function captureLog(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.error;
  console.error = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.error = original; } };
}

/**
 * Adună ce se scrie prin `console.warn` — REFUZURILE, nu configurația.
 *
 * Separat de `captureLog` fiindcă cele două suprafețe sunt separate și în cod:
 * un 401 e un avertisment (oricine îl poate provoca trimițând un antet), o
 * valoare care nu se poate citi e o eroare. Testele de configurație cer lista de
 * erori GOALĂ, deci dacă cele două ar ajunge în același loc, orice refuz dintr-un
 * test ar strica aserțiunile alea.
 */
export function captureWarn(): { lines: string[][]; restore: () => void } {
  const lines: string[][] = [];
  const original = console.warn;
  console.warn = (...args: unknown[]) => { lines.push(args.map(String)); };
  return { lines, restore: () => { console.warn = original; } };
}

/** Ce a plecat spre Telegram, ca să putem verifica TEXTUL, nu doar că s-a apelat ceva. */
export type SentMessage = { text: string; chat_id: string };

/**
 * Înlocuiește `fetch` global și adună mesajele.
 *
 * Nu se falsifică modulul `lib/telegram.ts`: dacă l-am înlocui, testul ar
 * confirma că am apelat propria noastră imitație. Așa trece prin codul real,
 * inclusiv prin construirea corpului HTML — locul în care un caracter greșit a
 * oprit deja o dată canalul de alertare.
 */
export function captureTelegram(opts: { ok?: boolean } = {}): {
  sent: SentMessage[];
  restore: () => void;
} {
  const sent: SentMessage[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: unknown, init?: { body?: string }) => {
    const url = String(input);
    if (!url.includes("api.telegram.org")) {
      throw new Error(`test: fetch neașteptat către ${url}`);
    }
    const body = JSON.parse(String(init?.body ?? "{}"));
    sent.push({ text: String(body.text ?? ""), chat_id: String(body.chat_id ?? "") });
    return new Response(JSON.stringify({ ok: opts.ok !== false }), {
      status: opts.ok === false ? 500 : 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { sent, restore: () => { globalThis.fetch = original; } };
}
