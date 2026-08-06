/**
 * Starea martorului, în spatele unei interfețe minime.
 *
 * Abstracția există dintr-un motiv practic, nu din eleganță: nu știm încă ce
 * stocare persistentă are găzduirea. Implementarea pe fișier merge oriunde
 * există un disc scriibil; dacă se dovedește că discul nu supraviețuiește
 * redeployului, se înlocuiește doar fișierul ăsta.
 *
 * Cantitatea de stare e mică dinadins — ultimul semnal, câteva contoare și dacă
 * o alertă a fost deja trimisă. Un martor care are nevoie de o bază de date ca
 * să spună „a tăcut" e un martor cu propriile moduri de a cădea.
 */

import { promises as fs } from "fs";
import path from "path";

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
  selfcheck: { worst: string; checks: number; bad: number; ran_at: string | null };
};

export type State = {
  last?: Beat;
  /** Ultima alertă trimisă, ca să nu repetăm la fiecare verificare. */
  alerted?: { kind: string; at: string };
  /** Când au avansat ultima dată contoarele, nu când a sosit ultimul semnal. */
  counters_moved_at?: string;
};

const FILE = process.env.SENTINEL_STATE_PATH
  || path.join(process.cwd(), ".sentinel-watcher.json");

export async function read(): Promise<State> {
  try {
    return JSON.parse(await fs.readFile(FILE, "utf8")) as State;
  } catch {
    // Primul semnal, sau stocare golită. Ambele înseamnă „nu știu încă", care
    // e diferit de „a tăcut" — apelantul trebuie să poată deosebi.
    return {};
  }
}

export async function write(state: State): Promise<void> {
  // Scriere atomică: o întrerupere la mijloc ar lăsa un JSON trunchiat, iar
  // martorul ar porni de la zero exact când e mai puțin potrivit.
  const tmp = `${FILE}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 2), "utf8");
  await fs.rename(tmp, FILE);
}
