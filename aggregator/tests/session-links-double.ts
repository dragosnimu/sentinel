/**
 * Dublu pentru instrucțiunile din `lib/session-links.ts`.
 *
 * ## Ce afirmă și ce nu
 *
 * Pe mașina de dezvoltare nu există MariaDB. Dublul **evaluează condițiile din
 * textul instrucțiunii** (`instance_id = ?`, `session_source_id IS NULL`,
 * `session_key = ?`, `ts >= ?`, `ts <= ?`, `source_id IN (...)`), nu aplică o
 * semantică scrisă de mână: un `instance_id` scos din `UPDATE`, un `IS NULL`
 * pierdut sau o margine inversată schimbă ce face dublul, deci se vede.
 *
 * Orice instrucțiune pe care n-o recunoaște e o EROARE, nu o operație nulă — un
 * dublu care înghite SQL necunoscut raportează verde pentru cod care în
 * producție n-ar face nimic.
 *
 * Ce NU dovedește: că MariaDB acceptă instrucțiunile (sintaxa) și cât durează
 * `UPDATE`-ul pe 500 000 de rânduri. Comparația de timp o face aici JavaScript
 * pe milisecunde; serverul o face pe `DATETIME(6)`, deci diferențe sub o
 * milisecundă nu se pot vedea de aici.
 */

import assert from "node:assert/strict";

import { parseDatetime } from "../lib/session-links";
import type { Db } from "../lib/migrate";

export type Row = Record<string, unknown>;

function flat(sql: string): string {
  return sql.replace(/\s+/g, " ").trim();
}

function inMarks(list: string): number {
  assert.match(list, /^\?(, \?)*$/, `dublul: IN cu altceva decât parametri: ${list}`);
  return list.split(",").length;
}

function ts(value: unknown): number {
  const ms = parseDatetime(value);
  assert.ok(ms !== null, `dublul: dată necitibilă ${String(value)}`);
  return ms as number;
}

export class LinkDouble implements Db {
  readonly asked: { sql: string; params: unknown[] }[] = [];

  constructor(
    private readonly sessions: () => Row[],
    private readonly commands: () => Row[],
  ) {}

  /** Câte `UPDATE`-uri de legare au rulat. */
  get updates(): { sql: string; params: unknown[] }[] {
    return this.asked.filter((q) => q.sql.startsWith("UPDATE"));
  }

  async all(sqlIn: string, params: unknown[] = []): Promise<Row[]> {
    const sql = flat(sqlIn);
    this.asked.push({ sql, params });
    let m: RegExpExecArray | null;

    if ((m = /^SELECT source_id, session_key FROM login_session_entries WHERE instance_id = \? AND source_id IN \(([^)]*)\)$/.exec(sql))) {
      const n = inMarks(m[1]);
      assert.equal(params.length, 1 + n);
      const [instance, ...ids] = params;
      const wanted = new Set(ids.map(Number));
      return this.sessions()
        .filter((s) => s.instance_id === instance && wanted.has(Number(s.source_id)))
        .map((s) => ({ source_id: String(s.source_id), session_key: s.session_key }));
    }

    if ((m = /^SELECT source_id, session_key, interactive, opened_at, closed_at FROM login_session_entries WHERE instance_id = \? AND session_key IN \(([^)]*)\)$/.exec(sql))) {
      const n = inMarks(m[1]);
      assert.equal(params.length, 1 + n);
      const [instance, ...keys] = params;
      return this.sessions()
        .filter((s) => s.instance_id === instance && keys.includes(s.session_key))
        .map((s) => ({ source_id: String(s.source_id), session_key: s.session_key,
                       interactive: s.interactive ?? 0, opened_at: s.opened_at,
                       closed_at: s.closed_at ?? null }));
    }

    if (sql === "SELECT source_id, session_key, interactive, opened_at, closed_at FROM login_session_entries WHERE instance_id = ?") {
      assert.equal(params.length, 1);
      return this.sessions().filter((s) => s.instance_id === params[0])
        .map((s) => ({ source_id: String(s.source_id), session_key: s.session_key,
                       interactive: s.interactive ?? 0, opened_at: s.opened_at,
                       closed_at: s.closed_at ?? null }));
    }

    if (sql === "SELECT DISTINCT instance_id FROM login_session_entries") {
      return [...new Set(this.sessions().map((s) => s.instance_id))]
        .map((instance_id) => ({ instance_id }));
    }

    if ((m = /^SELECT COUNT\(\*\) AS n FROM session_command_entries WHERE instance_id = \? AND session_source_id IS NULL AND source_id IN \(([^)]*)\)$/.exec(sql))) {
      const n = inMarks(m[1]);
      assert.equal(params.length, 1 + n);
      const [instance, ...ids] = params;
      const wanted = new Set(ids.map(Number));
      const count = this.commands().filter((c) => c.instance_id === instance
        && (c.session_source_id === null || c.session_source_id === undefined)
        && wanted.has(Number(c.source_id))).length;
      return [{ n: String(count) }]; // șir, ca `bigNumberStrings`
    }

    if (sql === "SELECT COUNT(*) AS n FROM session_command_entries WHERE instance_id = ? AND session_source_id IS NULL") {
      assert.equal(params.length, 1);
      const count = this.commands().filter((c) => c.instance_id === params[0]
        && (c.session_source_id === null || c.session_source_id === undefined)).length;
      return [{ n: String(count) }];
    }

    if ((m = /^SELECT COUNT\(\*\) AS n FROM session_command_entries WHERE instance_id = \? AND session_source_id IS NULL AND session_key = \? AND ts >= \?( AND ts <= \?)?$/.exec(sql))) {
      const bounded = m[1] !== undefined;
      assert.equal(params.length, bounded ? 4 : 3);
      const [instance, key, lo, hi] = params;
      const count = this.commands().filter((c) => c.instance_id === instance
        && (c.session_source_id === null || c.session_source_id === undefined)
        && c.session_key === key && ts(c.ts) >= ts(lo)
        && (!bounded || ts(c.ts) <= ts(hi))).length;
      return [{ n: String(count) }];
    }

    if ((m = /^SELECT session_key, MIN\(ts\) AS lo, MAX\(ts\) AS hi FROM session_command_entries WHERE instance_id = \? AND session_source_id IS NULL AND source_id IN \(([^)]*)\) GROUP BY session_key$/.exec(sql))) {
      const n = inMarks(m[1]);
      assert.equal(params.length, 1 + n);
      const [instance, ...ids] = params;
      const wanted = new Set(ids.map(Number));
      const per = new Map<string, number[]>();
      for (const c of this.commands()) {
        if (c.instance_id !== instance || !wanted.has(Number(c.source_id))) continue;
        if (c.session_source_id !== null && c.session_source_id !== undefined) continue;
        const list = per.get(String(c.session_key)) ?? [];
        list.push(ts(c.ts));
        per.set(String(c.session_key), list);
      }
      const fmt = (ms: number) => new Date(ms).toISOString().replace("T", " ").replace("Z", "000");
      return [...per.entries()].map(([session_key, list]) => ({
        session_key, lo: fmt(Math.min(...list)), hi: fmt(Math.max(...list)) }));
    }

    throw new Error(`LinkDouble: interogare neprevăzută: ${sql}`);
  }

  async run(sqlIn: string, params: unknown[] = []): Promise<void> {
    const sql = flat(sqlIn);
    this.asked.push({ sql, params });
    const m = /^UPDATE session_command_entries SET session_source_id = \? WHERE instance_id = \? AND session_source_id IS NULL AND session_key = \? AND ts >= \?( AND ts <= \?)?$/.exec(sql);
    if (!m) throw new Error(`LinkDouble: instrucțiune neprevăzută: ${sql}`);
    const bounded = m[1] !== undefined;
    assert.equal(params.length, bounded ? 5 : 4,
                 "dublul: număr de parametri nepotrivit cu instrucțiunea");
    const [sessionId, instance, key, lo, hi] = params;
    for (const c of this.commands()) {
      if (c.instance_id !== instance) continue;
      if (c.session_source_id !== null && c.session_source_id !== undefined) continue;
      if (c.session_key !== key) continue;
      if (ts(c.ts) < ts(lo)) continue;
      if (bounded && ts(c.ts) > ts(hi)) continue;
      c.session_source_id = sessionId;
    }
  }
}
