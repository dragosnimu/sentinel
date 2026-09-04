/**
 * `judge()` e singurul loc care decide dacă sună telefonul.
 *
 * Ambele erori costă la fel de scump și în direcții opuse: un verdict prea
 * relaxat înseamnă un server compromis despre care martorul spune „e în
 * regulă"; unul prea nervos înseamnă alerte la fiecare repornire de serviciu,
 * până când operatorul le ignoră — și atunci nu mai contează că a doua zi a
 * fost una adevărată.
 *
 * `countersAdvanced()` e regula pe care un „sunt viu" simplu nu o are: procesul
 * răspunde, deci pare viu, iar ingestia e moartă de o oră.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  judge, countersAdvanced, principalAlreadyDelivered,
  MISSED_BEATS_BEFORE_ALARM, STALL_SECONDS,
} from "@/lib/verify";
import type { Beat } from "@/lib/store";

// Legat de semnătura reală a funcției: `judge` primește azi `State`, iar după
// trecerea la mai multe instanțe primește `InstanceState`. Testul nu are de ce
// să se schimbe pentru asta — forma pe care o judecă e aceeași.
type Judged = Parameters<typeof judge>[0];

const NOW = new Date("2026-08-12T12:00:00.000Z");

function ago(seconds: number): string {
  return new Date(NOW.getTime() - seconds * 1000).toISOString();
}

function beat(over: Partial<Beat> = {}): Beat {
  return {
    seq: 10,
    sent_at: ago(5),
    received_at: ago(5),
    last_event_id: 1000,
    detect_cursor: 990,
    incidents_open: 0,
    blocklist_size: 0,
    audit_head: "a".repeat(64),
    interval_s: 60,
    selfcheck: { worst: "ok", checks: 33, bad: 0, ran_at: ago(60) },
    ...over,
  };
}

function judged(over: Partial<Judged> = {}): Judged {
  return { ...over } as Judged;
}

// ---------------------------------------------------------------------------
// Tăcere

test("fără niciun semnal, verdictul e „în regulă\" — nu sunăm la fiecare instalare", () => {
  const v = judge(judged(), NOW);
  assert.equal(v.kind, null);
});

test("un semnal proaspăt e „în regulă\"", () => {
  assert.equal(judge(judged({ last: beat() }), NOW).kind, null);
});

test("sub trei intervale de tăcere NU e alarmă", () => {
  // O repornire de serviciu sau o reîncercare de rețea nu au voie să trezească
  // pe nimeni. Pragul e chiar `MISSED_BEATS_BEFORE_ALARM` × intervalul.
  const justUnder = 60 * MISSED_BEATS_BEFORE_ALARM - 1;
  assert.equal(judge(judged({ last: beat({ received_at: ago(justUnder) }) }), NOW).kind, null);
});

test("peste trei intervale de tăcere e alarmă critică", () => {
  const justOver = 60 * MISSED_BEATS_BEFORE_ALARM + 1;
  const v = judge(judged({ last: beat({ received_at: ago(justOver) }) }), NOW);
  assert.equal(v.kind, "silent");
  assert.equal(v.severity, "critical");
  assert.match(v.message, /Niciun semnal/);
});

test("un interval configurat absurd de mic nu coboară pragul sub 90 de secunde", () => {
  // `Math.max(interval, 30)`: cu `interval_s: 1`, trei intervale ar însemna 3
  // secunde, iar martorul ar suna la fiecare rundă de cron.
  const b = beat({ interval_s: 1, received_at: ago(80) });
  assert.equal(judge(judged({ last: b }), NOW).kind, null);
  assert.equal(
    judge(judged({ last: beat({ interval_s: 1, received_at: ago(100) }) }), NOW).kind,
    "silent",
  );
});

// ---------------------------------------------------------------------------
// Conductă moartă

test("semnalele sosesc dar contoarele stau pe loc → „stalled\"", () => {
  const v = judge(
    judged({ last: beat(), counters_moved_at: ago(STALL_SECONDS + 60) }),
    NOW,
  );
  assert.equal(v.kind, "stalled");
  assert.equal(v.severity, "critical");
  assert.match(v.message, /contoarele/);
});

test("contoare oprite de mai puțin decât pragul NU sunt alarmă", () => {
  const v = judge(judged({ last: beat(), counters_moved_at: ago(STALL_SECONDS - 60) }), NOW);
  assert.equal(v.kind, null);
});

test("fără `counters_moved_at`, se pornește de la ultimul semnal, nu de la epocă", () => {
  // Eșecul pe care îl previne: o stare proaspătă (prima repornire a martorului)
  // ar fi arătat contoare „oprite din 1970" și ar fi alertat imediat.
  assert.equal(judge(judged({ last: beat() }), NOW).kind, null);
});

test("tăcerea are prioritate față de contoarele oprite", () => {
  // Când amândouă sunt adevărate, gazda e căzută. Asta e ce trebuie să scrie în
  // mesaj, fiindcă e ce trebuie făcut.
  const v = judge(
    judged({ last: beat({ received_at: ago(3600) }), counters_moved_at: ago(7200) }),
    NOW,
  );
  assert.equal(v.kind, "silent");
});

// ---------------------------------------------------------------------------
// Autodiagnostic

test("autodiagnosticul „down\" e critic, restul de probleme sunt „high\"", () => {
  const down = judge(
    judged({ last: beat({ selfcheck: { worst: "down", checks: 33, bad: 4, ran_at: ago(60) } }) }),
    NOW,
  );
  assert.equal(down.kind, "selfcheck");
  assert.equal(down.severity, "critical");
  assert.match(down.message, /4 din 33/);

  const degraded = judge(
    judged({ last: beat({ selfcheck: { worst: "degraded", checks: 33, bad: 1, ran_at: ago(60) } }) }),
    NOW,
  );
  assert.equal(degraded.kind, "selfcheck");
  assert.equal(degraded.severity, "high");
});

test("„unknown\" la autodiagnostic NU e alarmă", () => {
  // Comportamentul de azi, scris explicit ca să fie o decizie vizibilă, nu un
  // accident: `unknown` înseamnă „autodiagnosticul nu a rulat încă" — pe o
  // instalare proaspătă e normal, iar semnalul are deja alte contoare care
  // trebuie să avanseze.
  const v = judge(
    judged({ last: beat({ selfcheck: { worst: "unknown", checks: 0, bad: 0, ran_at: null } }) }),
    NOW,
  );
  assert.equal(v.kind, null);
});

// ---------------------------------------------------------------------------
// countersAdvanced

test("primul semnal contează întotdeauna ca avans", () => {
  assert.equal(countersAdvanced(undefined, beat()), true);
});

test("oricare dintre cele trei contoare care se mișcă înseamnă viață", () => {
  const prev = beat();
  assert.equal(countersAdvanced(prev, beat({ last_event_id: prev.last_event_id + 1 })), true);
  assert.equal(countersAdvanced(prev, beat({ detect_cursor: prev.detect_cursor + 1 })), true);
  assert.equal(countersAdvanced(prev, beat({ audit_head: "b".repeat(64) })), true);
});

test("niciun contor mișcat înseamnă conductă oprită", () => {
  const prev = beat();
  assert.equal(countersAdvanced(prev, beat()), false);
});

test("un contor care SCADE nu trece drept avans", () => {
  // Un `last_event_id` mai mic decât cel dinainte înseamnă bază refăcută dintr-un
  // backup sau o instanță confundată cu alta — în niciun caz progres.
  const prev = beat();
  assert.equal(countersAdvanced(prev, beat({ last_event_id: prev.last_event_id - 100 })), false);
});

test("capul de audit se compară prin schimbare, nu prin creștere", () => {
  // E un hash, nu un contor: ordinea între două valori nu înseamnă nimic, doar
  // faptul că s-a schimbat. Inclusiv trecerea la valoarea de eșec a sondei.
  const prev = beat({ audit_head: "c".repeat(64) });
  assert.equal(countersAdvanced(prev, beat({ audit_head: "" })), true);
  assert.equal(countersAdvanced(prev, beat({ audit_head: "unavailable" })), true);
});

// ---------------------------------------------------------------------------
// principalAlreadyDelivered — alertele duble
//
// Eșecul pe care îl previn testele astea: martorul dublează o alertă pe care
// Sentinel tocmai a trimis-o pe Telegram, la câteva secunde distanță — 131 de
// ori în 7 zile, măsurat, pentru `selfcheck`. Cerința operatorului e explicit
// direcțională: „de pe martorul extern se trimite mesaj doar dacă nu am primit
// același tip de mesaj de pe serverul principal" — deci orice incertitudine
// trebuie să cadă spre ALERTĂ, niciodată spre tăcere.

test("un `selfcheck` livrat CONFIRMAT de principal e citit ca suprimabil", () => {
  const last = beat({ alerted_kinds: { selfcheck: true } });
  assert.equal(principalAlreadyDelivered("selfcheck", last), true);
});

test("`selfcheck` marcat explicit `false` NU se suprimă", () => {
  // „Nu știu dacă a livrat" trebuie să ducă spre alertă. `false` explicit
  // (sonda a rulat și n-a găsit o livrare recentă) nu e altceva decât asta.
  const last = beat({ alerted_kinds: { selfcheck: false } });
  assert.equal(principalAlreadyDelivered("selfcheck", last), false);
});

test("`silent` nu e niciodată suprimabil, indiferent ce spune beaconul", () => {
  // Chiar dacă un beacon compromis sau cu bug ar trimite `alerted_kinds:
  // {silent: true}`, `SUPPRESSIBLE_KINDS` nu are cheie pentru `silent` — e
  // rostul martorului, iar principalul, dacă tace cu adevărat, n-a putut livra
  // nimic RECENT despre propria tăcere.
  const last = beat({ alerted_kinds: { silent: true, selfcheck: true } });
  assert.equal(principalAlreadyDelivered("silent", last), false);
});

test("`stalled` nu e niciodată suprimabil, indiferent ce spune beaconul", () => {
  const last = beat({ alerted_kinds: { stalled: true, selfcheck: true } });
  assert.equal(principalAlreadyDelivered("stalled", last), false);
});

test("`alerted_kinds` LIPSĂ (expeditor mai vechi decât martorul) nu suprimă nimic", () => {
  const last = beat(); // fără câmpul `alerted_kinds` deloc
  assert.equal(principalAlreadyDelivered("selfcheck", last), false);
});

test("semnalul LIPSĂ CU TOTUL (`last` nedefinit) nu suprimă nimic", () => {
  assert.equal(principalAlreadyDelivered("selfcheck", undefined), false);
});

test("un `kind` gol (null/undefined) nu suprimă nimic", () => {
  const last = beat({ alerted_kinds: { selfcheck: true } });
  assert.equal(principalAlreadyDelivered(null, last), false);
  assert.equal(principalAlreadyDelivered(undefined, last), false);
});
