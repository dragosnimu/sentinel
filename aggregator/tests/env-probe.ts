/**
 * Copilul probelor din `tests/env-file.test.ts`: spune ce vede din mediu și iese.
 *
 * Ia locul lui `bin/<unealta>.ts` în comanda REALĂ din `package.json`, deci ce
 * tipărește aici e ce ar vedea unealta după ce cârligul `--import` și-a făcut
 * treaba (sau nu). Nu cheamă `process.exit`: un copil care iese singur arată că
 * nici cârligul nu lasă nimic pornit în urmă.
 */

process.stdout.write(JSON.stringify({
  probe: process.env.SENTINEL_PROBE_VAR ?? null,
  other: process.env.SENTINEL_PROBE_OTHER ?? null,
}));
