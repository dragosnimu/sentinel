/**
 * Cârligul `--import` al celor șase unelte de operator: încarcă `.env.local`
 * ÎNAINTE ca uneltea să-și citească configurația.
 *
 *     node --import tsx --import ./bin/preload-env.ts bin/user.ts ...
 *
 * `tsx` primul: fără el un `.ts` nu se poate încărca. Logica e în
 * `bin/env-file.ts`, ca să se poată testa fără un proces; aici e doar partea cu
 * efecte — calea, `process.env`, `stderr`, codul de ieșire. Un fișier separat,
 * fiindcă importat dintr-un test ar încărca fișierul REAL al operatorului în
 * procesul de test.
 *
 * Fișierul e `aggregator/.env.local` (lângă `package.json`, nu relativ la
 * directorul curent: uneltele se pot chema și din altă parte). `SENTINEL_ENV_FILE`
 * indică altul.
 *
 * NU se pune pe `build`, `start`, `test` sau `typecheck`: acolo un fișier de
 * secrete de producție n-are ce căuta, iar pe găzduire aceste scripturi nu rulează.
 */

import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEFAULT_ENV_FILE, ENV_FILE_VARIABLE, loadEnvFile, reportFor,
} from "./env-file";

const packageRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const named = (process.env[ENV_FILE_VARIABLE] ?? "").trim();

const result = loadEnvFile({
  file: named ? path.resolve(named) : path.join(packageRoot, DEFAULT_ENV_FILE),
  explicit: named !== "",
  env: process.env,
});
const report = reportFor(result);
for (const line of report.lines) process.stderr.write(line + "\n");
if (report.fatal) process.exit(1);
