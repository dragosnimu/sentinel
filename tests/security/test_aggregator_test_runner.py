"""`npm test` în `aggregator/` trebuie să pice când n-a rulat nimic.

Până pe 18 august 2026 avea un geamăn, `test_watcher_test_runner.py`, fiindcă
martorul era o aplicație publicată separat, cu `run-tests.mjs`-ul lui. Martorul
s-a mutat în `aggregator/`, deci a rămas un singur script și un singur test
despre el — cel de aici, care în plus probează TERMENELE, singura purtare prin
care cele două scripturi chiar difereau.

Ce se pierde dacă suita raportează verde fără să fi rulat: nimic nu mai
dovedește contractul de semnare dintre `sentinel/report/signing.py` și
`aggregator/lib/verify.ts` (jumătatea TypeScript e în
`aggregator/tests/canonical.test.ts`), nimic nu mai dovedește că martorul refuză
un semnal reluat, și nimic nu mai dovedește că runner-ul de migrații reia de la
instrucțiunea la care a
murit, că nu consemnează o instrucțiune al cărei efect nu s-a confirmat, și că
secretele de instanță nu se pot muta de pe un rând pe altul. Toate trei sunt
proprietăți pe care numai suita aia le verifică, iar niciuna nu se vede pe gazdă
până în ziua în care contează.

Scriptul dinainte, în `watcher/`, era `node --test "tests/*.test.ts"`. Node
acceptă tipare glob la `--test` abia din 21; găzduirea rulează Node 20. Reparația
evidentă — `--test tests/` — e cea periculoasă: pe Node 20 raportează
`# pass 0  # fail 0` și **iese cu 0**.

Testele de aici rulează scriptul LIVRAT (`aggregator/run-tests.mjs`), copiat
lângă `node_modules` ca `tsx` să se rezolve, și se uită la codul de ieșire — nu
la ce scrie în el.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
RUNNER = AGGREGATOR / "run-tests.mjs"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU a rulat verificarea că `npm test` din "
    "aggregator/ pică pe o suită goală — adică pe o suită care n-a dovedit "
    "nimic despre runner-ul de migrații. Nu e „în regulă”, e „neverificat”."
)

_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva "
    "și testele astea ar cădea din alt motiv decât cel verificat. Rulează "
    "`npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.security,
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

PASSING = 'import { test } from "node:test";\ntest("merge-ts", () => {});\n'
PASSING_TSX = 'import { test } from "node:test";\ntest("merge-tsx", () => {});\n'
FAILING = ('import { test } from "node:test";\n'
           'import assert from "node:assert/strict";\n'
           'test("pică", () => { assert.equal(1, 2); });\n')

# Un `spawnSync` fals, instalat printr-un cârlig de rezolvare a modulelor.
#
# Există ca să se poată proba ramura `status === null` — copilul omorât de un
# semnal — pe ORICE platformă. Măsurat: pe Windows, un copil care își trimite
# `SIGKILL` iese cu `status = 1`, deci un test bazat pe semnale ar fi trecut
# fără să atingă ramura. Aici scriptul LIVRAT rulează neatins; doar
# `node:child_process` e înlocuit sub el.
#
# Cârligul scrie un fișier martor. Fără el, un cârlig care nu s-a aplicat ar
# lăsa scriptul să ruleze `node --test` pe un director gol, să iasă cu 1, iar
# testul ar fi trecut din alt motiv decât cel verificat.
HOOKS_MJS = """\
import { pathToFileURL } from "node:url";
export async function resolve(specifier, context, next) {
  if (specifier === "node:child_process" || specifier === "child_process") {
    return { url: pathToFileURL(process.env.SENTINEL_STUB).href, shortCircuit: true };
  }
  return next(specifier, context);
}
"""

REGISTER_MJS = """\
import { register } from "node:module";
register("./hooks.mjs", import.meta.url);
"""

STUB_MJS = """\
import { writeFileSync } from "node:fs";
export function spawnSync() {
  writeFileSync(process.env.SENTINEL_MARKER, "spawnSync a fost chemat");
  return { status: %s, signal: %s, error: %s };
}
"""

# Un test care nu se termină niciodată. Fără termen, `node --test` îl așteaptă la
# nesfârșit și nu tipărește nimic — vezi docstring-ul lui `run-tests.mjs`.
HANGING = ('import { test } from "node:test";\n'
           'test("atârnă", async () => { await new Promise(() => {}); });\n')

# `--test-timeout` există din Node 20.11. Dacă Node-ul de aici nu-l cunoaște,
# proba prin efect de mai jos NU se poate face, iar asta se spune ca skip cu
# motiv — nu se lasă să treacă verde. „Neverificat” și „în regulă” sunt stări
# diferite.
_TIMEOUT_FLAG_OK = NODE is not None and subprocess.run(
    [NODE, "--test-timeout=1000", "-e", "0"],
    capture_output=True).returncode == 0

_NO_TIMEOUT_FLAG = (
    "Node-ul de aici nu acceptă --test-timeout, deci NU s-a verificat că un "
    "test care atârnă e oprit. Pe un Node fără flagul ăsta scriptul cade pe "
    "termenul întregii suite, care e de zece minute și nu se poate proba aici."
)


def run_runner(tests: dict[str, str] | None,
               stub: tuple[str, ...] | None = None,
               env_extra: dict[str, str] | None = None,
               timeout: int = 180) -> subprocess.CompletedProcess:
    """Scriptul livrat, într-un director propriu de sub `aggregator/`.

    Sub `aggregator/`, nu în `tmp_path`: `--import tsx` se rezolvă urcând după
    `node_modules`, iar în afara depozitului n-ar găsi nimic.

    `stub` înlocuiește `node:child_process` cu unul care întoarce exact
    `(status, signal)` cerute, ca ramurile pe care un copil real nu le poate
    produce portabil să fie totuși probate.
    """
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-runner-") as tmp:
        root = Path(tmp)
        shutil.copy2(RUNNER, root / "run-tests.mjs")
        if tests is not None:
            (root / "tests").mkdir()
            for name, body in tests.items():
                (root / "tests" / name).write_text(body, encoding="utf-8", newline="\n")

        argv = [NODE, "run-tests.mjs"]
        env = {**os.environ, "NO_COLOR": "1", **(env_extra or {})}
        if stub is not None:
            status, signal, error = (*stub, "undefined")[:3]
            (root / "hooks.mjs").write_text(HOOKS_MJS, encoding="utf-8", newline="\n")
            (root / "register.mjs").write_text(REGISTER_MJS, encoding="utf-8", newline="\n")
            (root / "stub.mjs").write_text(STUB_MJS % (status, signal, error),
                                           encoding="utf-8", newline="\n")
            env["SENTINEL_STUB"] = str(root / "stub.mjs")
            env["SENTINEL_MARKER"] = str(root / "marker.txt")
            argv = [NODE, "--import", "./register.mjs", "run-tests.mjs"]

        proc = subprocess.run(
            argv, cwd=root, capture_output=True, text=True,
            # Explicit: pe Windows codificarea implicită a consolei e cp1252,
            # iar mesajele scriptului sunt în română.
            encoding="utf-8", errors="replace",
            env=env, timeout=timeout)
        if stub is not None:
            proc.stub_was_used = (root / "marker.txt").is_file()  # type: ignore[attr-defined]
        return proc


def test_a_suite_that_ran_nothing_fails():
    """Directorul `tests/` există și n-are niciun fișier de test.

    Eșecul pe care îl previne: `npm test` verde pe agregator, cu zero teste
    rulate. Nimic din `scripts/` sau din publicarea pe găzduire nu citește
    numărul de teste — codul de ieșire e singurul lucru care ajunge la cineva.
    """
    proc = run_runner({})
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "n-a rulat nimic" in (proc.stdout + proc.stderr)


def test_a_missing_tests_directory_fails():
    """Și când directorul lipsește cu totul — o suită care nu se poate citi nu
    e o suită verde."""
    proc = run_runner(None)
    assert proc.returncode != 0, proc.stdout + proc.stderr


def test_the_files_are_found_without_a_shell_glob():
    """Un fișier de test chiar e găsit și rulat.

    Fără testul ăsta, un script care iese cu 1 întotdeauna ar trece testele de
    mai sus. Și e jumătatea care dovedește că descoperirea fișierelor nu depinde
    de expandarea globurilor din shell — care pe Windows, unde `npm` rulează
    prin `cmd.exe`, nu se întâmplă deloc.
    """
    proc = run_runner({"a.test.ts": PASSING})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "merge-ts" in proc.stdout


def test_tsx_files_are_discovered_too():
    """O suită DOAR cu `.test.tsx` trebuie să ruleze.

    Măsurat în `watcher/`, unde s-a întâmplat: scos `.test.tsx` din filtrul de
    descoperire, suita trece de la 194 la 186 de teste, raportează
    `pass 186 fail 0` și iese cu 0. Un test care nu rulează nu are cum să pice.

    Trebuie să fie un test SEPARAT, cu un singur fișier: lângă un `.test.ts`,
    scoaterea lui `.test.tsx` lasă suita verde și nimeni nu observă.

    Aici, azi, `aggregator/tests/` n-are niciun `.tsx` — panoul din E3 îl va
    aduce. Filtrul îl acceptă de pe acum, deci ori e păzit acum, ori se va
    descoperi că nu e când primul fișier de panou nu va rula.
    """
    proc = run_runner({"panou.test.tsx": PASSING_TSX})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "merge-tsx" in proc.stdout


def test_both_extensions_run_in_the_same_pass():
    """Și împreună, fiindcă asta va fi forma reală a lui `aggregator/tests/`."""
    proc = run_runner({"a.test.ts": PASSING, "panou.test.tsx": PASSING_TSX})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "merge-ts" in proc.stdout and "merge-tsx" in proc.stdout


def test_a_child_killed_by_a_signal_is_not_success():
    """`spawnSync` întoarce `status: null` când copilul a fost omorât de un semnal.

    Eșecul pe care îl previne: `process.exit(child.status)` cu `status = null`
    iese cu **0**. Adică o suită omorâtă la jumătate — OOM killer, un timeout de
    CI, un `kill` de la un deploy — raportează succes. E aceeași minciună ca
    suita goală, doar declanșată de altceva, și e cea mai greu de observat,
    fiindcă ieșirea conține teste care chiar au trecut.

    Semnalul nu se poate produce portabil: măsurat pe Windows, un copil care își
    trimite `SIGKILL` iese cu `status = 1`, deci proba ar fi trecut fără să
    atingă ramura. Deci se înlocuiește `node:child_process` sub scriptul LIVRAT,
    care rămâne neatins.
    """
    proc = run_runner({"a.test.ts": PASSING}, stub=("null", '"SIGKILL"'))
    assert proc.stub_was_used, (
        "cârligul nu s-a aplicat, deci `spawnSync` real a rulat și testul ăsta "
        "n-a probat ramura pe care o numește: " + proc.stdout + proc.stderr)
    assert proc.returncode != 0, proc.stdout + proc.stderr


def test_the_stub_does_not_make_everything_fail():
    """Jumătatea care ține testul de mai sus onest.

    Fără ea, un cârlig care rupe scriptul în orice fel ar face proba de mai sus
    să treacă. Cu același mecanism și `status: 0`, scriptul trebuie să iasă cu 0.
    """
    proc = run_runner({"a.test.ts": PASSING}, stub=("0", "null"))
    assert proc.stub_was_used, proc.stdout + proc.stderr
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_a_failing_test_propagates_its_exit_code():
    """Codul de ieșire al copilului e cel care iese, nu al scriptului.

    Eșecul pe care îl previne: învelișul înghite eșecul copilului și `npm test`
    iese cu 0 peste o suită roșie — aceeași minciună ca suita goală, doar mai
    greu de observat.
    """
    proc = run_runner({"a.test.ts": PASSING, "b.test.ts": FAILING})
    assert proc.returncode != 0, proc.stdout + proc.stderr


@pytest.mark.skipif(not _TIMEOUT_FLAG_OK, reason=_NO_TIMEOUT_FLAG)
def test_a_hanging_test_is_stopped_and_named():
    """Un test care nu se mai întoarce trebuie să iasă ROȘU, nu să atârne.

    Eșecul pe care îl previne, și s-a întâmplat pe chiar suita asta: cu
    `release()` scos din `finally` în `aggregator/lib/auth/password.ts`, permisul
    semaforului se pierde la prima excepție, iar `node --test` a rulat 300 s
    fără să tipărească o linie și a trebuit omorât din afară. Pe o mașină de
    livrare aia arată ca „încă rulează", nu ca o suită roșie — deci nimeni nu-l
    citește ca defect, și e chiar tiparul depozitului: un mecanism care nu
    raportează niciodată eșec.

    Se probează PRIN EFECT, cu un fișier care așteaptă la infinit, nu prin
    citirea flagului din scriptul livrat: un `--test-timeout` scris în text și
    respins de Node ar trece o aserțiune pe text și n-ar opri nimic.
    """
    started = time.monotonic()
    proc = run_runner({"atarna.test.ts": HANGING},
                      env_extra={"SENTINEL_TEST_TIMEOUT_MS": "2000"},
                      # Dacă termenul nu funcționează, aici se ridică
                      # `TimeoutExpired` — un eșec zgomotos, nu o trecere.
                      timeout=60)
    elapsed = time.monotonic() - started

    assert proc.returncode != 0, proc.stdout + proc.stderr
    # Sub termenul întregii suite (zece minute), deci ce l-a oprit e termenul PER
    # TEST — altfel proba n-ar spune care dintre cele două mecanisme lucrează.
    assert elapsed < 30, f"a durat {elapsed:.0f} s"
    # Și testul e NUMIT. Asta e diferența dintre „un test a picat" și „suita a
    # fost omorâtă": fără nume, cine citește jurnalul de livrare n-are de unde
    # începe.
    assert "atârnă" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


def test_a_suite_stopped_by_its_own_deadline_says_so():
    """Termenul întregii suite nu se confundă cu „nu am putut porni node".

    Sunt două eșecuri diferite, iar mesajul dinainte le-ar fi confundat pe
    amândouă într-unul care trimite pe cineva să caute un `node` lipsă din PATH,
    când de fapt suita atârnase. `spawnSync` semnalează depășirea termenului
    prin `error.code === "ETIMEDOUT"` cu `status === null` — combinație pe care
    un copil real n-o poate produce în câteva secunde, deci se pune sub script
    la fel ca ramura semnalului.
    """
    proc = run_runner({"a.test.ts": PASSING},
                      stub=("null", '"SIGTERM"', '{ code: "ETIMEDOUT" }'))
    assert proc.stub_was_used, (
        "cârligul nu s-a aplicat, deci testul n-a probat ramura pe care o "
        "numește: " + proc.stdout + proc.stderr)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "a depășit" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


def test_npm_test_actually_invokes_the_runner():
    """`package.json` trebuie să cheme scriptul, altfel nimic de mai sus nu
    contează.

    Aserțiunea e pe conținut, nu pe efect, și asta se spune pe față: rularea
    efectivă a lui `npm test` E suita agregatorului, care se rulează separat. Ce
    se apără aici e revenirea la forma cu glob, care pe Node 20 nu găsește
    niciun fișier.
    """
    pkg = json.loads((AGGREGATOR / "package.json").read_text(encoding="utf-8"))
    assert pkg["scripts"]["test"] == "node run-tests.mjs"
    assert RUNNER.exists()
