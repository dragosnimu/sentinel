"""Ce sigilează instrumentul agregatorului trebuie să fie ce semnează serverul.

Cheia de expediere trăiește în două locuri: în `/etc/sentinel/secrets.env` pe
mașina monitorizată, de unde o citește `load_secrets` și cu ea semnează
`shipper.py`, și cifrată în tabela `instances` a agregatorului, unde o pune
`aggregator/bin/instance.ts`. Dacă cele două nu sunt ACEIAȘI OCTEȚI, fiecare lot
primește 401 — la nesfârșit, și imposibil de deosebit de o cheie greșită, fiindcă
`ship_once` tratează orice non-2xx la fel și nu citește niciodată corpul.

Instrumentul refuză (nu repară) orice valoare pe care serverul ar citi-o altfel.
Refuzul ăla se sprijină pe un model al parserului serverului, scris în
TypeScript, iar un model despre alt limbaj nu se poate verifica prin
raționament: `str.strip()` și `String.prototype.trim` NU taie aceleași
caractere. Măsurat, cinci valori treceau de instrument și erau tăiate de Python
— `U+001C`–`U+001F` și `U+0085`, pe care JavaScript nu le vede ca spațiu alb.

Deci testul de aici trece un corpus comun prin AMÂNDOUĂ implementările REALE și
cere proprietatea care contează:

    acceptat de instrument  ⟹  serverul semnează exact octeții aceia

Nu „amândouă resping". Refuzul e liber — un refuz e o linie de eroare pe care
operatorul o repară în cinci secunde. Acceptarea e cea care poate minți.

## De ce se cheamă `node`, și ce se întâmplă dacă lipsește

Fiindcă implementarea de verificat e cea LIVRATĂ, nu o transcriere a ei în
Python. O a doua transcriere ar fi exact greșeala pe care testul o caută.
Lipsa lui `node` sau a lui `node_modules` e SKIP cu motiv scris, nu verde: „n-am
putut verifica" și „e în regulă" sunt stări diferite.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
AGGREGATOR = REPO / "aggregator"
NODE = shutil.which("node")

_NO_NODE = (
    "node lipsește din PATH, deci NU s-a verificat că instrumentul de "
    "înregistrare sigilează exact ce semnează serverul. Nu e „în regulă”, e "
    "„neverificat”."
)
_NO_MODULES = (
    "aggregator/node_modules lipsește, deci `--import tsx` nu se poate rezolva. "
    "Rulează `npm install` în aggregator/. Nu e „în regulă”, e „neverificat”."
)

pytestmark = [
    pytest.mark.skipif(NODE is None, reason=_NO_NODE),
    pytest.mark.skipif(not (AGGREGATOR / "node_modules").is_dir(), reason=_NO_MODULES),
]

BASE = "a" * 64

# Corpusul. Fiecare intrare e o FORMĂ, nu un secret real — valorile sunt
# evident false. Numele spun ce se probează, ca un eșec să se citească fără să
# fie nevoie să numere cineva octeții.
#
# Caracterele se scriu prin cod (`chr`), nu ca litere: un caracter invizibil
# într-un diff e chiar felul în care se pierde o zi.
CORPUS: dict[str, str] = {
    "curat": BASE,
    "spatiu la cap": " " + BASE,
    "spatiu la coada": BASE + " ",
    "tab la coada": BASE + "\t",
    "CR la coada": BASE + "\r",
    "LF la coada": BASE + "\n",
    "VT la coada": BASE + "\v",
    "FF la coada": BASE + "\f",
    # Cele cinci care scăpaseră: Python le taie, JavaScript nu.
    "FS la coada": BASE + chr(0x1C),
    "GS la coada": BASE + chr(0x1D),
    "RS la coada": BASE + chr(0x1E),
    "US la coada": BASE + chr(0x1F),
    "NEL la coada": BASE + chr(0x85),
    # Invers: JavaScript taie BOM, Python nu.
    "BOM la coada": BASE + chr(0xFEFF),
    "BOM la cap": chr(0xFEFF) + BASE,
    # Spații Unicode pe care le taie amândouă.
    "NBSP la coada": BASE + chr(0xA0),
    "OGHAM la coada": BASE + chr(0x1680),
    "EN QUAD la coada": BASE + chr(0x2000),
    "NNBSP la coada": BASE + chr(0x202F),
    "MMSP la coada": BASE + chr(0x205F),
    "IDEOGRAFIC la coada": BASE + chr(0x3000),
    "LINE SEP la coada": BASE + chr(0x2028),
    "PARA SEP la coada": BASE + chr(0x2029),
    # Ghilimele.
    "ghilimele duble": '"' + BASE + '"',
    "ghilimele simple": "'" + BASE + "'",
    "ghilimea doar la cap": '"' + BASE,
    "ghilimea doar la coada": BASE + '"',
    "ghilimele in interior": BASE[:8] + '"' + BASE[8:],
    "ghilimele duble imbricate": '""' + BASE + '""',
    "ghilimele si spatiu": ' "' + BASE + '" ',
    # Sfârșit de linie ÎNĂUNTRU: `secrets.env` e un format pe linii, deci
    # serverul ar citi doar bucata dinaintea lui.
    "LF in interior": BASE[:32] + "\n" + BASE[32:],
    "CR in interior": BASE[:32] + "\r" + BASE[32:],
    "FS in interior": BASE[:32] + chr(0x1C) + BASE[32:],
    # Altele care trebuie să treacă neatinse.
    "egal in interior": BASE[:32] + "=" + BASE[32:],
    "diez la cap": "#" + BASE,
    "spatiu in interior": BASE[:32] + " " + BASE[32:],
    "gol": "",
    "doar spatii": "   ",
    "prea scurt": "a" * 31,
}

# Scriptul care cheamă implementarea LIVRATĂ. Primește corpusul pe intrare și
# scoate, pentru fiecare intrare, ce a decis instrumentul.
BRIDGE = """
import { checkSecretShape, serverSecretForm } from "./lib/register.ts";
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => { raw += c; });
process.stdin.on("end", () => {
  const corpus = JSON.parse(raw);
  const out = {};
  for (const [name, value] of Object.entries(corpus)) {
    const checked = checkSecretShape(value);
    out[name] = checked.ok
      ? { accepted: true, sealed: checked.secret, model: serverSecretForm(value) }
      : { accepted: false, model: serverSecretForm(value) };
  }
  process.stdout.write(JSON.stringify(out));
});
"""


def _run_tool(corpus: dict[str, str]) -> dict[str, dict]:
    with tempfile.TemporaryDirectory(dir=AGGREGATOR, prefix=".tmp-secret-form-") as tmp:
        script = Path(tmp) / "bridge.mjs"
        # Calea de import urcă un nivel, fiindcă scriptul stă într-un subdirector
        # temporar al agregatorului (ca `tsx` să se rezolve din node_modules).
        script.write_text(BRIDGE.replace('"./lib/register.ts"', '"../lib/register.ts"'),
                          encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [NODE, "--import", "tsx", str(script)],
            input=json.dumps(corpus), cwd=AGGREGATOR, capture_output=True,
            text=True, encoding="utf-8", timeout=180,
            env={**os.environ, "NO_COLOR": "1"},
        )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _server_value(raw: str) -> str | None:
    """Ce ar semna serverul, prin `load_secrets` REAL.

    Fișierul se scrie exact cum l-ar scrie operatorul: o linie
    `SENTINEL_SHIP_SECRET=<valoare>`. Dacă valoarea conține un sfârșit de linie,
    trunchierea care iese de aici NU e un artefact al testului — e chiar ce ar
    citi serverul.
    """
    from sentinel.config import load_secrets

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "secrets.env"
        path.write_text(f"SENTINEL_SHIP_SECRET={raw}\n", encoding="utf-8", newline="")
        os.chmod(path, 0o600)
        secrets = load_secrets(_SecurePath(path))
    return secrets.get("SENTINEL_SHIP_SECRET")


class _SecurePath(type(Path())):  # type: ignore[misc]
    """`Path` care raportează modul 0600.

    `load_secrets` refuză un `secrets.env` citibil de toată lumea — corect, și
    păzit de testul lui. Pe Windows `stat()` raportează 0666 pentru orice fișier,
    indiferent de `chmod`, deci fără shimul ăsta testul ar fi SĂRIT exact pe
    mașina pe care se scrie codul. Se schimbă doar biții de mod; conținutul și
    parsarea rămân cele reale.
    """

    def stat(self, **kwargs):  # noqa: D102
        st = super().stat(**kwargs)
        return os.stat_result((st.st_mode & ~0o777 | 0o600, *tuple(st)[1:]))


def test_what_the_tool_seals_is_what_the_server_signs():
    """Proprietatea: acceptat de instrument ⟹ serverul semnează exact octeții ăia.

    Eșecul pe care îl previne: o instanță înregistrată cu o cheie care diferă de
    a serverului printr-un caracter invizibil. Fiecare lot primește 401, la
    nesfârșit; pe server se vede ca o cheie greșită, iar cheia e corectă.
    """
    verdicts = _run_tool(CORPUS)
    assert set(verdicts) == set(CORPUS), "puntea nu a răspuns pentru tot corpusul"

    mismatches: list[str] = []
    accepted = 0
    for name, raw in CORPUS.items():
        verdict = verdicts[name]
        if not verdict["accepted"]:
            continue
        accepted += 1
        signed = _server_value(raw)
        if signed != verdict["sealed"]:
            mismatches.append(
                f"{name}: instrumentul sigilează {len(verdict['sealed'])} caractere, "
                f"serverul semnează {len(signed) if signed is not None else 'nimic'}"
            )

    assert not mismatches, "NEPOTRIVIRI TĂCUTE: " + " · ".join(mismatches)
    # Bucla goală ar trece verde — chiar tiparul din CLAUDE.md. Corpusul are
    # forme care TREBUIE acceptate, deci numărul nu poate fi zero.
    assert accepted >= 5, f"doar {accepted} valori acceptate; corpusul nu probează nimic"


def test_the_model_of_the_server_parser_is_the_parser():
    """`serverSecretForm` chiar descrie `load_secrets`, nu ce credem despre el.

    Testul de mai sus verifică doar valorile ACCEPTATE. Modelul e folosit și ca
    să se decidă refuzul, deci dacă el se rupe în direcția cealaltă — spune că
    serverul ar tăia ceva ce nu taie — instrumentul refuză valori bune, iar
    operatorul rămâne blocat fără să înțeleagă de ce.

    Se compară doar formele fără sfârșit de linie: pentru celelalte, valoarea pe
    care o citește serverul e tăiată de FORMATUL fișierului, nu de normalizarea
    valorii, iar modelul nu pretinde că descrie asta.
    """
    line_breaks = {"\n", "\r", "\v", "\f", chr(0x1C), chr(0x1D), chr(0x1E),
                   chr(0x85), chr(0x2028), chr(0x2029)}
    single_line = {name: raw for name, raw in CORPUS.items()
                   if not (line_breaks & set(raw))}
    assert len(single_line) >= 15, f"doar {len(single_line)} forme pe o linie"

    verdicts = _run_tool(single_line)
    wrong: list[str] = []
    for name, raw in single_line.items():
        signed = _server_value(raw)
        if verdicts[name]["model"] != signed:
            wrong.append(f"{name}: modelul spune {verdicts[name]['model']!r}, "
                         f"serverul citește {signed!r}")
    assert not wrong, "modelul nu e parserul: " + " · ".join(wrong)
