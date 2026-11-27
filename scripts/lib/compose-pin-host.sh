#!/usr/bin/env bash
#
# Fixează (pin) imaginile unui fișier docker-compose pe o versiune sau un digest, fără să schimbe ce rulează, și curăță drift-ul pe care îl
# creează. Rulează PE GAZDĂ, ca root, și nu e chemat direct: scripts/compose-pin.sh îl trimite prin `ssh ... sudo -n bash -s -- SUBCOMANDĂ ...`
# (stdin). Nimic nu se salvează pe gazdă, deci nu e nimic de verificat cu sumă după copiere.
#
#   compose-pin-host.sh show     --file F [--project P]                                   doar citire
#   compose-pin-host.sh pin      --file F --pin SERVICIU=REF [--pin ...] [--allow-version-change] [--allow-floating-tag]
#   compose-pin-host.sh recreate --file F --service S[,S]       repornește pe ACEEAȘI imagine serviciile cu drift de config-hash
#   compose-pin-host.sh restore  --file F [--backup B] [--force]  pune la loc copia scrisă de pin (doar dacă fișierul e încă cel scris de el)
#   (pin, recreate, restore:  [--plan] [--expect-sha256 H] — planul nu schimbă nimic, scrierea cere suma fișierului din plan)
#
# De ce există: `image: traefik` și `image: docker.n8n.io/n8nio/n8n` înseamnă `:latest`. `system-update.sh --phase containers` trage
# ce numește fișierul compose, deci în ziua în care n8n marchează 3.x «stable», o mentenanță de rutină face un upgrade major
# neplanificat. O etichetă scrisă în fișier închide ușa; dar o etichetă scrisă greșit (alta decât ce rulează) ar fi ea însăși
# upgrade-ul. De aceea `pin` e PUR implicit: REF se trage (`docker pull` pe EXACT acea referință; nu atinge containerele care
# rulează) și se refuză dacă ID-ul imaginii ei nu e ID-ul imaginii pe care containerul serviciului o rulează ACUM. Cu
# --allow-version-change se acceptă o versiune diferită. O etichetă flotantă (`stable`, `v3`, `v3.8`, `16-alpine`, `next`: orice nu e
# MAJOR.MINOR.PATCH sau digest) se refuză fără --allow-floating-tag: registrul o poate muta, deci nu fixează nimic.
#
# CE FACE FAZA containers DUPĂ UN PIN (citit din scripts/lib/system-update-containers.sh și dovedit de teste care rulează fazea reală):
# schimbarea șirului `image:` schimbă `com.docker.compose.config-hash` al serviciului (măsurat pe gazdă: traefik și n8n se schimbă, qpdf-api nu).
# Faza containers ține orice serviciu cu hash diferit ca `hold-config-drift` (su_pull_decision -> pull, apoi cfg_hash_changed != no), în afară de
# `--accept-drift <proiect>`. Consecințe:
#   * PIN PUR: cu --accept-drift pull-ul dă aceeași imagine (`up-to-date`, nimic recreat) și eticheta de hash NU se mai aliniază niciodată: drift
#     permanent. Ieșirea e `recreate`, care repornește containerul pe aceeași imagine și dovedește că eticheta a ajuns la hash-ul din fișier;
#   * VERSIUNE NOUĂ (--allow-version-change): faza containers o REȚINE; se aplică cu `system-update.sh --phase containers --accept-drift <proiect>`
#     (trage, vede altă imagine, recreează; prin recreare eticheta ajunge la zi) și rămâne în evidența lui (eticheta de rollback, baseline).
#     `recreate` REFUZĂ o schimbare de versiune: ar pune o imagine în afara acelei evidențe (proiectul ar fi ținut ca stale-baseline).
# `pin` tipărește pasul următor ADEVĂRAT, din hash-ul măsurat, nu din presupuneri.
#
# Ce se atinge în fișier: DOAR valoarea liniei `image:` a serviciului numit. Fișierul se citește și se scrie ca OCTEȚI (latin-1 dus-întors):
# comentariile, stilul ghilimelelor, indentarea, CRLF/LF și modul/proprietarul rămân. Locul liniei se află din blocul serviciului
# de sub `services:`; se refuză (nu se ghicește) la ancore (`&x`, `*x`, `<<:`), `extends`, `include`, `!reset/!override`, taburi în
# indentare, mai multe documente, un serviciu care apare de două ori sau într-o formă inline, o linie `image:` lipsă/dublă, o valoare
# cu `${...}` și orice valoare pe care compose o vede altfel decât o scrie fișierul.
#
# Dovada prin EFECT, nu prin intenție (un `mv` ieșit cu 0 nu dovedește ce vede compose):
#   1. `docker compose config --format json` ÎNAINTE (J0), apoi după (J1); J1 trebuie să fie J0 cu EXACT `image` schimbat la serviciile
#      țintă; orice altă diferență (în orice serviciu, rețea sau volum) e eșec. JSON-ul nu se tipărește niciodată (are secrete în
#      `environment`): la diferență se tipăresc doar CĂILE câmpurilor, niciodată valorile.
#   2. Eșec -> copia de rezervă se pune la loc automat, iar restaurarea se DOVEDEȘTE (suma fișierului = suma de dinainte).
#   3. `pin` nu recreează nimic: amprenta containerelor proiectului (id, StartedAt, RestartCount, imagine) se compară înainte/după (cod 4).
# Garda împotriva unei scrieri peste modificarea altcuiva: suma fișierului se măsoară la început și se re-verifică la scriere,
# înainte de `rename` (rămâne o fereastră de microsecunde între ultima verificare și `rename`; nu poate fi închisă fără blocare).
# Copia de rezervă (FIȘIER.pin-bak-<UTC>, 0600) se scrie ÎNAINTE de editare și i se verifică suma; lângă ea, FIȘIER.pin-bak-<UTC>.sums
# înregistrează suma de dinainte și suma pe care o va avea fișierul scris de unealtă: `restore` pune copia la loc doar dacă fișierul are
# încă suma scrisă (altfel ar șterge munca altcuiva) și doar dacă copia are încă suma de dinainte; --force sare peste prima, niciodată peste a doua.
# Editarea e atomică (temp în același director + rename, cu modul și proprietarul fișierului).
#
# `recreate`: doar pentru serviciile pe care fișierul le FIXEAZĂ, fără build:, care RULEAZĂ pe EXACT imaginea fixată și ai căror hash de
# configurație (eticheta containerului) ≠ `docker compose config --hash`. Rulează `docker compose up -d --no-deps --no-build --force-recreate S`
# (imaginea trebuie să existe local: `--no-build` nu e `--pull never`) și dovedește: container NOU (alt Id), imaginea cerută, eticheta de hash =
# hash-ul din fișier, running (și healthy dacă are healthcheck) într-un timp mărginit, apoi stabil o fereastră (aceleași reporniri, același
# StartedAt; ca verificarea faze containers: COMPOSE_PIN_STABLE_S=30, _WAIT_S=300, _POLL_S=5). Celelalte containere ale proiectului nu se ating
# (amprenta, cod 4). NU face rollback singur peste un serviciu care rulează: tipărește comanda exactă.
#
# Mediul și secretele: nicio valoare de mediu nu se tipărește (JSON-ul de config se parsează în python și nu iese din el); mesajele de
# eroare ale lui `docker compose config`/`up` NU se tipăresc (pot cita valori), doar codul lor.
#
# Coduri de ieșire: 0 totul dovedit (sau nimic de făcut); 1 refuzat / eșuat; 2 argumente greșite; 3 NU s-a putut măsura (nu e «bine»);
# 4 un container al proiectului s-a schimbat în timpul rulării.
#
# Opțiuni de mediu pentru teste (sudo curăță mediul, deci operatorul nu le poate seta pe gazdă): COMPOSE_PIN_TMPDIR (/run),
# COMPOSE_PIN_STABLE_S (30), COMPOSE_PIN_WAIT_S (300), COMPOSE_PIN_POLL_S (5).

set -euo pipefail
set +x
export PYTHONIOENCODING=utf-8

TMP_BASE="${COMPOSE_PIN_TMPDIR:-/run}"
STABLE_S="${COMPOSE_PIN_STABLE_S:-30}"
WAIT_S="${COMPOSE_PIN_WAIT_S:-300}"
POLL_S="${COMPOSE_PIN_POLL_S:-5}"
WAIT_TRIES=1
LABEL_PROJECT="com.docker.compose.project"
LABEL_SERVICE="com.docker.compose.service"
LABEL_FILES="com.docker.compose.project.config_files"
LABEL_HASH="com.docker.compose.config-hash"

FILE=""
PROJECT=""
PROJECT_OPT=""
ALLOW_VERSION_CHANGE=0
ALLOW_FLOATING=0
FORCE=0
PLAN=0
EXPECT_SHA=""
SERVICES=""
BACKUP_OPT=""
PINS=()
PURE_SVCS=()
CHANGE_SVCS=()
WORK=""
HASHES_OK=0
BACKUP_PATH=""
ELIG_RC=0
ELIG_CLASS=ok
ELIG_MSGS=()
ELIG_PLAN=()
declare -A S_IMAGE=() S_PIN=() S_WHY=()

# Mesajele nu au voie să omoare scriptul (SIGPIPE când ssh cade, sub `set -e`): fiecare își înghite eșecul.
say()  { printf '[.] %s\n' "$*" || true; }
good() { printf '[+] %s\n' "$*" || true; }
bad()  { printf '[x] %s\n' "$*" >&2 || true; }
refuse()  { bad "$*"; exit 1; }
unknown() { bad "$*"; bad "NECUNOSCUT: ceva n-a putut fi măsurat; asta NU e «bine»."; exit 3; }
is_digits() { [[ ${#1} -ge 1 && ${#1} -le 9 && "$1" =~ ^[0-9]+$ ]]; }

# ---------------------------------------------------------------------------------------------------------------
# Programul python (date, nu cod rulat aici): trimis cu `python3 -c`. Subcomenzi: show, edit, prove, restore, latest. Tipărește linii
# `ETICHETĂ<TAB>câmp...` pe stdout; un refuz e o linie `WHY<TAB>mesaj` și ieșire 1. Nu tipărește NICIODATĂ valori din JSON-ul de config.
# ---------------------------------------------------------------------------------------------------------------
read -r -d '' PIN_PY <<'PY' || true
import hashlib, json, os, re, stat as statmod, sys, tempfile

# pe Windows (testele), stdout-ul text ar scrie CRLF, iar bash ar citi un CR la coada sumei
sys.stdout.reconfigure(newline="\n")
sys.stderr.reconfigure(newline="\n")


def native(p):
    """Pe Windows (testele), bash dă căi MSYS (`/c/Users/..`); python vrea `C:/Users/..`. Pe Linux nu face nimic."""
    if os.name == "nt" and re.match(r"^/[A-Za-z]/", p):
        return p[1].upper() + ":" + p[2:]
    return p


def emit(*parts):
    sys.stdout.write("\t".join(str(p) for p in parts) + "\n")
    sys.stdout.flush()


def why(msg, code=1):
    emit("WHY", msg)
    sys.exit(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_json(p):
    with open(native(p), encoding="utf-8") as fh:
        return json.load(fh)


FULL_VERSION = re.compile(r"^v?[0-9]+\.[0-9]+\.[0-9]+([-+_.][A-Za-z0-9._+-]+)?$")


def classify(ref):
    """(fixat?, motiv). Fixat = digest sha256 întreg SAU o etichetă care e o versiune întreagă (MAJOR.MINOR.PATCH, cu `v` și sufix opționale).
    `latest`, eticheta goală, lipsa ei și orice etichetă flotantă (`stable`, `v3`, `v3.8`, `16-alpine`, `next`) NU fixează nimic."""
    if not ref:
        return "nu", "fără image:"
    if "@" in ref:
        digest = ref.split("@", 1)[1]
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            return "da", "digest"
        return "nu", "digest invalid"
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        if tag == "":
            return "nu", "etichetă goală"
        if tag.lower() == "latest":
            return "nu", "latest"
        if not FULL_VERSION.match(tag):
            return "nu", "etichetă flotantă (%s) — NEFIXAT: registrul o poate muta" % tag
        return "da", "etichetă " + tag
    return "nu", "fără etichetă (= latest)"


def cmd_show(argv):
    cfg = load_json(argv[0])
    for name in sorted(cfg.get("services") or {}):
        svc = cfg["services"][name]
        image = svc.get("image") or ""
        pinned, reason = classify(image)
        if "build" in svc:
            pinned, reason = "build", "construit local — nu se fixează aici (imaginea o face build-ul)"
        emit("SVC", name, image or "-", "da" if "build" in svc else "nu", pinned, reason)


def is_skippable(body):
    s = body.strip(" ")
    return s == "" or s.startswith("#")


def indent_of(body):
    return len(body) - len(body.lstrip(" "))


def code_part(body):
    """Linia fără șirurile citate și fără comentariul de la coadă: pe ea se caută ancore."""
    s = re.sub(r'"[^"]*"|\'[^\']*\'', '""', body)
    return re.split(r"(?:^|\s)#", s, maxsplit=1)[0]


def file_checks(text, bodies):
    if "\r" in text.replace("\r\n", ""):
        why("fișierul are un CR care nu face parte dintr-un CRLF; nu-l editez")
    seen_content = False
    for n, b in enumerate(bodies, 1):
        if re.match(r"^ *\t", b):
            why("linia %d: tab în indentare; YAML nu îl permite, iar eu n-aș ști unde e linia" % n)
        if is_skippable(b):
            continue
        if seen_content and (b.startswith("---") or b.startswith("...")):
            why("linia %d: mai multe documente YAML în același fișier; refuz" % n)
        seen_content = True
        code = code_part(b)
        if re.search(r"(^|[\s\[{,:-])[&*][A-Za-z0-9_]", code):
            why("linia %d: ancoră/alias YAML (&x sau *x); `image:` ar putea veni de altundeva, nu editez" % n)
        if re.search(r"<<\s*:", code):
            why("linia %d: cheie de îmbinare `<<:`; refuz" % n)
        if re.match(r"^\s*extends\s*:", code):
            why("linia %d: `extends`; imaginea poate veni din alt serviciu sau fișier, refuz" % n)
        if re.match(r"^include\s*:", code):
            why("linia %d: `include:` la rădăcină; imaginea poate veni din alt fișier, refuz" % n)
        if re.search(r"(^|\s)!(reset|override)\b", code):
            why("linia %d: etichetă `!reset`/`!override`; refuz" % n)


IMG = re.compile(r"""^( *image *:)( *)("([^"\\]*)"|'([^']*)'|([^\s#'"]+))( *(?:#.*)?)$""")
VALUE_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]*$")


def locate(bodies, svc):
    """Indexul liniei `image:` a serviciului `svc` și potrivirea ei. Refuză (WHY) la orice ambiguitate."""
    starts = [i for i, b in enumerate(bodies) if re.match(r"^services *: *(#.*)?$", b)]
    if len(starts) != 1:
        why("găsesc %d linii `services:` la rădăcină (cer exact una)" % len(starts))
    s = starts[0]
    child, end = None, len(bodies)
    for j in range(s + 1, len(bodies)):
        if is_skippable(bodies[j]):
            continue
        ind = indent_of(bodies[j])
        if ind == 0:
            end = j
            break
        if child is None:
            child = ind
    if child is None:
        why("blocul `services:` e gol")
    loose = re.compile(r"""^ {%d}(["']?)%s\1 *:""" % (child, re.escape(svc)))
    cands = [j for j in range(s + 1, end) if loose.match(bodies[j])]
    if len(cands) != 1:
        why("serviciul %s apare de %d ori sub services: (cer exact o dată)" % (svc, len(cands)))
    k = cands[0]
    if not re.match(r"^ {%d}%s *: *(#.*)?$" % (child, re.escape(svc)), bodies[k]):
        why("serviciul %s nu e scris în forma simplă (cheie citată, conținut inline sau ancoră); nu editez" % svc)
    stop, grand = end, None
    for j in range(k + 1, end):
        if is_skippable(bodies[j]):
            continue
        ind = indent_of(bodies[j])
        if ind <= child:
            stop = j
            break
        if grand is None:
            grand = ind
    if grand is None:
        why("serviciul %s n-are conținut" % svc)
    imgs = [j for j in range(k + 1, stop) if re.match(r"^ {%d}image *:" % grand, bodies[j])]
    if len(imgs) != 1:
        why("serviciul %s are %d linii `image:` la nivelul lui (cer exact una)" % (svc, len(imgs)))
    m = IMG.match(bodies[imgs[0]])
    if not m:
        why("linia %d (image: a lui %s) nu are forma `image: valoare` (bloc, etichetă YAML sau valoare neobișnuită); nu editez" % (imgs[0] + 1, svc))
    value = m.group(4) if m.group(4) is not None else m.group(5) if m.group(5) is not None else m.group(6)
    if "$" in value:
        why("linia %d: imaginea lui %s folosește o variabilă (%s); valoarea ei nu e în fișier, nu editez" % (imgs[0] + 1, svc, "${...}"))
    if not VALUE_OK.match(value):
        why("linia %d: valoarea imaginii lui %s are o formă neobișnuită; nu editez" % (imgs[0] + 1, svc))
    return imgs[0], m, value


def prepare_tmp(path, data, st):
    """Fișier temporar în ACELAȘI director, cu modul și proprietarul fișierului țintă; întoarce calea lui."""
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".pin-tmp-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            if hasattr(os, "fchmod"):
                os.fchmod(fh.fileno(), statmod.S_IMODE(st.st_mode))
            if hasattr(os, "fchown") and (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
                os.fchown(fh.fileno(), st.st_uid, st.st_gid)
            os.fsync(fh.fileno())
    except BaseException as exc:
        os.unlink(tmp)
        why("nu pot pregăti fișierul temporar (%s); nimic nu s-a schimbat" % type(exc).__name__)
    return tmp


def drop(*paths):
    for x in paths:
        try:
            os.unlink(x)
        except OSError:
            pass


def fsync_dir(path):
    if os.name != "nt":
        fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def read_bytes(p):
    with open(p, "rb") as fh:
        return fh.read()


def same_meta(a, b):
    if os.name == "nt":
        return True
    return (statmod.S_IMODE(a.st_mode), a.st_uid, a.st_gid) == (statmod.S_IMODE(b.st_mode), b.st_uid, b.st_gid)


def cmd_edit(argv):
    mode, path, json0, backup, expect = argv[:5]
    pins = argv[5:]
    p = native(path)
    if os.path.islink(p):
        why("%s e o legătură simbolică; `rename` ar înlocui legătura, nu ținta" % path)
    raw = read_bytes(p)
    h0 = sha(raw)
    if mode == "write" and h0 != expect:
        why("fișierul s-a schimbat între citire și scriere (suma de acum diferă de cea măsurată); nu scriu nimic")
    text = raw.decode("latin-1")
    lines = text.split("\n")
    bodies = [l[:-1] if l.endswith("\r") else l for l in lines]
    file_checks(text, bodies)
    services = load_json(json0).get("services") or {}
    changes, diff = [], []
    for spec in pins:
        name, _, ref = spec.partition("=")
        if name not in services:
            why("serviciul %s nu există în configurația compose (există: %s)" % (name, ", ".join(sorted(services)) or "niciunul"))
        if "build" in services[name]:
            why("serviciul %s are `build:`: imaginea lui se construiește local, iar o etichetă fixată peste ea e altă problemă (pe ce rulează build-ul, nu pe ce trage pull-ul); nu fixez" % name)
        idx, m, current = locate(bodies, name)
        if services[name].get("image") != current:
            why("fișierul scrie imaginea %s pentru %s, dar compose o vede ca %s; nu editez" % (current, name, services[name].get("image")))
        if current == ref:
            emit("NOOP", name, ref)
            continue
        tok = m.group(3)
        newtok = ('"%s"' % ref) if tok.startswith('"') else ("'%s'" % ref) if tok.startswith("'") else ref
        body = bodies[idx][:m.start(3)] + newtok + bodies[idx][m.end(3):]
        changes.append((idx, name, lines[idx], body + ("\r" if lines[idx].endswith("\r") else "")))
        emit("CHANGE", name, idx + 1, current, ref)
        diff += ["@@ -%d +%d @@" % (idx + 1, idx + 1), "-" + bodies[idx], "+" + body]
    emit("SHA256", h0)
    for d in diff:
        emit("DIFF", d)
    if not changes or mode == "dry":
        return
    new_lines = list(lines)
    for idx, _, _, new in changes:
        new_lines[idx] = new
    new_bytes = "\n".join(new_lines).encode("latin-1")
    st = os.stat(p)
    bak = None
    for n in range(0, 10):
        suffix = "" if n == 0 else "-%d" % n
        try:
            fd = os.open(native(backup) + suffix, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        bak = native(backup) + suffix
        shown = backup + suffix
        break
    if bak is None:
        why("nu pot crea copia de rezervă (%s* există deja); nu scriu nimic" % backup)
    with os.fdopen(fd, "wb") as fh:
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    if sha(read_bytes(bak)) != h0 or (os.name != "nt" and statmod.S_IMODE(os.stat(bak).st_mode) != 0o600):
        os.unlink(bak)
        why("copia de rezervă n-a ieșit identică sau nu e 0600; am șters-o și nu scriu nimic")
    emit("BACKUP", shown)
    rec = bak + ".sums"
    with open(rec, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("before=%s\nafter=%s\n" % (h0, sha(new_bytes)))
    if os.name != "nt":
        os.chmod(rec, 0o600)
    try:
        tmp = prepare_tmp(p, new_bytes, st)
    except BaseException as exc:
        # fie `why` din prepare_tmp (SystemExit), fie mkstemp însuși (OSError: director plin, fără drepturi): în ambele cazuri fișierul nu s-a atins,
        # deci copia și înregistrarea pe care tocmai le-am scris n-au ce căuta lângă el
        drop(bak, rec)
        if isinstance(exc, SystemExit):
            raise
        why("nu pot crea fișierul temporar lângă țintă (%s); nimic nu s-a schimbat, copia de rezervă ștearsă" % type(exc).__name__)
    if sha(read_bytes(p)) != h0:
        drop(tmp, bak, rec)
        why("fișierul s-a schimbat chiar înainte de scriere; nu scriu nimic (copia de rezervă ștearsă)")
    os.replace(tmp, p)
    emit("REPLACED")
    fsync_dir(p)
    st2 = os.stat(p)
    if sha(read_bytes(p)) != sha(new_bytes) or not same_meta(st, st2):
        why("după scriere, fișierul nu are octeții sau modul/proprietarul așteptate", 7)
    emit("SHA256_AFTER", sha(new_bytes))
    emit("META", "%o" % statmod.S_IMODE(st2.st_mode), "%s:%s" % (getattr(st2, "st_uid", "-"), getattr(st2, "st_gid", "-")))


def diff_paths(a, b, prefix, acc):
    """Căile (NU valorile) la care a și b diferă."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                acc.append("%s.%s (%s)" % (prefix, k, "lipsește după" if k not in b else "apărut după"))
            else:
                diff_paths(a[k], b[k], prefix + "." + k, acc)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            diff_paths(x, y, "%s[%d]" % (prefix, i), acc)
    elif a != b:
        acc.append(prefix)


def cmd_prove(argv):
    before, after = load_json(argv[0]), load_json(argv[1])
    expected = json.loads(json.dumps(before))
    for spec in argv[2:]:
        name, _, ref = spec.partition("=")
        expected["services"][name]["image"] = ref
    acc = []
    diff_paths(expected, after, "config", acc)
    for name, _, ref in (s.partition("=") for s in argv[2:]):
        got = (after.get("services") or {}).get(name, {}).get("image")
        emit("IMAGE", name, "ok" if got == ref else "DIFERĂ")
    if acc:
        for a in acc[:20]:
            emit("DIFF", a)
        sys.exit(1)


def read_sums(bak):
    try:
        text = read_bytes(bak + ".sums").decode("utf-8")
    except OSError:
        return None
    return dict(line.split("=", 1) for line in text.split() if "=" in line)


def cmd_latest(argv):
    path = argv[0]
    import glob
    found = sorted(g for g in glob.glob(native(path) + ".pin-bak-*") if not g.endswith(".sums"))
    if not found:
        why("nu există nicio copie de rezervă (%s.pin-bak-*)" % path)
    emit("BACKUP", path + found[-1][len(native(path)):])


def cmd_restore(argv):
    """restore MOD FIȘIER COPIE [dry]. MOD `strict`: fișierul trebuie să aibă încă suma scrisă de unealtă (înregistrată în COPIE.sums) și copia
    suma de dinainte; `force`: sare peste prima condiție, niciodată peste a doua (o copie stricată nu se pune peste nimic)."""
    mode, path, backup = argv[:3]
    dry = "dry" in argv[3:]
    p, b = native(path), native(backup)
    if not os.path.isfile(b):
        why("copia de rezervă %s nu există" % backup)
    data = read_bytes(b)
    h = sha(data)
    sums = read_sums(b)
    if sums is not None and sums.get("before") != h:
        why("copia de rezervă nu mai are suma înregistrată (s-a modificat); n-o pun peste fișier, nici cu --force")
    if mode != "force":
        if sums is None:
            why("lângă copie lipsește înregistrarea %s.sums: nu știu ce a scris unealta; nu suprascriu (--force dacă ești sigur)" % backup)
        cur = sha(read_bytes(p)) if os.path.exists(p) else None
        if cur != sums.get("after"):
            why("fișierul s-a schimbat după ce l-a scris unealta (suma de acum nu e cea înregistrată); nu-l suprascriu, ar șterge munca altcuiva (--force dacă ești sigur)")
    if dry:
        emit("CHECK_OK", h)
        return
    st = os.stat(p) if os.path.exists(p) else os.stat(b)
    tmp = prepare_tmp(p, data, st)
    os.replace(tmp, p)
    fsync_dir(p)
    if sha(read_bytes(p)) != h or not same_meta(st, os.stat(p)):
        why("după restaurare, fișierul nu are suma/modul de dinainte", 1)
    emit("RESTORED", h)


try:
    {"show": cmd_show, "edit": cmd_edit, "prove": cmd_prove, "restore": cmd_restore, "latest": cmd_latest}[sys.argv[1]](sys.argv[2:])
except SystemExit:
    raise
except Exception as exc:
    emit("WHY", "eroare neașteptată în program: %s" % type(exc).__name__)
    sys.exit(3)
PY

# ---------------------------------------------------------------------------------------------------------------

is_digits64() { [[ "$1" =~ ^[0-9a-f]{64}$ ]]; }

# O etichetă e FIXATĂ doar dacă e o versiune întreagă: MAJOR.MINOR.PATCH în cifre (cu `v` în față și un sufix ca -alpine, opționale), sau un
# digest. `stable`, `v3`, `v3.8`, `16-alpine`, `beta`, `next` sunt FLOTANTE: registrul le mută, deci un «pin» pe ele nu fixează nimic.
FULL_VERSION_RE='^v?[0-9]+\.[0-9]+\.[0-9]+([-+_.][A-Za-z0-9._+-]+)?$'

# REF = nume[:etichetă][@sha256:...]. Setează REF_WHY și întoarce 1 dacă nu e un REF valid; setează REF_FLOATING=1 pentru o etichetă flotantă
# (apelantul o refuză fără --allow-floating-tag). `latest`, eticheta goală și lipsa etichetei (care înseamnă latest) sunt refuzate aici:
# un pin care nu fixează nimic nu e un pin.
split_ref() {
    local ref="$1" rest last tag="" name digest=""
    REF_WHY=""; REF_FLOATING=0
    if [[ ${#ref} -gt 255 || ! "$ref" =~ ^[a-z0-9][A-Za-z0-9._:/@-]*$ ]]; then REF_WHY="caractere nepermise (sau prea lung)"; return 1; fi
    rest="$ref"
    if [[ "$rest" == *@* ]]; then
        digest="${rest#*@}"; rest="${rest%%@*}"
        [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { REF_WHY="digestul trebuie să fie sha256:<64 cifre hex>"; return 1; }
    fi
    last="${rest##*/}"
    if [[ "$last" == *:* ]]; then
        tag="${last##*:}"; name="${rest%:*}"
        [[ -n "$tag" ]] || { REF_WHY="eticheta e goală (după ':' nu urmează nimic)"; return 1; }
        [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { REF_WHY="etichetă invalidă"; return 1; }
        [[ "${tag,,}" != latest ]] || { REF_WHY="\`latest\` nu fixează nimic"; return 1; }
    else
        name="$rest"
    fi
    [[ -n "$name" && ! "$name" =~ (//|\.\.|:$|:/) && "$name" =~ ^[a-z0-9][a-z0-9._/:-]*[a-z0-9]$|^[a-z0-9]$ ]] || { REF_WHY="numele imaginii e invalid"; return 1; }
    [[ -n "$tag" || -n "$digest" ]] || { REF_WHY="nu are nici etichetă, nici digest (fără etichetă înseamnă latest)"; return 1; }
    if [[ -z "$digest" && ! "$tag" =~ $FULL_VERSION_RE ]]; then REF_FLOATING=1; fi
    return 0
}

usage_die() {
    bad "$*"
    bad "folosire: show --file F | pin --file F --pin SERVICIU=REF [--pin ...] [--allow-version-change] [--allow-floating-tag] [--plan] [--expect-sha256 H] | recreate --file F --service S[,S] [--plan] [--expect-sha256 H] | restore --file F [--backup B] [--force] [--plan] [--expect-sha256 H]   (toate: [--project P])"
    exit 2
}

valid_file() { [[ ${#1} -le 200 && "$1" =~ ^/[A-Za-z0-9._/@+-]+$ && ! "$1" =~ (^|/)\.\.(/|$) && "$1" != */ ]]; }
valid_service() { [[ ${#1} -le 64 && "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; }
valid_project() { [[ ${#1} -le 64 && "$1" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; }

PYOUT=""
# Rulează programul python; ieșirea merge în $PYOUT, iar liniile WHY se tipăresc ca [x]. Întoarce codul programului.
run_py() {
    local rc=0 tag rest
    PYOUT="$WORK/py.out"
    python3 -c "$PIN_PY" "$@" >"$PYOUT" 2>"$WORK/py.err" || rc=$?
    while IFS=$'\t' read -r tag rest; do
        [[ "$tag" == WHY ]] && bad "$rest"
    done <"$PYOUT"
    # fără WHY nu avem un motiv; ultima linie a erorii python (tip + loc, nu conținutul JSON-ului) ajută la diagnostic
    if [[ $rc -ne 0 && ! -s "$PYOUT" ]]; then bad "programul python a eșuat fără mesaj (cod $rc): $(tail -n 1 "$WORK/py.err" | cut -c1-200)"; fi
    return "$rc"
}

cleanup() {
    [[ -n "$WORK" && -d "$WORK" ]] && rm -rf -- "$WORK"
    return 0
}

# Fișierul de config al proiectului, ca JSON, în $1. Mesajul lui compose NU se tipărește (poate cita valori); doar codul.
compose_json() {
    local rc=0
    docker compose -p "$PROJECT" -f "$FILE" config --format json >"$1" 2>"$WORK/compose.err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        bad "docker compose config a eșuat (cod $rc); mesajul nu se tipărește fiindcă poate cita valori din configurație. Rulează-l singur pe gazdă."
        return 1
    fi
    [[ -s "$1" ]] || { bad "docker compose config n-a dat nimic"; return 1; }
    return 0
}

# Hash-urile de configurație ale serviciilor (`serviciu hash` pe linie) în $1. Fără --hash (compose vechi) sau la eroare întoarce 1.
config_hashes() { docker compose -p "$PROJECT" -f "$FILE" config --hash '*' >"$1" 2>"$WORK/hash.err"; }
hash_of() { awk -v s="$2" '$1 == s { print $2; exit }' "$1"; }
file_sum() { sha256sum "$FILE" | cut -d' ' -f1; }

# Numele proiectului: dat, sau din eticheta containerelor care au fost create din ACEST fișier. Un fișier fără containere nu are un
# nume măsurabil: se cade pe numele implicit al lui compose (directorul), cu o avertizare.
detect_project() {
    local found n=0 p first=""
    if [[ -n "$PROJECT_OPT" ]]; then PROJECT="$PROJECT_OPT"; return 0; fi
    found="$(docker ps -a --filter "label=${LABEL_FILES}=${FILE}" --format "{{.Label \"${LABEL_PROJECT}\"}}")" || unknown "nu pot lista containerele"
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        if [[ "$p" != "$first" ]]; then n=$((n + 1)); first="${first:-$p}"; fi
    done < <(sort -u <<<"$found")
    if [[ $n -gt 1 ]]; then unknown "fișierul $FILE a creat containere în mai multe proiecte; dă --project"; fi
    if [[ $n -eq 1 ]]; then PROJECT="$first"; return 0; fi
    PROJECT="$(basename "$(dirname "$FILE")" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9_\n-' '_')"
    valid_project "$PROJECT" || unknown "niciun container nu a fost creat din $FILE și nu pot deduce numele proiectului; dă --project"
    say "niciun container nu a fost creat din $FILE: folosesc numele implicit al proiectului ($PROJECT)"
}

service_containers() {
    docker ps -a --filter "label=${LABEL_PROJECT}=${PROJECT}" --filter "label=${LABEL_SERVICE}=$1" --format '{{.Names}}'
}

# Amprenta containerelor proiectului: (nume, id, StartedAt, RestartCount, imagine), fără cele numite în $1 (spațiu-separate). Schimbată =
# ceva a recreat/repornit. `pin`/`restore` n-au voie să schimbe NICIUN container; `recreate` doar pe cele numite.
fingerprint() {
    local names n line out="" skip=" ${1:-} "
    names="$(docker ps -a --filter "label=${LABEL_PROJECT}=${PROJECT}" --format '{{.Names}}' | sort)" || return 1
    while IFS= read -r n; do
        [[ -n "$n" && "$skip" != *" $n "* ]] || continue
        line="$(docker container inspect --format '{{.Id}} {{.State.StartedAt}} {{.RestartCount}} {{.Image}}' "$n")" || return 1
        out+="$n $line"$'\n'
    done <<<"$names"
    printf '%s' "$out"
}

common_checks() {
    [[ -n "$FILE" ]] || usage_die "lipsește --file"
    valid_file "$FILE" || usage_die "--file refuzat (cer o cale absolută, fără .., fără caractere speciale): \"$FILE\""
    command -v docker >/dev/null || unknown "docker lipsește de pe gazdă"
    command -v python3 >/dev/null || unknown "python3 lipsește de pe gazdă"
    docker version --format '{{.Server.Version}}' >/dev/null || unknown "daemonul docker nu răspunde"
    [[ ! -L "$FILE" ]] || refuse "$FILE e o legătură simbolică; nu o editez"
    [[ -f "$FILE" ]] || refuse "$FILE nu e un fișier obișnuit sau nu există"
    [[ -r "$FILE" ]] || unknown "nu pot citi $FILE"
    WORK="$(mktemp -d "${TMP_BASE%/}/compose-pin.XXXXXX")" || unknown "nu pot crea un director temporar în $TMP_BASE"
    chmod 700 "$WORK"
    detect_project
}

# Drift-ul unui container: eticheta lui de hash față de hash-ul pe care fișierul îl dă ACUM serviciului ($1 = fișierul de hash-uri, $2 = serviciu,
# $3 = container). yes | no | unknown. Același sens ca `cfg_hash_changed` din system-update-containers.sh (care ține serviciul ca hold-config-drift).
container_drift() {
    local want lab
    want="$(hash_of "$1" "$2")"
    lab="$(docker container inspect --format "{{index .Config.Labels \"${LABEL_HASH}\"}}" "$3")" || { echo unknown; return 0; }
    if [[ -z "$want" || -z "$lab" ]]; then echo unknown; elif [[ "$want" == "$lab" ]]; then echo no; else echo yes; fi
}

# ---------------------------------------------------------------------------------------------------------------

cmd_show() {
    local tag name image build pinned reason n=0 np=0 nb=0 cn state img ids hash_ok=0 drift
    compose_json "$WORK/j0.json" || unknown "nu pot citi configurația proiectului $PROJECT din $FILE"
    run_py show "$WORK/j0.json" || unknown "nu pot interpreta configurația"
    if config_hashes "$WORK/hash0.txt"; then hash_ok=1; fi
    say "fișier: $FILE   proiect: $PROJECT"
    while IFS=$'\t' read -r tag name image build pinned reason; do
        [[ "$tag" == SVC ]] || continue
        n=$((n + 1))
        case "$pinned" in
            da)    np=$((np + 1)); printf '[+] %s: FIXAT\n' "$name" || true ;;
            build) nb=$((nb + 1)); printf '[=] %s: construit local — nu se fixează aici\n' "$name" || true ;;
            *)     printf '[!] %s: NEFIXAT\n' "$name" || true ;;
        esac
        printf '      image scris : %s\n      build       : %s\n      fixat       : %s — %s\n' "$image" "$build" "$pinned" "$reason" || true
        ids="$(service_containers "$name")" || unknown "nu pot lista containerele serviciului $name"
        if [[ -z "$ids" ]]; then printf '      container   : niciunul\n' || true; fi
        while IFS= read -r cn; do
            [[ -n "$cn" ]] || continue
            state="$(docker container inspect --format '{{.State.Status}}' "$cn")" || unknown "nu pot citi containerul $cn"
            img="$(docker container inspect --format '{{.Image}}' "$cn")" || unknown "nu pot citi imaginea containerului $cn"
            printf '      container   : %s (%s) imagine %s\n' "$cn" "$state" "$img" || true
            printf '      RepoDigests : %s\n' "$(docker image inspect --format '{{range .RepoDigests}}{{.}} {{end}}' "$img" || echo '?')" || true
            if [[ $hash_ok -eq 1 ]]; then drift="$(container_drift "$WORK/hash0.txt" "$name" "$cn")"; else drift=unknown; fi
            case "$drift" in
                no)  printf '      config-hash : la zi (eticheta containerului = hash-ul din fișier)\n' || true ;;
                yes) printf '      config-hash : DRIFT (eticheta containerului ≠ hash-ul din fișier): faza containers îl reține ca hold-config-drift\n' || true ;;
                *)   printf '      config-hash : necunoscut (n-am putut compara)\n' || true ;;
            esac
        done <<<"$ids"
    done <"$PYOUT"
    say "$n servicii: $np fixate, $nb construite local, $((n - np - nb)) nefixate"
}

# ---------------------------------------------------------------------------------------------------------------

# Imaginea pe care o rulează serviciul acum și cea numită de REF. Setează RESOLVE_OK=0 la refuz (apelantul adună refuzurile), PURE_SVCS/CHANGE_SVCS
# la acceptare.
resolve_one() {
    local svc="$1" ref="$2" names cn running=() ids new_id rc=0 st stopped="" what_is what_not
    names="$(service_containers "$svc")" || unknown "nu pot lista containerele serviciului $svc"
    while IFS= read -r cn; do
        [[ -n "$cn" ]] || continue
        running+=("$(docker container inspect --format '{{.Image}}' "$cn")") || unknown "nu pot citi imaginea containerului $cn"
        st="$(docker container inspect --format '{{.State.Status}}' "$cn")" || unknown "nu pot citi starea containerului $cn"
        [[ "$st" == running ]] || stopped="$st"
    done <<<"$names"
    if [[ -n "$stopped" ]]; then
        what_is="EXACT imaginea containerului (oprit: $stopped)"; what_not="imaginea containerului (oprit: $stopped)"
    else
        what_is="EXACT imaginea care rulează acum"; what_not="imaginea care rulează"
    fi
    say "trag $ref (docker pull pe EXACT această referință; nu atinge containerele care rulează)"
    docker pull -q "$ref" >/dev/null 2>"$WORK/pull.err" || rc=$?
    if [[ $rc -ne 0 ]]; then
        if grep -qiE 'not found|manifest unknown|denied|requested access|invalid reference|repository does not exist' "$WORK/pull.err"; then
            bad "$svc: $ref nu poate fi tras ($(head -n 1 "$WORK/pull.err" | cut -c1-200))"; RESOLVE_OK=0; return 0
        fi
        unknown "$svc: pull-ul lui $ref a eșuat din alt motiv ($(head -n 1 "$WORK/pull.err" | cut -c1-200)); nu pot dovedi nimic"
    fi
    new_id="$(docker image inspect --format '{{.Id}}' "$ref")" || unknown "$svc: nu pot citi imaginea $ref după pull"
    [[ "$new_id" =~ ^sha256:[0-9a-f]{64}$ ]] || unknown "$svc: id de imagine neașteptat pentru $ref"
    ids="$(printf '%s\n' ${running[@]+"${running[@]}"} | sort -u | sed '/^$/d')"
    if [[ -z "$ids" ]]; then
        if [[ $ALLOW_VERSION_CHANGE -eq 1 ]]; then
            say "$svc: nu are container; nimic de comparat (--allow-version-change)"; CHANGE_SVCS+=("$svc"); return 0
        fi
        unknown "$svc: niciun container; nu pot dovedi că pin-ul nu schimbă ce rulează (dacă vrei oricum, --allow-version-change)"
    fi
    if [[ "$ids" == "$new_id" ]]; then
        good "$svc: $ref este $what_is (${new_id:0:19}…); pin-ul nu schimbă nimic din ce rulează"
        PURE_SVCS+=("$svc")
        return 0
    fi
    if [[ $ALLOW_VERSION_CHANGE -eq 1 ]]; then
        VERSION_CHANGE=1
        CHANGE_SVCS+=("$svc")
        say "$svc: VERSIUNE DIFERITĂ (acceptată cu --allow-version-change): ${what_not} $(tr '\n' ' ' <<<"$ids")→ $ref este $new_id"
        return 0
    fi
    bad "$svc: $ref NU este $what_not ($(tr '\n' ' ' <<<"$ids")e a containerului; $ref = $new_id). Un pin pur nu schimbă ce rulează, deci refuz. Dacă vrei versiunea aceea, --allow-version-change (nimic nu se recreează acum; faza containers o REȚINE ca hold-config-drift până o aplici cu --accept-drift ${PROJECT})."
    RESOLVE_OK=0
}

# Tabelul serviciilor din JSON-ul de config ($1): imaginea scrisă, fixat?, motiv. Același tabel și același predicat (recreate_eligibility) pentru poarta
# lui `recreate` ȘI pentru sfatul pe care îl tipărește `pin`: sfatul nu poate promite ce poarta ar refuza.
load_service_table() {
    local tag name image build pinned reason
    S_IMAGE=(); S_PIN=(); S_WHY=()
    run_py show "$1" || return 1
    while IFS=$'\t' read -r tag name image build pinned reason; do
        [[ "$tag" == SVC ]] || continue
        S_IMAGE[$name]="$image"; S_PIN[$name]="$pinned"; S_WHY[$name]="$reason"
    done <"$PYOUT"
}

elig_set() { ELIG_RC="$1"; ELIG_CLASS="$2"; ELIG_MSGS+=("$3"); }

# UN SINGUR predicat: «poate `recreate` să repornească serviciul $1, acum?». Chemat de `recreate` (poarta lui) și de `pin` (după scriere, pe starea REALĂ
# de atunci: fișierul scris, imaginea trasă, containerul de acum), ca `pin` să tipărească `recreate` doar dacă exact această funcție îl acceptă.
# $1 = serviciu, $2 = fișierul de hash-uri al fișierului compose. Rezultat: ELIG_RC (0 acceptat, 1 refuzat, 3 nu pot judeca), ELIG_CLASS (ok | unknown-service |
# build | floating | not-pinned | no-image-local | no-hash | no-container | stopped | version | no-label | nodrift | unreadable), ELIG_MSGS (motivul), ELIG_PLAN (ce se
# va întâmpla, pentru confirmare). Alegerea de proiectare: un pin flotant (--allow-floating-tag) NU e eligibil pentru `recreate` (poarta cere un serviciu FIXAT),
# deci `pin` spune asta și dă alternativele adevărate.
recreate_eligibility() {
    local svc="$1" hashfile="$2" ref_id want names cn st img lab
    ELIG_RC=0; ELIG_CLASS=ok; ELIG_MSGS=(); ELIG_PLAN=()
    if [[ -z "${S_IMAGE[$svc]+x}" ]]; then
        elig_set 1 unknown-service "$svc: nu există în configurația compose (există: $(printf '%s\n' "${!S_IMAGE[@]}" | sort | tr '\n' ' '))"; return 0
    fi
    case "${S_PIN[$svc]}" in
        build) elig_set 1 build "$svc: are build: (construit local); se reface cu system-update.sh --rebuild, nu de aici"; return 0 ;;
        da) ;;
        *)
            if [[ "${S_WHY[$svc]}" == "etichetă flotantă"* ]]; then ELIG_CLASS=floating; else ELIG_CLASS=not-pinned; fi
            elig_set 1 "$ELIG_CLASS" "$svc: imaginea scrisă în fișier (${S_IMAGE[$svc]}) nu e fixată (${S_WHY[$svc]}); fixează-o întâi cu \`pin\`. \`recreate\` repornește doar ce fișierul fixează"
            return 0 ;;
    esac
    ref_id="$(docker image inspect --format '{{.Id}}' "${S_IMAGE[$svc]}")" || {
        elig_set 1 no-image-local "$svc: imaginea ${S_IMAGE[$svc]} nu există local; \`up --no-build\` ar încerca s-o tragă. Rulează întâi \`pin\` (care o trage)"; return 0; }
    want="$(hash_of "$hashfile" "$svc")"
    [[ -n "$want" ]] || { elig_set 3 no-hash "$svc: nu pot citi hash-ul din fișier"; return 0; }
    names="$(service_containers "$svc")" || { elig_set 3 unreadable "$svc: nu pot lista containerele"; return 0; }
    [[ -n "$names" ]] || { elig_set 1 no-container "$svc: niciun container; \`recreate\` nu creează servicii noi, doar repornește cele care rulează"; return 0; }
    while IFS= read -r cn; do
        [[ -n "$cn" ]] || continue
        st="$(docker container inspect --format '{{.State.Status}}' "$cn")" || { elig_set 3 unreadable "$cn: nu-l pot citi"; return 0; }
        img="$(docker container inspect --format '{{.Image}}' "$cn")" || { elig_set 3 unreadable "$cn: nu-i pot citi imaginea"; return 0; }
        lab="$(docker container inspect --format "{{index .Config.Labels \"${LABEL_HASH}\"}}" "$cn")" || { elig_set 3 unreadable "$cn: nu-i pot citi eticheta de hash"; return 0; }
        if [[ "$st" != running ]]; then elig_set 1 stopped "$cn: nu rulează ($st); \`recreate\` nu pornește servicii oprite"; return 0; fi
        if [[ "$img" != "$ref_id" ]]; then
            elig_set 1 version "$cn: rulează $img, dar fișierul fixează ${S_IMAGE[$svc]} = $ref_id: e o SCHIMBARE DE VERSIUNE, nu un drift de configurație. \`recreate\` n-o face (ar pune o imagine nouă în afara evidenței system-update și proiectul ar fi ținut ca stale-baseline). Folosește system-update.sh --phase containers --accept-drift ${PROJECT}"
            return 0
        fi
        if [[ -z "$lab" ]]; then elig_set 3 no-label "$cn: n-are etichetă de hash (nu l-a creat compose?); nu pot judeca drift-ul"; return 0; fi
        if [[ "$lab" == "$want" ]]; then elig_set 1 nodrift "$cn: nu are drift (eticheta de hash = hash-ul din fișier); nimic de recreat"; return 0; fi
        ELIG_PLAN+=("$svc: container $cn (running), imagine ${img:0:19}… = ${S_IMAGE[$svc]}; hash ${lab:0:12}… → ${want:0:12}…: va fi OPRIT și recreat pe aceeași imagine (indisponibilitate de câteva secunde)")
    done <<<"$names"
}

# Predicatul pentru o VERSIUNE NOUĂ: «ar recrea faza containers serviciul $1 cu --accept-drift?». Oglindește su_pull_decision din system-update-lib.sh pe
# faptele de ACUM (faza le ia din baseline: dacă între timp s-a mutat o etichetă sau s-a făcut alt baseline, decizia ei poate diferi; asta nu se poate
# măsura de aici): containerul rulează; numele cu care a fost creat nu e un ID gol (skip-bare-id); imaginea din fișier există local (skip-no-image) și a
# venit dintr-un registru, RepoDigests > 0 (skip-local); eticheta numelui de creare arată imaginea care RULEAZĂ (hold-moved-tag). Aceleași clase ca ELIG_CLASS.
accept_drift_eligibility() {
    local svc="$1" ref="${S_IMAGE[$svc]:-}" names cn st cfg cfg_id img ndig
    ELIG_RC=0; ELIG_CLASS=ok; ELIG_MSGS=(); ELIG_PLAN=()
    names="$(service_containers "$svc")" || { elig_set 3 unreadable "$svc: nu pot lista containerele"; return 0; }
    [[ -n "$names" ]] || { elig_set 1 no-container "$svc: nu are container; faza containers lucrează doar pe serviciile care rulau la baseline"; return 0; }
    ndig="$(docker image inspect --format '{{len .RepoDigests}}' "$ref")" || { elig_set 1 no-image-local "$svc: imaginea $ref nu există local (skip-no-image)"; return 0; }
    [[ "$ndig" =~ ^[0-9]+$ ]] || { elig_set 3 unreadable "$svc: nu pot citi RepoDigests pentru $ref"; return 0; }
    (( ndig > 0 )) || { elig_set 1 local-only "$svc: $ref n-a venit niciodată dintr-un registru (RepoDigests gol): faza containers o sare (skip-local)"; return 0; }
    while IFS= read -r cn; do
        [[ -n "$cn" ]] || continue
        st="$(docker container inspect --format '{{.State.Status}}' "$cn")" || { elig_set 3 unreadable "$cn: nu-l pot citi"; return 0; }
        [[ "$st" == running ]] || { elig_set 1 stopped "$cn: nu rulează ($st); faza containers nu atinge ce nu rula la baseline"; return 0; }
        cfg="$(docker container inspect --format '{{.Config.Image}}' "$cn")" || { elig_set 3 unreadable "$cn: nu-i pot citi numele imaginii"; return 0; }
        if [[ "$cfg" =~ ^(sha256:)?[0-9a-f]{12,64}$ ]]; then elig_set 1 bare-id "$cn: a fost creat dintr-un ID de imagine gol ($cfg): nu există o etichetă de tras (skip-bare-id)"; return 0; fi
        img="$(docker container inspect --format '{{.Image}}' "$cn")" || { elig_set 3 unreadable "$cn: nu-i pot citi imaginea"; return 0; }
        cfg_id="$(docker image inspect --format '{{.Id}}' "$cfg")" || { elig_set 1 no-image-local "$cn: eticheta $cfg nu mai există local"; return 0; }
        if [[ "$cfg_id" != "$img" ]]; then
            elig_set 1 moved-tag "$cn: eticheta $cfg arată ${cfg_id:0:19}…, dar containerul rulează ${img:0:19}…: faza containers îl ține ca hold-moved-tag, și cu --accept-drift"; return 0
        fi
    done <<<"$names"
}

# După scriere: ce va face de fapt faza containers cu serviciul, măsurat (hash-ul nou din fișier față de eticheta containerului), și ce poate face
# operatorul ACUM. Liniile COMPOSE_PIN_NEXT= sunt citite de lansator: `recreate SERV` doar dacă recreate_eligibility ar accepta serviciul acum,
# `accept-drift PROIECT SERV` doar dacă accept_drift_eligibility ar accepta, altfel `explain SERV CLASĂ` (nimic de rulat; explicația e mai sus).
# Codul lui system-update-containers.sh: un serviciu cu hash diferit e hold-config-drift; cu --accept-drift pull-ul dă `up-to-date` (aceeași imagine, nimic
# recreat, eticheta rămâne veche) sau `recreate` (imagine diferită: `up` recreează și eticheta ajunge la zi).
report_next_step() {
    local svc="$1" kind="$2" ref="$3" cn drift worst=no names old new
    names="$(service_containers "$svc")" || { say "$svc: nu pot lista containerele; nu știu ce va face faza containers"; return 0; }
    if [[ -z "$names" ]]; then say "$svc: nu are container; faza containers nu-l atinge (lucrează doar pe serviciile care rulau)"; return 0; fi
    while IFS= read -r cn; do
        [[ -n "$cn" ]] || continue
        drift="$(container_drift "$WORK/hash1.txt" "$svc" "$cn")"
        case "$drift" in yes) worst=yes ;; unknown) [[ "$worst" == yes ]] || worst=unknown ;; esac
    done <<<"$names"
    old="$(hash_of "$WORK/hash0.txt" "$svc")"; new="$(hash_of "$WORK/hash1.txt" "$svc")"
    case "$worst" in
        no)
            say "$svc: config-hash-ul nou e egal cu cel al containerului; faza containers nu-l reține pentru configurație"
            return 0 ;;
        unknown)
            say "$svc: n-am putut compara config-hash-ul cu eticheta containerului; nu știu ce va face faza containers (verifică cu \`show\`)"
            printf 'COMPOSE_PIN_NEXT=explain %s unknown\n' "$svc" || true
            return 0 ;;
    esac
    if [[ "$kind" == pure ]]; then
        recreate_eligibility "$svc" "$WORK/hash1.txt"
        if [[ $ELIG_RC -eq 0 ]]; then
            say "$svc: config-hash ${old:0:8}… → ${new:0:8}…, iar containerul poartă hash-ul vechi: faza \`system-update.sh --phase containers\` va raporta hold-config-drift pentru $svc până rulezi: compose-pin.sh … recreate --file $FILE --service $svc (repornește containerul pe aceeași imagine; scurtă indisponibilitate). --accept-drift NU ajută la un pin pur: pull-ul dă aceeași imagine (up-to-date), nu recreează nimic, iar eticheta rămâne veche (drift permanent)."
            printf 'COMPOSE_PIN_NEXT=recreate %s\n' "$svc" || true
        elif [[ "$ELIG_CLASS" == floating ]]; then
            say "$svc: pin FLOTANT (\"$ref\"): config-hash ${old:0:8}… → ${new:0:8}…, deci faza containers va REȚINE serviciul (hold-config-drift), iar \`recreate\` va REFUZA (un serviciu pe etichetă flotantă nu e fixat). Opțiuni: (1) re-fixează pe o versiune întreagă: compose-pin.sh … pin --file $FILE --pin $svc=<nume>:<MAJOR.MINOR.PATCH> (dacă e aceeași imagine e un pin pur și atunci se aplică \`recreate\`); (2) readu fișierul: compose-pin.sh … restore --file $FILE --backup ${BACKUP_PATH:-<copia pin-bak>}. Nu există nicio comandă de rulat până atunci."
            printf 'COMPOSE_PIN_NEXT=explain %s floating\n' "$svc" || true
        else
            say "$svc: config-hash ${old:0:8}… → ${new:0:8}…: faza containers va REȚINE serviciul (hold-config-drift), dar \`recreate\` ar refuza acum: ${ELIG_MSGS[*]:-}. Nu există nicio comandă de rulat până nu se rezolvă asta."
            printf 'COMPOSE_PIN_NEXT=explain %s %s\n' "$svc" "$ELIG_CLASS" || true
        fi
    else
        accept_drift_eligibility "$svc"
        if [[ $ELIG_RC -eq 0 ]]; then
            say "$svc: config-hash ${old:0:8}… → ${new:0:8}…: faza \`system-update.sh --phase containers\` va REȚINE $svc (hold-config-drift); NU aplică de la sine versiunea nouă. Aplicarea: system-update.sh --phase containers --accept-drift ${PROJECT} (trage $ref, vede altă imagine decât cea care rulează și o recreează; prin recreare eticheta de hash ajunge la zi). --accept-drift acceptă driftul TUTUROR serviciilor proiectului ${PROJECT}. NU folosi \`recreate\` pentru o versiune nouă: ar pune imaginea în afara evidenței system-update (stale-baseline)."
            printf 'COMPOSE_PIN_NEXT=accept-drift %s %s\n' "$PROJECT" "$svc" || true
        else
            say "$svc: config-hash ${old:0:8}… → ${new:0:8}…: faza containers va REȚINE serviciul (hold-config-drift) și NU l-ar aplica nici cu --accept-drift: ${ELIG_MSGS[*]:-}. Nu există nicio comandă de rulat până nu se rezolvă asta (sau readu fișierul: compose-pin.sh … restore --file $FILE --backup ${BACKUP_PATH:-<copia pin-bak>})."
            printf 'COMPOSE_PIN_NEXT=explain %s %s\n' "$svc" "$ELIG_CLASS" || true
        fi
    fi
}

# Pune copia la loc cu regulile din python: `strict` refuză dacă fișierul nu mai e cel scris de unealtă; `force` nu cere asta (doar pentru
# cazul în care chiar scrierea noastră a ieșit greșit). Dovada: suma fișierului = suma copiei, citită cu sha256sum, nu doar raportată de python.
restore_backup() {
    local backup="$1" h0="$2" mode="$3" rc=0
    bad "PROBA A EȘUAT: pun copia de rezervă la loc"
    run_py restore "$mode" "$FILE" "$backup" || rc=$?
    if [[ $rc -eq 0 ]] && grep -q '^RESTORED' "$PYOUT" && [[ "$(file_sum)" == "$h0" ]]; then
        good "restaurat și DOVEDIT: suma fișierului e cea de dinainte ($h0)"
        return 0
    fi
    bad "RESTAURAREA NU E DOVEDITĂ. Fișierul $FILE poate fi într-o stare nefinală. Pune manual: cp -- $(printf '%q' "$backup") $(printf '%q' "$FILE") ; suma așteptată: $h0"
    return 1
}

cmd_pin() {
    local spec svc ref tag a b c d h0="" fp0 fp1 backup stamp rc=0 noop_only=1
    local -a changed=()
    RESOLVE_OK=1; VERSION_CHANGE=0; PURE_SVCS=(); CHANGE_SVCS=()
    for spec in "${PINS[@]}"; do
        split_ref "${spec#*=}" || true
        [[ $REF_FLOATING -eq 0 ]] || say "${spec%%=*}: ATENȚIE: \"${spec#*=}\" e o etichetă FLOTANTĂ (--allow-floating-tag): registrul o poate muta, deci asta NU e un pin real"
    done
    compose_json "$WORK/j0.json" || unknown "nu pot citi configurația proiectului $PROJECT din $FILE"
    run_py edit dry "$FILE" "$WORK/j0.json" "-" "-" "${PINS[@]}" || rc=$?
    [[ $rc -ne 3 ]] || unknown "programul de căutare a liniei a căzut"
    [[ $rc -eq 0 ]] || refuse "refuz: nu editez nimic"
    while IFS=$'\t' read -r tag a b c d; do
        case "$tag" in
            SHA256) h0="$a" ;;
            CHANGE) changed+=("$a=$d"); noop_only=0 ;;
            NOOP)   good "$a: $b e deja scris în fișier; nimic de făcut" ;;
        esac
    done <"$PYOUT"
    is_digits64 "$h0" || unknown "nu pot măsura suma fișierului"
    if [[ -n "$EXPECT_SHA" && "$EXPECT_SHA" != "$h0" ]]; then
        refuse "fișierul s-a schimbat de când l-ai văzut (suma $h0, nu $EXPECT_SHA); rulează din nou planul; nu s-a scris nimic"
    fi
    if [[ $noop_only -eq 1 ]]; then
        printf 'COMPOSE_PIN_NOOP=1\n' || true
        good "toate pin-urile cer exact ce scrie deja fișierul: nu s-a scris nimic, nu s-a făcut nicio copie, nu s-a tras nimic"
        return 0
    fi
    for spec in "${changed[@]}"; do
        resolve_one "${spec%%=*}" "${spec#*=}"
    done
    [[ $RESOLVE_OK -eq 1 ]] || refuse "refuz: cel puțin un pin ar schimba ce rulează sau nu poate fi tras; nu s-a scris nimic"
    say "diferența (doar liniile image:):"
    printf -- '--- %s\n+++ %s (după pin)\n' "$FILE" "$FILE" || true
    while IFS=$'\t' read -r tag a; do [[ "$tag" == DIFF ]] && { printf '%s\n' "$a" || true; }; done <"$WORK/py.out"
    if [[ $PLAN -eq 1 ]]; then
        printf 'COMPOSE_PIN_FILE_SHA256=%s\n' "$h0" || true
        good "plan: nimic nu s-a scris (suma fișierului: $h0)"
        return 0
    fi

    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="${FILE}.pin-bak-${stamp}"
    fp0="$(fingerprint)" || unknown "nu pot citi amprenta containerelor proiectului"
    if config_hashes "$WORK/hash0.txt"; then HASHES_OK=1; else say "nu pot măsura config-hash-urile (compose fără --hash?): voi spune doar ce se poate dovedi altfel"; fi

    rc=0
    run_py edit write "$FILE" "$WORK/j0.json" "$backup" "$h0" "${PINS[@]}" || rc=$?
    if [[ $rc -ne 0 ]]; then
        backup="$(awk -F'\t' '$1 == "BACKUP" { print $2 }' "$PYOUT")"
        if grep -q '^REPLACED' "$PYOUT" && [[ -n "$backup" ]]; then
            # exit 7 = chiar scrierea noastră a ieșit greșit (octeți/mod): nu mai e nimic de protejat al altcuiva, deci `force`
            if [[ $rc -eq 7 ]]; then restore_backup "$backup" "$h0" force || exit 1; else restore_backup "$backup" "$h0" strict || exit 1; fi
            exit 1
        fi
        refuse "nu s-a scris nimic (fișierul e neschimbat)"
    fi
    backup="$(awk -F'\t' '$1 == "BACKUP" { print $2 }' "$PYOUT")"
    [[ -n "$backup" ]] || unknown "editarea a reușit, dar nu știu unde e copia de rezervă"
    good "scris atomic; copia de rezervă: $backup (0600)"
    BACKUP_PATH="$backup"
    printf 'COMPOSE_PIN_BACKUP=%s\n' "$backup" || true

    rc=0
    if compose_json "$WORK/j1.json"; then
        run_py prove "$WORK/j0.json" "$WORK/j1.json" "${changed[@]}" || rc=$?
        if [[ $rc -ne 0 ]]; then
            while IFS=$'\t' read -r tag a b; do
                [[ "$tag" == DIFF ]] && bad "diferă după editare (doar calea, nu valoarea): $a"
                [[ "$tag" == IMAGE && "$b" != ok ]] && bad "image-ul lui $a nu e cel cerut după editare"
            done <"$PYOUT"
            restore_backup "$backup" "$h0" strict || exit 1
            refuse "proba a eșuat; fișierul e readus la starea de dinainte"
        fi
    else
        restore_backup "$backup" "$h0" strict || exit 1
        unknown "după editare compose nu mai poate citi configurația; fișierul e readus la starea de dinainte"
    fi
    good "DOVEDIT: compose vede imaginile cerute, iar restul configurației (toate serviciile, rețelele, volumele) e neschimbat"

    fp1="$(fingerprint)" || unknown "nu pot citi amprenta containerelor după editare"
    if [[ "$fp0" != "$fp1" ]]; then
        bad "un container al proiectului $PROJECT s-a schimbat în timpul rulării (id, StartedAt, RestartCount sau imagine); scriptul nu recreează nimic, deci nu e de la el. Citește starea."
        exit 4
    fi
    good "containerele proiectului sunt neatinse (id, StartedAt, RestartCount, imagine: amprenta identică înainte și după)"

    printf '    rollback (readuce DOAR fișierul; un container recreat între timp nu se readuce):\n        sudo cp -- %s %s && sudo sha256sum %s   # suma așteptată: %s\n        sau: compose-pin.sh … restore --file %s --backup %s\n' \
        "$(printf '%q' "$backup")" "$(printf '%q' "$FILE")" "$(printf '%q' "$FILE")" "$h0" "$(printf '%q' "$FILE")" "$(printf '%q' "$backup")" || true
    if [[ $HASHES_OK -eq 1 ]] && config_hashes "$WORK/hash1.txt" && load_service_table "$WORK/j1.json"; then
        for spec in "${changed[@]}"; do
            svc="${spec%%=*}"; ref="${spec#*=}"
            if [[ " ${PURE_SVCS[*]:-} " == *" $svc "* ]]; then report_next_step "$svc" pure "$ref"
            elif [[ " ${CHANGE_SVCS[*]:-} " == *" $svc "* ]]; then report_next_step "$svc" change "$ref"
            fi
        done
    else
        say "config-hash-ul n-a putut fi măsurat; nu știu ce va face faza containers cu serviciile fixate (drift)"
    fi
    if [[ $VERSION_CHANGE -eq 1 ]]; then
        say "VERSIUNE SCHIMBATĂ în fișier. NIMIC nu e recreat acum: containerele rulează în continuare imaginea veche."
    else
        say "pin pur: imaginea care rulează NU se schimbă, iar acum nu s-a recreat nimic."
    fi
}

# ---------------------------------------------------------------------------------------------------------------
# recreate: repornește pe ACEEAȘI imagine containerele ale căror hash de configurație a rămas în urma fișierului (drift creat de un pin).
# ---------------------------------------------------------------------------------------------------------------

sample_ctr() {
    docker container inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.Image}}|{{.Created}}' "$1"
}

# Dovada pentru un serviciu recreat: container NOU (alt Id), rulează imaginea cerută, eticheta de hash = hash-ul din fișier, ajunge la running/healthy
# (sau fără healthcheck: running) într-un timp mărginit și rămâne așa o fereastră STABLE_S (aceleași reporniri, același StartedAt).
verify_recreated() {
    local svc="$1" want_id="$2" want_hash="$3" old_ids="$4" names cn cid s1 s2 st hl img tries=0 lab ok=0
    names="$(service_containers "$svc")" || { bad "$svc: nu pot lista containerele după up"; return 1; }
    [[ -n "$names" ]] || { bad "$svc: niciun container după up"; return 1; }
    while IFS= read -r cn; do
        [[ -n "$cn" ]] || continue
        cid="$(docker container inspect --format '{{.Id}}' "$cn")" || { bad "$cn: nu-l pot citi după up"; return 1; }
        if [[ " $old_ids " == *" $cid "* ]]; then bad "$cn: e ACELAȘI container (Id neschimbat): \`up\` a ieșit, dar nu l-a recreat"; return 1; fi
        ok=0; tries=0
        while :; do
            s1="$(sample_ctr "$cn")" || { bad "$cn: nu-l pot citi"; return 1; }
            IFS='|' read -r st hl _ _ img _ <<<"$s1"
            case "$st/$hl" in
                running/none|running/healthy) ok=1; break ;;
                running/starting) ;;
                *) bad "$cn: după recreare e $st/$hl"; return 1 ;;
            esac
            tries=$((tries + 1))
            [[ $tries -lt $WAIT_TRIES ]] || break
            sleep "$POLL_S"
        done
        [[ $ok -eq 1 ]] || { bad "$cn: încă \"starting\" după $WAIT_TRIES încercări; nu pot dovedi că e sănătos"; return 1; }
        [[ "$img" == "$want_id" ]] || { bad "$cn: rulează $img, nu imaginea cerută $want_id"; return 1; }
        lab="$(docker container inspect --format "{{index .Config.Labels \"${LABEL_HASH}\"}}" "$cn")" || { bad "$cn: nu pot citi eticheta de hash"; return 1; }
        [[ "$lab" == "$want_hash" ]] || { bad "$cn: eticheta de hash (${lab:0:12}…) nu e cea din fișier (${want_hash:0:12}…): drift-ul NU s-a închis"; return 1; }
        sleep "$STABLE_S"
        s2="$(sample_ctr "$cn")" || { bad "$cn: nu-l pot citi după fereastra de stabilitate"; return 1; }
        if [[ "$(cut -d'|' -f1-4 <<<"$s1")" != "$(cut -d'|' -f1-4 <<<"$s2")" || "${s2%%|*}" != running ]]; then
            bad "$cn: nu e stabil în ${STABLE_S}s (${s1%|*|*} -> ${s2%|*|*}): reporniri sau stare schimbată"; return 1
        fi
        good "$cn: container nou, ${img:0:19}…, $hl, hash la zi, stabil ${STABLE_S}s"
    done <<<"$names"
    return 0
}

cmd_recreate() {
    local -a targets=()
    local -A S_NAMES=()
    local svc cn m h0 refused=0 unk=0 fp0 fp1 all_names="" old_ids up_rc=0 failed=0 ref_id plan_line
    IFS=, read -r -a targets <<<"$SERVICES"
    compose_json "$WORK/j0.json" || unknown "nu pot citi configurația proiectului $PROJECT din $FILE"
    load_service_table "$WORK/j0.json" || unknown "nu pot interpreta configurația"
    config_hashes "$WORK/hash0.txt" || unknown "nu pot măsura config-hash-urile din fișier (compose fără --hash?): fără ele nu pot judeca drift-ul"
    h0="$(file_sum)"
    if [[ -n "$EXPECT_SHA" && "$EXPECT_SHA" != "$h0" ]]; then
        refuse "fișierul s-a schimbat de când ai văzut planul (suma $h0, nu $EXPECT_SHA); rulează din nou planul; nu s-a repornit nimic"
    fi
    for svc in "${targets[@]}"; do
        recreate_eligibility "$svc" "$WORK/hash0.txt"
        case "$ELIG_RC" in
            0) for plan_line in "${ELIG_PLAN[@]}"; do say "$plan_line"; done
               S_NAMES[$svc]="$(service_containers "$svc")" || unknown "nu pot lista containerele serviciului $svc" ;;
            1) for m in "${ELIG_MSGS[@]}"; do bad "$m"; done; refused=1 ;;
            *) for m in "${ELIG_MSGS[@]}"; do bad "$m"; done; unk=1 ;;
        esac
    done
    [[ $refused -eq 0 ]] || refuse "refuz: nu s-a repornit nimic"
    [[ $unk -eq 0 ]] || unknown "nu pot dovedi că repornirea e necesară și sigură; nu s-a repornit nimic"
    if [[ $PLAN -eq 1 ]]; then
        printf 'COMPOSE_PIN_FILE_SHA256=%s\n' "$h0" || true
        good "plan: nimic nu s-a repornit (suma fișierului: $h0). Se va rula: docker compose -p $PROJECT -f $FILE up -d --no-deps --no-build --force-recreate ${targets[*]}"
        return 0
    fi

    for svc in "${targets[@]}"; do all_names+="${S_NAMES[$svc]//$'\n'/ } "; done
    fp0="$(fingerprint "$all_names")" || unknown "nu pot citi amprenta celorlalte containere"
    old_ids=""
    for cn in $all_names; do old_ids+="$(docker container inspect --format '{{.Id}}' "$cn") " || unknown "nu pot citi Id-ul lui $cn"; done
    say "recreez: ${targets[*]} (docker compose up -d --no-deps --no-build --force-recreate)"
    # Marcajul spune lansatorului că de aici încolo ceva a putut fi atins pe gazdă: doar atunci un rollback are sens. Tipărit ÎNAINTE de `up`, ca să existe
    # și dacă `up` e întrerupt sau ssh cade; orice ieșire dinaintea lui (refuz, nu pot măsura) n-are marcaj, deci nu are nimic de readus.
    printf 'COMPOSE_PIN_UP_RAN=1\n' || true
    docker compose -p "$PROJECT" -f "$FILE" up -d --no-deps --no-build --force-recreate "${targets[@]}" >"$WORK/up.out" 2>"$WORK/up.err" || up_rc=$?
    config_hashes "$WORK/hash1.txt" || unknown "nu pot măsura config-hash-urile după up (up A RULAT; starea nu e dovedită)"
    for svc in "${targets[@]}"; do
        ref_id="$(docker image inspect --format '{{.Id}}' "${S_IMAGE[$svc]}")" || { bad "$svc: nu pot citi imaginea ${S_IMAGE[$svc]}"; failed=1; continue; }
        verify_recreated "$svc" "$ref_id" "$(hash_of "$WORK/hash1.txt" "$svc")" "$old_ids" || failed=1
    done
    fp1="$(fingerprint "$all_names")" || unknown "nu pot citi amprenta celorlalte containere după up (up A RULAT)"
    if [[ "$fp0" != "$fp1" ]]; then
        bad "un container pe care nu l-am numit s-a schimbat în timpul rulării (\`--no-deps\` nu avea voie să-l atingă); citește starea înainte de orice altceva"
        exit 4
    fi
    good "celelalte containere ale proiectului sunt neatinse"
    if [[ $failed -ne 0 ]]; then
        # un singur verdict: ce a ieșit din `up` (cod; mesajul nu se tipărește, poate cita valori) face parte din motivul eșecului, nu un rând separat
        bad "RECREAREA NU E DOVEDITĂ pentru cel puțin un serviciu$([[ $up_rc -eq 0 ]] || printf ' (docker compose up a ieșit cu %s, mesajul nu se tipărește)' "$up_rc"). Nu fac rollback singur peste un serviciu care rulează."
        bad "rollback: (1) fișierul: compose-pin.sh … restore --file $FILE [--backup <copia pin-bak>] (readuce DOAR fișierul, doar dacă nu l-a mai atins nimeni); (2) containerul: docker compose -p $PROJECT -f $FILE up -d --no-deps --no-build --force-recreate ${targets[*]}  (după ce verifici că eticheta din fișier arată imaginea dorită)"
        exit 1
    fi
    if [[ $up_rc -ne 0 ]]; then
        good "DOVEDIT: ${targets[*]} rulează pe imaginea fixată, cu config-hash la zi, stabil; ATENȚIE: docker compose up a ieșit cu $up_rc (mesajul nu se tipărește), dar efectul e dovedit mai sus"
    else
        good "DOVEDIT: ${targets[*]} rulează pe imaginea fixată, cu config-hash la zi; faza containers nu le mai reține pentru configurație"
    fi
}

# ---------------------------------------------------------------------------------------------------------------
# restore: pune la loc copia de rezervă scrisă de `pin`, doar dacă fișierul e încă exact cel scris de unealtă (altfel ar șterge munca altcuiva).
# ---------------------------------------------------------------------------------------------------------------

cmd_restore() {
    local backup mode=strict h cur fp0 fp1 rc=0 before svc cn drift tag a b
    [[ $FORCE -eq 0 ]] || mode=force
    if [[ -n "$BACKUP_OPT" ]]; then
        backup="$BACKUP_OPT"
    else
        run_py latest "$FILE" || refuse "nu știu ce copie să pun la loc"
        backup="$(awk -F'\t' '$1 == "BACKUP" { print $2 }' "$PYOUT")"
    fi
    cur="$(file_sum)"
    if [[ -n "$EXPECT_SHA" && "$EXPECT_SHA" != "$cur" ]]; then
        refuse "fișierul s-a schimbat de când ai văzut planul (suma $cur, nu $EXPECT_SHA); rulează din nou planul; nu s-a restaurat nimic"
    fi
    run_py restore "$mode" "$FILE" "$backup" dry || rc=$?
    [[ $rc -ne 3 ]] || unknown "programul de restaurare a căzut"
    [[ $rc -eq 0 ]] || refuse "refuz: nu restaurez nimic (fișierul nu s-a atins)"
    h="$(awk -F'\t' '$1 == "CHECK_OK" { print $2 }' "$PYOUT")"
    is_digits64 "$h" || unknown "nu pot citi suma copiei de rezervă"
    say "copia $backup (suma $h) se pune peste $FILE (suma de acum $cur)"
    if [[ $PLAN -eq 1 ]]; then
        printf 'COMPOSE_PIN_FILE_SHA256=%s\n' "$cur" || true
        good "plan: nimic nu s-a restaurat"
        return 0
    fi
    fp0="$(fingerprint)" || unknown "nu pot citi amprenta containerelor proiectului"
    rc=0
    run_py restore "$mode" "$FILE" "$backup" || rc=$?
    [[ $rc -eq 0 ]] || refuse "restaurarea a eșuat (fișierul e neschimbat sau într-o stare pe care trebuie s-o verifici: suma de acum $(file_sum))"
    if [[ "$(file_sum)" != "$h" ]]; then bad "după restaurare suma fișierului ($(file_sum)) nu e cea a copiei ($h)"; exit 1; fi
    good "restaurat și DOVEDIT: suma fișierului = suma copiei ($h)"
    compose_json "$WORK/j1.json" || unknown "fișierul e restaurat, dar compose nu-l mai poate citi"
    fp1="$(fingerprint)" || unknown "nu pot citi amprenta containerelor după restaurare"
    if [[ "$fp0" != "$fp1" ]]; then bad "un container al proiectului s-a schimbat în timpul rulării; nu de la unealtă"; exit 4; fi
    good "containerele proiectului sunt neatinse"
    if config_hashes "$WORK/hash1.txt"; then
        run_py show "$WORK/j1.json" || true
        while IFS=$'\t' read -r tag svc a b; do
            [[ "$tag" == SVC ]] || continue
            while IFS= read -r cn; do
                [[ -n "$cn" ]] || continue
                drift="$(container_drift "$WORK/hash1.txt" "$svc" "$cn")"
                [[ "$drift" != yes ]] || say "$svc: $cn are drift față de fișierul restaurat (a fost recreat după pin?): faza containers îl va reține; repornește-l cu docker compose -p $PROJECT -f $FILE up -d --no-deps --no-build --force-recreate $svc după ce verifici imaginea din fișier"
            done <<<"$(service_containers "$svc")"
        done <"$PYOUT"
    else
        say "config-hash-ul n-a putut fi măsurat; nu știu dacă vreun container are drift față de fișierul restaurat"
    fi
}

main() {
    local sub="${1:-}" existing p ref
    trap '' PIPE
    set +x
    exec </dev/null
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        show|pin|recreate|restore) ;;
        *) usage_die "subcomandă necunoscută: \"$sub\"" ;;
    esac
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --allow-version-change) [[ "$sub" == pin ]] || usage_die "$1 e doar pentru pin"; ALLOW_VERSION_CHANGE=1; shift; continue ;;
            --allow-floating-tag) [[ "$sub" == pin ]] || usage_die "$1 e doar pentru pin"; ALLOW_FLOATING=1; shift; continue ;;
            --force) [[ "$sub" == restore ]] || usage_die "$1 e doar pentru restore"; FORCE=1; shift; continue ;;
            --plan) [[ "$sub" != show ]] || usage_die "$1 nu e pentru show"; PLAN=1; shift; continue ;;
        esac
        [[ $# -ge 2 ]] || usage_die "$1 cere o valoare"
        case "$1" in
            --file) FILE="$2" ;;
            --project) valid_project "$2" || usage_die "--project refuzat: \"$2\""; PROJECT_OPT="$2" ;;
            --pin)
                [[ "$sub" == pin ]] || usage_die "--pin e doar pentru pin"
                [[ "$2" == *=* ]] || usage_die "--pin cere SERVICIU=REF, nu \"$2\""
                valid_service "${2%%=*}" || usage_die "nume de serviciu invalid în --pin: \"${2%%=*}\""
                split_ref "${2#*=}" || usage_die "REF refuzat pentru ${2%%=*} (\"${2#*=}\"): $REF_WHY"
                for existing in ${PINS[@]+"${PINS[@]}"}; do
                    [[ "${existing%%=*}" != "${2%%=*}" ]] || usage_die "serviciul ${2%%=*} apare în două --pin"
                done
                PINS+=("$2") ;;
            --service)
                [[ "$sub" == recreate ]] || usage_die "--service e doar pentru recreate"
                SERVICES="$2" ;;
            --backup)
                [[ "$sub" == restore ]] || usage_die "--backup e doar pentru restore"
                BACKUP_OPT="$2" ;;
            --expect-sha256)
                [[ "$sub" != show ]] || usage_die "--expect-sha256 nu e pentru show"
                is_digits64 "$2" || usage_die "--expect-sha256 cere 64 de cifre hex"
                EXPECT_SHA="$2" ;;
            *) usage_die "argument necunoscut: \"$1\"" ;;
        esac
        shift 2
    done
    case "$sub" in
        pin)
            [[ ${#PINS[@]} -gt 0 ]] || usage_die "pin cere cel puțin un --pin SERVICIU=REF"
            for p in "${PINS[@]}"; do
                ref="${p#*=}"
                split_ref "$ref" || usage_die "REF refuzat: $REF_WHY"
                if [[ $REF_FLOATING -eq 1 && $ALLOW_FLOATING -eq 0 ]]; then
                    usage_die "eticheta lui ${p%%=*} (\"$ref\") e FLOTANTĂ: registrul o poate muta, deci nu fixează o versiune. Cer o versiune întreagă (MAJOR.MINOR.PATCH, ex. 2.49.5) sau un digest @sha256:...; dacă vrei oricum, --allow-floating-tag"
                fi
            done ;;
        recreate)
            [[ -n "$SERVICES" ]] || usage_die "recreate cere --service S[,S]"
            local seen=","
            local -a list=()
            IFS=, read -r -a list <<<"$SERVICES"
            for p in "${list[@]}"; do
                valid_service "$p" || usage_die "nume de serviciu invalid în --service: \"$p\""
                [[ "$seen" != *",$p,"* ]] || usage_die "serviciul $p apare de două ori în --service"
                seen+="$p,"
            done ;;
        restore)
            if [[ -n "$BACKUP_OPT" ]]; then
                [[ "$BACKUP_OPT" == "${FILE}.pin-bak-"* && "$BACKUP_OPT" =~ ^/[A-Za-z0-9._/@+-]+$ && ! "$BACKUP_OPT" =~ \.sums$ ]] || usage_die "--backup refuzat: trebuie să fie ${FILE}.pin-bak-<UTC> (copia scrisă de pin)"
            fi ;;
    esac
    is_digits "$POLL_S" && is_digits "$STABLE_S" && is_digits "$WAIT_S" || usage_die "COMPOSE_PIN_POLL_S/STABLE_S/WAIT_S cer numere"
    WAIT_TRIES=$((WAIT_S / (10#$POLL_S > 0 ? 10#$POLL_S : 1)))
    [[ $WAIT_TRIES -ge 1 ]] || WAIT_TRIES=1
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    common_checks
    case "$sub" in
        show)     cmd_show ;;
        pin)      cmd_pin ;;
        recreate) cmd_recreate ;;
        restore)  cmd_restore ;;
    esac
}

# Pornește doar când e rulat (prin `bash -s` sau direct), nu când e încărcat cu `source` de teste. Ultima linie, ca
# stdin-ul pe care îl citește `bash -s` să fie gol când rulează main.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
