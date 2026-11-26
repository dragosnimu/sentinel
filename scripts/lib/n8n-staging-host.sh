#!/usr/bin/env bash
#
# O copie de aruncat a instanței n8n de producție, pe VERSIUNEA NOUĂ, izolată de rețea, ca operatorul să încerce
# upgrade-ul (2.x -> 3.0.x) înainte să atingă producția. Rulează PE GAZDĂ, ca root, și nu e chemat direct:
# scripts/n8n-staging.sh îl trimite prin `ssh ... sudo -n bash -s -- SUBCOMANDĂ ...` (stdin). Nimic nu se salvează pe
# gazdă, deci nu e nimic de verificat cu sumă după copiere.
#
#   n8n-staging-host.sh up --version X.Y.Z      creează copia și dovedește că merge
#   n8n-staging-host.sh status                  doar citire
#   n8n-staging-host.sh logs [--tail N]         doar citire
#   n8n-staging-host.sh down                    șterge DOAR obiectele cu eticheta de staging
#
# De ce există: workflow-urile de producție sună debitori prin Twilio, trimit WhatsApp și e-mail, iar multe sunt active
# (schedule, Gmail). O copie care ar ajunge pe internet ar face apeluri REALE. Tot scriptul e construit în jurul unui
# singur fapt de dovedit, prin EFECT și nu prin intenție: din interiorul containerului, o conexiune TCP spre o adresă
# publică și o rezoluție DNS CAD amândouă. `docker network create --internal` e intenția; proba e efectul.
#
# Ordinea contează: n8n activează workflow-urile în clipa în care pornește. De aceea izolarea se dovedește ÎNTÂI cu un
# container de probă pe aceeași rețea (n8n încă NU rulează), apoi încă o dată din interiorul containerului pornit. Dacă
# a doua probă vede ieșire, containerul se șterge pe loc și ieșirea e 5.
#
# Cum se copiază baza de date, și de ce nu `cp`: producția rămâne PORNITĂ, iar SQLite lucrează în modul WAL. Un `cp` al
# fișierului principal fără -wal (sau cu un -wal prins la jumătate) dă o bază stricată sau veche, FĂRĂ nicio eroare. Se
# folosește API-ul de backup online al SQLite (sqlite3.Connection.backup, din python3-ul gazdei): un instantaneu
# consistent, într-o singură trecere, fără să oprească producția. Apoi două dovezi pe COPIE: `PRAGMA integrity_check`
# întoarce exact «ok», iar numărul de rânduri din workflow_entity e cel din producție (citit înainte ȘI după backup: dacă
# producția s-a schimbat în timpul copierii, nu se poate dovedi nimic și se refuză).
#
# Producția NU se atinge: amprenta lui root-n8n-1 (ID, StartedAt, RestartCount, ID imagine) se înregistrează la început
# și se compară la ORICE ieșire; o schimbare e ieșire 4, cu mesaj tare. Nu se rulează niciodată `docker compose`.
# Volumul de producție se citește (backup online + tar) și nu se montează în nimic.
#
# Mediul: din `docker container inspect` (Config.Env) MINUS ce a pus imaginea veche (altfel PATH/NODE_VERSION/N8N_VERSION
# ale imaginii vechi ar suprascrie imaginea nouă), cu suprascrieri pentru acces prin tunel ssh. Merge într-un fișier root
# 0600, șters la orice ieșire. NICIO valoare de mediu nu se tipărește: nici în ieșire, nici în erori (erorile docker trec
# printr-un filtru care înlocuiește valorile), nici în xtrace (`set +x`).
#
# /files: producția montează /local-files read-write la /files. Aici se montează DOAR-CITIRE (`:ro`), iar faptul se
# verifică pe containerul creat (RW=false), nu se presupune. Un workflow care scrie în /files va primi eroare în staging,
# nu va modifica producția.
#
# Coduri de ieșire: 0 totul dovedit; 1 refuzat / eșuat; 2 argumente greșite; 3 NU s-a putut măsura (nu e «bine»);
# 4 producția s-a schimbat; 5 s-a văzut ieșire din container (a fost șters).
#
# Opțiuni de mediu pentru teste (sudo curăță mediul, deci operatorul nu le poate seta pe gazdă):
#   N8N_STAGING_POLL_S (2)  N8N_STAGING_STABLE_SAMPLES (15 => ~30 s)  N8N_STAGING_HEALTH_TRIES (din --health-timeout / POLL_S)
#   N8N_STAGING_PROGRESS_EVERY (15 încercări între două linii de progres)  N8N_STAGING_TMPDIR (/run)
# Pragurile operatorului sunt ARGUMENTE ale lui `up`: --health-timeout S (60-7200, implicit 1200), --cpus C (0.25-2, implicit 1),
# --memory M (512m-6g, implicit 3g). Limitele merg pe container și pe containerul de probă; backup-ul și integrity_check rulează sub
# `ionice`/`nice`. Gateway-ul bridge-ului (adresa GAZDEI) rămâne atins din rețeaua internă: proba raportează porturile 80/443/8443/5678
# și avertizează când 80/443 răspund (traefik -> webhook-urile de producție); nu refuză și nu adaugă reguli de firewall.
# SIGPIPE e ignorat: dacă ssh cade, un `printf` nu are voie să omoare scriptul înainte de ștergerea unui container nedovedit.

set -euo pipefail
set +x
# Mesajele python conțin diacritice; sub un locale nepotrivit (sau cu stdout redirectat, pe Windows) `print` ar cădea cu
# UnicodeEncodeError și un backup bun ar fi refuzat din motive de codare.
export PYTHONIOENCODING=utf-8

PROD_CONTAINER="root-n8n-1"
PROD_VOLUME="n8n_data"
PROD_NETWORK="root_default"
STAGING_CONTAINER="n8n-staging"
STAGING_VOLUME="n8n_staging_data"
STAGING_NET="n8n-staging-net"
PROBE_CONTAINER="n8n-staging-probe"
LABEL_KEY="ro.cryptoitdata.n8n-staging"
IMAGE_REPO="docker.n8n.io/n8nio/n8n"
DATA_DIR_IN_CONTAINER="/home/node/.n8n"
N8N_PORT_IN_CONTAINER=5678
LOCAL_TUNNEL_PORT=5679
PROBE_TCP_HOST="1.1.1.1"
PROBE_TCP_PORT=443
PROBE_DNS_NAME="example.com"
PROBE_GATEWAY="-"

POLL_S="${N8N_STAGING_POLL_S:-2}"
STABLE_SAMPLES="${N8N_STAGING_STABLE_SAMPLES:-15}"
PROGRESS_EVERY="${N8N_STAGING_PROGRESS_EVERY:-15}"
TMP_BASE="${N8N_STAGING_TMPDIR:-/run}"
# Se pot da operatorului prin argumente (sudo curăță mediul, deci doar argumentele ajung pe gazdă); toate se validează aici.
HEALTH_TIMEOUT_S=1200
CPUS="1"
MEMORY="3g"
HEALTH_TRIES=""

# Ce se schimbă față de producție, ca instanța să meargă prin tunelul ssh. Doar valori NESECRETE (se și tipăresc).
ENV_OVERRIDES=(
    "N8N_HOST=localhost"
    "N8N_PORT=${N8N_PORT_IN_CONTAINER}"
    "N8N_PROTOCOL=http"
    "WEBHOOK_URL=http://localhost:${LOCAL_TUNNEL_PORT}/"
    "N8N_EDITOR_BASE_URL=http://localhost:${LOCAL_TUNNEL_PORT}"
    "N8N_SECURE_COOKIE=false"
    "N8N_LISTEN_ADDRESS=0.0.0.0"
    "N8N_PROXY_HOPS=0"
    "N8N_DIAGNOSTICS_ENABLED=false"
    "N8N_VERSION_NOTIFICATIONS_ENABLED=false"
)

PROD_FP_BEFORE=""
ENV_FILE=""
ERR_FILE=""
STAGING_CREATED=0
EGRESS_PROVEN=0

# Mesajele NU au voie să omoare scriptul: când ssh cade, scrierea pe conducta ruptă eșuează, iar sub `set -e` un `printf` eșuat
# ar opri scriptul chiar înainte de ștergerea unui container a cărui izolare nu s-a dovedit (măsurat de verificator: ieșire 141,
# containerul rămas). De aceea SIGPIPE e ignorat în main, iar fiecare mesaj își înghite eșecul.
say()  { printf '[.] %s\n' "$*" || true; }
good() { printf '[+] %s\n' "$*" || true; }
bad()  { printf '[x] %s\n' "$*" >&2 || true; }
refuse()  { bad "$*"; exit 1; }
unknown() { bad "$*"; bad "NECUNOSCUT: ceva n-a putut fi măsurat; asta NU e «bine»."; exit 3; }

# ---------------------------------------------------------------------------------------------------------------
# Programele python (date, nu cod rulat aici): trimise cu `python3 -c`. Valorile secrete circulă DOAR prin conducte și
# fișiere 0600, niciodată prin argv (vizibil în `ps`).
# ---------------------------------------------------------------------------------------------------------------

# Scrie fișierul de mediu. stdin: linia 1 = Config.Env al containerului de producție (JSON), linia 2 = Config.Env al
# imaginii lui. Tipărește DOAR numere.
read -r -d '' ENV_PY <<'PY' || true
import json, os, sys
dest = sys.argv[1]
overrides = {}
for a in sys.argv[2:]:
    k, _, v = a.partition("=")
    overrides[k] = v
lines = sys.stdin.read().split("\n")
prod_env = json.loads(lines[0])
image_env = set(json.loads(lines[1]))
kept, from_image = [], 0
for e in prod_env:
    if e in image_env:
        from_image += 1
        continue
    k, sep, _ = e.partition("=")
    if not sep:
        sys.exit("intrare de mediu fără '=' (cheia: %s)" % k)
    if "\n" in e or "\r" in e:
        sys.exit("valoare pe mai multe linii la cheia %s: nu se poate pune într-un fișier de mediu" % k)
    if k in overrides:
        continue
    kept.append(e)
out = kept + ["%s=%s" % (k, v) for k, v in overrides.items()]
fd = os.open(dest, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(fd, "w", newline="\n") as fh:
    fh.write("\n".join(out) + "\n")
print("preluate=%d din_imagine_omise=%d suprascrise=%d" % (len(kept), from_image, len(overrides)))
PY

# Înlocuiește în stdin orice VALOARE de mediu cu ***. Valorile vin din fișierul dat ca argument (KEY=VALUE pe linie) sau
# din JSON-ul din variabila N8N_SCRUB_JSON.
# Decizia se ia după CHEIE, nu după forma valorii (o formă «doar cifre» a lăsat să treacă o cheie CallMeBot și un număr de telefon,
# amândouă numerice): se maschează ORICE valoare de 4+ caractere, în afară de (a) valorile cheilor dintr-o listă numită de chei
# nesecrete (cele puse chiar de script, în N8N_SCRUB_SKIP_KEYS, plus configurația n8n cunoscută de mai jos) și (b) literalele
# `true`/`false`. O cheie care nu e pe listă se maschează oricum ar arăta valoarea. Dacă aceeași valoare apare ȘI sub o cheie
# nelistată, se maschează peste tot: partea secretă câștigă.
# Decizia (cheie/lungime/literal) se ia pe valoarea BRUTĂ; abia după ce o valoare e hotărâtă secretă se maschează și formele ei
# codificate, fiindcă un jurnal n8n nu citează mereu valoarea așa cum e în mediu (un e-mail `a@b.ro` apare ca `a%40b.ro`, un telefon
# `+40…` ca `%2B40…`, o valoare cu `/` sau `"` apare ca `\/` sau `\"` într-un JSON).
# NU se enumeră codificatoare: Python `quote`, Node `encodeURIComponent` și `URLSearchParams` lasă neescapate caractere diferite
# (`!` `'` `(` `)` `*` `~`), iar n8n e Node; o listă de codificatoare e o listă de presupuneri. În schimb fiecare CARACTER al valorii se
# potrivește cu oricare dintre formele lui, iar formele se pot amesteca în aceeași valoare:
#   (1) el însuși;
#   (2) octeții lui UTF-8 ca `%XX`, cifre hex mici sau mari, în orice combinație (`ă` = `%C4%83`); spațiul și ca `+`;
#   (3) escaparea JSON: `\"`, `\\`, `\/`, `\n \t \r \b \f`, `\uXXXX` cu hex mic sau mare, iar un caracter din afara BMP ca pereche
#       surogat (`\uD83D\uDE00`).
#   (4) formele Node: `\'` (util.inspect), `\xNN` pentru coduri sub 0x100 (util.inspect: `\x01`, `\x7F`), iar `escape()` vechi: `%uXXXX` pentru
#       coduri peste 0xFF (`ă` = `%u0103`) și `%XX` cu octetul Latin-1 pentru 0x80-0xFF (`ñ` = `%F1`); hex mic sau mare în toate.
# Fiecare secret dă o listă de forme per caracter; potrivirea o face o simulare de NFA (`longest_match`), NU un regex peste tot secretul:
# `\` și `\\` sunt amândouă forme ale unui backslash, iar motorul `re` încearcă pe rând toate felurile de a parcurge un șir de backslash-uri
# (exponențial: ~25 în jurnal = minute). Un regex scurt pe primele caractere doar alege pozițiile de început. Toate potrivirile tuturor
# secretelor se unesc în intervale (cele care se suprapun devin unul singur) și abia apoi se înlocuiesc cu `***`. Ordinea secretelor nu
# contează: un secret prefix al altuia sau două care se acoperă parțial (`ab/cd/ef` și `cd/ef/gh`) nu lasă rest. O valoare cu surogați
# singuri sau octeți non-UTF-8 nu ridică excepție (se potrivește ca literal).
# NEACOPERITE: base64, entități HTML (`&#64;`), dublă codificare (`%2540`, `\\u0103`), o valoare spartă pe două linii de jurnal,
# o formă derivată (hash, trunchiere), rescrierile parserului URL WHATWG (tab/newline scoase din URL, `\` → `/` în cale) și valorile
# excluse mai sus (scurte, true/false, chei nesecrete).
# O valoare secretă tot nu trebuie pusă în mediu sub o cheie pe care n-o vrei mascată.
# Dacă scriptul totuși pică, apelanții ascund jurnalul (`scrub_stream` iese nenul → «jurnal ascuns» / ieșire 3), nu îl tipăresc brut.
read -r -d '' SCRUB_PY <<'PY' || true
import json, os, re, sys
entries = []
if len(sys.argv) > 1:
    with open(sys.argv[1], encoding="utf-8", errors="surrogateescape") as fh:
        entries += [l.rstrip("\n") for l in fh]
if os.environ.get("N8N_SCRUB_JSON"):
    entries += json.loads(os.environ["N8N_SCRUB_JSON"]) or []
SAFE_KEYS = {"N8N_PORT", "N8N_PROTOCOL", "N8N_HOST", "GENERIC_TIMEZONE", "TZ", "NODE_ENV", "N8N_LOG_LEVEL",
             "N8N_PAYLOAD_SIZE_MAX", "N8N_DEFAULT_BINARY_DATA_MODE", "N8N_RELEASE_TYPE"}
SAFE_PREFIXES = ("EXECUTIONS_",)
safe = SAFE_KEYS | set(filter(None, os.environ.get("N8N_SCRUB_SKIP_KEYS", "").split(",")))
found = set()
for e in entries:
    k, _, v = e.partition("=")
    if k in safe or k.startswith(SAFE_PREFIXES) or len(v) < 4 or v.lower() in ("true", "false"):
        continue
    found.add(v)

# caracter → escaparea lui scurtă în JSON (două caractere: backslash + literă/semn)
JSON_SHORT = {'"': '\\"', "\\": "\\\\", "/": "\\/", "\n": "\\n", "\t": "\\t", "\r": "\\r", "\b": "\\b", "\f": "\\f"}


def hex_atoms(n, width):
    """Cifrele hex ale lui n ca atomi: o cifră-literă acceptă ambele litere (`c` și `C`), independent per cifră."""
    return tuple(d if d.isdigit() else d.lower() + d.upper() for d in "%0*x" % (width, n))


def char_forms(ch):
    """Toate formele în care jurnalul poate scrie caracterul `ch`; fiecare formă e un tuplu de ATOMI, iar un atom e șirul de caractere
    pe care îl acceptă într-o poziție (un singur caracter, sau `cC` pentru o cifră hex)."""
    forms = [(ch,)]
    if ch == " ":
        forms.append(("+",))
    try:
        raw = ch.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        raw = b""                         # surogat singur: nu are octeți, rămâne doar litera și formele cu cod
    if raw:
        forms.append(tuple(a for b in raw for a in ("%",) + hex_atoms(b, 2)))
    if ch in JSON_SHORT:
        forms.append(tuple(JSON_SHORT[ch]))
    if ch == "'":
        forms.append(("\\", "'"))            # util.inspect scrie 'a\'b'
    cp = ord(ch)
    if cp < 0x100:
        forms.append(("\\", "x") + hex_atoms(cp, 2))                  # util.inspect: caractere de control (x01, x7F, precedate de backslash)
    if 0x80 <= cp < 0x100:
        forms.append(("%",) + hex_atoms(cp, 2))                        # escape() legacy: octetul Latin-1 (ñ = %F1)
    units = [cp] if cp < 0x10000 else [0xD800 + ((cp - 0x10000) >> 10), 0xDC00 + ((cp - 0x10000) & 0x3FF)]
    forms.append(tuple(a for u in units for a in ("\\", "u") + hex_atoms(u, 4)))
    if cp > 0xFF:
        forms.append(tuple(a for u in units for a in ("%", "u") + hex_atoms(u, 4)))   # escape() legacy: ă = %u0103
    return list(dict.fromkeys(forms))


def atom_rx(atom):
    return re.escape(atom) if len(atom) == 1 else "[" + "".join(re.escape(c) for c in atom) + "]"


PREFIX_CHARS = 3


def prefix_regex(forms):
    """Doar primele PREFIX_CHARS caractere, ca filtru ieftin pentru pozițiile de început (apelantul reia căutarea de la start+1, ca să
    vadă și pozițiile care se suprapun). NU se potrivește tot secretul într-un regex: un backslash și două backslash-uri sunt amândouă
    forme ale aceluiași caracter, deci un șir de backslash-uri se poate parcurge în foarte multe feluri, iar motorul `re` le încearcă
    pe toate (exponențial: ~25 de backslash-uri în jurnal = minute). Verificarea întreagă o face `longest_match`, care ține MULȚIMEA
    stărilor, nu o cale."""
    return re.compile("".join("(?:" + "|".join("".join(atom_rx(a) for a in f) for f in forms[i]) + ")"
                              for i in range(min(PREFIX_CHARS, len(forms)))))


def longest_match(forms, text, start):
    """(primul, cel mai lung) sfârșit al unei potriviri a secretului (lista `forms`) care începe la `start`, sau (-1, -1). Simulare de NFA:
    starea e (index caracter, index formă, atomi consumați), iar mulțimea stărilor vii se avansează o dată per caracter de text, deci
    un șir ambiguu NU mai cere un număr exponențial de încercări. Costul e polinomial, nu liniar: la fiecare început candidat se
    parcurge cât timp mai trăiește vreo stare, deci ~(începuturi candidate × întinderea unei potriviri parțiale × stări); un secret de
    40 de backslash-uri + `Q`, absent într-un șir de 4000 de backslash-uri, durează secunde."""
    n, end = len(forms), len(text)
    live = {(0, f, 0) for f in range(len(forms[0]))}
    best, first, pos = -1, -1, start
    while live and pos < end:
        ch = text[pos]
        pos += 1
        nxt = set()
        for i, f, j in live:
            form = forms[i][f]
            if ch not in form[j]:
                continue
            if j + 1 < len(form):
                nxt.add((i, f, j + 1))
            elif i + 1 == n:
                best = pos
                if first < 0:
                    first = pos
            else:
                nxt.update((i + 1, g, 0) for g in range(len(forms[i + 1])))
        live = nxt
    return first, best


text = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
spans = []
for v in found:
    forms = [char_forms(c) for c in v]
    prefix, at = prefix_regex(forms), 0
    while True:
        m = prefix.search(text, at)
        if m is None:
            break
        first, e = longest_match(forms, text, m.start())
        if e >= 0:
            spans.append((m.start(), e))  # se maschează până la cea mai lungă potrivire...
            at = first                    # ...dar căutarea reia de la PRIMA: un secret care se termină în backslash are ca formă lungă
                                          # `\\`, al cărui al doilea backslash ar fi început o a doua apariție a secretului (rămânea în clar)
        else:
            at = m.start() + 1
spans.sort()
merged = []
for s, e in spans:
    if merged and s < merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], e)
    else:
        merged.append([s, e])
out, pos = [], 0
for s, e in merged:
    out += [text[pos:s], "***"]
    pos = e
out.append(text[pos:])
sys.stdout.buffer.write("".join(out).encode("utf-8", "surrogateescape"))
PY

# Valoarea lui N8N_RELEASE_TYPE din Config.Env (JSON pe stdin); nimic altceva din mediu nu se tipărește.
read -r -d '' RELEASE_PY <<'PY' || true
import json, sys
for e in json.load(sys.stdin) or []:
    if e.startswith("N8N_RELEASE_TYPE="):
        print(e.partition("=")[2])
        break
PY

# Copia online a bazei și dovezile pe ea. `backup SRC DST` tipărește «înainte după» (rânduri în workflow_entity în
# producție, înainte și după copiere). `verify DST ÎNAINTE DUPĂ` iese 0 doar dacă producția n-a avut nimic de schimbat în
# timpul copierii, numărul din copie e cel din producție, iar integrity_check întoarce exact «ok».
read -r -d '' SQLITE_PY <<'PY' || true
import pathlib, sqlite3, sys
cmd = sys.argv[1]

def uri(path, mode):
    return pathlib.Path(path).resolve().as_uri() + "?mode=" + mode

def count(path, mode="ro"):
    con = sqlite3.connect(uri(path, mode), uri=True, timeout=60)
    try:
        return con.execute("SELECT count(*) FROM workflow_entity").fetchone()[0]
    finally:
        con.close()

if cmd == "backup":
    src, dst = sys.argv[2], sys.argv[3]
    try:
        before = count(src)
        s = sqlite3.connect(uri(src, "ro"), uri=True, timeout=60)
        d = sqlite3.connect(dst)
        s.backup(d)                     # pages=-1: toată baza într-o singură trecere, un instantaneu consistent
        d.close()
        s.close()
        after = count(src)
    except sqlite3.Error as e:
        sys.exit("backup eșuat: %s: %s" % (type(e).__name__, e))
    print(before, after)
elif cmd == "verify":
    dst, before, after = sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
    if before != after:
        sys.exit("producția și-a schimbat workflow_entity în timpul copierii (%d -> %d): nu se poate dovedi nimic" % (before, after))
    try:
        copy_rows = count(dst, "rw")
    except sqlite3.Error as e:
        sys.exit("copia nu poate fi citită: %s: %s" % (type(e).__name__, e))
    if copy_rows != before:
        sys.exit("numărul de rânduri din workflow_entity NU coincide: producție=%d copie=%d" % (before, copy_rows))
    con = sqlite3.connect(uri(dst, "rw"), uri=True, timeout=60)
    try:
        res = [r[0] for r in con.execute("PRAGMA integrity_check").fetchall()]
    except sqlite3.Error as e:
        sys.exit("integrity_check n-a putut rula: %s: %s" % (type(e).__name__, e))
    finally:
        con.close()
    if res != ["ok"]:
        sys.exit("integrity_check pe copie NU e «ok»: %s" % "; ".join(res[:5]))
    print("integrity_check=ok workflow_entity producție=%d copie=%d" % (before, copy_rows))
else:
    sys.exit("subcomandă necunoscută")
PY

# Proba de ieșire, rulată cu `node` din imaginea n8n (garantat acolo). Tipărește exact trei linii:
#   SELF=ok         control pozitiv: sockets merg în container (altfel «blocat» n-ar dovedi nimic)
#   TCP=open|blocked|unknown      conexiune la ARGV[1]:ARGV[2]
#   DNS=open|blocked|unknown      rezoluția lui ARGV[3]
# «Blocat» înseamnă DOAR erori care spun că pachetul n-are drum (ENETUNREACH/EHOSTUNREACH/ETIMEDOUT/timeout). O conexiune
# REFUZATĂ înseamnă că a răspuns cineva, deci e «open».
read -r -d '' PROBE_JS <<'JS' || true
const net = require('net'), dns = require('dns');
const [host, port, name, gw] = process.argv.slice(1);
const GWPORTS = [80, 443, 8443, 5678];
const out = []; let pending = 3 + GWPORTS.length;
const fin = (l) => { out.push(l); if (--pending === 0) { console.log(out.sort().join('\n')); process.exit(0); } };
setTimeout(() => { console.log('TIMEOUT'); process.exit(0); }, 40000);
const srv = net.createServer((s) => s.end());
srv.listen(0, '127.0.0.1', () => {
  const c = net.connect(srv.address().port, '127.0.0.1');
  c.on('connect', () => { c.destroy(); srv.close(); fin('SELF=ok'); });
  c.on('error', () => { srv.close(); fin('SELF=fail'); });
});
const t = net.connect({ host, port: Number(port) });
t.setTimeout(6000);
t.on('connect', () => { t.destroy(); fin('TCP=open'); });
t.on('timeout', () => { t.destroy(); fin('TCP=blocked'); });
t.on('error', (e) => {
  if (['ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT'].includes(e.code)) fin('TCP=blocked');
  else if (['ECONNREFUSED', 'ECONNRESET'].includes(e.code)) fin('TCP=open');
  else fin('TCP=unknown');
});
dns.lookup(name, (e) => {
  if (!e) fin('DNS=open');
  else if (['ENOTFOUND', 'EAI_AGAIN'].includes(e.code)) fin('DNS=blocked');
  else fin('DNS=unknown');
});
// Gateway-ul bridge-ului (adresa gazdei, din rețeaua internă): INFORMATIV, nu intră în verdict. «refused» = gazda a răspuns, nimic nu ascultă.
GWPORTS.forEach((p) => {
  if (!gw || gw === '-') { fin('GW' + p + '=unknown'); return; }
  const g = net.connect({ host: gw, port: p });
  g.setTimeout(3000);
  g.on('connect', () => { g.destroy(); fin('GW' + p + '=open'); });
  g.on('timeout', () => { g.destroy(); fin('GW' + p + '=blocked'); });
  g.on('error', (e) => {
    if (e.code === 'ECONNREFUSED') fin('GW' + p + '=refused');
    else if (['ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT'].includes(e.code)) fin('GW' + p + '=blocked');
    else fin('GW' + p + '=unknown');
  });
});
JS

# ---------------------------------------------------------------------------------------------------------------
# docker: obiecte, etichete, amprenta producției
# ---------------------------------------------------------------------------------------------------------------

is_semver() { [[ ${#1} -le 32 && "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
is_digits() { [[ ${#1} -ge 1 && ${#1} -le 15 && "$1" =~ ^[0-9]+$ ]]; }

# Numele obiectelor de un fel. Cod 0 cu lista pe stdout; orice eșec al lui docker iese nenul (NU se confundă cu «nu există»).
list_names() {
    case "$1" in
        container) docker ps -a --format '{{.Names}}' ;;
        volume)    docker volume ls --format '{{.Name}}' ;;
        network)   docker network ls --format '{{.Name}}' ;;
        *) return 2 ;;
    esac
}

# Numele obiectelor de un fel care poartă eticheta de staging (cu orice valoare).
list_labelled() {
    case "$1" in
        container) docker ps -a --filter "label=${LABEL_KEY}" --format '{{.Names}}' ;;
        volume)    docker volume ls --filter "label=${LABEL_KEY}" --format '{{.Name}}' ;;
        network)   docker network ls --filter "label=${LABEL_KEY}" --format '{{.Name}}' ;;
        *) return 2 ;;
    esac
}

# 0 = există, 1 = nu există (lista s-a citit și nu-l conține), 3 = lista nu s-a putut citi.
has_name() {
    local names
    names="$(list_names "$1")" || return 3
    grep -Fxq -- "$2" <<<"$names"
}

has_name_or_die() {
    local rc=0
    has_name "$1" "$2" || rc=$?
    [[ $rc -ne 3 ]] || unknown "nu pot citi lista de obiecte docker ($1)"
    return "$rc"
}

label_value() {
    case "$1" in
        container) docker container inspect "$2" --format "{{index .Config.Labels \"${LABEL_KEY}\"}}" ;;
        volume)    docker volume inspect "$2" --format "{{index .Labels \"${LABEL_KEY}\"}}" ;;
        network)   docker network inspect "$2" --format "{{index .Labels \"${LABEL_KEY}\"}}" ;;
        *) return 2 ;;
    esac
}

# Amprenta containerului de producție, sau «absent». Un eșec de citire NU e «absent»: iese 3.
prod_fp() {
    local rc=0
    has_name container "$PROD_CONTAINER" || rc=$?
    [[ $rc -ne 3 ]] || return 3
    if [[ $rc -eq 1 ]]; then printf 'absent\n'; return 0; fi
    docker container inspect "$PROD_CONTAINER" --format '{{.Id}} {{.State.StartedAt}} {{.RestartCount}} {{.Image}}'
}

check_prod_unchanged() {
    local now
    [[ -n "$PROD_FP_BEFORE" ]] || return 0
    now="$(prod_fp)" || { bad "nu pot reciti amprenta producției ($PROD_CONTAINER): nu pot dovedi că n-a fost atinsă"; return 3; }
    if [[ "$now" != "$PROD_FP_BEFORE" ]]; then
        bad "################################################################################"
        bad "PRODUCȚIA S-A SCHIMBAT în timpul rulării: $PROD_CONTAINER (ID, StartedAt, RestartCount sau imaginea)."
        bad "înainte: $PROD_FP_BEFORE"
        bad "acum:    $now"
        bad "Scriptul asta nu atinge producția; verifică ce a repornit-o (jurnalul docker, watchdog-ul, un deploy)."
        bad "################################################################################"
        return 4
    fi
    return 0
}

# Tot ce vine din containerul de staging sau din erorile lui `docker create` trece prin acest filtru: orice VALOARE de mediu
# (din fișierul de mediu, dacă există, și din Config.Env al containerului, dacă există) devine ***, cu excepțiile din SCRUB_PY
# (cifre, true/false, valori scurte, suprascrierile noastre). Dacă nu are de unde să afle valorile, NU tipărește textul:
# «n-am putut filtra» nu înseamnă «nu e nimic de filtrat».
SCRUB_FAILED_MSG='(jurnal ascuns: filtrarea a eșuat)'
SCRUB_UNREADABLE_MSG='(text ascuns: nu pot citi valorile de mediu ca să-l filtrez)'
scrub_stream() {
    local json="" k skip=""
    for k in "${ENV_OVERRIDES[@]}"; do skip+="${k%%=*},"; done
    json="$(docker container inspect "$STAGING_CONTAINER" --format '{{json .Config.Env}}')" || json=""
    if [[ -n "$ENV_FILE" && -s "$ENV_FILE" ]]; then
        N8N_SCRUB_SKIP_KEYS="$skip" N8N_SCRUB_JSON="$json" python3 -c "$SCRUB_PY" "$ENV_FILE"
    elif [[ -n "$json" ]]; then
        N8N_SCRUB_SKIP_KEYS="$skip" N8N_SCRUB_JSON="$json" python3 -c "$SCRUB_PY"
    else
        cat >/dev/null
        printf '%s\n' "$SCRUB_UNREADABLE_MSG"
    fi
}

# ---------------------------------------------------------------------------------------------------------------
# Ieșirea: curățenie, comparația cu producția, codul final
# ---------------------------------------------------------------------------------------------------------------

# Șterge containerul de staging și DOVEDEȘTE că a dispărut. Tace cât timp reușește: ștergerea vine ÎNAINTE de orice mesaj.
remove_staging_container_now() {
    local rc=0 present=0
    docker rm -f "$STAGING_CONTAINER" >/dev/null || rc=$?
    has_name container "$STAGING_CONTAINER" || present=$?
    case "$present" in
        1) return 0 ;;
        0) bad "containerul $STAGING_CONTAINER încă există după rm -f (cod $rc): oprește-l de mână"; return 1 ;;
        *) bad "nu pot dovedi că $STAGING_CONTAINER a dispărut (lista docker nu se citește): oprește-l de mână"; return 1 ;;
    esac
}

on_exit() {
    local rc=$?
    local prod_rc=0 state="" removed=0 present=0
    set +e
    [[ -z "$ENV_FILE" ]] || rm -f -- "$ENV_FILE"
    [[ -z "$ERR_FILE" ]] || rm -f -- "$ERR_FILE"
    # Un container creat a cărui izolare NU s-a dovedit nu are voie să rămână pornit, indiferent de codul cu care ieșim și de ce
    # s-a întâmplat înainte (o conductă ruptă, un semnal, un `exit` oricare). Ștergerea e PRIMA acțiune, înaintea oricărui mesaj;
    # o stare ilizibilă se tratează ca «poate rulează». Rămâne doar un container clar oprit (jurnalul lui e tot ce are operatorul).
    if [[ $STAGING_CREATED -eq 1 && $EGRESS_PROVEN -eq 0 ]]; then
        has_name container "$STAGING_CONTAINER"
        present=$?
        if [[ $present -ne 1 ]]; then
            state="$(docker container inspect "$STAGING_CONTAINER" --format '{{.State.Status}}')"
            case "$state" in
                exited|created|dead) ;;
                *) remove_staging_container_now && removed=1 ;;
            esac
        fi
    fi
    if [[ $removed -eq 1 ]]; then bad "ieșire înainte ca izolarea să fie dovedită: am șters containerul $STAGING_CONTAINER"; fi
    check_prod_unchanged || prod_rc=$?
    # «producția s-a schimbat» (4) bate orice; «n-am putut reciti amprenta» (3) nu ascunde un alt eșec deja cunoscut
    if [[ $prod_rc -eq 4 ]]; then rc=4; elif [[ $prod_rc -ne 0 && $rc -eq 0 ]]; then rc=$prod_rc; fi
    exit "$rc"
}

# ---------------------------------------------------------------------------------------------------------------
# Dovada de izolare
# ---------------------------------------------------------------------------------------------------------------

# closed | open | unknown. «closed» cere TOATE cele trei fapte; orice «=open» bate orice altceva. Liniile GW* (gateway) nu intră aici.
egress_verdict() {
    local text="$1"
    if grep -Eq '^(TCP|DNS)=open' <<<"$text"; then printf 'open\n'; return 0; fi
    if grep -Fxq 'SELF=ok' <<<"$text" && grep -Fxq 'TCP=blocked' <<<"$text" && grep -Fxq 'DNS=blocked' <<<"$text"; then
        printf 'closed\n'; return 0
    fi
    printf 'unknown\n'
}

# Rulează proba (comanda dată + cele patru argumente) și tipărește pe stdout ieșirea ei brută, apoi, pe ULTIMA linie, verdictul.
# NU tipărește nimic către operator: apelantul întâi acționează (șterge, oprește), abia apoi arată liniile.
# O probă care iese nenul dar a tipărit totuși liniile se judecă după linii: «unknown» le prinde pe cele incomplete.
run_probe() {
    local out="" verdict
    out="$("$@" "$PROBE_TCP_HOST" "$PROBE_TCP_PORT" "$PROBE_DNS_NAME" "$PROBE_GATEWAY")" || true
    verdict="$(egress_verdict "$out")"
    printf '%s\n%s\n' "$out" "$verdict"
}

show_probe_lines() {
    local l
    while IFS= read -r l; do
        [[ -z "$l" ]] || printf '    probă: %s\n' "$l" || true
    done <<<"$1"
}

# Gateway-ul bridge-ului e adresa GAZDEI, atinsă din interiorul unei rețele `--internal`. Raportează fiecare port și avertizează
# când 80/443 răspund: traefik publică acolo și rutează spre webhook-urile n8n de PRODUCȚIE, deci un workflow care apelează un
# IP direct le-ar putea lovi. NU refuză (numele nu se rezolvă, DNS e blocat) și NU adaugă reguli de firewall.
report_gateway() {
    local raw="$1" p line state summary="" web_open=0
    for p in 80 443 8443 5678; do
        line="$(grep -E "^GW${p}=" <<<"$raw" || true)"
        state="${line#*=}"
        [[ -n "$line" ]] || state="lipsă"
        summary+=" ${p}=${state}"
        if [[ ( $p -eq 80 || $p -eq 443 ) && "$state" == open ]]; then web_open=1; fi
    done
    say "gateway-ul rețelei (adresa gazdei: ${PROBE_GATEWAY}), porturi din container:${summary}"
    if [[ $web_open -eq 1 ]]; then
        bad "################################################################################"
        bad "ATENȚIE: din container se ajunge la ${PROBE_GATEWAY} pe portul 80 și/sau 443, adică la traefik-ul GAZDEI, care rutează"
        bad "spre webhook-urile n8n de PRODUCȚIE. Un workflow care apelează o ADRESĂ IP direct (nu un nume: DNS e blocat, numele"
        bad "nu se rezolvă) ar putea lovi producția. Nu refuz și nu adaug reguli de firewall; decizia e a ta."
        bad "################################################################################"
    fi
}

network_gateway() {
    local g=""
    g="$(docker network inspect "$STAGING_NET" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}')" || g=""
    [[ "$g" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || g="-"
    printf '%s\n' "$g"
}

probe_before_start() {
    local image="$1" res verdict raw
    say "dovedesc izolarea ÎNAINTE să pornească n8n (container de probă pe ${STAGING_NET})"
    res="$(run_probe timeout 90 docker run --rm --name "$PROBE_CONTAINER" --network "$STAGING_NET" --label "${LABEL_KEY}=1" \
        --cpus "$CPUS" --memory "$MEMORY" --memory-swap "$MEMORY" --entrypoint node "$image" -e "$PROBE_JS")" || res=$'\nunknown'
    verdict="${res##*$'\n'}"
    raw="${res%$'\n'*}"
    docker rm -f "$PROBE_CONTAINER" >/dev/null 2>&1 || true
    show_probe_lines "$raw"
    case "$verdict" in
        closed) good "rețeaua ${STAGING_NET} nu are drum spre exterior (TCP și DNS blocate; control SELF=ok)"; report_gateway "$raw" ;;
        open)   bad "IEȘIRE DIN REȚEAUA ${STAGING_NET}: TCP sau DNS a trecut. n8n NU a pornit."; exit 5 ;;
        *)      unknown "n-am putut dovedi izolarea înainte de pornire (proba n-a dat rezultat complet); n8n NU a pornit" ;;
    esac
}

probe_after_start() {
    local res verdict raw state="" removed=0
    say "dovedesc izolarea din interiorul containerului pornit"
    res="$(run_probe docker exec "$STAGING_CONTAINER" node -e "$PROBE_JS")" || res=$'\nunknown'
    verdict="${res##*$'\n'}"
    raw="${res%$'\n'*}"
    case "$verdict" in
        closed)
            EGRESS_PROVEN=1
            show_probe_lines "$raw"
            good "din interiorul $STAGING_CONTAINER: TCP spre ${PROBE_TCP_HOST}:${PROBE_TCP_PORT} și DNS pentru ${PROBE_DNS_NAME} CAD amândouă"
            report_gateway "$raw" ;;
        open)
            # ȘTERGEREA întâi, mesajul după: dacă ssh a căzut, mesajul nu mai are cui, dar containerul NU are voie să rămână
            remove_staging_container_now && removed=1
            show_probe_lines "$raw"
            bad "IEȘIRE DIN CONTAINERUL $STAGING_CONTAINER: TCP sau DNS a trecut. Workflow-urile active ar putea suna debitori."
            [[ $removed -eq 1 ]] && bad "containerul a fost șters." || true
            exit 5 ;;
        *)
            state="$(docker container inspect "$STAGING_CONTAINER" --format '{{.State.Status}}')" || state="necunoscut"
            if [[ "$state" == running || "$state" == necunoscut ]]; then
                remove_staging_container_now && removed=1
                show_probe_lines "$raw"
                bad "n-am putut dovedi izolarea și containerul rula: $( [[ $removed -eq 1 ]] && echo 'l-am șters' || echo 'NU l-am putut șterge, oprește-l de mână' )"
                exit 3
            fi
            show_probe_lines "$raw"
            bad "containerul s-a oprit (stare: $state) înainte de proba de izolare; îl las oprit, ca să se citească jurnalul"
            show_log_excerpt
            exit 1 ;;
    esac
}

# ---------------------------------------------------------------------------------------------------------------
# up
# ---------------------------------------------------------------------------------------------------------------

# Ce există deja din staging: nume fixe (orice etichetă) ȘI tot ce poartă eticheta. O listă care nu se poate citi NU e «nimic».
staging_leftovers() {
    local kind name fixed rc labelled out=""
    for kind in container volume network; do
        case "$kind" in
            container) fixed="$STAGING_CONTAINER $PROBE_CONTAINER" ;;
            volume)    fixed="$STAGING_VOLUME" ;;
            network)   fixed="$STAGING_NET" ;;
        esac
        for name in $fixed; do
            rc=0; has_name_or_die "$kind" "$name" || rc=$?
            [[ $rc -ne 0 ]] || out+="${kind} ${name}"$'\n'
        done
        labelled="$(list_labelled "$kind")" || unknown "nu pot citi obiectele cu eticheta de staging ($kind)"
        while IFS= read -r name; do
            [[ -z "$name" ]] || out+="${kind} ${name}"$'\n'
        done <<<"$labelled"
    done
    printf '%s' "$out" | sort -u
}

# Volumul de date al producției: trebuie să fie n8n_data montat la /home/node/.n8n (faptul, din container, nu presupunerea).
prod_mounts() {
    docker container inspect "$PROD_CONTAINER" --format '{{range .Mounts}}{{.Destination}}|{{.Type}}|{{.Name}}|{{.Source}}|{{.RW}}{{println}}{{end}}'
}

FILES_SRC=""
up_preflight() {
    local state mounts dst typ name src rw data_ok=0 left mp size avail dbf du_out
    has_name_or_die container "$PROD_CONTAINER" || refuse "containerul de producție $PROD_CONTAINER nu există; nu creez nimic"
    state="$(docker container inspect "$PROD_CONTAINER" --format '{{.State.Status}}')" || unknown "nu pot citi starea lui $PROD_CONTAINER"
    [[ "$state" == running ]] || refuse "$PROD_CONTAINER nu rulează (stare: ${state}); nu copiez din ce nu rulează; nu creez nimic"

    mounts="$(prod_mounts)" || unknown "nu pot citi montările lui $PROD_CONTAINER"
    while IFS='|' read -r dst typ name src rw; do
        [[ -n "$dst" ]] || continue
        if [[ "$dst" == "$DATA_DIR_IN_CONTAINER" && "$typ" == volume && "$name" == "$PROD_VOLUME" ]]; then data_ok=1; fi
        if [[ "$dst" == /files && "$typ" == bind && "$src" == /* ]]; then FILES_SRC="$src"; fi
    done <<<"$mounts"
    [[ $data_ok -eq 1 ]] || refuse "$PROD_CONTAINER nu montează volumul $PROD_VOLUME la $DATA_DIR_IN_CONTAINER; nu știu ce să copiez; nu creez nimic"
    has_name_or_die volume "$PROD_VOLUME" || refuse "volumul $PROD_VOLUME lipsește; nu creez nimic"

    left="$(staging_leftovers)"
    if [[ -n "$left" ]]; then
        bad "există deja obiecte de staging:"
        printf '%s\n' "$left" | sed 's/^/    /' >&2
        refuse "rulează întâi \`down\`; nu creez nimic"
    fi

    command -v curl >/dev/null || refuse "lipsește curl pe gazdă (healthz); nu creez nimic"
    command -v tar >/dev/null || refuse "lipsește tar pe gazdă; nu creez nimic"
    python3 -c 'import sqlite3' || refuse "python3 sau modulul sqlite3 lipsește pe gazdă (backup-ul online al bazei); nu creez nimic"

    mp="$(docker volume inspect "$PROD_VOLUME" --format '{{.Mountpoint}}')" || unknown "nu pot citi unde e volumul $PROD_VOLUME"
    [[ "$mp" == /* && -d "$mp" ]] || unknown "punctul de montare al lui $PROD_VOLUME nu e un director citibil (\"$mp\")"
    dbf="$mp/database.sqlite"
    [[ -f "$dbf" ]] || refuse "n-am găsit $dbf: instanța nu folosește SQLite în acest volum; nu creez nimic"
    PROD_DATA_DIR="$mp"

    du_out="$(du -sb -- "$mp")" || true
    size="${du_out%%[[:space:]]*}"
    avail="$(df -B1 --output=avail -- "$mp" | tail -n 1 | tr -d '[:space:]')" || true
    is_digits "$size" || unknown "nu pot măsura mărimea lui $PROD_VOLUME (am primit \"${size}\")"
    is_digits "$avail" || unknown "nu pot măsura spațiul liber (am primit \"${avail}\")"
    if (( avail < 3 * size )); then
        refuse "spațiu liber insuficient: ${avail} octeți liberi, ${PROD_VOLUME} are ${size}; cer cel puțin 3x. Nu creez nimic"
    fi
    good "preflight: $PROD_CONTAINER rulează, $PROD_VOLUME e la $mp (${size} octeți), liber ${avail}, niciun obiect de staging"
}

PROD_DATA_DIR=""

# Mediul într-un fișier root 0600; tipărește doar numere.
write_env_file() {
    local img_id mode
    ENV_FILE="$(umask 077; mktemp "${TMP_BASE}/n8n-staging-env.XXXXXX")" || unknown "nu pot crea fișierul de mediu în ${TMP_BASE}"
    mode="$(stat -c %a -- "$ENV_FILE")"
    [[ "$mode" == 600 ]] || refuse "fișierul de mediu are modul $mode, nu 600; refuz să pun secrete în el"
    img_id="$(docker container inspect "$PROD_CONTAINER" --format '{{.Image}}')" || unknown "nu pot citi imaginea lui $PROD_CONTAINER"
    {
        docker container inspect "$PROD_CONTAINER" --format '{{json .Config.Env}}'
        docker image inspect "$img_id" --format '{{json .Config.Env}}'
    } | python3 -c "$ENV_PY" "$ENV_FILE" "${ENV_OVERRIDES[@]}" || refuse "n-am putut scrie fișierul de mediu"
}

# Copiază restul volumului (config cu cheia de criptare, nodes/, ...), FĂRĂ bază: baza are căi proprii. crash.journal e un
# marcaj «n8n rulează» al producției, nu stare: copiat, instanța nouă ar crede că a căzut la ultima rulare.
copy_rest_of_volume() {
    local src="$1" dst="$2" rcs src_list dst_list missing
    set +e
    ( cd "$src" && lowprio tar --anchored --exclude=./database.sqlite --exclude=./database.sqlite-wal --exclude=./database.sqlite-shm \
        --exclude=./crash.journal -cf - . ) | lowprio tar -C "$dst" --numeric-owner -xpf -
    rcs=("${PIPESTATUS[@]}")
    set -e
    # tar iese 1 pentru «fișier schimbat cât l-am citit» (jurnalul de evenimente n8n e scris continuu): nu e eroare. >=2 e.
    [[ ${rcs[0]} -le 1 && ${rcs[1]} -eq 0 ]] || refuse "copierea restului volumului a eșuat (tar: ${rcs[*]})"
    # Dovada pe EFECT: fiecare fișier din sursă (în afară de bază și crash.journal) există în copie. Ambele liste trebuie să
    # fie nevide: o listă goală ar face «nu lipsește nimic» adevărat pentru orice.
    src_list="$(cd "$src" && find . -type f ! -path ./database.sqlite ! -path ./database.sqlite-wal ! -path ./database.sqlite-shm ! -path ./crash.journal | sort)" \
        || unknown "nu pot lista fișierele din sursă"
    dst_list="$(cd "$dst" && find . -type f | sort)" || unknown "nu pot lista fișierele din copie"
    [[ -n "$src_list" ]] || unknown "sursa n-are niciun fișier în afară de bază: nu pot dovedi copia"
    missing="$(comm -23 <(printf '%s\n' "$src_list") <(printf '%s\n' "$dst_list"))" || unknown "comparația listelor de fișiere a eșuat"
    [[ -z "$missing" ]] || refuse "în copie lipsesc fișiere din volumul de producție (primele): $(head -n 5 <<<"$missing" | tr '\n' ' ')"
    # Cheia de criptare: dacă `config` diferă, toate credențialele din copie sunt ilizibile.
    if [[ -f "$src/config" ]]; then
        [[ -f "$dst/config" ]] || refuse "fișierul config (cheia de criptare) lipsește din copie"
        cmp -s -- "$src/config" "$dst/config" || refuse "fișierul config din copie diferă de cel din producție"
    fi
    # Directorul trebuie să aparțină utilizatorului `node` din container, ca în producție.
    chown "$(stat -c %u:%g -- "$src")" -- "$dst"
    chmod "$(stat -c %a -- "$src")" -- "$dst"
    [[ "$(stat -c %u:%g -- "$dst")" == "$(stat -c %u:%g -- "$src")" ]] || refuse "proprietarul directorului copiat nu coincide cu al sursei"
}

# Gazda are 2 procesoare, iar producția (n8n, site-urile) rulează pe ea fără limite: copierea unei baze de ~10 GB și un
# integrity_check de minute nu au voie să le ia I/O-ul și procesorul. `ionice -c3` = clasa idle (disk-ul gazdei, sda, folosește
# mq-deadline, care ignoră prioritățile din clasa best-effort, deci `-c2 -n7` n-ar fi făcut nimic), `nice -n 19` = cea mai joasă la procesor.
lowprio() {
    if command -v ionice >/dev/null; then ionice -c3 nice -n 19 "$@"; else nice -n 19 "$@"; fi
}

# Etapa 1: copia online. Tipărește «înainte după» pe stdout (rândurile din workflow_entity în producție).
db_backup() {
    lowprio python3 -c "$SQLITE_PY" backup "$1/database.sqlite" "$2/database.sqlite"
}

# Etapa 2: dovezile pe copie.
db_verify() {
    lowprio python3 -c "$SQLITE_PY" verify "$1/database.sqlite" "$2" "$3"
}

copy_database() {
    local src="$1" dst="$2" counts before after
    say "copiez baza prin backup online (producția rămâne pornită); la baze mari durează minute"
    counts="$(db_backup "$src" "$dst")" || refuse "backup-ul online al bazei a eșuat"
    read -r before after <<<"$counts"
    is_digits "${before:-}" && is_digits "${after:-}" || unknown "backup-ul n-a raportat numărul de rânduri (\"$counts\")"
    chown "$(stat -c %u:%g -- "$src/database.sqlite")" -- "$dst/database.sqlite"
    chmod "$(stat -c %a -- "$src/database.sqlite")" -- "$dst/database.sqlite"
    say "verific copia: workflow_entity și PRAGMA integrity_check (pe o bază mare durează mult)"
    db_verify "$dst" "$before" "$after" || refuse "copia bazei NU e dovedită; n8n NU pornește"
    # dovada folosește o conexiune care poate lăsa -wal/-shm: nu trebuie să ajungă în volumul copiat
    rm -f -- "$dst/database.sqlite-wal" "$dst/database.sqlite-shm"
}

# Containerul creat (încă oprit) are forma cerută: o singură rețea, fără porturi, volumul NOU, /files doar-citire.
verify_created_shape() {
    local net ports mounts dst typ name src rw saw_data=0 saw_files=0 lab limits nano mem
    net="$(docker container inspect "$STAGING_CONTAINER" --format '{{.HostConfig.NetworkMode}}')" || unknown "nu pot inspecta $STAGING_CONTAINER"
    [[ "$net" == "$STAGING_NET" ]] || refuse "containerul e pe rețeaua \"$net\", nu pe $STAGING_NET; nu pornesc"
    ports="$(docker container inspect "$STAGING_CONTAINER" --format '{{json .HostConfig.PortBindings}}')" || unknown "nu pot citi porturile"
    case "$ports" in '{}'|'null'|'') ;; *) refuse "containerul publică porturi ($ports); nu pornesc" ;; esac
    lab="$(label_value container "$STAGING_CONTAINER")" || unknown "nu pot citi eticheta containerului"
    [[ "$lab" == 1 ]] || refuse "containerul n-are eticheta ${LABEL_KEY}=1; nu pornesc"
    # limitele cerute (producția nu are; gazda are 2 procesoare): citite înapoi din container, nu presupuse
    limits="$(docker container inspect "$STAGING_CONTAINER" --format '{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}')" || unknown "nu pot citi limitele containerului"
    read -r nano mem <<<"$limits"
    { is_digits "${nano:-}" && is_digits "${mem:-}" && [[ "$nano" != 0 && "$mem" != 0 ]]; } \
        || refuse "containerul n-are limite de CPU/memorie (NanoCpus=${nano:-?} Memory=${mem:-?}); nu pornesc"
    mounts="$(docker container inspect "$STAGING_CONTAINER" --format '{{range .Mounts}}{{.Destination}}|{{.Type}}|{{.Name}}|{{.Source}}|{{.RW}}{{println}}{{end}}')" \
        || unknown "nu pot citi montările containerului"
    while IFS='|' read -r dst typ name src rw; do
        [[ -n "$dst" ]] || continue
        if [[ "$name" == "$PROD_VOLUME" || "$src" == */volumes/"$PROD_VOLUME"/* ]]; then
            refuse "containerul de staging montează VOLUMUL DE PRODUCȚIE $PROD_VOLUME la $dst; nu pornesc"
        fi
        if [[ "$dst" == "$DATA_DIR_IN_CONTAINER" ]]; then
            [[ "$name" == "$STAGING_VOLUME" ]] || refuse "$DATA_DIR_IN_CONTAINER nu e volumul $STAGING_VOLUME (e \"$name\"); nu pornesc"
            saw_data=1
        fi
        if [[ "$dst" == /files ]]; then
            [[ "$rw" == false ]] || refuse "/files e montat READ-WRITE în staging: un workflow ar modifica fișierele de producție; nu pornesc"
            saw_files=1
        fi
    done <<<"$mounts"
    [[ $saw_data -eq 1 ]] || refuse "containerul nu montează $STAGING_VOLUME la $DATA_DIR_IN_CONTAINER; nu pornesc"
    if [[ -n "$FILES_SRC" && $saw_files -ne 1 ]]; then refuse "/files trebuia montat doar-citire și lipsește din container; nu pornesc"; fi
}

container_ip() {
    docker container inspect "$STAGING_CONTAINER" \
        --format "{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}} {{\$v.IPAddress}}{{println}}{{end}}"
}

# După pornire: DOAR rețeaua de staging, cu o adresă. Tipărește adresa.
verified_ip() {
    local nets n ip name
    nets="$(container_ip)" || return 3
    n="$(grep -c . <<<"$nets" || true)"
    [[ "$n" == 1 ]] || { bad "containerul e pe $n rețele (trebuia exact una): $(tr '\n' ';' <<<"$nets")"; return 1; }
    read -r name ip <<<"$nets"
    [[ "$name" == "$STAGING_NET" ]] || { bad "containerul e pe rețeaua \"$name\", nu pe $STAGING_NET"; return 1; }
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { bad "containerul n-are adresă IPv4 pe $STAGING_NET (\"$ip\")"; return 3; }
    printf '%s\n' "$ip"
}

healthz_code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://$1:${N8N_PORT_IN_CONTAINER}/healthz" || true
}

sample_state() {
    docker container inspect "$STAGING_CONTAINER" --format '{{.State.Status}} {{.RestartCount}} {{.State.StartedAt}}'
}

# 0 dacă textul întors de scrub_stream e un înlocuitor (filtrul a căzut sau n-a avut valorile), nu un jurnal filtrat.
log_is_hidden() { [[ "$1" == "$SCRUB_FAILED_MSG" || "$1" == "$SCRUB_UNREADABLE_MSG" ]]; }

# Un jurnal ascuns NU e un jurnal fără migrări sau erori: sub fiecare titlu se spune că nu se știe, nu se lasă titlul gol (un titlu gol
# la capătul unui `up` reușit se citește ca «nicio eroare»).
show_log_excerpt() {
    local logs hidden=0
    logs="$(docker logs --tail 3000 "$STAGING_CONTAINER" 2>&1)" || true
    logs="$(scrub_stream <<<"$logs")" || logs="$SCRUB_FAILED_MSG"
    if log_is_hidden "$logs"; then hidden=1; fi
    say "migrările bazei, din jurnal (cel mult 30):"
    if [[ $hidden -eq 1 ]]; then
        printf '    %s\n    NU știu dacă există migrări: jurnalul nu poate fi arătat, iar liniile lui nu se tipăresc nefiltrate.\n' "$logs"
    else
        { grep -i -E 'migrat' <<<"$logs" || true; } | awk 'NR <= 30 { print "    " $0 }'
    fi
    say "linii de eroare, din jurnal (cel mult 30):"
    if [[ $hidden -eq 1 ]]; then
        printf '    %s\n    NU știu dacă există erori: jurnalul nu poate fi arătat, iar liniile lui nu se tipăresc nefiltrate.\n' "$logs"
    else
        { grep -i -E 'error|fatal|exception|cannot|failed' <<<"$logs" || true; } | awk 'NR <= 30 { print "    " $0 }'
    fi
}

# Progres cât așteaptă: ultimele linii din jurnal, filtrate. O migrare de ore pe o bază mare arată altfel ca un proces blocat.
show_progress() {
    local waited="$1" tail_logs
    tail_logs="$(docker logs --tail 2 "$STAGING_CONTAINER" 2>&1)" || tail_logs=""
    tail_logs="$(scrub_stream <<<"$tail_logs")" || tail_logs="$SCRUB_FAILED_MSG"
    say "încă aștept (~${waited}s); ultimele linii din jurnal:"
    if log_is_hidden "$tail_logs"; then
        printf '    | %s\n    | (liniile nu se tipăresc nefiltrate; nu știu ce spun)\n' "$tail_logs"
    else
        awk 'NF { print "    | " $0 }' <<<"$tail_logs"
    fi
}

wait_healthy() {
    local ip="$1" i code="" state waited=0
    say "aștept /healthz 200 pe http://${ip}:${N8N_PORT_IN_CONTAINER}, cel mult ${HEALTH_TRIES} încercări la ${POLL_S}s (migrările pe o bază mare pot dura zeci de minute)"
    for ((i = 0; i < HEALTH_TRIES; i++)); do
        state="$(sample_state)" || unknown "nu pot citi starea lui $STAGING_CONTAINER"
        if [[ "${state%% *}" != running ]]; then
            bad "containerul nu mai rulează (${state}) înainte să răspundă /healthz: a MURIT, nu migrează"
            show_log_excerpt
            exit 1
        fi
        code="$(healthz_code "$ip")"
        if [[ "$code" == 200 ]]; then good "/healthz a răspuns 200"; return 0; fi
        if [[ $PROGRESS_EVERY -gt 0 && $i -gt 0 && $((i % PROGRESS_EVERY)) -eq 0 ]]; then show_progress $((i * POLL_S)); fi
        sleep "$POLL_S"
    done
    # Timpul a trecut: spune dacă n8n încă lucrează sau a murit între timp (două situații cu remedii opuse).
    state="$(sample_state)" || unknown "nu pot citi starea lui $STAGING_CONTAINER după expirarea așteptării"
    if [[ "${state%% *}" == running ]]; then
        bad "/healthz n-a răspuns 200 în ${HEALTH_TRIES} încercări (ultimul cod: ${code:-?}), dar containerul ÎNCĂ RULEAZĂ (${state}): probabil încă migrează."
        bad "Urmărește cu \`logs\`; când /healthz răspunde, \`status\` o confirmă. Sau \`down\` și reia cu --health-timeout mai mare."
    else
        bad "/healthz n-a răspuns 200 în ${HEALTH_TRIES} încercări, iar containerul a MURIT între timp (${state}); jurnalul de mai jos spune de ce."
    fi
    show_log_excerpt
    exit 1
}

# O singură probă «rulează» nu dovedește nimic: o buclă de crash trece prin «running» la fiecare repornire. Fereastra cere
# ca TOATE eșantioanele să fie identice (rulează, RestartCount 0, același StartedAt) și /healthz 200 la capăt.
stability_window() {
    local ip="$1" first now i
    first="$(sample_state)" || unknown "nu pot citi starea lui $STAGING_CONTAINER"
    [[ "$first" == "running 0 "* ]] || { bad "la începutul ferestrei de stabilitate: \"$first\" (cerut: running, RestartCount 0)"; show_log_excerpt; exit 1; }
    say "fereastra de stabilitate: ${STABLE_SAMPLES} eșantioane la ${POLL_S}s, aceeași pornire, RestartCount 0"
    for ((i = 0; i < STABLE_SAMPLES; i++)); do
        sleep "$POLL_S"
        now="$(sample_state)" || unknown "nu pot citi starea lui $STAGING_CONTAINER"
        if [[ "$now" != "$first" ]]; then
            bad "containerul NU e stabil: la început \"$first\", acum \"$now\" (a repornit sau s-a oprit)"
            show_log_excerpt
            exit 1
        fi
    done
    [[ "$(healthz_code "$ip")" == 200 ]] || { bad "/healthz nu mai răspunde 200 la capătul ferestrei"; show_log_excerpt; exit 1; }
    good "stabil: ${STABLE_SAMPLES} eșantioane identice, RestartCount 0, /healthz 200"
}

# Tipul versiunii declarat de IMAGINE (N8N_RELEASE_TYPE din Config.Env): `3.0.1` a declarat `rc`. Doar informare + avertisment;
# nu refuză (operatorul poate vrea tocmai un rc ca să-l încerce). Se tipărește doar această cheie, nu tot mediul imaginii.
release_type_of() {
    docker image inspect "$1" --format '{{json .Config.Env}}' | python3 -c "$RELEASE_PY"
}

report_release_type() {
    local rt=""
    rt="$(release_type_of "$1")" || rt=""
    if [[ ! "$rt" =~ ^[A-Za-z0-9._-]{1,32}$ ]]; then
        bad "imaginea nu declară un N8N_RELEASE_TYPE lizibil: nu știu dacă e stabilă. Verifică înainte să tragi concluzii din încercare."
    elif [[ "$rt" != stable ]]; then
        bad "ATENȚIE: imaginea $1 declară N8N_RELEASE_TYPE=${rt}, nu «stable»: e o versiune de testare, nu cea pe care o vei instala în producție."
    else
        say "imaginea declară N8N_RELEASE_TYPE=stable"
    fi
}

cmd_up() {
    local version="$1" image ip stage_dir create_err
    image="${IMAGE_REPO}:${version}"
    up_preflight

    say "descarc ${image} (nimic de staging nu e creat încă)"
    docker pull -q "$image" >/dev/null || refuse "nu pot descărca ${image}; nu există versiunea sau registrul e inaccesibil; nu creez nimic"
    docker image inspect "$image" --format '{{.Id}}' >/dev/null || refuse "imaginea ${image} nu e pe gazdă după pull; nu creez nimic"
    report_release_type "$image"
    say "limite pentru container și probă: --cpus ${CPUS} --memory ${MEMORY} (producția n-are limite; gazda are 2 procesoare)"

    say "creez rețeaua ${STAGING_NET} (--internal)"
    docker network create --internal --label "${LABEL_KEY}=1" "$STAGING_NET" >/dev/null || refuse "nu pot crea rețeaua ${STAGING_NET}"
    [[ "$(docker network inspect "$STAGING_NET" --format '{{.Internal}}')" == true ]] || refuse "rețeaua ${STAGING_NET} NU e internă (Internal != true); nu continui"
    PROBE_GATEWAY="$(network_gateway)"
    probe_before_start "$image"

    say "creez volumul ${STAGING_VOLUME}"
    docker volume create --label "${LABEL_KEY}=1" "$STAGING_VOLUME" >/dev/null || refuse "nu pot crea volumul ${STAGING_VOLUME}"
    stage_dir="$(docker volume inspect "$STAGING_VOLUME" --format '{{.Mountpoint}}')" || unknown "nu pot citi unde e volumul ${STAGING_VOLUME}"
    [[ "$stage_dir" == /* && -d "$stage_dir" ]] || unknown "punctul de montare al lui ${STAGING_VOLUME} nu e un director (\"$stage_dir\")"
    [[ "$stage_dir" != "$PROD_DATA_DIR" ]] || refuse "volumul de staging e același director cu cel de producție; STOP"

    say "copiez restul volumului (config cu cheia de criptare, nodes/, ...)"
    copy_rest_of_volume "$PROD_DATA_DIR" "$stage_dir"
    good "restul volumului copiat; config identic"
    copy_database "$PROD_DATA_DIR" "$stage_dir"
    good "baza copiată și dovedită"

    say "pregătesc mediul (valorile NU se tipăresc)"
    write_env_file
    ERR_FILE="$(umask 077; mktemp "${TMP_BASE}/n8n-staging-err.XXXXXX")"
    local args=(create --name "$STAGING_CONTAINER" --network "$STAGING_NET" --label "${LABEL_KEY}=1" --restart no
                --cpus "$CPUS" --memory "$MEMORY" --memory-swap "$MEMORY"
                --env-file "$ENV_FILE" -v "${STAGING_VOLUME}:${DATA_DIR_IN_CONTAINER}")
    if [[ -n "$FILES_SRC" ]]; then
        args+=(-v "${FILES_SRC}:/files:ro")
        say "/files: montat DOAR-CITIRE din ${FILES_SRC}"
    else
        say "/files: producția nu are o montare bind la /files; nu montez nimic"
    fi
    args+=("$image")
    if ! docker "${args[@]}" >/dev/null 2>"$ERR_FILE"; then
        create_err="$(scrub_stream <"$ERR_FILE")" || create_err="$SCRUB_FAILED_MSG"
        if [[ -n "$create_err" ]]; then printf '%s\n' "$create_err" | sed 's/^/    docker: /' >&2; fi
        if log_is_hidden "$create_err"; then
            refuse "docker create a eșuat; mesajul lui docker NU se arată (filtrarea a eșuat sau nu pot citi valorile de mediu), deci nu știu ce a spus"
        fi
        refuse "docker create a eșuat (mesajul de mai sus are valorile de mediu înlocuite cu ***)"
    fi
    STAGING_CREATED=1
    rm -f -- "$ERR_FILE"; ERR_FILE=""
    verify_created_shape
    good "container creat: o singură rețea, fără porturi, volum nou, /files verificat"

    say "pornesc ${STAGING_CONTAINER}"
    docker start "$STAGING_CONTAINER" >/dev/null || refuse "docker start a eșuat"
    probe_after_start
    # O a doua rețea sau o rețea greșită după pornire contrazice tot ce s-a dovedit: containerul nu rămâne pornit.
    if ! ip="$(verified_ip)"; then
        remove_staging_container_now || true
        refuse "forma rețelei containerului pornit nu e cea cerută (o singură rețea, ${STAGING_NET}); l-am șters"
    fi
    wait_healthy "$ip"
    stability_window "$ip"
    show_log_excerpt
    good "TOT DOVEDIT: ${STAGING_CONTAINER} (${version}) rulează izolat, stabil, cu baza copiată și verificată"
    printf 'N8N_STAGING_IP=%s\n' "$ip"
    printf 'Tunel (de pe stația ta):  ssh -N -L %s:%s:%s <utilizator>@<gazdă>\n' "$LOCAL_TUNNEL_PORT" "$ip" "$N8N_PORT_IN_CONTAINER"
    printf 'Apoi deschide:            http://localhost:%s/\n' "$LOCAL_TUNNEL_PORT"
}

# ---------------------------------------------------------------------------------------------------------------
# status, logs, down
# ---------------------------------------------------------------------------------------------------------------

cmd_status() {
    local kind name present=0 total=0 rc state ip code lab
    for kind in container volume network; do
        case "$kind" in container) name="$STAGING_CONTAINER" ;; volume) name="$STAGING_VOLUME" ;; network) name="$STAGING_NET" ;; esac
        total=$((total + 1))
        rc=0; has_name_or_die "$kind" "$name" || rc=$?
        if [[ $rc -eq 0 ]]; then
            present=$((present + 1))
            lab="$(label_value "$kind" "$name")" || unknown "nu pot citi eticheta lui $kind $name"
            say "$kind $name: există (etichetă ${LABEL_KEY}=${lab:-<lipsă>})"
        else
            say "$kind $name: nu există"
        fi
    done
    if [[ $present -eq 0 ]]; then good "nu există staging"; return 0; fi
    if [[ $present -ne $total ]]; then bad "staging PARȚIAL ($present din $total obiecte); \`down\` îl curăță"; return 1; fi
    state="$(sample_state)" || unknown "nu pot citi starea lui $STAGING_CONTAINER"
    say "stare: $state"
    if [[ "$state" != "running 0 "* ]]; then bad "containerul nu rulează stabil"; return 1; fi
    ip="$(verified_ip)" || { bad "forma rețelei containerului nu e cea cerută"; return 1; }
    code="$(healthz_code "$ip")"
    say "adresă $ip, /healthz: ${code}"
    if [[ "$code" != 200 ]]; then bad "/healthz nu răspunde 200"; return 1; fi
    printf 'N8N_STAGING_IP=%s\n' "$ip"
    printf 'Tunel (de pe stația ta):  ssh -N -L %s:%s:%s <utilizator>@<gazdă>\n' "$LOCAL_TUNNEL_PORT" "$ip" "$N8N_PORT_IN_CONTAINER"
}

cmd_logs() {
    local tail="$1" logs filtered
    has_name_or_die container "$STAGING_CONTAINER" || refuse "containerul $STAGING_CONTAINER nu există"
    logs="$(docker logs --tail "$tail" "$STAGING_CONTAINER" 2>&1)" || unknown "docker logs a eșuat"
    filtered="$(scrub_stream <<<"$logs")" || unknown "nu pot filtra jurnalul; nu-l tipăresc"
    printf '%s\n' "$filtered"
}

# Șterge un obiect de un fel, DOAR dacă poartă eticheta; apoi dovedește că a dispărut.
remove_one() {
    local kind="$1" name="$2" rc=0
    case "$name" in
        "$PROD_CONTAINER"|"$PROD_VOLUME"|"$PROD_NETWORK") refuse "REFUZ: $kind $name e din producție" ;;
    esac
    case "$kind" in
        container) docker rm -f "$name" >/dev/null || rc=$? ;;
        volume)    docker volume rm "$name" >/dev/null || rc=$? ;;
        network)   docker network rm "$name" >/dev/null || rc=$? ;;
    esac
    [[ $rc -eq 0 ]] || refuse "nu pot șterge $kind $name (cod $rc)"
    rc=0; has_name_or_die "$kind" "$name" || rc=$?
    [[ $rc -eq 1 ]] || refuse "$kind $name încă există după ștergere"
    good "$kind $name: șters și dovedit că a dispărut"
}

# `down` nu șterge imaginea trasă de `up` (n-o poate dovedi a nimănui altcuiva, iar o imagine ștearsă se trage din nou cu minute de
# descărcare): doar spune ce a rămas și comanda exactă, ca operatorul să decidă.
note_pulled_image() {
    local ref="$1"
    if [[ "$ref" =~ ^docker\.n8n\.io/n8nio/n8n:[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        say "imaginea ${ref}, trasă de \`up\`, RĂMÂNE pe gazdă (nu o șterg automat). Ca s-o scoți:  docker image rm ${ref}"
    else
        say "imaginea trasă de \`up\` RĂMÂNE pe gazdă (nu o șterg automat). O vezi cu:  docker image ls docker.n8n.io/n8nio/n8n  și o scoți cu:  docker image rm docker.n8n.io/n8nio/n8n:X.Y.Z"
    fi
}

cmd_down() {
    local kind name fixed lab rc targets=() line labelled image_ref=""
    # 1) tot ce vom șterge trebuie să poarte eticheta, ÎNAINTE să ștergem ceva
    for kind in container volume network; do
        case "$kind" in container) fixed="$STAGING_CONTAINER" ;; volume) fixed="$STAGING_VOLUME" ;; network) fixed="$STAGING_NET" ;; esac
        rc=0; has_name_or_die "$kind" "$fixed" || rc=$?
        if [[ $rc -eq 0 ]]; then
            lab="$(label_value "$kind" "$fixed")" || unknown "nu pot citi eticheta lui $kind $fixed"
            [[ "$lab" == 1 ]] || refuse "$kind $fixed există dar NU poartă eticheta ${LABEL_KEY}=1; nu e al meu, nu șterg nimic"
            if [[ "$kind" == container ]]; then
                image_ref="$(docker container inspect "$fixed" --format '{{.Config.Image}}')" || image_ref=""
            fi
        fi
        labelled="$(list_labelled "$kind")" || unknown "nu pot citi obiectele cu eticheta de staging ($kind)"
        while IFS= read -r name; do
            [[ -n "$name" ]] || continue
            lab="$(label_value "$kind" "$name")" || unknown "nu pot citi eticheta lui $kind $name"
            [[ "$lab" == 1 ]] || refuse "$kind $name are eticheta ${LABEL_KEY} cu valoarea \"$lab\", nu 1; nu șterg nimic"
            targets+=("$kind $name")
        done <<<"$labelled"
    done
    if [[ ${#targets[@]} -eq 0 ]]; then
        good "nu există obiecte de staging; nimic de șters"
        note_pulled_image ""
        return 0
    fi
    # 2) ordinea: containere, apoi volume, apoi rețele (o rețea cu puncte finale active nu se șterge)
    for kind in container volume network; do
        for line in "${targets[@]}"; do
            [[ "${line%% *}" == "$kind" ]] || continue
            remove_one "$kind" "${line#* }"
        done
    done
    note_pulled_image "$image_ref"
}

# ---------------------------------------------------------------------------------------------------------------

usage_die() { bad "$*"; bad "folosire: up --version X.Y.Z [--health-timeout S] [--cpus C] [--memory M] | status | logs [--tail N] | down"; exit 2; }

# Argumentele care ajung pe gazdă se validează AICI (și la fel în launcher): nimic nevalidat nu intră în aritmetică sau în docker.
valid_health_timeout() { is_digits "$1" && [[ ${#1} -le 5 ]] && (( 10#$1 >= 60 && 10#$1 <= 7200 )); }

# 0.25 - 2 procesoare (gazda are 2), cel mult două zecimale.
valid_cpus() {
    local int frac hundredths
    [[ "$1" =~ ^([0-9])(\.([0-9]{1,2}))?$ ]] || return 1
    int="${BASH_REMATCH[1]}"
    frac="${BASH_REMATCH[3]:-0}"
    [[ ${#frac} -eq 2 ]] || frac="${frac}0"
    hundredths=$((10#$int * 100 + 10#$frac))
    (( hundredths >= 25 && hundredths <= 200 ))
}

# 512 MB - 6 GB (gazda are 7,9 GB și producția rulează pe ea), cu sufixul m sau g.
valid_memory() {
    local mb
    [[ "$1" =~ ^([0-9]{1,4})([mg])$ ]] || return 1
    mb=$((10#${BASH_REMATCH[1]}))
    if [[ "${BASH_REMATCH[2]}" == g ]]; then mb=$((mb * 1024)); fi
    (( mb >= 512 && mb <= 6144 ))
}

main() {
    local sub="${1:-}" version="" tail=200
    # Când ssh cade, scrierea pe stdout/stderr ar omorî scriptul cu SIGPIPE înainte să ruleze ștergerea unui container
    # nedovedit. Ignorat: scrierile eșuează, iar `say`/`good`/`bad` își înghit eșecul.
    trap '' PIPE
    set +x
    exec </dev/null
    [[ $# -gt 0 ]] && shift
    case "$sub" in
        up)
            while [[ $# -gt 0 ]]; do
                [[ $# -ge 2 ]] || usage_die "$1 cere o valoare"
                case "$1" in
                    --version)
                        is_semver "$2" || usage_die "versiune refuzată: trebuie să fie exact MAJOR.MINOR.PATCH (cifre), nu \"$2\""
                        version="$2" ;;
                    --health-timeout)
                        valid_health_timeout "$2" || usage_die "--health-timeout cere secunde, doar cifre, între 60 și 7200 (nu \"$2\")"
                        HEALTH_TIMEOUT_S=$((10#$2)) ;;
                    --cpus)
                        valid_cpus "$2" || usage_die "--cpus cere un număr între 0.25 și 2 (cel mult două zecimale), nu \"$2\""
                        CPUS="$2" ;;
                    --memory)
                        valid_memory "$2" || usage_die "--memory cere o valoare ca 3g sau 2048m, între 512m și 6g, nu \"$2\""
                        MEMORY="$2" ;;
                    *) usage_die "argument necunoscut pentru up: \"$1\"" ;;
                esac
                shift 2
            done
            [[ -n "$version" ]] || usage_die "up cere --version X.Y.Z" ;;
        logs)
            if [[ $# -gt 0 ]]; then
                [[ "$1" == --tail && $# -eq 2 ]] || usage_die "logs primește doar: --tail N"
                is_digits "$2" && [[ ${#2} -le 5 ]] || usage_die "--tail cere un număr, nu \"$2\""
                tail="$2"
            fi ;;
        status|down) [[ $# -eq 0 ]] || usage_die "$sub nu primește argumente" ;;
        *) usage_die "subcomandă necunoscută: \"$sub\"" ;;
    esac
    is_digits "$POLL_S" && is_digits "$STABLE_SAMPLES" && is_digits "$PROGRESS_EVERY" || usage_die "N8N_STAGING_POLL_S/STABLE_SAMPLES/PROGRESS_EVERY cer numere"
    if [[ -n "${N8N_STAGING_HEALTH_TRIES:-}" ]]; then
        HEALTH_TRIES="$N8N_STAGING_HEALTH_TRIES"
    else
        HEALTH_TRIES=$((HEALTH_TIMEOUT_S / (10#$POLL_S > 0 ? 10#$POLL_S : 1)))
    fi
    is_digits "$HEALTH_TRIES" || usage_die "N8N_STAGING_HEALTH_TRIES cere un număr"
    command -v docker >/dev/null || unknown "docker lipsește de pe gazdă"
    docker version --format '{{.Server.Version}}' >/dev/null || unknown "daemonul docker nu răspunde"
    trap on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    PROD_FP_BEFORE="$(prod_fp)" || unknown "nu pot citi amprenta lui $PROD_CONTAINER"
    say "amprenta producției ($PROD_CONTAINER): $PROD_FP_BEFORE"
    case "$sub" in
        up)     cmd_up "$version" ;;
        status) cmd_status ;;
        logs)   cmd_logs "$tail" ;;
        down)   cmd_down ;;
    esac
}

# Pornește doar când e rulat (prin `bash -s` sau direct), nu când e încărcat cu `source` de teste. Ultima linie, ca
# stdin-ul pe care îl citește `bash -s` să fie gol când rulează main.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
