"""Smoke-testul nu are voie să raporteze întărirea instalatorului ca defecțiune.

Eșecul pe care îl previne: în mod `dedicated`, instalatorul pune pe portul
dashboard-ului un `default_server` cu `server_name _` și `return 444`, ca un scan
al adresei să nu afle nimic. Sonda de pe loopback cerea `https://127.0.0.1:PORT/`,
adică `Host: 127.0.0.1`, care nu se potrivește cu niciun vhost, deci cădea pe acel
bloc și conexiunea se închidea fără răspuns. `curl` raporta `000`, iar fiecare
livrare `dedicated` se termina cu „Verificări eșuate. Nu considera deployment-ul
reușit", chiar cu panoul sănătos (măsurat pe gazda n8n, 7 octombrie 2026: același
`curl` cu `Host: <numele gazdei>` dădea 200).

Costul real nu e zgomotul, ci pierderea semnalului: o verificare roșie MEREU nu
mai deosebește un panou sănătos de unul căzut. De aceea testele de aici cer două
lucruri, nu unul:

  * sonda ajunge la vhostul Sentinel (probată cu un `curl` real, împotriva unui
    server TLS care se poartă ca blocul `return 444` + un vhost pe nume);
  * cele două feluri de `000` — „nimic nu ascultă" și „nginx a închis conexiunea"
    — au mesaje diferite, fiindcă reacția operatorului e diferită: primul se
    rezolvă pornind nginx, al doilea reparând un `server_name`.

Ce NU reproduce simularea de mai jos: nginx-ul real (HTTP/2, ordinea blocurilor).
Are în schimb ce contează aici: un socket TLS real, un `curl` real și o decizie
după nume. Cu nginx-ul real s-a măsurat o dată, de mână (nginx 1.30.5 într-un
container, cu șablonul `sentinel-default-deny.conf.tmpl` randat ca atare și curl
rulat în interiorul containerului): fără `Host` -> `000` cu curl rc=92 (eroare de
flux HTTP/2, NU rc=52 cum dă un 444 peste HTTP/1.1); cu `Host: <vhost>` -> 200
rc=0; pe un port gol -> `000` rc=7. De aceea ramura „închis" e reziduală (orice
`000` în afară de refuz, timp depășit și eșec TLS), nu legată de un cod anume:
serverul de aici dă alt cod decât cel real, iar ambele trebuie să ajungă la același
mesaj.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts" / "smoke-test.sh"

BASH = shutil.which("bash")
CURL = shutil.which("curl")
OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(BASH is None, reason="fără bash în PATH")
needs_real_curl = pytest.mark.skipif(
    CURL is None or OPENSSL is None,
    reason="fără curl sau openssl în PATH — proba cu server TLS real nu poate rula")

SMOKE_TEXT = SMOKE.read_text(encoding="utf-8")


def _function(name: str) -> str:
    """Funcția TĂIATĂ din scriptul livrat, nu rescrisă.

    Un test care retipărește logica probează copia lui, nu codul care ajunge la
    operator.
    """
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", SMOKE_TEXT, re.S | re.M)
    assert match, f"{name}() nu a fost găsită în smoke-test.sh"
    return match.group(0)


def _dashboard_block() -> str:
    """Secțiunea „Dashboard", până la `nginx -t` — adică ce rulează chiar scriptul.

    Fără ea, testele ar proba funcțiile, dar nu și faptul că scriptul le CHEAMĂ:
    o sondă readusă inline, fără Host, ar rămâne nevăzută.
    """
    start = SMOKE_TEXT.index('sect "Dashboard"')
    end = SMOKE_TEXT.index('if r "sudo nginx -t"')
    assert 0 < start < end, "secțiunea Dashboard nu mai e cum o taie testul"
    return SMOKE_TEXT[start:end]


PRELUDE = r"""
set -euo pipefail
PASS=0; FAIL=0; WARN=0
pass() { PASS=$((PASS+1)); printf 'PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$*"; }
warn() { WARN=$((WARN+1)); printf 'WARN %s\n' "$*"; }
sect() { :; }
"""

EPILOGUE = 'printf "CONTOARE %s %s %s\\n" "$PASS" "$WARN" "$FAIL"\n'


def _bash(script: str, stdin: str = "", **env: str) -> str:
    # Valorile ajung prin MEDIU, nu lipite în text: un nume ostil ca `$(id)` ar fi
    # fost executat de harness-ul însuși, nu de funcția probată.
    #
    # `encoding` explicit: pe Windows `text=True` folosește cp1252, iar diacriticele
    # din mesaje ies mutilate. Un test care pică pe codare nu spune nimic despre
    # logica probată.
    #
    # Scriptul se dă ca FIȘIER, nu cu `bash -c`: pe Windows linia de comandă e limitată
    # la ~32 de mii de caractere și e tăiată TĂCUT. Cu funcțiile de citit nginx și
    # comentariile lor, scriptul de probă a depășit limita; bash a primit o bucată
    # care se oprea după `sect "Dashboard"`, a ieșit cu 0 fără nicio linie, iar
    # testele au căzut cu „scriptul nu a ajuns la contoare" — nu cu o eroare care să
    # spună de ce.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.sh"
        path.write_bytes(script.encode("utf-8"))
        proc = subprocess.run([BASH, str(path)], input=stdin, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=90,
                              env={**os.environ, **env})
    return proc.stdout + ("\n[stderr] " + proc.stderr if proc.stderr.strip() else "")


def _counts(out: str) -> tuple[int, int, int]:
    found = re.search(r"CONTOARE (\d+) (\d+) (\d+)", out)
    assert found, f"scriptul nu a ajuns la contoare; ieșire: {out!r}"
    return int(found.group(1)), int(found.group(2)), int(found.group(3))


def _classify(raw: str, name: str = "panou.test",
              origin: str = "domeniul instalat") -> tuple[str, int, int]:
    """Rulează `report_loopback_probe` pe un răspuns fabricat al sondei."""
    script = (PRELUDE + _function("report_loopback_probe") + "\n"
              'report_loopback_probe "$(cat)" 8443 "$T_NAME" "$T_ORIGIN"\n' + EPILOGUE)
    out = _bash(script, stdin=raw, T_NAME=name, T_ORIGIN=origin)
    passes, _warns, fails = _counts(out)
    return out, passes, fails


# --- decizia pe un răspuns dat -------------------------------------------------

@pytest.mark.parametrize("raw", ["200 rc=0", "302 rc=0", "401 rc=0", "307 rc=0"])
def test_an_answering_vhost_is_a_pass(raw: str) -> None:
    """Cealaltă jumătate: un vhost care răspunde nu devine alarmă.

    Fără cazul ăsta, o „reparație" care ar face orice răspuns eșec ar trece — iar
    un smoke-test roșu mereu e chiar defectul de la care s-a plecat.
    """
    out, passes, fails = _classify(raw)
    assert (passes, fails) == (1, 0), out
    assert "Host: panou.test" in out, (
        "pass-ul nu spune ce nume a fost trimis, deci operatorul nu știe ce s-a probat")


def test_nothing_listening_is_named_as_nothing_listening() -> None:
    """`000` + conexiune refuzată: nginx e oprit, nu „vhost greșit".

    Operatorul care citește „a închis conexiunea" caută un `server_name`, deși
    nginx nici nu rulează. Mesajul trebuie să spună ce comandă pornește serviciul,
    nu ce vhost să schimbe.
    """
    out, passes, fails = _classify("000 rc=7")
    assert (passes, fails) == (0, 1), out
    assert "NIMIC NU ASCULTĂ" in out, out
    assert "închis conexiunea" not in out, (
        "refuzul e prezentat ca un vhost care nu se potrivește: reacția cerută "
        "operatorului ar fi cea greșită")


@pytest.mark.parametrize("rc", ["52", "56", "92", "16", "55"])
def test_a_closed_connection_is_named_as_closed_not_as_nothing_listening(rc: str) -> None:
    """`000` fără refuz: nginx a primit conexiunea și a tăiat-o (blocul `return 444`).

    Operatorul care citește „nimic nu ascultă" pornește un nginx care deja rulează
    și pierde timp, iar vhostul cu `server_name` greșit rămâne neatins. Codurile
    sunt cele pe care curl le dă pentru conexiune închisă sau resetată, inclusiv
    cele de HTTP/2: 92 e codul MĂSURAT pe nginx-ul real (1.30.5, șablonul de
    refuz al instalatorului); 52 e cel al unui 444 peste HTTP/1.1. O ramură legată
    doar de 52 n-ar fi recunoscut închiderea tocmai pe gazda reală.
    """
    out, passes, fails = _classify(f"000 rc={rc}")
    assert (passes, fails) == (0, 1), out
    assert "închis conexiunea" in out, out
    assert "NIMIC NU ASCULTĂ" not in out, (
        f"curl rc={rc} (nginx a răspuns TCP) a fost numit „nimic nu ascultă”")
    assert "server_name panou.test" in out, (
        "mesajul nu spune ce să caute în configurație")
    assert f"rc={rc}" in out, "codul curl lipsește, deci diagnosticul nu se poate repeta"


@pytest.mark.parametrize("raw, phrase", [
    ("000 rc=28", "10 s"),
    ("000 rc=35", "handshake-ul TLS"),
    (" rc=127", "curl nu există pe gazdă"),
])
def test_other_failures_each_get_their_own_message(raw: str, phrase: str) -> None:
    """Timp depășit, TLS stricat și curl lipsă nu sunt „vhost greșit".

    Fiecare are altă cauză și altă reacție; toate ar fi arătat la fel sub un
    singur „nu răspunde".
    """
    out, passes, fails = _classify(raw)
    assert (passes, fails) == (0, 1), out
    assert phrase in out, out
    assert "închis conexiunea" not in out, out


@pytest.mark.parametrize("raw", ["", "000000", "garbage", "200"])
def test_an_unreadable_answer_is_a_failure_not_a_pass(raw: str) -> None:
    """Un răspuns pe care nu-l înțeleg nu dovedește nimic.

    ssh căzut dă o ieșire goală; vechiul `|| echo 000` lipea două `000`. Niciunul
    nu e „nginx servește" și niciunul nu e „nimic nu ascultă": e „nu știu", iar o
    verificare care nu poate dovedi nu are voie să treacă.
    """
    out, passes, fails = _classify(raw)
    assert (passes, fails) == (0, 1), out
    assert "citibil" in out, out
    assert "NIMIC NU ASCULTĂ" not in out, out


def test_an_http_error_from_the_vhost_is_a_failure() -> None:
    """404/500 de la nginx nu sunt „serviciul răspunde".

    Vhost-ul e ales corect, dar `/healthz` nu e al Sentinel: dashboard-ul nu e
    acolo, deci verde ar fi minciună.
    """
    out, passes, fails = _classify("404 rc=0")
    assert (passes, fails) == (0, 1), out
    assert "HTTP 404" in out, out


def test_a_truncated_response_is_not_accepted_on_its_status_line_alone() -> None:
    """`200` urmat de un curl care a murit nu e un 200 întreg.

    Cu codul de ieșire ignorat, un răspuns tăiat la jumătate trecea ca sănătos.
    """
    out, passes, fails = _classify("200 rc=28")
    assert (passes, fails) == (0, 1), out
    assert "întrerupt" in out, out


def test_only_the_last_line_of_the_remote_output_is_the_answer() -> None:
    """Un banner pe care gazda îl tipărește la login nu strică citirea.

    Un `.bashrc` care face `echo` ar fi transformat orice sondă într-un
    „răspuns ilizibil", adică un eșec fals de alt fel.
    """
    out, passes, fails = _classify("Welcome to host\nlast login: x\n200 rc=0")
    assert (passes, fails) == (1, 0), out


# --- alegerea numelui ----------------------------------------------------------

def _pick_full(*, flag: str = "", yaml: str = "", host: str = "n8n",
               state: str = "unreadable", nginx_name: str = "",
               nginx_names: str = "") -> tuple[str, str, str]:
    """`pick_probe_name` pe intrări fabricate: (nume, de unde, notă).

    `DOMAIN` e ce ar fi lăsat scriptul după citirea lui sentinel.yaml: flag-ul dacă
    a fost dat, altfel domeniul din yaml.
    """
    script = (PRELUDE + _function("pick_probe_name") + "\n"
              'DOMAIN_FLAG="$T_FLAG"; DOMAIN="${T_FLAG:-$T_YAML}"; HOST="$T_HOST"; WEB_PORT=8443\n'
              'NGINX_STATE="$T_STATE"; NGINX_NAME="$T_NGINX"; NGINX_NAMES="$T_NAMES"\n'
              'pick_probe_name\n'
              'printf "NUME=[%s]\\nDIN=[%s]\\nNOTA=[%s]\\n" "$PROBE_NAME" "$PROBE_NAME_FROM" "$PROBE_NOTE"\n')
    out = _bash(script, T_FLAG=flag, T_YAML=yaml, T_HOST=host, T_STATE=state,
                T_NGINX=nginx_name, T_NAMES=nginx_names)
    name = re.search(r"NUME=\[(.*)\]", out)
    origin = re.search(r"DIN=\[(.*)\]", out)
    note = re.search(r"NOTA=\[(.*)\]", out)
    assert name and origin and note, out
    return name.group(1), origin.group(1), note.group(1)


def _pick(domain: str, host: str) -> tuple[str, str]:
    name, origin, _note = _pick_full(yaml=domain, host=host)
    return name, origin


def test_the_domain_wins_over_the_ssh_host() -> None:
    """Vhostul se alege după domeniu; adresa ssh poate fi un IP sau alt nume.

    Cu `--host` luat înaintea domeniului, o gazdă ajunsă prin IP ar trimite
    `Host: <ip>`, care cade pe blocul de refuz — chiar eșecul fals reparat aici.
    """
    assert _pick("panou.exemplu.ro", "203.0.113.10")[0] == "panou.exemplu.ro"


def test_without_a_domain_the_ssh_host_is_used_and_says_so() -> None:
    """Fără domeniu se încearcă `--host`, iar mesajul spune de unde vine numele.

    Altfel un eșec ar trimite operatorul să caute un vhost după un nume pe care
    scriptul l-a ghicit, nu pe care l-a primit.
    """
    name, origin = _pick("", "gazda.exemplu.ro")
    assert name == "gazda.exemplu.ro"
    assert "--host" in origin, origin


@pytest.mark.parametrize("hostile", ["x'; touch /tmp/pwn; '", "a b", "$(id)", "a`id`", "2001:db8::1", ""])
def test_a_name_that_is_not_a_plain_hostname_is_never_sent(hostile: str) -> None:
    """Numele intră într-o comandă care rulează pe gazdă, ca root-adiacent.

    `--domain` e dat de operator, dar `domain:` vine și din sentinel.yaml de pe
    gazdă: un fișier care nu trebuie să poată executa nimic în comanda de probă.
    Un nume cu ghilimele sau spații nu se trimite deloc; sonda rulează fără antet
    și spune că n-a avut un nume.
    """
    name, origin = _pick(hostile, hostile)
    assert name == "", f"nume nesigur acceptat: {name!r}"
    assert "niciun nume utilizabil" in origin, origin

    # Și ce ajunge efectiv în comanda trimisă gazdei, nu doar numele ales.
    script = (PRELUDE + _function("pick_probe_name") + "\n" + _function("probe_loopback") + "\n"
              'DOMAIN_FLAG=""; DOMAIN="$T_DOMAIN"; HOST="$T_HOST"; WEB_PORT=8443\n'
              'NGINX_STATE=unreadable; NGINX_NAME=""; NGINX_NAMES=""\n'
              'r() { printf "%s" "$*"; }\n'
              'pick_probe_name\n'
              'probe_loopback 8443 "$PROBE_NAME"\n')
    sent = _bash(script, T_DOMAIN=hostile, T_HOST=hostile)
    assert "curl" in sent, f"proba n-a produs nicio comandă: {sent!r}"
    assert "-H" not in sent and "touch" not in sent, sent


# --- cu un curl real, împotriva unui nginx de joacă -----------------------------

class FakeNginx:
    """Un server TLS care se poartă ca instalarea `dedicated`.

    Un vhost pe nume (`vhost`) care răspunde 200 și un `default_server` care
    închide conexiunea fără un octet (`return 444`). Alege după antetul `Host`,
    ca nginx.
    """

    def __init__(self, vhost: str | None, cert: Path, key: Path, hang: bool = False,
                 status: int = 200) -> None:
        self.vhost = vhost
        self.status = status  # ce răspunde vhostul: 200, o redirecționare, o eroare
        self.hang = hang  # primește cererea și nu mai răspunde niciodată
        self.hosts_seen: list[str] = []
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(str(cert), str(key))
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        try:
            raw.settimeout(10)
            conn = self._ctx.wrap_socket(raw, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                head += chunk
            found = re.search(rb"(?im)^host:[ \t]*([^\r\n:]*)", head)
            host = found.group(1).decode("ascii", "replace").strip().lower() if found else ""
            self.hosts_seen.append(host)
            if self.hang:
                time.sleep(15)
                conn.close()
                return
            if self.vhost is None or host == self.vhost:  # None = fără bloc de refuz
                reason = {200: "OK", 307: "Temporary Redirect", 404: "Not Found"}[self.status]
                conn.sendall(f"HTTP/1.1 {self.status} {reason}\r\nContent-Length: 2\r\n"
                             "Location: /login\r\nConnection: close\r\n\r\nok".encode())
            # altfel: 444 — se închide fără niciun octet de răspuns
            try:
                conn.unwrap()
            except (OSError, ssl.SSLError):
                pass
            conn.close()
        except (OSError, ssl.SSLError):
            try:
                raw.close()
            except OSError:
                pass

    def close(self) -> None:
        self._sock.close()


@pytest.fixture(scope="module")
def tls_pair(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Certificat autosemnat generat acum — nicio cheie privată în depozit."""
    directory = tmp_path_factory.mktemp("tls")
    cert, key = directory / "c.pem", directory / "k.pem"
    subprocess.run(
        [OPENSSL, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
         "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=probe"],
        check=True, capture_output=True, timeout=60,
        env={**os.environ, "MSYS_NO_PATHCONV": "1"})
    return cert, key


def _free_port_nobody_listens_on() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


_APP_STUBS = {"ok": "printf 200", "refused": "printf 000; return 7", "ssh_down": "return 255"}


def _run_dashboard(*, domain: str, host: str, port: int, app: str = "ok",
                   flag: str = "", nginx_dump: str = "", mode: str = "dedicated",
                   container: str = "",
                   nginx_unreadable: bool = False) -> tuple[str, int, int]:
    """Secțiunea Dashboard din scriptul livrat, cu `r` care rulează LOCAL.

    `r` înlocuiește ssh: comanda de pe gazdă e dată unui shell, ca acolo. Verificarea
    de pe 8787 e răspunsă de un cod fix (`app`): „ok" = 200, „refused" = curl a
    tipărit 000 și a ieșit cu 7, „ssh_down" = nicio ieșire și cod 255.

    `domain` e ce a citit scriptul din sentinel.yaml (sau flag-ul), `flag` doar ce a
    dat operatorul cu `--domain`. `nginx_dump` e ce întoarce `sudo nginx -T` (gol =
    nu s-a putut citi). Cu `container`, TOATE comenzile de pe gazdă rulează în acel
    container nginx, nu local — adică pe un nginx adevărat.
    """
    functions = "\n".join(_function(n) for n in (
        "parse_nginx_vhost_name", "pick_probe_name", "probe_loopback",
        "report_loopback_probe"))
    # Un sudo care cere parola: nicio listare, cod nenul — ce vede scriptul când nu
    # poate citi nginx (aceeași comandă, nu un alt cod de ieșire inventat).
    denied = '*"nginx -T"*) printf "sudo: a password is required"; return 1 ;; '
    if container:
        # `sudo` nu există în container; comanda rămâne aceeași, fără prefix.
        runner = ((denied if nginx_unreadable else "")
                  + '*) docker exec ' + container + ' sh -c "${*//sudo /}" ;;')
    else:
        runner = ((denied if nginx_unreadable else "")
                  + '*"nginx -T"*) printf "%s" "$T_DUMP" ;; *) bash -c "$*" ;;')
    script = (PRELUDE + functions + "\n"
              f'DOMAIN_FLAG="$T_FLAG"; DOMAIN="$T_DOMAIN"; HOST="$T_HOST"; '
              f'WEB_PORT={port}; NGINX_MODE="$T_MODE"\n'
              'r() { case "$*" in *127.0.0.1:8787*) ' + _APP_STUBS[app]
              + ' ;; ' + runner + ' esac; }\n'
              + _dashboard_block() + "\n" + EPILOGUE)
    out = _bash(script, T_DOMAIN=domain, T_HOST=host, T_FLAG=flag, T_DUMP=nginx_dump,
                T_MODE=mode)
    passes, _warns, fails = _counts(out)
    return out, passes, fails


@needs_real_curl
def test_the_probe_reaches_sentinels_vhost_behind_a_catch_all_deny(tls_pair) -> None:
    """Cazul care a dat „Verificări eșuate" pe un panou sănătos.

    Un `default_server` care închide conexiunea și un vhost pe nume: sonda trebuie
    să treacă. Reintrodu `https://127.0.0.1:PORT/healthz` fără Host și cererea cade
    pe blocul de refuz — deci testul pică exact cum a picat livrarea.
    """
    server = FakeNginx("panou.test", *tls_pair)
    try:
        out, passes, fails = _run_dashboard(domain="panou.test", host="127.0.0.1",
                                            port=server.port)
    finally:
        server.close()
    assert fails == 0, f"sonda a picat pe un vhost sănătos:\n{out}"
    assert "PASS nginx serving" in out, out
    assert "panou.test" in server.hosts_seen, (
        f"serverul n-a primit niciodată Host: panou.test (a primit {server.hosts_seen}) — "
        "sonda n-a ajuns la vhost, a trecut prin altceva")


@needs_real_curl
def test_a_vhost_that_does_not_match_the_name_is_reported_as_closed(tls_pair) -> None:
    """Vhost cu alt `server_name` decât domeniul: eșec, și spune CE e greșit.

    Fără ramura asta panoul ar putea fi nerutat pentru toți vizitatorii, iar
    smoke-testul ar rămâne verde.
    """
    server = FakeNginx("alt-nume.test", *tls_pair)
    try:
        out, passes, fails = _run_dashboard(domain="panou.test", host="127.0.0.1",
                                            port=server.port)
    finally:
        server.close()
    assert fails == 1, out
    assert "închis conexiunea" in out, out
    assert "NIMIC NU ASCULTĂ" not in out, out
    assert "server_name panou.test" in out, out


@needs_real_curl
def test_a_port_nobody_listens_on_is_reported_as_nothing_listening() -> None:
    """Același `000` din ochii lui `%{http_code}`, cauză opusă: nginx nu rulează."""
    out, passes, fails = _run_dashboard(domain="panou.test", host="127.0.0.1",
                                        port=_free_port_nobody_listens_on())
    assert fails == 1, out
    assert "NIMIC NU ASCULTĂ" in out, out
    assert "închis conexiunea" not in out, out


@needs_real_curl
def test_an_nginx_that_never_answers_ends_the_probe_instead_of_hanging_it(tls_pair) -> None:
    """Un nginx blocat nu are voie să blocheze și smoke-testul.

    Fără limita de timp a lui curl, o gazdă cu nginx agățat ține livrarea
    deschisă la nesfârșit, fără nicio linie care să spună de ce — un blocaj tăcut
    arată ca o verificare „încă rulează", nu ca una roșie. Costă ~10 s, cât
    limita; e singura cale să vezi că limita există în comanda trimisă gazdei.
    """
    server = FakeNginx("panou.test", *tls_pair, hang=True)
    started = time.monotonic()
    try:
        out, passes, fails = _run_dashboard(domain="panou.test", host="127.0.0.1",
                                            port=server.port)
    finally:
        server.close()
    elapsed = time.monotonic() - started
    assert fails == 1, out
    assert "10 s" in out, f"timpul depășit nu e numit ca atare:\n{out}"
    assert elapsed < 60, f"sonda a durat {elapsed:.0f} s: limita lui curl nu mai există"


def test_a_dead_ssh_leaves_the_probe_empty_and_the_script_alive() -> None:
    """Un ssh căzut dă o ieșire goală și cod 0, nu oprește scriptul.

    `set -e` e activ în smoke-test: dacă funcția ar întoarce codul 255 al lui ssh,
    prima atribuire de tip `raw="$(probe_loopback …)"` ar ucide raportul la
    mijloc, fără nicio linie roșie și fără rezumat — exact tăcerea pe care
    verificarea e făcută s-o împiedice.
    """
    script = (PRELUDE + _function("probe_loopback") + "\n"
              'r() { return 255; }\n'
              'raw="$(probe_loopback 8443 panou.test)"\n'
              'printf "ALIVE raw=[%s]\n" "$raw"\n')
    out = _bash(script)
    assert "ALIVE raw=[]" in out, f"scriptul a murit sau a inventat un răspuns: {out!r}"


# --- `|| echo 000` -------------------------------------------------------------

def test_the_app_check_reports_a_single_000_when_curl_fails() -> None:
    """Mesajul pe care îl citește operatorul nu are voie să mintă nici mărunt.

    Un curl eșuat tipărește el însuși `000` și iese nenul; `|| echo 000` lipea al
    doilea. Operatorul citea „got 000000" — un cod care nu există — și nu putea ști
    că de fapt n-a răspuns nimic.
    """
    out, _passes, _fails = _run_dashboard(
        domain="panou.test", host="127.0.0.1", port=_free_port_nobody_listens_on(),
        app="refused")
    assert "app did not answer on 8787 (got 000)" in out, out
    assert "000000" not in out, out


def test_a_silent_ssh_is_read_as_000_not_as_an_empty_code() -> None:
    """Fără nicio ieșire de la ssh, mesajul nu rămâne cu o paranteză goală."""
    out, _passes, _fails = _run_dashboard(
        domain="panou.test", host="127.0.0.1", port=_free_port_nobody_listens_on(),
        app="ssh_down")
    assert "app did not answer on 8787 (got 000)" in out, out


def _slice(start: str, end: str) -> str:
    a = SMOKE_TEXT.index(start)
    b = SMOKE_TEXT.index(end, a)
    return SMOKE_TEXT[a:b]


@needs_real_curl
def test_the_external_check_names_a_failed_connection_as_not_connecting() -> None:
    """„did not connect" îl trimite pe operator la firewall-ul furnizorului sau la DNS.

    Cu `000000`, ramura aia nu se potrivea și ieșea „returned 000000", fără nicio
    pistă. Rulează lanțul livrat, cu un nume care se rezolvă local și un port gol.
    """
    port = _free_port_nobody_listens_on()
    chain = _slice('    code="$(curl -s -o /dev/null', '    if curl -s --max-time 15 -o /dev/null')
    script = (PRELUDE + f'DOMAIN=localhost; URL_SUFFIX=":{port}"; WEB_PORT={port}\n'
              + chain + EPILOGUE)
    out = _bash(script)
    assert "did not connect" in out, out
    assert "000000" not in out, out


@needs_real_curl
def test_in_dedicated_mode_an_unknown_host_that_gets_nothing_is_a_pass(tls_pair) -> None:
    """Refuzul fără răspuns e starea CORECTĂ pe portul dedicat, nu un avertisment.

    Cu `000000` comparația cu „000" nu se potrivea, deci o instalare sănătoasă cu
    blocul de refuz primea „unknown Host returned 000000; expected no response" —
    un avertisment fals pe exact întărirea pe care verificarea o promite.
    """
    server = FakeNginx("panou.test", *tls_pair)
    try:
        chain = _slice("    body=\"$(curl -sk --max-time 10 -H 'Host: not-sentinel.invalid'",
                       'sect "Configurație și secrete"')
        chain = chain[:chain.rindex("\nfi\n")]
        script = (PRELUDE + f'HOST=127.0.0.1; URL_SUFFIX=":{server.port}"; '
                  + 'NGINX_MODE=dedicated; WEB_PORT=1\n' + chain + "\n" + EPILOGUE)
        out = _bash(script)
    finally:
        server.close()
    assert "PASS unknown Host refused with no response" in out, out
    assert "WARN" not in out and "000000" not in out, out


# --- deploy/install.sh: aceeași întrebare, aceeași alegere ------------------------

INSTALL_TEXT = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")


def _install_function(name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", INSTALL_TEXT, re.S | re.M)
    assert match, f"{name}() nu a fost găsită în deploy/install.sh"
    return match.group(0)


INSTALL_PRELUDE = r"""
set -euo pipefail
ok()   { printf 'OK %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
"""


def _install_probe(domain: str, port: int) -> str:
    # SENTINEL_ANSWERED e o variabilă, nu o funcție: tăiată tot din install.sh, ca
    # garda să vadă exact lista de coduri pe care o folosește instalatorul.
    answered = re.search(r"^SENTINEL_ANSWERED=.*$", INSTALL_TEXT, re.M)
    assert answered, "SENTINEL_ANSWERED nu mai e definită în deploy/install.sh"
    script = (INSTALL_PRELUDE + answered.group(0) + "\n"
              + _install_function("https_code") + "\n"
              + _install_function("smoke_loopback_check") + "\n"
              f'DOMAIN="$T_DOMAIN"; PUBLIC_PORT={port}\n'
              'smoke_loopback_check\n')
    return _bash(script, T_DOMAIN=domain)


@needs_real_curl
@pytest.mark.parametrize("vhost, status, healthy", [
    ("panou.test", 200, True),
    ("panou.test", 307, True),    # vhostul redirecționează: un răspuns acceptat de toți trei
    ("panou.test", 404, False),   # vhostul răspunde, dar nu e dashboard-ul
    ("alt-nume.test", 200, False),
])
def test_install_and_smoke_test_agree_on_a_host_with_the_deny_block(
        tls_pair, vhost: str, status: int, healthy: bool) -> None:
    """Cele două sonde de loopback nu au voie să se despartă.

    Nu pot fi o singură funcție: `scripts/smoke-test.sh` rulează pe stația
    operatorului, peste ssh, și nu poate fi inclus (`source`); instalatorul rulează
    pe gazdă. Garda e aici: ACELAȘI server (un `default_server` care închide și un
    vhost pe nume), ambele sonde, și cerința ca verdictul să fie același. Dacă
    instalatorul revine la adresa goală, avertizează „nimic nu a răspuns" pe fiecare
    gazdă sănătoasă cu bloc de refuz — iar un avertisment care sună mereu nu mai e
    citit pe gazda unde e adevărat.

    Cazul 307 există fiindcă serverul răspunde altfel doar 200 sau închide, iar o
    divergență pe LISTA de coduri n-ar fi apărut niciodată: instalatorul avea
    `200|401|302|503`, iar `SENTINEL_ANSWERED` și smoke-testul acceptau și 301,
    303, 307, 308. Un vhost care redirecționa era bun pentru poartă și pentru
    smoke-test, și un avertisment aici.
    """
    server = FakeNginx(vhost, *tls_pair, status=status)
    try:
        installer = _install_probe("panou.test", server.port)
        smoke, _passes, smoke_fails = _run_dashboard(
            domain="panou.test", host="127.0.0.1", port=server.port)
    finally:
        server.close()
    installer_ok = "OK nginx is serving" in installer and "WARN" not in installer
    smoke_ok = smoke_fails == 0
    assert installer_ok == healthy, f"instalatorul: {installer!r}"
    assert smoke_ok == healthy, f"smoke-test:\n{smoke}"


@needs_real_curl
def test_the_installer_sends_no_name_when_there_is_no_domain(tls_pair) -> None:
    """Fără `--domain` nu există bloc de refuz; vhost-ul e `default_server`.

    Atunci orice Host merge, iar un nume inventat ar fi o ghicire — exact ce
    instalatorul refuză să facă („Guessing the name was rejected").
    """
    server = FakeNginx(None, *tls_pair)
    try:
        out = _install_probe("", server.port)
    finally:
        server.close()
    assert "OK nginx is serving" in out and "WARN" not in out, out
    assert server.hosts_seen == ["127.0.0.1"], server.hosts_seen


@needs_real_curl
def test_the_installers_warning_names_the_host_and_the_code(tls_pair) -> None:
    """Un avertisment spune ce s-a întrebat și ce s-a primit, nu doar „nimic".

    Operatorul trebuie să vadă că s-a cerut `Host: <domeniu>` și că răspunsul a fost
    `000` (nicio conexiune răspunsă), ca să nu caute o problemă de aplicație.
    """
    server = FakeNginx("alt-nume.test", *tls_pair)
    try:
        out = _install_probe("panou.test", server.port)
    finally:
        server.close()
    assert "WARN" in out and "Host: panou.test" in out and "HTTP 000" in out, out


# --- numele vhostului vine de la nginx ------------------------------------------
#
# Eșecul pe care îl previn testele de mai jos: pe n8n, `sentinel.yaml` are
# `domain: ""` și nu se va repara singur (configurația gazdei nu se regenerează la
# livrare). Cu `--host n8n` — aliasul ssh, adică felul firesc în care operatorul
# ajunge la gazdă — sonda trimitea `Host: n8n`, care nu e `server_name` nicăieri,
# cădea pe blocul de refuz și dădea „nginx ASCULTĂ dar a închis conexiunea" pe o
# gazdă sănătoasă (măsurat de verificator, RC=1). Reparația din runda 1 ținea doar
# când operatorul tasta numele întreg. Numele trebuie luat de la nginx.

DENY_TMPL = ROOT / "deploy" / "nginx" / "sentinel-default-deny.conf.tmpl"
VHOST_TMPL = ROOT / "deploy" / "nginx" / "sentinel.conf.tmpl"
SHARED_TMPL = ROOT / "deploy" / "nginx" / "sentinel-shared.conf.tmpl"


def _render(template: Path, **values: str) -> str:
    """Șablonul LIVRAT, cu marcajele `@@X@@` înlocuite — nu o copie scrisă de mână.

    Parserul trebuie să citească ce scrie instalatorul: blocuri `location`
    imbricate, `proxy_pass http://sentinel_app`, comentarii cu acolade.
    """
    text = template.read_text(encoding="utf-8")
    return re.sub(r"@@([A-Z_]+)@@", lambda m: values.get(m.group(1), "x"), text)


def _conf(*files: tuple[str, str]) -> str:
    """Ce tipărește `nginx -T`: antet, apoi fiecare fișier sub eticheta lui."""
    out = ["nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
           "nginx: configuration file /etc/nginx/nginx.conf test is successful",
           "# configuration file /etc/nginx/nginx.conf:",
           "events {}", "http { include /etc/nginx/conf.d/*.conf; }"]
    for path, body in files:
        out += [f"# configuration file {path}:", body]
    return "\n".join(out) + "\n"


def _deny(port: int = 8443) -> tuple[str, str]:
    return ("/etc/nginx/conf.d/00-default-deny.conf",
            _render(DENY_TMPL, PUBLIC_PORT=str(port), TLS_DIR="/tls"))


def _vhost(name: str, port: int = 8443) -> tuple[str, str]:
    return ("/etc/nginx/conf.d/sentinel.conf",
            _render(VHOST_TMPL, DOMAIN=name, PUBLIC_PORT=str(port), DEFAULT_SERVER="",
                    PORT="8787", TLS_DIR="/tls"))


def _shared_vhost(name: str) -> tuple[str, str]:
    return ("/etc/nginx/conf.d/sentinel-shared.conf",
            _render(SHARED_TMPL, DOMAIN=name, PORT="8787", TLS_DIR="/tls"))


def _operator(name: str, port: int = 443) -> tuple[str, str]:
    return (f"/etc/nginx/conf.d/{name}.conf",
            f"server {{\n    listen {port} ssl;\n    server_name {name};\n"
            f"    location / {{ return 200 'x'; }}\n}}\n")


def _parse(dump: str, port: int = 8443, mode: str = "dedicated") -> tuple[str, str, str]:
    script = (PRELUDE + _function("parse_nginx_vhost_name") + "\n"
              'parse_nginx_vhost_name "$T_DUMP" "$T_PORT" "$T_MODE"\n'
              'printf "STARE=[%s]\\nNUME=[%s]\\nVAZUTE=[%s]\\n" "$NGINX_STATE" "$NGINX_NAME" "$NGINX_NAMES"\n')
    out = _bash(script, T_DUMP=dump, T_PORT=str(port), T_MODE=mode)
    found = [re.search(rf"{k}=\[(.*)\]", out) for k in ("STARE", "NUME", "VAZUTE")]
    assert all(found), out
    return found[0].group(1), found[1].group(1), found[2].group(1).strip()


def test_the_name_is_taken_from_the_vhost_that_listens_on_the_port() -> None:
    """Numele exact cu care vhostul a fost scris, din șabloanele livrate.

    Fără asta sonda cade pe `--host`, iar un alias ssh dă o închidere falsă.
    """
    dump = _conf(_deny(), _vhost("panou.exemplu.ro"))
    assert _parse(dump)[:2] == ("found", "panou.exemplu.ro")


def test_the_deny_blocks_underscore_is_not_a_name() -> None:
    """`server_name _` nu e un nume: e „nimic nu se potrivește".

    Trimis ca `Host: _`, ar cădea pe blocul de refuz. Singur pe port (instalare fără
    --domain, sau vhostul dispărut) înseamnă `none`, nu un nume.
    """
    assert _parse(_conf(_deny()))[:2] == ("none", "")


@pytest.mark.parametrize("raw", [
    "",
    "sudo: a password is required",
    "bash: nginx: command not found",
    "nginx: [emerg] unexpected end of file, expecting \"}\" in /etc/nginx/nginx.conf:9",
])
def test_an_answer_that_is_not_a_listing_is_unreadable_not_none(raw: str) -> None:
    """Un sudo căzut arată, după filtrare, exact ca „niciun vhost".

    Fără antetul `# configuration file …:` nu e o listare. `none` ar însemna „am
    citit nginx și n-are nume" — o afirmație despre gazdă făcută din nimic.
    """
    assert _parse(raw)[0] == "unreadable"


def test_two_unmarked_names_are_ambiguous_and_none_is_guessed() -> None:
    """Două nume pe portul dedicat, niciunul al Sentinel: nu aleg la nimereală."""
    dump = _conf(_deny(), _operator("unu.test", 8443), _operator("doi.test", 8443))
    state, name, seen = _parse(dump)
    assert (state, name) == ("ambiguous", "")
    assert "unu.test" in seen and "doi.test" in seen


def test_the_marked_block_wins_over_other_names_on_the_same_port() -> None:
    """Blocul care face `proxy_pass http://sentinel_app` e al Sentinel, oricine mai e acolo."""
    dump = _conf(_deny(), _operator("operator.test", 8443), _vhost("panou.test"))
    assert _parse(dump)[:2] == ("found", "panou.test")


def test_in_shared_mode_only_the_marked_block_counts() -> None:
    """Pe 443 stau și site-urile operatorului; primul nume de acolo nu e al Sentinel.

    Fără marcaj, sonda ar fi trimis `Host:` al unui site străin și ar fi raportat
    „panoul servește" pe baza răspunsului altcuiva.
    """
    dump = _conf(_operator("site-strain.test", 443), _shared_vhost("panou.exemplu.ro"))
    assert _parse(dump, port=443, mode="shared")[:2] == ("found", "panou.exemplu.ro")
    only_theirs = _conf(_operator("site-strain.test", 443))
    assert _parse(only_theirs, port=443, mode="shared")[:2] == ("none", "")


def test_the_first_plain_name_of_a_block_is_taken() -> None:
    """`server_name www.x.test x.test;` — oricare selectează vhostul; primul curat."""
    conf = ("server {\n listen 8443 ssl;\n server_name *.wild.test ~^re$ www.x.test x.test;\n"
            " location / { proxy_pass http://sentinel_app; }\n}\n")
    assert _parse(_conf(("/etc/nginx/conf.d/a.conf", conf)))[:2] == ("found", "www.x.test")


def test_wildcards_and_regexes_are_not_names_one_can_send() -> None:
    conf = "server {\n listen 8443 ssl;\n server_name *.wild.test ~^re$ .dot.test;\n}\n"
    assert _parse(_conf(("/etc/nginx/conf.d/a.conf", conf)))[0] == "none"


def test_other_ports_and_port_prefixes_are_ignored() -> None:
    """`:84430` nu e `:8443`, iar un bloc de pe alt port nu e al vhostului de aici."""
    other = _conf(_vhost("altul.test", 9443), _vhost("prefix.test", 84430))
    assert _parse(other)[0] == "none"


def test_ipv6_only_listener_counts() -> None:
    conf = ("server {\n listen [::]:8443 ssl;\n server_name v6.test;\n"
            " location / { proxy_pass http://sentinel_app; }\n}\n")
    assert _parse(_conf(("/etc/nginx/conf.d/v6.conf", conf)))[:2] == ("found", "v6.test")


def test_commented_directives_are_not_read() -> None:
    """Un `# server_name vechi.test;` rămas în fișier nu e configurația activă."""
    conf = ("server {\n listen 8443 ssl;\n # server_name vechi.test;\n server_name nou.test;\n"
            " # listen 9999;\n location / { proxy_pass http://sentinel_app; }\n}\n")
    assert _parse(_conf(("/etc/nginx/conf.d/a.conf", conf)))[:2] == ("found", "nou.test")


def test_braces_inside_comments_do_not_move_the_block_boundary() -> None:
    """Un `}` dintr-un comentariu nu închide blocul.

    Șabloanele livrate au comentarii lungi; unul cu o acoladă în text ar fi tăiat
    blocul înainte de `server_name`, iar vhostul ar fi dispărut din citire.
    """
    conf = ("server {\n listen 443 ssl;\n # vechiul bloc } s-a mutat { aici\n"
            " server_name cu-comentariu.test; # } coadă\n"
            " location / { proxy_pass http://sentinel_app; }\n}\n")
    dump = _conf(("/etc/nginx/conf.d/a.conf", conf))
    assert _parse(dump, 443, "shared")[:2] == ("found", "cu-comentariu.test")


def test_a_nested_location_does_not_end_the_block_early() -> None:
    """`proxy_pass` stă într-un `location` imbricat, după `server_name`.

    Dacă acoladele s-ar număra greșit, blocul s-ar închide la primul `}` și
    marcajul n-ar fi văzut: vhostul Sentinel ar trece drept „nemarcat" — în shared,
    drept inexistent.
    """
    conf = ("server {\n listen 443 ssl;\n server_name adanc.test;\n"
            " location /a { location /b { return 200; } }\n"
            " location /c { proxy_pass http://sentinel_app; }\n}\n")
    assert _parse(_conf(("/etc/nginx/conf.d/a.conf", conf)), 443, "shared")[:2] == ("found", "adanc.test")


# --- alegerea: precedența, rezerva, dezacordul -----------------------------------

def test_an_explicit_domain_wins_over_nginx_and_yaml() -> None:
    """Operatorul a afirmat un nume: nu-l contrazic, dar spun că nginx zice altceva."""
    name, origin, note = _pick_full(flag="cerut.test", yaml="yaml.test", host="n8n",
                                    state="found", nginx_name="nginx.test")
    assert name == "cerut.test" and "--domain" in origin
    assert "dezacord" in note and "cerut.test" in note and "nginx.test" in note


def test_nginx_wins_over_yaml_and_the_disagreement_is_said() -> None:
    """Yaml și nginx cu nume diferite: gazda servește ce zice nginx."""
    name, origin, note = _pick_full(yaml="vechi.test", state="found", nginx_name="nou.test")
    assert (name, origin) == ("nou.test", "nginx")
    assert "dezacord" in note and "vechi.test" in note and "nou.test" in note


def test_yaml_with_an_empty_domain_but_nginx_with_a_name_is_a_state_of_its_own() -> None:
    """Exact n8n. Nu e o eroare (sonda trece) și nu e o tăcere (se spune).

    Configurația și ce servește gazda nu spun același lucru, iar yaml-ul nu se va
    repara singur: divergența asta devine o pană peste șase luni.
    """
    name, origin, note = _pick_full(yaml="", host="n8n", state="found", nginx_name="panou.test")
    assert (name, origin) == ("panou.test", "nginx")
    assert "dezacord" in note and "domain gol" in note and "panou.test" in note


def test_agreement_between_yaml_and_nginx_is_silent_and_ignores_case() -> None:
    """Un avertisment care sună mereu nu mai e citit: la acord, nicio notă."""
    _name, _origin, note = _pick_full(yaml="Panou.Test", state="found", nginx_name="panou.test")
    assert note == ""


def test_a_declared_name_that_nginx_does_not_serve_is_a_disagreement() -> None:
    """yaml cu `domain: x`, dar nginx n-are niciun vhost cu nume pe port."""
    name, _origin, note = _pick_full(yaml="x.test", state="none")
    assert name == "x.test"
    assert "dezacord" in note and "x.test" in note


def test_no_domain_anywhere_and_no_named_vhost_is_the_normal_no_domain_install() -> None:
    """Fără --domain vhostul e `default_server`: nicio notă, rezerva e `--host`."""
    name, origin, note = _pick_full(yaml="", host="gazda.test", state="none")
    assert name == "gazda.test" and "--host" in origin
    assert note == ""


@pytest.mark.parametrize("state", ["unreadable", "ambiguous"])
def test_when_nginx_gives_no_name_the_fallback_is_used_and_said(state: str) -> None:
    """Rezerva nu e tăcută: nota spune că nu s-a putut afla din nginx și ce s-a folosit.

    Un `--host` luat ca nume fără să se spună ar fi chiar greșeala de la care s-a
    plecat: un nume ghicit, prezentat ca unul aflat.
    """
    name, origin, note = _pick_full(yaml="", host="n8n", state=state,
                                    nginx_names="unu.test doi.test")
    assert name == "n8n"
    assert "--host" in origin and "rezervă" in origin, origin
    assert "n-a putut fi luat din nginx" in note and "n8n" in note, note


def test_yaml_is_the_fallback_before_host_when_nginx_cannot_be_read() -> None:
    name, origin, note = _pick_full(yaml="yaml.test", host="n8n", state="unreadable")
    assert name == "yaml.test" and "sentinel.yaml" in origin
    assert "n-a putut fi luat din nginx" in note


def test_an_explicit_domain_needs_no_note_when_nginx_is_unreadable() -> None:
    """Numele e afirmat de operator; n-are ce explica scriptul."""
    name, _origin, note = _pick_full(flag="cerut.test", state="unreadable")
    assert name == "cerut.test" and note == ""


# --- cap la cap: nginx-ul de joacă, cu aliasul ssh ---------------------------------

@needs_real_curl
def test_the_ssh_alias_no_longer_turns_a_healthy_dedicated_host_red(tls_pair) -> None:
    """Scenariul verificatorului pe n8n: yaml `domain: ""`, `--host n8n`.

    Înainte: `Host: n8n` -> blocul de refuz -> „nginx ASCULTĂ dar a închis
    conexiunea" -> RC=1 pe o gazdă sănătoasă. Acum numele vine din nginx.
    """
    server = FakeNginx("panou.test", *tls_pair)
    try:
        dump = _conf(_deny(server.port), _vhost("panou.test", server.port))
        out, _passes, fails = _run_dashboard(domain="", host="n8n", port=server.port,
                                             nginx_dump=dump)
    finally:
        server.close()
    assert fails == 0, out
    assert "Host: panou.test, din nginx" in out, out
    assert "domain gol" in out and "WARN" in out, "dezacordul nu a fost arătat:\n" + out
    assert "n8n" not in server.hosts_seen, server.hosts_seen


@needs_real_curl
def test_an_explicit_domain_is_what_gets_sent_even_if_nginx_says_otherwise(tls_pair) -> None:
    server = FakeNginx("panou.test", *tls_pair)
    try:
        dump = _conf(_deny(server.port), _vhost("panou.test", server.port))
        out, _passes, fails = _run_dashboard(domain="altul.test", flag="altul.test",
                                             host="n8n", port=server.port, nginx_dump=dump)
    finally:
        server.close()
    assert fails == 1 and "închis conexiunea" in out, out
    assert server.hosts_seen == ["altul.test"], server.hosts_seen
    assert "dezacord" in out, out


@needs_real_curl
def test_with_an_unreadable_nginx_the_host_fallback_is_used_and_said(tls_pair) -> None:
    """sudo refuzat: nu devine „niciun vhost", cade pe `--host` și o spune."""
    server = FakeNginx("panou.test", *tls_pair)
    try:
        good, _p, good_fails = _run_dashboard(domain="", host="panou.test", port=server.port,
                                              nginx_dump="")
        bad, _p2, bad_fails = _run_dashboard(domain="", host="n8n", port=server.port,
                                             nginx_dump="")
    finally:
        server.close()
    assert good_fails == 0 and "--host, rezervă" in good, good
    assert "n-a putut fi luat din nginx" in good and "WARN" in good, good
    assert bad_fails == 1 and "închis conexiunea" in bad and "rezervă" in bad, bad


# --- pe un nginx ADEVĂRAT, în container -------------------------------------------
#
# Serverul de joacă de mai sus dă rc=52 la o conexiune închisă; nginx-ul real dă
# rc=92 (HTTP/2) — iar parserul trebuie să citească `nginx -T` așa cum îl tipărește
# nginx, nu cum îl imaginez eu. De aceea testele de mai jos rulează TOT lanțul
# (șablonul de refuz randat, un vhost marcat, un vhost străin pe același port, curl
# rulat ÎN container) pe nginx 1.30. Sar, cu motiv, fără docker.

DOCKER = shutil.which("docker")
NGINX_IMAGE = "nginx:stable"


def _docker(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([DOCKER, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def _require_docker() -> None:
    if DOCKER is None:
        pytest.skip("fără docker în PATH — proba pe nginx real nu poate rula")
    try:
        if _docker("info", timeout=30).returncode != 0:
            pytest.skip("daemonul docker nu răspunde — proba pe nginx real nu poate rula")
        if _docker("image", "inspect", NGINX_IMAGE).returncode != 0:
            if _docker("pull", NGINX_IMAGE, timeout=240).returncode != 0:
                pytest.skip(f"imaginea {NGINX_IMAGE} nu e locală și nu s-a putut trage")
    except subprocess.TimeoutExpired:
        pytest.skip("docker nu răspunde la timp — proba pe nginx real nu poate rula")


def _start_nginx(tmp_path_factory, tls_pair, confs: dict[str, str]) -> str:
    _require_docker()
    conf_dir = tmp_path_factory.mktemp("nginx-conf")
    for name, body in confs.items():
        (conf_dir / name).write_bytes(body.encode("utf-8"))
    name = f"sentinel-probe-{os.getpid()}-{len(confs)}"
    _docker("rm", "-f", name)
    started = _docker("run", "-d", "--name", name,
                      "-v", f"{conf_dir.resolve().as_posix()}:/etc/nginx/conf.d:ro",
                      "-v", f"{tls_pair[0].parent.resolve().as_posix()}:/tls:ro", NGINX_IMAGE)
    assert started.returncode == 0, started.stderr
    for _ in range(40):
        if _docker("exec", name, "nginx", "-t").returncode == 0 \
                and _docker("exec", name, "curl", "-sk", "-o", "/dev/null", "--max-time", "2",
                            "https://127.0.0.1:8443/").returncode in (0, 52, 92):
            return name
        time.sleep(0.5)
    logs = _docker("logs", name).stdout
    _docker("rm", "-f", name)
    pytest.fail(f"nginx-ul de probă nu a pornit:\n{logs[-800:]}")


def _real_confs(*, vhost: bool = True, operator: bool = True) -> dict[str, str]:
    confs = {"00-default-deny.conf":
             _render(DENY_TMPL, PUBLIC_PORT="8443", TLS_DIR="/tls")
             .replace("/tls/certs/sentinel-selfsigned.crt", "/tls/c.pem")
             .replace("/tls/private/sentinel-selfsigned.key", "/tls/k.pem")
             .replace("/var/log/nginx/sentinel-probe.log", "/dev/stdout")}
    if vhost:
        confs["10-vhost.conf"] = (
            "upstream sentinel_app { server 127.0.0.1:1; }\n"
            "server {\n    listen 8443 ssl http2;\n    listen [::]:8443 ssl http2;\n"
            "    server_name panou.test;\n    ssl_certificate /tls/c.pem;\n"
            "    ssl_certificate_key /tls/k.pem;\n"
            "    location = /healthz { return 200 'ok'; }\n"
            "    location / { proxy_pass http://sentinel_app; }\n}\n")
    if operator:
        confs["20-operator.conf"] = (
            "server {\n    listen 8443 ssl http2;\n    server_name operator.test;\n"
            "    ssl_certificate /tls/c.pem;\n    ssl_certificate_key /tls/k.pem;\n"
            "    location / { return 200 'op'; }\n}\n")
    return confs


@pytest.fixture(scope="module")
def real_nginx(tmp_path_factory, tls_pair):
    name = _start_nginx(tmp_path_factory, tls_pair, _real_confs())
    yield name
    _docker("rm", "-f", name)


@pytest.fixture(scope="module")
def real_nginx_deny_only(tmp_path_factory, tls_pair):
    name = _start_nginx(tmp_path_factory, tls_pair, _real_confs(vhost=False, operator=False))
    yield name
    _docker("rm", "-f", name)


def _real_dump(container: str) -> str:
    done = _docker("exec", container, "nginx", "-T")
    return done.stdout + done.stderr


def test_real_nginx_dump_is_read_in_both_modes(real_nginx) -> None:
    """Parserul pe ieșirea REALĂ a lui `nginx -T`, nu pe una imaginată.

    Pe același port stau un vhost marcat (`panou.test`) și unul străin
    (`operator.test`): în ambele moduri vhostul Sentinel e cel marcat.
    """
    dump = _real_dump(real_nginx)
    assert "# configuration file " in dump, dump[:300]
    assert _parse(dump, 8443, "dedicated")[:2] == ("found", "panou.test")
    assert _parse(dump, 8443, "shared")[:2] == ("found", "panou.test")


def test_real_nginx_with_only_the_deny_block_has_no_name(real_nginx_deny_only) -> None:
    """Instalare fără --domain sau vhost dispărut: nginx citit, niciun nume."""
    state, name, _seen = _parse(_real_dump(real_nginx_deny_only))
    assert (state, name) == ("none", "")


def test_real_nginx_ssh_alias_with_empty_yaml_domain_is_green_and_flags_the_disagreement(
        real_nginx) -> None:
    """Scenariul n8n pe un nginx adevărat: yaml `domain: ""`, `--host n8n`.

    Verdictul pe gazda sănătoasă e verde, iar dezacordul dintre yaml și nginx se
    vede ca avertisment.
    """
    out, _passes, fails = _run_dashboard(domain="", host="n8n", port=8443,
                                         container=real_nginx)
    assert fails == 0, out
    assert "PASS nginx serving on :8443 (HTTP 200; Host: panou.test, din nginx)" in out, out
    assert "WARN dezacord" in out and "domain gol" in out, out


def test_real_nginx_explicit_domain_takes_precedence(real_nginx) -> None:
    """`--domain operator.test` (un vhost real, care răspunde) bate numele din nginx."""
    out, _passes, fails = _run_dashboard(domain="operator.test", flag="operator.test",
                                         host="n8n", port=8443, container=real_nginx)
    assert fails == 0, out
    assert "Host: operator.test, din --domain dat explicit" in out, out
    assert "WARN dezacord" in out and "panou.test" in out, out


def test_real_nginx_beats_a_stale_yaml_domain(real_nginx) -> None:
    out, _passes, fails = _run_dashboard(domain="vechi.test", host="n8n", port=8443,
                                         container=real_nginx)
    assert fails == 0, out
    assert "Host: panou.test, din nginx" in out, out
    assert "WARN dezacord" in out and "vechi.test" in out, out


def test_real_nginx_unreadable_falls_back_to_host_and_says_so(real_nginx) -> None:
    """sudo refuzat pe gazdă: rezerva pe `--host`, spusă — și un alias dă roșu, onest."""
    good, _p, good_fails = _run_dashboard(domain="", host="panou.test", port=8443,
                                          container=real_nginx, nginx_unreadable=True)
    assert good_fails == 0 and "--host, rezervă" in good, good
    assert "n-a putut fi luat din nginx" in good, good
    bad, _p2, bad_fails = _run_dashboard(domain="", host="n8n", port=8443,
                                         container=real_nginx, nginx_unreadable=True)
    assert bad_fails == 1 and "rc=92" in bad and "rezervă" in bad, bad


@pytest.mark.parametrize("path", ["scripts/smoke-test.sh", "deploy/install.sh"])
def test_no_curl_in_the_shipped_scripts_is_followed_by_or_echo_000(path: str) -> None:
    """Un curl eșuat tipărește el însuși `000`; `|| echo 000` îl dublează în „000000".

    Gardă TEXTUALĂ, spusă ca atare: sonda „am devenit default vhost?" din
    `install.sh` stă în mijlocul unei funcții de o sută de linii care cere un nginx
    real ca s-o rulezi, deci efectul ei n-are un test propriu; efectul tiparului e
    însă măsurat (`000000`, pe nginx 1.30 și pe serverul de joacă) și acoperit pentru
    smoke-test de testele de mai sus. Comentariile care NUMESC tiparul sunt scutite.
    """
    offenders = [
        f"{path}:{number}: {line.strip()}"
        for number, line in enumerate((ROOT / path).read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"\|\|\s*echo\s+000", line) and not line.lstrip().startswith("#")
    ]
    assert not offenders, "\n".join(offenders)


# --- scriptul ÎNTREG, cu un ssh de joacă --------------------------------------------
#
# Funcțiile și secțiunea Dashboard sunt probate mai sus, tăiate din script. Ce nu
# vede nicio tăietură: legătura dintre argumentele din linia de comandă și acele
# funcții — `DOMAIN_FLAG` se fixează PRIMA dată după citirea argumentelor, înainte ca
# `DOMAIN` să fie completat din sentinel.yaml. Scoasă, un `--domain` explicit ar
# fi tratat ca un nume oarecare din yaml și ar pierde în fața celui din nginx.
# Singura probă e scriptul real, pornit de la `--host`, cu `ssh`, `sudo` și `nginx`
# înlocuite prin programe care rulează comenzile LOCAL.

def _fake_host_tools(directory: Path, dump: Path) -> None:
    (directory / "ssh").write_bytes(
        b'#!/usr/bin/env bash\nexec bash -c "${@: -1}"\n')
    (directory / "sudo").write_bytes(b'#!/usr/bin/env bash\nexec "$@"\n')
    (directory / "nginx").write_bytes(
        f'#!/usr/bin/env bash\ncat "{dump.as_posix()}"\n'.encode("utf-8"))


def _run_whole_script(tmp_path: Path, *, port: int, dump: str, extra: list[str]) -> str:
    tools = tmp_path / "bin"
    tools.mkdir()
    dump_file = tmp_path / "nginx-T.txt"
    dump_file.write_bytes(dump.encode("utf-8"))
    _fake_host_tools(tools, dump_file)
    path = os.pathsep.join([str(tools), os.environ["PATH"]])
    proc = subprocess.run(
        [BASH, str(SMOKE), "--host", "n8n", "--user", "operator", "--web-port", str(port), *extra],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240,
        env={**os.environ, "PATH": path})
    return proc.stdout


@needs_real_curl
def test_the_whole_script_keeps_an_explicit_domain_ahead_of_nginx(tls_pair, tmp_path) -> None:
    """`--domain` dat de operator rămâne `--domain`, nu devine „numele din yaml".

    Dacă `DOMAIN_FLAG` nu se mai fixează înainte de completarea din yaml, nginx
    ar câștiga în tăcere și flag-ul ar dispărea din sondă.
    """
    server = FakeNginx("panou.test", *tls_pair)
    try:
        dump = _conf(_deny(server.port), _vhost("panou.test", server.port))
        out = _run_whole_script(tmp_path, port=server.port, dump=dump,
                                extra=["--domain", "altul.test"])
    finally:
        server.close()
    assert "Host: altul.test, din --domain dat explicit" in out, out
    assert "altul.test" in server.hosts_seen, server.hosts_seen
    # Același rulaj arată că nginx a fost citit (altfel n-ar exista dezacordul):
    # singurul loc unde se vede ordinea reală, din script, a citirii înaintea sondei.
    assert "dezacord" in out and "panou.test" in out, out
