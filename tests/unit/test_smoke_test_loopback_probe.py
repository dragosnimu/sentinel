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
    proc = subprocess.run([BASH, "-c", script], input=stdin, capture_output=True,
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

def _pick(domain: str, host: str) -> tuple[str, str]:
    script = (PRELUDE + _function("pick_probe_name") + "\n"
              'DOMAIN="$T_DOMAIN"; HOST="$T_HOST"\n'
              'pick_probe_name\n'
              'printf "NUME=[%s]\\nDIN=[%s]\\n" "$PROBE_NAME" "$PROBE_NAME_FROM"\n')
    out = _bash(script, T_DOMAIN=domain, T_HOST=host)
    name = re.search(r"NUME=\[(.*)\]", out)
    origin = re.search(r"DIN=\[(.*)\]", out)
    assert name and origin, out
    return name.group(1), origin.group(1)


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
              'DOMAIN="$T_DOMAIN"; HOST="$T_HOST"\n'
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

    def __init__(self, vhost: str | None, cert: Path, key: Path, hang: bool = False) -> None:
        self.vhost = vhost
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
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
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


def _run_dashboard(*, domain: str, host: str, port: int,
                   app: str = "ok") -> tuple[str, int, int]:
    """Secțiunea Dashboard din scriptul livrat, cu `r` care rulează LOCAL.

    `r` înlocuiește ssh: comanda de pe gazdă e dată unui shell, ca acolo. Verificarea
    de pe 8787 e răspunsă de un cod fix (`app`): „ok" = 200, „refused" = curl a
    tipărit 000 și a ieșit cu 7, „ssh_down" = nicio ieșire și cod 255.
    """
    functions = "\n".join(_function(n) for n in
                          ("pick_probe_name", "probe_loopback", "report_loopback_probe"))
    script = (PRELUDE + functions + "\n"
              f'DOMAIN="$T_DOMAIN"; HOST="$T_HOST"; WEB_PORT={port}\n'
              'r() { case "$*" in *127.0.0.1:8787*) ' + _APP_STUBS[app]
              + ' ;; *) bash -c "$*" ;; esac; }\n'
              + _dashboard_block() + "\n" + EPILOGUE)
    out = _bash(script, T_DOMAIN=domain, T_HOST=host)
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
    script = (INSTALL_PRELUDE + _install_function("https_code") + "\n"
              + _install_function("smoke_loopback_check") + "\n"
              f'DOMAIN="$T_DOMAIN"; PUBLIC_PORT={port}\n'
              'smoke_loopback_check\n')
    return _bash(script, T_DOMAIN=domain)


@needs_real_curl
@pytest.mark.parametrize("vhost, healthy", [("panou.test", True), ("alt-nume.test", False)])
def test_install_and_smoke_test_agree_on_a_host_with_the_deny_block(
        tls_pair, vhost: str, healthy: bool) -> None:
    """Cele două sonde de loopback nu au voie să se despartă.

    Nu pot fi o singură funcție: `scripts/smoke-test.sh` rulează pe stația
    operatorului, peste ssh, și nu poate fi inclus (`source`); instalatorul rulează
    pe gazdă. Garda e aici: ACELAȘI server (un `default_server` care închide și un
    vhost pe nume), ambele sonde, și cerința ca verdictul să fie același. Dacă
    instalatorul revine la adresa goală, avertizează „nimic nu a răspuns" pe fiecare
    gazdă sănătoasă cu bloc de refuz — iar un avertisment care sună mereu nu mai e
    citit pe gazda unde e adevărat.
    """
    server = FakeNginx(vhost, *tls_pair)
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
