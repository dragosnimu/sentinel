"""Redactarea secretelor dintr-o linie de comandă, înainte să atingă baza.

## De ce aici, și nu la citire

Istoricul de comenzi înregistrează `argv`-ul fiecărui proces pornit într-o
sesiune cu login. `argv` e vizibil în `/proc` pentru orice utilizator de pe
gazdă, iar tocmai de-asta `scripts/deploy.sh` trimite secretele pe **stdin,
niciodată în argv**. Dar restul lumii nu respectă regula aia: `mysql -pparola`,
`curl -H "Authorization: Bearer …"`, `ssh-keygen -N frază` — toate scriu
secretul în linia de comandă.

Fără redactare, baza Sentinel ar deveni locul în care se adună secretele scrise
greșit de altcineva, cu retenție nelimitată, replicat pe o găzduire partajată.
Redactat la CITIRE, secretul ar fi tot acolo: în tabelă, în backup, în arhiva
externă. Deci se taie înainte de scriere, iar ce se pierde se pierde definitiv.

## Ce NU face

Nu e o garanție. E o listă de tipare, iar un secret care nu seamănă cu niciunul
trece întreg — `curl https://api/x?k=SECRET`, un token pus într-un argument
pozițional, o parolă care arată ca un cuvânt obișnuit. Limita e scrisă aici și
în `docs/SECURITATE.md` fiindcă alternativa e ca cineva să creadă că e o
garanție.

A doua limită: redactarea vede argumentele DESPĂRȚITE, cum le dă `EXECVE`. Un
shell care primește `-c "mysql -pparola"` are tot secretul într-un singur
argument; tiparele de mai jos caută și în interiorul unui argument, tocmai
pentru cazul ăsta.
"""

from __future__ import annotations

import re

#: Ce se pune în locul valorii tăiate. Scurt, și imposibil de confundat cu o
#: valoare reală — un `***` care ar putea fi chiar parola cuiva nu ajută.
MASK = "«redactat»"

#: Lungimea de la care un șir fără spații e tratat ca secret prin el însuși.
#:
#: 32 fiindcă acolo încep cheile: un `sha256` are 64, un token JWT trece de 100,
#: un UUID are 36. Sub atât sunt nume de fișiere și argumente obișnuite, iar un
#: prag mai jos ar redacta jumătate din comenzi și ar face istoricul inutil.
ENTROPY_MIN_LEN = 32

#: Cât se păstrează dintr-o linie de comandă. Un `argv` poate fi arbitrar de
#: lung, iar restul e controlat de cine rulează comanda.
MAX_COMMAND_LEN = 4000

# ---------------------------------------------------------------------------
# Tiparele
# ---------------------------------------------------------------------------
# Fiecare are un test în `tests/unit/test_redact.py` care numește comanda reală
# de la care a pornit. Ordinea contează: cele cu `=` întâi, ca `--password=x` să
# nu fie prins de regula de opțiune-cu-valoare-separată și tăiat pe jumătate.

#: Numele de opțiuni ale căror valori sunt secrete, oriunde ar apărea.
_SECRET_WORDS = (
    "password", "passwd", "pass", "pwd", "secret", "token", "apikey",
    "api-key", "api_key", "auth", "authorization", "credential", "credentials",
    "private-key", "private_key", "passphrase", "access-key", "access_key",
    "secret-key", "secret_key", "session-key", "bearer",
)
_WORDS = "|".join(re.escape(w) for w in _SECRET_WORDS)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # `--password=parola`, `token=abc`, `AUTH_TOKEN=abc` — inclusiv atribuirile
    # de mediu puse în fața comenzii, care sunt cel mai frecvent caz real.
    (re.compile(rf"(?i)\b((?:[A-Za-z0-9_-]*(?:{_WORDS}))[A-Za-z0-9_-]*\s*=\s*)\S+"),
     rf"\1{MASK}"),
    # `--password parola`, `-p parola`, `--token parola` — valoare separată.
    (re.compile(rf"(?i)(--?(?:{_WORDS})[A-Za-z0-9_-]*\s+)(?!-)\S+"),
     rf"\1{MASK}"),
    # `Authorization: Bearer abc`, `X-Api-Key: abc` — antete HTTP.
    (re.compile(rf"(?i)\b((?:{_WORDS}|x-[a-z-]*key)\s*:\s*)(?:Bearer\s+)?\S+"),
     rf"\1{MASK}"),
    # `https://user:parola@gazda` — acreditări în URL.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)"),
     rf"\1{MASK}\2"),
)

#: Opțiuni de o literă care sunt secrete DOAR pentru anumite programe.
#:
#: `-N` e fraza de acces la `ssh-keygen` și cu totul altceva la `nl`, `nmap` sau
#: `sort`. O listă generală de litere ar redacta jumătate din istoric; una legată
#: de program taie exact ce trebuie. Se caută în primul cuvânt al liniei, fiindcă
#: acolo stă binarul în forma pe care o dă `EXECVE`.
#: `mysql -pparola` — valoarea lipită de opțiune, fără separator.
#:
#: Legată de PROGRAM, nu globală, și asta e o reparație. Ca regulă generală
#: mânca `find -print`, `find -perm`, `-pid`, `-pattern` — măsurat pe datele
#: reale pe 25 august 2026, 530 din 4416 de comenzi aveau ceva redactat, iar o
#: parte erau chiar astea. `find /etc -name x -p«redactat»` nu mai spune ce
#: căuta cineva.
_GLUED_PASSWORD = re.compile(r"(?<![\w-])(-p)(?=\S)\S+")

_BY_COMMAND: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("mysql", _GLUED_PASSWORD, rf"\1{MASK}"),
    ("mysqldump", _GLUED_PASSWORD, rf"\1{MASK}"),
    ("mysqladmin", _GLUED_PASSWORD, rf"\1{MASK}"),
    ("mariadb", _GLUED_PASSWORD, rf"\1{MASK}"),
    ("mariadb-dump", _GLUED_PASSWORD, rf"\1{MASK}"),
    ("ssh-keygen", re.compile(r"(\s-[NP]\s+)(?!-)\S+"), rf"\1{MASK}"),
    ("openssl", re.compile(r"(\s-pass(?:in|out)\s+)(?!-)\S+"), rf"\1{MASK}"),
    ("htpasswd", re.compile(r"(\s-b\s+\S+\s+)(?!-)\S+"), rf"\1{MASK}"),
)

#: Un șir lung fără spații, format numai din caractere de token.
#:
#: Se aplică DUPĂ tiparele de mai sus, ca ultimă plasă.
#:
#: ## `/` NU e în clasa de caractere, și asta e o reparație
#:
#: Prima versiune îl includea, fiindcă base64 îl folosește. Rezultatul, măsurat
#: pe datele reale din 25 august 2026: **68 059 de comenzi din 534 000** aveau
#: ceva redactat, iar o parte erau căi:
#:
#:     mkdir -p «redactat»
#:     cp «redactat» /opt/sentinel/VERSION
#:     awk «redactat»
#:
#: `/tmp/sentinel-deploy-20260825-061110` are 36 de caractere, toate din clasă,
#: și amestecă litere cu cifre — deci se potrivea întreg. Iar întrebarea „ce
#: fișier a atins" e chiar una dintre cele la care istoricul trebuie să
#: răspundă. O redactare care mănâncă răspunsul e mai rea decât una absentă.
#:
#: Testul care ar fi trebuit s-o prindă trecea: calea din el avea un punct
#: (`etc-sentinel.tar.gz`), iar punctul rupea potrivirea din întâmplare. De-aia
#: garda de mai jos are acum și o cale FĂRĂ punct.
#:
#: Costul, spus pe față: un token base64 care conține `/` scapă întreg. E un rest
#: cunoscut, adăugat la lista din capul modulului — iar asimetria e limpede, o
#: cale pierdută e o pierdere sigură, un token cu slash e o pierdere posibilă.
_LONG_TOKEN = re.compile(rf"(?<![\w/.=:-])[A-Za-z0-9+_-]{{{ENTROPY_MIN_LEN},}}={{0,2}}"
                         r"(?![\w/.-])")


def _looks_like_token(value: str) -> bool:
    """Un șir lung e secret doar dacă AMESTECĂ tipurile de caractere.

    `aaaaaaaa…` de 40 de caractere nu e un token, e un nume prostesc sau un
    argument repetitiv. Un token real are și litere, și cifre. Fără condiția
    asta, `--comment aaaaaaaa…` ar fi redactat, iar redactarea care taie lucruri
    inofensive e cea pe care cineva o oprește.
    """
    return (any(c.isdigit() for c in value)
            and any(c.isalpha() for c in value))


def redact(command: str) -> str:
    """Linia de comandă, cu valorile care arată a secret înlocuite.

    Pură și fără stare: aceeași intrare dă mereu aceeași ieșire, ca rezultatul
    să se poată proba fără gazdă și fără bază.
    """
    if not command:
        return command

    out = command
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)

    # Binarul, ca să se poată aplica opțiunile legate de program. `EXECVE` dă
    # calea cu care a fost pornit, deci `/usr/bin/ssh-keygen` și `ssh-keygen`
    # sunt același lucru și trebuie tratate la fel.
    binar = out.split(" ", 1)[0].rsplit("/", 1)[-1]
    for nume, pattern, replacement in _BY_COMMAND:
        if binar == nume:
            out = pattern.sub(replacement, out)

    out = _LONG_TOKEN.sub(
        lambda m: MASK if _looks_like_token(m.group(0)) else m.group(0), out)

    # Trunchierea vine ULTIMA. Făcută întâi, un secret de la sfârșitul unei linii
    # lungi ar fi tăiat din întâmplare pe unele linii și păstrat pe altele — iar
    # o redactare care depinde de lungimea intrării nu e o redactare.
    if len(out) > MAX_COMMAND_LEN:
        out = out[:MAX_COMMAND_LEN] + f"… (+{len(out) - MAX_COMMAND_LEN} car.)"
    return out


def redact_argv(argv: list[str]) -> list[str]:
    """Aceeași redactare, peste argumentele despărțite.

    Se lucrează pe linia reasamblată, nu argument cu argument: `--password` și
    valoarea lui sunt DOUĂ elemente în `EXECVE`, iar un tipar aplicat separat
    fiecăruia n-ar vedea niciodată perechea. După redactare se despart la loc pe
    spații, ceea ce înseamnă că un argument care conținea spații se desface —
    acceptabil, fiindcă forma citită de om e oricum linia întreagă.
    """
    if not argv:
        return argv
    return redact(" ".join(argv)).split(" ")
