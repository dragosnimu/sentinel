"""Redactarea secretelor din liniile de comandă înregistrate.

Eșecul pe care îl previne: istoricul de comenzi are retenție NELIMITATĂ pe
gazdă și pleacă spre agregator, adică pe o găzduire partajată unde personalul
furnizorului are acces la bază. Un secret scris în `argv` — de altcineva, într-o
comandă obișnuită — ar ajunge acolo o dată și ar rămâne pentru totdeauna, în
tabelă, în backup și în replică.

Fiecare test de mai jos pornește de la o comandă pe care cineva chiar o scrie.

A doua jumătate, la fel de importantă: o redactare care taie lucruri inofensive
e una pe care operatorul o oprește, iar atunci nu mai redactează nimic. Deci se
cere și ce trebuie să RĂMÂNĂ întreg — căi, porturi, adrese, nume de fișiere.
"""

from __future__ import annotations

import pytest

from sentinel.redact import (
    ENTROPY_MIN_LEN, MASK, MAX_COMMAND_LEN, redact, redact_argv,
)


# ---------------------------------------------------------------------------
# Ce trebuie tăiat
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("comanda,ramane", [
    # `mysql -pparola` — forma lipită, cea mai frecventă și cea pe care un
    # tipar naiv o ratează, fiindcă nu există separator.
    ("mysql -h db -u root -pParolaMea123 sentinel", "mysql -h db -u root"),
    ("mysqldump -pS3cret --all-databases", "mysqldump"),
    # Atribuire de mediu în fața comenzii.
    ("PGPASSWORD=parola psql -h 127.0.0.1", "psql -h 127.0.0.1"),
    ("API_TOKEN=abc123 ./deploy.sh", "./deploy.sh"),
    # Opțiune cu `=`.
    ("curl --header --password=parola https://x", "curl"),
    ("wget --password=parola https://x", "wget"),
    # Opțiune cu valoare separată.
    ("app --token abcdef --port 8080", "--port 8080"),
    ("ssh-keygen -N parolaCheii -f /tmp/k", "ssh-keygen"),
    # Antet HTTP.
    ('curl -H "Authorization: Bearer eyJhbGciOi" https://x', "curl"),
    ("curl -H 'X-Api-Key: cheiaMea' https://x", "curl"),
    # Acreditări în URL.
    ("git clone https://user:parola@github.com/x/y.git", "git clone"),
])
def test_a_secret_written_in_argv_never_reaches_the_database(
        comanda: str, ramane: str) -> None:
    """Tiparele, fiecare de la o comandă reală.

    Se cere DOUĂ lucruri: că masca a apărut, și că secretul chiar a dispărut.
    Numai prima ar trece și pentru o redactare care adaugă masca lângă valoare.
    """
    iesit = redact(comanda)
    assert MASK in iesit, f"nimic nu s-a redactat din {comanda!r}"
    assert ramane in iesit, (
        f"redactarea a înghițit și partea utilă: {iesit!r} nu mai conține "
        f"{ramane!r}, iar un istoric din care nu se mai înțelege ce s-a rulat "
        f"nu răspunde la nicio întrebare")
    for secret in ("ParolaMea123", "S3cret", "parola", "abc123", "abcdef",
                   "parolaCheii", "eyJhbGciOi", "cheiaMea"):
        if secret in comanda:
            assert secret not in iesit, (
                f"secretul {secret!r} a rămas în {iesit!r} — masca a fost pusă "
                f"lângă valoare, nu în locul ei")


def test_a_long_mixed_token_is_cut_even_without_a_name_in_front() -> None:
    """Plasa de rezervă: un token care nu e precedat de niciun cuvânt cunoscut.

    `curl https://api/x <token>` nu are `--token` nicăieri. Fără plasa asta,
    fiecare secret pus ca argument pozițional ar trece întreg.
    """
    token = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW"
    assert len(token) >= ENTROPY_MIN_LEN
    iesit = redact(f"./tool {token} --verbose")
    assert token not in iesit
    assert "--verbose" in iesit


# ---------------------------------------------------------------------------
# Ce trebuie să rămână
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("comanda", [
    # Calea absolută lungă e chiar ce trebuie citit dintr-un istoric.
    "cp /var/lib/sentinel/backups/predeploy-20260824-102505/sentinel.yaml /tmp",
    # `-p` cu spațiu e un port, un pod, un proiect — nu o parolă.
    "docker run -p 8080:80 nginx",
    "psql -h 127.0.0.1 -p 5432 -U sentinel",
    # Suma de control e lungă, dar e chiar dovada pe care o cauți.
    "sha256sum /opt/sentinel/lib/sentinel/report/shipper.py",
    # Un șir lung dintr-un singur fel de caractere nu e un token.
    "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    # `-p` LIPIT înseamnă parolă doar la `mysql` și rudele lui. Ca regulă
    # generală mânca `find -print` și `find -perm` — măsurat pe datele reale pe
    # 25 august 2026, iar `find /etc -name x -p«redactat»` nu mai spune ce căuta
    # cineva.
    "find /etc/debuginfod -name *.certpath -print",
    "find / -perm -4000 -type f",
    "docker ps -q",
    # `-p` cu SPAȚIU la `mysql` e forma „cere-mi parola la prompt": ce urmează e
    # numele bazei, nu parola. Redactat, istoricul n-ar mai spune pe ce bază s-a
    # lucrat — iar parola oricum n-a fost niciodată în linia de comandă.
    "mysql -h 127.0.0.1 -u root -p sentinel",
    # Interogările din operare, întregi: fără ele nu se poate reconstitui ce a
    # citit cineva din bază.
    "psql -d sentinel -Atc SELECT count(*) FROM raw_events",
    "/usr/bin/sed -r -e s|@@DOMAIN@@|exemplu|g /tmp/vhost",
    # Comenzile obișnuite de operare, întregi.
    "systemctl restart sentinel-shipper",
    "journalctl -u sentinel-detect --since -10min",
    "nft list ruleset",
])
def test_an_ordinary_command_is_left_alone(comanda: str) -> None:
    """O redactare care taie lucruri inofensive e una pe care cineva o oprește.

    Iar un istoric în care jumătate din linii sunt «redactat» nu se mai
    citește — ceea ce e același lucru cu a nu avea istoric.
    """
    assert redact(comanda) == comanda, (
        f"s-a redactat dintr-o comandă obișnuită: {redact(comanda)!r}")


@pytest.mark.parametrize("cale", [
    # CU punct — cazul pe care îl acoperea prima versiune a testului, și care
    # trecea din întâmplare: punctul rupea potrivirea.
    "/var/backups/sentinel/predeploy-20260824-102505/etc-sentinel.tar.gz",
    # FĂRĂ punct — cazul care a scăpat, și care s-a văzut abia în datele reale.
    # Măsurat pe 25 august 2026: `mkdir -p «redactat»`, `cp «redactat» …`.
    "/tmp/sentinel-deploy-20260825-061110",
    "/opt/sentinel/lib/sentinel/collectors",
    "/var/backups/sentinel/predeploy-20260825-061120",
])
def test_a_path_is_never_redacted(cale: str) -> None:
    """Defectul măsurat pe datele reale, pe 25 august 2026.

    68 059 de comenzi din 534 000 aveau ceva redactat, iar o parte erau CĂI:
    `mkdir -p «redactat»`, `cp «redactat» /opt/sentinel/VERSION`. Calea
    `/tmp/sentinel-deploy-20260825-061110` are 36 de caractere, toate din clasa
    de token, și amestecă litere cu cifre — deci se potrivea întreagă.

    Iar „ce fișier a atins" e chiar una dintre întrebările la care istoricul
    trebuie să răspundă. O redactare care mănâncă răspunsul e mai rea decât una
    absentă: prima arată ca acoperire.
    """
    assert len(cale) >= ENTROPY_MIN_LEN, "calea de probă e prea scurtă ca să prindă"
    assert redact(f"tar xzf {cale}") == f"tar xzf {cale}", (
        f"calea a fost redactată: {redact(f'tar xzf {cale}')!r}")


def test_a_path_that_merely_looks_long_survives() -> None:
    """Garda pentru plasa de token: căile au `/` și `.`, tokenii nu.

    Fără excluderea asta, fiecare cale absolută mai lungă de 32 de caractere ar
    dispărea din istoric — adică exact răspunsul la «ce fișier a atins».
    """
    cale = "/var/backups/sentinel/predeploy-20260824-102505/etc-sentinel.tar.gz"
    assert len(cale) >= ENTROPY_MIN_LEN
    assert redact(f"tar xzf {cale}") == f"tar xzf {cale}"


# ---------------------------------------------------------------------------
# Forma
# ---------------------------------------------------------------------------
def test_the_line_is_truncated_after_redaction_not_before() -> None:
    """Ordinea celor două operații e ea însăși o proprietate de securitate.

    Trunchiată întâi, o linie lungă și-ar pierde coada — iar un secret aflat
    dincolo de plafon ar fi «redactat» pe unele linii și păstrat pe altele, după
    cât de lungă a fost comanda. O redactare care depinde de lungimea intrării
    nu e o redactare.
    """
    umplutura = "x" * MAX_COMMAND_LEN
    iesit = redact(f"./tool {umplutura} --password=SecretulMeu")
    assert "SecretulMeu" not in iesit, (
        "secretul de după plafon a scăpat: linia a fost tăiată înainte de a fi "
        "redactată")
    assert len(iesit) <= MAX_COMMAND_LEN + 40
    assert "car.)" in iesit, "trunchierea nu spune că a tăiat"


def test_a_short_command_is_not_truncated() -> None:
    """Garda celuilalt sens: fără ea, testul de mai sus ar trece și pentru o
    funcție care taie ORICE linie."""
    assert redact("ls -la") == "ls -la"


def test_the_mask_cannot_be_mistaken_for_a_value() -> None:
    """Un `***` ar putea fi chiar parola cuiva, iar atunci cine citește
    istoricul nu poate ști dacă valoarea a fost tăiată sau chiar aia era."""
    assert not MASK.isalnum()
    assert len(MASK) > 3


def test_argv_is_redacted_across_argument_boundaries() -> None:
    """`--password` și valoarea lui sunt DOUĂ elemente în `EXECVE`.

    Un tipar aplicat fiecărui argument separat n-ar vedea niciodată perechea, iar
    valoarea ar trece întreagă — cu testele de mai sus toate verzi, fiindcă ele
    lucrează pe linia deja reasamblată.
    """
    argv = ["mysql", "--password", "ParolaMea", "sentinel"]
    iesit = redact_argv(argv)
    assert "ParolaMea" not in " ".join(iesit)
    assert iesit[0] == "mysql"
    assert "sentinel" in iesit


def test_an_empty_command_stays_empty() -> None:
    """`EXECVE` fără argumente există; o excepție aici ar opri colectorul."""
    assert redact("") == ""
    assert redact_argv([]) == []
