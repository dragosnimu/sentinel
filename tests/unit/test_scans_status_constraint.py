"""`scans.status` nu mai poate purta o valoare pe care nimeni n-o citește onest.

Eșecul, citit din cod pe 26 august 2026 — nu văzut pe gazdă, unde sunt 0 rânduri
`skipped`: `check_last_scan` tratează orice status care nu e `running`, `failed`
sau `timeout` ca pe o rulare încheiată, deci un rând cu `status = 'skipped'` ar fi
ieșit «ok | ultima rulare încheiată acum 1h, 0 constatări». „0 constatări" despre
o scanare care nu a rulat e un panou verde pus peste o măsurătoare care nu s-a
făcut niciodată — chiar forma de minciună pe care verificarea aia există ca s-o
prevină. E o cale deschisă, nu o pană trăită; se spune așa fiindcă aici
docstring-ul e evidența.

Nimic din cod nu scria valoarea. Era o capcană armată pentru primul care avea s-o
scrie, iar decizia operatorului a fost s-o facă NEREPREZENTABILĂ, nu s-o trateze:
gestionată, corectitudinea ar depinde de fiecare cititor viitor; scoasă din
constrângere, baza refuză.

Testele de aici păzesc trei lucruri: că starea chiar a ieșit din schemă, că
migrația refuză în loc să rescrie istoric, și că niciun apel din cod nu scrie un
status pe care baza l-ar respinge — adică nu se repară o parte și se sparge alta.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "sentinel" / "db" / "migrations"

_ADD_CONSTRAINT = re.compile(
    r"ADD\s+CONSTRAINT\s+scans_status_check\s+CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)\s*\)",
    re.I | re.S)
_LITERAL = re.compile(r"'([a-z_]+)'")


#: Ce ARE VOIE să conțină 0029, nu ce n-are voie. A treia oară că aceeași cauză
#: e prinsă prea îngust, deci nu se mai adaugă o alternanță — se schimbă
#: întrebarea. Vezi docstring-ul testului pentru de ce.
#:
#: Lista e a ACESTEI migrații, nu un cadru. Alta care are nevoie de alte
#: instrucțiuni își declară propria listă, lângă propriile ei motive.
#:
#: `ALTER TABLE` merge un pas mai departe de primul cuvânt fiindcă e singurul
#: verb care e și unealta legitimă de aici, și una dintre cele care remodelează
#: tabela: constrângeri da, coloane și tipuri nu.
_INSTRUCTIUNI_PERMISE: tuple[re.Pattern[str], ...] = (
    re.compile(r"DO\s*\$", re.I),
    re.compile(r"ALTER\s+TABLE\s+scans\s+(?:ADD|DROP)\s+CONSTRAINT\b", re.I),
    re.compile(r"COMMENT\s+ON\s+COLUMN\s+scans\.\w+\b", re.I),
)

#: Și a doua listă albă: locurile în care are voie să apară NUMELE tabelei,
#: oriunde în cod. Asta e ce ajunge în corpul blocurilor `DO`, unde despărțirea
#: în instrucțiuni se oprește — PL/pgSQL nu se poate despărți după `;`, fiindcă
#: `BEGIN`, `THEN` și `EXCEPTION WHEN` deschid instrucțiuni fără unul, iar o
#: despărțire aproximativă ar da fragmente care încep cu `BEGIN` și ar înghiți
#: orice ar urma. Acolo nu se judecă instrucțiuni, ci fiecare pomenire: o
#: scriere trebuie să numească tabela, iar o pomenire care nu e una dintre
#: astea patru pică — inclusiv `public.scans` și `"scans"`.
#:
#: Se potrivesc pe codul din care literalii de șir au fost înlocuiți cu `''`.
_REFERINTE_PERMISE: tuple[re.Pattern[str], ...] = (
    # pasul 1: numărătoarea rândurilor de care migrația se împiedică
    re.compile(r"SELECT\s+count\(\*\)\s+INTO\s+n\s+FROM\s+(scans)"
               r"\s+WHERE\s+status\s*=\s*''", re.I),
    # pasul 2: constrângerile. Forma, nu numele — o altă constrângere adăugată
    # deliberat mâine e legitimă; o coloană sau un tip nu.
    re.compile(r"ALTER\s+TABLE\s+(scans)\s+(?:ADD|DROP)\s+CONSTRAINT\b", re.I),
    re.compile(r"COMMENT\s+ON\s+COLUMN\s+(scans)\.\w+\b", re.I),
    # pasul 3: inserarea de probă, ÎNTREAGĂ și până la `;`. O coadă în plus
    # (`... ON CONFLICT DO UPDATE SET ...`) nu se mai potrivește, deci nu trece.
    re.compile(r"INSERT\s+INTO\s+(scans)\s*\(\s*scanner\s*,\s*target\s*,"
               r"\s*status\s*\)\s*VALUES\s*\(\s*''\s*,\s*''\s*,\s*''\s*\)\s*;",
               re.I),
)

#: `\b` la capăt ca `scans_status_check` să NU fie o pomenire a tabelei, dar
#: `public.scans`, `"scans"` și `sentinel.scans` să fie.
_NUMELE_TABELEI = re.compile(r"\bscans\b", re.I)

#: `$$` sau `$eticheta$`. Cifra nu poate deschide o etichetă, deci `$1` dintr-un
#: parametru nu e confundat cu un citat cu dolar.
_ETICHETA_DOLAR = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")


def _scaneaza(sql: str) -> tuple[str, list[str]]:
    """SQL fără comentarii, ȘI instrucțiunile lui de nivel superior.

    Decuparea de dinainte lua doar liniile care ÎNCEP cu `--`, deci un
    `RAISE NOTICE ...; -- comentariu care pomenește EXECUTE` la capătul unei
    linii de cod rămânea în text și declanșa interdicția de SQL dinamic pe o
    migrație perfect curată. Un test care pică din alt motiv decât cel scris în
    el e la fel de nefolositor ca unul care trece degeaba — și, aici, ar fi
    picat pe fiecare rulare până ce cineva l-ar fi „reparat" lărgind
    interdicția. Se taie deci `--…` până la capătul liniei, oriunde pe linie, și
    `/*…*/` pe oricâte linii.

    Scanare caracter cu caracter, nu `re.sub`, și ăsta e tot rostul funcției: un
    `--` din INTERIORUL unui literal (`'... -- ...'`) nu e comentariu. Un
    `re.sub(r"--.*$", "", ...)` ar tăia acolo, ar lăsa literalul fără ghilimeaua
    de închidere, iar decuparea literalilor de mai târziu ar înghiți apoi cod
    adevărat — o aserțiune care nu mai vede scrierea pe care există s-o vadă, și
    care tace despre asta.

    Șirurile citate cu dolar (`$$ … $$`) rămân întregi și sunt tratate ca ce
    sunt: corpul blocurilor `DO`, adică instrucțiuni care chiar se execută.
    Comentariile și literalii dinăuntrul lor se taie la fel ca afară, fiindcă
    acolo chiar sunt comentarii și literali PL/pgSQL.

    A doua treabă, adăugată în aceeași trecere în loc să fie scrisă a doua oară:
    despărțirea în instrucțiuni de nivel superior. Se despart la `;`, dar NUMAI
    la un `;` care e cu adevărat separator — nu unul dintr-un literal, și nu
    unul din corpul unui `$$ … $$`, unde există câte unul după fiecare linie de
    PL/pgSQL. Fără eticheta de dolar, singurul `DO` din migrație s-ar sparge în
    zece cioburi care încep cu `DECLARE`, `BEGIN`, `SELECT`, `END`; cu ea, e o
    instrucțiune. Un scaner al doilea, scris separat, ar fi însemnat două
    păreri despre unde se termină un literal.
    """
    tot: list[str] = []
    curent: list[str] = []
    instructiuni: list[str] = []

    def emite(txt: str) -> None:
        tot.append(txt)
        curent.append(txt)

    def incheie() -> None:
        text = "".join(curent).strip()
        if text:
            instructiuni.append(text)
        curent.clear()

    i, n = 0, len(sql)
    eticheta: str | None = None
    while i < n:
        if eticheta is None:
            deschide = _ETICHETA_DOLAR.match(sql, i)
            if deschide:
                eticheta = deschide.group(0)
                emite(eticheta)
                i = deschide.end()
                continue
        elif sql.startswith(eticheta, i):
            emite(eticheta)
            i += len(eticheta)
            eticheta = None
            continue

        if sql[i] == "'":
            j = i + 1
            while j < n:
                if sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            emite(sql[i:j])
            i = j
        elif sql.startswith("--", i):
            capat = sql.find("\n", i)
            i = n if capat == -1 else capat
        elif sql.startswith("/*", i):
            capat = sql.find("*/", i + 2)
            i = n if capat == -1 else capat + 2
            emite(" ")
        elif sql[i] == ";" and eticheta is None:
            tot.append(";")
            i += 1
            incheie()
        else:
            emite(sql[i])
            i += 1
    incheie()
    return "".join(tot), instructiuni


def _fara_comentarii(sql: str) -> str:
    """Doar textul, pentru cine n-are nevoie și de despărțire."""
    return _scaneaza(sql)[0]


def _migrations_in_order() -> list[tuple[int, Path]]:
    found = [(int(re.match(r"^(\d+)_", f.name).group(1)), f)
             for f in MIGRATIONS.glob("*.sql")]
    assert found, f"nicio migrație găsită în {MIGRATIONS}"
    return sorted(found)


def _effective_scans_statuses() -> tuple[int, set[str]]:
    """Ce valori acceptă `scans.status` după TOATE migrațiile, și din care vine.

    Se citește ultima constrângere numită `scans_status_check` adăugată explicit.
    Constrângerea originală din 0003 e anonimă (Postgres o botează după
    convenția `<tabelă>_<coloană>_check`), deci nu apare aici — și tocmai de-aia
    testul de mai jos verifică separat că ea chiar conținea `skipped`: altfel
    testul ar putea trece pe un depozit unde n-a fost niciodată nimic de scos.
    """
    ultima: tuple[int, set[str]] | None = None
    for version, path in _migrations_in_order():
        m = _ADD_CONSTRAINT.search(path.read_text(encoding="utf-8"))
        if m:
            ultima = (version, set(_LITERAL.findall(m.group(1))))
    assert ultima is not None, (
        "nicio migrație nu adaugă `scans_status_check` cu nume explicit, deci "
        "constrângerea efectivă e tot cea anonimă din 0003")
    return ultima


def test_the_scans_status_constraint_no_longer_admits_skipped() -> None:
    """Starea care mințea nu mai poate ajunge în tabelă.

    Eșecul pe care îl previne: cât timp `'skipped'` e o valoare legală,
    următoarea bucată de cod care o scrie — un scaner condiționat, o rulare
    întreruptă din configurație — produce imediat «ultima rulare încheiată acum
    1h, 0 constatări» în `/selfcheck` și în panou, fără ca nimeni să atingă
    verificarea. Baza e singurul loc unde asta se oprește o dată pentru tot.
    """
    version, statuses = _effective_scans_statuses()
    assert "skipped" not in statuses, (
        f"constrângerea efectivă (din migrația {version:04d}) încă acceptă "
        f"`skipped`: {sorted(statuses)}")
    assert statuses == {"running", "completed", "failed", "timeout"}, (
        f"lista de statusuri s-a schimbat altfel decât se aștepta: "
        f"{sorted(statuses)}")


def test_the_original_constraint_really_did_admit_skipped() -> None:
    """Fără asta, testul de deasupra ar putea trece degeaba.

    Eșecul pe care îl previne: dacă `0003` n-ar fi conținut niciodată `skipped`,
    testul de deasupra ar fi verde pe un depozit în care nu s-a reparat nimic —
    o aserțiune care nu poate pica nu păzește nimic. Aici se arată că valoarea
    chiar era acolo, deci că migrația nouă are ce scoate.

    `0003` e imuabilă (runner-ul refuză o migrație aplicată al cărei conținut
    s-a schimbat), deci propoziția asta rămâne adevărată prin construcție.
    """
    text = (MIGRATIONS / "0003_vuln.sql").read_text(encoding="utf-8")
    bloc = text[text.index("CREATE TABLE scans"):]
    bloc = bloc[:bloc.index("\n);")]
    m = re.search(r"CHECK\s*\(\s*status\s+IN\s*\(([^)]*)\)\s*\)", bloc, re.I | re.S)
    assert m, f"nu am găsit constrângerea de status în CREATE TABLE scans:\n{bloc}"
    assert "skipped" in set(_LITERAL.findall(m.group(1)))


def test_the_migration_refuses_the_rows_instead_of_rewriting_them() -> None:
    """Rândurile existente nu se convertesc tăcut — și nici nu se șterg.

    Eșecul pe care îl previne: `UPDATE scans SET status='completed' WHERE status
    ='skipped'` ar fi trecut migrația fără o vorbă și ar fi REscris istoric — o
    rulare care n-a măsurat nimic ar fi devenit, în date, una care a măsurat și
    n-a găsit nimic. Adică exact afirmația falsă din care a pornit toată treaba,
    doar că împietrită în tabelă în loc să fie produsă la citire. Un `DELETE` ar
    fi pierdut singura urmă că cineva scrie valoarea aia.

    Pe gazda operatorului sunt 0 astfel de rânduri, deci refuzul e operație nulă.
    Dacă se declanșează pe altă instanță, aia e informație, nu obstacol — și
    atunci mesajul trebuie să-i spună operatorului ce are de făcut.

    ## De ce listă albă, și nu încă o alternanță

    Garda asta a fost respinsă de trei ori, de fiecare dată fiindcă era o listă
    NEAGRĂ: oarbă întâi la SQL dinamic (`DO $$ BEGIN EXECUTE 'UPDATE scans SET
    ...'; END $$;`, un șir care dispărea cu totul la decuparea literalilor),
    apoi la două ortografii, apoi la treisprezece. Cea care a dărâmat-o ultima
    oară e banală: `UPDATE public.scans SET status='completed' WHERE status=
    'skipped'` — calificarea cu schemă e stil obișnuit într-o migrație. Rulată
    în migrația reală, suita întreagă a rămas 2663 passed, identică cu
    baseline-ul.

    Fiecare rundă a adăugat alternanțele la care se gândise verificatorul de
    dinainte, și fiecare rundă următoare a găsit alta în câteva minute:
    `UPDATE "scans"`, `UPDATE sentinel.scans`, `DELETE FROM public.scans`,
    `TRUNCATE scans`, `TRUNCATE TABLE scans`, `DROP TABLE scans`, `DROP TABLE IF
    EXISTS scans CASCADE`, `INSERT ... ON CONFLICT DO UPDATE`, `COPY scans FROM
    PROGRAM ...`, `ALTER TABLE scans DROP COLUMN findings_count`, `ALTER TABLE
    scans ALTER COLUMN status TYPE ...`. Mulțimea instrucțiunilor care scriu,
    distrug sau remodelează o tabelă în PG 16 nu e enumerabilă, deci o listă
    neagră completă nu se poate scrie — iar una incompletă tace exact acolo unde
    contează, cu suita verde.

    Deci întrebarea e alta: nu „conține vreo scriere?", ci „conține ALTCEVA
    decât instrucțiunile așteptate?". 0029 e cinci instrucțiuni și cinci
    pomeniri ale tabelei, toate cunoscute și scrise în `_INSTRUCTIUNI_PERMISE`
    și `_REFERINTE_PERMISE`. Orice în plus pică, fără să fie numit nicăieri.

    ## De ce blocul de probă din migrație NU acoperă asta

    Migrația își pune singură efectul la încercare (pasul 3, păzit de testul
    următor), și e ușor de crezut că proba aia prinde și o conversie tăcută.
    Nu o prinde: ea dovedește că baza refuză `skipped` DUPĂ rescrierea
    constrângerii. Un `UPDATE` strecurat rulează ÎNAINTE, golește tabela de
    rânduri `skipped`, deci numărătoarea de la pasul 1 găsește zero, refuzul nu
    se mai declanșează, proba trece ca de obicei, iar migrația raportează
    succes. Rândurile rescrise nu mai există ca să se plângă. Singurul loc unde
    asta se oprește e citirea fișierului, aici.

    ## Ce NU acoperă

    Despărțirea în instrucțiuni e a nivelului superior; corpul unui bloc `DO` nu
    se poate despărți la fel, iar acolo ajunge a doua listă albă, cea pe
    pomenirile tabelei. Rămâne neacoperit ce nu numește tabela și nu e o
    instrucțiune de nivel superior: o scriere printr-un view sau printr-un
    trigger. `EXECUTE` e interzis cu totul mai jos, iar view-uri și triggere
    0029 nu creează — s-ar vedea ca instrucțiuni în afara listei albe.
    """
    sql = (MIGRATIONS / "0029_scans_no_skipped.sql").read_text(encoding="utf-8")
    # Comentariile explică tocmai ce NU face migrația; se judecă doar codul.
    cod, instructiuni = _scaneaza(sql)

    # Interdicția pe SQL dinamic se pune pe `cod`, ÎNAINTE de decuparea de mai
    # jos — altfel tocmai scrierea ascunsă într-un literal ar fi cea decupată.
    # Migrația n-are nevoie de `EXECUTE` ca să facă ce spune (numără, refuză,
    # rescrie constrângerea, probează efectul), deci interdicția totală e
    # gratuită și nu cere nicio judecată despre ce e înăuntrul șirului.
    assert not re.search(r"\bEXECUTE\b", cod, re.I), (
        "migrația conține SQL dinamic; orice scriere de acolo e invizibilă "
        "pentru aserțiunile de mai jos, care caută în codul fără literali de șir")

    # Despărțirea se dovedește ÎNAINTE să fie folosită. Dacă `$$ … $$` n-ar mai
    # fi opac la `;`, blocurile `DO` s-ar sparge în cioburi care încep cu
    # `DECLARE`, `BEGIN`, `SELECT`, și lista albă ar judeca cioburi. Dacă `;`
    # n-ar mai despărți deloc, tot fișierul ar fi o singură instrucțiune care
    # începe cu `DO` — și ar trece întreagă, orice ar conține.
    assert len(instructiuni) >= 5, (
        f"despărțirea a găsit {len(instructiuni)} instrucțiuni în 0029, care "
        f"are cinci; dacă `;` nu mai desparte nimic, tot fișierul e o singură "
        f"instrucțiune care începe cu `DO` și trece întreagă")
    # Cele două blocuri `DO`, recunoscute după ce e ÎN ele, nu după cum încep:
    # dacă citatele cu dolar n-ar mai fi opace, cioburile care poartă marcajele
    # astea ar începe cu `BEGIN`, nu cu `DO`.
    intregi = [x for x in instructiuni
               if "count(*)" in x or "INSERT INTO scans" in x]
    assert len(intregi) == 2 and all(re.match(r"DO\b", x, re.I) for x in intregi), (
        "cele două blocuri `DO` nu mai ies din despărțire ca instrucțiuni "
        "întregi, deci lista albă de mai jos judecă cioburi de PL/pgSQL")

    for instructiune in instructiuni:
        assert any(p.match(instructiune) for p in _INSTRUCTIUNI_PERMISE), (
            f"instrucțiune din afara listei albe a lui 0029: "
            f"{' '.join(instructiune.split())[:140]!r}. Migrația are voie doar "
            f"cu `DO $…$`, `ALTER TABLE scans ADD/DROP CONSTRAINT` și "
            f"`COMMENT ON COLUMN scans.…`")

    # …iar mesajul de refuz îi ARATĂ operatorului un `UPDATE` pe care să-l ruleze
    # el, cu ochii pe rând. Ăla e text, nu instrucțiune, deci literalii se taie
    # înainte de căutarea de mai jos: altfel sfatul ar fi confundat cu fapta.
    executabil = re.sub(r"'(?:[^']|'')*'", "''", cod)

    pomeniri = list(_NUMELE_TABELEI.finditer(executabil))
    assert len(pomeniri) >= 5, (
        f"doar {len(pomeniri)} pomeniri ale tabelei în codul lui 0029; sunt "
        f"cinci. O căutare care nu găsește nimic trece liniștită pentru "
        f"totdeauna, și exact așa au trecut aici teste care nu verificau nimic")
    permise = {m.start(1) for p in _REFERINTE_PERMISE for m in p.finditer(executabil)}
    straine = [" ".join(executabil[max(0, m.start() - 45):m.end() + 25].split())
               for m in pomeniri if m.start() not in permise]
    assert not straine, (
        f"`scans` e pomenit în codul lui 0029 în afara celor patru locuri pe "
        f"care migrația le are — o scriere trebuie să numească tabela, deci "
        f"aici se oprește și cea din corpul unui bloc `DO`: {straine}")

    assert re.search(r"count\(\*\)\s+INTO\s+n\s+FROM\s+scans\s+WHERE\s+status\s*=\s*'skipped'",
                     cod, re.I), (
        "migrația nu numără rândurile `skipped`, deci n-are de unde ști dacă "
        "există vreunul de care să se împiedice")
    assert re.search(r"IF\s+n\s*>\s*0\s+THEN", cod, re.I), cod
    assert "RAISE EXCEPTION" in cod, (
        "migrația nu se oprește; ar trece peste rânduri pe care nu le înțelege")
    # Refuzul trebuie să-i spună ce să facă, nu doar că refuză.
    assert "HINT" in cod and "SELECT id, scanner" in cod, (
        "mesajul de refuz nu-i arată operatorului cum să vadă rândurile")


def test_the_migration_proves_the_constraint_bites_instead_of_assuming_it() -> None:
    """`ALTER TABLE` care întoarce succes nu e dovadă că baza respinge valoarea.

    Eșecul pe care îl previne, în forma pe care o are tot depozitul ăsta:
    `DROP CONSTRAINT IF EXISTS scans_status_check` nu întoarce eroare când nu
    găsește nimic. Dacă în 0003 constrângerea ar purta alt nume decât cel dat de
    convenția Postgres, dropul n-ar șterge nimic, s-ar adăuga una nouă lângă cea
    veche, migrația ar raporta succes — și abia peste luni s-ar afla că nu
    valoarea a fost scoasă, ci doar că s-a mai adăugat un rând în catalog.

    Ce verifică testul ăsta: că migrația își pune la încercare propriul efect,
    adică încearcă să insereze `skipped` și se rupe dacă baza îl acceptă. Ce NU
    verifică: că blocul chiar rulează așa — asta se vede numai pe un Postgres.
    """
    sql = (MIGRATIONS / "0029_scans_no_skipped.sql").read_text(encoding="utf-8")
    cod = _fara_comentarii(sql)

    proba = re.search(r"INSERT\s+INTO\s+scans\s*\([^)]*status[^)]*\)\s*VALUES\s*\([^)]*'skipped'[^)]*\)",
                      cod, re.I | re.S)
    assert proba, (
        "migrația nu încearcă niciodată să insereze `skipped`, deci raportează "
        "intenția (am rescris constrângerea), nu efectul (baza o respinge)")
    dupa = cod[proba.end():]
    assert "RAISE EXCEPTION" in dupa, (
        "proba se inserează dar nimic nu se întâmplă dacă REUȘEȘTE — o probă "
        "care nu poate pica nu dovedește nimic")
    assert "check_violation" in dupa, (
        "nu se prinde respingerea așteptată, deci calea fericită ar rupe migrația")


# ---------------------------------------------------------------------------
# Codul și schema trebuie să spună acelaşi lucru
# ---------------------------------------------------------------------------
def _finish_scan_statuses() -> list[tuple[str, str]]:
    """Fiecare `status=` literal dat lui `finish_scan`, cu fișierul din care vine."""
    gasite: list[tuple[str, str]] = []
    for pachet in ("sentinel", "executor"):
        for path in (ROOT / pachet).rglob("*.py"):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError as exc:  # pragma: no cover - ar pica oricum la import
                pytest.fail(f"{path}: {exc}")
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                nume = fn.attr if isinstance(fn, ast.Attribute) else (
                    fn.id if isinstance(fn, ast.Name) else None)
                if nume != "finish_scan":
                    continue
                for kw in node.keywords:
                    if kw.arg == "status" and isinstance(kw.value, ast.Constant) \
                            and isinstance(kw.value.value, str):
                        gasite.append((str(path.relative_to(ROOT)), kw.value.value))
    return gasite


def test_no_code_path_writes_a_status_the_constraint_would_reject() -> None:
    """Ce scrie codul trebuie să încapă în ce acceptă baza.

    Eșecul pe care îl previne: strâmtând constrângerea, un apel rămas cu o
    valoare scoasă ar începe să arunce `CheckViolationError` la finalul fiecărei
    scanări. Rândul ar rămâne `running` pentru totdeauna — adică fix defectul
    celălalt din runda asta, produs de reparația acestuia.

    Aserțiunea pe lista NEGOALĂ e la fel de importantă ca cea pe conținut: o
    căutare care nu găsește niciun apel ar trece liniștită pentru totdeauna, și
    exact așa au trecut aici teste care nu verificau nimic.
    """
    _, permise = _effective_scans_statuses()
    gasite = _finish_scan_statuses()
    assert gasite, (
        "niciun apel `finish_scan(status=...)` găsit prin AST — testul nu "
        "verifică nimic; s-a mutat funcția sau i s-a schimbat numele?")

    gresite = [(f, s) for f, s in gasite if s not in permise]
    assert not gresite, (
        f"apeluri care scriu un status respins de `scans_status_check` "
        f"({sorted(permise)}): {gresite}")
