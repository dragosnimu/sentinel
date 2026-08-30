"""Coloana `signature` pe `raw_events`, umplută de un declanșator — nu de un
index de expresie și nu de o coloană GENERATED.

`ids_signatures` rămâne cea mai scumpă interogare a panoului după 0033/0034:
`raw->>'signature'` stă în `raw`, iar PostgreSQL 16 nu poate întoarce valoarea
unei expresii dintr-un index, deci fiecare rând de suricata din fereastră cerea
o pagină de heap. 0035/0036/0037 adaugă o coloană reală, umplută la INSERT de
un declanșator, backfill-uită o dată pentru rândurile vechi, și indexată.

Sunt TREI migrații, nu una, și motivul e măsurat, nu stilistic: `ALTER TABLE
ADD COLUMN` și `CREATE TRIGGER` (0035) cer `ACCESS EXCLUSIVE`, iar acest lacăt
rămâne ținut până la COMMIT-ul întregii tranzacții a fișierului — nu doar cât
ține instrucțiunea. Dacă backfill-ul (0036, 24,7–29,4 s măsurat) ar fi în
ACEEAȘI tranzacție ca declanșatorul, tot intervalul ăla ar bloca și `SELECT`-uri
obișnuite, nu doar scrieri — verificat direct, cu o tranzacție ținută deschisă
după `ALTER TABLE` + `CREATE TRIGGER`: un `SELECT` din altă sesiune a picat la
`statement_timeout`. Separate, fiecare migrație ia doar lacătul strict necesar
instrucțiunii ei proprii.

Testele de aici păzesc felurile în care reparația ar putea raporta succes fără
efect: o coloană cu tip/nul/implicit greșit, un backfill care nu-și verifică
rezultatul, un index omonim cu altă formă, și o interogare rescrisă care ar
cere din nou `raw`.

Ce s-a verificat manual pe o replică locală (PostgreSQL 16.4), și NU intră în
suita asta fiindcă cere un Postgres viu:

* declanșatorul se CLONEAZĂ automat pe o partiție creată DUPĂ el — o partiție
  nouă a primit `raw_events_signature_trg` fără nicio comandă în plus, iar un
  INSERT de suricata acolo a umplut `signature` corect. Descoperire suplimentară:
  PostgreSQL REFUZĂ să lase un declanșator clonat să fie șters de pe o singură
  partiție («trigger ... on table ... requires it») — invariantul e impus de
  motor, nu doar copiat o dată.
* backfill-ul (0036) rulat a doua oară dă `UPDATE 0` — idempotent.
* `ids_signatures` pe coloană și pe expresie dau EXACT aceleași rânduri:
  `EXCEPT` în ambele sensuri, pe fereastra de 7 zile, fără `LIMIT`, a dat 0.
* un `SELECT` și un `INSERT` lansate din altă sesiune CÂT TIMP backfill-ul
  (0036, singur în tranzacția lui) rula, s-au întors amândouă sub 300 ms.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from sentinel.analytics import aggregate

RADACINA = Path(__file__).resolve().parents[2]
MIGRATII = RADACINA / "sentinel" / "db" / "migrations"
M_COLOANA = MIGRATII / "0035_suricata_signature_column.sql"
M_BACKFILL = MIGRATII / "0036_suricata_signature_backfill.sql"
M_INDEX = MIGRATII / "0037_suricata_signature_index.sql"


def _fara_comentarii(sql: str) -> str:
    return "\n".join(re.sub(r"--.*$", "", linie) for linie in sql.splitlines())


# ---------------------------------------------------------------------------
# 0035: coloana + declanșatorul
# ---------------------------------------------------------------------------
def test_coloana_e_text_nul_fara_implicita():
    """Un tip, `NOT NULL` sau o valoare implicită greșite ar trece `IF NOT
    EXISTS` fără eroare și ar strica ceva diferit mai departe: `NOT NULL` ar
    refuza orice rând non-suricata (majoritatea ingestiei), iar o valoare
    implicită ar naște rânduri noi „umplute" cu ceva ce nu vine din `raw`."""
    text = _fara_comentarii(M_COLOANA.read_text(encoding="utf-8"))
    assert re.search(r"ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+signature\s+text\s*;", text, re.I), text
    assert "tip <> 'text'" in text
    assert "NOT accepta_nul" in text
    assert "are_implicita" in text


def test_declansatorul_e_pe_parinte_for_each_row_fara_only_fara_instead_of():
    """Ăsta e exact contractul PostgreSQL pentru clonarea automată pe partiții,
    prezente ȘI viitoare: `FOR EACH ROW`, pe tabela părinte, fără `ONLY` și
    fără `INSTEAD OF`. Un declanșator `FOR EACH STATEMENT` nu se clonează
    deloc, iar unul scris `ON ONLY raw_events` s-ar aplica doar rândurilor
    inserate direct în părinte — niciodată, fiindcă toate INSERT-urile
    ingestiei cad într-o partiție."""
    text = _fara_comentarii(M_COLOANA.read_text(encoding="utf-8"))
    m = re.search(
        r"CREATE\s+TRIGGER\s+raw_events_signature_trg\s+"
        r"BEFORE\s+INSERT\s+ON\s+(ONLY\s+)?raw_events\s+"
        r"FOR\s+EACH\s+(ROW|STATEMENT)",
        text, re.I | re.S)
    assert m, "nu mai găsesc CREATE TRIGGER raw_events_signature_trg pe forma așteptată"
    assert m.group(1) is None, "ON ONLY raw_events nu s-ar clona pe partiții"
    assert m.group(2).upper() == "ROW", "FOR EACH STATEMENT nu se clonează pe partiții"
    assert "INSTEAD OF" not in text.upper()


def test_declansatorul_scrie_signature_doar_pentru_suricata_nescris_deja():
    """`WHEN` la nivel de declanșator, nu în corp: cost zero pe restul
    ingestiei. `signature IS NULL` lasă o valoare pusă explicit la INSERT să
    câștige față de declanșator."""
    text = _fara_comentarii(M_COLOANA.read_text(encoding="utf-8"))
    m = re.search(r"WHEN\s*\(([^)]*)\)", text, re.I)
    assert m, "declanșatorul nu mai are o clauză WHEN"
    conditie = m.group(1)
    assert "NEW.source = 'suricata'" in conditie
    assert "NEW.signature IS NULL" in conditie


def test_functia_declansatorului_citeste_din_raw():
    text = M_COLOANA.read_text(encoding="utf-8")
    assert re.search(r"NEW\.signature\s*:=\s*NEW\.raw\s*->>\s*'signature'", text)


def test_garda_verifica_toate_partitiile_curente():
    """Fără verificarea asta, o partiție unde `CREATE TRIGGER` a eșuat parțial
    — teoretic, printr-o restricție locală neobișnuită — ar trece neobservată,
    iar rândurile de suricata scrise acolo n-ar primi niciodată `signature`."""
    text = _fara_comentarii(M_COLOANA.read_text(encoding="utf-8"))
    assert "pg_inherits" in text and "pg_trigger" in text
    # Garda trebuie să existe DUPĂ CREATE TRIGGER (verifică efectul lui), și
    # trebuie să ridice o excepție când găsește o partiție neacoperită — nu
    # doar să numere, altfel un cod de ieșire zero ar însemna „gata" chiar
    # când o partiție a rămas fără declanșator.
    dupa_trigger = text.split("CREATE TRIGGER raw_events_signature_trg", 1)[1]
    assert "fara_declansator" in dupa_trigger
    bloc_garda = dupa_trigger.split("fara_declansator", 1)[1]
    assert "RAISE EXCEPTION" in bloc_garda, (
        "garda numără partițiile neacoperite dar nu oprește migrația pentru ele")


# ---------------------------------------------------------------------------
# 0036: backfill-ul
# ---------------------------------------------------------------------------
def test_backfillul_e_intr_un_fisier_separat_de_declansator():
    """Dacă cineva ar muta backfill-ul înapoi în 0035 — „mai simplu, un
    singur fișier" — ar reintroduce exact lacătul care blochează panoul cât
    rulează backfill-ul. Fișierele separate înseamnă tranzacții separate."""
    assert M_BACKFILL != M_COLOANA
    text_coloana = _fara_comentarii(M_COLOANA.read_text(encoding="utf-8"))
    assert not re.search(r"UPDATE\s+raw_events\s+SET\s+signature", text_coloana, re.I), (
        "0035 conține și backfill-ul — ar moșteni ACCESS EXCLUSIVE de la ALTER/CREATE TRIGGER")


def test_backfillul_nu_are_nicio_comanda_access_exclusive():
    """Orice `ALTER`/`CREATE INDEX`/`CREATE TRIGGER` aici ar readuce exact
    lacătul pe care fișierul separat există ca să-l evite."""
    text = _fara_comentarii(M_BACKFILL.read_text(encoding="utf-8"))
    assert not re.search(r"\b(ALTER\s+TABLE|CREATE\s+TRIGGER|CREATE\s+INDEX)\b", text, re.I), text
    assert re.search(r"UPDATE\s+raw_events\s+SET\s+signature\s*=\s*raw\s*->>\s*'signature'",
                      text, re.I)


def test_backfillul_e_idempotent_prin_where_signature_is_null():
    """Fără `signature IS NULL` în WHERE, o a doua rulare ar rescrie toate
    rândurile de suricata din retenție degeaba — și, mai rău, ar intra în
    coliziune cu rânduri deja umplute corect de declanșator după 0035, fără
    niciun beneficiu."""
    text = _fara_comentarii(M_BACKFILL.read_text(encoding="utf-8"))
    m = re.search(r"UPDATE\s+raw_events\s+SET\s+signature[^;]*WHERE\s+([^;]*);", text, re.I | re.S)
    assert m, "nu mai găsesc clauza WHERE a backfill-ului"
    where = " ".join(m.group(1).split())
    assert "source = 'suricata'" in where
    assert "signature IS NULL" in where


def test_garda_backfillului_verifica_zero_randuri_ramase():
    """Un `UPDATE` reușit cu zero rânduri atinse, pe o bază cu suricata vechi
    real, ar însemna un WHERE stricat — nu se poate deosebi de „nu era nimic
    de reparat" decât uitându-se la ce a mai rămas NULL după."""
    text = _fara_comentarii(M_BACKFILL.read_text(encoding="utf-8"))
    assert "signature IS NULL" in text.split("UPDATE raw_events", 2)[-1]
    assert "count(*) INTO ramase" in text
    assert "ramase > 0" in text


# ---------------------------------------------------------------------------
# 0037: indexul
# ---------------------------------------------------------------------------
_INDEX = re.compile(
    r"CREATE\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?P<nume>\w+)\s+ON\s+(?P<tabela>\w+)\s*"
    r"(?:USING\s+\w+\s*)?\((?P<chei>[^)]*)\)"
    r"(?:\s*INCLUDE\s*\((?P<include>[^)]*)\))?"
    r"(?:\s*WHERE\s+(?P<predicat>[^;]*))?\s*;",
    re.I | re.S,
)


def _coloane(lista: str | None) -> list[str]:
    if not lista:
        return []
    return [c.split()[0].strip('"') for c in lista.split(",") if c.strip()]


def _indexul_semnaturilor() -> dict[str, object]:
    text = _fara_comentarii(M_INDEX.read_text(encoding="utf-8"))
    for m in _INDEX.finditer(text):
        if m.group("nume").lower() == "raw_events_suricata_sig_idx":
            return {
                "chei": _coloane(m.group("chei")),
                "include": _coloane(m.group("include")),
                "predicat": " ".join((m.group("predicat") or "").split()),
            }
    raise AssertionError("raw_events_suricata_sig_idx nu mai e creat de 0037")


def test_indexul_index_only_scan_posibil():
    idx = _indexul_semnaturilor()
    assert idx["chei"][:1] == ["ts"], "ts nu e prima cheie — fereastra de 7 zile ar citi tot"
    assert "signature" in idx["chei"]
    assert "src_ip" in idx["include"]
    assert re.search(r"source\s*=\s*'suricata'", idx["predicat"]), idx


def test_garda_indexului_respinge_omonime():
    text = M_INDEX.read_text(encoding="utf-8")
    tipare = [re.compile(g.replace("''", "'"))
              for g in re.findall(r"definitie\s*!~\s*'((?:[^']|'')*)'", text)]
    assert tipare, "0037 nu mai compară definiția indexului cu nimic"

    cap = "CREATE INDEX raw_events_suricata_sig_idx ON ONLY public.raw_events USING btree "

    def trece(definitie: str) -> bool:
        return all(t.search(definitie) for t in tipare)

    assert trece(cap + "(ts DESC, signature) INCLUDE (src_ip) "
                       "WHERE (source = 'suricata'::text)")
    assert not trece(cap + "(ts DESC, signature) INCLUDE (src_ip)"), \
        "garda ar binecuvânta un index fără source în predicat"
    assert not trece(cap + "(ts DESC, signature) WHERE (source = 'suricata'::text)"), \
        "garda ar binecuvânta un index fără INCLUDE (src_ip)"


def test_migratiile_indexului_si_backfillului_ridica_timeout_urile():
    for fisier in (M_BACKFILL, M_INDEX):
        text = fisier.read_text(encoding="utf-8")
        assert re.search(r"SET\s+LOCAL\s+statement_timeout\s*=\s*'10min'", text, re.I), fisier
        assert re.search(r"SET\s+LOCAL\s+lock_timeout\s*=\s*'60s'", text, re.I), fisier


# ---------------------------------------------------------------------------
# aggregate.ids_signatures: rescrisă pe coloană
# ---------------------------------------------------------------------------
def _sql_livrat(functie) -> str:
    sursa = inspect.getsource(functie)
    m = re.search(r'db\.fetch\(\s*"""(.*?)"""', sursa, re.S)
    assert m, f"nu mai găsesc interogarea livrată de {functie.__name__}"
    return m.group(1)


def test_ids_signatures_nu_mai_cere_raw():
    """Dacă interogarea ar reveni la `raw->>'signature'`, indexul din 0037
    n-ar mai fi ales de planificator — exact regresia pe care 0035/0036/0037
    există ca s-o repare."""
    sql = _sql_livrat(aggregate.ids_signatures)
    assert "raw->>" not in sql and "raw ->>" not in sql, sql
    assert re.search(r"\bsignature\b", sql), sql


def test_ids_signatures_pastreaza_filtrul_diagnosticelor_de_motor():
    """`NOT LIKE 'SURICATA %'` scoate diagnosticele motorului, nu amenințări
    reale — pierdut la rescriere, panoul s-ar umple cu zgomot intern."""
    sql = _sql_livrat(aggregate.ids_signatures)
    assert "NOT LIKE 'SURICATA %'" in sql, sql
    assert "source = 'suricata'" in sql, sql
    assert "interval '7 days'" in sql, sql


def test_ids_signatures_pastreaza_gruparea_pe_semnatura_si_ip():
    """Gruparea pe (semnătură, ip) e ce face `count(ip)` să numere adrese
    distincte în loc de rânduri — pierdută, cifrele de pe panou s-ar umfla."""
    sql = _sql_livrat(aggregate.ids_signatures)
    assert re.search(r"GROUP BY 1,\s*2", sql), sql
    assert "count(ip)" in sql, sql
    assert "host(src_ip)" in sql, sql
