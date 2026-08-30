-- 0035_suricata_signature_column: coloană reală pentru semnătura Suricata,
-- umplută de un declanșator — nu GENERATED, nu doar un index de expresie.
--
-- ## De ce nu indexul de expresie
--
-- Cardul „Semnături IDS" — `aggregate.ids_signatures` — rămâne cea mai scumpă
-- interogare a panoului după 0033/0034: `raw->>'signature'` stă în `raw`, iar
-- PostgreSQL 16 NU poate întoarce valoarea unei coloane-expresie dintr-un
-- index (`check_index_only` o ignoră). S-a construit indexul de expresie și
-- s-a măsurat, pe o tabelă de 200 000 de rânduri unde era SINGURUL index
-- posibil, cu `enable_seqscan`/`enable_bitmapscan` stinse:
--
--     index pe (raw->>'signature')   Index Scan,      13 264 de buffere
--     coloană reală                  Index Only Scan,    175 de buffere
--
-- Pe `raw_events`, cu indexul de expresie prezent, planificatorul nici măcar
-- nu-l alege — rămâne pe `raw_events_source_idx`, citind heap-ul pentru
-- fiecare rând de suricata din fereastră. Un index care planificatorul nu-l
-- folosește e cost curat, scris la fiecare INSERT suricata, fără niciun plan
-- mai bun. Deci nu index de expresie: coloană reală.
--
-- ## De ce declanșator și nu GENERATED ALWAYS AS
--
-- O coloană `GENERATED ... STORED` s-ar fi umplut singură, fără cod de scris,
-- dar `ALTER TABLE ... ADD COLUMN ... GENERATED` cere o rescriere a TABELEI
-- ÎNTREGI sub `ACCESS EXCLUSIVE` — măsurat pe replică, 89,9 s pentru volumul de
---aici. Pe discul gazdei, împărțit cu ingestia, Suricata și nginx, ar fi
-- minute, nu secunde — timp în care STAU și ingestia, și panoul. Mai grav:
-- cititorul de journald pentru sshd/sudo (defectul documentat la migrația
-- 0031) PIERDE DEFINITIV evenimentele consumate în pasele care eșuează cât
-- durează blocajul. Pierdere reală de date pentru o coloană de confort.
--
-- Un declanșator `BEFORE INSERT` costă, măsurat pe replică, +14,5% la timpul
-- unui INSERT (1296 → 1484 ms la 300 000 de rânduri din trei surse). Pare mult
-- până se înmulțește cu volumul real: 0,63 µs/rând × ~55 000 evenimente/zi =
-- **35 ms pe zi**. Zero întrerupere, zero pierdere — costul e pe calea cea mai
-- fierbinte, dar e nesemnificativ față de o rescriere de minute.
--
-- ## Coloana
--
-- `ADD COLUMN` fără valoare implicită nu rescrie tabela partiționată — pe
-- fiecare din cele ~30 de partiții zilnice e doar o schimbare de catalog.
-- Lacătul `ACCESS EXCLUSIVE` se ia și se dă drumul aproape imediat, la fel ca
-- la 0032. Coloana rămâne NULL pentru orice sursă în afară de suricata — și
-- pentru rândurile de suricata scrise ÎNAINTE de migrația asta, până la
-- backfill-ul din 0036.
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS signature text;

COMMENT ON COLUMN raw_events.signature IS
    'raw->>''signature'' pentru rândurile de suricata, umplut de raw_events_signature_trg. '
    'NULL pentru orice altă sursă, și pentru suricata dinainte de backfill (0036). '
    'Vezi aggregate.ids_signatures.';

-- ## De ce se citește catalogul după ALTER, la fel ca la 0032
--
-- `IF NOT EXISTS` se uită DOAR LA NUME. O coloană `signature` cu alt tip, sau
-- cu `NOT NULL`, sau cu o valoare implicită, ar trece codul de ieșire pe zero
-- fără să dea migrația înapoi — și fiecare din cele trei ar strica ceva diferit
-- mai departe: un tip greșit face `NOT LIKE` din 0037 să pice sau să compare
-- altceva; `NOT NULL` ar refuza orice rând non-suricata (adică majoritatea
-- ingestiei); o valoare implicită ar face un rând nou să se nască „umplut" cu
-- ceva care nu vine din `raw`.
DO $$
DECLARE
    tip           text;
    accepta_nul   boolean;
    are_implicita boolean;
BEGIN
    SELECT format_type(a.atttypid, a.atttypmod), NOT a.attnotnull, a.atthasdef
      INTO tip, accepta_nul, are_implicita
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
     WHERE c.relname = 'raw_events'
       AND c.relkind = 'p'          -- tabela partiționată (părintele), nu o partiție
       AND a.attname = 'signature'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF tip IS NULL THEN
        RAISE EXCEPTION 'raw_events.signature nu există pe părinte după ALTER TABLE';
    END IF;

    IF tip <> 'text' THEN
        RAISE EXCEPTION
            'raw_events.signature există, dar are tipul %; comparațiile din aggregate.ids_signatures ar însemna altceva', tip;
    END IF;

    IF NOT accepta_nul THEN
        RAISE EXCEPTION
            'raw_events.signature e NOT NULL — orice rând non-suricata ar refuza INSERT-ul';
    END IF;

    IF are_implicita THEN
        RAISE EXCEPTION
            'raw_events.signature are o valoare implicită — un rând nou s-ar naște cu o semnătură care nu vine din raw';
    END IF;
END $$;

-- ## Declanșatorul
--
-- `WHEN (NEW.source = 'suricata' AND NEW.signature IS NULL)` la nivel de
-- DECLANȘATOR, nu în corpul funcției: PostgreSQL nu mai apelează funcția
-- deloc pentru restul surselor — cost zero pe ~96% din ingestie (nginx, sshd,
-- auditd). Condiția `signature IS NULL` lasă o valoare pusă explicit la
-- INSERT să câștige față de declanșator, deși nimic din codul de azi face
-- asta — e aceeași plasă de siguranță ca supra-scrierea tăcută dintr-un
-- rescris viitor.
CREATE OR REPLACE FUNCTION sentinel_fill_signature() RETURNS trigger AS $$
BEGIN
    NEW.signature := NEW.raw->>'signature';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Creat pe PĂRINTELE partiționat, FOR EACH ROW, fără ONLY și fără INSTEAD OF:
-- exact condițiile sub care PostgreSQL clonează automat un declanșator pe
-- TOATE partițiile — cele care există acum ȘI cele create mai târziu de
-- `sentinel_create_partition` (0007). Verificat pe o replică locală
-- (PostgreSQL 16.4): o partiție creată DUPĂ acest `CREATE TRIGGER` a primit
-- declanșatorul fără nicio comandă în plus, iar un INSERT de suricata în ea
-- a umplut `signature` corect. Fără asta, fiecare zi nouă ar redeschide
-- exact golul pe care declanșatorul îl închide azi.
CREATE TRIGGER raw_events_signature_trg
    BEFORE INSERT ON raw_events
    FOR EACH ROW
    WHEN (NEW.source = 'suricata' AND NEW.signature IS NULL)
    EXECUTE FUNCTION sentinel_fill_signature();

COMMENT ON TRIGGER raw_events_signature_trg ON raw_events IS
    'Umple raw_events.signature din raw->>''signature'' la INSERT. Se clonează automat pe partițiile noi — vezi 0035.';

-- ## Garda: declanșatorul chiar există pe TOATE partițiile de azi
--
-- Clonarea pe partiții viitoare e un comportament al motorului, nu al
-- migrației, și nu poate fi testat AICI fără să se creeze o partiție reală în
-- plus pe gazdă. Ce SE poate verifica acum e efectul imediat: că declanșatorul
-- chiar a ajuns pe fiecare partiție existentă, nu doar pe părinte. Un
-- `CREATE TRIGGER` care ar eșua silențios pe o singură partiție — de pildă una
-- creată manual, în afara lui `sentinel_create_partition`, cu o restricție care
-- respinge declanșatoare moștenite — ar lăsa exact acea zi neacoperită, fără
-- ca migrația să raporteze altceva decât succes.
DO $$
DECLARE
    fara_declansator text;
BEGIN
    SELECT string_agg(c.relname, ', ')
      INTO fara_declansator
      FROM pg_inherits i
      JOIN pg_class c ON c.oid = i.inhrelid
      JOIN pg_class p ON p.oid = i.inhparent
     WHERE p.relname = 'raw_events'
       AND NOT EXISTS (
           SELECT 1 FROM pg_trigger t
            WHERE t.tgrelid = c.oid
              AND t.tgname = 'raw_events_signature_trg'
              AND NOT t.tgisinternal
       );

    IF fara_declansator IS NOT NULL THEN
        RAISE EXCEPTION
            'raw_events_signature_trg lipsește de pe partițiile: %. Rândurile de suricata scrise acolo nu-și vor umple signature.',
            fara_declansator;
    END IF;
END $$;

-- ## Ce NU face migrația asta, și de ce e în alte fișiere
--
-- Backfill-ul rândurilor de suricata scrise ÎNAINTE de declanșator e în 0036,
-- NU aici: `ALTER TABLE` și `CREATE TRIGGER` cer amândouă `ACCESS EXCLUSIVE`,
-- iar acest lacăt NU se eliberează la finalul instrucțiunii — rămâne ținut
-- până la COMMIT-ul întregii tranzacții a migrației. Măsurat direct: cu
-- `ALTER TABLE ... ADD COLUMN` și `CREATE TRIGGER` într-o tranzacție ținută
-- deschisă câteva secunde, un `SELECT` obișnuit din altă sesiune AȘTEAPTĂ și
-- pică la `statement_timeout`, nu doar un `INSERT`. Dacă backfill-ul de
-- ~318 000 de rânduri (24,7–29,4 s măsurat) ar fi în ACEEAȘI tranzacție ca
-- `CREATE TRIGGER`, tot timpul ăla panoul ar pica exact cu simptomul pe care
-- toată seria asta de migrații (0030–0034) încearcă să-l repare — de data asta
-- din migrație, nu din interogare. Indexul din 0037 e la fel, separat, pentru
-- alt motiv: se construiește peste date deja complete (vezi 0036 și 0037).
