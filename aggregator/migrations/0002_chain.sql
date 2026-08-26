-- Rezultatul verificării lanțului de hash-uri, per instanță.
--
-- Fișier NOU, nu o modificare a lui `0001_core.sql`: acela e aplicat pe baza
-- reală, iar `lib/migrate.ts` consemnează INSTRUCȚIUNI cu suma lor de control —
-- o editare a unei instrucțiuni deja aplicate oprește toate migrațiile, cu un
-- mesaj despre istorie rescrisă. Aceleași convenții ca acolo: o gardă `@guard`
-- deasupra fiecărei instrucțiuni, fără `DELIMITER`, identificatori în
-- `ascii_bin`, timpi în `DATETIME(6)`.
--
-- ============================================================================
-- De ce există tabela asta
-- ============================================================================
--
-- „N-am verificat niciodată" și „am verificat și e bine" nu au voie să arate la
-- fel. Fără un loc în care se scrie rezultatul, singurul mod de a afla dacă
-- lanțul a fost vreodată verificat ar fi absența unei alarme — adică exact
-- forma pe care o ia o verificare care nu s-a executat niciodată.
--
-- Deci: lipsa rândului ÎNSEAMNĂ „niciodată verificat". Nu există valoare
-- implicită care să semene cu „bine": `status` e NOT NULL fără DEFAULT, iar cine
-- inserează trebuie să spună explicit ce a găsit.
--
-- ============================================================================
-- Ce se ține minte, și de ce fiecare coloană
-- ============================================================================
--
-- `verified_through` — cel mai mare `source_id` până la care lanțul e legat fără
-- întrerupere. E numărul care se compară cu `sync_cursors.last_source_id`: dacă
-- rămâne mult în urmă, verificarea nu ține pasul cu ingestia, iar asta nu se
-- vede din `status`.
--
-- `first_source_id` / `first_prev_hash` — capătul de jos al copiei noastre,
-- FIXAT la prima verificare. Fără el, o ștergere a primelor rânduri ar arăta
-- identic cu pragul de backfill (`ship:<flux>:floor` pe server, rândurile de sub
-- el nu pleacă niciodată): în ambele cazuri, primul rând stocat are un
-- `prev_hash` care nu se poate verifica. Odată fixat, o schimbare a lui e o
-- trunchiere a istoriei, nu o pornire.
--
-- `broken_at` — CÂND s-a văzut ruptura prima oară, nu când a rulat ultima
-- verificare. O rulare ulterioară nu are voie să reseteze momentul: prima
-- observație e cea care spune ce interval trebuie cercetat.
--
-- `status` are trei valori și nu se colapsează niciodată la două:
--   'ok'      — toate legăturile de la `first_source_id` la `verified_through`
--               se potrivesc;
--   'broken'  — o legătură nu se potrivește, iar rândurile din jur sunt sub
--               filigranul confirmat, deci nu mai pot fi „încă pe drum";
--   'unknown' — verificarea nu a putut decide (nu s-a putut citi, sau capătul
--               de sus e peste filigran și încă se mișcă).

-- @guard table audit_chain_state
CREATE TABLE audit_chain_state (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id      VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Fără DEFAULT, dinadins: vezi capul fișierului. Nu e ENUM fiindcă o a patra
    -- valoare adăugată mai târziu ar cere ALTER pe o tabelă vie, iar mulțimea de
    -- valori e impusă oricum de codul care scrie.
    status           VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                     COMMENT 'ok | broken | unknown; lipsa randului = neverificat',

    checked_links    BIGINT UNSIGNED NOT NULL DEFAULT 0
                     COMMENT 'cate legaturi s-au comparat la ultima rulare',
    verified_through BIGINT NULL
                     COMMENT 'cel mai mare source_id pana la care lantul e legat',

    first_source_id  BIGINT NULL
                     COMMENT 'capatul de jos al copiei, fixat la prima verificare',
    first_prev_hash  VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,

    break_source_id  BIGINT NULL
                     COMMENT 'randul la care lantul nu se mai leaga',
    break_detail     TEXT NULL,
    broken_at        DATETIME(6) NULL
                     COMMENT 'cand s-a vazut PRIMA oara, nu ultima rulare',

    last_run_at      DATETIME(6) NOT NULL,
    last_run_kind    VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                     COMMENT 'ingest | scheduled — cine a rulat verificarea',

    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                     ON UPDATE CURRENT_TIMESTAMP(6),

    PRIMARY KEY (id),
    -- O singură stare per instanță. Istoria rulărilor NU se ține aici: ar fi o
    -- tabelă care crește la fiecare cron, iar întrebarea la care răspunde
    -- verificarea e „acum e rupt?", nu „de câte ori am întrebat".
    UNIQUE KEY uk_audit_chain_state_instance (instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='verificarea lantului de audit; lipsa randului = neverificat';
