-- 0015_login_history: cine s-a logat pe fiecare instanță, și ce a rulat.
--
-- Replica celor două tabele adăugate pe server de `0026_login_history.sql` și
-- `0027_session_close.sql`. Aceleași motive pentru care există acolo, plus unul
-- propriu găzduirii ăsteia.
--
-- ## Ce e diferit față de server
--
-- **Retenția.** Pe gazdă istoricul e nelimitat: e mașina ta, are 91 GB liberi,
-- iar întrebarea «ce a rulat cineva acum trei luni» e chiar cazul de folosință.
-- Aici e mărginit, fiindcă găzduirea e partajată și are cotă — iar o creștere
-- nemărginită nu se termină cu «tabela e mare», se termină cu **ingestia
-- refuzată pentru TOATE fluxurile**. Un flux care crește necontrolat le doboară
-- pe celelalte nouă.
--
-- Măsurat pe gazdă pe 24 august 2026: 97 415 comenzi = 22 MB în Postgres, iar
-- baza asta avea în total 83 MB. Deci fluxul ăsta e, singur, mai mare decât tot
-- restul agregatorului — și de-asta jobul de retenție îl taie la 180 de zile.
--
-- **Ce NU pleacă de pe gazdă:** `unexpected` (ce anume a fost neobișnuit la o
-- logare) rămâne acolo. E `text[]`, iar expeditorul nu trimite tablouri; panoul
-- extern vede că sesiunea a fost neobișnuită din severitatea alertei.
--
-- ## `argv` e redactat ÎNAINTE să plece
--
-- Redactarea se face la colectare, pe gazdă (`sentinel/redact.py`). Nu e o
-- politeţe: personalul furnizorului de găzduire are acces la baza asta, iar un
-- secret ajuns aici rămâne în tabelă, în backup și în replicile lui. Limita
-- redactării — e o listă de tipare, nu o garanţie — e scrisă în `docs/SECURITATE.md`.

-- @guard table login_session_entries
CREATE TABLE login_session_entries (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    instance_id     VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id       BIGINT       NOT NULL COMMENT 'login_sessions.id de pe instanță',

    session_key     VARCHAR(32)  NOT NULL COMMENT 'ses de la nucleu; unic pe pornire',
    username        VARCHAR(128) NULL COMMENT 'NULL = nucleul n-a putut rezolva un cont',
    auid            VARCHAR(32)  NULL,
    src_ip          INET6        NULL,
    terminal        VARCHAR(64)  NULL COMMENT 'pts0 = om; ssh = script',
    interactive     TINYINT(1)   NOT NULL DEFAULT 0,

    opened_at       DATETIME(6)  NOT NULL,
    closed_at       DATETIME(6)  NULL,
    closed_inferred TINYINT(1)   NOT NULL DEFAULT 0
        COMMENT '1 = nu s-a văzut nicio ieșire; momentul e ultima activitate',

    command_count   INT          NOT NULL DEFAULT 0,
    sudo_count      INT          NOT NULL DEFAULT 0,

    updated_at      DATETIME(6)  NOT NULL COMMENT 'ordinea de expediere',

    -- Contabilitatea sosirii, ca la orice tabela replicata. Fara ea, garda
    -- din `tests/schema.test.ts` citeste tabela drept una de LEGATURA:
    -- scrisa ca sub-rand si GOLITA la fiecare lot al altui flux. Adica
    -- istoricul sters la fiecare expediere.
    received_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq       BIGINT UNSIGNED NULL,

    -- Idempotența ingestiei. Aceeași formă ca la celelalte fluxuri mutabile: un
    -- lot reluat e o operație nulă, nu o duplicare.
    UNIQUE KEY uk_login_session_entries (instance_id, source_id),
    KEY ix_login_session_entries_opened (instance_id, opened_at),
    KEY ix_login_session_entries_updated (instance_id, updated_at),
    -- Sesiunile interactive: cele câteva zeci care contează, dintre mii.
    KEY ix_login_session_entries_human (instance_id, interactive, opened_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- @guard table session_command_entries
CREATE TABLE session_command_entries (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    instance_id   VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id     BIGINT       NOT NULL COMMENT 'session_commands.id de pe instanță',

    -- `login_sessions.id` de pe instanță, NU `login_session_entries.id` de aici.
    -- Nicio cheie străină, ca peste tot în replica asta: cursoarele avansează
    -- independent pe flux, iar o comandă poate ajunge legitim înaintea sesiunii
    -- ei. O referință suspendată e o stare normală, nu o eroare de respins.
    session_source_id BIGINT   NULL,
    session_key   VARCHAR(32)  NOT NULL,

    ts            DATETIME(6)  NOT NULL,
    username      VARCHAR(128) NULL,
    exe           VARCHAR(512) NULL,
    -- Linia întreagă, REDACTATĂ pe gazdă. `TEXT` și nu `VARCHAR`: `argv` e
    -- tăiat la 4000 de caractere de `sentinel/redact.py`, iar un `VARCHAR(4000)`
    -- în utf8mb4 depășește limita de rând a InnoDB.
    argv          TEXT         NOT NULL,
    cwd           VARCHAR(1024) NULL,
    tty           VARCHAR(64)  NULL,
    pid           INT          NULL,
    ppid          INT          NULL COMMENT 'deosebește o comandă tastată de una pornită de un script',
    success       TINYINT(1)   NULL,

    received_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq     BIGINT UNSIGNED NULL,

    UNIQUE KEY uk_session_command_entries (instance_id, source_id),
    KEY ix_session_command_entries_session (instance_id, session_source_id, source_id),
    KEY ix_session_command_entries_ts (instance_id, ts),
    KEY ix_session_command_entries_user (instance_id, username, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
