-- Schema agregatorului: instanțe, intrări de audit, cursoare de sincronizare.
--
-- Se citește de sus în jos ca o listă de decizii, fiindcă asta e. Fiecare
-- instrucțiune are deasupra o gardă `-- @guard`, iar garda e obligatorie: o
-- instrucțiune fără ea e o eroare de încărcare, nu o instrucțiune fără
-- pre-verificare. Vezi `lib/migrate.ts` pentru de ce.
--
-- Fișierul se poate da direct unui client (`mysql < 0001_core.sql`): nu are
-- `DELIMITER`, nu are nimic asamblat la execuție, iar comentariile `@guard`
-- sunt comentarii SQL obișnuite. Asta e deliberat — vrem să se poată verifica
-- pe gazdă, nu doar prin runner.
--
-- ============================================================================
-- Trei reguli care se aplică peste tot mai jos
-- ============================================================================
--
-- 1. IDENTITATEA REALĂ E (instance_id, source_id). Cheia primară `BIGINT
--    AUTO_INCREMENT` e o comoditate — o rețea de rânduri se leagă mai ieftin
--    printr-un întreg local decât printr-o pereche. Nimic nu are voie să
--    presupună că `id`-ul de aici înseamnă ceva pe serverul sursă: două
--    instanțe pot trimite același `source_id`, iar același `source_id` retrimis
--    trebuie să nimerească același rând.
--
-- 2. FĂRĂ CHEI STRĂINE. Cursoarele avansează independent pe flux, deci o
--    detecție poate ajunge legitim înaintea incidentului ei, iar un rând de
--    audit poate ajunge înaintea rândului din `instances`. Cu o cheie străină,
--    ordinea aia — normală, nu excepțională — ar RESPINGE rândul, iar rândul
--    respins nu se mai întoarce niciodată: expeditorul primește ecoul doar
--    pentru ce a intrat. Se stochează referințe atârnate și se reconciliază.
--
-- 3. NU SE RECREEAZĂ INDEXURILE UNICE PARȚIALE ALE SERVERULUI. Agregatorul e o
--    replică, nu o a doua sursă de adevăr. Amprenta F deschisă, rezolvată și
--    redeschisă peste două săptămâni e istorie perfect legitimă, cu două
--    rânduri deschise la momente diferite; `incidents_fingerprint_open_idx`
--    recreat aici ar refuza al doilea rând, iar simptomul ar fi „lipsește un
--    incident din panou" — descoperit târziu și pus pe seama expedierii.
--    (Regula asta privește tabelele REPLICATE. Pe datele proprii agregatorului
--    — sesiuni, în E3 — invariantul se emulează cu o coloană obișnuită
--    întreținută de un trigger, fiindcă `GENERATED ALWAYS AS` refuză și `IF`,
--    și `CASE`, pe MariaDB: ERROR 1901, măsurat pe gazdă.)
--
-- ============================================================================
-- Tipuri: ce s-a ales și de ce
-- ============================================================================
--
-- `VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin` pentru identificatori.
-- Colația contează, nu e cosmetică: sub o colație insensibilă la majuscule,
-- `Prod` și `prod` sunt ACELAȘI rând. Regula de identificator a expeditorului
-- (`watcher/lib/instances.ts`) acceptă și litere mari, deci două instanțe
-- distincte s-ar putea ciocni într-o cheie unică. Comparație pe octeți.
--
-- Coloanele libere ale sursei (`actor`, `source`, `operation`, `target`,
-- `result`, `detail`) sunt `text` în Postgres, adică nemărginite. Aici devin
-- TEXT/MEDIUMTEXT, NU `VARCHAR(n)`: o margine inventată de replică taie
-- conținutul care intră în `entry_hash`, iar un rând tăiat arată identic cu un
-- rând falsificat atunci când se verifică lanțul. Cu `STRICT_TRANS_TABLES` un
-- `VARCHAR` prea scurt ar da eroare în loc de tăiere — dar atunci rândul e
-- respins, adică tot pierdere. Nimic nu se trunchiază aici.
--
-- `DATETIME(6)`, nu `TIMESTAMP`: `TIMESTAMP` moare în 2038 și se convertește
-- după fusul sesiunii. Ce se stochează e UTC, întotdeauna — conversia din
-- ISO 8601 cu decalaj o face ruta de ingestie (E2.4), iar driverul e
-- configurat cu `dateStrings` tocmai ca nimeni să nu convertească a doua oară.

-- @guard table instances
CREATE TABLE instances (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                       COMMENT 'identitatea instalarii, /etc/sentinel/instance_id',

    -- Cosmetic, niciodată cheie. Vine din `sentinel.yaml` și e ales de om, deci
    -- se schimbă; tot ce se leagă de o instanță se leagă de `instance_id`.
    label              VARCHAR(190) NULL
                       COMMENT 'nume afisat, ales de operator, NICIODATA cheie',

    enabled            TINYINT(1) NOT NULL DEFAULT 1
                       COMMENT '0 = loturile ei se refuza, dar istoria ramane',

    -- Secretul de expediere, CIFRAT ÎN REPAUS (AES-256-GCM, cheie derivată
    -- HKDF-SHA256 dintr-un secret din mediu — `lib/crypto.ts`). Un dump al
    -- bazei nu trebuie să dea chei cu care se pot fabrica loturi pentru orice
    -- instanță. Textul cifrat e legat prin AAD de `instance_id` ȘI de numele
    -- coloanei, deci mutarea unui blob de pe un rând pe altul nu se decriptează.
    ship_secret_enc    VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NULL
                       COMMENT 'AES-256-GCM; NU se scrie niciodata in clar',
    ship_secret_set_at DATETIME(6) NULL,

    first_seen_at      DATETIME(6) NULL
                       COMMENT 'primul lot acceptat; NULL = configurata, inca nimic',
    last_batch_at      DATETIME(6) NULL,
    last_batch_seq     BIGINT UNSIGNED NULL
                       COMMENT 'ultimul batch_seq acceptat; scaderea lui e o reluare',

    -- Tip nativ MariaDB, probat pe gazdă: acceptă și `203.0.113.10`, și
    -- `2001:db8::1`, într-o singură coloană, cu ordonare și comparație corecte.
    -- Perechea VARBINARY(16) + VARCHAR(45) din planul inițial nu mai e nevoie.
    last_source_ip     INET6 NULL
                       COMMENT 'de unde a venit ultimul lot; diagnostic, nu autorizare',

    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                       ON UPDATE CURRENT_TIMESTAMP(6),

    PRIMARY KEY (id),
    UNIQUE KEY uk_instances_instance_id (instance_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='o instalare Sentinel; secretele stau cifrate';

-- @guard table audit_entries
--
-- Replica jurnalului de audit al serverului. E primul flux dinadins: e
-- append-only la sursă, e mic, și duce `prev_hash`/`entry_hash` — adică
-- singura verificare de integritate pe care mașina monitorizată nu și-o poate
-- face singură. Ce se poate verifica de aici: că `prev_hash`-ul fiecărui rând e
-- `entry_hash`-ul celui dinainte, ceea ce prinde inserarea, ștergerea și
-- reordonarea. Ce NU se poate: recalcularea lui `entry_hash` din conținut —
-- serverul îl calculează peste un `json.dumps(..., sort_keys=True)` din Python,
-- adică exact perechea de serializatoare pe care `sentinel/report/signing.py`
-- argumentează că nu se poate face să coincidă între limbaje.
CREATE TABLE audit_entries (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id  VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id    BIGINT NOT NULL
                 COMMENT 'audit_log.id de pe server; unic doar in cadrul instantei',

    at           DATETIME(6) NOT NULL COMMENT 'UTC, convertit la ingestie',

    actor        TEXT NOT NULL,
    source       TEXT NOT NULL,
    operation    TEXT NOT NULL,
    target       TEXT NULL,

    -- `params` intră în `entry_hash`, deci nu are voie să lipsească și nu are
    -- voie să fie re-serializat. Expeditorul îl trimite ca TEXT exact așa cum
    -- l-a scos din `jsonb`; aici se păstrează ca atare. Tipul `JSON` al
    -- MariaDB e `LONGTEXT` + `CHECK (json_valid(...))`: verificarea e utilă,
    -- fiindcă un `params` care nu e JSON valid înseamnă că altceva s-a rupt pe
    -- drum, iar un refuz zgomotos e mai bun decât un rând de audit corupt.
    params       JSON NOT NULL,

    -- Fără CHECK pe valorile lui `result`. Serverul are unul
    -- (`ok|refused|error`); recreat aici, ziua în care serverul adaugă a patra
    -- valoare devine ziua în care replica începe să refuze rânduri. Invariantul
    -- aparține sursei.
    result       TEXT NOT NULL,
    detail       MEDIUMTEXT NULL,

    prev_hash    VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL
                 COMMENT 'entry_hash-ul randului anterior; NULL doar la primul',
    entry_hash   VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Când a ajuns AICI, nu când s-a întâmplat acolo. Diferența dintre cele
    -- două e chiar restanța expeditorului, și trebuie să se poată citi.
    received_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq    BIGINT UNSIGNED NULL COMMENT 'lotul in care a sosit',

    PRIMARY KEY (id),

    -- Identitatea reală. Idempotența ingestiei stă pe ea: același rând
    -- retrimis nimerește aceeași cheie, deci o reluare e o operație nulă.
    UNIQUE KEY uk_audit_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica audit_log; append-only, impus prin triggere';

-- @guard index audit_entries ix_audit_entries_instance_at
--
-- Separat de tabelă, nu inline, fiindcă e singurul index de aici care există
-- pentru VITEZĂ, nu pentru un invariant: panoul din E3 listează pe instanță și
-- pe timp. Dacă vreodată încurcă, se poate arunca fără să se piardă nimic —
-- spre deosebire de `uk_audit_entries_source`, care ESTE idempotența.
CREATE INDEX ix_audit_entries_instance_at ON audit_entries (instance_id, at);

-- @guard trigger audit_entries_no_update
--
-- Echivalentul lui `audit_log_append_only()` din `0002_response.sql:165-173`:
-- cine are drepturi pe baza asta tot nu poate rescrie istoria. `SIGNAL
-- SQLSTATE '45000'` e forma MariaDB a lui `RAISE EXCEPTION`; probat pe gazdă,
-- dă `ERROR 1644 (45000)` iar valoarea rămâne neschimbată.
--
-- Corp de o singură instrucțiune, deci FĂRĂ `BEGIN ... END` și fără
-- `DELIMITER`. Nu e o economie de stil: `DELIMITER` e o directivă de CLIENT, pe
-- care driverul nu o înțelege, iar un fișier care are nevoie de ea nu mai poate
-- fi rulat la fel de runner și de `mysql`.
--
-- CONSECINȚĂ PENTRU E2.4, scrisă aici ca să nu fie descoperită la implementare:
-- cu triggerul ăsta, `INSERT ... ON DUPLICATE KEY UPDATE` pe `audit_entries`
-- EȘUEAZĂ la primul rând deja prezent, fiindcă ramura de UPDATE îl declanșează.
-- Nu e un bug, e invariantul. Idempotența trebuie făcută cu `INSERT IGNORE` —
-- iar `INSERT IGNORE` înghite în tăcere și alte erori, deci ruta e obligată să
-- se uite la EFECT: numărul de rânduri prezente după inserare trebuie să fie
-- egal cu cel trimis, altfel nu se ecouă filigranul. Regula cursorului de la
-- celălalt capăt (`sentinel/report/shipper.py`) depinde de asta.
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
    FOR EACH ROW SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'audit_entries is append-only (UPDATE refused)';

-- @guard trigger audit_entries_no_delete
CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
    FOR EACH ROW SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'audit_entries is append-only (DELETE refused)';

-- @guard table sync_cursors
--
-- Cât a primit agregatorul, per instanță și per flux. NU e cursorul
-- expeditorului: acela stă în `collector_cursors` pe server, sub `ship:<flux>`,
-- și el decide ce se trimite. Ăsta spune ce a AJUNS. Cele două pot să nu fie de
-- acord, și tocmai dezacordul e informația — un cursor local mult în urma celui
-- de pe server înseamnă loturi care pleacă și nu intră.
CREATE TABLE sync_cursors (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id    VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    stream         VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                   COMMENT 'audit_log, si restul fluxurilor din E3',

    last_source_id BIGINT NOT NULL DEFAULT 0
                   COMMENT 'cel mai mare source_id acceptat; filigranul ecouat',
    rows_ingested  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_batch_seq BIGINT UNSIGNED NULL,

    first_seen_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                   ON UPDATE CURRENT_TIMESTAMP(6),

    PRIMARY KEY (id),
    UNIQUE KEY uk_sync_cursors_stream (instance_id, stream)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='ce a ajuns, per instanta si flux; nu ce s-a trimis';
