-- Replica vulnerabilităților și a plasturilor: ce s-a găsit, ce s-a plănuit, ce
-- s-a executat, pas cu pas.
--
-- PARTEA A DOUA din E3a-2, și ultima bucată de schemă: `findings`, `scans`,
-- `patch_plans`, `patch_executions`, `patch_steps`, plus `patch_plan_findings`.
-- Cu `0004_health.sql` înainte, replica acoperă tot ce s-a cerut.
--
-- Se citește peste `0001_core.sql`, `0003_entities.sql` și `0004_health.sql`,
-- care țin regulile generale. Ele se aplică ÎNTOCMAI și aici, deci nu se repetă:
-- identitatea replicată e `(instance_id, <cheia sursei>)` și e singura unicitate,
-- fără chei străine, fără recrearea indexurilor unice ale serverului,
-- `DATETIME(6)` și nu tipul care se termină în 2038, identificatorii se compară
-- pe octeți, fiecare instrucțiune are `@guard`.
--
-- Fișier NOU, nu o editare a celor dinainte. Atenție la ce înseamnă asta: din
-- fișierele de aici e APLICAT pe baza reală doar `0001_core.sql`, iar
-- `lib/migrate.ts` consemnează instrucțiuni cu suma lor de control — o editare a
-- unei instrucțiuni APLICATE oprește toate migrațiile. Ce n-a fost încă aplicat
-- se poate corecta pe loc, iar cine vrea să știe care e care citește
-- `schema_version` din baza de date, nu comentariul ăsta.
--
-- ============================================================================
-- Felul cursorului fiecărei tabele — CITIT DIN CĂILE DE SCRIERE
-- ============================================================================
--
-- Toate cinci sunt MUTABILE. Două dintre ele arată append-only și nu sunt, iar
-- diferența nu se vede din nume, ci din codul care le scrie:
--
--   * `findings` — `sentinel/db/repo/findings.py`, `upsert_finding`:
--     `ON CONFLICT (finding_key) DO UPDATE`, care mută `last_seen`, `severity`,
--     `priority`, `raw`, și REDESCHIDE un rând rezolvat. Plus
--     `mark_resolved_absent`, care trece pe `resolved` ce n-a mai apărut.
--   * `scans` — același fișier: `INSERT` cu status `running`, apoi `UPDATE` cu
--     cifrele finale la sfârșitul scanării.
--   * `patch_plans` — `sentinel/db/repo/patches.py`: `status` trece prin
--     `validated`, `approved`, `applied`, `expired`, fiecare un `UPDATE`.
--   * `patch_executions` — PARE append-only, NU e. `finish_execution` face
--     `UPDATE ... SET status, finished_at, duration_ms`, iar `restore_point_id`
--     și `notified_at` se scriu tot după inserare.
--   * `patch_steps` — la fel. `start_step` inserează rândul ÎNAINTE de a rula
--     comanda (ca o cădere la jumătate să lase urma), iar `end_step` îi
--     completează `status`, `exit_code`, `stdout`, `stderr`, `duration_ms`.
--     Rândul scris primul e cel INCOMPLET; păstrat ca definitiv, panoul ar arăta
--     pentru totdeauna un pas „în curs" care s-a terminat acum o lună.
--
-- Cine înregistrează fluxurile ia felul cursorului de aici. `INSERT IGNORE` pe
-- oricare dintre ele păstrează tăcut prima versiune, adică exact versiunea
-- incompletă.
--
-- ============================================================================
-- Identitatea, și unicitățile care NU se recreează
-- ============================================================================
--
-- `findings` are DOUĂ identități pe server: `id` (cheia primară) și
-- `finding_key` (sha256 peste scanner|activ|pachet|CVE|locație, unic). Replica
-- folosește `(instance_id, source_id)`, ca toate celelalte tabele, fiindcă cele
-- două sunt unu-la-unu și stabile: cheia nu se schimbă niciodată la actualizare,
-- iar `id`-ul e ce poate trimite expeditorul ca filigran.
--
-- Unicitatea lui `finding_key` NU se recreează aici — e un invariant al sursei,
-- iar dacă vreodată ar sosi două rânduri cu aceeași cheie (o migrație a
-- serverului, o reconstrucție), replica trebuie să le PĂSTREZE pe amândouă și să
-- arate divergența, nu să refuze al doilea rând și să oprească fluxul. Indexul de
-- mai jos e obișnuit, nu unic, și e acolo doar pentru căutare.
--
-- Din același motiv nu se recreează nici a doua unicitate a lui `patch_steps`,
-- `(execution_id, seq)`: ordinea pașilor e o proprietate pe care o impune cine
-- execută, iar replica doar o stochează.
--
-- ============================================================================
-- Ce NU intră, și de ce
-- ============================================================================
--
-- **`scans.raw_output_path`** — o cale către un fișier de pe gazda monitorizată.
-- Aici n-are ce citi nimeni de la capătul ăla, deci coloana n-ar aduce decât
-- forma directoarelor serverului. Absentă, nu goală.
--
-- **`patch_plans.finding_ids`** — tabloul se desfășoară în `patch_plan_findings`,
-- ca `tags` în `0003_entities.sql`. Un tablou într-o coloană face din „ce planuri
-- ating descoperirea X" o parcurgere completă.
--
-- **`updated_at`** — pe server abia se adaugă (migrația `0023`, cursorul
-- `(updated_at, id)`), și NU e livrată. O coloană a replicii modelată după una
-- nelivrată ar fi o ghicire cu formă de fapt; se adaugă odată cu înregistrarea
-- fluxului, când cele două capete se pot compara. Până atunci, un flux care ar
-- trimite câmpul primește un refuz zgomotos de la `prepareRows` — „câmp
-- necunoscut" —, nu o scriere tăcută pe lângă.
--
-- **Ce rămâne, deși atinge granița: `location`, `target`, `cwd`.** Sunt căi,
-- URL-uri sau nume de imagine — aceeași familie cu ce refuză `0003_entities.sql`
-- pentru inventar. Rămân fiindcă fără ele rândul nu mai e acționabil: o
-- descoperire fără locație nu se poate nici confirma, nici repara, iar
-- `finding_key` e calculat CU locația, deci două descoperiri diferite ar arăta
-- identic în panou. Argumentul de graniță nu dispare, se mută: ce poartă
-- recunoașterea scumpă e faptul că replica are descoperirile deloc — „gazda X
-- are CVE-ul Y nepatchuit, expus în internet" —, iar decizia aia a fost luată
-- când s-a cerut replicarea lor. Locația adaugă puțin peste asta.
--
-- E totuși o decizie de operator, nu de fișier, și direcția ieftină e într-un
-- singur sens: o coloană neexpediată se poate adăuga mai târziu cu o migrație, în
-- timp ce date deja ajunse aici nu se pot neexpedia. Scrisă aici ca să poată fi
-- răsturnată în cunoștință de cauză, nu descoperită din panou.
--
-- ============================================================================
-- Comenzile: se ARATĂ, nu se execută
-- ============================================================================
--
-- `patch_steps.argv` și `patch_plans.plan` poartă singurul lucru din tot
-- agregatorul care arată a comandă. Sunt DATE de afișat, iar comentariul stă pe
-- coloană, nu doar aici: cine deschide vreodată schema trebuie să vadă la
-- coloană că agregatorul nu execută asta niciodată. N-are executor, n-are gazdă
-- de atins și n-are voie să capete unul — un panou care poate rula ce i-a fost
-- expediat ar transforma o replică de citire într-o cale de control către toate
-- mașinile monitorizate.

-- ============================================================================
-- Scanările și descoperirile
-- ============================================================================
-- @guard table scan_entries
CREATE TABLE scan_entries (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id       VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id         BIGINT NOT NULL COMMENT 'scans.id de pe server',

    scanner           TEXT NOT NULL
                      COMMENT 'dnf|trivy_fs|trivy_image|nuclei|semgrep|lynis|web_checks|tls',
    target            TEXT NOT NULL COMMENT 'ce s-a scanat; vezi nota de granita din cap',
    asset_source_id   BIGINT NULL COMMENT 'assets.id de pe server; fara cheie straina',

    status            TEXT NOT NULL COMMENT 'running|completed|failed|timeout|skipped',
    started_at        DATETIME(6) NOT NULL,
    finished_at       DATETIME(6) NULL,
    duration_ms       INT NULL,
    exit_code         INT NULL,

    findings_count    INT NOT NULL,
    new_findings      INT NOT NULL,
    resolved_findings INT NOT NULL,

    -- Un raport curat de la un scaner cu baza de trei săptămâni e o imagine
    -- parțială, iar operatorul trebuie să știe asta.
    db_version        TEXT NULL,
    error             TEXT NULL,
    triggered_by      TEXT NOT NULL,

    received_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq         BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_scan_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='rulari de scanare; se completeaza la final, deci flux mutabil';

-- @guard index scan_entries ix_scan_entries_recent
CREATE INDEX ix_scan_entries_recent
    ON scan_entries (instance_id, started_at);

-- @guard table finding_entries
--
-- Valoarea tabelei nu e scanarea, e `finding_key` și `priority`: prima face
-- dintr-o descoperire un LUCRU CU ISTORIE în loc de un rând nou în fiecare
-- noapte, a doua e ordinea în care se uită operatorul.
CREATE TABLE finding_entries (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id          BIGINT NOT NULL COMMENT 'findings.id de pe server',

    -- sha256 hexa, 64 de caractere, exact ca `entry_hash` din `0001_core.sql`.
    -- Unicitatea lui de pe server NU se recreează aici — vezi capul fișierului.
    finding_key        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                       COMMENT 'sha256(scanner|activ|pachet|cve|locatie), calculat pe server',

    asset_source_id    BIGINT NULL COMMENT 'assets.id de pe server; fara cheie straina',
    scanner            TEXT NOT NULL,

    cve                TEXT NULL,
    advisory_id        TEXT NULL COMMENT 'ALSA-2026:1234, autoritar pe AlmaLinux',
    title              TEXT NULL,
    description        TEXT NULL,

    severity           TEXT NOT NULL COMMENT 'info|low|medium|high|critical, fara CHECK',
    cvss               DECIMAL(3,1) NULL,
    cvss_vector        TEXT NULL,

    -- Sosesc calculate: probabilitatea de exploatare la 30 de zile (FIRST EPSS)
    -- și lista CISA a celor exploatate ACUM. Replica nu le recalculează — n-are
    -- fluxurile de intel, și n-are nevoie de ele ca să afișeze.
    epss               DECIMAL(5,4) NULL,
    kev                TINYINT(1) NOT NULL,
    kev_due_date       DATE NULL,

    package            TEXT NULL,
    installed_version  TEXT NULL,
    fixed_version      TEXT NULL,
    location           TEXT NULL COMMENT 'cale, imagine sau URL; vezi nota de granita din cap',
    ecosystem          TEXT NULL COMMENT 'rpm|npm|pypi|composer|go|container',

    priority           SMALLINT NOT NULL COMMENT '0-100, calculat pe server',
    status             TEXT NOT NULL
                       COMMENT 'open|patch_planned|patching|resolved|accepted_risk|deferred|false_positive',

    first_seen         DATETIME(6) NOT NULL,
    last_seen          DATETIME(6) NOT NULL,
    resolved_at        DATETIME(6) NULL,
    resolution         TEXT NULL COMMENT 'poate spune ca plasturele s-a aplicat si NU a rezolvat',

    deferred_until     DATETIME(6) NULL,
    accepted_by        TEXT NULL,
    accepted_reason    TEXT NULL,

    requires_manual_intervention TINYINT(1) NOT NULL
                       COMMENT '1 = activ protejat; niciun plan automat nu se genereaza',

    scan_source_id     BIGINT NULL COMMENT 'scans.id de pe server; fara cheie straina',
    raw                JSON NOT NULL COMMENT 'iesirea scanerului, ca blob; nu se despacheteaza aici',

    ai_assessment      JSON NULL,
    ai_assessed_at     DATETIME(6) NULL,

    received_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq          BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_finding_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='descoperiri deduplicate; se redeschid si se rezolva, deci flux mutabil';

-- @guard index finding_entries ix_finding_entries_open
--
-- Ordinea în care se uită operatorul: ce e deschis, cel mai grav întâi. Filtrul
-- pe stare nu poate intra în index (MariaDB n-are indexuri parțiale), deci
-- intră `status` ca primă coloană după instanță.
CREATE INDEX ix_finding_entries_open
    ON finding_entries (instance_id, status(64), priority);

-- @guard index finding_entries ix_finding_entries_key
--
-- OBIȘNUIT, nu unic: aceeași cheie sosită de două ori e o divergență de arătat,
-- nu un rând de refuzat.
CREATE INDEX ix_finding_entries_key
    ON finding_entries (instance_id, finding_key);

-- ============================================================================
-- Planurile de plasture
-- ============================================================================
-- @guard table patch_plan_entries
--
-- `plan_hash` leagă o aprobare de un plan EXACT: regenerarea planului schimbă
-- hash-ul și omoară fiecare buton rămas în Telegram. Aici e doar stocat — ce
-- apără proprietatea aia e serverul.
CREATE TABLE patch_plan_entries (
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id          VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id            BIGINT NOT NULL COMMENT 'patch_plans.id de pe server',

    plan_uuid            VARCHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                         COMMENT 'patch_plans.plan_id, uuid ca text',
    plan_hash            VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                         COMMENT 'sha256 peste continutul semantic al planului',

    -- Planul întreg, ca blob. CONȚINE COMENZI, iar agregatorul nu execută asta
    -- niciodata: n-are executor si nu capata unul.
    plan                 JSON NOT NULL
                         COMMENT 'doar pentru afisare; agregatorul nu executa asta niciodata',

    asset_source_id      BIGINT NULL COMMENT 'assets.id de pe server; fara cheie straina',

    status               TEXT NOT NULL
                         COMMENT 'draft|validated|rejected_invalid|approved|scheduled|applying|applied|rolled_back|failed|rejected|expired',
    risk_level           TEXT NULL COMMENT 'low|medium|high|critical, fara CHECK',
    blast_radius         TEXT NULL,
    requires_reboot      TINYINT(1) NOT NULL,
    reversible           TINYINT(1) NOT NULL,
    estimated_downtime_s INT NULL,
    estimated_backup_mb  INT NULL,
    confidence           DECIMAL(3,2) NULL,

    -- Se umple când validatorul determinist respinge planul. „IA n-a putut
    -- produce o procedură sigură" e un rezultat acceptabil, și mult mai bun
    -- decât un plan plauzibil care strică producția.
    validation_errors    JSON NULL,
    validation_attempts  SMALLINT NOT NULL,

    generated_by         TEXT NULL,
    model                TEXT NULL,
    prompt_version       TEXT NULL,
    generation_ms        INT NULL,

    created_at           DATETIME(6) NOT NULL,
    approved_by          TEXT NULL,
    approved_at          DATETIME(6) NULL,
    scheduled_for        DATETIME(6) NULL,
    rejected_by          TEXT NULL,
    rejected_reason      TEXT NULL,
    notified_at          DATETIME(6) NULL,

    received_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq            BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_patch_plan_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='planuri de plasture; starea lor se schimba, deci flux mutabil';

-- @guard index patch_plan_entries ix_patch_plan_entries_status
CREATE INDEX ix_patch_plan_entries_status
    ON patch_plan_entries (instance_id, status(64), created_at);

-- @guard table patch_plan_findings
--
-- Desfășurarea lui `patch_plans.finding_ids` — „ce descoperiri repară planul
-- ăsta", răspuns fără o parcurgere completă.
--
-- APARTENENȚA E DECISĂ (#62, august 2026): sub-rânduri ale planului, sosite
-- odată cu el. De-aia tabela n-are `received_at` și `batch_seq` — nu-i lipsesc,
-- n-are ce contabiliza: nu are sosire proprie. Pe server datele nici nu există
-- separat, sunt un tablou pe rândul părinte (`patch_plans.finding_ids`).
--
-- Ce s-a schimbat în cod ca decizia să poată fi luată: `prepareRows` și
-- numărătoarea de efect nu mai presupun „un rând = o identitate", `writeSql`
-- emite coloanele de contabilitate doar pentru rândurile care le au, iar
-- mulțimea de sub-rânduri a unui părinte se ÎNLOCUIEȘTE, nu se contopește. Vezi
-- `aggregator/lib/streams.ts` (`ChildStream`, registrul tabelelor de legătură)
-- și `aggregator/lib/ingest.ts`.
--
-- Aceeași decizie acoperă cele patru tabele de legătură din `0003_entities.sql`.
-- Ce NU s-a făcut încă: niciun flux cu sub-rânduri nu e ÎNREGISTRAT la vreun
-- capăt, deci nimeni nu scrie încă tabela asta.
--
-- Doar comentariul s-a schimbat, nu instrucțiunea: `lib/sql-statements.ts` scoate
-- comentariile înainte de normalizare, deci suma de control a instrucțiunii
-- rămâne cea consemnată.
CREATE TABLE patch_plan_findings (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id       VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    plan_source_id    BIGINT NOT NULL COMMENT 'patch_plans.id de pe server',
    finding_source_id BIGINT NOT NULL COMMENT 'findings.id de pe server',

    PRIMARY KEY (id),
    UNIQUE KEY uk_patch_plan_findings (instance_id, plan_source_id, finding_source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='patch_plans.finding_ids, desfasurat; cine o scrie e nedecis';

-- @guard index patch_plan_findings ix_patch_plan_findings_finding
CREATE INDEX ix_patch_plan_findings_finding
    ON patch_plan_findings (instance_id, finding_source_id);

-- ============================================================================
-- Execuțiile, pas cu pas
-- ============================================================================
-- @guard table patch_execution_entries
CREATE TABLE patch_execution_entries (
    id                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id              VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id                BIGINT NOT NULL COMMENT 'patch_executions.id de pe server',
    plan_source_id           BIGINT NOT NULL COMMENT 'patch_plans.id de pe server; fara cheie straina',

    mode                     TEXT NOT NULL COMMENT 'dry_run|apply, fara CHECK',
    status                   TEXT NOT NULL
                             COMMENT 'running|succeeded|failed|rolled_back|rollback_failed|aborted',

    started_at               DATETIME(6) NOT NULL,
    finished_at              DATETIME(6) NULL,
    duration_ms              INT NULL,

    -- `restore_points` NU se replică (granița de date din `0003_entities.sql`),
    -- deci numărul ăsta nu are ce indica aici. Rămâne fiindcă „a existat un
    -- punct de restaurare" e chiar întrebarea care se pune după un plasture
    -- eșuat, iar căutarea lui se face pe server.
    restore_point_source_id  BIGINT NULL COMMENT 'restore_points.id de pe server; tabela nu se replica',
    triggered_by             TEXT NOT NULL,

    rollback_reason          TEXT NULL COMMENT 'ce verificare a picat, sau ce pas a iesit nenul',
    rollback_at              DATETIME(6) NULL,

    -- Post-verificarea reia chiar proba scanerului. Dacă tot se aprinde după o
    -- aplicare reușită, asta se consemnează, nu se trece cu vederea.
    post_verification_passed TINYINT(1) NULL,
    result                   JSON NULL,
    error                    TEXT NULL,
    notified_at              DATETIME(6) NULL,

    received_at              DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq                BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_patch_execution_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='executii; se completeaza la final, deci flux mutabil';

-- @guard index patch_execution_entries ix_patch_execution_entries_plan
CREATE INDEX ix_patch_execution_entries_plan
    ON patch_execution_entries (instance_id, plan_source_id, started_at);

-- @guard table patch_step_entries
--
-- Urma criminalistică: rândul se scrie ÎNAINTE de a rula comanda, deci o cădere
-- la jumătate — OOM, pană de curent — lasă exact cât s-a apucat să facă.
--
-- A doua unicitate a serverului, `(execution_id, seq)`, NU se recreează aici;
-- motivul e în capul fișierului.
CREATE TABLE patch_step_entries (
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id          VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id            BIGINT NOT NULL COMMENT 'patch_steps.id de pe server',
    execution_source_id  BIGINT NOT NULL
                         COMMENT 'patch_executions.id de pe server; fara cheie straina',

    phase                TEXT NOT NULL
                         COMMENT 'preflight|backup|apply|health_check|rollback|post_verification',
    step_id              TEXT NOT NULL COMMENT 'id-ul pasului din plan',
    seq                  INT NOT NULL,

    -- Tabloul de argumente al comenzii care S-A rulat pe gazda monitorizată.
    -- Se pastreaza ca sa poata fi CITIT: cine se uita la un plasture esuat
    -- trebuie sa vada exact ce s-a executat, cuvant cu cuvant.
    argv                 JSON NOT NULL
                         COMMENT 'doar pentru afisare; agregatorul nu executa asta niciodata',
    cwd                  TEXT NULL COMMENT 'directorul comenzii; vezi nota de granita din cap',
    run_as               TEXT NULL,

    started_at           DATETIME(6) NOT NULL,
    finished_at          DATETIME(6) NULL,
    duration_ms          INT NULL,
    exit_code            INT NULL,
    timed_out            TINYINT(1) NOT NULL,

    -- Trunchiate și trecute prin redactorul de credențiale PE SERVER, înainte de
    -- stocare acolo. Replica nu redactează nimic: n-are cum să știe ce e un
    -- secret în textul altcuiva, iar o a doua redactare care ratează ar fi mai
    -- rea decât niciuna, fiindcă ar părea că s-a făcut.
    stdout               MEDIUMTEXT NULL,
    stderr               MEDIUMTEXT NULL,

    status               TEXT NOT NULL COMMENT 'running|ok|failed|skipped, fara CHECK',

    received_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq            BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_patch_step_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='pasi de executie; rowul se completeaza la final, deci flux mutabil';

-- @guard index patch_step_entries ix_patch_step_entries_execution
--
-- Ordinea în care se citește o execuție: pașii ei, în ordinea lor.
CREATE INDEX ix_patch_step_entries_execution
    ON patch_step_entries (instance_id, execution_source_id, seq);
