-- Replica stării operaționale: ce a văzut auto-verificarea, cât a fost sus, ce
-- a căzut, și contorul orar de evenimente.
--
-- PARTEA ÎNTÂI din E3a-2. Ce e aici: `selfcheck_state`, `selfcheck_runs`,
-- `availability_rollup`, `outages`, `event_rollup_1h`. Ce rămâne pentru partea a
-- doua: `findings`, `scans`, `patch_plans`, `patch_executions`, `patch_steps`,
-- `patch_plan_findings`. Motivul împărțirii e în raportul rundei; ca și
-- `0003_entities.sql`, fișierul ăsta e complet pentru ce conține.
--
-- Se citește peste `0001_core.sql` și `0003_entities.sql`, care țin regulile
-- generale. Ele se aplică ÎNTOCMAI și aici, deci nu se repetă: identitatea reală
-- e `(instance_id, <cheia sursei>)` și e singura unicitate, fără chei străine,
-- fără recrearea indexurilor unice parțiale ale serverului, `DATETIME(6)` și nu
-- tipul care se termină în 2038, coloanele libere rămân nemărginite,
-- identificatorii se compară pe octeți, fiecare instrucțiune are `@guard`.
--
-- Fișier NOU, nu o editare a celor dinainte. Atenție la ce înseamnă asta: din
-- fișierele de aici e APLICAT pe baza reală doar `0001_core.sql`, iar
-- `lib/migrate.ts` consemnează instrucțiuni cu suma lor de control — o editare a
-- unei instrucțiuni APLICATE oprește toate migrațiile. Ce n-a fost încă aplicat
-- se poate corecta pe loc, iar cine vrea să știe care e care citește
-- `schema_version` din baza de date, nu comentariul ăsta.
--
-- ============================================================================
-- Felul cursorului fiecărei tabele — CITIT DIN CODUL SERVERULUI
-- ============================================================================
--
-- Numele nu spune nimic: `selfcheck_runs` ar putea la fel de bine să fie
-- actualizată la sfârșitul rulării. Deci fiecare a fost citită de unde se scrie:
--
--   * `selfcheck_state` — MUTABIL. `sentinel/selfcheck/runner.py` scrie
--     `INSERT ... ON CONFLICT (key) DO UPDATE`, iar `since`, `last_seen`,
--     `stale` și `status` se schimbă în loc, pe aceeași cheie.
--   * `selfcheck_runs` — APPEND-ONLY. Același fișier scrie UN singur `INSERT`,
--     după ce rularea s-a terminat, cu cifrele finale. Nicio actualizare nicăieri.
--   * `availability_rollup` — ROLLUP. `sentinel/health/sla.py` reface ziua cu
--     `ON CONFLICT (asset_id, day) DO UPDATE`, deci bucketul curent se rescrie
--     cât timp ziua e în curs.
--   * `event_rollup_1h` — ROLLUP. `sentinel_rollup_events_1h` reagregă din
--     `event_rollup_1m` cu `ON CONFLICT (bucket, asset_id, source, action)`.
--   * `outages` — MUTABIL. `sentinel/db/repo/health.py` deschide rândul cu
--     `INSERT`, iar la revenire îi completează `ended_at` și `duration_s`.
--
-- Cine înregistrează fluxurile (partea a treia) ia felul cursorului de aici, nu
-- din nume: `INSERT IGNORE` pe o tabelă mutabilă păstrează tăcut versiunea veche.
--
-- ============================================================================
-- Cartografierea, și ce e specific fișierului ăstuia
-- ============================================================================
--
-- **Percentilele sosesc CALCULATE și nu se recalculează.** Pe server sunt
-- coloane, umplute cu `percentile_disc(...) WITHIN GROUP (...)` peste eșantioane
-- pe care replica nu le primește niciodată — `health_samples` nu pleacă de
-- acolo. Deci `p50/p95/p99/max` se copiază ca atare. MariaDB n-are
-- `percentile_cont`, dar chiar dacă ar avea, un al doilea calculator ar da
-- răspunsuri care se abat de la panoul serverului fără ca cineva să afle care e
-- corect. La fel `uptime_pct`: e o rotunjire a sursei, nu o socoteală de aici.
--
-- **Marginile inventate pentru coloanele de cheie.** `0003_entities.sql` scria
-- că `tag` e „singurul loc din replică unde o margine e inventată". Fișierul
-- ăsta mai adaugă trei — `check_key`, `source`, `action` —, toate din același
-- motiv și niciuna pe conținut: sunt coloane de identitate, iar o coloană de
-- identitate trebuie să încapă într-un index. `VARCHAR(190)` × 4 octeți intră în
-- limita de 3072 a InnoDB alături de restul cheii. Ingestia REFUZĂ ce nu încape,
-- nu taie — un rând tăiat ar fi o identitate schimbată tăcut.
--
-- **`utf8mb4_bin` pe coloanele de cheie.** Colația implicită a tabelei e
-- insensibilă la majuscule, deci sub ea `check_key = 'Disk'` și `'disk'` ar fi
-- același rând, iar două verificări diferite s-ar suprascrie una pe alta.
-- Aceeași grijă ca `ascii_bin` la `instance_id` și `actor_key`, cu `utf8mb4` în
-- loc de `ascii` fiindcă aici nu se știe dinainte că valoarea e ascii, iar o
-- conversie de set de caractere schimbă octeții TĂCUT.
--
-- **`key` devine `check_key`.** `KEY` e cuvânt rezervat în MariaDB. Ar merge cu
-- ghilimele inverse peste tot, dar atunci fiecare interogare a panoului și
-- fiecare instrucțiune generată ar trebui să-și amintească asta; o coloană
-- redenumită o dată e mai ieftină decât o clasă de erori de sintaxă.
--
-- ============================================================================
-- Ce NU poate spune replica asta
-- ============================================================================
--
-- Pe server, `_reconcile_state` ȘTERGE din `selfcheck_state` cheile pe care o
-- rulare completă nu le-a produs: verificarea și-a retras rezultatul, deci
-- rândul rămâne fără autor. Aici ștergerea aia nu se vede — fluxurile expediază
-- rânduri, nu pietre funerare. Consecința, scrisă acum ca să nu fie descoperită
-- din panou: o verificare retrasă își păstrează ULTIMUL rând în replică, cu
-- `last_seen` înghețat la momentul în care a fost văzută ultima oară.
--
-- `last_seen` e deci singurul lucru care deosebește „încă se verifică" de „nu
-- mai există", iar panoul trebuie să-l citească. Nu se rezolvă cu un `DELETE`
-- ghicit de aici: ar însemna ca replica să decidă singură că un rând nu mai e
-- adevărat, adică exact ce nu are voie să facă. Rezolvarea reală e un flux de
-- reconciliere, și e o decizie a operatorului, nu a fișierului ăstuia.

-- ============================================================================
-- Auto-verificarea
-- ============================================================================
-- @guard table selfcheck_state_entries
--
-- Cheia sursei e `key`, un text — aceeași formă ca `actor_entries`, altă cheie.
-- Tabela e mică prin construcție (o zi de verificări are câteva zeci de chei pe
-- instanță), deci n-are niciun index în plus: pe atâtea rânduri, o parcurgere
-- după cheia unică e ieftină, iar un index pe `status` ar cere o margine
-- inventată pe o coloană care nu e de identitate.
CREATE TABLE selfcheck_state_entries (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id   VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    check_key     VARCHAR(190) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL
                  COMMENT 'selfcheck_state.key de pe server; KEY e rezervat aici',

    status        TEXT NOT NULL COMMENT 'ok|degraded|down|unknown, fara CHECK',
    title         TEXT NOT NULL,
    detail        TEXT NOT NULL,
    facts         JSON NOT NULL,

    since         DATETIME(6) NOT NULL
                  COMMENT 'de cand e in starea CURENTA; se misca doar cu status',
    last_seen     DATETIME(6) NOT NULL,
    last_alert_at DATETIME(6) NULL,
    stale         TINYINT(1) NOT NULL
                  COMMENT '1 = ultima rulare a fost incompleta, cifra e ultima stiuta',

    received_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq     BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_selfcheck_state_entries (instance_id, check_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='ultimul rezultat per verificare; randurile se compara, nu se acumuleaza';

-- @guard table selfcheck_run_entries
--
-- Rulările, ca să se poată răspunde „când a terminat ultima oară auto-verificarea"
-- — inclusiv de către cea de după o cădere. Un rând per rulare, scris o singură
-- dată, la sfârșit, cu cifrele finale.
CREATE TABLE selfcheck_run_entries (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id  VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id    BIGINT NOT NULL COMMENT 'selfcheck_runs.id de pe server',

    started_at   DATETIME(6) NOT NULL,
    duration_ms  INT NULL,
    worst_status TEXT NOT NULL,
    checks_run   INT NOT NULL,
    checks_bad   INT NOT NULL,

    received_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq    BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_selfcheck_run_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='cate o rulare de auto-verificare; scrisa o data, la sfarsit';

-- @guard index selfcheck_run_entries ix_selfcheck_run_entries_recent
--
-- „A mai rulat auto-verificarea pe instanța asta în ultima oră?" e prima
-- întrebare a panoului, și singura care contează când tace o instanță.
CREATE INDEX ix_selfcheck_run_entries_recent
    ON selfcheck_run_entries (instance_id, started_at);

-- ============================================================================
-- Disponibilitatea
-- ============================================================================
-- @guard table availability_rollup_entries
--
-- Cheia sursei e `(asset_id, day)`, fără `id` — deci identitatea replicată e
-- `(instance_id, asset_source_id, day)`. Bucketul zilei în curs se retrimite la
-- fiecare rundă, cu cifre mai mari; forma de scriere a fluxului e upsert, altfel
-- ziua ar rămâne înghețată la prima ei oră.
CREATE TABLE availability_rollup_entries (
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id      VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    asset_source_id  BIGINT NOT NULL COMMENT 'assets.id de pe server; fara cheie straina',
    day              DATE NOT NULL,

    samples          INT NOT NULL,
    up_samples       INT NOT NULL,
    degraded_samples INT NOT NULL,
    down_samples     INT NOT NULL,

    -- Calculate pe server, copiate ca atare. Vezi capul fișierului: eșantioanele
    -- din care ies nu ajung niciodată aici, deci un al doilea calcul n-ar avea
    -- din ce să iasă.
    uptime_pct       DECIMAL(6,3) NULL
                     COMMENT 'degradat conteaza ca sus; rotunjirea e a serverului',
    p50_latency_ms   INT NULL,
    p95_latency_ms   INT NULL,
    p99_latency_ms   INT NULL,
    max_latency_ms   INT NULL,

    incidents_count  INT NOT NULL,
    longest_outage_s INT NOT NULL,

    received_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq        BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_availability_rollup_entries (instance_id, asset_source_id, day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='o zi per activ; percentilele sosesc calculate de pe server';

-- @guard index availability_rollup_entries ix_availability_rollup_entries_day
CREATE INDEX ix_availability_rollup_entries_day
    ON availability_rollup_entries (instance_id, day);

-- @guard table outage_entries
--
-- Căderile ca RÂNDURI, nu ca goluri deduse dintre eșantioane. Rândul se deschide
-- când cade și se completează când revine, deci fluxul e mutabil: cu prima
-- versiune păstrată, fiecare cădere ar rămâne pentru totdeauna „în curs" în
-- panou.
--
-- Serverul are un index parțial pe căderile deschise. Nu e unic, deci nu intră
-- sub regula indexurilor care nu se recreează — și nu se recreează oricum,
-- fiindcă MariaDB n-are indexuri parțiale; interogarea merge pe indexul de mai
-- jos plus o condiție.
CREATE TABLE outage_entries (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id          BIGINT NOT NULL COMMENT 'outages.id de pe server',
    asset_source_id    BIGINT NOT NULL COMMENT 'assets.id de pe server; fara cheie straina',

    started_at         DATETIME(6) NOT NULL,
    ended_at           DATETIME(6) NULL COMMENT 'NULL = inca in curs la ultima expediere',
    duration_s         INT NULL,

    kind               TEXT NOT NULL COMMENT 'down|degraded, fara CHECK',
    cause              TEXT NULL,
    incident_source_id BIGINT NULL COMMENT 'incidents.id de pe server; fara cheie straina',
    planned            TINYINT(1) NOT NULL
                       COMMENT '1 = fereastra de mentenanta, nu strica disponibilitatea',

    received_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq          BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_outage_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='caderi ca randuri; se completeaza la revenire, deci flux mutabil';

-- @guard index outage_entries ix_outage_entries_asset
CREATE INDEX ix_outage_entries_asset
    ON outage_entries (instance_id, asset_source_id, started_at);

-- ============================================================================
-- Contorul orar de evenimente
-- ============================================================================
-- @guard table event_rollup_1h_entries
--
-- Cheia sursei e `(bucket, asset_id, source, action)`, toate patru. `source` și
-- `action` sunt `text` nemărginit acolo și devin `VARCHAR(190)` aici din motivul
-- scris în cap: intră în cheie. Sunt etichete de colector — `nginx`, `sshd`,
-- `login_failed` —, nu conținut, iar un `source` mai lung de 190 de caractere ar
-- fi refuzat la ingestie, nu tăiat.
--
-- Ce NU se face aici: reagregarea. Ora vine gata însumată de pe server, iar
-- `uniq_src` e un maxim peste minute, nu o sumă — o subestimare cunoscută, aleasă
-- acolo. Recalculată aici din altceva, ar deveni un al doilea răspuns la aceeași
-- întrebare.
CREATE TABLE event_rollup_1h_entries (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id     VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    bucket          DATETIME(6) NOT NULL COMMENT 'inceputul orei, UTC',
    asset_source_id BIGINT NOT NULL COMMENT 'assets.id de pe server; fara cheie straina',
    source          VARCHAR(190) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    action          VARCHAR(190) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,

    n               BIGINT NOT NULL,
    uniq_src        INT NOT NULL COMMENT 'maxim peste minute, nu suma; asa vine',
    bytes_in        BIGINT NOT NULL,
    bytes_out       BIGINT NOT NULL,
    p95_latency_ms  INT NULL COMMENT 'calculat pe server',

    received_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq       BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_event_rollup_1h_entries (instance_id, bucket, asset_source_id, source, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='contor orar, agregat pe server; replica nu reagrega nimic';

-- @guard index event_rollup_1h_entries ix_event_rollup_1h_entries_bucket
--
-- Panoul citește pe interval de timp, peste toate activele unei instanțe; cheia
-- unică începe cu `bucket` doar după `instance_id`, deci pentru „ultimele 24 de
-- ore, tot ce s-a întâmplat" e nevoie de ordinea asta.
CREATE INDEX ix_event_rollup_1h_entries_bucket
    ON event_rollup_1h_entries (instance_id, bucket, source);
