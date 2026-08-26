-- Replica entităților de securitate: cine a atacat, ce s-a detectat, ce s-a blocat.
--
-- PARTEA ÎNTÂI din E3a. Ce e aici: `assets` (subset), `actors` + cele două
-- tabele de atribute, `detections` + `detection_events`, `incidents`,
-- `incident_timeline`, `blocklist`. Ce rămâne pentru partea a doua:
-- `findings`, `scans`, `patch_*`, `selfcheck_*`, `availability_rollup`,
-- `outages`, `event_rollup_1h`. Motivul împărțirii e în raportul rundei;
-- fișierul ăsta e complet pentru ce conține, nu o jumătate de fișier.
--
-- Se citește peste `0001_core.sql`, care ține regulile generale. Ele se aplică
-- ÎNTOCMAI și aici, deci nu se repetă: identitatea reală e `(instance_id,
-- <cheia sursei>)`, fără chei străine, fără recrearea indexurilor unice parțiale
-- ale serverului, `DATETIME(6)` și nu `TIMESTAMP`, coloanele libere rămân
-- nemărginite, identificatorii se compară pe octeți.
--
-- Fișier NOU, nu o editare a lui `0001_core.sql`: acela e aplicat pe baza reală,
-- iar `lib/migrate.ts` consemnează instrucțiuni cu suma lor de control — o
-- editare a uneia aplicate oprește toate migrațiile.
--
-- CE E APLICAT, la zi: doar cele șase instrucțiuni ale lui `0001_core.sql`
-- (singura rulare de până acum a raportat `applied=6`, iar fișierul are exact
-- șase). `0002_chain.sql` și tot ce vine după au fost scrise ULTERIOR și n-au
-- atins încă serverul — deci se pot încă corecta pe loc, în loc să primească un
-- `ALTER TABLE` într-o migrație viitoare. Așa a fost reparată colația lui
-- `asset_tags.tag` de mai jos.
--
-- Registrul care decide asta e `schema_version`, și trăiește în baza de date, nu
-- aici: cine repară un fișier trebuie să se uite ACOLO întâi, nu la comentariul
-- ăsta, care e adevărat doar cât timp nimeni n-a mai rulat migrațiile.
--
-- ============================================================================
-- Ce NU e aici, și de ce absența e o decizie
-- ============================================================================
--
-- Nu există tabele pentru `users`, `sessions`, `login_attempts`,
-- `telegram_callbacks`, `telegram_chats`, `approval_tokens`, `ai_jobs`,
-- `ai_usage`, `allowlist`, `collector_cursors`, `intel_feeds`,
-- `restore_points`, și nici pentru `raw_events` în bloc. O parte conțin datele
-- personale ale OPERATORULUI, nu ale atacatorului — `login_attempts` are
-- IP-urile de la care se conectează el, `allowlist` conține peer-ul lui SSH.
-- Restul sunt fie stare locală care nu înseamnă nimic în altă parte
-- (`collector_cursors`), fie conținut care ar muta pe agregator fragmente de
-- jurnal (`ai_jobs`). Granița e scrisă în plan, secțiunea „Granița de date".
--
-- Absența lor nu e o omisiune de completat mai târziu: e granița. Cine adaugă
-- una dintre ele adaugă și motivul pentru care s-a răzgândit.
--
-- ============================================================================
-- Cartografierea, și de ce fiecare alegere
-- ============================================================================
--
-- `timestamptz` → `DATETIME(6)`, UTC, convertit la ingestie. `boolean` →
-- `TINYINT(1)`. `numeric(p,s)` → `DECIMAL(p,s)`: percentilele și scorurile sosesc
-- CALCULATE de pe server (`p50/p95/p99` sunt coloane acolo), iar agregatorul nu
-- calculează niciodată percentile — n-are `percentile_cont`, și n-are nevoie.
--
-- **`inet` → `INET6`**, tipul nativ MariaDB. Probat pe gazdă: acceptă și
-- `203.0.113.10`, și `2001:db8::1`, într-o singură coloană, cu ordonare corectă.
-- Perechea `VARBINARY(16)` + `VARCHAR(45)` din planul inițial nu mai e nevoie.
--
-- **`cidr` → limite precalculate.** MariaDB nu are `<<=`, deci întrebarea „e
-- adresa asta într-o plajă blocată?" nu se poate pune ca în Postgres. Se
-- păstrează adresa și lungimea prefixului AȘA CUM sosesc, plus limitele plajei
-- ca `VARBINARY(16)`, iar apartenența devine un `BETWEEN` pe ele. Limitele se
-- calculează LA INGESTIE, nu pe server: sunt o comoditate a replicii, nu un fapt
-- al sursei, iar un câmp calculat cerut expeditorului ar fi încă un loc în care
-- cele două capete pot să nu fie de acord.
--
-- **`text[]` → tabelă de legătură.** Un tablou într-o coloană JSON face din
-- „care actori au eticheta X" o parcurgere completă. Cele cinci tablouri de
-- atribute ale unui actor intră într-o singură tabelă cu un discriminator, nu în
-- cinci tabele: sunt aceeași formă de date (o listă de șiruri atârnată de un
-- actor) și au aceleași interogări.
--
-- **`jsonb` → `JSON`, plus scalarii după care filtrează panoul ca COLOANE
-- REALE.** Pentru tabelele de aici, scalarii ăia există deja ca coloane pe
-- server — panoul filtrează incidentele după `status`, `severity`, `ai_severity`,
-- `actor_key`, `asset_id`, iar detecțiile după `rule_id`, `severity`, `ts`. Deci
-- nu se inventează coloane aplatizate: blobul rămâne blob (`ai_verdict`,
-- `evidence`, `detail`), iar filtrarea merge pe coloanele care existau. Regula
-- devine muncă adevărată la `raw_events.raw` (E4), unde nu există coloane.
--
-- **Fără CHECK pe valori.** Serverul are `CHECK (status IN (...))`,
-- `CHECK (severity IN (...))`, `CHECK (kind IN (...))`. Recreate aici, ziua în
-- care serverul adaugă o a șasea severitate devine ziua în care replica începe
-- să refuze rânduri. Invariantul aparține sursei; replica îl stochează.

-- ============================================================================
-- Inventarul
-- ============================================================================
-- @guard table asset_entries
--
-- SUBSETUL din `assets`. Coloanele care NU pleacă de pe server nu au voie să
-- existe aici: `vhost_file`, `webroot`, `repo_path`, `repo_remote`,
-- `repo_branch`, `container_image`, `databases`.
--
-- Motivul e mai tare decât „nu e nevoie": împreună, alea sunt o hartă gratuită a
-- infrastructurii — unde stă fiecare vhost, din ce depozit se desfășoară, ce
-- baze de date există și pe ce porturi. Un agregator compromis ar da unui
-- atacator exact recunoașterea care e partea scumpă a unui atac, despre un
-- server pe care nu l-a atins încă. Panoul e util și fără ele.
--
-- `bind_addr`, `port`, `systemd_unit`, `container_id`, `stack`,
-- `confirmed_by_operator` și `notes` lipsesc din aceeași familie de motive:
-- primele descriu suprafața locală de rețea, ultimele două sunt stare de decizie
-- a operatorului, iar `notes` e text liber în care el scrie orice.
--
-- Absența lor e păzită de `tests/schema.test.ts`, testul „coloanele care NU
-- pleacă din `assets` nu există în schema replicii" — nu de disciplina cuiva
-- care își amintește lista.
CREATE TABLE asset_entries (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id         VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id           BIGINT NOT NULL COMMENT 'assets.id de pe server',

    name                TEXT NOT NULL,
    kind                TEXT NOT NULL COMMENT 'web|service|container|database|host, fara CHECK',
    criticality         SMALLINT NOT NULL,
    is_internet_exposed TINYINT(1) NOT NULL,
    protected           TINYINT(1) NOT NULL
                        COMMENT '1 = nicio procedura automata nu are voie sa-l atinga',

    first_seen          DATETIME(6) NOT NULL,
    last_seen           DATETIME(6) NOT NULL,

    received_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq           BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_asset_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='subset din assets; harta de infrastructura NU pleaca de pe server';

-- @guard index asset_entries ix_asset_entries_exposed
CREATE INDEX ix_asset_entries_exposed
    ON asset_entries (instance_id, is_internet_exposed, criticality);

-- @guard table asset_tags
--
-- `assets.tags text[]`. Aceeași regulă ca la atributele actorilor: un tablou
-- într-o coloană face din „ce active au eticheta X" o parcurgere completă.
CREATE TABLE asset_tags (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    instance_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id   BIGINT NOT NULL COMMENT 'assets.id de pe server',
    tag         VARCHAR(190) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,

    PRIMARY KEY (id),
    -- `VARCHAR(190)`, nu TEXT, fiindcă intră într-o cheie unică: 190 × 4 octeți
    -- încap în limita de 3072 a InnoDB alături de restul cheii. E singurul loc
    -- din replică unde o margine e inventată, și e inventată pentru o ETICHETĂ,
    -- nu pentru conținut care intră într-un hash — iar ingestia refuză, nu taie.
    --
    -- `utf8mb4_bin`, nu colația tabelei: `tag` e coloană de IDENTITATE, iar sub
    -- `utf8mb4_unicode_ci` etichetele `Prod` și `prod` de pe același activ sunt
    -- același rând — a doua s-ar pierde tăcut la ingestie, cu filigranul ecouat.
    -- Marginea inventată și colația sunt aceeași decizie luată o dată: dacă o
    -- coloană trebuie să încapă într-un index de identitate, trebuie și să se
    -- compare pe octeți. Regula e păzită acum de `tests/schema.test.ts`, testul
    -- „o coloană de identitate nu se compară printr-o colație insensibilă".
    UNIQUE KEY uk_asset_tags (instance_id, source_id, tag)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='assets.tags, desfasurat';

-- ============================================================================
-- Actorii
-- ============================================================================
-- @guard table actor_entries
--
-- Cheia sursei e `actor_key` (un text: o adresă, sau `cluster:<hash>`), nu un
-- `id`. Deci identitatea reală aici e `(instance_id, actor_key)` — aceeași
-- regulă, altă cheie.
CREATE TABLE actor_entries (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id       VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    -- `ascii_bin` ca la `instance_id`, și din același motiv: sub o colație
    -- insensibilă la majuscule, `cluster:AB` și `cluster:ab` ar fi același rând.
    actor_key         VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    kind              TEXT NOT NULL COMMENT 'ip|cluster, fara CHECK',
    killchain_stage   SMALLINT NOT NULL,
    stage_entered_at  DATETIME(6) NOT NULL,
    first_seen        DATETIME(6) NOT NULL,
    last_seen         DATETIME(6) NOT NULL,
    event_count       BIGINT NOT NULL,
    detection_count   BIGINT NOT NULL,
    is_known_scanner  TINYINT(1) NOT NULL,
    risk_score        SMALLINT NOT NULL,
    is_blocked        TINYINT(1) NOT NULL,
    is_allowlisted    TINYINT(1) NOT NULL,
    notes             TEXT NULL,

    received_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq         BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_actor_entries_source (instance_id, actor_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica actors; cheia sursei e actor_key, nu un id';

-- @guard index actor_entries ix_actor_entries_risk
CREATE INDEX ix_actor_entries_risk ON actor_entries (instance_id, risk_score);

-- @guard table actor_ips
--
-- `actors.member_ips inet[]`. Tabelă proprie, nu `actor_attrs`: aici tipul
-- coloanei e `INET6`, adică se poate ordona și compara ca adresă, nu ca text.
-- Vârâtă în tabela de atribute ca șir, întrebarea „ce actor a folosit adresa
-- asta" ar fi o potrivire de text.
CREATE TABLE actor_ips (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    instance_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    actor_key   VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    ip          INET6 NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_actor_ips (instance_id, actor_key, ip),
    KEY ix_actor_ips_ip (instance_id, ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='actors.member_ips, desfasurat; INET6 nativ';

-- @guard table actor_attrs
--
-- Cele CINCI tablouri de text ale unui actor — `countries`, `asns`,
-- `user_agents`, `ja4_fingerprints`, `reputation` — plus `targeted_assets`,
-- într-o singură tabelă cu un discriminator.
--
-- A șasea valoare a discriminatorului nu e o abatere de la plan, e aceeași
-- mecanică aplicată consecvent: `targeted_assets` e tot un tablou atârnat de un
-- actor, iar lăsat afară ar însemna că panoul nu poate spune spre ce a mers
-- cineva. Se stochează ca text, ca restul; e o referință atârnată către
-- `asset_entries.source_id`, nu o cheie străină.
--
-- `value_hash` există fiindcă unicitatea nu se poate pune pe valoare: un
-- `user_agent` trece lejer de limita de cheie a InnoDB. Se calculează LA
-- INGESTIE (SHA-256 peste valoare), ca limitele de plajă de la `blocklist`.
CREATE TABLE actor_attrs (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    instance_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    actor_key   VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- ENUM, singurul din schemă: mulțimea asta e a REPLICII, nu a sursei — o
    -- alege cartografierea de aici, nu serverul —, deci nu intră sub regula
    -- „invariantul aparține sursei". O valoare nouă ar fi oricum o migrație.
    kind        ENUM('country','asn','user_agent','ja4','reputation','targeted_asset')
                NOT NULL,
    value       TEXT NOT NULL,
    value_hash  BINARY(32) NOT NULL COMMENT 'SHA-256 peste value; calculat la ingestie',

    PRIMARY KEY (id),
    UNIQUE KEY uk_actor_attrs (instance_id, actor_key, kind, value_hash),
    KEY ix_actor_attrs_kind (instance_id, kind, value_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='cinci tablouri de atribute + targeted_assets, un discriminator';

-- ============================================================================
-- Detecțiile
-- ============================================================================
-- @guard table detection_entries
CREATE TABLE detection_entries (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id     VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id       BIGINT NOT NULL COMMENT 'detections.id de pe server',

    ts              DATETIME(6) NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_family     TEXT NOT NULL,
    severity        TEXT NOT NULL COMMENT 'info|low|medium|high|critical, fara CHECK',
    score           DECIMAL(6,2) NULL COMMENT 'z-scor robust, calculat pe server',

    -- Referințe ATÂRNATE, nu chei străine: o detecție poate ajunge legitim
    -- înaintea actorului sau a incidentului ei, fiindcă fiecare flux are cursorul
    -- lui. Cu o cheie străină, ordinea aia — normală — ar respinge rândul, iar
    -- rândul respins nu se mai întoarce niciodată.
    actor_key       VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NULL,
    asset_source_id BIGINT NULL,
    incident_source_id BIGINT NULL,

    src_ip          INET6 NULL,
    dst_port        INT NULL,

    -- Blobul rămâne blob: ce filtrează panoul — regulă, severitate, actor,
    -- activ, timp — sunt deja coloane. Vezi nota despre `jsonb` din capul
    -- fișierului.
    evidence        JSON NOT NULL,

    suppressed      TINYINT(1) NOT NULL,
    suppress_reason TEXT NULL,

    received_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq       BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_detection_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica detections; referintele raman atarnate, fara chei straine';

-- @guard index detection_entries ix_detection_entries_ts
CREATE INDEX ix_detection_entries_ts ON detection_entries (instance_id, ts);

-- @guard index detection_entries ix_detection_entries_incident
CREATE INDEX ix_detection_entries_incident
    ON detection_entries (instance_id, incident_source_id);

-- @guard table detection_events
--
-- `detections.event_ids bigint[]`. Tabela asta ESTE motorul expedierii de dovezi
-- din E4: de aici se află ce rânduri din `raw_events` trebuie trimise pentru o
-- detecție expediată. Fără ea, legătura ar trăi într-un tablou JSON și ar trebui
-- parcursă.
CREATE TABLE detection_events (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    instance_id         VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    detection_source_id BIGINT NOT NULL,
    event_source_id     BIGINT NOT NULL COMMENT 'raw_events.id de pe server',

    PRIMARY KEY (id),
    UNIQUE KEY uk_detection_events (instance_id, detection_source_id, event_source_id),
    KEY ix_detection_events_event (instance_id, event_source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='detections.event_ids; motorul expedierii de dovezi din E4';

-- ============================================================================
-- Incidentele
-- ============================================================================
-- @guard table incident_entries
--
-- ATENȚIE, aici e locul în care cineva ar adăuga un index unic parțial.
--
-- Serverul are `incidents_fingerprint_open_idx` — `UNIQUE (fingerprint) WHERE
-- status IN ('open','acknowledged')` — și e un invariant REAL acolo: fără el, o
-- încercare de forță brută devine 400 de incidente în loc de unul.
--
-- **Aici NU se recreează.** Agregatorul e o replică, nu a doua sursă de adevăr.
-- Amprenta F deschisă, rezolvată, și redeschisă peste două săptămâni e istorie
-- perfect legitimă: două rânduri cu aceeași amprentă, amândouă `open` la momente
-- diferite. Un index unic aici ar refuza al doilea rând, iar simptomul ar fi
-- „lipsește un incident din panou" — descoperit târziu și pus, greșit, pe seama
-- expedierii.
--
-- MariaDB nu are oricum indexuri parțiale; tentația e să se emuleze cu o coloană
-- întreținută de trigger, cum se face pentru sesiuni în E3. Nu aici: acolo
-- invariantul e al agregatorului, aici e al serverului.
CREATE TABLE incident_entries (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id          BIGINT NOT NULL COMMENT 'incidents.id de pe server',

    fingerprint        VARCHAR(190) NOT NULL
                       COMMENT 'NU e unica aici; vezi comentariul de deasupra',
    status             TEXT NOT NULL COMMENT 'open|acknowledged|resolved|..., fara CHECK',
    severity           TEXT NOT NULL,

    -- Verdictul AI stă lângă severitatea deterministă, nu peste ea: dezacordul
    -- dintre ele e informația. `ai_severity` și `ai_confidence` sunt coloane
    -- reale, deci panoul filtrează după ele fără să deschidă blobul.
    ai_severity        TEXT NULL,
    ai_verdict         JSON NULL,
    ai_confidence      DECIMAL(3,2) NULL,
    ai_analyzed_at     DATETIME(6) NULL,

    title              TEXT NOT NULL,
    summary            TEXT NULL,

    actor_key          VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NULL,
    asset_source_id    BIGINT NULL,

    detection_count    INT NOT NULL,
    created_at         DATETIME(6) NOT NULL,
    first_detection_at DATETIME(6) NOT NULL,
    last_detection_at  DATETIME(6) NOT NULL,

    acknowledged_by    TEXT NULL,
    acknowledged_at    DATETIME(6) NULL,
    resolved_at        DATETIME(6) NULL,
    resolution_note    TEXT NULL,
    notified_at        DATETIME(6) NULL,

    received_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq          BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_incident_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica incidents; amprenta NU e unica aici, dinadins';

-- @guard index incident_entries ix_incident_entries_status
CREATE INDEX ix_incident_entries_status
    ON incident_entries (instance_id, status(64), last_detection_at);

-- @guard index incident_entries ix_incident_entries_fingerprint
--
-- Index OBIȘNUIT pe amprentă, nu unic: panoul are nevoie să adune istoria unei
-- amprente, adică exact ce ar face imposibil un index unic.
CREATE INDEX ix_incident_entries_fingerprint
    ON incident_entries (instance_id, fingerprint, first_detection_at);

-- @guard table incident_timeline_entries
CREATE TABLE incident_timeline_entries (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id          BIGINT NOT NULL COMMENT 'incident_timeline.id de pe server',

    incident_source_id BIGINT NOT NULL,
    at                 DATETIME(6) NOT NULL,
    kind               TEXT NOT NULL COMMENT 'detection|action|note|ai_verdict|status',
    actor              TEXT NULL,
    detail             JSON NOT NULL,

    received_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq          BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_incident_timeline_source (instance_id, source_id),
    KEY ix_incident_timeline_incident (instance_id, incident_source_id, at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica incident_timeline; append-only la sursa';

-- ============================================================================
-- Blocarea
-- ============================================================================
-- @guard table blocklist_entries
--
-- AL DOILEA loc în care cineva ar adăuga un index unic parțial. Serverul are
-- `blocklist_active_ip_idx` — `UNIQUE (ip) WHERE active` —, iar acolo e corect:
-- două reguli active pentru aceeași adresă ar fi o contradicție.
--
-- **Aici NU se recreează**, din același motiv ca la amprenta incidentelor: o
-- adresă blocată, deblocată, și blocată din nou peste o lună are două rânduri cu
-- `active = 1` la momente diferite, iar istoria aia e legitimă. Unicitatea ar
-- refuza al doilea rând, și ar lipsi din panou tocmai blocarea recentă.
CREATE TABLE blocklist_entries (
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    instance_id        VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    source_id          BIGINT NOT NULL COMMENT 'blocklist.id de pe server',

    ip                 INET6 NOT NULL,
    prefix_len         SMALLINT NULL COMMENT 'NULL = o singura adresa',

    -- Limitele plajei, ca `BETWEEN` să înlocuiască `<<=`, care nu există în
    -- MariaDB. Calculate LA INGESTIE din `ip` + `prefix_len`, nu cerute
    -- expeditorului: sunt o comoditate a replicii, iar un câmp calculat cerut de
    -- la sursă ar fi încă un loc în care cele două capete pot să nu fie de acord.
    -- NULL până când ingestia le scrie — vezi partea a doua a lui E3a.
    net_start_bin      VARBINARY(16) NULL,
    net_end_bin        VARBINARY(16) NULL,
    cidr_text          VARCHAR(45) NULL COMMENT 'forma citibila, pentru panou',

    reason             TEXT NOT NULL,
    rule_id            TEXT NULL,
    incident_source_id BIGINT NULL,
    actor_key          VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NULL,

    blocked_at         DATETIME(6) NOT NULL,
    expires_at         DATETIME(6) NULL COMMENT 'NULL = permanent',
    ttl_seconds        INT NULL,

    hit_count          BIGINT NOT NULL COMMENT 'citit din contorul nftables',
    last_hit_at        DATETIME(6) NULL,

    created_by         TEXT NOT NULL COMMENT 'auto|telegram:<id>|operator:<user>',
    active             TINYINT(1) NOT NULL,
    unblocked_at       DATETIME(6) NULL,
    unblocked_by       TEXT NULL,
    unblock_reason     TEXT NULL,

    received_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    batch_seq          BIGINT UNSIGNED NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_blocklist_entries_source (instance_id, source_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='replica blocklist; unicitatea pe ip activ NU se recreeaza';

-- @guard index blocklist_entries ix_blocklist_entries_range
--
-- Pentru `BETWEEN`-ul care ține locul lui `<<=`.
CREATE INDEX ix_blocklist_entries_range
    ON blocklist_entries (instance_id, net_start_bin, net_end_bin);

-- @guard index blocklist_entries ix_blocklist_entries_active
CREATE INDEX ix_blocklist_entries_active
    ON blocklist_entries (instance_id, active, blocked_at);
