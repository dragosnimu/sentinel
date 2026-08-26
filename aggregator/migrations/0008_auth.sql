-- Autentificarea panoului: `users`, `sessions`, `login_attempts`, `user_instances`.
--
-- Fișier NOU, ca `0002`–`0007`: `lib/migrate.ts` consemnează INSTRUCȚIUNI cu
-- suma lor de control, iar editarea uneia deja aplicate oprește toate migrațiile
-- cu un mesaj despre istorie rescrisă. Aceleași convenții ca în `0001_core.sql`:
-- o gardă `@guard` deasupra fiecărei instrucțiuni, fără `DELIMITER`,
-- identificatori în `ascii_bin`, timpi în `DATETIME(6)`.
--
-- ============================================================================
-- TABELELE ASTEA NU SUNT O REPLICĂ. Nimic din ele nu vine prin sincronizare.
-- ============================================================================
--
-- `users`, `sessions` și `login_attempts` există și pe serverul monitorizat
-- (`sentinel/db/migrations/0006_auth_audit.sql`, `0009_web_session.sql`) și
-- ALEA NU PLEACĂ NICIODATĂ de acolo: conțin adresele IP ale operatorului și
-- datele lui personale, nu ale atacatorului. Regula e scrisă în
-- `docs/PLAN-arhitectura-distribuita.md`, secțiunea „Granița de date", și e
-- ținută la celălalt capăt de lista de fluxuri din `sentinel/report/shipper.py`.
--
-- Ce se creează aici sunt tabelele AGREGATORULUI, populate local, de panoul lui:
-- alți utilizatori, alte sesiuni, alt jurnal de încercări. Coincidența de nume e
-- reală și e capcana: cine caută mai târziu „unde ajung sesiunile serverului"
-- găsește tabela asta și trage concluzia greșită. De-aia scrie aici, o dată,
-- explicit — și de-aia cele patru nume sunt trecute în `AGGREGATOR_OWNED` din
-- `tests/schema.test.ts`, unde decid ce reguli li se aplică:
--
--   * regulile REPLICII (exact o cheie unică, începută cu `instance_id`;
--     contabilitatea sosirii `received_at`/`batch_seq`; fiecare coloană
--     nemărginită numită în README) NU li se aplică, fiindcă nu sosesc de
--     nicăieri;
--   * în schimb pe datele lui proprii agregatorul are voie să impună invarianți
--     reali — și chiar trebuie, vezi triggerele de mai jos.
--
-- Că niciun flux nu scrie în ele nu se lasă pe seama numelui: e o aserțiune, în
-- `tests/auth-schema.test.ts`, testul „niciun flux de sincronizare nu scrie în
-- tabelele de autentificare".
--
-- ============================================================================
-- Timpii se scriu în UTC EXPLICIT, deci nicio coloană de aici n-are DEFAULT
-- ============================================================================
--
-- Restul schemei folosește `DEFAULT CURRENT_TIMESTAMP(6)`, care dă ora
-- FUSULUI SESIUNII. Fusul sesiunii pe găzduire **nu a fost măsurat** (`lib/db.ts`
-- setează `timezone` la driver, ceea ce nu schimbă `time_zone` al serverului),
-- iar aici diferența nu e cosmetică: `expires_at` se compară cu ora serverului
-- la fiecare cerere. O sesiune scrisă în ora locală și comparată cu UTC trăiește
-- cu câteva ore mai mult sau moare la naștere, iar simptomul — „mă deconectează
-- imediat" sau, mai rău, „sesiunile nu expiră" — nu arată spre un fus orar.
--
-- Deci coloanele de timp de aici sunt `NOT NULL` FĂRĂ implicit, iar cine
-- inserează scrie `UTC_TIMESTAMP(6)`. `DEFAULT UTC_TIMESTAMP(6)` ar fi fost
-- varianta scurtă, dar nu e verificată pe MariaDB de aici (implicitele
-- neconstante sunt limitate, iar ce acceptă versiunea gazdei nu s-a măsurat), și
-- o migrație care poate fi refuzată de server nu se scrie „ar trebui să meargă".
-- Lipsa implicitului are și un efect bun: un `INSERT` care uită timpul e o
-- eroare zgomotoasă, nu un rând cu ora greșită.

-- ============================================================================
-- Utilizatorii panoului
-- ============================================================================
--
-- Ștacheta e `sentinel/web/security.py`, iar acordul dintre cele două capete e
-- ținut de `tests/unit/test_aggregator_auth_parity.py`: parametrii Argon2id,
-- fereastra TOTP, forma jetonului și vocabularul de roluri se citesc acolo din
-- AMBELE surse și se compară.
--
-- @guard table users
CREATE TABLE users (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Identitate, deci comparație pe octeți: sub o colație insensibilă `Admin`
    -- și `admin` ar fi același rând, iar cheia unică de mai jos ar contopi două
    -- conturi distincte. Aceeași regulă ca pentru `instance_id` în `0001_core.sql`.
    username            VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Argon2id în forma PHC codificată: `$argon2id$v=19$m=65536,t=3,p=2$<sare>$<hash>`.
    -- Parametrii stau ÎN șir, deci o schimbare viitoare a costului se poate
    -- detecta la login și hashul se poate ridica fără resetare de parolă —
    -- exact mecanica din `security.py` (`check_needs_rehash`).
    -- 255 e o margine cunoscută, nu inventată: forma de mai sus are 96–100 de
    -- caractere cu sarea și hashul noastre.
    password_hash       VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Vocabularul e ACELAȘI ca pe server (`0006_auth_audit.sql`), și e impus de
    -- bază, nu doar de cod. `CHECK`, nu `ENUM`: `ENUM` se aplică strict doar sub
    -- `STRICT_TRANS_TABLES`, iar `sql_mode` al găzduirii nu a fost măsurat — sub
    -- alt mod, o valoare nevalidă ar deveni un avertisment și un șir gol.
    role                VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                        DEFAULT 'viewer',

    disabled            TINYINT(1) NOT NULL DEFAULT 0
                        COMMENT '1 = contul nu se mai poate autentifica; istoria ramane',

    -- Cifrat în repaus cu AES-256-GCM (`lib/crypto.ts`, `lib/auth/totp.ts`).
    -- NICIODATĂ în clar: un dump al bazei nu are voie să dea al doilea factor,
    -- fiindcă exact asta ar anula rostul lui.
    totp_secret_enc     TEXT NULL,

    -- Înrolarea e în doi pași: se generează secretul, se arată codul QR, și abia
    -- când utilizatorul dovedește că poate produce un cod devine confirmat. Fără
    -- coloana asta, o înrolare întreruptă lasă un cont care CERE un al doilea
    -- factor pe care nu-l are nimeni.
    totp_confirmed_at   DATETIME(6) NULL,

    -- Anti-reluare. Un cod TOTP e valabil o fereastră de 30 s; fără ultimul
    -- contor acceptat, același cod merge de două ori înăuntrul ei — destul
    -- pentru cineva care l-a citit peste umăr sau care reia o cerere capturată.
    -- Consumarea se face în SQL, cu `<` strict (`lib/auth/totp.ts`), ca două
    -- cereri simultane cu același cod să nu poată câștiga amândouă.
    totp_last_counter   BIGINT UNSIGNED NULL,

    failed_attempts     INT UNSIGNED NOT NULL DEFAULT 0,
    locked_until        DATETIME(6) NULL,

    last_login_at       DATETIME(6) NULL,
    last_login_ip       INET6 NULL,

    password_changed_at DATETIME(6) NOT NULL,
    created_at          DATETIME(6) NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_users_username (username),
    CONSTRAINT ck_users_role CHECK (role IN ('owner', 'operator', 'viewer'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='utilizatorii PANOULUI agregator; date locale, NU o replica a serverului';

-- ============================================================================
-- Sesiunile
-- ============================================================================
--
-- Cookie-ul poartă un jeton opac de 256 de biți. Ce se stochează aici e SHA-256
-- al lui, niciodată jetonul: un dump al bazei — un backup lăsat citibil, panoul
-- de administrare al găzduirii, personalul furnizorului — ar preda altfel toate
-- sesiunile vii. Jetonul e de mare entropie și de unică folosință, deci un
-- SHA-256 simplu ajunge; nu e nimic de spart prin forță brută.
--
-- `pending_totp` e o COLOANĂ, nu un fanion într-un cookie semnat. O sesiune
-- doar-cu-parolă poate ajunge la `/totp` și nicăieri altundeva, iar rândul însuși
-- spune că e pe jumătate făcută — deci nicio umblătură la cookie nu sare peste
-- al doilea factor.
--
-- ## `active_token_hash`: unicitatea parțială, emulată cu un trigger
--
-- Pe server invariantul e un index unic parțial:
-- `CREATE UNIQUE INDEX sessions_token_hash_idx ON sessions (token_hash)
--  WHERE revoked_at IS NULL` (`0009_web_session.sql`). MariaDB n-are indexuri
-- parțiale, iar varianta evidentă — o coloană generată — NU merge: refuză și
-- `IF`, și `CASE`, în `GENERATED ALWAYS AS`, atât `STORED` cât și `VIRTUAL`
-- (ERROR 1901, măsurat pe gazdă pe 13 august 2026).
--
-- Deci: o coloană obișnuită, întreținută de triggerele de mai jos, cu o cheie
-- unică pe ea. NULL-urile duplicate sunt acceptate de un index unic în MariaDB,
-- deci oricâte rânduri REVOCATE pot purta același `token_hash`, iar al doilea
-- rând ACTIV cu același jeton e refuzat de bază cu ERROR 1062.
--
-- Și de ce aici da, iar pe tabelele replicate nu (regula 3 din `0001_core.sql`):
-- acolo unicitatea ar respinge istorie legitimă venită de pe alt server; aici
-- datele sunt ale agregatorului, iar „două sesiuni active cu același jeton" nu e
-- istorie, e o eroare de program pe care baza trebuie s-o oprească.
--
-- @guard table sessions
CREATE TABLE sessions (
    -- Id opac de rând, nu credențialul. Cine îl vede într-un jurnal sau într-un
    -- rând din `login_attempts` nu capătă nimic cu care să se autentifice.
    id                CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    user_id           BIGINT UNSIGNED NOT NULL,

    -- SHA-256 hexa, 64 de caractere. Jetonul în clar nu există în nicio coloană
    -- — proprietate probată de `tests/auth-session.test.ts`, testul „jetonul în
    -- clar nu ajunge în nicio coloană".
    token_hash        CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Întreținută EXCLUSIV de triggere. Cine o scrie de mână nu strică nimic —
    -- triggerul rescrie valoarea oricum — dar nici nu obține ceva.
    active_token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,

    -- Jeton CSRF per sesiune, comparat în timp constant la fiecare formular.
    -- 43 de caractere = 32 de octeți în base64url fără umplutură, exact ce
    -- produce `randomBytes(32).toString("base64url")` și ce produce
    -- `secrets.token_urlsafe(32)` pe server.
    csrf_token        CHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Fără implicit, dinadins: cine creează o sesiune trebuie să SPUNĂ dacă e
    -- pe jumătate autentificată. Un `DEFAULT 0` ar face ca o inserare care uită
    -- câmpul să producă tăcut o sesiune complet autentificată.
    pending_totp      TINYINT(1) NOT NULL,

    -- Adresa de la care s-a creat, ca un cookie furat și folosit din altă parte
    -- să fie vizibil în urmă chiar dacă adresa nu e blocată.
    created_ip        INET6 NULL,
    user_agent        VARCHAR(512) NULL,

    created_at        DATETIME(6) NOT NULL,
    last_seen_at      DATETIME(6) NOT NULL,
    -- Expirare ABSOLUTĂ, niciodată glisantă: o expirare care se împinge la
    -- fiecare cerere înseamnă că un cookie furat rămâne valabil cât îl folosește
    -- hoțul. Aceeași decizie ca `sessions.touch` de pe server.
    expires_at        DATETIME(6) NOT NULL,

    revoked_at        DATETIME(6) NULL,
    revoked_reason    VARCHAR(64) NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_sessions_active_token (active_token_hash),
    KEY ix_sessions_user (user_id),
    KEY ix_sessions_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='sesiunile PANOULUI agregator; se stocheaza sha256 al jetonului';

-- Corp de o singură instrucțiune, deci fără `BEGIN ... END` și fără `DELIMITER`
-- — aceeași constrângere ca la triggerele de append-only din `0001_core.sql`, și
-- din același motiv: un fișier care are nevoie de `DELIMITER` nu se mai aplică
-- identic prin runner și prin `mysql`.
--
-- Două triggere, nu unul: `BEFORE INSERT` singur ar lăsa revocarea (un `UPDATE`)
-- fără efect asupra coloanei, deci un jeton revocat ar rămâne „activ" în cheia
-- unică și n-ar mai putea fi refolosit niciodată; `BEFORE UPDATE` singur ar lăsa
-- prima inserare fără valoare, deci unicitatea n-ar păzi nimic.
--
-- @guard trigger sessions_active_token_bi
CREATE TRIGGER sessions_active_token_bi BEFORE INSERT ON sessions
    FOR EACH ROW SET NEW.active_token_hash =
        IF(NEW.revoked_at IS NULL, NEW.token_hash, NULL);

-- @guard trigger sessions_active_token_bu
CREATE TRIGGER sessions_active_token_bu BEFORE UPDATE ON sessions
    FOR EACH ROW SET NEW.active_token_hash =
        IF(NEW.revoked_at IS NULL, NEW.token_hash, NULL);

-- ============================================================================
-- Încercările de autentificare
-- ============================================================================
--
-- Fiecare încercare, reușită sau nu. Răspunde la „autentificarea aia
-- neobișnuită am fost eu, în deplasare?" înainte ca cineva să-i spună
-- compromitere.
--
-- Blocarea e per utilizator ȘI per sursă: doar per utilizator, un atacator
-- blochează un cont cunoscut ca negare de serviciu; doar per sursă, o încercare
-- distribuită trece. Indexul pe `(ip, at)` e cel pe care se sprijină numărătoarea
-- per sursă. Aplicarea propriu-zisă a limitării e piesa 2 — aici e locul în care
-- se scrie.
--
-- `username` NU e o identitate aici, e CE S-A TASTAT: poate să nu existe niciun
-- cont cu numele ăla. De-aia nu e `ascii` (o tastare cu diacritice ar fi o eroare
-- de inserare, adică o încercare de login care pică din alt motiv decât cel
-- adevărat), și de-aia cine scrie trebuie să taie la 64 de caractere, ca
-- `security.py` (`username[:64]`).
--
-- @guard table login_attempts
CREATE TABLE login_attempts (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    at         DATETIME(6) NOT NULL,

    username   VARCHAR(64) NULL COMMENT 'ce s-a tastat, nu o identitate',
    ip         INET6 NULL,
    user_agent VARCHAR(512) NULL,

    -- Același vocabular ca pe server (`0006_auth_audit.sql`), impus de bază.
    result     VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    -- Care etapă a picat, ca „parolă greșită" și „al doilea factor greșit" să se
    -- deosebească în urmă: o serie de `bad_totp` peste o parolă corectă înseamnă
    -- că cineva ARE parola.
    stage      VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    session_id CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL,
    detail     VARCHAR(255) NULL,

    PRIMARY KEY (id),
    KEY ix_login_attempts_ip_at (ip, at),
    KEY ix_login_attempts_username_at (username, at),
    CONSTRAINT ck_login_attempts_result CHECK (
        result IN ('ok', 'bad_password', 'bad_totp', 'locked', 'unknown_user')),
    CONSTRAINT ck_login_attempts_stage CHECK (
        stage IS NULL OR stage IN ('password', 'totp'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='incercarile de autentificare pe PANOUL agregator; date locale';

-- ============================================================================
-- Cine ce instanță are voie să vadă
-- ============================================================================
--
-- Autorizarea multi-instanță. Absența unui rând ÎNSEAMNĂ „nicio instanță": un
-- utilizator nou primește zero, nu tot. Eșecul variantei inverse — „vede tot din
-- start" — e tăcut și se descoperă când persoana greșită vede serverul greșit.
--
-- Aplicarea e în stratul de date (piesa 3): fiecare interogare poartă
-- `WHERE instance_id IN (?)`, iar un filtru într-o componentă React nu e un
-- control de autorizare. Aici e doar tabela.
--
-- Fără cheie străină spre `users` sau `instances`, ca peste tot în schema asta
-- (regula 2 din `0001_core.sql`, ținută de testul „NICIO cheie străină" din
-- `tests/schema.test.ts`). Consecința, scrisă ca să nu fie descoperită mai
-- târziu: ștergerea unui utilizator nu curăță rândurile de aici, iar un rând
-- rămas în urmă ar da drepturi unui `user_id` reciclat. Utilizatorii NU se șterg
-- — se pune `disabled = 1` —, exact ca instanțele, care se opresc fără să-și
-- piardă istoria.
--
-- @guard table user_instances
CREATE TABLE user_instances (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    user_id     BIGINT UNSIGNED NOT NULL,
    -- Aceeași formă și aceeași colație ca `instances.instance_id`: identitățile
    -- se compară pe octeți, altfel `Prod` și `prod` ar fi același drept.
    instance_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Rolul PE INSTANȚA ASTA. Poate fi mai mic decât `users.role`; niciodată mai
    -- mare, iar asta o decide stratul de autorizare, nu schema.
    role        VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL
                DEFAULT 'viewer',

    granted_at  DATETIME(6) NOT NULL,
    granted_by  VARCHAR(64) NULL COMMENT 'cine a dat dreptul; pentru urma de audit',

    PRIMARY KEY (id),
    UNIQUE KEY uk_user_instances (user_id, instance_id),
    KEY ix_user_instances_instance (instance_id),
    CONSTRAINT ck_user_instances_role CHECK (role IN ('owner', 'operator', 'viewer'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='ce instanta vede fiecare utilizator; lipsa randului = nicio instanta';
