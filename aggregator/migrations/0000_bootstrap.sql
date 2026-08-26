-- Registrul migrațiilor. Singurul fișier care NU se înregistrează în el însuși.
--
-- Ordinea e o problemă de ou și găină: nimic nu se poate consemna ca aplicat
-- înainte să existe tabela în care se consemnează. Deci fișierul ăsta are alt
-- regim decât restul: se rulează la fiecare pornire a runner-ului, e scris cu
-- `IF NOT EXISTS`, iar dovada că a mers NU e codul de retur, ci o interogare pe
-- `information_schema` de după — vezi `bootstrap()` din `lib/migrate.ts`.
--
-- `IF NOT EXISTS` singur nu e o dovadă: pe MariaDB el transformă „exista deja"
-- într-un avertisment și iese cu succes, iar un `CREATE` refuzat din alt motiv
-- (cotă, drepturi) tot un cod de ieșire dă. „Am cerut" și „există" sunt lucruri
-- diferite.
--
-- Se înregistrează INSTRUCȚIUNI, nu fișiere. Un fișier de 12 instrucțiuni care
-- moare la a 7-a lasă baza într-o stare pe care niciun număr de versiune nu o
-- descrie; cu un rând per instrucțiune, reluarea e comportamentul implicit.

-- @guard table schema_version
CREATE TABLE IF NOT EXISTS schema_version (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

    -- Numele fișierului, exact cum e pe disc. Perechea (fișier, poziție) e
    -- identitatea instrucțiunii; numărul de versiune singur n-a descris
    -- niciodată o migrație oprită la mijloc.
    migration   VARCHAR(190) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    stmt_index  INT UNSIGNED NOT NULL
                COMMENT 'poziția, de la 1, în fișier',

    -- Suma se calculează peste textul EXECUTABIL (comentarii scoase, spații
    -- normalizate). Un comentariu rescris nu e istorie rescrisă; o instrucțiune
    -- rescrisă este, și atunci runner-ul refuză să continue.
    stmt_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,

    -- Garda declarată în fișier (`-- @guard table audit_entries`). Ținută aici
    -- pentru diagnostic: ea e cea care a decis dacă instrucțiunea se sare.
    guard       VARCHAR(190) NOT NULL,

    -- 1 doar dacă garda a CONFIRMAT obiectul după execuție. `guard none` nu are
    -- ce confirma, deci se consemnează cu 0 — „a rulat" și „e dovedit acolo"
    -- sunt stări diferite și n-au voie să arate la fel într-un registru.
    verified    TINYINT(1) NOT NULL,

    -- 'reconciled' când obiectul exista deja la pornire: instrucțiunea rulase,
    -- dar procesul murise înainte să apuce să scrie rândul ăsta.
    note        VARCHAR(190) NULL,

    applied_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    duration_ms INT UNSIGNED NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uk_schema_version_stmt (migration, stmt_index)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC
  COMMENT='un rând per INSTRUCȚIUNE aplicată, nu per fișier';
