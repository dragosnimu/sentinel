-- Ce mărginește autentificarea: un index, o colație, și trei comentarii.
--
-- Fișier NOU, nu o editare a lui `0008_auth.sql`: `lib/migrate.ts` consemnează
-- INSTRUCȚIUNI cu suma lor de control, iar textul uneia deja aplicate nu se mai
-- schimbă — s-ar opri toate migrațiile cu un mesaj despre istorie rescrisă.
--
-- ============================================================================
-- De ce e nevoie de el
-- ============================================================================
--
-- `login_attempts` nu e o urmă, e STAREA celor trei limitatoare din
-- `lib/auth/ratelimit.ts`. Trei lucruri lipseau din schemă ca să fie așa:
--
--   1. **niciun index pe `at` singur.** `countFailuresGlobal` filtrează numai
--      `result <> 'ok' AND at >= …`, iar `result <> …` nu e sargabil — deci
--      numărătoarea aia e o BALEIERE COMPLETĂ a tabelei, la fiecare
--      `POST /login` și la fiecare `POST /totp`. Cele două straturi cu prefix
--      (`(ip, at)`, `(username, at)`) sunt deja indexate corect;
--   2. **fereastra de 15 minute exista doar în proza unui docstring
--      TypeScript.** Un job de retenție scris în SQL — cel care va tăia tabela
--      asta când crește — nu citește TypeScript. Dacă șterge rânduri mai noi de
--      15 minute, șterge chiar starea limitatoarelor, iar simptomul nu e o
--      eroare: e un plafon care nu se mai aplică, tăcut;
--   3. **colația coloanei `username` era `utf8mb4_unicode_ci`**, adică
--      insensibilă la majuscule, în timp ce `users.username` e `ascii_bin`.
--      Consecința nu e „se numără mai mult", e „se REFUZĂ mai mult": eșecuri
--      tastate `ADMIN` intrau în fereastra lui `admin`, iar `Admin` și `admin`
--      — două conturi distincte în `users` — își împărțeau fereastra. Eșecul pe
--      care straturile astea există să-l scoată e negarea operatorului legitim.
--
-- Plus două coloane moarte în `users`, care mint fără să spună nimeni.
--
-- ============================================================================
-- Ce NU se poate confirma de aici, spus pe față
-- ============================================================================
--
-- Instrucțiunile 2–5 sunt `@guard none`, deci se consemnează cu `verified = 0`:
-- „a rulat, n-am putut dovedi efectul". Nu e o scăpare, e limita gărzilor —
-- `guardPresent` întreabă `information_schema` dacă un OBIECT există, iar un
-- comentariu și o colație sunt ATRIBUTE ale unui obiect care există deja. O
-- gardă `table login_attempts` ar fi mai rea decât niciuna: obiectul e acolo,
-- deci instrucțiunea s-ar sări pentru totdeauna, consemnată „reconciled", și
-- nimic n-ar rula vreodată.
--
-- Ce le dovedește e o citire pe gazdă, după rulare:
--
--     SELECT COLUMN_NAME, COLLATION_NAME, COLUMN_COMMENT
--       FROM information_schema.COLUMNS
--      WHERE TABLE_SCHEMA = DATABASE()
--        AND TABLE_NAME IN ('users', 'login_attempts');
--     SELECT TABLE_NAME, TABLE_COMMENT FROM information_schema.TABLES
--      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'login_attempts';
--
-- Iar `MODIFY COLUMN` rescrie DEFINIȚIA întreagă: ce nu e repetat mai jos se
-- pierde. De-aia fiecare `MODIFY` de aici repetă tipul, nulabilitatea și
-- implicitul din `0008_auth.sql`, nu doar comentariul.

-- Indexul pe `at` singur. Separat de tabelă, ca `ix_audit_entries_instance_at`
-- din `0001_core.sql`, și din același motiv: există pentru VITEZĂ, nu pentru un
-- invariant, deci se poate arunca fără să se piardă nimic.
--
-- @guard index login_attempts ix_login_attempts_at
CREATE INDEX ix_login_attempts_at ON login_attempts (at);

-- Colația coloanei, nu un `COLLATE` în `WHERE`: pus în interogare, ar fi scos
-- `ix_login_attempts_username_at` din joc și ar fi transformat și stratul per
-- cont într-o baleiere — adică reparația unei probleme cu chiar problema de
-- deasupra. `utf8mb4_bin`, nu `ascii_bin` ca geamăna din `users`: coloana asta
-- ține CE S-A TASTAT, iar o tastare cu diacritice trebuie să încapă (vezi
-- argumentul din `0008_auth.sql`), doar să nu se contopească cu alta.
--
-- @guard none colatia unei coloane nu e un obiect in information_schema.TABLES
ALTER TABLE login_attempts
    MODIFY COLUMN username VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL
    COMMENT 'ce s-a tastat, nu o identitate; octeti, ca users.username';

-- Pragul, scris unde îl vede cine deschide baza, nu doar unde îl vede cine
-- deschide `lib/auth/ratelimit.ts`.
--
-- @guard none COMMENT-ul unei tabele nu se poate citi prin guardPresent
ALTER TABLE login_attempts
    COMMENT = 'incercarile de autentificare pe PANOUL agregator; date locale. E STAREA celor trei limitatoare, nu doar o urma: se numara randurile cu result <> ok pe o fereastra alunecatoare de 15 minute (per ip, per nume, global). Retentia NU are voie sa stearga randuri mai noi de 15 minute - ar sterge chiar plafoanele, si tacut';

-- Cele două coloane moarte. Nu se scot printr-un `DROP` pe o tabelă vie — aia e
-- o decizie a operatorului —, dar `failed_attempts` e mai rea decât inertă:
-- `NOT NULL DEFAULT 0` înseamnă că ORICE raport sau unealtă de administrare
-- citește din ea „0 eșecuri" despre orice cont, pentru totdeauna. O valoare
-- falsă cu un consumator evident.
--
-- @guard none COMMENT-ul unei coloane nu se poate citi prin guardPresent
ALTER TABLE users
    MODIFY COLUMN failed_attempts INT UNSIGNED NOT NULL DEFAULT 0
    COMMENT 'INERTA din 2026-08-17: nimeni nu o scrie si nimeni nu o citeste. 0 NU inseamna zero esecuri; blocarea per cont e o fereastra peste login_attempts';

-- @guard none COMMENT-ul unei coloane nu se poate citi prin guardPresent
ALTER TABLE users
    MODIFY COLUMN locked_until DATETIME(6) NULL
    COMMENT 'INERTA din 2026-08-17: nimeni nu o scrie si nimeni nu o citeste. NULL NU inseamna cont neblocat; vezi disabled';
