-- 0023_ship_watermarks: filigranul unei entități care se SCHIMBĂ.
--
-- Numărul: planul cere „0022_ship_watermarks". 0022 e deja luat de
-- `0022_instance_identity.sql`, iar `discover()` din `sentinel/db/migrate.py`
-- refuză să pornească dacă două fișiere poartă același număr — deci schema
-- întreagă ar fi încremenit, nu doar migrația asta.
--
-- ## De ce există
--
-- `sentinel/report/shipper.py` expediază azi un singur flux, `audit_log`, cu
-- cursor pe `id`. Motivul e scris acolo, în capul modulului: `id`-urile unei
-- tabele append-only sunt monotone și nu depind de ceas. Un incident închis, un
-- scor de actor recalculat, un finding rezolvat — nimic din toate astea nu
-- schimbă `id`-ul rândului, deci un cursor pe `id` nu le vede niciodată. Fără
-- coloana de mai jos, NICIUN flux mutabil nu se poate expedia, oricât ar accepta
-- agregatorul.
--
-- ## Trigger, nu tabelă outbox
--
-- O tabelă outbox e exactă și ordonată, dar cere editat fiecare modul din
-- `sentinel/db/repo/` care mută o entitate expediată — și fiecare editare e un
-- loc unde se poate uita. Un `UPDATE` scris peste șase luni, într-o cale nouă,
-- nu scrie în outbox și rândul lui nu pleacă niciodată; nimic nu raportează
-- lipsa, fiindcă nimeni nu știe ce trebuia să fie acolo.
--
-- Un trigger nu se uită. Costul e că un rând actualizat la mijlocul unei
-- ferestre de expediere se trimite de două ori, iar asta e inofensiv: ingestia
-- agregatorului e upsert pe `(instance_id, source_id)`.
--
-- ## De ce NU pe `audit_log`
--
-- `0002_response.sql:165-173` pune acolo un trigger `BEFORE UPDATE OR DELETE`
-- care ridică excepție: tabela e append-only, impus de bază, nu doar evitat în
-- cod. Un al doilea trigger `BEFORE UPDATE` pe aceeași tabelă ar fi cod care nu
-- se poate executa niciodată — orice UPDATE moare înainte —, deci ar fi o
-- afirmație falsă lăsată în schemă. Fluxul lui `audit_log` rămâne pe `id`.
--
-- ## Ce se întâmplă cu rândurile care există deja
--
-- `ADD COLUMN ... NOT NULL DEFAULT now()`: `now()` e STABLE, nu VOLATILE, deci
-- PostgreSQL (≥ 11) evaluează expresia O DATĂ și o păstrează ca valoare lipsă
-- în catalog, fără să rescrie tabela. Consecința care contează: TOATE rândurile
-- existente primesc aceeași valoare — momentul migrației. Un flux mutabil pornit
-- după asta le vede pe toate ca „recent atinse" și le expediază pe toate o dată,
-- lot cu lot. E purtarea dorită (panoul are nevoie de starea curentă, nu de
-- istorie), dar trebuie știută înainte, nu descoperită ca o restanță bruscă.
--
-- ## Ce NU face coloana asta
--
-- `updated_at` e ceasul bazei, iar un ceas nu e monoton. Două consecințe, ambele
-- tratate în `sentinel/report/shipper.py` și niciuna aici:
--
--   * un salt înapoi al ceasului lasă cursorul unui flux ÎNAINTEA lui `now()`,
--     iar fluxul se oprește tăcut — interogarea e validă și întoarce zero rânduri;
--   * două tranzacții pot comite în altă ordine decât cea a lui `now()` de la
--     începutul lor, deci un rând atins într-o tranzacție lungă poate deveni
--     vizibil DUPĂ ce cursorul a trecut de momentul lui.
--
-- Prima e detectată și raportată (`check_ship_lag`); a doua e mărginită de
-- `COMMIT_SAFETY_LAG_S` din shipper. Coloana singură nu rezolvă nici una.

-- ---------------------------------------------------------------------------
-- Funcția de trigger, scrisă o dată
-- ---------------------------------------------------------------------------
-- `now()` e ora de ÎNCEPUT a tranzacției, nu a instrucțiunii. Alegerea e
-- deliberată și e aceeași pe care o face `DEFAULT now()`: două rânduri atinse de
-- aceeași tranzacție primesc același moment, deci fie pleacă amândouă, fie
-- niciunul. Cu `clock_timestamp()` ar fi putut cădea de o parte și de alta a
-- unui filigran, iar jumătate dintr-o schimbare atomică ar fi ajuns pe agregator.
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION set_updated_at() IS
    'Pune updated_at = now() la fiecare UPDATE. Filigranul fluxurilor mutabile '
    'din sentinel/report/shipper.py se sprijină pe ea.';

-- ---------------------------------------------------------------------------
-- Tabelele mutabile expediate
-- ---------------------------------------------------------------------------
-- `DROP TRIGGER IF EXISTS` înainte de `CREATE`, nu `CREATE OR REPLACE TRIGGER`:
-- al doilea există abia din PostgreSQL 14, iar versiunea gazdei nu e o
-- presupunere pe care s-o facă un fișier de migrație. Perechea asta merge pe
-- orice versiune care rulează restul schemei.
--
-- Indexul e `(updated_at, <cheie>)` în exact ordinea în care expeditorul cere
-- rândurile: fără el, fiecare rundă a fiecărui flux mutabil e o parcurgere
-- completă plus o sortare.

ALTER TABLE incidents ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS incidents_set_updated_at ON incidents;
CREATE TRIGGER incidents_set_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX incidents_updated_idx ON incidents (updated_at, id);

ALTER TABLE blocklist ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS blocklist_set_updated_at ON blocklist;
CREATE TRIGGER blocklist_set_updated_at
    BEFORE UPDATE ON blocklist
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX blocklist_updated_idx ON blocklist (updated_at, id);

ALTER TABLE findings ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS findings_set_updated_at ON findings;
CREATE TRIGGER findings_set_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX findings_updated_idx ON findings (updated_at, id);

ALTER TABLE patch_plans ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS patch_plans_set_updated_at ON patch_plans;
CREATE TRIGGER patch_plans_set_updated_at
    BEFORE UPDATE ON patch_plans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX patch_plans_updated_idx ON patch_plans (updated_at, id);

ALTER TABLE assets ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS assets_set_updated_at ON assets;
CREATE TRIGGER assets_set_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX assets_updated_idx ON assets (updated_at, id);

-- `actors` și `selfcheck_state` nu au `id`: cheile lor primare sunt `actor_key`
-- (text) și `key` (text). Indexul le urmează, fiindcă o departajare pe alt tip
-- decât cel al indexului ar ordona rândurile altfel decât le compară cursorul —
-- adică ar sări peste ele exact la marginea unui lot.
--
-- Coloana le e adăugată acum, cu restul, ca să nu fie nevoie de a doua migrație
-- pe aceleași tabele. EXPEDIATE nu pot fi încă, și motivul nu e aici: filigranul
-- care pleacă pe sârmă e un ÎNTREG pozitiv, egal cu cel mai mare `id` din lot
-- (`aggregator/app/api/sentinel/sync/route.ts`), iar un flux cu cheie text n-are
-- ce pune acolo. Un flux mutabil cu cheie text se OPREȘTE vizibil în expeditor,
-- cu numele coloanei în mesaj, în loc să trimită un filigran inventat — vezi
-- `tests/unit/test_shipper.py::test_a_mutable_stream_with_a_text_key_stalls_instead_of_inventing_a_watermark`.
ALTER TABLE actors ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS actors_set_updated_at ON actors;
CREATE TRIGGER actors_set_updated_at
    BEFORE UPDATE ON actors
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX actors_updated_idx ON actors (updated_at, actor_key);

-- ATENȚIE la fluxul ăsta când va fi înregistrat: `selfcheck/runner.py` scrie
-- fiecare cheie la FIECARE rulare (`last_seen = now()`), schimbată sau nu, deci
-- triggerul ridică `updated_at` pe toate rândurile la fiecare rulare, iar fluxul
-- ar retrimite întreaga tabelă la fiecare rundă. Sunt câteva zeci de rânduri,
-- deci e ieftin — dar e chiar bucla „retrimite rânduri neschimbate" pe care
-- criteriul de acceptanță al lui E3 cere s-o vedem, nu s-o presupunem stinsă.
ALTER TABLE selfcheck_state ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS selfcheck_state_set_updated_at ON selfcheck_state;
CREATE TRIGGER selfcheck_state_set_updated_at
    BEFORE UPDATE ON selfcheck_state
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX selfcheck_state_updated_idx ON selfcheck_state (updated_at, key);

-- ---------------------------------------------------------------------------
-- Jumătatea de timp a cursorului
-- ---------------------------------------------------------------------------
-- `collector_cursors.cursor` e text și rămâne text: pentru un flux mutabil ține
-- CHEIA ultimului rând expediat. Momentul lui stă alături, într-o coloană cu
-- tipul lui adevărat.
--
-- De ce o coloană și nu un singur text de forma `<moment>|<cheie>`: comparația
-- „cursorul a avansat?" se face în SQL, în aceeași instrucțiune cu scrierea, iar
-- pe un text ar fi cerut un al doilea parser (în SQL, lângă cel din Python)
-- pentru aceeași gramatică. Două gramatici scrise în două limbaje, fără nimic
-- care să le lege, e chiar defectul livrat de 0015 și 0020.
--
-- `NULL` pentru cursoarele care nu sunt legate de timp — colectoarele, și
-- fluxurile append-only ale expeditorului. NULL nu e „zero": într-o comparație
-- de rânduri face rezultatul necunoscut, deci un cursor mutabil căruia îi
-- lipsește momentul NU avansează și `_advance` raportează nepotrivirea. E starea
-- corectă: „nu știu unde am rămas" nu are voie să treacă drept „de la început".
ALTER TABLE collector_cursors ADD COLUMN cursor_at timestamptz;

COMMENT ON COLUMN collector_cursors.cursor_at IS
    'Jumătatea de timp a filigranului unui flux mutabil expediat; NULL pentru '
    'cursoarele pe id și pentru colectoare. Perechea e (cursor_at, cursor).';
