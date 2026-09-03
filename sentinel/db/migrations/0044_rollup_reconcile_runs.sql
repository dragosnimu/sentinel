-- 0044_rollup_reconcile_runs: reconcilierea `event_rollup_1h` se scrie o
-- dată pe oră, nu se recalculează la fiecare citire.
--
-- Runda 2 a funcționalității care repară filigranul din
-- `maintenance_service.rollup_events` (vezi antetul acelui modul) trimisese
-- verificarea directă în `check_rollup_reconcile`: o interogare peste toată
-- fereastra brutului (`HOURLY_GAPS_SQL`), rulată din nou la fiecare trecere
-- de autoverificare. Măsurat de verificator pe gazdă, la 728h reale: 1,5-2 s
-- caldă, 13-15 s rece, de cinci ori pe zi — adică 288 de rulări complete pe
-- lună de date, pentru un răspuns care se poate schimba o singură dată pe
-- oră, fiindcă doar mentenanța scrie `event_rollup_1h`. Exact tiparul deja
-- consemnat pentru panou: o verificare la 5 minute peste agregări scumpe
-- reface singură simptomul de încetineală pe care ar trebui să-l vadă.
--
-- Tabela asta e locul unde stă rezultatul. `repair_rollup_gaps` scrie un
-- rând la FIECARE trecere (chiar și când n-are ce compara — `status` spune
-- de ce), iar `check_rollup_reconcile` citește doar cel mai recent, un
-- singur rând indexat pe `checked_at`. Append-only, ca `scans`/
-- `restore_drills`: istoricul rămâne, iar „când s-a verificat ultima oară"
-- e el însuși un fapt pe care operatorul îl poate cere.

CREATE TABLE rollup_reconcile_runs (
    id              bigserial   PRIMARY KEY,
    checked_at      timestamptz NOT NULL DEFAULT now(),

    -- 'never_ran'     — event_rollup_1h n-a fost scris încă deloc (filigranul
    --                   lipsește); `raw_exists` spune dacă e o instalare
    --                   proaspătă sau o mentenanță care n-a ajuns la pas.
    -- 'empty_window'  — nicio oră stabilită încă de comparat (brutul a ajuns
    --                   deja din urmă filigranul, sau filigranul abia a
    --                   pornit).
    -- 'ok'            — fereastra a fost comparată și nu lipsește nimic.
    -- 'gaps'          — cel puțin o oră STABILITĂ are mai puține rânduri în
    --                   agregat decât în raw_events.
    status          text        NOT NULL
                      CHECK (status IN ('never_ran', 'empty_window', 'ok', 'gaps')),
    raw_exists      boolean     NOT NULL,

    window_lower    timestamptz,
    window_upper    timestamptz,

    -- Numărul TOTAL de ore lipsă din fereastră și rândurile lor, nu doar
    -- eșantionul pe care `repair_rollup_gaps` l-a reparat pe rularea asta —
    -- vezi `GapReport.total_hours`/`total_missing` în `db/repo/rollups.py`
    -- (calculate cu `count(*) OVER()`/`sum(...) OVER()`, înainte de LIMIT).
    gap_hours       integer     NOT NULL DEFAULT 0,
    rows_missing    bigint      NOT NULL DEFAULT 0,

    -- Ora cu CEL MAI MULT lipsă, nu cea mai veche — cea mai veche e prioritatea
    -- de reparare (concurează cu retenția), dar cea mai gravă e ce trebuie
    -- să vadă operatorul întâi.
    worst_bucket    timestamptz,
    worst_missing   bigint,

    hours_repaired  integer     NOT NULL DEFAULT 0
);

-- `check_rollup_reconcile` citește un singur rând, cel mai proaspăt — index-only
-- pe coloana de sortare, ca citirea de la fiecare autoverificare să coste cât un
-- `LIMIT 1`, nu un scan.
CREATE INDEX rollup_reconcile_runs_recent_idx ON rollup_reconcile_runs (checked_at DESC);
