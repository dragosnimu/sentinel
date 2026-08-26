-- `login_session_entries.commands_purged`: ce a rulat sesiunea, și ce se mai vede.
--
-- Perechea lui `sentinel/db/migrations/0028_commands_purged.sql`, cu aceleași
-- motive și cu o diferență care contează: coloana asta NU se expediază de pe
-- gazdă. O scrie CURĂȚAREA DE AICI, cu ce a șters ea din
-- `session_command_entries`.
--
-- ## Eșecul pe care îl previne
--
-- `command_count` vine de pe gazdă și e numărul de rânduri din
-- `session_commands` de acolo. `lib/purge-automation.ts` șterge din
-- `session_command_entries` de aici și, prin proiectare, nu atinge
-- `login_session_entries`. După prima rulare cu `--apply`, panoul de la
-- `lib/panel-page.ts` ar fi arătat «558 079 comenzi» deasupra unui tabel gol.
--
-- ## De ce fiecare parte își numără ștergerile ei
--
-- Cele două baze se curăță independent, cu două scripturi, la momente diferite.
-- O cifră expediată de pe gazdă ar fi o afirmație a gazdei despre fișierul
-- altcuiva: dacă cineva curăță doar replica — cazul obișnuit, fiindcă aici cota
-- e problema —, gazda n-are ce trimite și panoul ar continua să mintă.
--
-- Numărată local, «558 079 comenzi, 558 079 șterse» e adevărul citit de aici:
-- gazda le mai are, replica nu.
--
-- `BIGINT` și nu `INT` ca `command_count`: cumulează peste rulări, iar un singur
-- deploy aduce jumătate de milion. `NOT NULL DEFAULT 0` fiindcă zero e adevărul
-- despre orice rând de dinaintea migrației — nu s-a șters nimic din el încă.

-- @guard column login_session_entries commands_purged
ALTER TABLE login_session_entries
    ADD COLUMN commands_purged BIGINT NOT NULL DEFAULT 0
        COMMENT 'câte comenzi ale sesiunii a șters curățarea DE AICI; cumulat';
