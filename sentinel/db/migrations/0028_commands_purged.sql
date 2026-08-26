-- 0028_commands_purged: ce a rulat sesiunea, și ce se mai vede din ea.
--
-- ## Eșecul măsurat
--
-- `command_count` e un contor MEMORAT al rândurilor din `session_commands`, ținut
-- la zi de `_refresh_counters`, al cărui docstring spune exact de ce există:
-- «rezumatul de la închiderea sesiunii ar raporta un număr de comenzi care nu se
-- potrivește cu lista de sub el».
--
-- `scripts/purge-automation-commands.py` șterge rânduri și, prin proiectare, NU
-- atinge `login_sessions`. După prima rulare cu `--apply`, sesiunea 2521 ar fi
-- arătat **«558 079 comenzi» deasupra unui tabel gol** — în panou
-- (`aggregator/lib/panel-page.ts`) și în rezumatul de închidere de pe Telegram
-- (`sentinel/detect/logins.py`). Adică fix eșecul pentru care există contorul.
--
-- ## De ce o coloană nouă și nu doar o renumărare
--
-- Renumărarea singură ar fi fost corectă și ar fi pierdut ceva: «sesiunea asta a
-- rulat 558 079 de comenzi în 140 de secunde» e chiar faptul din care s-a născut
-- filtrul. Șters, peste trei luni nimeni nu mai poate răspunde la «de ce e
-- filtrul ăsta aici» decât citind cod.
--
-- Deci amândouă, fiindcă sunt două afirmații diferite:
--
--   * `command_count` = câte rânduri SUNT. Invariantul lui `_refresh_counters`
--     rămâne neatins: numărat din tabelă, nu incrementat în cod;
--   * `commands_purged` = câte au fost șterse de aici, cumulat. Numai curățarea
--     îl scrie, și numai crescător.
--
-- Panoul și Telegram le arată pe amândouă: «0 comenzi (558 079 șterse ca zgomot
-- de automatizare)». Un zero singur ar fi la fel de mincinos ca 558 079 — ar
-- spune «n-a rulat nimic» despre un deploy.
--
-- ## De ce nu se expediază spre agregator
--
-- Replica are propriul script de curățare și propria coloană, scrisă de el.
-- Fiecare parte numără CE A ȘTERS EA, iar dacă cineva curăță doar replica,
-- «558 079 comenzi, 558 079 șterse» e adevărul acolo: gazda le mai are.
-- Expediată, cifra ar fi fost o afirmație a gazdei despre fișierul altcuiva.
ALTER TABLE login_sessions
    ADD COLUMN commands_purged bigint NOT NULL DEFAULT 0;

COMMENT ON COLUMN login_sessions.commands_purged IS
    'Câte comenzi ale sesiunii au fost șterse din session_commands de curățare. Cumulat, doar crescător.';
