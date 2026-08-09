-- 0020_quiet_schedule: constrângerea de pe `quiet_hours` nu știa de zile.
--
-- ## Ce era stricat
--
-- 0015 a creat `telegram_chats_quiet_hours_shape` pe vremea când liniștea era o
-- singură fereastră zilnică:
--
--     CHECK (quiet_hours IS NULL
--            OR quiet_hours ~ '^[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]$')
--
-- Între timp `/mute` a învățat reguli pe zile, iar constrângerea nu a fost
-- lărgită niciodată. Deci `parse_schedule` accepta, `str(Schedule)` producea, și
-- PostgreSQL respingea la INSERT:
--
--     /mute 22:00-06:00; du,sa 22:00-09:00     -> eroare
--     /mute 22:00-06:00; vi,sa 22:00-09:00     -> eroare
--     /mute 22:00-06:00; weekend 22:00-09:00   -> eroare
--
-- Toate trei sunt forme pe care textul de ajutor al comenzii le oferă ca
-- exemplu. Ultima scriere reușită pe gazdă e din 4 august, adică de dinainte de
-- extindere: funcționalitatea nu a fost niciodată salvabilă.
--
-- ## Ce se schimbă
--
-- Regexul devine gramatica reală a programului:
--
--     program  := regula ('; ' regula)*
--     regula   := (zile ' ')? fereastra
--     zile     := lu|ma|mi|jo|vi|sa|du (',' ...)*  |  weekend  |  lucratoare
--     fereastra:= HH:MM-HH:MM
--
-- ## De ce nu scris de mână aici
--
-- Fiindcă exact asta a produs defectul: aceeași gramatică scrisă de două ori, în
-- două limbaje, fără nimic care să le lege. Un prag ales manual aici ar repeta
-- greșeala cu alt număr.
--
-- Șirul de mai jos este copiat VERBATIM din `sentinel.telegram.quiet`, care îl
-- construiește din aceleași tabele de zile pe care le folosește `_compact_days`
-- la scriere:
--
--     python -c "from sentinel.telegram import quiet; print(quiet.SCHEDULE_SQL_REGEX)"
--
-- `tests/unit/test_quiet_hours.py` compară cele două șiruri caracter cu caracter
-- ȘI trece prin regexul citit din FIȘIERUL ĂSTA fiecare valoare pe care o
-- produce `str(Schedule)` — inclusiv fiecare exemplu extras din `_MUTE_HELP`.
-- O gramatică lărgită în Python fără o migrație nouă pică în teste, nu pe
-- telefonul operatorului.
--
-- ## De ce orele rămân [0-2][0-9] și nu [01][0-9]|2[0-3]
--
-- `%H` nu produce niciodată peste 23, deci varianta strictă ar fi „mai corectă".
-- Ar fi însă și mai îngustă decât regexul din 0015 pentru orele 24–29, iar
-- `ADD CONSTRAINT` validează rândurile existente: pe o gazdă unde cineva a scris
-- manual în coloană, migrația ar cădea. Regexul de aici e o supramulțime strictă
-- a celui din 0015 — orice rând care trecea, trece. Forma exactă rămâne treaba
-- lui `parse_schedule`; CHECK-ul ține gunoiul afară, cum spunea deja 0015.
--
-- Nu se scrie și nu se șterge niciun rând: o migrație care ar atinge programele
-- existente ar schimba orele în care serverul cuiva nu mai e supravegheat.

ALTER TABLE telegram_chats
    DROP CONSTRAINT IF EXISTS telegram_chats_quiet_hours_shape;

ALTER TABLE telegram_chats
    ADD CONSTRAINT telegram_chats_quiet_hours_shape
    CHECK (quiet_hours IS NULL OR quiet_hours ~ '^(((lu|ma|mi|jo|vi|sa|du)(,(lu|ma|mi|jo|vi|sa|du))*|weekend|lucratoare) )?[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9](; (((lu|ma|mi|jo|vi|sa|du)(,(lu|ma|mi|jo|vi|sa|du))*|weekend|lucratoare) )?[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9])*$');

COMMENT ON COLUMN telegram_chats.quiet_hours IS
    'Program local recurent: "22:00-06:00" sau "22:00-06:00; vi,sa 22:00-09:00". NULL = se folosește configurația.';
