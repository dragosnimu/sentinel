-- 0040_session_commands_event_id_comment: de ce coloana rămâne goală pentru
-- tot ce s-a scris până azi, și de ce asta nu se repară cu un backfill.
--
-- ## Problema, măsurată pe gazdă (31 august 2026)
--
-- `session_commands.event_id` există din 0026, cu comentariul care explică
-- de ce n-are cheie străină spre `raw_events`. Nimic n-o scria niciodată:
-- `record_command` (`sentinel/db/repo/logins.py`) pur și simplu n-o includea
-- în lista de coloane a INSERT-ului. Măsurat: 0 din 420 494 de rânduri o
-- aveau populată.
--
-- Reparația de cod (același commit) preallocă id-ul din `raw_events_id_seq`
-- ÎNAINTE de scrierea evenimentului și îl pune pe obiectul `Event`, deci
-- `record_command` îl are la îndemână fără să citească nimic înapoi din bază.
-- De aici încolo, rândurile noi primesc `event_id` corect (sau NULL, dacă
-- preallocarea a eșuat pentru lot — colectarea rămâne calea vitală, nu
-- coloana de urmărire).
--
-- ## De ce NU există backfill pentru cele 420 494 de rânduri vechi
--
-- Nu e o chestiune de volum sau de fereastră de retenție — e structural.
-- Codul vechi nu a păstrat NICIUNDE care rând din `raw_events` a produs o
-- comandă scrisă înainte de reparația asta. Singura cale de reconstituire
-- ar fi o cheie naturală: potrivire pe (ts, username, argv, pid, tty) între
-- `session_commands` și `raw_events`. Aia nu e o cheie unică — două comenzi
-- identice rulate la două secunde distanță de același proces (o buclă de
-- `sleep` de instalator, măsurată chiar în acest fișier de proiecție) ar
-- potrivi la fel de bine oricare din mai multe rânduri candidate.
--
-- Regula de la care pleacă toată reparația asta e explicită: un `event_id`
-- greșit e mai rău decât unul absent, fiindcă o legătură care arată sigură
-- și duce în altă parte otrăvește exact investigația pentru care există
-- coloana. O potrivire pe cheie naturală nesigură ar produce exact acel
-- rezultat — la scară, pe 420 494 de rânduri — ca să umple o coloană care
-- azi spune corect „nu știu". Deci: fără backfill, pentru niciun rând scris
-- înainte de acest commit. Rândurile vechi rămân NULL pentru totdeauna;
-- rândurile noi sunt corecte de la scriere.
--
-- Nicio schimbare de schemă aici — doar comentariul de mai jos, ca decizia
-- să se citească din bază, nu doar din istoricul git.
COMMENT ON COLUMN session_commands.event_id IS
    'Rândul din raw_events care a produs comanda, cât timp mai trăiește (retenție '
    '30 de zile, fără cheie străină — vezi 0026). Populat de la 2026-08-31 încoace; '
    'rândurile scrise înainte sunt NULL definitiv, fiindcă nu există cheie naturală '
    'unică pentru o reconstituire sigură (vezi 0040).';
