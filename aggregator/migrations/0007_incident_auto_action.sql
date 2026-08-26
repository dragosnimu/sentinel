-- `incident_entries.auto_action` și `auto_action_at`: ce a FĂCUT agentul.
--
-- Coloanele există pe server din `0011_autonomy.sql` și lipseau din replică
-- fiindcă `0003_entities.sql` a fost scris înaintea lor. Se adaugă acum, odată
-- cu înregistrarea fluxului `incidents`, ca fluxul să le poată duce.
--
-- De ce merită coloane, nu o omisiune: un incident al cărui răspuns automat e
-- invizibil în panou înseamnă că operatorul NU poate spune dacă Sentinel a
-- acționat — și aia e chiar informația pentru care cineva deschide un incident
-- vechi. „S-a blocat adresa acum trei zile" și „nu s-a făcut nimic" arată identic
-- fără ele.
--
-- Și nu poartă recunoaștere: descriu ce a făcut agentul, nu cum e construită
-- infrastructura. Vezi secțiunea din `README.md` pentru granița aia și pentru
-- lista completă a coloanelor care o ating.

-- @guard column incident_entries auto_action
ALTER TABLE incident_entries
    ADD COLUMN auto_action TEXT NULL
    COMMENT 'ce a facut agentul automat: blocare, izolare, nimic';

-- @guard column incident_entries auto_action_at
ALTER TABLE incident_entries
    ADD COLUMN auto_action_at DATETIME(6) NULL
    COMMENT 'cand; NULL = nicio actiune automata';
