-- 0027_session_close: cum se termină o sesiune, de fapt.
--
-- ## Ce s-a măsurat, pe gazdă, la prima livrare (24 august 2026)
--
-- 0026 a presupus că `USER_END` de la auditd înseamnă „sesiunea s-a încheiat".
-- Numărat pe jurnalul real, într-o singură rotație:
--
--     31  USER_LOGIN      logări
--     44  USER_START      deschideri de strat PAM
--     44  USER_END        închideri de strat PAM
--     11  USER_LOGOUT     ieșiri adevărate
--
-- `USER_END` nu e perechea lui `USER_LOGIN`. E perechea lui `USER_START`, iar
-- PAM deschide și închide un strat pentru fiecare `sudo`, `su` sau modul de
-- autentificare din interiorul sesiunii. Prima închidere sosea la o secundă după
-- logare — încă din faza de autentificare a lui sshd.
--
-- Două consecințe, amândouă vizibile în date:
--
--   * **1534 de comenzi orfane din 14157** (11%). Sesiunea era deja „închisă"
--     când soseau comenzile ei, deci nu-și mai găseau părintele. Rândurile se
--     scriau, dar nu apăreau în niciun rezumat și în nicio cronologie — prezente
--     în tabelă și invizibile acolo unde le-ar căuta cineva;
--   * **rânduri-fantomă**: a doua și a treia închidere nu mai găseau nimic
--     deschis și fabricau sesiuni noi, fără cont și fără adresă. În panou,
--     fiecare logare apărea de două-trei ori, iar fantoma arăta exact ca o
--     logare pe care Sentinel n-a putut s-o atribuie nimănui.
--
-- ## Reparația, și de ce cere o coloană
--
-- Sesiunea se închide pe `USER_LOGOUT`. Dar `USER_LOGOUT` sosește mai rar decât
-- `USER_LOGIN` — 11 față de 31 — fiindcă o sesiune tăiată de rețea, de un
-- `reboot`, sau una încă deschisă când s-a rotit jurnalul nu produce niciuna.
--
-- Deci a doua cale: o sesiune fără activitate de mai mult de `STALE_SESSION_H`
-- ore se închide PRESUPUS. Iar diferența dintre cele două se scrie, nu se
-- deduce: „s-a deconectat la 14:32" și „n-am mai auzit nimic de ea după 14:32"
-- sunt afirmații diferite, iar un panou care le arată identic minte liniștit.
ALTER TABLE login_sessions
    ADD COLUMN closed_inferred boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN login_sessions.closed_inferred IS
    'true = nu s-a văzut nicio ieșire; momentul e ultima activitate, nu o deconectare.';

-- Sesiunile candidate la închiderea presupusă. Parțial, ca celelalte: cele
-- deschise sunt câteva zeci, cele închise vor fi sute de mii.
CREATE INDEX login_sessions_stale_idx ON login_sessions (opened_at)
    WHERE closed_at IS NULL;
