-- 0026_login_history: cine s-a logat, și ce a rulat după aceea.
--
-- ## De ce tabele proprii, și nu `raw_events`
--
-- Trei motive, fiecare măsurat:
--
--   1. **Retenția.** `raw_events` se taie la 30 de zile. Istoricul de comenzi are
--      retenție NELIMITATĂ pe gazdă — întrebarea «ce a rulat cineva acum trei
--      luni» e chiar cazul de folosință. Ținute în aceeași tabelă, ori se pierde
--      istoricul, ori se păstrează 30 de zile de trafic nginx degeaba.
--
--   2. **Sesiunea e o ENTITATE, nu un eveniment.** Se deschide, adună comenzi, se
--      închide. Un rând care se schimbă în timp nu încape într-o tabelă
--      append-only, iar «ultimul eveniment despre sesiunea 432» e o interogare pe
--      care nimeni n-o scrie corect din prima.
--
--   3. **Expedierea.** Fluxurile pleacă pe tabelă. Amestecate, panoul extern ar
--      primi ori tot traficul brut, ori nimic.
--
-- ## Cheia de sesiune
--
-- `ses` din auditd — identificatorul dat de nucleu la login. Leagă fiecare
-- `execve` de logarea care l-a produs. E unic *pe pornire*: după un reboot,
-- numerotarea o ia de la capăt. De-asta cheia naturală e `(session_key,
-- opened_at)`, nu `session_key` singur — altfel prima sesiune de după o repornire
-- s-ar contopi cu una de acum trei luni, iar comenzile ei ar apărea în cronologia
-- altcuiva.

CREATE TABLE login_sessions (
    id            bigserial   PRIMARY KEY,

    -- `ses` de la nucleu. Text, nu întreg: `4294967295` e «nicio sesiune», iar
    -- forma lui e a nucleului, nu a noastră.
    session_key   text        NOT NULL,

    -- Contul care s-a autentificat, cu numele rezolvat de auditd la momentul
    -- faptei. NULL înseamnă că nucleul n-a putut rezolva unul — se scrie NULL,
    -- nu `(unknown)`, ca să nu apară un cont inventat în clasamente.
    username      text,
    auid          text,

    src_ip        inet,

    -- `ssh` pentru o comandă rulată prin ssh fără terminal (deploy, rsync,
    -- diagnostic); `/dev/pts/N` pentru un om. Măsurat pe gazdă pe 7 zile: 557 de
    -- primul fel, 29 de al doilea.
    terminal      text,

    -- Derivat din `terminal`, dar STOCAT: politica de alertare atârnă de el, iar
    -- o expresie recalculată la fiecare citire se schimbă tăcut când cineva
    -- rescrie interogarea. Scris o dată, se poate și audita.
    interactive   boolean     NOT NULL DEFAULT false,

    opened_at     timestamptz NOT NULL,
    closed_at     timestamptz,

    command_count integer     NOT NULL DEFAULT 0,
    -- Câte dintre comenzi au fost privilegiate. E jumătatea utilă a rezumatului
    -- de la închidere: «412 comenzi» nu spune nimic, «412 comenzi, 3 cu sudo»
    -- spune ce s-a întâmplat.
    sudo_count    integer     NOT NULL DEFAULT 0,

    -- Când a plecat alerta de deschidere și cea de închidere. NULL înseamnă «nu
    -- a plecat încă», iar asta e ce citește expeditorul de notificări: o coloană
    -- de stare, nu o listă ținută în memoria unui proces care se poate reporni.
    alerted_at    timestamptz,
    summarised_at timestamptz,

    -- Ce anume a fost neașteptat la logarea asta: cont nou, adresă nouă, oră
    -- nefirească. Gol înseamnă «nimic» — adică mesaj, fără incident.
    unexpected    text[]      NOT NULL DEFAULT '{}',

    updated_at    timestamptz NOT NULL DEFAULT now(),

    -- Vezi nota despre reboot din capul fișierului.
    UNIQUE (session_key, opened_at)
);

-- Sesiunile deschise, pentru corelarea comenzilor care sosesc. Parțial: pe o
-- gazdă cu istoric de un an, cele deschise sunt câteva, iar un index peste tot
-- ar fi de o mie de ori mai mare fără să răspundă mai repede.
CREATE INDEX login_sessions_open_idx ON login_sessions (session_key)
    WHERE closed_at IS NULL;
CREATE INDEX login_sessions_opened_idx ON login_sessions (opened_at DESC);
-- Coada de notificări: sesiunile pentru care n-a plecat încă mesajul. Tot
-- parțial, și din același motiv.
CREATE INDEX login_sessions_pending_idx ON login_sessions (opened_at)
    WHERE alerted_at IS NULL;

DROP TRIGGER IF EXISTS login_sessions_set_updated_at ON login_sessions;
CREATE TRIGGER login_sessions_set_updated_at
    BEFORE UPDATE ON login_sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMENT ON TABLE login_sessions IS
    'O sesiune de login, de la deschidere la închidere. Cheia e `ses` de la auditd.';


-- ---------------------------------------------------------------------------
-- Comenzile
-- ---------------------------------------------------------------------------
-- Append-only prin folosire, nu prin trigger: nimic nu actualizează un rând de
-- aici după ce a fost scris, iar fluxul de expediere merge pe `id`. Fără trigger
-- de `updated_at` tocmai fiindcă n-are nevoie de unul — un cursor pe `id` e
-- monoton, fără goluri și independent de ceas.
CREATE TABLE session_commands (
    id          bigserial   PRIMARY KEY,

    -- Sesiunea, când s-a putut lega. NULL înseamnă că logarea nu a fost văzută:
    -- înregistrări pierdute de nucleu, sau colectorul pornit la mijlocul unei
    -- sesiuni. `session_key` rămâne pe rând oricum, deci legătura se poate reface
    -- mai târziu, iar comanda nu se pierde fiindcă nu i-am găsit părintele.
    session_id  bigint      REFERENCES login_sessions(id) ON DELETE SET NULL,
    session_key text        NOT NULL,

    ts          timestamptz NOT NULL,
    username    text,

    -- Binarul, așa cum l-a văzut nucleul, și linia întreagă REDACTATĂ.
    -- Redactarea se face la colectare (`sentinel/redact.py`): rândul ăsta are
    -- retenție nelimitată și pleacă spre o găzduire partajată, deci un secret
    -- ajuns aici rămâne în tabelă, în backup și în replică.
    exe         text,
    argv        text        NOT NULL,

    cwd         text,
    tty         text,
    pid         integer,
    -- Procesul-părinte. E ce deosebește o comandă tastată de una pornită de un
    -- script: fără el, cele câteva mii de rânduri ale unui deploy și cele zece
    -- ale unui om arată la fel.
    ppid        integer,
    success     boolean,

    -- Rândul din `raw_events`, cât timp mai trăiește. Legătura se rupe singură
    -- după 30 de zile, iar asta e în regulă: dovada completă e efemeră, istoricul
    -- nu. Nicio cheie străină — `raw_events` e partiționată și se taie.
    event_id    bigint
);

CREATE INDEX session_commands_session_idx ON session_commands (session_id, id);
CREATE INDEX session_commands_ts_idx ON session_commands (ts DESC);
CREATE INDEX session_commands_user_idx ON session_commands (username, ts DESC);
-- Căutarea după ce s-a rulat. `text_pattern_ops` ca `LIKE 'systemctl%'` să poată
-- folosi indexul; căutarea liberă în mijlocul liniei rămâne o scanare, și e în
-- regulă — se face rar și pe o singură instanță.
CREATE INDEX session_commands_argv_idx ON session_commands (argv text_pattern_ops);

COMMENT ON TABLE session_commands IS
    'Fiecare execve dintr-o sesiune cu login. Retenție nelimitată; argv redactat.';


-- ---------------------------------------------------------------------------
-- Ce e „obișnuit"
-- ---------------------------------------------------------------------------
-- Linia de referință pentru «logare neașteptată». Se învață singură din ce se
-- întâmplă, iar în primele zile NU ridică incidente — altfel prima săptămână ar
-- produce un incident la fiecare logare, exact când încă nu știi dacă sistemul e
-- de încredere.
--
-- Fereastra de învățare se măsoară de la cel mai VECHI `first_seen` din tabelă,
-- nu dintr-o dată scrisă undeva. Derivată, nu configurată: o dată de pornire
-- ținută separat s-ar putea desincroniza de conținut, iar atunci fereastra ar
-- spune «am învățat» despre o tabelă goală.
CREATE TABLE login_baseline (
    -- `account`, `src_ip`, `key_fp`, `hour`. Lista trăiește în cod: ce ANUME
    -- face o logare neașteptată e o decizie de securitate, iar un fișier de
    -- configurație e locul greșit în care să lași pe cineva s-o lărgească.
    kind       text        NOT NULL,
    value      text        NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    seen_count integer     NOT NULL DEFAULT 1,
    PRIMARY KEY (kind, value)
);

COMMENT ON TABLE login_baseline IS
    'Ce s-a mai văzut: conturi, adrese, ore. Fereastra de învățare pornește de la cel mai vechi first_seen.';


-- ---------------------------------------------------------------------------
-- `notifications.kind`: ce fel de veste e, ca să se poată ști ce nu se tace
-- ---------------------------------------------------------------------------
-- Până acum, botul scria `kind="selfcheck"` în cod pentru fiecare rând din coada
-- generică — singurul producător care exista. Comentariul de acolo o spunea pe
-- față: „`kind="selfcheck"` e ce scrie în tabelă azi".
--
-- Cu al doilea producător — alerta de logare, care NU se tace niciodată — asta
-- nu mai merge: felul trebuie să călătorească pe rând, nu să fie ghicit la
-- livrare. Un fel ghicit greșit ar tăcea exact alerta care nu are voie să tacă,
-- iar simptomul ar fi liniște, adică nimic.
--
-- Implicit `'selfcheck'`: rândurile scrise înainte de migrație păstrează exact
-- comportamentul pe care îl aveau, iar `NOT NULL` face ca un producător nou să
-- nu poată uita să-l pună.
ALTER TABLE notifications
    ADD COLUMN kind text NOT NULL DEFAULT 'selfcheck';

COMMENT ON COLUMN notifications.kind IS
    'Felul vestii. Decide ce trece prin fereastra de liniște — vezi telegram/quiet.py.';

-- Coada de livrare citește `state` și `kind` împreună.
CREATE INDEX notifications_kind_idx ON notifications (kind, state)
    WHERE state = 'queued';
