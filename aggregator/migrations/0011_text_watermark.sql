-- Filigran TEXT: `sync_cursors.last_source_key`.
--
-- ============================================================================
-- De ce era nevoie
-- ============================================================================
--
-- Filigranul de pe sârmă nu e o poziție, e un JETON DE ECOU: expeditorul
-- avansează cursorul doar dacă receptorul îi întoarce exact valoarea trimisă,
-- derivată din rândurile chiar scrise. Poziția reală rămâne la expeditor, ca
-- `(updated_at, cheie)`, și nu pleacă de acolo.
--
-- Până azi jetonul era obligatoriu un întreg pozitiv, iar asta a lăsat trei
-- surse de date afară — nu fiindcă ar fi fost greu de replicat, ci fiindcă
-- cheia lor nu e un număr:
--
--   * `selfcheck_state` — cheia e `key text`. Blochează pagina Servicii;
--   * `actors` — cheia e `actor_key text`. Blochează harta atacatorilor pe țări
--     și ASN-uri din rezumat;
--   * rollup-urile — cheie compusă, fără `id` deloc. Blochează Rapoartele.
--
-- Un jeton text le acoperă pe toate trei cu un singur mecanism. Alternativa —
-- un filigran derivat, numeric, doar pentru rollup-uri — ar fi deblocat o pagină
-- și ar fi lăsat două, cu un al doilea mecanism de întreținut.
--
-- ============================================================================
-- De ce o coloană NOUĂ și nu lărgirea celei existente
-- ============================================================================
--
-- `last_source_id` e `BIGINT` și e citită ca POZIȚIE CONFIRMATĂ de `lib/chain.ts`,
-- unde pe ea stă discriminatorul dintre „arhiva e goală" și „lanțul e rupt".
-- Schimbată în text, comparațiile de acolo ar deveni lexicografice fără ca
-- nimeni să ceară asta, iar `GREATEST` peste un `BIGINT` stocat ca șir ar
-- compara „100" cu „99" și ar alege „99".
--
-- Două coloane, deci, iar fluxul declară care dintre ele e a lui. Un flux nu are
-- niciodată amândouă: felul filigranului e o proprietate a declarației, nu a
-- rândului.
--
-- `NULL` la ambele e starea unui cursor care n-a primit încă nimic de felul lui
-- — adevărat, spre deosebire de un zero sau un șir gol, care ar spune „am ajuns
-- la începutul listei".

-- @guard column sync_cursors last_source_key
ALTER TABLE sync_cursors
    ADD COLUMN last_source_key VARCHAR(190)
        CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL
    COMMENT 'filigranul ecouat, pentru fluxurile cu cheie text; vezi last_source_id';

-- Colație BINARĂ, nu una care ignoră registrul, și e o alegere:
-- `GREATEST` peste coloana asta trebuie să dea același răspuns ca `max()` din
-- expeditor, care compară octeți. O colație care consideră „ABC" egal cu „abc"
-- ar putea alege alt maxim decât cel trimis, iar ecoul n-ar mai potrivi — deci
-- cursorul n-ar mai avansa NICIODATĂ, pe un lot perfect valid.
