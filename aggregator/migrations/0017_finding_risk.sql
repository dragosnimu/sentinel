-- `finding_entries`: semaforul SSVC al constatării, replicat de pe server.
--
-- Perechea lui `sentinel/db/migrations/0047_risk_intel.sql`. Serverul decide
-- culoarea (roșu / galben / gri / verde) dintr-un arbore CISA SSVC, cu EPSS, KEV
-- și CVSS-ul furnizorului; replica doar o afișează, ca la `priority`. Nu are
-- fluxurile de intel și n-are nevoie de ele ca să arate ce a decis gazda.
--
-- ## ORDINEA DE LIVRARE contează, și nu se poate evita
--
-- Ingestia REFUZĂ un câmp necunoscut (dinadins: ignorat, ar fi un rând pierdut
-- definitiv) ȘI refuză un câmp care lipsește. Deci:
--
--   * serverul nou, agregatorul vechi -> „câmpul necunoscut risk_color", fluxul
--     `findings` al ACELUI server stă pe loc, vizibil în `ship:lag`;
--   * agregatorul nou, serverul vechi -> „lipsește câmpul risk_color", la fel.
--
-- Ordinea corectă e: (1) migrația asta + codul agregatorului, (2) apoi fiecare
-- server, pe rând. Cât timp un server n-a primit încă versiunea nouă, fluxul lui
-- `findings` stă oprit (nu pierde nimic: ce n-a trecut de cursor se retrimite),
-- iar celelalte fluxuri merg. Fereastra se închide singură când serverul e livrat.
--
-- ## Ce primesc rândurile sosite înainte de migrație
--
-- Coloanele se adaugă DUPĂ ce tabela are rânduri, iar un rând sosit înainte n-are
-- de unde să aibă o culoare. `risk_color` are `DEFAULT 'grey'`, ca pe server:
-- „încă neevaluat" e gri, nu verde. Un `DEFAULT 'green'` ar fi spus „evaluat și în
-- regulă" despre ceva pe care nimeni nu l-a evaluat; `NULL` ar fi cerut fiecărei
-- interogări să-l trateze ca gri. Celelalte patru coloane sunt NULL-abile:
-- `NULL` e adevărul („nu se știe") pentru decizie, scor, percentilă și `risk`.
--
-- `risk` e `JSON` ca `raw`, dar nu poartă proză: doar cifre, cuvinte dintr-un
-- vocabular, id-uri, date și vectori CVSS. Justificarea scrisă a furnizorului
-- rămâne pe server.

-- @guard column finding_entries epss_percentile
ALTER TABLE finding_entries
    ADD COLUMN epss_percentile DECIMAL(5,4) NULL
    COMMENT 'findings.epss_percentile; percentila EPSS, afisata langa probabilitate';

-- @guard column finding_entries risk_color
ALTER TABLE finding_entries
    ADD COLUMN risk_color VARCHAR(8) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'grey'
    COMMENT 'red|amber|green|grey, decis pe server; implicit gri = neevaluat';

-- @guard column finding_entries risk_decision
ALTER TABLE finding_entries
    ADD COLUMN risk_decision VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL
    COMMENT 'act|attend|track_star|track (CISA SSVC), dupa ajustarea pentru repornire; NULL = gri';

-- @guard column finding_entries risk_score
ALTER TABLE finding_entries
    ADD COLUMN risk_score DECIMAL(6,5) NULL
    COMMENT 'probabilitate x impact, 0..1; ordoneaza in interiorul unei culori';

-- @guard column finding_entries risk
ALTER TABLE finding_entries
    ADD COLUMN risk JSON NULL
    COMMENT 'cele patru puncte de decizie si sursa lor, CVSS ales, EPSS; fara proza';
