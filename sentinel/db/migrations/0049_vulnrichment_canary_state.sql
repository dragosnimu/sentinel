-- 0049_vulnrichment_canary_state: verdictul controlului pozitiv al parserului
-- CISA Vulnrichment primește rândul LUI în `intel_state`.
--
-- Verdictul „parserul nu mai vede puncte CISA" stătea în `intel_state.detail` al
-- rândului `vulnrichment`, iar `mirror.run_lookups` rescrie `detail` ÎNTREG la
-- sfârșitul oricărei treceri care a primit vreun răspuns: alarma ridicată de o
-- trecere era ștearsă de următoarea, adică în cel mult o oră. Pe rândul separat
-- `vulnrichment_canary` verdictul se schimbă doar când o nouă încercare a
-- controlului dă alt răspuns, iar `last_ok_at` al lui e ultima CONFIRMARE (controlul
-- a dat puncte), nu ultima trecere (vezi `sentinel/intel/vulnrichment.py`).
--
-- E o migrație nouă, nu o modificare a lui 0047/0048: migrațiile își țin checksum-ul
-- și sunt imuabile odată aplicate (`sentinel/db/migrate.py`), iar ambele sunt deja
-- aplicate pe ambele gazde. Schimbă doar lista surselor admise; nu atinge rânduri.
--
-- Fără ea, `mirror.record` ar eșua pe CHECK, iar eșecul lui e înghițit dinadins (un
-- jurnal de stare nu are voie să strice o scanare): verdictul nu s-ar scrie
-- niciodată, iar autoverificarea ar spune `unknown` la nesfârșit.

ALTER TABLE intel_state DROP CONSTRAINT intel_state_source_check;
ALTER TABLE intel_state ADD CONSTRAINT intel_state_source_check
    CHECK (source IN ('epss', 'redhat', 'osv', 'risk', 'vulnrichment',
                      'vulnrichment_canary'));
