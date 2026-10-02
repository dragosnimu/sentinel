-- 0048_vulnrichment: oglinda locală a punctelor SSVC PUBLICATE de CISA
-- (programul Vulnrichment) — Exploitation, Automatable, Technical Impact.
--
-- Până aici cele trei puncte erau DEDUSE: Automatable și Technical Impact dintr-un
-- vector CVSS (euristici), Exploitation dintr-un prag EPSS (o PREVIZIUNE luată drept
-- OBSERVAȚIE). CISA publică valorile ei pentru fiecare CVE pe care l-a evaluat, în
-- chiar înregistrarea CVE (containerul ADP „CISA-ADP"), fără cheie:
--     https://cveawg.mitre.org/api/cve/<CVE>
-- Cu valoarea publicată, euristica rămâne doar pentru CVE-urile pe care CISA nu
-- le-a evaluat (măsurat pe gazda de producție, 2 octombrie 2026: CISA a publicat puncte pentru
-- 196 din cele 406 CVE-uri distincte deschise = 48,3%, cu acoperire foarte diferită pe ecosistem:
-- npm 78/78, composer 36/36, go 45/57, alpine 13/16, deb 13/185 (7%), rpm 6/32 (19%)).
--
-- E o migrație nouă, nu o modificare a lui 0047: migrațiile își țin checksum-ul și
-- sunt imuabile odată aplicate (`sentinel/db/migrate.py`), iar 0047 ar putea fi
-- aplicat deja undeva.
--
-- ## Ce înseamnă un rând
--
--   status = 'found'      CVE-ul există în înregistrarea CVE. Punctele pot fi toate
--                         NULL: CISA nu l-a evaluat (încă). Asta e un răspuns
--                         („nepublicat"), diferit de „nu l-am întrebat niciodată"
--                         (niciun rând) — și risc.py le tratează diferit.
--   status = 'not_found'  API-ul a răspuns 404 (CVE rezervat, sau cu alt id).
--
-- `ssvc_at` e MOMENTUL în care CISA a făcut evaluarea, nu cel al descărcării:
-- Exploitation e o fotografie. CVE-2025-29927 are `none` din 8 aprilie 2025,
-- cu EPSS 0,992 în octombrie 2026. Vechimea trebuie să se vadă, nu să se ascundă.

ALTER TABLE intel_state DROP CONSTRAINT intel_state_source_check;
ALTER TABLE intel_state ADD CONSTRAINT intel_state_source_check
    CHECK (source IN ('epss', 'redhat', 'osv', 'risk', 'vulnrichment'));

CREATE TABLE vulnrichment (
    cve              text        PRIMARY KEY,
    status           text        NOT NULL CHECK (status IN ('found', 'not_found')),
    -- Vocabularul SSVC al arborelui „CISA Coordinator", nu al nostru: orice altă
    -- valoare e refuzată la scriere (`vulnrichment.parse`), nu stocată.
    exploitation     text        CHECK (exploitation IN ('none', 'poc', 'active')),
    automatable      text        CHECK (automatable IN ('yes', 'no')),
    technical_impact text        CHECK (technical_impact IN ('partial', 'total')),
    ssvc_at          timestamptz,
    ssvc_version     text,
    fetched_at       timestamptz NOT NULL DEFAULT now(),

    CHECK (status = 'found' OR (exploitation IS NULL AND automatable IS NULL
                                AND technical_impact IS NULL AND ssvc_at IS NULL))
);
