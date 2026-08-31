-- 0039_incident_campaigns: unitatea de citire nu mai e incidentul, e campania.
--
-- ## De ce `incident_campaigns`, nu `campaigns`
--
-- `0008_baselines.sql` a creat deja o tabelă `campaigns` — clustering de
-- actori pe /24, ASN, user agent, JA4, secvență de căi și timing, parte din
-- stratul de predicție. E în schemă din faza P6 dar nicio linie de cod din
-- `sentinel/` n-o citește sau n-o scrie (verificat: zero potriviri pentru
-- `risk_score`, `ai_narrative`, `max_stage`, `actor_keys` în afara migrației
-- ei) — o funcționalitate proiectată în schemă, neconstruită încă în Python.
--
-- Gruparea de aici e alta: pe FAMILIA regulii care a produs incidentul, nu pe
-- asemănarea dintre actori. Un `CREATE TABLE campaigns` ar fi picat direct cu
-- „relation campaigns already exists" pe orice instalare care a trecut de
-- 0008 — adică pe toate. Numele nou evită coliziunea fără să atingă tabela
-- din 0008, care rămâne exact cum era, pentru ziua în care clustering-ul de
-- actori chiar se implementează.
--
-- ## Problema, măsurată pe gazdă (31 august 2026)
--
-- 968 de incidente deschise, unul pe (adresă, regulă, fereastră de 15 minute).
-- Nimeni nu citește 968 de rânduri, iar cel care contează se ascunde printre
-- cele 960 care nu contau. Gruparea pe rețea a fost măsurată și respinsă
-- înainte să ajungă cod: pe (familie, /24, zi) ies 822 de grupuri din 968, pe
-- (familie, ASN, zi) ies 391 — ambele aproape inutile. Cele 510 incidente
-- `ids.suricata` vin de la 510 actori distincți, fiecare din altă rețea: nu e
-- o campanie per rețea, e zgomot de fond de pe internet lovind același front.
-- Gruparea pe FAMILIA regulii (partea dinaintea primului `:` din
-- `fingerprint`) reduce cele 968 la 14 campanii, iar cele 67 vii din ultimele
-- 24h la 5. `asset_id` e NULL pe 967 din 968 și n-ar adăuga nimic la cheie.
--
-- ## De ce campania e o tabelă, nu o coloană calculată
--
-- „Familia curentă" a unui incident se poate calcula oricând din
-- `fingerprint` (`split_part(fingerprint, ':', 1)`), dar „câte incidente și
-- câți actori distincți sunt ACUM în fața asta" nu se poate fără o agregare
-- peste toate incidentele, la fiecare încărcare de pagină. O tabelă cu
-- contoare recalculate la fiecare atașare (vezi
-- `sentinel/db/repo/incident_campaigns.py:attach_incident`) mută costul de la
-- citire (de zeci de ori pe zi) la scriere (o dată pe detecție).
--
-- ## Indexul unic parțial e piesa centrală
--
-- Oglindește deliberat `incidents_fingerprint_open_idx` din
-- `0001_core.sql:268`: o singură campanie ACTIVĂ per familie, impusă de bază,
-- nu de cod. `attach_incident` se sprijină pe el pentru
-- `INSERT ... ON CONFLICT (campaign_key) WHERE status = 'active'` — fără
-- index, ar fi un SELECT-apoi-INSERT care pierde o cursă între două detecții
-- simultane pe aceeași familie.
--
-- O campanie `quiet` NU se reactivează, din același motiv ca la incidente
-- (0001, și `close_stale_incidents` din `maintenance_service.py`): indexul
-- acoperă doar `active`, deci activitate nouă pe o familie liniștită deschide
-- o campanie NOUĂ. Un front care tace o zi și revine e un eveniment, nu o
-- continuare.
--
-- ## Ce NU face migrația asta
--
-- Nu populează nimic retroactiv. Incidentele existente rămân cu
-- `campaign_id = NULL` și se leagă de mecanismul normal pe măsură ce primesc
-- activitate nouă — o reluare a aceleiași regului trece din nou prin
-- `upsert_incident`, care cheamă `attach_incident`. Un backfill ar inventa
-- acum 14 campanii peste 901 incidente care nu mai primesc nimic — zgomot, nu
-- informație: ce contează e ce e ÎN CURS, nu o etichetă pusă retroactiv peste
-- ce s-a închis deja.
--
-- ## Lacătul
--
-- `ALTER TABLE incidents ADD COLUMN` ia `ACCESS EXCLUSIVE` pe `incidents`
-- până la COMMIT. Pe gazda asta tabela are ~2700 de rânduri, deci lacătul se
-- ia și se dă drumul practic instant — dar tratamentul ăsta NU se transferă la
-- o tabelă mare: acolo `ACCESS EXCLUSIVE` ține blocate și citirile, nu doar
-- scrierile, cât durează comanda. Următorul care copiază tiparul ăsta pe o
-- tabelă mare trebuie să măsoare, nu să presupună.
--
-- ## De ce nu CONCURRENTLY
--
-- `sentinel/db/migrate.py` rulează fiecare fișier într-o singură tranzacție,
-- iar PostgreSQL refuză „CONCURRENTLY" într-o tranzacție (25001) — aceeași
-- constrângere ca la 0019/0030/0031/0033/0037. Index obișnuit; tabela e goală
-- la momentul migrației, deci lacătul e scurt.

CREATE TABLE incident_campaigns (
    id                bigserial   PRIMARY KEY,
    campaign_key      text        NOT NULL,
    status            text        NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'quiet', 'closed')),
    severity          text        NOT NULL
                        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title             text        NOT NULL,
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_activity_at  timestamptz NOT NULL DEFAULT now(),
    incident_count    integer     NOT NULL DEFAULT 0,
    actor_count       integer     NOT NULL DEFAULT 0,
    quieted_at        timestamptz,
    closed_at         timestamptz
);

COMMENT ON TABLE incident_campaigns IS
    'Gruparea pe familie de regulă a incidentelor în curs. Nu e tabela `campaigns` din 0008 (clustering de actori, neimplementat încă). Vezi sentinel/db/repo/incident_campaigns.py.';

-- Piesa centrală: o singură campanie ACTIVĂ per familie, impusă de bază.
CREATE UNIQUE INDEX incident_campaigns_key_active_idx
    ON incident_campaigns (campaign_key) WHERE status = 'active';

ALTER TABLE incidents ADD COLUMN campaign_id bigint REFERENCES incident_campaigns(id) ON DELETE SET NULL;

-- Fără el, recalcularea membrilor unei campanii (incident_count/actor_count
-- din attach_incident, la fiecare detecție) ar scana toată tabela `incidents`.
CREATE INDEX incidents_campaign_idx ON incidents (campaign_id);

-- ## Garda: ce a rămas în catalog, nu ce s-a cerut
--
-- Aceleași capcane plătite deja la 0032/0033/0037: catalogul poate arăta
-- „există" pentru ceva construit greșit — fără UNIQUE, pe altă coloană, fără
-- predicatul corect, sau INVALID dintr-un CONCURRENTLY întrerupt de mână.
DO $$
DECLARE
    definitie text;
    e_bun     boolean;
BEGIN
    SELECT pg_get_indexdef(i.indexrelid), i.indisvalid AND i.indisready
      INTO definitie, e_bun
      FROM pg_index i
      JOIN pg_class ci ON ci.oid = i.indexrelid
      JOIN pg_class ct ON ct.oid = i.indrelid
     WHERE ci.relname = 'incident_campaigns_key_active_idx'
       AND ct.relname = 'incident_campaigns';

    IF definitie IS NULL THEN
        RAISE EXCEPTION
            'incident_campaigns_key_active_idx nu există pe incident_campaigns după CREATE INDEX';
    END IF;

    IF definitie !~ 'CREATE UNIQUE INDEX' THEN
        RAISE EXCEPTION
            'incident_campaigns_key_active_idx nu e UNIC — o singură campanie activă per familie nu mai e garantată de bază: %',
            definitie;
    END IF;

    IF definitie !~ '\(campaign_key\)' THEN
        RAISE EXCEPTION
            'incident_campaigns_key_active_idx nu e pe campaign_key: %', definitie;
    END IF;

    IF definitie !~ 'status = ''active''' THEN
        RAISE EXCEPTION
            'incident_campaigns_key_active_idx nu e parțial pe status = ''active'' — ON CONFLICT din attach_incident nu mai are pe ce indice să se sprijine: %',
            definitie;
    END IF;

    IF NOT e_bun THEN
        RAISE EXCEPTION
            'incident_campaigns_key_active_idx există dar e INVALID — un CREATE INDEX CONCURRENTLY întrerupt. Ștergeți-l și reluați migrația.';
    END IF;
END $$;

-- Coloana de legătură, verificată la fel: tipul și cheia străină, nu doar
-- prezența numelui.
DO $$
DECLARE
    tip    text;
    are_fk boolean;
BEGIN
    SELECT format_type(a.atttypid, a.atttypmod)
      INTO tip
      FROM pg_attribute a
      JOIN pg_class c ON c.oid = a.attrelid
     WHERE c.relname = 'incidents'
       AND c.relkind = 'r'
       AND a.attname = 'campaign_id'
       AND a.attnum > 0
       AND NOT a.attisdropped;

    IF tip IS NULL THEN
        RAISE EXCEPTION 'incidents.campaign_id nu există după ALTER TABLE';
    END IF;

    IF tip <> 'bigint' THEN
        RAISE EXCEPTION 'incidents.campaign_id are tipul %, nu bigint', tip;
    END IF;

    SELECT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'incidents'::regclass
           AND contype = 'f'
           AND confrelid = 'incident_campaigns'::regclass
    ) INTO are_fk;

    IF NOT are_fk THEN
        RAISE EXCEPTION
            'incidents.campaign_id nu are cheie străină către incident_campaigns — un id orfan ar trece nedetectat';
    END IF;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_index i
        JOIN pg_class ci ON ci.oid = i.indexrelid
        JOIN pg_class ct ON ct.oid = i.indrelid
        WHERE ct.relname = 'incidents' AND ci.relname = 'incidents_campaign_idx'
          AND i.indisvalid AND i.indisready
    ) THEN
        RAISE EXCEPTION
            'incidents_campaign_idx lipsește sau e invalid — recalcularea membrilor unei campanii ar scana toată tabela incidents';
    END IF;
END $$;
