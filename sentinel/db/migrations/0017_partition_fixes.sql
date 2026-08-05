-- 0017_partition_fixes: reparații în funcțiile de mentenanță din 0007.
--
-- Funcțiile astea au fost scrise în 0007 și nu au fost executate niciodată:
-- serviciul care le apelează lipsea din build, deci timerul eșua din oră în oră
-- înainte să ajungă la ele. Prima rulare reală, pe 5 august 2026, a picat pe
-- amândouă.
--
-- Merită spus limpede: SQL care există și se aplică fără eroare la instalare nu
-- e SQL care funcționează. Nimic nu îl exercita, deci nimic nu îl contrazicea.
--
-- Migrația schimbă DOAR definiții de funcții. Nu mută niciun rând. Rândurile
-- rămase blocate în partițiile DEFAULT se recuperează de serviciul de
-- mentenanță, plafonat, la fiecare rulare — o migrație care mută milioane de
-- rânduri în timpul unui deploy e o fereastră de indisponibilitate pe care
-- nimeni nu a cerut-o.

-- ---------------------------------------------------------------------------
-- 0. Coloana de partiționare
-- ---------------------------------------------------------------------------
-- Citită din catalog, nu presupusă. Toate trei tabelele partiționate folosesc
-- `ts` azi; a scrie `ts` în cod ar face funcțiile să mintă tăcut în ziua în care
-- una nu o mai face.
--
-- `partattrs` e `int2vector`, al cărui indice de bază nu e același lucru cu al
-- unui array obișnuit. Trecerea prin text și cast la smallint[] scoate întrebarea
-- din discuție.
CREATE OR REPLACE FUNCTION sentinel_partition_key(parent text)
RETURNS text AS $$
    SELECT a.attname
    FROM pg_partitioned_table pt
    JOIN pg_class c     ON c.oid = pt.partrelid
    JOIN pg_attribute a ON a.attrelid = c.oid
     AND a.attnum = (string_to_array(pt.partattrs::text, ' ')::smallint[])[1]
    WHERE c.relname = parent;
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------------------
-- 1. Ambiguitatea `n`
-- ---------------------------------------------------------------------------
-- `DECLARE n integer` se ciocnește cu coloana `n` din event_rollup_1m. În
-- `SET n = EXCLUDED.n`, PL/pgSQL nu poate decide dacă `n` din stânga e variabila
-- sau coloana, și refuză:
--
--     column reference "n" is ambiguous
--
-- Variabila se redenumește. Alternativa, `#variable_conflict use_column`, ar
-- rezolva simptomul lăsând capcana în loc pentru următorul care declară o
-- variabilă cu numele unei coloane.
CREATE OR REPLACE FUNCTION sentinel_rollup_events_1m(
    from_ts timestamptz,
    to_ts   timestamptz
) RETURNS integer AS $$
DECLARE
    rows_written integer;
BEGIN
    INSERT INTO event_rollup_1m (bucket, asset_id, source, action, n, uniq_src,
                                 bytes_in, bytes_out, p95_latency_ms)
    SELECT date_trunc('minute', ts),
           COALESCE(asset_id, 0),
           source,
           action,
           count(*),
           count(DISTINCT src_ip),
           COALESCE(sum(bytes_in), 0),
           COALESCE(sum(bytes_out), 0),
           percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms)::integer
    FROM raw_events
    WHERE ts >= from_ts AND ts < to_ts
    GROUP BY 1, 2, 3, 4
    ON CONFLICT (bucket, asset_id, source, action) DO UPDATE
        SET n = EXCLUDED.n,
            uniq_src = EXCLUDED.uniq_src,
            bytes_in = EXCLUDED.bytes_in,
            bytes_out = EXCLUDED.bytes_out,
            p95_latency_ms = EXCLUDED.p95_latency_ms;

    GET DIAGNOSTICS rows_written = ROW_COUNT;
    RETURN rows_written;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sentinel_rollup_events_1h(
    from_ts timestamptz,
    to_ts   timestamptz
) RETURNS integer AS $$
DECLARE
    rows_written integer;
BEGIN
    INSERT INTO event_rollup_1h (bucket, asset_id, source, action, n, uniq_src,
                                 bytes_in, bytes_out, p95_latency_ms)
    SELECT date_trunc('hour', bucket),
           asset_id,
           source,
           action,
           sum(n),
           -- Unicii nu se pot însuma peste minute: aceeași sursă apare în mai
           -- multe minute și ar fi numărată de mai multe ori. `max` subestimează,
           -- dar o subestimare cunoscută bate o supraestimare care arată la fel
           -- de bine ca un adevăr.
           max(uniq_src),
           sum(bytes_in),
           sum(bytes_out),
           max(p95_latency_ms)
    FROM event_rollup_1m
    WHERE bucket >= from_ts AND bucket < to_ts
    GROUP BY 1, 2, 3, 4
    ON CONFLICT (bucket, asset_id, source, action) DO UPDATE
        SET n = EXCLUDED.n,
            uniq_src = EXCLUDED.uniq_src,
            bytes_in = EXCLUDED.bytes_in,
            bytes_out = EXCLUDED.bytes_out,
            p95_latency_ms = EXCLUDED.p95_latency_ms;

    GET DIAGNOSTICS rows_written = ROW_COUNT;
    RETURN rows_written;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- 2. Crearea unei partiții când DEFAULT ține deja rânduri din acea zi
-- ---------------------------------------------------------------------------
-- Rândurile ajung în DEFAULT când partiția zilei lipsește — adică exact ce s-a
-- întâmplat cât timp mentenanța nu a rulat. Iar odată ajunse acolo:
--
--     updated partition constraint for default partition "raw_events_default"
--     would be violated by some row
--
-- Postgres refuză să atașeze o partiție al cărei interval e acoperit de rânduri
-- din DEFAULT, fiindcă ar exista două locuri valide pentru același rând.
--
-- Blocajul se auto-întreține: cu cât rămâne mai mult nereparat, cu atât DEFAULT
-- crește. Iar DEFAULT nu e atins de retenție — el conține fix datele sosite cât
-- ceva era stricat, deci a-l arunca ar șterge dovezile perioadei.
--
-- Reparația e mutarea rândurilor, într-o singură tranzacție:
--   a) tabel liber, cu structura părintelui;
--   b) rândurile zilei se mută din DEFAULT în el;
--   c) CHECK identic cu intervalul partiției — fără el, ATTACH scanează tot
--      tabelul ca să se convingă; cu el, validarea e instantanee;
--   d) ATTACH, apoi CHECK-ul redundant se elimină.
--
-- Dacă orice pas cade, tranzacția se derulează înapoi și rândurile rămân în
-- DEFAULT. Nicio cale prin funcția asta nu pierde un eveniment.
CREATE OR REPLACE FUNCTION sentinel_create_partition(
    parent  text,
    day     date
) RETURNS text AS $$
DECLARE
    part_name text := format('%s_%s', parent, to_char(day, 'YYYYMMDD'));
    def_name  text := format('%s_default', parent);
    key_col   text := sentinel_partition_key(parent);
    stranded  bigint := 0;
BEGIN
    IF to_regclass(part_name) IS NOT NULL THEN
        RETURN part_name;
    END IF;
    IF key_col IS NULL THEN
        RAISE EXCEPTION 'sentinel_create_partition: % nu e o tabelă partiționată', parent;
    END IF;

    IF to_regclass(def_name) IS NOT NULL THEN
        EXECUTE format('SELECT count(*) FROM %I WHERE %I >= %L AND %I < %L',
                       def_name, key_col, day, key_col, day + 1)
        INTO stranded;
    END IF;

    IF stranded = 0 THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
            part_name, parent, day, day + 1);
        RETURN part_name;
    END IF;

    RAISE NOTICE 'sentinel_create_partition: mut % rânduri din % în %',
                 stranded, def_name, part_name;

    EXECUTE format(
        'CREATE TABLE %I (LIKE %I INCLUDING DEFAULTS INCLUDING CONSTRAINTS INCLUDING STORAGE)',
        part_name, parent);
    EXECUTE format(
        'WITH moved AS (DELETE FROM %I WHERE %I >= %L AND %I < %L RETURNING *)
         INSERT INTO %I SELECT * FROM moved',
        def_name, key_col, day, key_col, day + 1, part_name);
    EXECUTE format(
        'ALTER TABLE %I ADD CONSTRAINT %I CHECK (%I >= %L AND %I < %L)',
        part_name, part_name || '_range', key_col, day, key_col, day + 1);
    EXECUTE format('ALTER TABLE %I ATTACH PARTITION %I FOR VALUES FROM (%L) TO (%L)',
                   parent, part_name, day, day + 1);
    -- Redundant după ATTACH: partiția își are limitele din definiție. Păstrat,
    -- ar fi două constrângeri care spun același lucru, verificate la fiecare
    -- insert pentru totdeauna.
    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', part_name, part_name || '_range');

    RETURN part_name;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- 3. Ce zile stau blocate în DEFAULT
-- ---------------------------------------------------------------------------
-- Serviciul de mentenanță întreabă asta la fiecare rulare și golește câteva zile
-- odată. Aici e doar interogarea; mutarea se face de sus, plafonat, ca să nu
-- existe o singură operație lungă și neîntreruptibilă.
CREATE OR REPLACE FUNCTION sentinel_default_partition_days(parent text)
RETURNS TABLE (day date, rows_in_default bigint) AS $$
DECLARE
    def_name text := format('%s_default', parent);
    key_col  text := sentinel_partition_key(parent);
BEGIN
    IF key_col IS NULL OR to_regclass(def_name) IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY EXECUTE format(
        'SELECT %I::date AS day, count(*)::bigint
           FROM %I GROUP BY 1 ORDER BY 1', key_col, def_name);
END;
$$ LANGUAGE plpgsql;
