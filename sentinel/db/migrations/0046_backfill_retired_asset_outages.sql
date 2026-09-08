-- 0046_backfill_retired_asset_outages: S6 — patru găuri deschise pe gazdă,
-- de la asset-uri retrase LUNI de zile în urmă.
--
-- ## Ce s-a măsurat
--
-- Pe gazda de producție, 4 rânduri în `outages` cu `ended_at IS NULL`,
-- toate pe `asset_id`-uri al căror `retired_at` e din august. Nu erau
-- servicii picate — erau servicii care nu mai există, dezinstalate, scoase
-- din `inventory.yaml` și retrase cu mult înainte ca `retire_missing`
-- (`sentinel/db/repo/assets.py`) să învețe să închidă și găurile odată cu
-- retragerea (fixul „go-forward" al aceleiași runde). Acel fix închide
-- corect orice retragere de ACUM ÎNAINTE — dar rulează o singură dată, la
-- retragere; cele patru retrageri deja întâmplate ÎNAINTE de fix au rămas
-- exact cum le-a lăsat codul vechi, permanent.
--
-- Costul e același ca-n 0032: uptime-ul unui activ retras și orice
-- interogare care numără găuri deschise poartă la nesfârșit un serviciu pe
-- care nimeni nu-l mai urmărește.
--
-- ## De ce doar atât, și nu mai mult
--
-- Migrația asta NU repetă logica lui `retire_missing` (păstrarea cauzei
-- reale de sondă, „(asset retired)" adăugat la coadă) — o repetă EXACT,
-- rând cu rând, din același motiv pentru care 0036 nu inventează o formulă
-- nouă pentru un backfill: comportamentul de-acum trebuie să fie
-- indistingibil de „ar fi fost închis la timp, de codul reparat".
--
-- `ended_at` ia valoarea `assets.retired_at`, nu `now()`: momentul real al
-- retragerii, nu momentul rulării acestei migrații — un `duration_s` calculat
-- din `now()` ar inventa o gaură cu câteva luni mai lungă decât a fost de
-- fapt.
--
-- ## De ce e sigur să ruleze din nou (și n-o va face fără efect a doua oară)
--
-- `WHERE o.ended_at IS NULL` exclude exact rândurile deja atinse — o a doua
-- rulare (schema_version resetat, ipotetic) ar da `UPDATE 0`, verificat mai
-- jos prin efect, nu prin codul de ieșire.
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '10s';

UPDATE outages o
   SET ended_at = a.retired_at,
       duration_s = GREATEST(0, EXTRACT(EPOCH FROM (a.retired_at - o.started_at))::int),
       cause = CASE WHEN o.cause IS NULL OR o.cause = '' THEN 'retired'
                    ELSE o.cause || ' (asset retired)' END
  FROM assets a
 WHERE o.asset_id = a.id
   AND a.retired_at IS NOT NULL
   AND o.ended_at IS NULL;

-- ## Garda: efectul, nu doar codul de ieșire zero
--
-- Un `UPDATE` reușit cu zero rânduri atinse ar însemna aici că filtrul n-a
-- găsit nimic de reparat — plauzibil doar dacă gazda chiar nu are găuri
-- vechi pe activi retrași. Nu se poate deosebi de un `WHERE` stricat (un
-- typo în `retired_at`, o comparație inversată) decât uitându-se la ce a
-- mai rămas deschis. Dacă mai există o gaură cu `ended_at IS NULL` pe un
-- activ retras după această comandă, migrația a „reușit" fără efect.
DO $$
DECLARE
    ramase bigint;
BEGIN
    SELECT count(*) INTO ramase
      FROM outages o
      JOIN assets a ON a.id = o.asset_id
     WHERE a.retired_at IS NOT NULL
       AND o.ended_at IS NULL;

    IF ramase > 0 THEN
        RAISE EXCEPTION
            'au rămas % găuri deschise pe active retrase după backfill — WHERE-ul UPDATE-ului nu a acoperit tot ce trebuia',
            ramase;
    END IF;
END $$;
