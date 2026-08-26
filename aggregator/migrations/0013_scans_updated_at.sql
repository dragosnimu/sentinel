-- `scan_entries.updated_at`: coloana pe care o CERE cursorul mutabil.
--
-- ## De ce fluxul de scanări e mutabil, și de ce asta nu e o alegere de stil
--
-- Un rând din `scans` se scrie ca `running` și se COMPLETEAZĂ la final, cu
-- `status`, `finished_at` și numărătorile. Un cursor pe `id` l-ar prinde o
-- singură dată, în starea în care e la momentul ăla — adică fluxul ar expedia
-- „rulează" pentru totdeauna și n-ar arăta niciodată CUM s-a încheiat.
--
-- Exact informația care lipsea pe 21 august 2026: operatorul a văzut 31 de
-- vulnerabilități neaplicate în panou și nimic de actualizat pe server. Numărul
-- fusese măsurat la 03:23, pachetele reparate la 09:14, iar scanarea de la 10:33
-- — cea care le-ar fi închis — eșuase cu `timeout`. Eșecul acela nu ajungea
-- nicăieri, iar pagina arăta o cifră veche fără să spună nici că e veche, nici
-- de ce nu se mai împrospătează.
--
-- Coloana e NULL-abilă, ca la `incident_entries`: rândurile sosite înainte de
-- migrație n-au de unde s-o aibă, iar un `DEFAULT` ar inventa un moment. „Nu
-- știu când" e altceva decât „la 1970", și nu se contopesc.

-- @guard column scan_entries updated_at
ALTER TABLE scan_entries
    ADD COLUMN updated_at DATETIME(6) NULL
    COMMENT 'scans.updated_at de pe server; ordinea de expediere, nu ora sosirii';

-- @guard index scan_entries ix_scan_entries_updated
--
-- Ordinea în care sosesc rândurile unui flux mutabil e chiar asta. Nu e unic:
-- două instanțe pot avea același moment, iar identitatea rămâne
-- `(instance_id, source_id)`.
CREATE INDEX ix_scan_entries_updated
    ON scan_entries (instance_id, updated_at);
