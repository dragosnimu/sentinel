-- 0024_scans_watermark: rulările de scanare capătă filigran, ca să poată pleca.
--
-- ## Eșecul din care a ieșit migrația asta
--
-- Pe 21 august 2026 operatorul s-a uitat în panou, a văzut 31 de vulnerabilități
-- neaplicate, a rulat `dnf update` pe server și n-a găsit nimic de actualizat.
-- Panoul nu greșea numărul: îl măsurase la 03:23, iar pachetele fuseseră reparate
-- la 09:14. Între cele două a mai rulat o scanare, la 10:33 — și A EȘUAT, cu
-- `timeout`. Reușită, ea ar fi închis toate cele 31.
--
-- Eșecul acela n-a ajuns nicăieri: nici pe Telegram, nici în panou, nici într-o
-- verificare de sănătate. Rândul din `scans` îl spunea, dar tabela aia nu pleacă
-- de pe gazdă. Deci pagina de vulnerabilități arăta o cifră veche, fără să spună
-- că e veche și fără să spună că încercarea de a o reîmprospăta căzuse.
--
-- ## De ce coloana asta, și de ce trigger
--
-- Un rând din `scans` se scrie ca `running` și se COMPLETEAZĂ la final, cu
-- `status`, `finished_at` și numărătorile. Un cursor pe `id` l-ar prinde o
-- singură dată, în starea în care e la momentul ăla — adică fluxul ar expedia
-- „rulează" pentru totdeauna și n-ar arăta niciodată că s-a încheiat, cu atât
-- mai puțin CUM. Exact informația care lipsea.
--
-- Deci filigran pe `(updated_at, id)`, ca la celelalte entități mutabile, cu
-- același trigger. `set_updated_at()` există deja din 0023; aici doar se leagă.
--
-- Indexul poartă perechea întreagă, în ordinea în care o citește expedierea.

ALTER TABLE scans ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
DROP TRIGGER IF EXISTS scans_set_updated_at ON scans;
CREATE TRIGGER scans_set_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX scans_updated_idx ON scans (updated_at, id);
