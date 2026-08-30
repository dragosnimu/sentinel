-- 0038_reputation_entries: unde stau adresele/intervalele efective ale
-- feed-urilor de reputație — 0006 a adus `intel_feeds` (numele, URL-ul,
-- întrerupătorul de circuit), dar nimic nu descria CE conține un feed.
--
-- ## De ce o tabelă separată, nu o coloană array pe `intel_feeds`
--
-- Un feed poate avea zeci de mii de intrări (un array Postgres de zeci de mii
-- de `cidr` pe un singur rând ar fi rescris integral la fiecare
-- reîmprospătare, sub un UPDATE care ține lock pe rândul din `intel_feeds` —
-- exact rândul pe care `refresh_intel` din `maintenance_service.py` îl cere
-- pentru fiecare feed, la fiecare oră). O tabelă cu o intrare pe rând permite
-- `DELETE ... WHERE feed_name = $1` + `INSERT` în lot, ambele scurte, și
-- `ON DELETE CASCADE` curăță automat dacă un feed e vreodată șters din
-- `intel_feeds`.
--
-- ## De ce `cidr`, nu `inet`
--
-- O intrare e fie o adresă unică (stocată ca rețea /32 sau /128 — exact ce
-- `cidr` cere: fără biți de gazdă), fie un interval real ca la Spamhaus DROP.
-- Ambele forme sunt "o rețea", niciodată "o gazdă cu mască", deci `cidr`
-- interzice la nivel de tip exact greșeala pe care ar permite-o `inet`.
--
-- ## Ce NU face migrația asta
--
-- Nu inserează niciun feed și nici nu activează vreunul — `intel_feeds` a
-- pornit goală la 0006 și rămâne goală aici. Feed-urile propuse (Spamhaus
-- DROP pentru `drop`, blocklist.de pentru `botnet`/`compromised`, lista de
-- exit noduri a proiectului Tor pentru `tor`) sunt argumentate în docstring-ul
-- lui `sentinel/intel/reputation.py` și în predarea funcționalității — nu
-- aici, ca un URL scris într-o migrație SQL să nu pară "deja pornit" doar
-- fiindcă a ajuns în schemă.

CREATE TABLE intel_feed_entries (
    feed_name   text NOT NULL REFERENCES intel_feeds(name) ON DELETE CASCADE,
    network     cidr NOT NULL,
    PRIMARY KEY (feed_name, network)
);

-- Pentru DELETE-ul care precede fiecare reîmprospătare și pentru CASCADE.
CREATE INDEX intel_feed_entries_feed_idx ON intel_feed_entries (feed_name);
