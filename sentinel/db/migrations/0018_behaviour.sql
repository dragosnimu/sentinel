-- 0018_behaviour: profilul de comportament normal al gazdei.
--
-- Regulile de detecție prind ce am știut să descriu dinainte. Profilul prinde
-- ce nu am știut: „lucrul ăsta nu s-a mai întâmplat niciodată aici".
--
-- ## De ce noutate, nu volum
--
-- Baza de date are deja `baselines`: mediană și MAD sezonier pe volum, cu 14
-- zile de încălzire. Răspunde la „e mai mult trafic decât de obicei?" — bună
-- pentru inundații, oarbă pentru compromitere. Un atacator care se
-- autentifică o dată, cu credențiale furate, dintr-o țară în care nu ai fost
-- niciodată, nu mișcă niciun volum.
--
-- Compoziția se schimbă înaintea volumului. Un utilizator care nu a mai apărut,
-- un ASN nou pentru o autentificare reușită, un binar care nu s-a executat
-- niciodată pe gazda asta — fiecare e o singură observație, iar volumul rămâne
-- plat. De asta profilul e o MULȚIME de chei văzute, nu o serie de numere.
--
-- Consecința practică pe care a cerut-o operatorul: noutatea devine utilă după
-- câteva zile, nu după paisprezece. Ai nevoie de destule observații ca să știi
-- ce e normal, nu de destule ca să estimezi o distribuție.

CREATE TABLE behaviour_profiles (
    dimension     text        NOT NULL,
    key           text        NOT NULL,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    observations  bigint      NOT NULL DEFAULT 1,
    -- Marcat de operator: „știu, e al meu". Rămâne în profil, nu mai alertează
    -- niciodată, și se vede că a fost o decizie umană, nu o învățare tăcută.
    acknowledged  boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (dimension, key)
);

CREATE INDEX behaviour_profiles_dim_idx   ON behaviour_profiles (dimension, last_seen DESC);
CREATE INDEX behaviour_profiles_first_idx ON behaviour_profiles (dimension, first_seen);

-- Starea de învățare, per dimensiune.
--
-- Ținută separat de profil fiindcă răspunde la altă întrebare: profilul spune
-- CE s-a văzut, asta spune DACĂ am văzut destul cât să am dreptul să alertez.
-- Fără poarta asta, prima zi de rulare ar produce o alertă pentru fiecare
-- utilizator, fiecare ASN și fiecare binar de pe server — adică sute — și ar
-- învăța operatorul, din prima zi, să ignore canalul.
CREATE TABLE behaviour_learning (
    dimension     text        PRIMARY KEY,
    started_at    timestamptz NOT NULL DEFAULT now(),
    observations  bigint      NOT NULL DEFAULT 0,
    distinct_keys bigint      NOT NULL DEFAULT 0,
    -- Setat de cod când ambele praguri sunt atinse. Persistat, nu recalculat:
    -- o dimensiune care a devenit caldă nu are voie să redevină rece dacă
    -- retenția taie observațiile vechi.
    warm_at       timestamptz
);

-- Rata de chei noi pe oră, per dimensiune.
--
-- A doua întrebare, cea pe care o pune operatorul: „s-a schimbat BRUSC
-- comportamentul?". După încălzire, rata de chei noi tinde spre zero — un
-- server matur nu descoperă utilizatori noi în fiecare oră. O rafală de chei
-- noi în aceeași oră e o schimbare de compoziție, chiar dacă fiecare cheie în
-- parte ar putea avea o explicație nevinovată.
--
-- Ținut ca serie, nu calculat la cerere, fiindcă fereastra de comparație e
-- propriul istoric al dimensiunii și partițiile de evenimente se elimină prin
-- retenție cu mult înaintea lui.
CREATE TABLE behaviour_novelty_rate (
    dimension  text        NOT NULL,
    bucket     timestamptz NOT NULL,   -- trunchiat la oră
    new_keys   integer     NOT NULL DEFAULT 0,
    total_obs  integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (dimension, bucket)
);

CREATE INDEX behaviour_novelty_rate_bucket_idx ON behaviour_novelty_rate (bucket DESC);
