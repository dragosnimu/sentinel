-- 0022_instance_identity: oglinda locală a identității instalării.
--
-- ## De ce există
--
-- Agregatorul extern primește de la N servere. Fără un identificator stabil per
-- instalare, rândurile a două gazde nu se pot deosebi, iar eșecul e tăcut în
-- ambele sensuri: două servere cu aceeași identitate se contopesc într-o
-- singură istorie, un server cu două identități se bifurcă în două. Niciunul
-- nu produce vreo eroare undeva — cifrele doar încetează să însemne ce spun.
--
-- ## Fișierul e autoritatea, tabela e oglinda
--
-- Valoarea se generează o singură dată, la instalare, în
-- `/etc/sentinel/instance_id` (0640 root:sentinel), și nu se regenerează
-- niciodată. Rândul de aici e o copie a ei.
--
-- Copia nu e redundanță, e martorul: un backup al bazei restaurat pe o mașină
-- clonată aduce datele lui A peste fișierul lui B. Fără o a doua reprezentare
-- pe care s-o contrazică, asta bifurcă tăcut un server în două pe agregator.
-- Comparația o face `check_instance_identity` din `sentinel/selfcheck/checks.py`
-- și nepotrivirea E constatarea.
--
-- ## De ce un singur rând, impus de schemă și nu prin convenție
--
-- `only_row boolean PRIMARY KEY CHECK (only_row)`: cheia primară admite o
-- singură valoare, iar CHECK-ul spune care e aia. Al doilea INSERT se lovește
-- de unicitate și eșuează; nu se așază tăcut lângă primul.
--
-- Convenția — „scriem doar un rând, avem grijă" — cedează exact în cazul pentru
-- care există tabela: două scrieri, două valori diferite, iar un `SELECT ... `
-- fără `ORDER BY` întoarce oricare dintre ele. Verificarea ar compara fișierul
-- cu un rând ales la întâmplare și ar raporta o nepotrivire într-o zi și niciuna
-- în următoarea.
--
-- ## De ce nu hostname și de ce nu /etc/machine-id
--
-- Hostname-ul se schimbă (redenumire, migrare, un panou care recreează VPS-ul),
-- iar identitatea schimbată e o istorie bifurcată. Pe un panou partajat e și
-- recunoaștere gratuită: spune cui se uită cum se cheamă mașinile operatorului.
--
-- `/etc/machine-id` e moștenit de o mașină clonată. Identitatea duplicată e
-- exact eșecul pe care valoarea aleatoare îl evită — și singurul care nu
-- produce niciun raport de defecțiune nicăieri.
--
-- ## De ce CHECK-ul de formă, și de ce exact acesta
--
-- `openssl rand -hex 16` produce 32 de caractere hexa minuscule. Orice altceva
-- în coloană e o scriere trunchiată sau o valoare pusă de mână, iar o identitate
-- trunchiată se coliziona cu alta la fel de trunchiată.
--
-- Aceeași expresie e scrisă în trei locuri — aici, în `sentinel/identity.py` și
-- în `ensure_instance_id` din `deploy/install.sh`.
-- `tests/security/test_instance_id_is_stable.py` le compară caracter cu
-- caracter, fiindcă o gramatică scrisă de două ori în două limbaje, fără nimic
-- care să le lege, e exact defectul livrat de 0015/0020.
--
-- Nu se scrie niciun rând aici. Migrația creează locul; oglinda se scrie de
-- codul care citește fișierul, care poate fi testat.

CREATE TABLE IF NOT EXISTS instance_identity (
    only_row     boolean     PRIMARY KEY DEFAULT true CHECK (only_row),

    instance_id  text        NOT NULL CHECK (instance_id ~ '^[0-9a-f]{32}$'),

    -- Când a văzut BAZA identitatea asta prima dată — nu momentul instalării.
    -- Diferența e utilă tocmai în cazul pe care tabela îl păzește: pe o bază
    -- restaurată, `first_seen` e din viața gazdei dinainte, iar asta e jumătate
    -- din răspunsul la „de unde a apărut identitatea asta aici".
    first_seen   timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE instance_identity IS
    'Oglinda identității instalării. Autoritatea e /etc/sentinel/instance_id; '
    'rândul ăsta există ca nepotrivirea dintre ele să fie observabilă. Un '
    'singur rând, impus de cheia primară pe only_row.';

COMMENT ON COLUMN instance_identity.instance_id IS
    'openssl rand -hex 16, generat o dată la instalare și niciodată regenerat. '
    'Nu e secret și nu e cheie: semnarea folosește SENTINEL_BEACON_SECRET.';
