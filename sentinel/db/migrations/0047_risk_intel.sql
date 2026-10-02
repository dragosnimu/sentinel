-- 0047_risk_intel: oglinzile locale ale surselor de risc (EPSS, Red Hat, OSV) și
-- evaluarea SSVC a fiecărei constatări.
--
-- Până aici `findings.cvss` venea doar de la trivy, iar `findings.epss` nu venea
-- de nicăieri: pe producție, 6912 de constatări `dnf` fără niciun scor și nicio
-- constatare cu EPSS. `sentinel/scan/prioritize.py` consuma ambele câmpuri și
-- rămânea fără hrană. Culoarea nu mai iese dintr-o formulă, ci din arborele CISA
-- SSVC (`sentinel/scan/ssvc.py`); aici stau doar datele de care are nevoie.
--
-- ## Cele trei tabele de intrare, și de ce sunt oglinzi
--
-- Ca `kev_catalog`: se umplu din surse publice, o dată pe zi, și o scanare
-- citește din ele. Un feed căzut nu oprește scanarea — doar lasă constatările
-- fără datele lui, iar fără date culoarea e GRI, niciodată verde.
--
--   epss_scores   — fișierul zilnic FIRST, filtrat la CVE-urile pe care le avem.
--                   Un CVE cerut dar absent din fișier se scrie cu `epss` NULL:
--                   e un răspuns („EPSS nu-l cunoaște încă"), și fără el
--                   fiecare trecere ar descărca iar fișierul pentru el.
--   vuln_intel    — răspunsul Red Hat (pachete rpm) sau OSV (restul) pentru un
--                   id. `not_found` e și el un rând, din același motiv.
--   intel_state   — când a încercat fiecare sursă ultima oară, când a reușit,
--                   și ce a zis. Fără el „mirror-ul e vechi de nouă zile" și
--                   „mirror-ul e la zi dar n-are CVE-ul ăsta" arată la fel.

CREATE TABLE intel_state (
    source          text        PRIMARY KEY
                      CHECK (source IN ('epss', 'redhat', 'osv', 'risk')),
    last_attempt_at timestamptz,
    last_ok_at      timestamptz,
    last_error      text,
    detail          jsonb       NOT NULL DEFAULT '{}'::jsonb
);

COMMENT ON TABLE intel_state IS
    'Ultima încercare / ultimul succes al fiecărei surse de risc. `risk` e '
    'trecerea de evaluare însăși: last_ok_at = ultima dată când TOATE '
    'constatările deschise au fost evaluate.';

CREATE TABLE epss_scores (
    cve         text        PRIMARY KEY,
    -- Probabilitatea ca CVE-ul să fie exploatat în următoarele 30 de zile
    -- (FIRST), cu cinci zecimale cum o publică fișierul. NULL = absent din
    -- fișierul zilei `score_date`.
    epss        numeric(6,5) CHECK (epss IS NULL OR epss BETWEEN 0 AND 1),
    percentile  numeric(6,5) CHECK (percentile IS NULL OR percentile BETWEEN 0 AND 1),
    -- Ziua modelului (din antetul fișierului), NU ziua descărcării: așa se vede
    -- vechimea reală a unei valori.
    score_date  date,
    fetched_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((epss IS NULL) = (percentile IS NULL))
);

CREATE TABLE vuln_intel (
    -- CVE-xxxx sau GHSA-xxxx: OSV răspunde și pe id-uri GitHub, iar 10 din
    -- 17 avize GHSA deschise pe producție nu au niciun alias CVE.
    vuln_id        text        NOT NULL,
    source         text        NOT NULL CHECK (source IN ('redhat', 'osv')),
    status         text        NOT NULL CHECK (status IN ('found', 'not_found')),

    cvss_score     numeric(3,1) CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10),
    cvss_vector    text,
    cvss_version   text,
    -- Cuvântul sursei, netradus: Red Hat spune Low/Moderate/Important/Critical,
    -- GitHub spune LOW/MODERATE/HIGH/CRITICAL. Nu sunt aceeași scară.
    severity       text,
    -- Red Hat `statement`: justificarea scrisă a evaluării. Mărginită la
    -- scriere; vine din rețea și ajunge în Telegram și în panou.
    justification  text,
    aliases        text[]      NOT NULL DEFAULT '{}',
    advisories     text[]      NOT NULL DEFAULT '{}',
    fetched_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (vuln_id, source),
    CHECK (status = 'found' OR (cvss_score IS NULL AND cvss_vector IS NULL))
);

-- ---------------------------------------------------------------------------
-- Evaluarea, pe constatare
-- ---------------------------------------------------------------------------
-- `priority` rămâne, cu CHECK-ul și indexurile lui: e coloana după care ordonează
-- tot ce există (lista web, `generate_for_kev`, agregatorul, anunțul). Se
-- schimbă DOAR cine o scrie: de acum e derivată din (culoare, scor) de
-- `sentinel/scan/risk.py::priority_of`, nu din formula veche. Benzile:
--   Act 80..100 · Attend 60..79 · gri 40..59 · Track* 20..39 · Track 0..19.
-- Gri stă deasupra lui verde: un CVE fără scor nu e unul sigur.
--
-- Ce se întâmplă cu rândurile vechi: constatările NEREZOLVATE primesc aici
-- banda grie (40) până la prima evaluare, ca să nu rămână o prioritate din
-- formula veche lângă o culoare „fără date". Cele REZOLVATE își păstrează
-- numărul vechi: nimeni nu le ordonează, iar rescrierea lor ar ridica
-- `updated_at` pe ~6700 de rânduri și le-ar reexpedia pe toate.

ALTER TABLE findings
    ADD COLUMN epss_percentile numeric(5,4)
        CHECK (epss_percentile IS NULL OR epss_percentile BETWEEN 0 AND 1),
    -- Semaforul. Implicit `grey`: un rând care n-a fost niciodată evaluat nu
    -- are date, iar „fără date" nu e „verde".
    ADD COLUMN risk_color text NOT NULL DEFAULT 'grey'
        CHECK (risk_color IN ('red', 'amber', 'green', 'grey')),
    -- Decizia SSVC, după ajustarea pentru repornire. NULL ⇔ gri.
    ADD COLUMN risk_decision text
        CHECK (risk_decision IN ('act', 'attend', 'track_star', 'track')),
    -- probabilitate × impact, 0..1. Numărul după care se ordonează ÎN INTERIORUL
    -- unei culori. NULL când nu se poate calcula (gri).
    --
    -- `numeric`, NU `real`: expeditorul către martorul extern refuză un `float`
    -- (`shipper.encode_value`: nu se poate semna identic la ambele capete), iar
    -- o coloană refuzată oprește fluxul `findings` ÎNTREG, vizibil doar ca o
    -- restanță crescândă în `ship:lag`. `Decimal` pleacă drept șir, exact.
    ADD COLUMN risk_score numeric(6,5)
        CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 1),
    -- Tot ce stă în spatele culorii: cele patru puncte de decizie și sursa
    -- fiecăruia, CVSS-ul ales și de unde, EPSS cu percentilă, justificarea
    -- furnizorului, ce lipsește. Schema e în `risk.py` (`SCHEMA_VERSION`).
    ADD COLUMN risk jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Când s-a schimbat ultima oară conținutul evaluării (NU când a fost
    -- recalculată: o evaluare neschimbată nu se rescrie, ca triggerul de
    -- `updated_at` să nu reexpedieze rândul degeaba). NULL = niciodată evaluată.
    ADD COLUMN risk_changed_at timestamptz,
    -- Când a fost anunțat că a devenit roșu. Se pune O DATĂ: un EPSS care
    -- oscilează în jurul unui prag nu poate redeschide canalul.
    ADD COLUMN risk_red_announced_at timestamptz;

-- `IS NOT NULL` explicit pe fiecare ramură cu decizie, nu `= 'act'` singur: un
-- CHECK trece când expresia e NULL, iar `NULL = 'act'` e NULL — adică „verde cu
-- decizie NULL" ar fi trecut, exact combinația pe care constrângerea există să
-- o refuze. Prins de `tests/integration/test_risk_intel_pg.py`.
ALTER TABLE findings ADD CONSTRAINT findings_risk_color_matches_decision CHECK (
       (risk_color = 'grey'  AND risk_decision IS NULL)
    OR (risk_color = 'red'   AND risk_decision IS NOT NULL AND risk_decision = 'act')
    OR (risk_color = 'amber' AND risk_decision IS NOT NULL AND risk_decision = 'attend')
    OR (risk_color = 'green' AND risk_decision IS NOT NULL
                             AND risk_decision IN ('track', 'track_star'))
);

UPDATE findings SET priority = 40
WHERE status IN ('open', 'patch_planned', 'patching', 'deferred');

CREATE INDEX findings_open_risk_idx
    ON findings (priority DESC, risk_score DESC NULLS LAST)
    WHERE status = 'open';
