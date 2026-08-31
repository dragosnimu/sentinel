-- 0041_ask_log: rate limit pentru /intreaba.
--
-- Comanda cheamă modelul de DOUĂ ori (interpretarea întrebării, apoi formularea
-- răspunsului), deci apăsată în buclă ar multiplica costul de două ori mai
-- repede decât orice altă comandă din bot. `ask_rate_limit_per_hour` există în
-- `AIConfig` din schema inițială și n-a fost citit de nimic până acum — tabela
-- asta e ce-i lipsea ca să însemne ceva.
--
-- Un rând per încercare ACCEPTATĂ (adică ajunsă până la primul apel către
-- model), nu per mesaj primit: o comandă respinsă la plafon nu costă nimic și
-- nu trebuie să se numere singură ca să prelungească propriul refuz.
CREATE TABLE ask_log (
    id       bigserial   PRIMARY KEY,
    chat_id  bigint      NOT NULL,
    asked_at timestamptz NOT NULL DEFAULT now()
);

-- Interogarea de rată citește "câte în ultima oră pentru chat-ul ăsta" — un
-- index pe (chat_id, asked_at) face asta o căutare, nu o scanare a tabelei
-- întregi pe măsură ce crește.
CREATE INDEX ask_log_chat_idx ON ask_log (chat_id, asked_at DESC);
