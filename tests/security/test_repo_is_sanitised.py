r"""Depozitul e public. Nimic din infrastructura reală nu are voie să ajungă în el.

Regula nu e despre jenă, e despre ce câștigă cineva citind. Un depozit de
securitate spune deja, exact, ce se monitorizează și cum. Adăugând adrese,
domenii și nume de utilizator, spune și PE CINE — iar recunoașterea, care e
partea scumpă a unui atac, devine gratuită.

Cazul cel mai important e domeniul martorului extern. E singura mașină pe care
un atacator cu root pe serverul monitorizat NU o controlează, deci e primul
lucru pe care ar vrea să-l afle: unde pleacă semnalul a cărui absență îl dă de
gol. A stat într-un fișier de documentație până a fost observat.

Testul rulează peste tot ce ar ajunge într-un push — urmărit sau
neurmărit-și-neignorat — și peste ambele versiuni ale fiecărui fișier, cea de pe
disc și cea din index. Depinde de `git`; fără el ar trece în tăcere, deci lipsa
lui e eșec.

## Limita cunoscută: UTF-16

Un fișier scris în UTF-16 (PowerShell 5.1 face asta la redirectare) se decodează
ca octeți intercalați cu NUL, deci o adresă IP din el nu se mai potrivește.
Scris aici fiindcă o limită nedocumentată e cea care mușcă: verificarea nu
raportează nimic, iar tăcerea ei arată identic cu „e curat".

## Limita cunoscută: verificarea pe valoare are nevoie de magazia locală

`test_no_value_from_the_local_secret_store_appears_in_the_tree` compară arborele
cu valorile reale din `secrets/.env.local` — fișier ignorat de git, deci absent
pe o clonă proaspătă. Acolo testul se raportează SKIP, nu verde: „n-am putut
verifica" și „e curat" sunt stări diferite.

`addopts` din `pyproject.toml` conține `-rfEs` tocmai ca MOTIVUL skip-ului să
apară. Fără el, tot semnalul pe o altă mașină era cifra „1 skipped" dintr-o linie
de sumar — adică o propoziție scrisă cu grijă pe care n-o citea nimeni.

`-rfEs`, nu `-rs`: `-r` ÎNLOCUIEȘTE lista implicită (`fE`), deci un `-rs` singur
ar fi ascuns liniile „FAILED ...". Scris și aici, nu doar în `pyproject.toml`,
fiindcă un comentariu rămas în urmă e cum se reintroduce un bug reparat: cineva
aliniază configurația la el.

Pe mașina de pe care pleacă push-ul fișierul există. Nimic nu IMPUNE însă ca
push-ul să plece de acolo: nu e instalat niciun hook (`.git/hooks` are doar
`.sample`), `core.hooksPath` nu e setat. Garanția e disciplina operatorului, nu
un mecanism — scris aici fiindcă o garanție presupusă e cea care cedează.

Consecința: `pytest -m security` poate arăta un skip pe o mașină fără secrete,
deși `README.md` și `docs/TESTARE.md` cer ca testele de securitate să nu fie
sărite. Skip-ul spune exact ce nu s-a verificat; alternativa — să treacă verde
fără să se uite la nimic — e chiar tiparul pe care fișierul ăsta îl păzește.

## Secretele se caută pe VALOARE, nu pe numele de lângă

Garda de secrete a fost, până pe 15 august 2026, o pereche „nume care sugerează
un secret" + „valoare lungă imediat după". A fost respinsă de două ori, în
aceeași direcție, și de fiecare dată reparația a îngustat tiparul ca să omoare o
alarmă falsă. Găurile rămase, MĂSURATE, nu presupuse:

  - `{"<id de 16 caractere>":"<hexa de 64>"}` — ghilimeaua care închide NUMELE
    rupea înșiruirea, deci cei 32 de caractere neîntrerupți se puteau potrivi
    doar pe identificator. Corpusul „dovedea" forma cu un identificator de exact
    32, în timp ce `watcher/.env.example` documentează identificatori de 16;
  - `"secret": "<hexa de 64>",` și `{"bot_token": "<hexa de 64>"}` — orice JSON
    cu cheia în ghilimele, din același motiv;
  - `"beacon_secret": <hexa de 64>` — YAML cu cheia în ghilimele;
  - `SENTINEL_BEACON_SECRET=<base64url>` — alfabetul cerut nu avea `-` și `_`.

Cauza nu e niciunul din cele patru cazuri, e că tiparul și corpusul care îl
dovedea aveau același autor în aceeași ședință: nu se puteau falsifica reciproc.
Fiecare rundă îngusta tiparul, iar corpusul era scris ca să treacă.

Deci se caută VALOAREA: orice înșiruire de cel puțin 32 de caractere din
alfabetul unei valori generate — hexa, base64 (`+/`) și base64url (`-_`) —
oriunde în fișier, indiferent ce e lângă ea. Numele nu mai contează, deci nu mai
poate fi scris altfel decât se aștepta.

### Ce decide dacă o înșiruire e un secret, și ce pierde regula

Alfabetul singur nu e destul: `test_no_value_from_the_local_secret_store...` are
61 de caractere din el, și tot depozitul e plin de nume la fel de lungi. Măsurat
pe 15 august 2026, peste tot arborele: 2506 înșiruiri de peste 32 de caractere
sunt nume scrise de om. Deci se cere, în plus, forma unei valori GENERATE:

  - hexazecimal curat — `openssl rand -hex 16/32`, adică exact ce cere procedura
    de instalare a martorului, și orice sumă sau amprentă; SAU
  - literă mică ȘI literă mare ȘI cifră în aceeași înșiruire — compoziția pe care
    o are, practic sigur, orice ieșire base64 sau base64url; SAU
  - alfabetul base32, o singură cutie plus cifrele 2-7, ȘI cel puțin o cifră.
    Clauza asta nu e ipotetică: `sentinel/web/security.py:217` e
    `pyotp.random_base32()`, sămânța TOTP a contului de administrator al
    panoului web, 32 de caractere majuscule — o singură cutie, deci regula de
    compoziție n-o vede, și nu e hexa, deci nici cealaltă. Costul ei, măsurat
    peste tot arborele: ZERO înșiruiri noi, în ambele cutii, iar de pe 15 august
    2026 numărul ăla e fixat de
    `test_the_base32_clause_still_costs_the_measured_zero` în loc să fie o
    propoziție. Cerința de cifră e a doua jumătate și are prețul ei scris în
    `_secret_shape`: fără ea, `[a-z2-7]+` potrivește orice propoziție lipită, iar
    arborele are deja un literal de 31 de caractere minuscule; SAU
  - hexazecimal curat DUPĂ eliminarea cratimelor — adică un UUID. 122 de biți de
    entropie și o formă comună de jeton API, pe care nicio clauză de mai sus n-o
    vede: cratimele îl scot din „hexa curat", iar un `uuid4()` minuscul n-are
    literă mare. Costul, măsurat peste tot arborele ÎNAINTE de a fi adăugată: o
    SINGURĂ potrivire nouă, UUID-ul sintetic de zerouri din
    `tests/unit/test_patch_runner.py`, care are scutire numită. Se raportează ca
    `hexa`, fiindcă asta e.

Regula e o regulă de FORMĂ, nu o îngustare de alfabet: alfabetul rămâne întreg,
se cere doar ca înșiruirea să arate a valoare generată, nu a propoziție. Prețul
ei se poate calcula, deci e scris aici și nu presupus:

  - `openssl rand -base64 24` (32 de caractere) nu conține nicio cifră o dată la
    ~230 de generări, iar `secrets.token_urlsafe(32)` (43) o dată la ~1500. Alea
    trec. Lipsa unei litere mari sau mici e sub una la zece milioane;
  - o parolă-frază scrisă de om, dintr-o singură cutie, fără cifră și fără
    separator, nu e văzută deloc. Rămâne singura gaură deschisă din familia asta,
    și e deschisă dinadins: singura regulă care ar prinde-o e „orice înșiruire
    lungă dintr-o singură cutie", adică exact cea care a fost măsurată la 2506
    fals-pozitive pe arborele ăsta. Niciun generator din depozit nu produce așa
    ceva, iar o valoare pe care doar un om o poate scrie n-are formă proprie;
  - o valoare base32 scrisă cu litere MICI și ieșită fără nicio cifră 2-7 — o
    dată la ~770 de generări, dacă cineva ar scrie-o vreodată așa. Preț plătit
    conștient pentru cerința de cifră din cutia mică, care apără împotriva prozei
    lipite; cutia MARE, în care scrie `pyotp.random_base32()`, nu cere nimic în
    plus și e acoperită întreagă. Vezi `_secret_shape`.

`=` e tratat ca umplutură de coadă, niciodată ca literă din interior. În base64
aia e singura lui poziție, iar în restul depozitului `=` e chiar ce desparte
numele de valoare. Fără distincția asta `NUME_DE_VARIABILA=<64 de zerouri>` ar fi
o singură înșiruire, cu compoziția NUMELUI — adică exact secretul pe care garda
îl caută, ascuns de propriul lui nume.

### Alarmele false se sting NUMIT, nu prin îngustare

O scutire e vizibilă, motivată și localizată; o îngustare de tipar e tăcută și
globală, și exact așa s-au deschis cele patru găuri de mai sus. Sunt două
feluri, amândouă cu motivul scris:

  - `VALUE_SHAPE_EXEMPT` — reguli de formă, valabile oriunde. Una singură azi:
    sumele de integritate SRI din `package-lock.json`, 181 de bucăți, care sunt
    amprentele unor artefacte PUBLICE;
  - `VALUE_EXEMPT` — fișiere care conțin vectori de aur, sume de control fixate
    sau material sintetic de forma unui secret. Fiecare intrare poartă NUMĂRUL
    de înșiruiri măsurat în fișier, iar garda cere egalitate pe MAXIMUL dintre
    versiunile fișierului (discul și indexul): una în plus e ceva nou de privit,
    iar zero e o gardă care a încetat să vadă. A doua stare e cea care contează —
    un tipar stricat tăcut arată identic cu un depozit curat. Maximul, și nu
    fiecare versiune separat, fiindcă în timpul unei editări cele două diferă
    legitim, iar o gardă care țipă la lucru corect e o gardă comentată la 22:00.

Și drumul dintre ele — bucla peste fișiere, aritmetica scutirilor, aplicarea
tiparelor de format — e cod, deci are nevoie de teste ca oricare altul. Măsurat
pe 15 august 2026: patru mutații în el treceau verzi pe suita întreagă, cu un
secret hexa de 64 de caractere plantat în arbore. De aceea `_scan_tree_for_secrets`
ia enumerarea și cititorul ca argumente: ca să poată fi condus pe un arbore
fabricat, nu doar pe cel real.

### Domeniul scanării: pe linie, plus literalii lipiți peste linie

Se scanează linie cu linie, fiindcă mesajul de eșec trebuie să spună UNDE.
Formatul cu perechi al lui `SENTINEL_INSTANCE_SECRETS` acceptă linia nouă ca
separator, deci liniile 2..n ale unei valori n-au niciun cuvânt lângă ele — dar
poartă fiecare propria valoare, iar garda pe valoare le vede pe toate. Măsurat
înainte: din trei chei pe trei linii, garda veche raporta una.

Ce nu vede o scanare pe linie e un literal SPART în două linii, cum îl scrie
formatarea automată în Python și în TypeScript. Pentru asta se mai face o
trecere peste text cu literalii alăturați PESTE O LINIE NOUĂ lipiți — doar
peste linie nouă, nu oriunde: lipirea oricăror două ghilimele alăturate ar
transforma `["deadbeef", "cafebabe", "12345678", "abcdef01"]` într-o înșiruire
hexa de 32 și ar da alarmă falsă. Potrivirile din trecerea asta se raportează cu
linia `0`, „în fișier, linie nesigură", ca la verificarea pe valoare. Măsurat
peste tot arborele: trecerea a doua nu adaugă nicio potrivire azi, deci nu
plătește nimeni pentru ea.

### Corpusul nu se mai scrie de mână

Formele de probă se EXTRAG din fișierele care le documentează
(`_FORM_SOURCES`), cu valorile înlocuite cu cifre în ordine și cu un tipar
base64url evident sintetic. Efectul cerut: o formă documentată în depozit pe
care garda n-o vede pică testul automat, fără să depindă de cine s-a gândit s-o
adauge în corpus. Ce NU poate extractorul e scris la `_documented_secret_forms`.

## De ce NU există o verificare „numărul ăsta pare un chat id"

A existat una, o rundă: un număr lipit de un nume care conține „chat", acceptat
doar dacă era o fixtură cunoscută. Măsurată pe forme realiste, rata ei de ratare
a fost 21 din 28 — un indice (`allowed_chat_ids[0] == <id>`), un sufix
(`chat_id_2`), un argument pozițional (`send_message(<id>, ...)`), un id scris
ÎNAINTEA cuvântului, un nume fără „chat" în el (`TELEGRAM_OWNER_ID`), un antet de
tabel `psql` cu valoarea pe rândul de sub. Iar alarma falsă: 17 din 19 linii
legitime — `"chat_last_seen": <timestamp>`, `CHAT_HISTORY_MAX_BYTES`,
`SELECT chat_id ... WHERE created_at > <timestamp>`, până și `chat_id = 1000000`,
adică exact pragul pe care comentariul ei îl declara inofensiv.

Cauza nu e o expresie regulată prost scrisă, e că un chat id nu are formă
proprie: zece cifre, nedeosebite de un timestamp, de un port sau de o dimensiune.
Cele două erori nu pot scădea simultan — tot ce lărgește acoperirea lărgește și
zgomotul. O gardă care ratează majoritatea formelor și țipă la lucru corect nu e
o jumătate de protecție: e încredere fără acoperire, iar prima ei consecință
practică e cineva care o comentează la 22:00 ca să-și poată face treaba.

Deci se verifică VALOAREA: ori valoarea reală e în text, ori nu e. Fals pozitiv
nu are cum să dea. Ratări are — nu pe „numele de lângă", ci pe REPREZENTĂRI ale
aceleiași valori, iar alea se pot enumera, ceea ce o euristică de context nu
poate. Cele acoperite sunt în `_searchable_forms` și în testul lui.

Rămân ratate, știut și scris ca să nu fie descoperit de cineva la a treia
scurgere:

  - literalii adunați într-o listă, `["555", "000", "1111"]` — lipirea lor ar
    cere ștergerea oricărei virgule dintre ghilimele, adică lipirea oricăror
    două elemente alăturate din orice tablou din depozit;
  - continuarea de linie în interiorul unui literal: un backslash urmat imediat
    de newline, între ghilimele;
  - zerourile din față (`0005550001111`) — ilegale ca literal zecimal în Python,
    posibile în alte formate;
  - valorile DERIVATE, nu copiate: un id de supergrup `-100` + id, un hash, o
    codificare base64. Verificarea caută valoarea, nu funcții de ea.

Prețul celălalt e dependența de magazia locală, iar el e scris mai sus — nu
ascuns sub un nume de test care promite mai mult.

## Identitatea operatorului: numele de utilizator și domeniul înregistrabil

Două găuri măsurate pe 14 august 2026, amândouă în arbore, niciuna în istoric:

  - numele de utilizator nu era acoperit deloc. `FORBIDDEN` avea un singur tipar
    (adrese IPv4 publice), `SECRETS` cheile și jetoanele. Contul de shell al
    operatorului apărea de 25 de ori în patru fișiere — căi `/home/<nume>`
    copiate din înregistrări auditd reale, un `ssh <nume>@gazdă` dintr-o
    procedură, o listă de conturi. Un `git add -A` le publica pe toate;
  - garda domeniului martorului cerea prefixul `sentinel.`, deci prindea
    `sentinel.<domeniu>.<tld>` și lăsa să treacă `<domeniu>.<tld>` gol. Forma
    care trecea e cea mai utilă atacatorului: din domeniul înregistrabil,
    subdomeniul martorului iese dintr-un jurnal de transparență a certificatelor
    în câteva secunde. Măsurat: subdomeniul apărea de 0 ori, domeniul gol de 16.

Verificarea nouă e pe VALOARE, din același motiv scris mai jos pentru chat id: o
euristică de formă („ce arată a nume de utilizator") n-are cum să deosebească
numele operatorului de `deploy`, nici domeniul lui de `example.com` — sunt
identice ca formă. Garda pe formă a domeniului rămâne exact atât cât poate
acoperi, subdomeniul, și spune asta în docstring-ul ei, ca nimeni să n-o creadă
completă.

Valorile vin din aceeași magazie locală, `secrets/.env.local`, sub două chei noi
(`IDENTITY_KEYS`). Nu se inventează un al doilea mecanism: e același fișier,
același parser, aceeași disciplină „valorile nu părăsesc cadrul".

Diferența față de restul magaziei: cheile astea nu sunt secrete pe care le
citește produsul, ci valori pe care garda trebuie să le CAUTE. Consecința
practică e că `deploy/install.sh` le primește pe stdin ca pe orice altă linie și
avertizează o dată per cheie că nu le scrie — corect, dar zgomot. Scris aici
fiindcă alternativa (un al doilea fișier de magazie) ar fi rupt semantica pe care
se sprijină testul de mai jos: „magazia există" ÎNSEAMNĂ „mașina asta e cea a
operatorului".

De aici cele două stări, care nu se confundă:

  - magazia LIPSEȘTE (clonă proaspătă, mașina altcuiva) — SKIP cu motivul scris,
    la fel ca verificarea pe valoare de mai jos. Nu există nimic de protejat
    acolo, iar un eșec ar antrena pe oricine clonează depozitul să scoată testul;
  - magazia EXISTĂ dar cheile lipsesc, sunt goale sau prea scurte — EȘEC, cu
    cheile enumerate. Aici garda chiar are ce face și nu i s-a spus ce; „am
    verificat zero valori" nu are voie să arate ca verde.

### Ce reprezentări se acoperă, și de ce nu celelalte

`_identity_matcher` acoperă, pentru fiecare valoare:

  - forma verbatim — acoperă singură calea (`/home/<nume>/.ssh`), URL-ul
    (`https://<domeniu>/contact`), `ssh <nume>@gazdă` și proza, fiindcă în toate
    valoarea e scrisă neschimbată;
  - punctul rescris: `%2E`/`%2e` (cale ajunsă într-un URL) și `\.` (fixtură de
    expresie regulată sau tipar de grep — depozitul e plin de amândouă);
  - valoarea inversată. Nu e o ipoteză: `docs/landing-sentinel.html` scrie adresa
    de e-mail ca `data-d="<domeniu inversat>"`, trucul obișnuit contra
    recoltatoarelor. O gardă care nu vede inversarea ar fi raportat curat exact
    fișierul care conținea domeniul de două ori în plus;
  - literalii alăturați, prin `_searchable_forms`, ca la secrete;
  - diferența de majuscule. DNS-ul e insensibil la ea, deci scrierea de marcă a
    unui domeniu (`ExempluFirmă.ro`) e același domeniu, iar un nume de cont
    scris cu majusculă la început e același nume în proză.
    Rândul ăsta a conținut, prima oară, chiar domeniul real, ca „exemplu" de
    scriere de marcă. L-a prins garda de mai jos, la prima ei rulare — de aceea
    `test_no_operator_identity_appears_in_the_tree` NU se scutește pe sine, spre
    deosebire de gărzile pe tipar, care sar peste fișierul ăsta fiindcă tiparele
    lor s-ar potrivi cu ele însele.

Rămân neacoperite, știut:

  - punctul ȘTERS de tot, adică numele de cont scris fără el. Nu e o rescriere a
    aceleiași valori, e alt identificator — contul de GitHub — iar el apare în
    `README.md` și `docs/DEPLOYMENT.md` în chiar comanda `git clone` prin care
    cititorul a obținut depozitul. A-l cere șters ar fi o redactare care nu
    ascunde nimic de nimeni, în timp ce contul de pe gazdă are nevoie de punct
    ca să fie un login valid și o cale `/home/` validă;
  - valorile DERIVATE — hash, base64, punycode. Același motiv ca la secrete:
    verificarea caută valoarea, nu funcții de ea;
  - valoarea spartă într-o variabilă de șablon (`/home/{user}`) — nu mai există
    nimic de potrivit;
  - numele de firmă fără TLD, care apare de ~22 de ori în cele două fișiere de
    prezentare comercială și duce la același domeniu printr-o singură căutare. E
    o alegere de acoperire, nu o scăpare: un cuvânt de marcă nu are formă
    proprie, deci nu poate fi cerut de o regulă. Dacă operatorul vrea și marca
    scoasă, cuvântul se adaugă pur și simplu în `SANITISE_DOMAINS` — garda îl
    caută atunci ca pe orice altă valoare, fără nicio schimbare de cod.

## Valorile reale nu au voie să existe într-o variabilă locală de test

`pytest -l` (`--showlocals`) randează variabilele locale ale FIECĂRUI cadru din
traceback. O primă variantă ținea `{cheie: valoare}` chiar în funcția de test:
mesajul de eșec nu tipărea nimic, dar `-l` tipărea parola de producție integral.
Iar momentul în care rulezi `-l` e exact momentul în care garda tocmai a picat.

De aceea scanarea stă în `_scan_secret_store`, care se întoarce cu ȘIRURI deja
formatate și nu asertează niciodată: când aserțiunea din test eșuează, cadrul
care a ținut valorile nu mai e pe stivă.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest

# Poarta documentata in docs/TESTARE.md e `pytest -m security`. Fisierul vecin
# a primit marcajul in aceeasi runda; asta, care apara scurgerea de
# infrastructura, ramasese fara.
pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]

# Tipare, nu valori: valorile reale n-au ce căuta nici într-un test. Fiecare
# intrare e o clasă de lucruri care nu au voie să apară, cu motivul ei.
FORBIDDEN: dict[str, str] = {
    # Adrese publice reale. Exclude documentația (RFC 5737/3849), spațiul privat
    # și loopback — acelea sunt exact ce TREBUIE folosit în exemple.
    r"\b(?!0\.)(?!10\.)(?!127\.)(?!169\.254\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)"
    r"(?!192\.168\.)(?!192\.0\.2\.)(?!198\.51\.100\.)(?!203\.0\.113\.)"
    r"(?!22[4-9]\.|23\d\.)(?!25[0-5]\.)"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b":
        "adresă IP publică reală — folosește 192.0.2.x / 198.51.100.x / 203.0.113.x",

    # Chei și jetoane cu formă recunoscută.
}

# Se aplică PESTE TOT, inclusiv în teste. Un secret într-o fixtură e la fel de
# scurs ca unul în cod.
SECRETS: dict[str, str] = {
    r"sk-ant-[A-Za-z0-9_-]{10,}": "cheie API Anthropic",
    # {30,}, nu {35}: forma reala e 35, dar o potrivire care depinde de o
    # lungime exacta rateaza orice varianta si da aceeasi bifa verde.
    r"\b\d{8,10}:[A-Za-z0-9_-]{30,}": "token de bot Telegram",
    # Doua puncte incluse in clasa: un token de Telegram atribuit unei variabile
    # numite ...TOKEN se opreste altfel la primul `:`, adica dupa zece cifre.
    #
    # Aici raman doar tiparele de FORMAT — cele care recunosc un secret dupa cum
    # arata el, nu dupa numele de langa. Al treilea tipar, „valoare lunga langa un
    # nume care sugereaza un secret", a fost scos pe 15 august 2026: motivul e in
    # docstring-ul modulului, sectiunea „Secretele se cauta pe VALOARE". Ce
    # acoperea el si nu mai acopera nimeni: o valoare de peste 32 de caractere
    # dintr-o singura cutie, care nu e nici hexa (`TOKEN=zzzz…`). Un generator nu
    # produce asa ceva; un om care isi scrie parola in cod, da.
}

# --- Forma unei valori generate ---------------------------------------------
#
# Alfabetul unei valori generate: hexa, base64 (`+/`), base64url (`-_`) si
# base32 (majuscule si cifrele 2-7). `=` intra doar ca umplutura la coada —
# motivul e in docstring-ul modulului si e cel care decide daca `NUME=<valoare>`
# se citeste ca doua lucruri sau ca unul.
#
# `={0,6}`, nu `={0,2}`: base64 umple cu cel mult doua, base32 cu pana la SASE.
# Masurat: `base64.b32encode(os.urandom(21))` are 34 de caractere de corp si sase
# de umplutura, iar cu plafonul la doi potrivirea esua de tot — nu se scurta, nu
# se potrivea deloc, fiindca lookahead-ul vedea un `=` dupa.
#
# Fara lookbehind, si asta nu e o scapare: lookahead-ul interzice ca o potrivire
# sa se termine cand urmeaza un caracter din clasa, deci fiecare potrivire merge
# pana la capatul insiruirii maximale, deci NICIO potrivire nu poate incepe
# imediat dupa un caracter din clasa. Un lookbehind ar fi o echivalenta moarta —
# masurata ca atare de verificator pe 400 000 de siruri — iar o cale redundanta e
# o cale care se poate sterge cu suita verde, adica o falsificare care nu
# dovedeste nimic.
_SECRET_RUN = re.compile(r"[A-Za-z0-9+/_-]{32,}={0,6}(?![A-Za-z0-9+/=_-])")

_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")
# Base32, pe CUTII SEPARATE, fiindca pretul lor nu e acelasi. `pyotp.random_base32()`
# — samanta TOTP a contului de administrator al panoului web,
# `sentinel/web/security.py:217` — da 32 de caractere MAJUSCULE, adica fix
# pragul: o singura cutie, deci regula de compozitie nu o vede, si nu e hexa,
# deci nici cealalta.
#
# Cutia mica cere in plus o cifra 2-7 (vezi `_secret_shape`), cea mare nu. Motivul
# e masurat, nu simetric: `[a-z2-7]+` se ciocneste de proza lipita — arborele are
# chiar acum un literal de 31 de caractere minuscule in
# `aggregator/tests/instances.route.test.ts`, la UN caracter de prag — iar
# `[A-Z2-7]+` nu se ciocneste de nimic: cea mai lunga insiruire de majuscule
# masurata pe tot arborele are 26 de caractere (alfabetul scris intreg, intr-un
# test). O cerinta de cifra pusa si pe cutia mare ar fi costat o samanta TOTP din
# ~770 fara sa cumpere nimic masurabil.
_BASE32_UPPER = re.compile(r"[A-Z2-7]+")
_BASE32_LOWER = re.compile(r"[a-z2-7]+")

# Reguli de forma care sting o insiruire ORIUNDE ar aparea ea. Una singura azi.
# Fiecare are motivul scris: o regula fara motiv devine, in sase luni, gaura.
VALUE_SHAPE_EXEMPT: dict[str, str] = {
    # `"integrity": "sha512-…"` din package-lock.json, 181 de bucati masurate.
    # E amprenta unui artefact PUBLIC, publicata de npm chiar pentru a fi citita;
    # nu deschide nimic si nu spune nimic despre gazda. Prefixul e cerut ancorat
    # la inceputul insiruirii, deci regula nu poate stinge decat exact forma asta.
    r"^sha(?:1|256|384|512)-[A-Za-z0-9+/]+={0,2}$":
        "sumă de integritate SRI — amprenta unui artefact public, nu un secret",
}

# Compilate o data, la incarcarea modulului. Un `functools.lru_cache(maxsize=None)`
# pe o functie fara argumente facea acelasi lucru mai complicat, si aducea un
# `UP033` in plus fata de HEAD.
_VALUE_SHAPE_EXEMPT_RX = tuple(re.compile(p) for p in VALUE_SHAPE_EXEMPT)

# Literali alaturati despartiti DOAR de o trecere la linie noua: `"…"\n  "…"` in
# Python, `"…" +\n  "…"` in TypeScript. Vezi docstring-ul modulului pentru de ce
# nu se lipesc ghilimelele alaturate de pe ACEEASI linie.
_JOINED_LITERALS = re.compile(r"[\"']\s*\+?\s*\r?\n\s*[\"']")

# Extensii binare și directoare care nu sunt cod scris de noi.
SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".mmdb",
               ".woff", ".woff2", ".zip", ".gz"}
SKIP_PREFIX = ("watcher/node_modules/", "aggregator/node_modules/", "dist/")

# Scutiri numite, cu motiv. O scutire fără motiv scris devine, în șase luni,
# locul prin care trece exact lucrul pe care testul îl păzea.
EXEMPT: dict[str, str] = {
    # Verifică refuzul blocurilor prea largi. `1.0.0.0/8` TREBUIE să fie un
    # interval public real — un vector din spațiul de documentație n-ar dovedi
    # nimic despre ce se întâmplă când cineva cere blocarea unui optime din
    # internet. Sunt argumente respinse, nu adrese configurate.
    "tests/security/test_executor_policy.py":
        "vectori de test pentru refuzul CIDR-urilor prea largi",
}

# Numele celor două forme de valoare generată. Sunt chei în `VALUE_EXEMPT`, deci
# stau într-o constantă: o scutire scrisă cu numele greșit n-ar stinge nimic și
# nici n-ar spune că nu stinge — testul de mai jos verifică și numele.
SHAPE_HEX = "hexa"
SHAPE_B64 = "base64"
SHAPE_B32 = "base32"
SHAPES = (SHAPE_HEX, SHAPE_B64, SHAPE_B32)

# Scutiri pe FIȘIER pentru garda de valoare, fiecare cu forma, numărul măsurat și
# motivul. Numărul e o măsurătoare, nu o estimare: dacă fișierul ajunge să aibă
# mai multe înșiruiri decât acoperă scutirea, garda le raportează pe toate.
#
# Regula e EGALITATE pe maximul dintre versiuni — vezi docstring-ul lui
# `_unexempted_value_hits`, unde e argumentată. Ce PIERDE alegerea asta, scris ca
# să nu fie descoperit la a treia scurgere: o valoare SCHIMBATĂ cu alta într-un
# fișier deja scutit. Adăugarea e acoperită, fiindcă spațiul liber e zero.
# Contra „garda a orbit" nu apără numărul, ci
# `test_every_value_exemption_still_earns_its_place`, care cere ca fiecare
# scutire să mai stingă ceva.
#
# Blocul de aici a susținut până pe 15 august 2026 exact contrariul — „cel mult,
# nu exact", cu motivul că egalitatea ar țipa la orice editare în curs. Codul
# spunea deja altceva, iar afirmația s-a dovedit falsă la măsurare: regula tace
# prin toate stările intermediare (disc 1 / index 1, index absent, index 0,
# disc 0 / index 1) și se declanșează doar la o schimbare reală de număr.
# Comentariul rămâne aici ca avertisment, fiindcă un comentariu rămas în urmă e
# felul în care se reintroduce un bug reparat: cineva aliniază codul la el.
VALUE_EXEMPT: dict[str, tuple[dict[str, int], str]] = {
    # Vectorii de aur ai contractului de semnare: intrarea, forma ei canonică și
    # HMAC-ul calculat cu o cheie de test scrisă în clar chiar lângă ei
    # (`GOLDEN_SECRET = "cheie-de-test…"`). Sunt IEȘIRI ale unei funcții, nu chei:
    # publicarea lor nu deschide nimic, iar schimbarea lor rupe exact testul care
    # dovedește că Python și TypeScript produc aceiași octeți.
    "tests/fixtures/canonical-corpus.json": ({SHAPE_HEX: 18}, "vectori de aur canonici"),
    # Vectorul comun al plicului de transport, de pe 25 august 2026. Aceeași
    # formă și același argument ca vectorii canonici de deasupra: sunt IEȘIRI ale
    # unor funcții, nu chei. Hexa e HMAC-ul peste conținut, calculat cu o cheie
    # de test scrisă în clar chiar lângă el, în același fișier
    # (`"secret": "cheie-de-expediere-fixtura"`); base64-ul e corpul canonic
    # comprimat — decomprimat, îi poți citi conținutul, care e un lot fabricat de
    # `session_commands`. Forma lor TREBUIE să fie cea reală: e chiar ce probează
    # `aggregator/tests/envelope.test.ts`, adică faptul că partea TypeScript
    # citește octeți produși de partea Python.
    "tests/fixtures/transport-envelope.json":
        ({SHAPE_HEX: 1, SHAPE_B64: 1}, "vector de aur al plicului de transport"),
    "tests/unit/test_signing.py": ({SHAPE_HEX: 5}, "vectori de aur canonici"),
    "tests/unit/test_beacon.py": ({SHAPE_HEX: 2}, "vector de aur canonic"),
    "aggregator/tests/canonical.test.ts": ({SHAPE_HEX: 4}, "vectori de aur canonici"),
    "aggregator/tests/signature.test.ts": ({SHAPE_HEX: 5}, "vectori de aur canonici"),

    # Identități și chei de test, toate vizibil sintetice (`0123456789abcdef` de
    # două ori, `aaaa…bbbb…`, `"0".repeat(32)`). Nu sunt ale nimănui, iar forma
    # lor TREBUIE să fie cea reală: un identificator de altă lungime n-ar mai
    # dovedi nimic despre ce acceptă `ensure_instance_id`.
    "tests/security/test_instance_id_is_stable.py": ({SHAPE_HEX: 5}, "identități de test"),
    "tests/unit/test_identity_mirror.py": ({SHAPE_HEX: 2}, "identități de test"),
    "tests/unit/test_instance_identity.py": ({SHAPE_HEX: 2}, "identități de test"),
    "tests/unit/test_shipper.py": ({SHAPE_HEX: 1}, "identitate de test"),
    # Doua siruri fabricate ca sa ARATE a secret, fiindca exact asta se probeaza:
    # ca redactarea taie un token pus ca argument pozitional, si ca NU taie o
    # suma de control care e chiar dovada cautata. Nu deschid nimic — sunt
    # intrarile unei functii pure, iar forma lor trebuie sa fie cea reala.
    "tests/unit/test_redact.py": ({SHAPE_HEX: 1, SHAPE_B64: 1},
                                  "material sintetic pentru probarea redactarii"),
    # `bash -c systemctl restart sentinel-web`, scris cu octetii lui — asa scrie
    # auditd orice argument care contine un spatiu. E INTRAREA testului care
    # dovedeste ca hexa se decodifica, deci forma lui trebuie sa fie cea reala;
    # decodificat, ii poti citi continutul chiar in fisier.
    "tests/unit/test_auditd_sessions.py": ({SHAPE_HEX: 1},
                                           "un argv codificat hexa de auditd, "
                                           "intrarea probei de decodificare"),
    # Singura potrivire pe care a adus-o clauza UUID, măsurată pe tot arborele
    # ÎNAINTE ca ea să fie scrisă: `plan_id` al unui plan de patch fabricat,
    # `00000000-0000-0000-0000-000000000001` — zerouri și un unu, adică vizibil
    # sintetic, într-un dublu de bază de date.
    "tests/unit/test_patch_runner.py": ({SHAPE_HEX: 1}, "UUID sintetic de plan de test"),
    "aggregator/tests/crypto.test.ts":
        ({SHAPE_HEX: 2, SHAPE_B64: 1},
         "chei de test sintetice, plus alfabetul base64url scris ca literal"),
    "aggregator/tests/sync-harness.ts": ({SHAPE_HEX: 1}, "cheie de test sintetică"),
    # A doua potrivire de UUID din arbore, aceeași formă și același motiv ca
    # prima: `plan_uuid` al unui plan de patch fabricat în dublul de bază de
    # date al panoului, tot zerouri și un unu. Un UUID de altă formă n-ar mai
    # dovedi nimic despre ce încape în `VARCHAR(36)`.
    "aggregator/tests/auth-harness.ts":
        ({SHAPE_HEX: 1}, "UUID sintetic de plan de test"),

    # Base32, prima formă de felul ăsta din arbore. Clauza a intrat pe argumentul
    # că nu adaugă NICIO potrivire; astea patru sunt primele, și niciuna nu e un
    # secret al nimănui:
    #   * alfabetul RFC 4648 scris ca literal — 32 de caractere, exact pragul,
    #     fiindcă are toate literele mari plus cifrele 2-7;
    #   * două semințe TOTP sintetice de test (`JBSWY3DP…`, adică „Hello!" repetat,
    #     și secretul din vectorii RFC 6238), care TREBUIE să aibă forma reală: cu
    #     alta, testele n-ar mai dovedi nimic despre ce acceptă implementarea;
    #   * aceeași sămânță de test în capătul Python al probei trans-limbaj — e
    #     comună dinadins, fiindcă acolo se cere ca ambele capete să producă
    #     aceleași cifre din același secret.
    "aggregator/lib/auth/totp.ts": ({SHAPE_B32: 1}, "alfabetul RFC 4648 ca literal"),
    "aggregator/tests/auth-totp.test.ts":
        ({SHAPE_B32: 2}, "semințe TOTP sintetice: una de probă, una din RFC 6238"),
    "tests/unit/test_aggregator_auth_parity.py":
        ({SHAPE_B32: 1}, "sămânță TOTP sintetică, comună celor două capete"),
    # Apărut în arbore în timpul rundei a doua, scris de alt agent, și prins de
    # gardă la prima rulare de după: același `"0".repeat(32) + "abcdef…"` ca în
    # celelalte două fișiere de aici. E dovada că numărul nu e decorativ.
    "aggregator/tests/register.test.ts": ({SHAPE_HEX: 1}, "cheie de test sintetică"),

    # Material de formă de secret, dinadins: testul dovedește că instalatorul NU
    # tipărește ce refuză să scrie, deci are nevoie de ceva care chiar arată a
    # coadă de cheie. Dacă ar fi înlocuit cu text inofensiv, testul ar trece fără
    # să mai dovedească nimic.
    "tests/security/test_secrets_preserved.py":
        ({SHAPE_HEX: 1, SHAPE_B64: 2}, "material sintetic de formă de cheie"),

    # Hexa care nu e cheie: o adresă IPv6 în forma din /proc/net și un
    # `proctitle` auditd, care e hexa prin definiția formatului.
    "tests/unit/test_exposed.py": ({SHAPE_HEX: 1}, "adresă IPv6 în forma din /proc/net"),
    "tests/unit/test_auditd_watch.py": ({SHAPE_HEX: 1}, "proctitle auditd, hexa prin format"),

    # Sumele sha256 ale unor binare publice, fixate dinadins: e chiar mecanismul
    # care face `curl | bash` inutil. Nu sunt secrete, sunt opusul lor — valori
    # publice a căror schimbare tăcută e ce trebuie observat.
    #
    # Erau 1 până pe 26 august 2026 (doar trivy). Sunt 2 de atunci: nuclei a fost
    # adăugat în manifest, cu suma lui. Numărul e o măsurătoare, deci crește
    # odată cu manifestul, nu înainte.
    "deploy/tools/manifest.txt": ({SHAPE_HEX: 2}, "sume sha256 fixate ale unor binare publice"),
    # Aceleași două sume, scrise a doua oară ca aserțiune de conținut: testul
    # cere ca manifestul să fixeze EXACT valorile verificate de operator la
    # sursă, ca o editare accidentală să pice aici, nu pe gazdă. Ca să dovedească
    # asta trebuie să le conțină literal; o comparație cu ce e în manifest s-ar
    # potrivi cu orice ar scrie manifestul.
    "tests/security/test_installer_external_tools.py":
        ({SHAPE_HEX: 2}, "sumele fixate, repetate ca aserțiune de conținut"),

    # Numele unei unelte MCP, `mcp__…_restartNode_jsApplicationV1`. Are literă
    # mică, literă mare și cifră, deci trece de regula de compoziție; e un nume de
    # API public, scris identic în lista de permisiuni și în procedura de deploy.
    ".claude/settings.json": ({SHAPE_B64: 1}, "nume de unealtă MCP"),
    "watcher/INCARCARE-HOSTINGER.md": ({SHAPE_B64: 1}, "nume de unealtă MCP"),

    # Aceeași clasă ca numele de unealtă MCP de deasupra: un identificator PUBLIC
    # care nimerește regula de compoziție. Aici e URL-ul de avizare al unui GHSA
    # din eșantionul de ieșire `trivy image` —
    # `github.com/advisories/GHSA-…`, unde `com/advisories/GHSA-7788-qqqq-wwww`
    # are exact 34 de caractere din alfabetul base64, fiindcă punctul din
    # `github.com` rupe șirul și restul e numai litere, cifre, `/` și `-`.
    # Forma trebuie să rămână cea reală: eșantionul există ca să dovedească
    # exact că parserul potrivește ce scrie trivy, iar un URL scurtat ca să
    # tacă garda ar face proba să nu mai probeze nimic. Nu deschide nimic — e
    # o adresă publică, iar avizul din spatele ei e fabricat.
    "tests/unit/test_scan_trivy_image.py":
        ({SHAPE_B64: 1}, "URL public de avizare GitHub din eșantionul trivy"),
}

# Fișierele din care se EXTRAG formele de probă, cu podeaua măsurată azi. Podeaua
# e `cel puțin`: o formă nouă documentată trebuie să intre în corpus fără să
# strice testul, dar una care dispare din extragere înseamnă că extractorul a
# încetat să vadă fișierul — și asta arată identic cu „nu era nimic acolo".
_FORM_SOURCES: dict[str, tuple[int, str]] = {
    "watcher/.env.example": (7, "cheile martorului, cu ambele formate de perechi"),
    "deploy/config/secrets.env.example": (6, "cheile serverului monitorizat"),
    "watcher/INCARCARE-HOSTINGER.md": (4, "procedura de import în panoul găzduirii"),
    "watcher/README.md": (3, "formele hărții JSON, ale perechilor și cheia din URL-ul cron"),
    # Podeaua a fost zero până în runda a doua: fișierul numea variabila într-un
    # tabel și nu scria nicio atribuire. Între timp a căpătat un `grep
    # '^SENTINEL_SHIP_SECRET=' …`, iar extractorul îl ia acum. Sursa a stat în
    # listă cu podeaua zero SCRISĂ, nu lipsă — altfel forma nouă n-ar fi intrat în
    # corpus, și nimeni n-ar fi aflat de ce.
    "aggregator/README.md": (1, "cheia de expediere, într-un tipar de căutare"),
}

# Magazia locală de secrete: singurul loc din care se pot afla valorile reale
# fără să le scriu aici. E ignorată de git prin `.gitignore`, iar testul verifică
# asta înainte s-o citească — dacă ajunge vreodată urmărită, sursa de adevăr a
# gărzii ar fi ea însăși scurgerea.
SECRET_STORE = ("secrets/.env.local",)

# Identitatea operatorului, în aceeași magazie și din același motiv. Valoarea e
# o listă despărțită prin virgulă, ca operatorul să poată adăuga al doilea cont
# sau al doilea domeniu fără să atingă codul.
#
# Textul de aici ajunge în mesajul de eșec, deci e scris ca instrucțiune: cine
# vede testul picând trebuie să afle din el ce are de pus în fișier.
IDENTITY_KEYS: dict[str, str] = {
    "SANITISE_USERNAMES":
        "conturile de shell ale operatorului pe gazda monitorizată "
        "(apar în căi /home/…, în ssh utilizator@gazdă, în liste de conturi)",
    "SANITISE_DOMAINS":
        "domeniile ÎNREGISTRABILE ale operatorului, nu subdomeniile — din "
        "domeniul înregistrabil, subdomeniul martorului se află dintr-un jurnal "
        "de transparență a certificatelor",
}

# Cheile de identitate sunt scoase din scanarea generică de secrete: acolo se
# caută valoarea întreagă a cheii, iar o listă cu două intrări nu apare niciodată
# ca atare în arbore. Ar fi însemnat că verificarea se face sau nu după cât de
# multe conturi a scris operatorul — adică o gardă care tace când lista crește.
# Le are testul lor, care despică lista și caută fiecare intrare.


def _git(*args: str) -> list[str]:
    r"""Cai, despartite pe NUL.

    Fara `-z`, git citeaza numele non-ASCII: `docs/raport\304\203ri.md`. Calea
    aia nu exista pe disc, iar verificarea o sarea in tacere — intr-un depozit cu
    documentatie in romana, o chestiune de timp.
    """
    # `encoding="utf-8"` explicit, nu `text=True`: acela decodeaza cu
    # codificarea LOCALA (cp1252 pe Windows), deci o cale cu diacritice iese
    # stricata, fisierul „nu exista", iar verificarea il sarea in tacere. Git
    # da octeti UTF-8; ii citim ca atare.
    # `errors="replace"`, nu decodare stricta. Pe Windows, `subprocess` cu
    # `encoding=` decodeaza intr-un FIR separat; un UnicodeDecodeError acolo moare
    # tacut si `stdout` devine None cu `returncode=0`. Rezultatul ar fi
    # `None.split()`, adica o eroare fara legatura cu ce s-a intamplat.
    out = subprocess.run(["git", *args, "-z"], cwd=REPO, capture_output=True,
                         encoding="utf-8", errors="replace", check=True)
    return [p for p in (out.stdout or "").split(chr(0)) if p]


@functools.lru_cache(maxsize=None)
def _contents(rel: str) -> list[tuple[str, str]]:
    """TOATE versiunile care s-ar putea publica: discul SI indexul.

    `git commit` fara `-a` scrie INDEXUL. O versiune anterioara citea discul
    daca fisierul exista acolo, si cadea pe index doar cand nu exista — ceea ce
    face garda sa verifice o versiune in timp ce git publica alta.

    Fluxul care produce dezastrul nu e exotic; e chiar cel pe care depozitul il
    documenteaza ca reactie la o scurgere: `git add -A`, garda pica, editezi
    fisierul ca sa scoti adresa, rulezi din nou — verde — si comiti blobul vechi,
    deja pus in index. E mai rau decat lipsa garzii: da confirmarea exact in
    clipa in care omul crede ca a reparat.

    Deci nu alegem intre surse. Le citim pe amandoua, si le numim, ca mesajul de
    eroare sa spuna UNDE e problema.
    """
    # Rezultatul se cachează: fiecare fișier e citit de patru teste, iar un
    # `git show` per fișier per test însemna ~1330 de procese și dubla durata
    # suitei. `lru_cache` hash-uieste ARGUMENTELE, nu valoarea intoarsa, deci
    # lista se poate intoarce ca atare — o versiune anterioara o convertea in
    # tuplu „ca sa fie hashable", ceea ce era o neintelegere.
    out: list[tuple[str, str]] = []
    path = REPO / rel
    if path.is_file():
        try:
            # `errors="replace"` si aici, a treia locatie de decodare.
            #
            # O reparatie anterioara a pus-o la enumerare si la citirea din
            # index, si a sarit peste asta. Efectul: un fisier editat intr-un
            # editor cp1252 — scenariul numit chiar de comentariul de mai sus —
            # crapa la decodare, `except: pass` inghitea, si ramanea DOAR
            # versiunea din index. Adica exact versiunea curata, in timp ce
            # arborele de lucru continea adresa reala. Lista nu era goala, deci
            # nici garda de necitibilitate nu observa.
            out.append(("disc", path.read_bytes().decode("utf-8", errors="replace")))
        except OSError:
            pass
    # `errors="replace"` si verificare pe stdout, nu doar pe returncode.
    #
    # Un blob binar din index — `.ttf`, `.whl`, `.pcapng`, extensii pe care
    # `.gitattributes` le stie binare dar `SKIP_SUFFIX` nu le are — producea
    # `("index", None)` cu returncode 0. Lista nu era goala, deci
    # `test_every_enumerated_file_can_be_read` declara fisierul citit, iar
    # celelalte trei garzi crapau cu AttributeError in loc de mesajul lor.
    #
    # Cu `replace`, un binar devine text cu caractere de inlocuire — si atat mai
    # bine: o adresa IP scrisa in ASCII in interiorul unui binar ramane
    # gasibila, ceea ce sarind fisierul nu era.
    staged = subprocess.run(["git", "show", f":{rel}"], cwd=REPO, capture_output=True,
                            encoding="utf-8", errors="replace")
    if (staged.returncode == 0 and staged.stdout is not None
            and not any(t == staged.stdout for _, t in out)):
        out.append(("index", staged.stdout))
    return out


def _tracked_files() -> list[str]:
    """Tot ce ar ajunge intr-un push: urmarit SAU neurmarit-si-neignorat.

    Prima versiune enumera doar `git ls-files`, adica doar fisierele deja
    urmarite. Asta face garda sa anunte scurgerea abia DUPA ce a intrat in
    istoric — momentul in care „elimin-o" nu mai e o optiune.

    A costat imediat: un fisier de definitie de agent, scris cu adresa reala a
    serverului, utilizatorul SSH si numele cheii, statea neurmarit intr-un
    director urmarit. Urmatorul `git add` l-ar fi dus in depozitul public, iar
    garda ar fi tacut pana atunci.

    `--others --exclude-standard` adauga exact ce ar prinde un `git add -A`, si
    respecta `.gitignore` — un fisier ignorat constient ramane in afara
    verificarii, ceea ce e corect: acolo stau secretele, dinadins.
    """
    rels: list[str] = []
    for args in (("ls-files",), ("ls-files", "--others", "--exclude-standard")):
        for rel in _git(*args):
            if rel.startswith(SKIP_PREFIX) or Path(rel).suffix.lower() in SKIP_SUFFIX:
                continue
            rels.append(rel)
    return rels


# --- Garda pe valoare: ce formă are o valoare generată ------------------------


def _secret_shape(token: str) -> str | None:
    """Numele formei de valoare generată pe care o are înșiruirea, sau None.

    Ordinea contează: regulile de formă din `VALUE_SHAPE_EXEMPT` se aplică
    ÎNAINTE de clasificare, fiindcă o sumă SRI e base64 curat și ar fi altfel
    raportată de 181 de ori.

    `rstrip("=")` scoate umplutura, și nu e o precauție: base32 umple cu până la
    șase `=`, iar clauza base32 cere ca TOT corpul să fie din alfabetul ei. Cu
    umplutura înăuntru, o sămânță TOTP scrisă cu `=` la coadă n-ar mai fi
    recunoscută. Un `=` la mijloc n-ar fi umplutură, ci separatorul dintre un
    nume și o valoare — iar `_SECRET_RUN` nici nu-l lasă să intre în interiorul
    unei potriviri.

    Funcția se cheamă DOAR pe potriviri ale lui `_SECRET_RUN`, care cere cel
    puțin 32 de caractere din afara lui `=`; `rstrip("=")` nu poate coborî corpul
    sub pragul ăla. Clauza base32 a purtat până pe 15 august 2026 un `len(body)
    >= 32` în plus, care din cauza asta nu se putea evalua niciodată fals — cod
    mort care făcea pragul să pară verificat aici. E scos; pragul e al lui
    `_SECRET_RUN` și e verificat acolo.

    ## Prețul fiecărei clauze, măsurat, nu presupus

    * **base32, pe cutii separate.** Cutia MICĂ cere în plus o cifră 2-7; cea
      MARE nu. Asimetria e o măsurătoare, nu o scăpare:

      - fără cerință, `[a-z2-7]+` potrivește ORICE înșiruire de litere mici,
        adică orice propoziție lipită. Nu e ipotetic — arborele are chiar acum un
        literal de 31 de caractere minuscule în
        `aggregator/tests/instances.route.test.ts`, la UN caracter de prag;
      - `[A-Z2-7]+` nu se ciocnește de nimic: cea mai lungă înșiruire de
        majuscule măsurată pe tot arborele are 26 de caractere (alfabetul scris
        întreg, într-un test). Măsurat separat, renunțarea la cifră în cutia mare
        adaugă ZERO potriviri noi.

      Prima versiune a clauzei cerea cifra în ambele cutii. Costa o sămânță
      `pyotp.random_base32()` care iese fără nicio cifră — `(26/32)**32`, una la
      ~770 de generări — pentru zero fals-pozitive evitate, fiindcă `pyotp` scrie
      MAJUSCULE. Cu despicarea, sămânța administratorului e acoperită întreagă.
      Ce rămâne neacoperit e o valoare base32 scrisă cu litere mici și ieșită
      fără nicio cifră; niciun generator din depozit nu produce așa ceva.
      `test_the_base32_clause_still_costs_the_measured_zero` ține numărul.
    * **UUID — hexa pur după eliminarea cratimelor.** Docstring-ul modulului a
      declarat un an gaura asta drept cunoscută și deschisă: un UUID nu e hexa
      curat (are cratime) și de obicei n-are literă mare, deci nu-l vedea nicio
      clauză, deși are 122 de biți de entropie și e o formă comună de jeton API.
      Costul măsurat pe tot arborele înainte de a fi adăugată: O SINGURĂ
      potrivire nouă, UUID-ul sintetic de zerouri din `tests/unit/
      test_patch_runner.py`, care își are scutirea numită. Se raportează ca
      `hexa` fiindcă asta ESTE, iar o formă nouă ar cere un nume în `SHAPES` și
      în fiecare scutire care o folosește, pentru nimic în plus.

    Clauza UUID e ULTIMA dinadins: `Ab0-Ab0-…` (base64url sintetic) devine hexa
    curat după eliminarea cratimelor, deci pusă mai sus ar reclasifica valori
    base64 ca hexa și ar strica numerele din `VALUE_EXEMPT` fără ca vreo valoare
    să se schimbe în arbore.
    """
    if any(rx.search(token) for rx in _VALUE_SHAPE_EXEMPT_RX):
        return None
    body = token.rstrip("=")
    if _HEX_ONLY.fullmatch(body):
        return SHAPE_HEX
    if (any(c.islower() for c in body) and any(c.isupper() for c in body)
            and any(c.isdigit() for c in body)):
        return SHAPE_B64
    # După celelalte două, nu înaintea lor: hexa cu majuscule e și base32 valid,
    # iar forma raportată trebuie să fie cea care spune ce e valoarea.
    if _BASE32_UPPER.fullmatch(body):
        return SHAPE_B32
    if _BASE32_LOWER.fullmatch(body) and any(c.isdigit() for c in body):
        return SHAPE_B32
    dashless = body.replace("-", "")
    if dashless and _HEX_ONLY.fullmatch(dashless):
        return SHAPE_HEX
    return None


def _secret_value_hits(text: str) -> list[tuple[int, str, int]]:
    """(linie, formă, lungime) pentru fiecare valoare de formă de secret din text.

    Niciodată valoarea. Mesajul de eșec al unei gărzi de scurgere nu are voie să
    tipărească ce apără — de aceea se întoarce LUNGIMEA, care e destul ca să
    recunoști ce ai găsit când te duci la linia aia.

    Două treceri, iar a doua e cea care nu se vede: literalii lipiți peste o
    linie nouă. Potrivirile ei se raportează cu linia `0` — „în fișier, linie
    nesigură", aceeași sentinelă ca `_locations_of`, și pentru același motiv: o
    potrivire adevărată căreia nu i se poate atribui o linie nu are voie să
    devină o trecere tăcută.
    """
    hits: list[tuple[int, str, int]] = []
    seen: set[str] = set()
    for line_no, line in enumerate(text.splitlines(), 1):
        for m in _SECRET_RUN.finditer(line):
            token = m.group(0)
            shape = _secret_shape(token)
            if shape:
                hits.append((line_no, shape, len(token)))
                seen.add(token)

    joined = _JOINED_LITERALS.sub("", text)
    if joined != text:
        for m in _SECRET_RUN.finditer(joined):
            token = m.group(0)
            if token in seen:
                continue
            shape = _secret_shape(token)
            if shape:
                seen.add(token)
                hits.append((0, shape, len(token)))
    return hits


def _unexempted_value_hits(
        rel: str,
        per_version: list[tuple[str, list[tuple[int, str, int]]]]) -> list[str]:
    """Potrivirile pe care scutirea numită a fișierului NU le acoperă, ca text.

    Ia TOATE versiunile fișierului odată — discul și indexul — fiindcă numărul
    din scutire se compară cu MAXIMUL dintre ele, și cere egalitate.

    De ce maximul, și nu fiecare versiune separat: în timpul unei editări
    obișnuite cele două diferă legitim (măsurat: `tests/unit/test_beacon.py` are
    2 pe disc și 1 în index), iar o gardă care țipă la orice editare în curs e o
    gardă comentată la 22:00.

    De ce EGALITATE, și nu „cel mult": cu „cel mult", o valoare adăugată sub
    plafon într-un fișier deja scutit ar fi tăcută. Spațiul liber e măsurat zero
    — toate cele 21 de perechi (fișier, formă) stau exact la plafon — deci
    egalitatea nu costă nimic azi și închide rezidualul. Prețul ei e că
    ștergerea unui vector de aur face garda să ceară coborârea numărului, ceea ce
    e chiar disciplina scrisă peste tot în fișierul ăsta: numărul e o
    măsurătoare, nu o estimare.

    Depășirea se raportează întreagă, nu „cele de peste plafon": care anume sunt
    în plus nu se poate ști dintr-un număr, iar o listă aleasă arbitrar ar trimite
    cititorul la linia greșită.
    """
    allowance, why = VALUE_EXEMPT.get(rel, ({}, ""))
    shapes = set(allowance) | {shape for _, hits in per_version for _, shape, _ in hits}

    out: list[str] = []
    for shape in sorted(shapes):
        allowed = allowance.get(shape, 0)
        counts = [sum(1 for _, s, _ in hits if s == shape) for _, hits in per_version]
        if max(counts, default=0) == allowed:
            continue
        note = (f" — scutirea „{why}” cere {allowed} de formă {shape}, maximul "
                f"între versiuni e {max(counts, default=0)}") if rel in VALUE_EXEMPT else ""
        for source, hits in per_version:
            for line_no, s, length in hits:
                if s != shape:
                    continue
                where = f"{rel}:{line_no}" if line_no else f"{rel} (linie nesigură)"
                out.append(f"{where} ({source}) — {shape}, {length} caractere{note}")
        if not any(s == shape for _, hits in per_version for _, s, _ in hits):
            # Scutire care nu mai stinge nimic: fișierul s-a curățat, sau garda a
            # încetat să vadă forma. A doua arată identic cu un depozit curat.
            out.append(f"{rel} — nicio potrivire de formă {shape}, dar scutirea "
                       f"„{why}” cere {allowed}")
    return out


def _scan_tree_for_secrets(
        rels: Iterable[str],
        read: Callable[[str], list[tuple[str, str]]]) -> list[str]:
    """Ofensatorii, ca ȘIRURI deja formatate. Niciodată valori.

    Bucla stă AICI, nu în test, și nu e o preferință de stil. `pytest -l`
    randează variabilele locale ale fiecărui cadru din traceback, iar cu bucla în
    corpul testului `line` și `text` sunt chiar conținutul fișierului găsit —
    deci garda tipărea secretul integral exact în clipa în care cineva rula `-l`
    ca să vadă de ce a picat. Măsurat de verificator pe 15 august 2026, pe forma
    moștenită din HEAD; raza de acțiune e nouă, fiindcă versiunea veche potrivea
    doar două tipare de format, iar asta potrivește orice valoare generată.
    E aceeași disciplină, și pentru același motiv, ca `_scan_secret_store`.

    Ia enumerarea și cititorul ca ARGUMENTE, ca să poată fi condusă pe un arbore
    fabricat. Fără asta, drumul de raportare — bucla, aritmetica scutirilor,
    aplicarea tiparelor de format — nu era executat de niciun test: patru mutații
    independente în el au trecut verzi pe suita întreagă, cu un secret de beacon
    hexa de 64 de caractere plantat în arbore.
    """
    offenders: list[str] = []
    compiled = [(re.compile(p), why) for p, why in SECRETS.items()]
    me = Path(__file__).relative_to(REPO).as_posix()
    rel = source = text = line = versions = per_version = None
    try:
        for rel in rels:
            # Fișierul ăsta conține chiar formele de probă; se sare, ca gărzile pe
            # tipar să nu se potrivească cu ele însele.
            if rel == me:
                continue
            versions = read(rel)
            for source, text in versions:
                for line_no, line in enumerate(text.splitlines(), 1):
                    for rx, why in compiled:
                        if rx.search(line):
                            offenders.append(f"{rel}:{line_no} ({source}) — {why}")
            # Buclă explicită, nu comprehensiune. O comprehensiune are cadrul EI,
            # pe care golirea de mai jos nu-l atinge, iar variabila ei de ciclu e
            # chiar textul fișierului. Sub un `Exception` nu s-ar vedea — `raise …
            # from None` aruncă traceback-ul vechi — dar sub un `BaseException`
            # (SystemExit, Ctrl-C) se vede întreg, iar ăla nu se convertește.
            # Măsurat cu sonda `-l` de mai jos: cu comprehensiune, `pytest -l`
            # tipărea fișierul găsit. Aceeași notă e la `_scan_identity`.
            per_version = []
            for source, text in versions:
                per_version.append((source, _secret_value_hits(text)))
            offenders += _unexempted_value_hits(rel, per_version)
    except Exception as exc:
        # Doar numele tipului: `str(exc)` al unei erori de regex citează tiparul,
        # iar `text`, `line` și `versions` sunt conținutul fișierului.
        name = type(exc).__name__
        rel = source = text = line = versions = per_version = None
        raise RuntimeError(f"scanarea arborelui a eșuat: {name}") from None
    except BaseException:
        # Ctrl-C în secundele de scanare: nu se transformă în altceva, doar se
        # golește cadrul și se lasă să plece mai departe.
        rel = source = text = line = versions = per_version = None
        raise
    return offenders


@pytest.mark.skipif(shutil.which("git") is None, reason="")
def test_every_enumerated_file_can_be_read() -> None:
    """O cale care nu poate fi citita nu poate fi verificata.

    `_content` intorcea None si apelantii treceau mai departe — adica exact
    bifa verde care nu s-a uitat la nimic. Un fisier binar are extensia
    exclusa; orice altceva neciteibil e o gaura in acoperire, si trebuie sa se
    vada ca atare.
    """
    unreadable = [rel for rel in _tracked_files() if not _contents(rel)]
    assert not unreadable, (
        "fisiere enumerate dar necitibile, deci neverificate: "
        + ", ".join(unreadable[:10]))


@pytest.mark.skipif(shutil.which("git") is None, reason="")
def test_git_is_available() -> None:
    """Fără git, testele de mai jos n-ar avea ce citi și ar trece în tăcere.

    Un test de sanitizare care trece fiindcă nu s-a uitat la nimic e mai rău
    decât niciunul: dă exact aceeași bifă verde.
    """
    assert shutil.which("git"), "acest test are nevoie de git ca să enumere fișierele"


def test_no_real_infrastructure_in_tracked_files() -> None:
    """Regula adreselor se aplică în afara suitei de teste.

    Fixturile conțin adrese de atacatori copiate din jurnale reale — un
    brute-forcer chinezesc, un scaner olandez. Alea nu sunt infrastructura
    nimănui de aici, iar înlocuirea lor cu 203.0.113.x ar face fixturile mai
    puțin fidele fără să ascundă nimic despre acest server.

    Ce se aplică peste tot, inclusiv în teste, sunt tiparele de secrete și
    domeniul martorului — verificate în celelalte două teste din fișier.
    Distincția e între „o adresă publică apare în text" și „infrastructura
    ACESTUI deployment poate fi dedusă", iar doar a doua e o scurgere.
    """
    offenders: list[str] = []
    compiled = [(re.compile(p), why) for p, why in FORBIDDEN.items()]

    me = Path(__file__).relative_to(REPO).as_posix()
    for rel in _tracked_files():
        if rel.startswith("tests/") or rel == me or rel in EXEMPT:
            continue
        for source, text in _contents(rel):
            for line_no, line in enumerate(text.splitlines(), 1):
                for rx, why in compiled:
                    m = rx.search(line)
                    if m:
                        offenders.append(
                            f"{rel}:{line_no} ({source}): {m.group(0)[:40]} — {why}")

    assert not offenders, (
        "conținut real de infrastructură în depozitul public:\n  "
        + "\n  ".join(offenders[:20]))


# Valori de probă pentru garda de tipare: nu sunt ale nimănui, sunt cifre în
# ordine. 32 și 64 de caractere, adică exact lungimile pe care le produc
# `openssl rand -hex 16` și `-hex 32` — cele două care apar în procedura de
# instalare a martorului.
_HEX_32 = "0123456789abcdef" * 2
_HEX_64 = "0123456789abcdef" * 4


# Valoarea de probă base64url: evident sintetică, dar cu literă mică, literă mare
# și cifră, adică fix compoziția pe care regula de formă o cere. Cifre în ordine
# n-ar fi mers aici — ar fi ieșit hexa, și proba ar fi dovedit cealaltă ramură.
_B64URL_43 = ("Ab0-" * 11)[:43]

# Identificator scurt de instanță, în lungimea documentată în
# `watcher/.env.example`: 16, nu 32. Diferența asta e chiar gaura măsurată.
_ID_16 = "0011223344556677"

# Base32, în ambele cutii, plus forma cu umplutură. Alfabetul e A-Z și 2-7, deci
# `G` și `H` fac probele să nu fie hexa din întâmplare, iar lipsa unei cutii
# amestecate le ține în afara regulii de compoziție — adică exact forma pe care
# `pyotp.random_base32()` o produce pentru sămânța TOTP a panoului web.
_B32_32 = "ABCDEFGH23456777" * 2
_B32_LOWER_32 = "abcdefgh23456777" * 2
_B32_PADDED = ("ABCDEFGH23456777" * 3)[:34] + "======"

# Sămânța TOTP care iese FĂRĂ nicio cifră — o generare din ~770, și exact ce
# scăpa cât timp clauza cerea o cifră în ambele cutii. `pyotp.random_base32()`
# scrie majuscule, deci cutia mare e cea în care cade cazul ăsta. Litere din
# afara alfabetului hexa (I, J, K…) ca proba să nu treacă din întâmplare pe
# ramura hexa.
_B32_NO_DIGIT_32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF"

# UUID sintetic, în forma pe care o produce `uuid4()`: 8-4-4-4-12, cratime,
# minuscule. Nu e hexa curat (cratimele) și n-are literă mare, deci până pe
# 15 august 2026 nu-l vedea nicio clauză — gaură scrisă în docstring-ul modulului
# și lăsată deschisă.
_UUID_36 = "0011223a-4455-6677-8899-aabbccddeeff"

# Cuvinte românești lipite, fără separator și fără nicio cifră: 34 de caractere
# minuscule. E prețul alfabetului base32 în cutia mică, `[a-z2-7]+`, care
# potrivește orice propozitie lipită. Nu e o formă inventată pentru test —
# `aggregator/tests/instances.route.test.ts` are chiar acum un literal de 31 de
# caractere de forma asta, la UN caracter de pragul lui `_SECRET_RUN`.
_CUVINTE_LIPITE_34 = "cheiacarenutrebuiesaaparaniciodata"


def _caught_as_value(text: str) -> bool:
    """True dacă garda vede o valoare de formă de secret în text, oriunde."""
    return bool(_secret_value_hits(text))


def test_the_secret_guard_sees_every_measured_form() -> None:
    """Fiecare formă de aici a trecut, măsurat, pe lângă o versiune a gărzii.

    Primele opt sunt corpusul din 15 august 2026, când garda cerea ca numele să
    fie lipit de valoare; ultimele cinci sunt găurile pentru care garda a fost
    respinsă de două ori, toate în același sens: ghilimeaua care închide NUMELE
    rupea înșiruirea, deci JSON-ul și YAML-ul cu cheia în ghilimele treceau, iar
    alfabetul cerut nu avea `-` și `_`, deci base64url trecea.

    Ce se strică pentru operator dacă vreuna încetează să fie prinsă: fișierul
    `.env` pe care i-l cere procedura din `watcher/INCARCARE-HOSTINGER.md` pleacă
    la un `git add -A` într-un depozit public, iar cheile din el nu se mai iau
    înapoi prin ștergere din arbore — doar prin rotire la ambele capete.
    """
    # Podeaua de corpus: o listă de forme ieșită goală, sau scurtată tăcut, a
    # trecut deja o dată în depozitul ăsta.
    EXPECTED_FORMS = 18
    forms = {
        # Sămânța TOTP care iese fără nicio cifră 2-7 — o generare din ~770.
        # Scăpa cât timp clauza base32 cerea o cifră în AMBELE cutii, iar
        # măsurătoarea care justifica cerința fusese luată pe cutia mică (proza
        # lipită e minusculă, `pyotp.random_base32()` e majusculă).
        "base32 majuscul FĂRĂ nicio cifră": f"TOTP_SECRET={_B32_NO_DIGIT_32}",
        # Gaura pe care docstring-ul modulului a declarat-o un an „cunoscută și
        # rămasă deschisă": 122 de biți de entropie pe care nu-i vedea nicio
        # clauză, fiindcă are cratime (deci nu e hexa curat) și e într-o singură
        # cutie (deci regula de compoziție n-o vede).
        "UUID, forma lui uuid4()": f"HOSTINGER_API_KEY={_UUID_36}",
        # Sămânța TOTP a contului de administrator al panoului web,
        # `sentinel/web/security.py:217` → `pyotp.random_base32()`. O singură
        # cutie și nu hexa, deci înainte de clauza base32 era verificat tăcut
        # end-to-end: 32 de caractere de secret în arbore, gardă mulțumită.
        "base32, ca pyotp.random_base32()": f"TOTP_SECRET={_B32_32}",
        "base32 cu litere mici": f"totp_secret = '{_B32_LOWER_32}'",
        # Umplutura e ce face `rstrip("=")` din `_secret_shape` să conteze:
        # base32 umple cu până la șase, iar clauza cere tot corpul din alfabet.
        "base32 cu umplutură": f"TOTP_SECRET={_B32_PADDED}",
        "singular, valoare hexa": f"SENTINEL_BEACON_SECRET={_HEX_64}",
        "PLURAL, hartă JSON": f'SENTINEL_INSTANCE_SECRETS={{"{_HEX_32}":"{_HEX_64}"}}',
        "PLURAL, forma cu perechi": f"SENTINEL_INSTANCE_SECRETS={_HEX_32}:{_HEX_64}",
        "sufix după cuvânt": f"API_KEY_HOSTINGER={_HEX_64}",
        "jeton la plural": f"BOT_TOKENS={_HEX_64}",
        "două puncte, ca în YAML": f"beacon_secret: {_HEX_64}",
        "valoare în ghilimele": f'SECRETS = "{_HEX_64}"',
        "valoare în listă": f'TOKENS = ["{_HEX_64}"]',

        # Cele cinci ratări măsurate care au cerut reproiectarea. Identificatorul
        # de 16 e cel documentat în `watcher/.env.example`; cu unul de 32, forma
        # trecea de garda veche și „dovedea" o acoperire pe care n-o avea.
        "JSON cu identificator scurt": f'{{"{_ID_16}":"{_HEX_64}"}}',
        "JSON generic, cheie ghilimelată": f'  "secret": "{_HEX_64}",',
        "JSON generic, jeton": f'{{"bot_token": "{_HEX_64}"}}',
        "YAML cu cheie ghilimelată": f'"beacon_secret": {_HEX_64}',
        "base64url": f"SENTINEL_BEACON_SECRET={_B64URL_43}",
    }
    assert len(forms) == EXPECTED_FORMS, (
        f"corpusul are {len(forms)} forme, nu {EXPECTED_FORMS} — dacă scoaterea a "
        "fost intenționată, coboară podeaua ODATĂ CU ea, ca numărul să rămână o "
        "măsurătoare")
    for name, line in forms.items():
        assert _caught_as_value(line), f"neprins — {name}: {line[:60]}…"

    # Formele de FORMAT, care nu depind de valoare: rămân în `SECRETS` și se
    # verifică aici, ca scoaterea uneia să nu treacă cu suita verde.
    compiled = [re.compile(p) for p in SECRETS]
    for name, line in {
        "cheie API Anthropic": "ANTHROPIC_API_KEY=sk-ant-" + "0" * 40,
        "token de bot Telegram": "TELEGRAM_BOT_TOKEN=1234567890:" + "A" * 35,
    }.items():
        assert any(rx.search(line) for rx in compiled), f"neprins — {name}"


def test_the_shape_reported_is_the_one_that_describes_the_value() -> None:
    """Forma nu e decorativă: e cheia după care se face aritmetica scutirilor.

    `_unexempted_value_hits` numără PE FORMĂ și cere egalitate cu numărul din
    `VALUE_EXEMPT`. Deci o valoare care își schimbă clasificarea — fără ca ceva
    din arbore să se schimbe — face o scutire să nu mai stingă nimic și alta să
    fie depășită, adică garda se face roșie pentru o mutare de cod.

    Ordinea clauzelor din `_secret_shape` e chiar ce se fixează aici, și testul
    există fiindcă mutația care o strică trecea VERDE pe toată suita: mutată
    înaintea regulii de compoziție, clauza UUID reclasifică orice base64url ca
    hexa, fiindcă `Ab0-Ab0-…` fără cratime E hexa curat. În arborele de azi nu se
    vede — niciuna dintre cele 12 valori base64 nu are cratimă — deci fără
    aserțiunea de mai jos regula ar fi rămas o afirmație dintr-un docstring.
    """
    for name, token, expected in (
        ("hexa de 64", _HEX_64, SHAPE_HEX),
        ("base64url cu cratime", _B64URL_43, SHAPE_B64),
        ("base32 majuscule", _B32_32, SHAPE_B32),
        ("base32 majuscul fără cifră", _B32_NO_DIGIT_32, SHAPE_B32),
        ("base32 cu umplutură", _B32_PADDED, SHAPE_B32),
        ("UUID", _UUID_36, SHAPE_HEX),
    ):
        assert _secret_shape(token) == expected, (
            f"{name}: forma raportata e {_secret_shape(token)}, nu {expected} — "
            f"aritmetica scutirilor se face pe forma asta")

    # Și forma trebuie să fie una dintre cele NUMITE: o valoare întoarsă care nu
    # e în `SHAPES` n-ar putea fi scutită niciodată, iar mesajul ar trimite
    # cititorul după un nume care nu există.
    assert set(SHAPES) == {SHAPE_HEX, SHAPE_B64, SHAPE_B32}


def test_the_secret_guard_reports_every_line_of_a_multiline_value() -> None:
    """Trei chei pe trei linii, iar garda raporta una singură.

    `SENTINEL_INSTANCE_SECRETS` acceptă linia nouă ca separator de perechi, deci
    liniile 2 și 3 ale unei valori n-au niciun cuvânt `secret` lângă ele. Măsurat
    înainte de reproiectare: garda raporta linia 1 și tăcea despre 2 și 3 — un
    semnal roșu care pare complet și nu e, adică exact starea în care operatorul
    șterge o linie, rulează din nou, vede verde și publică celelalte două.

    Cazul al doilea e literalul SPART în două linii: niciuna dintre jumătăți nu
    are 32 de caractere, deci scanarea pe linie nu-l poate vedea deloc. Se
    raportează cu linia `0`, nu se pierde.
    """
    trei_linii = (f"SENTINEL_INSTANCE_SECRETS={_ID_16}:{_HEX_64}\n"
                  f"0011223344556688:{_HEX_64}\n"
                  f"0011223344556699:{_HEX_64}\n")
    linii = sorted(line for line, _, _ in _secret_value_hits(trei_linii))
    assert linii == [1, 2, 3], (
        f"din trei chei pe trei linii, garda raportează liniile {linii} — "
        "un semnal roșu incomplet e mai rău decât niciunul: pare că l-ai reparat")

    jumatate = _HEX_64[:31]
    spart = f'SECRET = (\n    "{jumatate}"\n    "{jumatate}"\n)\n'
    assert not any(_SECRET_RUN.search(line) for line in spart.splitlines()), (
        "proba nu mai dovedește nimic: o jumătate a ajuns singură peste prag, "
        "deci trecerea pe linie ar prinde-o și fără lipirea peste linie")
    hits = _secret_value_hits(spart)
    assert [line for line, _, _ in hits] == [0], (
        f"literalul spart în două linii nu e raportat: {hits}")


def test_the_secret_guard_stays_quiet_on_the_measured_false_positives() -> None:
    """O gardă care țipă la lucru corect e o gardă comentată la 22:00.

    Și atunci nu mai apără nimic — ceea ce pentru operator arată identic cu a nu
    fi avut-o niciodată, doar că suita e verde. Fiecare formă de mai jos apare
    legitim în depozit, iar primele două sunt liniile pe care o versiune mai
    largă a gărzii le-a raportat la prima ei rulare, pe 15 august 2026.

    Niciuna nu e stinsă printr-o îngustare de alfabet: prima și a doua cad pe
    regula de compoziție (o singură cutie de litere), a treia pe regula de formă
    numită `VALUE_SHAPE_EXEMPT`. Diferența contează — o îngustare e globală și
    tăcută, o regulă numită e citibilă și se poate contrazice.
    """
    EXPECTED_FORMS = 15
    innocent = {
        # Prețul clauzei base32, înregistrat aici fiindcă altfel nu e înregistrat
        # nicăieri: alfabetul ei în cutia mică, `[a-z2-7]+`, potrivește orice
        # înșiruire de litere mici, adică orice propoziție lipită. Măsurat pe tot
        # arborele, `aggregator/tests/instances.route.test.ts` are un literal de 31
        # de caractere de forma asta — la UN caracter de pragul lui
        # `_SECRET_RUN`. De aceea clauza cere ȘI o cifră 2-7; ce costă cerința
        # aia e scris în `_secret_shape`.
        "cuvinte lipite, doar litere mici":
            f"const mesaj = \"{_CUVINTE_LIPITE_34}\";",
        "cale de fișier, peste 32 de caractere":
            "local key=/etc/pki/tls/private/sentinel-selfsigned.key",
        "constantă descriptivă în kebab-case":
            'export const SHIP_SECRET_INFO = "sentinel-aggregator-instance-secret-v1";',
        "sumă de integritate SRI":
            '"integrity": "sha512-+LpyBk7L44ZIXwz/VYfglaXokxezESc6UxDSoyo2Ks6Jxc4Y7sGjpg=="',
        "valoare scurtă": "SENTINEL_BEACON_SECRET=schimba-ma",
        "proză despre secrete": "Secretul se pune în /etc/sentinel/secrets.env",
        "nume fără valoare": "SENTINEL_INSTANCE_SECRETS=",
        "substituent de șablon": "SENTINEL_BEACON_SECRET=${BEACON_SECRET}",
        "cuvântul singur, fără separator": "cheia se numește TELEGRAM_BOT_TOKEN",
        # Formele de mai jos sunt cele care fac diferența dintre „caut valoarea"
        # și „raportez orice înșiruire lungă": depozitul e plin de ele, 2506
        # măsurate, iar fiecare ar fi cerut o scutire proprie.
        "nume lung de funcție de test":
            "def test_no_value_from_the_local_secret_store_appears_in_the_tree():",
        "identificator camelCase lung":
            "export function readInstanceSecretsFromEnvironment(env: Env) {",
        "directivă systemd": "Environment=PYTHONDONTWRITEBYTECODE=1",
        "URL lung": "https://github.com/aquasecurity/trivy/releases/download/v0.73.0/t.gz",
        "identificator de instanță, 16 caractere": f"SENTINEL_INSTANCE_ID={_ID_16}",
        # Ghilimele alăturate pe ACEEAȘI linie: dacă lipirea s-ar face oriunde,
        # cele patru cuvinte hexa ar deveni o înșiruire de 32 și ar da alarmă.
        "tablou de literali scurți, hexa":
            '["deadbeef", "cafebabe", "12345678", "abcdef01"]',
    }
    assert len(innocent) == EXPECTED_FORMS, (
        f"corpusul de forme nevinovate are {len(innocent)}, nu {EXPECTED_FORMS} — "
        "coboară podeaua ODATĂ cu scoaterea, ca numărul să rămână o măsurătoare")
    for name, line in innocent.items():
        assert not _caught_as_value(line), f"alarmă falsă — {name}: {line}"
        assert not any(rx.search(line) for rx in
                       (re.compile(p) for p in SECRETS)), f"alarmă falsă — {name}"


# --- Corpusul extras din fișierele care documentează formele -----------------

# Un nume care CONȚINE un cuvânt de secret, urmat de o ATRIBUIRE. Prefixul e
# opțional dinadins: `"secret":` are numele chiar egal cu cuvântul, iar o versiune
# care cerea măcar o literă înainte l-ar fi sărit — exact clasa de eroare care a
# produs găurile pe care testul le repară.
#
# `=` liber, dar `:` numai cu numele în ghilimele. Măsurat: un `:` liber prindea
# proza din `deploy/config/secrets.env.example` („separate from the bot token: a")
# și forma STRICATĂ documentată în INCARCARE-HOSTINGER.md (`a1b2c3:cheieD4e5f6`),
# adică linii în care nu există nicio valoare de materializat. Forma JSON și cea
# YAML au numele în ghilimele; forma cu perechi intră prin `_NAMED_PLACEHOLDER`.
_SECRET_WORD = r"(?:secret|token|key|cheie|parol|pin|password)"
_ASSIGNMENT = re.compile(
    rf"(?i)(?:^|[^A-Za-z0-9_-])(?:"
    rf"[A-Za-z0-9_-]*{_SECRET_WORD}[A-Za-z0-9_-]*\s*="
    rf"|[\"'][A-Za-z0-9_-]*{_SECRET_WORD}[A-Za-z0-9_-]*[\"']\s*:"
    rf")")

# Un substituent care numește el însuși o cheie: `<cheie hexa>`, `<key>`. Fără
# regula asta, forma perechilor scrisă în README fără nicio variabilă în față —
# `<instance_id>:<cheie>,<instance_id>:<cheie>` — n-ar intra în corpus.
_NAMED_PLACEHOLDER = re.compile(r"(?i)<[^<>]*(?:cheie|secret|token|key|parol)[^<>]*>")

# Locurile în care documentația scrie „aici vine o valoare".
_SLOT = re.compile(
    r"<[^<>]{1,40}>"
    r"|\.\.\."
    r"|(?<![0-9A-Za-z])[0-9a-fA-F]{8,}(?![0-9A-Za-z])"
    r"|(?<=[:=])[A-Z][A-Z0-9_-]{3,}")
_CONCRETE_HEX = re.compile(r"[0-9a-fA-F]{8,}")


def _synthetic(index: int, width: int, alphabet: str) -> str:
    """O valoare de probă evident falsă, în alfabetul cerut.

    Depozitul e public: valorile de probă sunt cifre în ordine sau un tipar care
    se repetă din patru în patru caractere. Nimeni nu le poate confunda cu o
    cheie, iar garda TREBUIE să le vadă oricum — asta e chiar ce se măsoară.
    """
    if alphabet == SHAPE_HEX:
        return str(index % 10) * width
    return (f"Ab{index % 10}-" * (width // 4 + 1))[:width]


def _quotable_lines(rel: str, text: str) -> list[str]:
    """Liniile din care se poate citi o formă documentată.

    Într-un `.md` forma stă ori într-un bloc îngrădit, ori între accente grave în
    mijlocul unei propoziții — a doua e chiar cazul hărții JSON din
    `watcher/README.md`, deci nu se poate lua doar prima. Într-un `.env.example`
    exemplele stau în comentarii, deci `#`-ul din față se scoate.
    """
    if not rel.endswith(".md"):
        return [re.sub(r"^\s*#+\s?", "", line).strip() for line in text.splitlines()]

    out: list[str] = []
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            out.append(line.strip())
        else:
            out.extend(span.strip() for span in re.findall(r"`([^`]+)`", line))
    return out


def _documented_secret_forms() -> tuple[list[tuple[str, str, str]], list[str]]:
    """(forme, probleme) extrase din fișierele care DOCUMENTEAZĂ formele.

    Corpusul scris de mână și tiparul pe care îl dovedea au avut, de două ori,
    același autor în aceeași ședință — deci nu se puteau falsifica reciproc.
    Aici formele vin din sursele care le definesc, cu valorile înlocuite: cifre
    în ordine pentru varianta hexa, un tipar repetat pentru cea base64url.
    Efectul cerut: o formă documentată pe care garda n-o vede pică testul, fără
    să depindă de cine s-a gândit s-o adauge în corpus.

    Ce se ia dintr-un fișier:

      - `.env.example` — fiecare linie, cu `#`-ul din față scos, fiindcă chiar
        acolo stau exemplele de hartă JSON și de perechi;
      - `.md` — liniile din blocurile îngrădite ȘI fiecare bucată dintre
        accente grave, fiindcă forma cu hartă JSON e scrisă în text, nu în bloc.

    Ce se PĂSTREAZĂ din ce s-a luat: o linie în care un nume care conține
    secret/token/key/cheie/parolă/pin e urmat de `=`, sau de `:` dar numai cu
    numele în ghilimele (JSON, YAML), sau una în care un substituent `<…>`
    numește chiar o cheie. Restul nu e o formă de atribuire, ci proză care se
    întâmplă să conțină cuvântul — vezi comentariul de la `_ASSIGNMENT` pentru
    cele două linii măsurate care intrau altfel.

    Ce NU poate extractorul, scris ca să nu fie crezut complet:

      - CORPUSUL NU POATE SCOATE LA IVEALĂ UN GOL DE FORMĂ, și e important
        fiindcă forma e chiar axa pe care reproiectarea se sprijină. `_synthetic`
        materializează fiecare substituent ca cifre în ordine sau ca tiparul
        `Ab0-`, adică prin construcție hexa curat sau amestec de cutii — exact
        cele două lucruri pe care `_secret_shape` e definit să le accepte. Deci
        dacă mâine documentația scrie o cheie ca base32 sau ca UUID, corpusul
        raportează tot „văzută", indiferent dacă garda o vede cu adevărat. Ce
        prinde el sunt goluri de EXPRESIE — o înșiruire ruptă de o ghilimea, un
        separator, un nume scris altfel — iar alea au fost patru din patru
        găurile ultimelor două runde. Golurile de formă se acoperă numai prin
        corpusul măsurat de mai sus, unde fiecare probă e scrisă în alfabetul ei;
      - o formă documentată fără nume și fără substituent numit — de pildă un
        exemplu scris doar ca `abc123…` — nu are cum să fie recunoscută;
      - lungimile substituenților abstracte (`<cheie>`, `...`) se materializează
        la 64, adică la ce produce `openssl rand -hex 32`. Un `TELEGRAM_APPLY_PIN`
        real are șase cifre și NU ar fi văzut de gardă; corpusul nu dovedește
        altceva despre el;
      - `sk-ant-…` din `deploy/config/secrets.env.example` e într-o linie de
        comentariu fără atribuire, deci nu intră în corpus. Are tiparul lui de
        format în `SECRETS`, verificat separat;
      - fișierele se citesc de pe DISC, nu din index: aici se măsoară ce
        documentează depozitul, nu ce e pe cale să fie comis.
    """
    forms: list[tuple[str, str, str]] = []
    problems: list[str] = []
    counter = 0

    def materialise(line: str, alphabet: str) -> str | None:
        nonlocal counter
        used = False

        def slot(m: re.Match[str]) -> str:
            nonlocal counter, used
            used = True
            raw = m.group(0)
            # Un literal concret își păstrează lungimea: identificatorul de 16 din
            # `watcher/.env.example` e chiar gaura măsurată, iar materializat la 64
            # ar înceta să fie ea.
            width = len(raw) if _CONCRETE_HEX.fullmatch(raw) else 64
            counter += 1
            return _synthetic(counter - 1, width, alphabet)

        out = _SLOT.sub(slot, line)
        if used:
            return out
        # Niciun substituent: valoarea se pune imediat DUPĂ separator. Acoperă și
        # `NUME=` la capăt de linie, și `grep '^NUME=' fișier` din
        # `aggregator/README.md` — a doua formă nu are unde să scrie o valoare,
        # fiindcă e un tipar de căutare, dar TOT descrie o linie cu o cheie în ea,
        # iar garda trebuie s-o vadă acolo. Alternativa era s-o sar, adică exact
        # „am verificat zero forme" cu suita verde.
        anchor = _ASSIGNMENT.search(out)
        if anchor:
            counter += 1
            cut = anchor.end()
            return out[:cut] + _synthetic(counter - 1, 64, alphabet) + out[cut:]
        return None

    for rel, (floor, what) in _FORM_SOURCES.items():
        path = REPO / rel
        if not path.is_file():
            problems.append(f"{rel} lipsește — sursa de forme „{what}” nu s-a citit")
            continue
        taken = 0
        for line in _quotable_lines(rel, path.read_bytes().decode("utf-8", "replace")):
            if not (_ASSIGNMENT.search(line) or _NAMED_PLACEHOLDER.search(line)):
                continue
            taken += 1
            for alphabet in (SHAPE_HEX, SHAPE_B64):
                built = materialise(line, alphabet)
                if built is None:
                    problems.append(
                        f"{rel}: nu s-a putut materializa o formă documentată, deci "
                        f"nu s-a verificat nimic despre ea: {line[:80]}")
                    break
                forms.append((rel, line, built))
        if taken < floor:
            problems.append(
                f"{rel}: extragerea a scos {taken} forme, sub podeaua măsurată de "
                f"{floor} — extractorul a încetat să vadă „{what}”")
    return forms, problems


def test_every_documented_secret_form_is_seen_by_the_guard() -> None:
    """O formă documentată pe care garda n-o vede trebuie să pice testul singură.

    Ăsta e punctul reproiectării, nu un adaos: de două ori corpusul care dovedea
    tiparul a fost scris de aceeași mână, în aceeași ședință, ca să treacă. Un
    corpus extras din documentație nu poate face asta — dacă cineva adaugă în
    `watcher/INCARCARE-HOSTINGER.md` o formă nouă de scris o cheie, forma intră
    în corpus fără să-și amintească nimeni de testul ăsta, iar dacă garda n-o
    vede, suita se face roșie atunci, nu după scurgere.
    """
    forms, problems = _documented_secret_forms()
    assert not problems, "extragerea formelor documentate:\n  " + "\n  ".join(problems)

    # Podeaua totală, pe lângă cea per sursă: o extragere care se prăbușește la
    # câteva forme ar trece toate podelele mici și n-ar mai dovedi nimic.
    assert len(forms) >= 42, (
        f"corpusul extras are {len(forms)} forme, sub cele 42 măsurate pe 15 august "
        "2026 — extractorul vede mai puțin decât atunci")

    # Identificatorul de 16 caractere din `watcher/.env.example` trebuie să rămână
    # SCURT după materializare: gaura măsurată e chiar aia — o hartă JSON în care
    # singura înșiruire lungă începe după ghilimeaua care închide numele. Un
    # extractor care ar da tuturor substituenților 64 de caractere ar produce un
    # corpus care trece fără să mai conțină forma pentru care s-a scris.
    scurte = [b for _, _, b in forms if re.search(r"(?<![0-9])(\d)\1{15}(?![0-9])", b)]
    assert scurte, (
        "corpusul extras nu mai conține niciun identificator scurt materializat — "
        "forma pentru care garda a fost respinsă de două ori a dispărut din el")

    neprinse = [f"{rel}: {raw[:70]}" for rel, raw, built in forms
                if not _caught_as_value(built)]
    assert not neprinse, (
        "forme documentate în depozit pe care garda de secrete NU le vede:\n  "
        + "\n  ".join(dict.fromkeys(neprinse)))


def test_the_base32_clause_still_costs_the_measured_zero() -> None:
    """Zero era un număr într-un docstring. Aici e o aserțiune.

    Clauza base32 a intrat pe argumentul că nu adaugă NICIO potrivire pe tot
    arborele — argument care i-a fost permis exact fiindcă era o măsurătoare.
    Numărul n-a fost însă fixat de nimic: o lărgire ulterioară a alfabetului sau
    a compoziției ar fi început să raporteze nume scrise de om, iar prima
    consecință practică a unei gărzi care țipă la lucru corect e cineva care o
    comentează la 22:00 — după care nu mai apără nimic, dar suita e verde.

    Se măsoară forma raportată, nu potrivirea brută: dacă vreodată o valoare
    base32 legitimă ajunge în arbore, ea primește o scutire NUMITĂ în
    `VALUE_EXEMPT`, iar testul o numără de acolo. Ce nu poate trece e o creștere
    tăcută.

    Fișierul ăsta se sare, ca peste tot: conține chiar formele de probă.
    """
    if shutil.which("git") is None:
        pytest.skip("fără git nu se pot enumera fișierele")

    me = Path(__file__).relative_to(REPO).as_posix()
    gasite: list[str] = []
    for rel in _tracked_files():
        if rel == me:
            continue
        for source, hits in ((s, _secret_value_hits(t)) for s, t in _contents(rel)):
            for line_no, shape, length in hits:
                if shape == SHAPE_B32:
                    gasite.append(f"{rel}:{line_no} ({source}) — {length} caractere")

    permise = sum(a.get(SHAPE_B32, 0) for a, _ in VALUE_EXEMPT.values())
    assert len(gasite) == permise, (
        f"clauza base32 raportează {len(gasite)} înșiruiri, scutite sunt "
        f"{permise}. Măsurat pe 15 august 2026: ZERO, în tot arborele. O creștere "
        f"înseamnă ori o valoare base32 nouă (atunci scutire numită, cu motiv), "
        f"ori o clauză care s-a lărgit și a început să vadă nume scrise de om:\n  "
        + "\n  ".join(gasite[:20]))


def test_every_value_exemption_still_earns_its_place() -> None:
    """O scutire care nu mai stinge nimic e ori moartă, ori garda a orbit.

    A doua stare e cea de temut, și e chiar tiparul pe care fișierul ăsta îl
    păzește: un tipar stricat tăcut nu raportează nimic, iar tăcerea lui arată
    identic cu „depozitul e curat". Testul ăsta e singurul loc din fișier în care
    o gardă de secrete e obligată să GĂSEASCĂ ceva — în cele 19 fișiere despre
    care se știe de ce au înșiruiri lungi, fiecare formă scutită trebuie să mai
    apară măcar o dată.

    Numerele din docstring-ul ăsta și din `_unexempted_value_hits` erau deja
    rămase în urmă cu unul înainte de 15 august 2026: scutirea lui
    `aggregator/tests/register.test.ts` a intrat fără să le miște. Corectate
    odată cu clauza UUID, care a adus a doua. Un număr rămas în urmă e cum se
    reintroduce un bug reparat — cineva aliniază codul la comentariu.
    """
    if shutil.which("git") is None:
        pytest.skip("fără git nu se pot enumera fișierele, deci nici scutirile")

    numite = set(VALUE_EXEMPT)
    enumerate_ = set(_tracked_files())
    lipsa = sorted(numite - enumerate_)
    assert not lipsa, (
        "fișiere scutite care nu mai sunt enumerate de gardă — scoate scutirea, "
        "altfel rămâne o gaură deschisă pentru un nume refolosit: " + ", ".join(lipsa))

    moarte: list[str] = []
    for rel, (allowance, why) in VALUE_EXEMPT.items():
        gasit: dict[str, int] = {}
        for _, text in _contents(rel):
            for _, shape, _ in _secret_value_hits(text):
                gasit[shape] = gasit.get(shape, 0) + 1
        for shape, count in allowance.items():
            assert shape in SHAPES, (
                f"{rel}: scutirea numește forma „{shape}”, care nu există — "
                "o scutire scrisă greșit nu stinge nimic și nici nu spune asta")
            if count and not gasit.get(shape):
                moarte.append(f"{rel} ({shape}, scutit {count}) — „{why}”")
    assert not moarte, (
        "scutiri care nu mai sting nimic. Ori fișierul s-a curățat și scutirea "
        "trebuie ștearsă, ori garda a încetat să vadă forma aia — a doua e "
        "indistinctibilă de un depozit curat:\n  " + "\n  ".join(moarte))


@pytest.mark.skipif(shutil.which("git") is None,
                    reason="fără git nu se poate întreba dacă un nume e ignorat")
def test_the_environment_file_family_is_ignored() -> None:
    """Fișierul de import cu chei de producție nu are voie să plece la un `git add -A`.

    Procedura din `watcher/INCARCARE-HOSTINGER.md` cere operatorului să
    construiască un fișier `.env` cu chei, fiindcă importul lui e singura
    operație pe care panoul găzduirii o aplică efectiv. Fișierul se scrie din nou
    la fiecare rotire de cheie, deci nu e un accident care se întâmplă o dată.

    Pe 15 august 2026 unul dintre ele stătea în rădăcină ca `env.txt`: neurmărit
    ȘI neignorat. `.env` și `.env.*` acopereau doar convenția dotfile. Ce s-ar fi
    întâmplat: `git add -A`, iar cheile de instanță ar fi ajuns într-un depozit
    public — de unde nu se mai iau înapoi prin ștergere din arbore, ci doar prin
    rotire la ambele capete.

    Canarul invers e la fel de important: dacă tiparele s-ar lărgi până ar
    înghiți fișiere obișnuite, gărzile de mai sus ar înceta să le mai enumere, și
    tocmai lărgirea ar deschide gaura pe care testul ăsta o închide.
    """
    trebuie_ignorate = ("env.txt", "hostinger.env", "sentinel.env", "watcher.env",
                        "variabile.txt", ".env", ".env.hostinger", "credentiale.txt",
                        "secrets/.env.local")
    neignorate = [n for n in trebuie_ignorate if _gitignore_problem(n) is not None]
    assert not neignorate, (
        "nume de fișier cu variabile de mediu care NU sunt ignorate de git: "
        + ", ".join(neignorate)
        + "\n  Procedura de instalare a martorului cere un astfel de fișier cu chei "
          "de producție; depozitul e public.")

    # Și invers: un fișier obișnuit trebuie să rămână vizibil pentru gărzi.
    trebuie_vazute = ("deploy/tools/manifest.txt", "requirements.txt",
                      "watcher/.env.example", "deploy/config/secrets.env.example")
    inghitite = [n for n in trebuie_vazute if _gitignore_problem(n) is None]
    assert not inghitite, (
        "tipare prea largi — fișiere obișnuite au devenit invizibile pentru "
        "gărzile de sanitizare: " + ", ".join(inghitite))


def test_no_secrets_anywhere_including_fixtures() -> None:
    """Un secret într-o fixtură e la fel de scurs ca unul în cod.

    Regula adreselor tolerează suita de teste; asta nu. Diferența e că o adresă
    dintr-un jurnal nu deschide nimic, iar un jeton da.

    Se caută două lucruri diferite, și e important că nu se confundă: tiparele de
    FORMAT din `SECRETS` (o cheie Anthropic, un token de Telegram — se recunosc
    după cum arată, oriunde), și VALOAREA de formă generată, oriunde în fișier,
    indiferent ce nume e lângă ea. A doua e cea reproiectată pe 15 august 2026;
    motivul, prețul și scutirile ei sunt în docstring-ul modulului.

    Mesajul numește fișierul, linia, forma și lungimea — niciodată conținutul. Un
    test de scurgere care tipărește secretul în propria ieșire îl mută dintr-un
    loc privat în altul public, iar ieșirea unui test ajunge în jurnale de CI.

    Bucla nu e aici, ci în `_scan_tree_for_secrets`, tot din motivul ăla: sub
    `pytest -l` variabilele locale ale ACESTUI cadru s-ar tipări întregi.
    `test_a_failing_scan_never_prints_the_value_under_showlocals` verifică efectul,
    nu intenția — rulează chiar funcția asta sub `-l`, pe un arbore fabricat.
    """
    offenders = _scan_tree_for_secrets(_tracked_files(), _contents)

    assert not offenders, (
        "posibile secrete în depozitul public:\n  " + "\n  ".join(offenders[:20])
        + "\n  Dacă vreuna e legitimă, primește o scutire NUMITĂ în `VALUE_EXEMPT`, "
          "cu forma, numărul și motivul — nu o îngustare de tipar: aia e tăcută, "
          "globală, și e cum s-au deschis găurile de dinainte.")


# Valoarea de probă pentru arborele fabricat și pentru sonda `-l`. Cifre, deci
# hexa, dar NU un singur caracter repetat: o ieșire `-l` trunchiată trebuie să
# rămână recunoscibilă după primele caractere, altfel sonda ar căuta ceva ce
# trunchierea a tăiat și ar raporta „curat" fără să se fi uitat.
_PROBE_HEX_64 = ("9876543210" * 7)[:64]


def test_the_assembled_guard_reports_a_fabricated_tree() -> None:
    """Drumul de raportare — bucla, aritmetica scutirilor, tiparele de format.

    Testele de mai sus verifică funcțiile pure. Măsurat de verificator pe 15
    august 2026: patru mutații independente în DRUMUL dintre ele — scanarea de
    valori scoasă din buclă, fiecare fișier sărit, `_unexempted_value_hits`
    întorcând mereu gol, tiparele de format care nu se mai declanșează — treceau
    toate VERZI, pe fișier și pe suita întreagă. Cu un secret de beacon hexa de
    64 de caractere plantat în arborele publicabil, suita rămânea verde.

    Ce se strică pentru operator: garda nu spune nimic, iar tăcerea ei arată
    exact ca un depozit curat — chiar tiparul pentru care fișierul ăsta există.
    O probă de mână, rulată o dată, nu reface asta peste șase luni, când cineva
    „simplifică" bucla.

    Arborele e fabricat, deci nu depinde de git și nici de ce e pe disc azi.
    """
    # Se ia din `VALUE_EXEMPT` o scutire de forma {hexa: 1}, nu o cale scrisă cu
    # mâna: testul verifică aritmetica, nu ce fișier o poartă azi.
    scutit = next((rel for rel, (a, _) in VALUE_EXEMPT.items()
                   if a == {SHAPE_HEX: 1}), None)
    assert scutit, "nicio scutire de forma {hexa: 1} — proba de aritmetică n-are pe ce rula"
    me = Path(__file__).relative_to(REPO).as_posix()

    hexa = f"SENTINEL_BEACON_SECRET={_PROBE_HEX_64}\n"
    doua = hexa + f"AL_DOILEA={_PROBE_HEX_64}\n"

    def scan(tree: dict[str, list[tuple[str, str]]]) -> list[str]:
        return _scan_tree_for_secrets(list(tree), lambda rel: tree[rel])

    # 1. Fișier nescutit, o valoare: exact un ofensator, cu fișierul și linia.
    unul = scan({"nescutit.env": [("disc", hexa)]})
    assert len(unul) == 1 and "nescutit.env:1" in unul[0] and SHAPE_HEX in unul[0], unul

    # 2. Fișier scutit, exact cât acoperă scutirea: tăcere.
    assert scan({scutit: [("disc", hexa)]}) == []

    # 3. Unul în plus: se raportează AMÂNDOUĂ, cu plafonul numit în mesaj.
    peste = scan({scutit: [("disc", doua)]})
    assert len(peste) == 2 and all("cere 1 de formă hexa" in o for o in peste), peste

    # 4. Scutire care nu mai stinge nimic: fișierul s-a curățat, sau garda a orbit.
    goala = scan({scutit: [("disc", "nimic aici\n")]})
    assert len(goala) == 1 and "nicio potrivire" in goala[0], goala

    # 5. Maximul între versiuni, nu fiecare separat: o editare în curs care încă
    #    n-a ajuns în index nu are voie să facă garda să țipe.
    assert scan({scutit: [("disc", hexa), ("index", "nimic\n")]}) == []

    # 6. Tiparele de FORMAT se aplică și ele. `sk-ant-` urmat de cifre nu e nici
    #    hexa, nici amestec, nici base32 — deci aici se declanșează DOAR formatul,
    #    ceea ce face proba să nu poată trece din greșeală prin garda pe valoare.
    format_ = scan({"chei.txt": [("disc", "ANTHROPIC_API_KEY=sk-ant-" + "0" * 40 + "\n")]})
    assert len(format_) == 1 and "Anthropic" in format_[0], format_

    # 7. Fișierul ăsta se sare — altfel gărzile pe tipar s-ar potrivi cu ele însele.
    assert scan({me: [("disc", hexa)]}) == []

    # 8. Ambele versiuni ale unui fișier nescutit se raportează, și se văd care.
    doua_surse = scan({"nescutit.env": [("disc", hexa), ("index", hexa)]})
    assert len(doua_surse) == 2 and {"(disc)" in o for o in doua_surse} == {True, False}, \
        doua_surse

    # 9. Valoare pe mai multe linii: toate liniile, prin buclă, nu doar prima.
    multi = scan({"perechi.env": [("disc", f"SENTINEL_INSTANCE_SECRETS=aa:{_PROBE_HEX_64}\n"
                                           f"bb:{_PROBE_HEX_64}\n"
                                           f"cc:{_PROBE_HEX_64}\n")]})
    assert len(multi) == 3, multi

    # 10. Și, peste tot: mesajul nu conține valoarea.
    for lot in (unul, peste, goala, format_, doua_surse, multi):
        for o in lot:
            assert _PROBE_HEX_64[:16] not in o, f"mesajul conține valoarea: {o[:40]}"


# Sonda pentru `pytest -l`. Conduce CHIAR funcția de test livrată, pe un arbore
# fabricat, ca defectul să fie prins și dacă cineva mută bucla înapoi în ea.
_SHOWLOCALS_PROBE = '''\
import importlib.util

_spec = importlib.util.spec_from_file_location("garda", {modul})
garda = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(garda)


def _payload():
    return "SENTINEL_BEACON_SECRET=" + {valoare} + "\\n"


def _fabricate():
    garda._tracked_files = lambda: ["proba-scurgere.env"]
    garda._contents = lambda rel: [("disc", _payload())]


# Cele doua inlocuitoare isi golesc PROPRIUL parametru inainte sa arunce, dar
# NUMAI unul dintre ele are nevoie de asta — si e important care, fiindca varianta
# de dinainte a comentariului spunea „amandoua" si trimitea cititorul sa apere un
# cadru pe care nimeni nu-l vede.
#
# Masurat, cu mutatia care lasa parametrul pe loc in fiecare ciot pe rand:
#
#   `_boom_hard` (SystemExit) → ROSU. `BaseException` nu se converteste, deci
#       traceback-ul pastreaza si cadrul ciotului, cu textul fisierului in el.
#       Golirea de aici e singura care apara ceva.
#   `_boom` (ValueError)      → VERDE. Garda prinde `Exception` si re-arunca cu
#       `raise … from None`, care ARUNCA urma veche: cadrul ciotului nu ajunge
#       niciodata in traceback-ul tiparit de `-l`. Golirea e cod mort, din exact
#       motivul pe care autorul garzii il descoperise cu o runda inainte.
#
# Se pastreaza si in `_boom` dinadins: cele doua ciopturi sunt simetrice, iar
# daca `from None` dispare vreodata din garda, ciotul asimetric ar fi a doua
# scurgere descoperita in aceeasi zi. Ce nu se mai pastreaza e afirmatia ca
# amandoua sunt necesare.
def _boom(text):
    text = None
    raise ValueError("crapa dinadins, ca sa se vada ce ramane in cadre")


def _boom_hard(text):
    text = None
    raise SystemExit("nu e Exception, deci nu se converteste, deci cadrele raman")


def test_garda_pica_pe_arbore_fabricat():
    _fabricate()
    garda.test_no_secrets_anywhere_including_fixtures()


def test_garda_crapa_in_timpul_scanarii():
    _fabricate()
    garda._secret_value_hits = _boom
    garda.test_no_secrets_anywhere_including_fixtures()


def test_garda_iese_fortat_in_timpul_scanarii():
    _fabricate()
    garda._secret_value_hits = _boom_hard
    garda.test_no_secrets_anywhere_including_fixtures()
'''


def test_a_failing_scan_never_prints_the_value_under_showlocals(tmp_path) -> None:
    """`pytest -l` tipărea secretul în clar, exact când garda tocmai îl găsise.

    Docstring-ul modulului documentează pe larg clasa asta de defect și are, de
    o rundă, un răspuns — `_scan_secret_store`. Ea a fost reintrodusă la trei
    sute de rânduri distanță, în bucla de scanare a arborelui: `line` și `text`
    erau locale ale cadrului de test, încă legate când pica aserțiunea. Iar `-l`
    e chiar ce rulează cineva în clipa în care garda s-a înroșit; de acolo
    secretul ajunge în terminal și în jurnalul de CI.

    Verificarea e pe EFECT, nu pe intenție: se rulează un pytest adevărat, cu
    `-l`, peste un arbore fabricat cu o valoare de probă, și se citește ieșirea.
    O aserțiune că bucla „stă într-un ajutor" ar fi confirmarea intenției.

    Trei scenarii, fiindcă sunt trei căi prin care valoarea ajunge într-un
    traceback:

      - aserțiunea care pică normal — cadrul scanării s-a întors deja;
      - scanarea care crapă cu un `Exception` — cadrul ei e în traceback, dar
        excepția se convertește, deci se vede DOAR cadrul funcției, golit;
      - scanarea care iese cu un `BaseException` (SystemExit, Ctrl-C) — aia NU se
        convertește, deci traceback-ul păstrează și cadrele de dedesubt.

    Al treilea a găsit singurul defect adevărat al reparației ăsteia, și l-a
    găsit după ce mutația pe al doilea trecuse VERDE: o comprehensiune de listă
    are cadrul ei, pe care golirea din `except` nu-l atinge, iar variabila ei de
    ciclu era textul fișierului. Sub `Exception` nu se vedea, fiindcă `raise …
    from None` aruncă traceback-ul vechi; sub `SystemExit` se vedea întreg.
    Măsurat, nu dedus — prima oară comentariul de la buclă a spus că sonda l-a
    prins, și nu era adevărat.
    """
    probe = tmp_path / "test_sonda_showlocals.py"
    probe.write_bytes(_SHOWLOCALS_PROBE.format(
        modul=repr(str(Path(__file__).resolve())),
        valoare=repr(_PROBE_HEX_64)).encode("utf-8"))

    # `PYTHONIOENCODING` explicit: pe Windows, stdout-ul unui proces-copil legat
    # la o conductă se codifică cu cp1252, iar diacriticele din mesajele gărzii
    # ies stricate. Aserțiunile de mai jos se sprijină oricum doar pe fragmente
    # ASCII — o potrivire pe un text care nu poate ajunge întreg în ieșire e
    # exact „grep după un tipar care nu există niciodată".
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    run = subprocess.run(
        [sys.executable, "-m", "pytest", str(probe), "-l", "--tb=long",
         "-p", "no:cacheprovider"],
        cwd=tmp_path, capture_output=True, encoding="utf-8", errors="replace", env=env)
    out = (run.stdout or "") + (run.stderr or "")

    # Întâi că sonda chiar a produs eșecurile pe care le inspectăm. O ieșire
    # goală, sau un pytest care n-a rulat nimic, ar face restul o bifă verde pe
    # nimic — și exact așa arată o sondă stricată.
    assert run.returncode != 0, f"sonda nu a picat, deci n-are ce inspecta:\n{out[-2000:]}"
    assert "3 failed" in out, f"sonda n-a rulat toate scenariile:\n{out[-2000:]}"
    assert "proba-scurgere.env:1" in out, (
        f"garda n-a raportat fișierul fabricat, deci eșecul inspectat e altul:\n{out[-2000:]}")
    assert "scanarea arborelui" in out and "ValueError" in out, (
        f"scenariul cu `Exception` n-a trecut prin `except`, deci golirea "
        f"cadrului nu a fost pusă la încercare:\n{out[-2000:]}")
    assert "SystemExit" in out, (
        f"scenariul cu `BaseException` n-a rulat — el e singurul în care excepția "
        f"NU se convertește, deci singurul care vede cadrele de sub bucla de "
        f"scanare:\n{out[-2000:]}")

    # Prefixul, nu valoarea întreagă: `-l` trunchiază șirurile lungi, iar o
    # scurgere trunchiată e tot o scurgere.
    assert _PROBE_HEX_64[:24] not in out, (
        "`pytest -l` a tipărit valoarea găsită de gardă — un test de scurgere "
        "care își tipărește propriul secret îl mută dintr-un loc privat în "
        "altul public")


def test_the_witness_domain_is_not_named_anywhere() -> None:
    """Cea mai valoroasă informație pentru cineva care a luat serverul.

    Semnalul care pleacă spre martor e ce îl dă de gol. Aflând unde pleacă,
    poate încerca să-l blocheze înainte să facă orice altceva. Verificarea e
    separată de cea de mai sus fiindcă mesajul de eșec trebuie să spună exact
    asta, nu „un tipar a fost găsit".

    ACOPERIRE PARȚIALĂ, scrisă aici ca să nu fie crezută completă: tiparul cere
    prefixul `sentinel.`, deci vede subdomeniul și NU vede domeniul înregistrabil
    singur. Nu e o scăpare care se poate repara aici — un tipar care ar prinde
    orice `<ceva>.<tld>` ar cere ștergerea lui `example.com`, a lui
    `fonts.googleapis.com` și a fiecărei adrese de documentație din depozit,
    adică ar fi scos din suită în aceeași săptămână.

    Forma goală o acoperă `test_no_operator_identity_appears_in_the_tree`, pe
    valoare. Testul ăsta rămâne fiindcă e singurul care funcționează pe o clonă
    fără magazia locală, deci prinde subdomeniul chiar și acolo unde celălalt
    raportează SKIP. Măsurat pe 14 august 2026: subdomeniul apărea de 0 ori,
    domeniul înregistrabil de 16 — verde aici, scurgere acolo.
    """
    # Orice `sentinel.<ceva>.<tld>` care NU e un substituent evident. Nu pot
    # enumera domeniul real fara sa-l scriu aici, deci regula e inversa: se
    # accepta doar numele despre care se vede din citire ca sunt exemple.
    #
    # Enumerarea e aceeasi ca mai sus, NU `git grep`. Prima versiune folosea
    # `git grep`, care se uita doar la fisierele urmarite — adica exact defectul
    # reparat in `_tracked_files`, lasat intact in verificarea pe care
    # docstring-ul modulului o numeste „cazul cel mai important".
    PLACEHOLDERS = ("exemplu", "example", "exemple", "test", "localhost", "invalid")
    me = Path(__file__).relative_to(REPO).as_posix()
    rx = re.compile(r"sentinel\.([a-z0-9-]+)\.(?:eu|ro|com|net|dev|io)(?![a-z0-9.-])",
                    re.IGNORECASE)
    hits = []
    for rel in _tracked_files():
        if rel == me:
            continue
        for source, text in _contents(rel):
            for m in rx.finditer(text):
                if m.group(1).lower() not in PLACEHOLDERS:
                    hits.append(f"{rel} ({source}): {m.group(0)}")
                    break

    assert not hits, (
        "domeniul martorului extern apare în: " + ", ".join(hits)
        + "\n  E singura mașină pe care un atacator cu root pe gazda monitorizată "
          "nu o controlează. Un depozit public nu e locul unde să afle unde e.")


# --- Valoarea reală: ce stă în magazia locală nu are voie în arbore ----------
#
# Verificarea asta nu ghicește. Ori valoarea din `secrets/.env.local` apare în
# text, ori nu apare — deci n-are nici fals-pozitive de explicat, nici forme
# ratate din cauza numelui de lângă. Ce poate rata sunt REPREZENTĂRI ale
# aceleiași valori, iar alea se enumeră mai jos și se verifică separat.

# Sub șase caractere o valoare se potrivește peste tot și verificarea ar deveni
# zgomot. Nu se sare tăcut: testul enumeră cheile prea scurte și pică, fiindcă
# „prea scurtă ca s-o caut" e o gaură de acoperire, nu o trecere.
MIN_SEARCHABLE_SECRET = 6

# Valori de probă pentru testele de mai jos: nu sunt ale nimănui, și nu sunt
# valoarea reală — un test care ar avea nevoie de ea ca să demonstreze ceva ar fi
# exact scurgerea de reparat. Trei lungimi, fiindcă un cont Telegram vechi are
# opt cifre și un supergrup treisprezece; o suită de probe toate de zece ar lăsa
# o prescurtare legată de lungime să intre neobservată.
_STANDIN = "5550001111"
_STANDIN_8 = "55500011"
_STANDIN_13 = "5550001111222"

# Doi literali lipiți sunt un singur șir: `"55500" "01111"` în Python, iar cu
# `+` în orice limbaj din depozit. `\+?` nu e un amănunt: lipirea implicită NU
# există în TypeScript, deci `+` e SINGURUL mod de a sparge un literal în
# `watcher/`, care e scanat de aceeași gardă.
_ADJACENT_QUOTES = re.compile(r"""["']\s*\+?\s*["']""")
# Grupuri de cifre despărțite de un separator, oricare din cele scrise de om.
_DIGIT_SEPARATOR = re.compile(r"(?<=[0-9])[ _,.-](?=[0-9])")


def _searchable_forms(text: str) -> tuple[str, ...]:
    """Copii ale textului în care o valoare rescrisă redevine căutabilă.

    Fiecare formă vine dintr-un mod real de a scrie același număr:

      - lipirea grupurilor: `5 550 001 111`, `5,550,001,111`, `5_550_001_111`,
        `5.550.001.111`, `555-000-1111`;
      - lipirea literalilor: `"55500" "01111"` și `"55500" + "01111"`, pe care un
        `in text` nu le vede deloc, deși sunt același șir pentru cine rulează
        codul. Varianta cu `+` e obligatorie: în TypeScript, care e jumătate din
        `watcher/`, lipirea implicită nici nu există.

    Efectele secundare (o adresă IP își pierde punctele, două șiruri fără
    legătură se lipesc) nu contează: copiile astea se folosesc DOAR ca să se
    caute în ele o valoare deja cunoscută, iar șansa ca lipirea să producă exact
    valoarea căutată e neglijabilă. Dacă totuși o produce, mesajul dă fișierul și
    linia, deci coincidența se vede din prima.

    Trei forme, nu patru: o variantă „doar cifre lipite, fără lipirea
    literalilor" ar fi acoperită în întregime de ultima, iar o cale redundantă e
    o cale care se poate șterge cu suita verde — adică o falsificare care nu
    demonstrează nimic. Așa, fiecare din cele trei se rupe singură, și când o
    rupi, testul de mai jos pică.
    """
    concat = _ADJACENT_QUOTES.sub("", text)
    return (text, concat, _DIGIT_SEPARATOR.sub("", concat))


def _value_matcher(value: str) -> re.Pattern[str]:
    """Tiparul care găsește valoarea, inclusiv scrisă în hexazecimal.

    Granițe de cifră pentru valorile numerice: un PIN de șase cifre din
    interiorul unui timestamp nu e PIN-ul, iar fără granițe garda ar cere
    ștergerea unor numere nevinovate până când cineva ar scoate-o din suită.

    Hexazecimalul e a doua reprezentare pe care o ia un id copiat dintr-un
    depanator sau dintr-un dump. Se cere prefixul `0x`: fără el, nouă caractere
    hexa s-ar potrivi din întâmplare în interiorul unui hash.

    Fără `(?i)` la mijloc de tipar — pe Python 3.11+ un flag global care nu e la
    început e eroare, iar tiparul ăsta se compune prin `|`. Insensibilitatea se
    scrie pe litere, unde chiar e nevoie de ea.
    """
    if not value.lstrip("-").isdigit():
        # Un secret nenumeric (parolă, jeton) se caută ca atare: dacă apare lipit
        # de altceva, tot a scăpat.
        return re.compile(re.escape(value))

    hexa = format(abs(int(value)), "x")
    insensitive = "".join(f"[{c}{c.upper()}]" if c.isalpha() else c for c in hexa)
    return re.compile(
        rf"(?<![0-9]){re.escape(value)}(?![0-9])"
        rf"|0[xX]0*{insensitive}(?![0-9a-fA-F])")


def _locations_of(text: str, rx: re.Pattern[str]) -> list[int]:
    """Liniile pe care se potrivește tiparul. `0` înseamnă „în fișier, linie nesigură".

    Sentinela `0` există fiindcă lipirea literalilor alăturați poate traversa
    linii: potrivirea e reală pe tot textul, dar nu se poate atribui unei linii.
    O versiune care ar întoarce lista goală în cazul ăsta ar transforma o
    potrivire adevărată într-o trecere tăcută — exact tiparul păzit aici.

    Ia un tipar deja compilat, nu o valoare, fiindcă îl folosesc două verificări
    cu tipare diferite (secret și identitate) și un singur loc care atribuie
    liniile. Cu două copii ale logicii ăsteia, sentinela `0` ar fi fost reparată
    o dată și uitată în cealaltă.
    """
    if not any(rx.search(form) for form in _searchable_forms(text)):
        return []

    hits = [n for n, line in enumerate(text.splitlines(), 1)
            if any(rx.search(form) for form in _searchable_forms(line))]
    return hits or [0]


def _locations(text: str, value: str) -> list[int]:
    """Liniile pe care apare valoarea unui secret."""
    return _locations_of(text, _value_matcher(value))


# Punctul, așa cum îl poate scrie cine copiază o cale într-un URL sau într-o
# expresie regulată. Restul caracterelor se scapă normal — numai punctul are
# rescrieri care apar chiar în depozitul ăsta.
_DOT_REWRITINGS = r"(?:\.|%2[eE]|\\\.)"


def _identity_matcher(value: str) -> re.Pattern[str]:
    """Tiparul care găsește o valoare de identitate, inclusiv rescrisă sau inversată.

    Insensibil la majuscule: DNS-ul e insensibil, deci scrierea de marcă a unui
    domeniu e același domeniu, iar un cont scris cu majusculă în proză e același
    cont. Riscul de alarmă falsă e neglijabil la lungimea minimă cerută.

    Inversarea nu e o ipoteză: adresa de e-mail din pagina de prezentare e scrisă
    exact așa, ca să nu fie recoltată. Se caută ca alternativă, nu inversând
    textul: textul are 400 de fișiere, valorile sunt câteva.

    Granițele sunt pe litere și cifre, nu pe `\\b`: valoarea începe și se termină
    în litere, iar vecinii reali sunt `/`, `@`, `"`, `=`, `<`. Ce resping ele e
    exact ce nu e valoarea — un domeniu scurt din interiorul unui cuvânt mai
    lung, care altfel ar cere ștergerea unor cuvinte nevinovate până când cineva
    ar scoate garda din suită.
    """
    def rewritten(v: str) -> str:
        return "".join(_DOT_REWRITINGS if ch == "." else re.escape(ch) for ch in v)

    # `dict.fromkeys` și nu `set`: ordinea contează pentru mesajul de eroare, iar
    # o valoare palindrom ar da de două ori aceeași alternativă.
    alternatives = "|".join(dict.fromkeys((rewritten(value), rewritten(value[::-1]))))
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alternatives})(?![A-Za-z0-9])",
                      re.IGNORECASE)


def _secret_store_values(rel: str) -> dict[str, str]:
    """`KEY=VALUE` din magazia locală. Valorile nu părăsesc procesul."""
    values: dict[str, str] = {}
    text = (REPO / rel).read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("\"'")
        if value:
            values[key.strip()] = value
    return values


def _gitignore_problem(rel: str) -> str | None:
    """None dacă fișierul e sigur ignorat de git; altfel motivul, ca text.

    `git check-ignore`: 0 = ignorat, 1 = NU e ignorat, ≥128 = git a eșuat.
    Ultimul nu se confundă cu al doilea — „n-am putut afla" nu e „e în regulă".

    Întoarce text în loc să asserteze, ca să poată fi chemat din două teste cu
    același mesaj. Cu două copii, una s-ar fi reparat și cealaltă nu.
    """
    ignored = subprocess.run(["git", "check-ignore", "-q", rel], cwd=REPO,
                             capture_output=True)
    if ignored.returncode not in (0, 1):
        return (f"nu s-a putut afla dacă {rel} e ignorat de git (cod "
                f"{ignored.returncode}) — verificarea nu se poate face în siguranță")
    if ignored.returncode != 0:
        return (f"{rel} NU e ignorat de git — magazia de secrete e pe cale să fie "
                "publicată ea însăși")
    return None


def _identity_values(sources: tuple[str, ...]) -> tuple[dict[str, list[str]], list[str]]:
    """({cheie: [intrări]}, probleme) — probleme sunt ȘIRURI, niciodată valori.

    O cheie lipsă, o cheie goală, o listă din care nu iese nicio intrare și o
    intrare prea scurtă ca s-o cauți fără zgomot sunt patru feluri de a acoperi
    nimic, iar toate patru trebuie să se vadă. Diferența față de `too_short` de
    la secrete e doar că aici lipsa cheii e ea însăși o problemă: un secret pe
    care magazia nu-l are chiar nu există, dar operatorul are întotdeauna un nume
    de utilizator.
    """
    found: dict[str, list[str]] = {}
    problems: list[str] = []
    raw: dict[str, str] = {}
    for source_rel in sources:
        raw.update(_secret_store_values(source_rel))

    where = " / ".join(sources)
    for key, what in IDENTITY_KEYS.items():
        if key not in raw:
            problems.append(f"{key} lipsește din {where} — pune acolo {what}")
            continue
        entries = [e.strip() for e in raw[key].split(",")]
        entries = [e for e in entries if e]
        if not entries:
            problems.append(
                f"{key} există în {where} dar nu conține nicio intrare — {what}")
            continue
        short = [i for i, e in enumerate(entries, 1)
                 if len(e) < MIN_SEARCHABLE_SECRET]
        if short:
            # Poziția, nu valoarea: mesajul de eșec al unei gărzi de scurgere nu
            # are voie să tipărească ce apără.
            problems.append(
                f"{key}: intrarea/intrările {short} au sub {MIN_SEARCHABLE_SECRET} "
                "caractere, deci NU au fost căutate")
        keep = [e for e in entries if len(e) >= MIN_SEARCHABLE_SECRET]
        if keep:
            found[key] = keep
    return found, problems


def _scan_identity(sources: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """(apariții, probleme) — ȘIRURI deja formatate, niciodată valori.

    Aceeași disciplină ca `_scan_secret_store`, și pentru același motiv: `-l`
    randează variabilele locale ale fiecărui cadru din traceback, iar cadrul care
    a ținut numele de utilizator nu are voie să mai fie pe stivă când pică
    aserțiunea. Numele operatorului e mai puțin periculos decât o parolă și
    exact la fel de inutil de publicat.
    """
    found: dict[str, list[str]] = {}
    problems: list[str] = []
    offenders: list[str] = []
    matchers: list[tuple[str, re.Pattern[str]]] = []
    key = value = text = None
    try:
        found, problems = _identity_values(sources)
        # Buclă explicită, nu comprehensiune: o comprehensiune are cadrul EI, pe
        # care golirea de mai jos nu-l atinge. Dacă `_identity_matcher` ar arunca
        # dinăuntrul ei, cadrul acela ar ajunge în traceback cu valoarea legată.
        for key, entries in found.items():
            for value in entries:
                matchers.append((key, _identity_matcher(value)))
        for rel in _tracked_files():
            for source, text in _contents(rel):
                for key, rx in matchers:
                    for line_no in _locations_of(text, rx):
                        where = f"{rel}:{line_no}" if line_no else f"{rel} (linie nesigură)"
                        offenders.append(f"{where} ({source}) — o intrare din {key}")
    except Exception as exc:
        # Doar numele tipului. `str(exc)` al unei erori de regex citează tiparul,
        # iar tiparul e construit din valoare — și tot din valoare e construit
        # `matchers`, prin `.pattern`, deci și el se golește.
        name = type(exc).__name__
        found, matchers, entries = {}, [], None
        key = value = text = None
        raise RuntimeError(f"scanarea identității a eșuat: {name}") from None
    except BaseException:
        found, matchers, entries = {}, [], None
        key = value = text = None
        raise
    return offenders, problems


def _scan_secret_store(sources: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """(scurgeri, chei necăutabile) — ȘIRURI deja formatate, niciodată valori.

    Funcția asta e singurul loc în care valorile reale sunt legate de un nume, și
    nu asertează nimic: se ÎNTOARCE. Când aserțiunea din test eșuează, cadrul de
    aici nu mai e pe stivă, deci `pytest -l` n-are ce randa din el.

    Nicio ieșire prin excepție nu are voie să ridice cadrul ăsta într-un
    traceback cu valorile în el — de aici cele DOUĂ clauze `except`, care golesc
    numele înainte să arunce mai departe. `f_locals` se citește la raportare, nu
    la ridicare, deci golirea ajunge la timp.

    Două, nu una, fiindcă `Exception` nu prinde `KeyboardInterrupt` și
    `SystemExit`. Un Ctrl-C în secundele de scanare ieșea pe lângă clauză, cadrul
    rămânea pe stivă plin, iar `--full-trace` îl randa — adică exact clipa în
    care cineva depanează garda. `BaseException` nu se transformă în altceva
    (un Ctrl-C trebuie să rămână Ctrl-C), doar se golește și se re-aruncă.
    """
    values: dict[str, tuple[str, str]] = {}
    too_short: list[str] = []
    offenders: list[str] = []
    key = value = src = text = None
    try:
        for source_rel in sources:
            for key, value in _secret_store_values(source_rel).items():
                # Vezi comentariul de la `IDENTITY_KEYS`: alea sunt liste, nu
                # valori, și au testul lor.
                if key in IDENTITY_KEYS:
                    continue
                if len(value) < MIN_SEARCHABLE_SECRET:
                    too_short.append(f"{key} ({source_rel})")
                else:
                    values[key] = (source_rel, value)

        for rel in _tracked_files():
            for source, text in _contents(rel):
                for key, (src, value) in values.items():
                    for line_no in _locations(text, value):
                        where = f"{rel}:{line_no}" if line_no else f"{rel} (linie nesigură)"
                        offenders.append(
                            f"{where} ({source}) — valoarea lui {key} din {src}")
    except Exception as exc:
        # Doar numele tipului: `str(exc)` al unei erori de regex citează tiparul,
        # iar tiparul e construit din valoare.
        name = type(exc).__name__
        values = {}
        key = value = src = text = None
        raise RuntimeError(f"scanarea magaziei de secrete a eșuat: {name}") from None
    except BaseException:
        # Ctrl-C, SystemExit, orice altceva care nu e `Exception`. Nu se
        # convertește — se golește cadrul și se lasă să plece mai departe.
        values = {}
        key = value = src = text = None
        raise
    return offenders, too_short


def test_the_value_matcher_sees_through_every_rewriting_of_the_same_value() -> None:
    """Fără asta, verificarea ar prinde doar forma copiată verbatim.

    O valoare rescrisă cu separatori, cu underscore, în hexazecimal sau spartă în
    doi literali alăturați e aceeași valoare pentru cine o citește din depozitul
    public. Fiecare formă de mai jos există fiindcă un om chiar scrie așa; dacă
    vreuna încetează să fie prinsă, valoarea trece pe lângă gardă și ajunge în
    depozit, unde rămâne și după ce e ștearsă din arbore.

    Probele au opt, zece și treisprezece cifre — un cont Telegram vechi, unul de
    azi, un supergrup — ca nicio prescurtare legată de lungime să nu poată intra
    neobservată.
    """
    for standin in (_STANDIN, _STANDIN_8, _STANDIN_13):
        n = int(standin)
        head, mid, tail = standin[:1], standin[1:4], standin[4:]
        forms = {
            "verbatim": f"x = {standin}",
            "în șir": f'x = "{standin}"',
            "în comentariu": f"# vezi {standin}",
            "underscore": f"x = {head}_{mid}_{tail}",
            "virgule": f"x = {head},{mid},{tail}",
            "spații": f"x = {head} {mid} {tail}",
            "puncte": f"x = {head}.{mid}.{tail}",
            "cratime": f"x = {standin[:3]}-{standin[3:6]}-{standin[6:]}",
            "hexazecimal": f"x = {hex(n)}",
            "hexazecimal cu majuscule": "x = 0X" + format(n, "X"),
            "doi literali alăturați": f'x = "{standin[:5]}" "{standin[5:]}"',
            "doi literali cu +": f'x = "{standin[:5]}" + "{standin[5:]}"',
            "doi literali cu + fără spații": f'x = "{standin[:5]}"+"{standin[5:]}"',
        }
        for name, form in forms.items():
            assert _locations(form, standin), \
                f"neprins ({len(standin)} cifre) — {name}: {form!r}"

    # Și nu orice: valoarea din interiorul unui număr mai lung nu e valoarea, iar
    # hexazecimalul fără prefix s-ar potrivi în orice hash.
    #
    # Cazul hexa are terminația `z` dinadins: cu un caracter hexa după el,
    # `(?![0-9a-fA-F])` ar respinge oricum potrivirea, iar proba ar trece și fără
    # cerința prefixului `0x` — adică ar demonstra altceva decât spune.
    hexa = format(int(_STANDIN), "x")
    for form in (f"x = 9{_STANDIN}", f"x = {_STANDIN}9", "x = 555000111",
                 f"h = 'zzz{hexa}zzz'"):
        assert not _locations(form, _STANDIN), f"alarmă falsă: {form!r}"

    # Sentinela: potrivire reală pe text, dar pe nicio linie. Trebuie raportată,
    # nu pierdută.
    across_lines = f'x = ("{_STANDIN[:5]}"\n     "{_STANDIN[5:]}")'
    assert _locations(across_lines, _STANDIN) == [0]

    # Un secret nenumeric se caută ca atare, inclusiv lipit de altceva.
    assert _locations("KEY=abcdef123456", "abcdef123456") == [1]

    # Și o valoare care conține ea însăși ce normalizarea mătură. Aici, ghilimele
    # alăturate: formele normalizate le șterg din text ȘI din valoare, deci doar
    # forma BRUTĂ o mai găsește. Proba e ce ține forma brută în listă — fără ea
    # se poate scoate ca redundantă, cu suita verde.
    assert _locations("""K = 'a" "b'""", 'a" "b') == [1]


@pytest.mark.skipif(
    shutil.which("git") is None,
    reason="fără git nu se pot enumera fișierele care ar pleca într-un push, "
           "deci nu se poate căuta în ele")
def test_no_value_from_the_local_secret_store_appears_in_the_tree() -> None:
    """Ce e în `secrets/` e, prin definiție, ce nu are voie să fie publicat.

    Chat id-ul operatorului a intrat de două ori în suita de teste — o constantă
    de modul și o valoare implicită de parametru — și nicio verificare nu s-a
    uitat la el. Singur nu deschide nimic (mai trebuie și jetonul botului), dar e
    un identificator stabil al persoanei într-un depozit public, iar acolo rămâne
    și după ce e șters din arbore. Aceeași verificare acoperă parola bazei,
    jetonul, cheia API și PIN-ul, fiindcă toate stau în același fișier.

    Mesajul de eșec numește cheia și locul, niciodată valoarea: un test de
    scurgere care tipărește secretul în propria ieșire îl mută dintr-un loc
    privat în altul public.
    """
    for src in SECRET_STORE:
        if not (REPO / src).is_file():
            pytest.skip(
                f"{src} lipsește, deci verificarea pe valoare NU s-a făcut — nu e "
                "o trecere. Pe o clonă proaspătă e normal; înainte de push, rulează "
                "pe mașina care are magazia de secrete.")
        # Dacă sursa de adevăr ajunge urmărită, ea e scurgerea, nu ce caută ea.
        assert _gitignore_problem(src) is None, _gitignore_problem(src)

    # Valorile trăiesc și mor în cadrul de mai jos. Aici nu ajunge decât text
    # deja formatat, ca `-l` să n-aibă ce scoate la iveală.
    offenders, too_short = _scan_secret_store(SECRET_STORE)

    assert not offenders, (
        "valori reale din magazia de secrete, în arborele publicabil:\n  "
        + "\n  ".join(offenders[:20]))
    assert not too_short, (
        "valori prea scurte ca să fie căutate fără zgomot, deci NEVERIFICATE: "
        + ", ".join(too_short))


# --- Identitatea operatorului -----------------------------------------------

# Valori de probă, la fel ca `_STANDIN`: nu sunt ale nimănui. Amândouă conțin un
# punct, fiindcă punctul e singurul caracter cu rescrieri de acoperit, iar o
# probă fără el ar lăsa toate cele trei forme de punct nedemonstrate.
_STANDIN_USER = "standin.account"
_STANDIN_DOMAIN = "standin-domain.example"


def test_the_identity_matcher_sees_through_the_rewritings_that_occur_here() -> None:
    """Fără asta, garda de identitate ar prinde doar forma copiată verbatim.

    Fiecare formă de mai jos e un mod în care numele operatorului sau domeniul
    lui CHIAR sunt scrise în depozitul ăsta: o cale din `/home`, un `ssh
    utilizator@gazdă` dintr-o procedură, un URL de contact, un punct scăpat
    într-o fixtură de expresie regulată, și adresa de e-mail scrisă inversat ca
    să nu fie recoltată. Dacă vreuna încetează să fie prinsă, valoarea trece pe
    lângă gardă și rămâne în istoricul public și după ce e ștearsă din arbore.

    Testul verifică și limitele declarate în docstring-ul modulului: forma fără
    punct NU se prinde, și e scrisă aici ca aserțiune tocmai ca să nu rămână doar
    o afirmație în proză pe care n-o măsoară nimeni.
    """
    # Podeaua de corpus. O listă parametrizată ieșită goală a trecut deja o dată
    # în depozitul ăsta, verde și fără să verifice nimic; aici, dacă cineva șterge
    # forme, testul spune câte au rămas în loc să treacă mai repede.
    EXPECTED_FORMS = 15

    for standin in (_STANDIN_USER, _STANDIN_DOMAIN):
        dotted = standin.replace(".", "%2E")
        dotted_lower = standin.replace(".", "%2e")
        escaped = standin.replace(".", r"\.")
        head, tail = standin[:5], standin[5:]
        forms = {
            "verbatim": f"contul {standin} are shell",
            "în cale": f"/home/{standin}/.ssh/config",
            "în cale, ghilimele auditd": f'cwd="/home/{standin}"',
            "în ssh utilizator@gazdă": f"ssh {standin}@203.0.113.10",
            "în URL": f"https://{standin}/contact",
            "ca sufix de subdomeniu": f"https://sentinel.{standin}/api",
            "în e-mail": f"scrie la contact@{standin}",
            "punct procent-codat": f"/home/{dotted}/x",
            "punct procent-codat minuscul": f"/home/{dotted_lower}/x",
            "punct scăpat de regex": f're.compile(r"^/home/{escaped}/")',
            "inversat, ca data-d": f'<a data-u="olleh" data-d="{standin[::-1]}">',
            "majuscule": f"contul {standin.upper()} are shell",
            "majuscule mixte": f"contul {standin.capitalize()} are shell",
            "doi literali alăturați": f'x = "{head}" "{tail}"',
            "doi literali cu +": f'x = "{head}" + "{tail}"',
        }
        assert len(forms) == EXPECTED_FORMS, (
            f"corpusul de forme are {len(forms)}, nu {EXPECTED_FORMS} — dacă "
            "scoaterea a fost intenționată, coboară podeaua ODATĂ CU ea, ca "
            "numărul să rămână o măsurătoare")
        rx = _identity_matcher(standin)
        for name, form in forms.items():
            assert _locations_of(form, rx), f"neprins — {name}: {form!r}"

    # Și nu orice. Valoarea lipită de litere sau cifre nu e valoarea: fără
    # granițe, un domeniu scurt din interiorul unui cuvânt mai lung ar cere
    # ștergerea unor cuvinte nevinovate până când cineva ar scoate garda.
    rx = _identity_matcher(_STANDIN_DOMAIN)
    for form in (f"x{_STANDIN_DOMAIN}", f"{_STANDIN_DOMAIN}x",
                 f"{_STANDIN_DOMAIN}9"):
        assert not _locations_of(form, rx), f"alarmă falsă: {form!r}"

    # Limita declarată în docstring: punctul ȘTERS nu e o rescriere a aceleiași
    # valori, e alt identificator, iar el apare legitim în comanda `git clone`
    # din README. Dacă asta se schimbă vreodată, se schimbă și proza de sus.
    rx = _identity_matcher(_STANDIN_USER)
    assert not _locations_of(_STANDIN_USER.replace(".", ""), rx), \
        "forma fără punct e prinsă acum — docstring-ul modulului spune că nu e"

    # Potrivirea peste linii trebuie raportată, nu pierdută: aceeași sentinelă ca
    # la secrete, pe același `_locations_of`.
    across = f'x = ("{_STANDIN_USER[:5]}"\n     "{_STANDIN_USER[5:]}")'
    assert _locations_of(across, rx) == [0]

    # Canar pe verificarea de gitignore: dacă ar întoarce mereu None, garda de
    # mai jos ar trece peste o magazie devenită urmărită fără să spună nimic.
    # `README.md` e urmărit și neignorat prin construcție.
    assert _gitignore_problem("README.md") is not None, \
        "verificarea de gitignore nu mai poate spune „nu e ignorat"

    # Și că lista de chei nu poate ieși goală: o gardă fără nimic de căutat ar
    # trece verde peste tot.
    assert IDENTITY_KEYS, "IDENTITY_KEYS e gol — garda n-ar căuta nimic"
    assert all(v.strip() for v in IDENTITY_KEYS.values()), \
        "o cheie fără explicație scrisă lasă mesajul de eșec fără instrucțiune"


def test_the_identity_guard_says_so_when_the_store_tells_it_nothing(tmp_path) -> None:
    """Patru feluri de a acoperi nimic, și niciunul n-are voie să arate a verde.

    O gardă de sanitizare căreia nu i s-a spus ce să caute nu găsește nimic — și
    exact asta arată identic cu „depozitul e curat". Depozitul ăsta a livrat deja
    o listă parametrizată ieșită goală și sărită tăcut, și o podea de corpus pusă
    sub numărul de cazuri; a treia oară s-ar chema tipar.

    Ultimul caz e la fel de important ca primele patru: pe o magazie bună, lista
    de probleme trebuie să iasă GOALĂ, iar intrările să fie despicate toate. Fără
    el, o verificare stricată în sens invers — care se plânge mereu — ar trece
    testul ăsta și ar fi comentată de cineva vineri seara.
    """
    def problems_for(body: str) -> list[str]:
        store = tmp_path / "store.env"
        store.write_text(body, encoding="utf-8")
        # `REPO / <cale absolută>` întoarce calea absolută — magazia de probă
        # trăiește în tmp_path, nu în depozit.
        return _identity_values((str(store),))[1]

    keys = list(IDENTITY_KEYS)
    first, second = keys[0], keys[1] if len(keys) > 1 else keys[0]
    good = f"{_STANDIN_USER},{_STANDIN_DOMAIN}"

    absent = problems_for(f"{second}={good}\n")
    assert any(first in p and "lipsește" in p for p in absent), absent

    empty = problems_for(f"{first}=\n{second}={good}\n")
    assert any(first in p for p in empty), ("o cheie cu valoare goală trebuie "
                                            f"raportată, nu ignorată: {empty}")

    only_commas = problems_for(f"{first}= , ,,\n{second}={good}\n")
    assert any(first in p and "nicio intrare" in p for p in only_commas), only_commas

    too_short = problems_for(f"{first}=abc,{_STANDIN_USER}\n{second}={good}\n")
    assert any(first in p and "NU au fost căutate" in p for p in too_short), too_short

    # Și magazia bună: fără plângeri, și cu TOATE intrările despicate. O
    # despicare care ar păstra doar prima ar lăsa al doilea cont neverificat.
    store = tmp_path / "store.env"
    store.write_text(f"{first}={good}\n{second}={good}\n", encoding="utf-8")
    found, clean = _identity_values((str(store),))
    assert clean == [], clean
    assert set(found) == set(IDENTITY_KEYS), found
    assert all(len(v) == 2 for v in found.values()), (
        "lista despărțită prin virgulă nu s-a despicat toată — a doua intrare "
        "ar rămâne necăutată, în tăcere")


@pytest.mark.skipif(
    shutil.which("git") is None,
    reason="fără git nu se pot enumera fișierele care ar pleca într-un push, "
           "deci nu se poate căuta în ele")
def test_no_operator_identity_appears_in_the_tree() -> None:
    """Cine e monitorizat, și unde se uită după restul.

    Numele de utilizator dă jumătate dintr-o acreditare SSH și prefixul fiecărei
    căi din `/home`. Domeniul înregistrabil dă, printr-un jurnal de transparență
    a certificatelor, subdomeniul martorului extern — singura mașină pe care un
    atacator cu root pe gazda monitorizată NU o controlează. Niciuna nu deschide
    ceva singură, și amândouă transformă recunoașterea, partea scumpă a unui
    atac, în două căutări.

    Mesajul de eșec numește cheia și locul, niciodată valoarea.
    """
    for src in SECRET_STORE:
        if not (REPO / src).is_file():
            pytest.skip(
                f"{src} lipsește, deci verificarea pe identitate NU s-a făcut — nu "
                "e o trecere. Pe o clonă proaspătă e normal: acolo nu există nimic "
                "de protejat. Înainte de push, rulează pe mașina operatorului.")
        assert _gitignore_problem(src) is None, _gitignore_problem(src)

    offenders, problems = _scan_identity(SECRET_STORE)

    report: list[str] = []
    if problems:
        report.append("NU S-A VERIFICAT — magazia locală nu spune ce să caute:")
        report += [f"  - {p}" for p in problems]
        report.append(
            "Pune-le în " + " / ".join(SECRET_STORE) + ", câte o listă despărțită "
            "prin virgulă per cheie. Fișierul e ignorat de git, deci valorile nu "
            "ajung în depozit. deploy/install.sh le primește pe stdin ca pe orice "
            "altă linie și avertizează o dată per cheie că nu le scrie — corect, "
            "n-au ce căuta pe server.")
    if offenders:
        report.append("identitatea operatorului, în arborele publicabil:")
        report += [f"  - {o}" for o in offenders[:20]]

    assert not report, "\n  " + "\n  ".join(report)
