#!/usr/bin/env bash
# VPS watchdog - monitorizare disponibilitate/capacitate + auto-remediere marginita.
#
# Rulat de vps-watchdog.timer, o data pe minut. Nu depinde de Sentinel (nici baza
# de date, nici venv-ul): foloseste doar bash, awk, curl si docker. Trimite pe
# Telegram cu tokenul din secrets.env, deci mesajele ajung sub numele botului
# Sentinel - de aceea scriptul traieste in depozit, revizuit, nu pe gazda.
#
# CONFIGURAREA GAZDEI NU E AICI. Domeniile verificate sunt ale unor clienti, iar
# depozitul e public: stau in /etc/sentinel/vps-watchdog.conf (vezi
# deploy/config/vps-watchdog.conf.example) si se citesc la fiecare rulare. Fisierul
# NU e executat (`source`): se citesc doar cheile de mai jos, ca date.
#
# ---------------------------------------------------------------------------
# 1. Identitatea unei probleme e CHEIA (campul dinaintea primului `|`), nu linia.
#
# Versiunea de dinainte compara linii intregi, iar linia continea masuratoarea
# ("Swap la 99%"). Fiecare punct procentual de miscare producea o "problema noua"
# si una "rezolvata" - operatorul a primit "Swap la 99%" ca nou si "Swap la 100%"
# ca rezolvat, desi nimic nu se rezolvase. Acum noua/rezolvata se calculeaza
# doar din chei; o problema care persista cu alta valoare nu emite nimic.
#
# Fisierul de stare pastreaza TOT randul (cheie|text), pentru ca mesajul
# "rezolvat" trebuie sa citeze textul unei probleme care nu mai exista in rularea
# curenta. Formatul e cel vechi, deci o stare scrisa de versiunea dinainte se
# citeste fara migrare - si ramane cel vechi: contoarele de la sectiunea 5 stau
# intr-un fisier separat (hysteresis.state), nu in coloane noi ale acestuia.
#
# ---------------------------------------------------------------------------
# 2. Swap-ul plin NU e o defectiune; paginarea activa ESTE.
#
# Pragul pe procentul de swap masura consecinta: nucleul scosese ~2 GB pe disc
# cand RAM-ul fusese strans, iar swap-ul ramanea la 99-100% ore intregi dupa ce
# presiunea trecuse (vmstat: si=0 so=0). Alerta suna pe starea statica, nu pe
# eveniment. Acum se masoara RITMUL: pswpin+pswpout din /proc/vmstat sunt
# contoare cumulative, deci se pastreaza un istoric scurt (vmstat.ring) si se
# calculeaza media pagini/s pe ~5 minute.
#
#   PAGING_PAGES_S_MAX=100  (implicit)
#     Masurat pe capacity_samples (2026-10-09..21, 33k esantioane la ~31 s),
#     cu suma |variatiei swap| pe 300 s ca margine inferioara a ritmului brut:
#     sub 100 pagini/s raman doar salturi izolate de 8-15 MB (<= ~13 pagini/s
#     pe 5 min, zilnic); peste, 12 episoade in 12 zile, fiecare cu >= ~117 MB
#     miscati in 5 min, inclusiv cele trei din ultimele 24 h (doua dintre cele 12
#     sunt scaderi bruste de 720-800 MB intr-un singur esantion - swapoff sau
#     repornire, nu paginare - deci numarul e un plafon). Intre 50 si 250
#     numarul de episoade se schimba doar 14 -> 10: pragul nu e sensibil.
#     Paginarea de pe gazda vine in rafale de 30-65 s (ex.: 560 MB intr-un
#     minut), nu in platouri: de aceea e o MEDIE pe fereastra, nu "N rulari la
#     rand peste prag", care ar fi ratat toate cele trei evenimente.
#     Contoarele din /proc/vmstat de pe gazda dau in medie 3,3 pagini/s
#     (brut, pe 2,7 zile, rafalele incluse), deci in afara rafalelor ritmul real e ~0.
#
# Prima rulare dupa instalare (sau dupa repornire, sau dupa o pauza lunga) NU are
# un esantion anterior: nu alerteaza si nu raporteaza niciun ritm. Cat timp nu
# exista istoric de cel putin PAGING_MIN_SPAN_S, verificarea e "fara verdict" -
# NU "sanatoasa": o problema deja semnalata ramane semnalata, nu se declara
# rezolvata din lipsa de date. Cu timerul de 60 s, verdictul apare la a treia
# rulare (tests/security/test_vps_watchdog.py tine legatura asta).
#
# Contoarele care scad (repornire) sau ceasul dat inapoi arunca istoricul.
#
# ---------------------------------------------------------------------------
# 3. RAM disponibil: pragul 1200 MB (MEM_AVAIL_MIN_MB), nu 400.
#
# Gazda are 7680 MB. Pragul de 400 MB (cel vechi) s-a atins o SINGURA data in 12,5
# zile: 85 MB, 2026-10-21 10:42:23 UTC, cu 22 s inainte ca nucleul sa omoare un proces
# (sectiunea 5). Pana atunci minimul fusese 809 MB (20 oct 17:22, swap-ul la 36%). Pe
# 12-19 octombrie minimul zilnic a fost 1642 MB; 1200 e de 1,48 ori peste 809 si cu 27%
# sub 1642, deci vede un eveniment ca cel din 20 oct fara sa sune pe zilele normale.
# Intre pragurile 900/1000/1200/1500 are cele mai putine episoade pe date (8, fata de
# 63/33/17): adica cele mai putine perechi nou/rezolvat. Se schimba in conf pe o gazda
# cu alta memorie.
#
# ---------------------------------------------------------------------------
# 4. "Nu pot citi" nu e "e bine".
#
# O masuratoare ilizibila (df, /proc/meminfo, /proc/loadavg, /proc/vmstat) da o
# problema `unk:*` si pastreaza starea anterioara a verificarii. Versiunea
# veche inlocuia valoarea lipsa cu una sanatoasa (disc 0%, RAM 99999 MB).
# Valorile invalide din conf se raporteaza (`sys:config:*`), nu se ignora tacut.
#
# ---------------------------------------------------------------------------
# 5. Histerezis pe RAM: aceeasi conditie nu intra si iese de patru ori in 5 minute -
#    dar o citire ADANCA nu asteapta nicio confirmare.
#
# Toate cifrele de aici vin din interogari pe capacity_samples rulate pe 2026-10-21
# (33542 de esantioane, 2026-10-09 00:00 .. 2026-10-21 11:58 UTC = 12,5 zile, mediana
# 32 s intre ele), prag 1200 MB, si din scriptul REAL rulat prin harness-ul din
# tests/security/test_vps_watchdog.py cu esantionul tinut pana la urmatoarea proba
# ("60 de faze" = secunda din minut in care cade proba, la cadenta timerului). O versiune
# anterioara a acestei sectiuni numara patru episoade si un singur episod de load; azi
# sunt opt si doua - cifrele nu se copiaza dintr-o zi in alta.
#
# Ce a vazut gazda: 8 episoade sub prag (16 traversari). UNUL lung: 20 oct 10:59 -> 21 oct
# 00:38, 13,65 h, 1543 de esantioane la rand, minim 809. SAPTE scurte, de 1-2 esantioane,
# toate pe 21 oct: 04:16 (1115), 05:41 (862), 05:43 (810), 09:51 (844), 09:53 (826) -
# zgomot - si 10:40 (497), 10:41 (85), care sunt evenimentul real. La 10:42:45 UTC
# (13:42:45 EEST) nucleul a chemat oom-killer si a omorat next-server (anon-rss 2476940
# kB); `oom_kill` din /proc/vmstat e 1 de la pornirea din 18 oct. Seria: 10:39:41 1354 |
# 10:40:19 1019 | 10:40:45 497 | 10:41:17 1505 | 10:41:44 939 | 10:42:23 85 | 10:42:54
# 2219 (swap 2047 -> 805, load1 20,5). Rafala de la 05:41 a fost 899 -> 1724 -> 810 ->
# 2164 MB in 2,5 minute; scriptul fara histerezis (cheia ca identitate, nimic altceva),
# rulat pe ea in cele 60 de faze, a trimis 3 mesaje in 27 de faze si 5 in 33 (2 sau 4
# dintre ele despre RAM, restul despre paginare).
#
# Patru mecanisme, fiecare cu ce cumpara MASURAT (mesaje de RAM, 60 de faze):
#
#   * REZOLVAT dupa MEM_CLEAR_RUNS=2 rulari consecutive peste prag: ASTA opreste perechile
#     nou/rezolvat. Cu o singura proba peste prag, "rezolvat" urmat de "nou" in 10 minute
#     apare de 83 de ori (suma pe cele 60 de faze, 12,5 zile); cu doua, de 0. Rafala de la
#     05:41-05:50, mesaje de RAM: 2 sau 4 (27 / 33 de faze, scriptul real) cu o singura proba;
#     2 in toate cele 60 de faze cu doua probe (model, confirmare 1); 0 sau 2 (57 / 3 faze,
#     scriptul real) cu ambele.
#   * Marja de 10% (MEM_CLEAR_MARGIN_PCT; rezolvat doar peste 1320 MB): pe cadenta de 60 s NU
#     schimba nimic pe datele de azi (0 "rezolvat" urmat de "nou", cu marja 0 si cu 10%, pe
#     60 de faze). Conteaza la cadenta nativa a esantioanelor (31 s): 2 -> 0, din cauza lui
#     1304 MB de la 05:42:43, care fara marja numara ca a doua proba "buna". A ramas ca
#     asigurare ieftina, nu ca mecanism dovedit pe cadenta reala. PLAFON: gazda traieste
#     dupa episodul lung la p1 = 1504 MB (p5 = 1534), deci o marja peste ~25% ar tine
#     alerta deschisa pentru totdeauna. Amplitudinea pe 5 minute in episodul lung: p99 =
#     112 MB (9,3%), maxim 141 MB (11,8%).
#   * CONFIRMARE: MEM_CONFIRM_RUNS=2 rulari CONSECUTIVE sub prag. Opreste doar caderile de
#     UN esantion (04:16, 09:51, 09:53, jumatate din 05:41): pe cele 10 ore de zgomot de
#     azi (00:38-10:38) da 0 mesaje in 57 de faze si o pereche in 3, fata de 4-8 mesaje
#     (media 5,5) cu confirmare 1. SINGURA, ar fi costat evenimentul real: pe seria de mai
#     sus, 27 de faze din 60 nu aveau niciun mesaj de RAM, iar in celelalte 33 anuntul
#     venea tarziu si cita 939 MB, nu adancimea (85). Alerta de RAM nu are voie sa devina
#     tacere in cel mai rau minut al lunii.
#   * SCAPARE DE ADANCIME: o citire sub MEM_DEEP_MB = MEM_DEEP_PCT (50%) din prag = 600 MB
#     se anunta IMEDIAT, fara confirmare. Limita se deriva din date: sub 810 MB exista
#     exact trei esantioane (809, 497, 85), si NICIUNUL intre 498 si 808 (interogarea cu
#     martor: <810 intoarce 3 randuri). Zgomotul scurt nu coboara sub 810; evenimentul a
#     coborat la 497 si 85. Orice limita din (497, 809) separa datele la fel (rulat cu 500,
#     600, 700, 800: rezultate identice); 600 e jumatatea pragului, deci urmareste pragul
#     din conf, si sta la 5,4% de media geometrica a golului (634). Rezultat pe aceeasi
#     serie, 60 de faze, scriptul real: 54 de faze anunta (32 citeaza 497, 21 citeaza 85,
#     una 939; TOATE inainte de kill-ul de la 10:42:45), 6 nu. Fara scapare: 33 de faze
#     anunta, toate citand 939, si 27 nu anunta deloc. Pe cele 10 ore de zgomot: neschimbat
#     (0,1 mesaje in medie), pe episodul lung: neschimbat (doua mesaje).
#
# GOLUL RAMAS, MASURAT: cu proba la secunda 17-22 din minut (6 din 60 de faze) nicio proba
# nu cade pe cele doua esantioane adanci (497 si 85 MB tin ~30 s fiecare), iar restul seriei
# (1019, 1505, 939) arata ca rafala de la 05:41. Alerta de RAM tace in acele faze; orice
# regula care le prinde plateste in zgomot (confirmare 1: 5,5 mesaje in 10 ore; "2 din
# ultimele 3": 2,1 si tot o faza muta). Nu e un gol de CANAL: in toate cele 60 de faze
# operatorul a primit un mesaj (load1 20,5 la 10:42:54, deci "Load1" la proba urmatoare;
# plus paginare, derivata din swap) - verificat pe scriptul real; o simulare fara load
# (cum a fost prima oara reprodusa) da "zero mesaje" doar fiindca nimeni nu a pus load-ul.
# Serviciul real pornea in acel minut la secundele 37 si 46 (jurnal: 13:41:37 si 13:42:46
# EEST); citirea de RAM vine la cateva secunde dupa pornire, deci tot in zona prinsa -
# dar faza deriva cu ~1 s pe minut si trece prin toate secundele intr-o ora, deci golul
# e ~10% din timp, nu zero. CE INCHIDE GOLUL, dar DUPA kill, nu inainte: contorul `oom_kill`
# din /proc/vmstat - o crestere intre doua rulari e dovada unui OOM kill indiferent de faza
# (sectiunea 6). Alerta de RAM ramane singura care poate suna INAINTE.
#
# Limita onesta: opt episoade si un singur OOM sunt un esantion mic; cifrele sunt cele mai
# mici care opresc ce s-a vazut, nu o garantie pentru alte rafale. Ipoteza modelului:
# intre doua esantioane de ~31 s valoarea se tine; ce a facut RAM-ul intre ele nu se stie.
#
# DOAR cap:mem, si fiecare alta verificare a fost decisa separat:
#   cap:paging - e deja o medie pe ~5 minute (sectiunea 2): are propria confirmare.
#   cap:disk   - masurat: 18,4-85,9%, rampa de 8-10 puncte/zi (12-15 oct) si o singura
#                curatare (16 oct, 85,4 -> 18,4). Cu pragul implicit 88 niciun esantion
#                nu l-a atins: zero traversari, deci nicio cifra pentru histerezis. `df`
#                rotunjeste in sus la intreg: langa 85 a stat 16 h, iar un prag pus la 86
#                ar fi avut 6 intrari/iesiri - de aceea nu se coboara pragul fara a relua
#                masuratoarea. Un minut de intarziere nu cumpara nimic.
#   cap:load   - load1 e deja o medie exponentiala a nucleului: 2 episoade peste 2,0 x 4
#                nuclee (19 oct 21:53, 3 esantioane, varf 34,6; 21 oct 10:42:54, 4
#                esantioane, varf 20,5), fara reintrari. Al doilea e chiar minutul OOM.
#   sys:docker, ctr:*, net:* - nu au nicio masuratoare in capacity_samples, deci nicio
#                cifra de sustinut; un daemon cazut sau un site al unui client picat
#                e exact ce vrea operatorul repede. NEMASURAT, nu "sigur".
#   Mesajele de auto-remediere (reparare, "urmaresc", "dezactivat") raporteaza o ACTIUNE
#                sau o stare deja luata; nu trec prin diferenta de chei si nu se intarzie.
#   unk:*, sys:config:* - se spun imediat: sunt chiar lipsa de date.
#
# Contoarele stau in hysteresis.state, `cheie|pend|n|ts` (anuntul asteptat) sau
# `cheie|clear|n|ts` (rezolvarea asteptata); problems.state ramane `cheie|text`, deci
# nu exista nicio migrare, iar copia veche de pe gazda il citeste in continuare. Un
# contor e valid doar daca are 4 campuri numerice, `ts` nu e din viitor si e mai nou de
# HYST_STALE_S = 420 s. Fereastra NU e "3 cadente": un contor care expira intre doua
# rulari valide transforma confirmarea in tacere. Unitatea permite unei rulari sa dureze
# pana la TimeoutStartSec=300, iar timerul porneste urmatoarea la 60 s dupa - doua rulari
# terminate pot fi la 360 s; 420 = asta + 60 s, si un test leaga cele trei valori (cu 180,
# RAM la 900 MB timp de 20 de minute cu rulari la 200 s unul de altul nu da NICIUN mesaj,
# contorul ramane `pend|1`, iar `unk:hysteresis` nu apare: el acopera contoare ce nu se
# pot SCRIE, nu contoare EXPIRATE). Pe gazda reala asta e teoretic: din 2732 de porniri
# ale serviciului (jurnal, 19-21 oct) intervalul maxim a fost 68,9 s, niciunul peste 120 s;
# dar rularile se lungesc tocmai sub presiune (20 s in minutul OOM-ului). Alternativa
# luata in calcul - confirmare dupa TIMP scurs de la prima citire proasta, nu dupa numar
# de rulari - nu scoate fereastra: un contor tot trebuie sa expire undeva, altfel o citire
# de acum ore ar confirma una singura de azi; ar ajuta doar la rulari mai dese decat
# cadenta (pornite de mana) si cere un camp nou in fisier. NU s-a ales. Ramane: o rulare
# omorata de TimeoutStartSec nu produce nicio citire, iar doua la rand (peste 420 s) reseteaza
# numaratoarea - atunci serviciul apare in `systemctl --failed`, nu ca tacere de RAM.
# Un fisier de contoare lipsa, stricat sau expirat poate doar INTARZIA un mesaj - niciodata
# sa emita unul. Invers, un fisier care nu se poate scrie ar tine confirmarea la 1 pentru
# totdeauna si ar amuti alerta: atunci se renunta la confirmare (se anunta imediat) si
# se raporteaza `unk:hysteresis`. O citire ilizibila (unknown/carry) nu e proba: reseteaza
# numaratoarea, nu o avanseaza.
#
# ---------------------------------------------------------------------------
# 6. Nucleul a omorat ceva: contorul `oom_kill`, un EVENIMENT.
#
# Pe 21 oct 2026 nucleul a omorat o aplicatie de productie (next-server, anon-rss
# 2476940 kB) si operatorul n-a aflat de la nimeni. Sectiunea 5 e avertizare, adica un
# model: la ~1 faza din 10 proba cade intre citirile adanci, iar pe faza serviciului real
# alerta ar fi venit la 3-4 s DUPA kill. /proc/vmstat are un contor al nucleului,
# `oom_kill` (1 pe gazda azi, din 18 oct; un singur camp `oom*` din 185), care creste cu
# fiecare proces omorat de oom-killer, inclusiv in cgroup. O crestere intre doua rulari e
# dovada nucleului ca ceva a fost omorat: fara fals pozitiv si fara dependenta de faza. NU
# avertizeaza - raporteaza in cel mult un minut - deci completeaza sectiunea 5, n-o inlocuieste.
#
#   * EVENIMENT, nu stare. Nu are cheie, nu trece prin motorul de diferente, nu are
#     "problema noua" / "rezolvat" (nu e nimic de rezolvat) si nu se deduplica pe text: un
#     mesaj `💀 ... nucleul a omorat N proces(e)` pleaca direct. Ultima valoare vazuta sta in
#     oom_kill.state, langa restul starii, ca O PERECHE pe un rand: `<boot_id> <contor>`.
#   * Prima rulare nu are valoare anterioara: o retine si NU anunta. Fara asta, instalarea
#     ar anunta ca "nou" kill-ul de acum o zi, din istoria contorului.
#   * Contorul porneste de la 0 la FIECARE pornire, deci o valoare nu inseamna nimic fara
#     pornirea ei. Gazda se reporneste cam o data pe saptamana (`last -x reboot`: 4 sep, 10 sep,
#     15 sep, 29 sep, 5 oct, 18 oct: sase in 44 de zile), iar `OnBootSec=2min` pune
#     prima rulare la doua minute dupa pornire, exact cand cele noua containere pornesc deodata
#     si memoria e cea mai stransa. Fara pornire in stare, un kill de atunci era orb in doua
#     feluri: retinut 1, repornire, un kill => contorul e tot 1, egal cu baza, nici mesaj, nici
#     baza refacuta; retinut 3, repornire, doua kill-uri => 2, luat drept "repornire" si baza
#     refacuta TACUT. `/proc/sys/kernel/random/boot_id` (UUID, 37 de octeti cu newline,
#     citibil de oricine) se schimba la fiecare pornire: ALTA pornire => valoarea veche se
#     socoteste 0, deci orice contor > 0 se anunta ("oom_kill 0 -> N", cu o nota ca gazda s-a
#     repornit), iar un contor 0 reface baza fara mesaj si retine pornirea noua.
#   * Aceeasi pornire si contorul a SCAZUT: un contor al nucleului nu scade in cursul unei
#     porniri, deci "a fost o repornire" nu mai explica nimic. `unk:oom`, baza refacuta.
#   * `boot_id` ilizibil (lipsa, gol, alta forma) => `unk:oom` ("nu pot citi boot_id") si se
#     compara DOAR contorul, exact ca inainte de boot_id: o crestere se anunta, o scadere reface
#     baza fara mesaj, nimic nu se inventeaza si nimic nu e declarat sanatos. Starea retine
#     atunci `-` in loc de pornire; `-` (la scriere sau la citire) inseamna "nu stiu", nu "alta
#     pornire", iar la prima rulare cu `boot_id` citibil perechea se completeaza.
#   * Prima rulare (fisier lipsa) tace, deci un kill de dupa o stergere a starii nu se vede.
#   * Contor ilizibil sau lipsa (/proc/vmstat fara `oom_kill`) => `unk:oom` ("nu pot citi"),
#     ca la paginare: nici kill inventat, nici "sanatos". Fisier de stare care nu e EXACT o
#     pereche valida (gol, un singur numar - formatul de dinainte de boot_id -, un camp in
#     plus, o pornire care nu e UUID) => `unk:oom` o rulare si baza refacuta (un kill dintre
#     timp poate lipsi). Doar primul rand se citeste.
#   * O singura citire a /proc/vmstat pe rulare: aceeasi pentru paginare si OOM.
#   * Mesajul nu uita un kill: baza se muta DOAR dupa ce `curl` a primit 2xx. Un kill in
#     timpul unei pene de retea (exact cand o gazda sufocata de memorie pierde conexiuni)
#     se reincearca la urmatoarea rulare, deci poate veni de doua ori daca raspunsul s-a
#     pierdut dupa livrare - mai bine decat niciodata. Invers, temporarul cu valoarea noua se
#     scrie INAINTE de trimitere: daca nu se poate scrie, nu se anunta (fiecare minut ar
#     repeta aceeasi crestere) si apare `unk:oom`. La fel daca `mv` nu poate inlocui starea
#     (dupa mesaj sau la stabilirea bazei): `unk:oom`, nu o rulare care pare reusita.
#   * Victima: `journalctl -k` ruland ca root, linia `Killed process PID (nume) ... anon-rss`.
#     Marginit: `timeout` OOM_JOURNAL_TIMEOUT_S si fereastra OOM_LOOKBACK_MIN. Jurnalul gazdei
#     e persistent (Storage persistent, /var/log/journal ~1,6 G, istoric de la 26 sept - masurat
#     pe 22 oct; o nota mai veche il dadea volatil, nu mai e), deci fereastra NU e o scuza
#     pentru un jurnal care se pierde. 30 de minute acopera cateva reincercari ale unui mesaj
#     nelivrat (una pe minut); plafonul de timp e cel care tine rularea sub controlul unitatii
#     pe un jurnal mare. Un kill mai vechi nu e numit - mesajul spune asta si contorul ramane
#     dovada. `--since` trece peste repornire: dupa una, o victima de dinainte de ea poate fi
#     numita doar daca jurnalul n-are cele `delta` linii de dupa; `-b` nu s-a adaugat. Se iau
#     cel mult min(N, OOM_NAMES_MAX) randuri, cele mai noi. Daca nu gaseste nimic, mesajul spune asta
#     si pleaca oricum: contorul e dovada, numele e doar comoditate. Numele vine de la un
#     proces, deci se taie la caractere tiparibile si 40 de caractere. Formatul real are
#     paranteze in nume (`next-server (v`).
#
# Auto-remedierea containerelor (sectiunea docker) e neschimbata fata de
# versiunea de dinainte: aceleasi reguli, aceleasi plafoane.
set -uo pipefail

# Caile se pot muta doar prin mediu - pentru teste, nu pentru operare. Unitatea
# systemd nu seteaza nimic din ele.
SECRETS="${WATCHDOG_SECRETS:-/etc/sentinel/secrets.env}"
CONF="${WATCHDOG_CONF:-/etc/sentinel/vps-watchdog.conf}"
STATE_DIR="${WATCHDOG_STATE_DIR:-/opt/vps-watchdog/state}"
PROC="${WATCHDOG_PROC:-/proc}"

STATE="$STATE_DIR/problems.state"; SEEDED="$STATE_DIR/.seeded"; FIXDIR="$STATE_DIR/fix"
RING="$STATE_DIR/vmstat.ring"
HYST="$STATE_DIR/hysteresis.state"
OOM_STATE="$STATE_DIR/oom_kill.state"
mkdir -p "$STATE_DIR" "$FIXDIR"

# Valori implicite. Se pot suprascrie din conf (doar cele din lista de mai jos).
AUTO_FIX=1; MAX_FIX=3; UNHEALTHY_STREAK=2; EXCLUDE_AUTOFIX="root-app-1"
DISK_PCT_MAX=88; MEM_AVAIL_MIN_MB=1200; PAGING_PAGES_S_MAX=100; LOAD_PER_CORE_MAX=2.0
HEALTH_DOMAINS=""; CURL_TIMEOUT=10
# Constante de proiectare, nu de operare: fereastra tinta, istoricul minim fara
# de care nu dam verdict, si cat de vechi poate fi un esantion ca sa mai conteze.
PAGING_MIN_SPAN_S=120; PAGING_KEEP_S=330; PAGING_RING_MAX=8
# Histerezis (sectiunea 5 din antet): doar cap:mem. Constante de proiectare, nu de
# operare - o valoare gresita in conf (confirmare 99) ar amuti alerta de RAM.
# MEM_DEEP_PCT: sub aceasta parte din prag citirea se anunta FARA confirmare.
# HYST_STALE_S = TimeoutStartSec (300) + 2 cadente ale timerului: un contor mai vechi
# nu mai e "consecutiv", dar nici o rulare permisa de unitate nu trebuie sa-l expire
# (tests/security/test_vps_watchdog.py leaga cele trei valori).
MEM_CONFIRM_RUNS=2; MEM_CLEAR_RUNS=2; MEM_CLEAR_MARGIN_PCT=10; MEM_DEEP_PCT=50; HYST_STALE_S=420
HYST_POLICY="cap:mem=${MEM_CONFIRM_RUNS}/${MEM_CLEAR_RUNS}"
# OOM kill (sectiunea 6 din antet). Constante de proiectare: fereastra jurnalului acopera
# cateva reincercari ale unui mesaj nelivrat, nu istoria; plafonul de timp tine cautarea
# victimei sub controlul unitatii (o rulare agatata amuteste watchdog-ul).
OOM_LOOKBACK_MIN=30; OOM_NAMES_MAX=3; OOM_JOURNAL_TIMEOUT_S=5
# Chei care nu se mai emit. Se scot din starea anterioara, ca dispari lor sa nu
# apara ca "rezolvat" (swap-ul nu s-a rezolvat: pur si simplu nu mai e verificat).
RETIRED_KEYS="cap:swap"

problems=""; add(){ problems+="$1"$'\n'; }

# conf_get FISIER CHEIE -> valoarea, fara ghilimele; iese cu 1 daca fisierul nu
# se poate citi sau cheia lipseste. Nu executa nimic din fisier. Ultima aparitie
# castiga (ca la `source`); CR de la sfarsit de rand se ignora.
conf_get(){
  [ -r "$1" ] || return 1
  awk -v k="$2" -v q="'" '
    { sub(/\r$/, ""); line = $0; sub(/^[ \t]*export[ \t]+/, "", line) }
    index(line, k "=") == 1 { v = substr(line, length(k) + 2); found = 1 }
    END {
      if (!found) exit 1
      c = substr(v, 1, 1)
      if (c == "\"" || c == q) { v = substr(v, 2); i = index(v, c); if (i) v = substr(v, 1, i - 1) }
      else { sub(/[ \t]*#.*$/, "", v); sub(/[ \t]+$/, "", v) }
      print v
    }' "$1"
}

# setting NUME TIP - valoarea din conf peste cea implicita. O valoare invalida
# NU se ignora in tacere: ramane cea implicita, iar problema se vede.
setting(){
  local name="$1" kind="$2" val
  local re_int='^[0-9]+$' re_num='^[0-9]+(\.[0-9]+)?$' re_list='^[A-Za-z0-9._ -]*$'
  val=$(conf_get "$CONF" "$name") || return 0
  case "$kind" in
    int)  [[ "$val" =~ $re_int ]] ;;
    num)  [[ "$val" =~ $re_num ]] ;;
    list) [[ "$val" =~ $re_list ]] ;;
    *)    false ;;
  esac && { printf -v "$name" '%s' "$val"; return 0; }
  add "sys:config:${name}|⚙️ ${name} din ${CONF} e invalid ('${val}') - folosesc valoarea implicita"
}

if [ -e "$CONF" ] && [ ! -r "$CONF" ]; then
  add "sys:config|⚙️ Nu pot citi ${CONF} - folosesc valorile implicite, fara domenii de verificat"
fi
for s in AUTO_FIX:int MAX_FIX:int UNHEALTHY_STREAK:int DISK_PCT_MAX:int MEM_AVAIL_MIN_MB:int \
         PAGING_PAGES_S_MAX:int CURL_TIMEOUT:int LOAD_PER_CORE_MAX:num \
         HEALTH_DOMAINS:list EXCLUDE_AUTOFIX:list; do
  setting "${s%%:*}" "${s##*:}"
done

TG_TOKEN=$(conf_get "$SECRETS" TELEGRAM_BOT_TOKEN) || TG_TOKEN=""
TG_CHAT=$(conf_get "$SECRETS" TELEGRAM_CHAT_ID) || TG_CHAT=""
# Tokenul NU intra in argv (`ps` il arata oricui are cont pe gazda, iar aici se
# vorbeste cu planul de control al botului): URL-ul merge pe stdin, spre `curl -K -`.
# send_try TEXT - 0 doar daca curl a primit un raspuns 2xx (`-f`); 1 si cand nu e configurat
# niciun canal, si cand trimiterea a esuat. Doar evenimentele (sectiunea 6) il folosesc:
# ele nu au o stare care sa se reia singura, deci trebuie sa stie daca mesajul a plecat.
send_try(){
  [ -n "$TG_TOKEN" ] && [ -n "$TG_CHAT" ] || return 1
  printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$TG_TOKEN" \
    | curl -fsS -m 15 -K - --data-urlencode "chat_id=${TG_CHAT}" --data-urlencode "text=$1" >/dev/null 2>&1
}
send(){ send_try "$1" || true; }
HOST=$(hostname -s)
in_list(){ case " $2 " in *" $1 "*) return 0;; *) return 1;; esac; }
SEED=0; [ ! -f "$SEEDED" ] && SEED=1
baseline_extra=""

# Starea anterioara, fara cheile retrase. Citita inainte de orice verificare:
# `carry` are nevoie de ea.
prev=""
[ -f "$STATE" ] && prev=$(awk -v r="$RETIRED_KEYS" '
  BEGIN { n = split(r, a, " "); for (i = 1; i <= n; i++) dead[a[i]] = 1 }
  { i = index($0, "|"); k = (i ? substr($0, 1, i - 1) : $0); if (!(k in dead)) print }' "$STATE")

# prev_line CHEIE - randul anuntat in rularea trecuta (gol daca nu era anuntata).
prev_line(){ printf '%s\n' "$prev" | awk -F'|' -v k="$1" '$1 == k { print; exit }'; }
# carry CHEIE - pastreaza problema din rularea trecuta, daca era una. Pentru o
# verificare care NU poate spune nimic acum: "necunoscut" nu e "rezolvat". Pentru
# motorul de histerezis e un rand "inca rau": nu avanseaza numaratoarea de rezolvare.
carry(){
  local line
  line=$(prev_line "$1")
  [ -n "$line" ] && problems+="$line"$'\n'
  return 0
}
# unknown CHEIE-cap:* CE - nu am putut citi masuratoarea.
unknown(){
  add "unk:${1#cap:}|❔ Nu pot citi ${2} - starea (${1#cap:}) e NECUNOSCUTA, nu sanatoasa"
  carry "$1"
}

if timeout 20 docker info >/dev/null 2>&1; then
  while read -r name; do
    [ -z "$name" ] && continue
    pol=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$name" 2>/dev/null || echo "")
    case "$pol" in unless-stopped|always) ;; *) continue ;; esac
    status=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo "?")
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$name" 2>/dev/null || echo "")
    fa="$FIXDIR/$name.attempts"; fd="$FIXDIR/$name.disabled"; fu="$FIXDIR/$name.ustreak"

    # OK = running + healthy (sau fara healthcheck)
    if [ "$status" = "running" ] && { [ "$health" = "healthy" ] || [ -z "$health" ]; }; then
      if [ -f "$fd" ] || [ -f "$fa" ]; then rm -f "$fa" "$fd" "$fu"; send "✅ VPS ${HOST}: \"$name\" functional din nou (auto-fix resetat)."; else rm -f "$fu"; fi
      continue
    fi
    # PENDING = health "starting" (grace dupa pornire/restart): asteapta, nu reseta, nu reporni
    if [ "$status" = "running" ] && [ "$health" = "starting" ]; then continue; fi
    # crash-loop
    if [ "$status" = "restarting" ]; then add "ctr:$name:loop|🔁 \"$name\" in crash-loop - auto-fix NU reporneste crash-loop, necesita investigatie"; continue; fi
    # broken
    if [ "$status" = "running" ]; then brk="unhealthy"; else brk="down ($status)"; fi
    if in_list "$name" "$EXCLUDE_AUTOFIX"; then add "ctr:$name:excl|⛔ \"$name\" $brk (auto-fix exclus - manual)"; continue; fi
    if [ -f "$fd" ]; then add "ctr:$name:disabled|⛔ \"$name\" $brk (auto-fix dezactivat dupa esecuri - manual)"; continue; fi
    if [ "$SEED" = 1 ]; then baseline_extra+="• \"$name\" $brk (se va remedia automat)"$'\n'; continue; fi
    if [ "$AUTO_FIX" != 1 ]; then add "ctr:$name:brk|⚠️ \"$name\" $brk"; continue; fi
    # unhealthy: cere streak consecutiv
    if [ "$status" = "running" ]; then
      us=$(cat "$fu" 2>/dev/null || echo 0); us=$((us+1)); echo "$us" > "$fu"
      if [ "$us" -lt "$UNHEALTHY_STREAK" ]; then send "⚠️ VPS ${HOST}: \"$name\" unhealthy - urmaresc; repornesc daca persista."; continue; fi
    fi
    at=$(cat "$fa" 2>/dev/null || echo 0); at=$((at+1)); echo "$at" > "$fa"
    if [ "$at" -gt "$MAX_FIX" ]; then touch "$fd"; send "⛔ VPS ${HOST}: \"$name\" inca $brk dupa ${MAX_FIX} reporniri - auto-fix DEZACTIVAT, necesita interventie manuala."; continue; fi
    if docker restart "$name" >/dev/null 2>&1; then r=ok; else r=ESEC; fi
    rm -f "$fu"   # reset streak dupa restart (urmatorul restart cere iar 2 unhealthy)
    sleep 3
    ns=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo "?")
    send "🔧 VPS ${HOST} auto-remediere: \"$name\" era $brk → restart ($at/${MAX_FIX}, $r). Status acum: $ns."
  done < <(docker ps -a --format '{{.Names}}')
else
  add "sys:docker|🔴 Docker daemon nu raspunde"
fi

# --- /proc/vmstat: o singura citire pentru paginare si OOM -------------------
# VM_PIN / VM_POUT / VM_OOM = pswpin / pswpout / oom_kill, sau `-` daca lipsesc (fisier
# ilizibil, camp absent sau fara valoare). `-` nu e un numar, deci cele doua verificari de
# mai jos il citesc ca "nu pot citi", nu ca zero.
VM_PIN=""; VM_POUT=""; VM_OOM=""
read_vmstat(){
  read -r VM_PIN VM_POUT VM_OOM <<< "$(awk '
    $1 == "pswpin" || $1 == "pswpout" || $1 == "oom_kill" { v[$1] = $2 }
    function f(k) { return (k in v && v[k] != "") ? v[k] : "-" }
    END { print f("pswpin"), f("pswpout"), f("oom_kill") }' "$PROC/vmstat" 2>/dev/null)"
}

# --- paginare ---------------------------------------------------------------
# Vezi antetul, sectiunea 2. Scrie istoricul in $RING (atomic) si adauga
# cap:paging doar la un verdict HIGH.
check_paging(){
  local pin="$VM_PIN" pout="$VM_POUT" now res verdict rate span
  now=$(date +%s)
  if ! [[ "$pin" =~ ^[0-9]+$ && "$pout" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]]; then
    unknown cap:paging "pswpin/pswpout din $PROC/vmstat"; return 0
  fi
  local src="$RING"; [ -f "$src" ] || src=/dev/null
  res=$(awk -v now="$now" -v cin="$pin" -v cout="$pout" -v keep="$PAGING_KEEP_S" \
            -v minspan="$PAGING_MIN_SPAN_S" -v maxn="$PAGING_RING_MAX" -v thr="$PAGING_PAGES_S_MAX" '
    BEGIN { n = 0 }
    NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { t[n] = $1 + 0; pi[n] = $2 + 0; po[n] = $3 + 0; n++ }
    END {
      # Contoare mai mari decat cele de acum, esantion din viitor sau istoric
      # necrescator: repornire sau ceas dat inapoi. Istoricul nu mai spune nimic.
      reset = 0
      for (i = 0; i < n; i++) {
        if (t[i] > now || pi[i] > cin || po[i] > cout) reset = 1
        if (i > 0 && (t[i] < t[i-1] || pi[i] < pi[i-1] || po[i] < po[i-1])) reset = 1
      }
      m = 0
      if (!reset) for (i = 0; i < n; i++) if (now - t[i] <= keep) { kt[m] = t[i]; ki[m] = pi[i]; ko[m] = po[i]; m++ }
      kt[m] = now; ki[m] = cin; ko[m] = cout; m++
      first = (m > maxn) ? m - maxn : 0
      span = now - kt[first]; rate = 0; verdict = "NONE"
      if (span >= minspan) { rate = ((cin - ki[first]) + (cout - ko[first])) / span; verdict = (rate >= thr) ? "HIGH" : "OK" }
      printf "%s %.0f %.0f\n", verdict, rate, span
      for (i = first; i < m; i++) printf "%.0f %.0f %.0f\n", kt[i], ki[i], ko[i]
    }' "$src") || res=""
  if [ -z "$res" ]; then unknown cap:paging "istoricul de paginare (awk a esuat)"; return 0; fi
  if ! printf '%s\n' "$res" | tail -n +2 > "$RING.tmp" || ! mv -f "$RING.tmp" "$RING"; then
    unknown cap:paging "istoricul de paginare (nu pot scrie $RING)"; return 0
  fi
  read -r verdict rate span <<< "$(printf '%s\n' "$res" | head -n 1)"
  case "$verdict" in
    HIGH) add "cap:paging|📄 Paginare swap ~${rate} pagini/s (media pe ${span}s, prag ${PAGING_PAGES_S_MAX}/s)" ;;
    OK)   ;;
    *)    carry cap:paging ;;   # fara istoric suficient: nu stim, deci nu declaram rezolvat
  esac
}

# --- OOM kill ---------------------------------------------------------------
# Vezi antetul, sectiunea 6. Un EVENIMENT, nu o stare: nu are cheie, nu trece prin motorul
# de diferente si nu are "rezolvat". Mesajul pleaca direct; baza (ultima valoare a
# contorului `oom_kill`) se muta doar dupa ce mesajul a plecat.

# oom_victims N - cel mult N randuri `ora|pid|rss_kB|nume` din jurnalul nucleului, cele mai
# noi. Marginit in timp (`timeout`) si in fereastra (`--since`): jurnalul gazdei e mare
# (persistent, ~1,6 G), iar un kill mai vechi decat fereastra nu e gasit - mesajul atunci nu
# numeste nimic, ceea ce e mai bine decat un mesaj tarziu. Nu esueaza niciodata catre apelant.
# `[:print:]` scoate din nume orice caracter de control: numele vine de la un proces.
# Greedy pe nume: `comm` poate contine paranteze (pe gazda: "next-server (v").
oom_victims(){
  command -v journalctl >/dev/null 2>&1 || return 0
  timeout "$OOM_JOURNAL_TIMEOUT_S" journalctl -k --no-pager -q -o short-iso \
      --since "-${OOM_LOOKBACK_MIN}min" 2>/dev/null \
    | grep 'Killed process [0-9]' | tail -n "$1" | tr -cd '[:print:]\n' \
    | sed -n 's/^\([^ ]*\) .*Killed process \([0-9][0-9]*\) (\(.*\)) total-vm:[^,]*, anon-rss:\([0-9][0-9]*\)kB.*$/\1|\2|\4|\3/p'
  return 0
}

# boot_id al nucleului: un UUID (litere mici, 36 de caractere), nou la fiecare pornire. Orice
# altceva - fisier lipsa, gol, alt format - nu e un boot_id si NU se trateaza ca "aceeasi
# pornire". In fisierul de stare, `-` inseamna "pornirea nu se stia la scriere".
OOM_BOOT_RE='^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$'

check_oom(){
  local cur="$VM_OOM" last="" sboot="" extra="" boot="" had=0 rebooted=0 delta line ts pid rss name names="" nfound=0 msg tmp="$OOM_STATE.tmp"
  if ! [[ "$cur" =~ ^[0-9]{1,15}$ ]]; then unknown cap:oom "oom_kill din $PROC/vmstat"; return 0; fi
  cur=$((10#$cur))
  # Pornirea curenta. Se verifica FORMA citita, nu codul de iesire al `read`: un fisier fara
  # newline final face `read` sa intoarca 1 desi a citit, iar unul gol sau lipsa lasa variabila goala.
  { read -r boot < "$PROC/sys/kernel/random/boot_id"; } 2>/dev/null
  if ! [[ "$boot" =~ $OOM_BOOT_RE ]]; then
    boot="-"
    unknown cap:oom "boot_id din $PROC/sys/kernel/random/boot_id (compar doar contorul; un kill dupa o repornire poate trece nevazut)"
  fi
  if [ -e "$OOM_STATE" ] || [ -L "$OOM_STATE" ]; then
    # Ceva care nu e fisier obisnuit (director, legatura moarta) nu se poate inlocui cu `mv`
    # (ar muta temporarul IN director si rularea ar parea reusita): se spune si se renunta.
    [ -f "$OOM_STATE" ] || { unknown cap:oom "starea contorului oom_kill ($OOM_STATE nu e un fisier obisnuit)"; return 0; }
    # Format: `<boot_id|-> <contor>`, un singur rand. Un fisier care exista dar nu are exact
    # perechea asta (gol, un singur numar - formatul dinainte de boot_id - sau cu ceva in plus)
    # nu e "prima rulare": un kill dintre timp poate lipsi, si asta se spune. Baza se reface
    # oricum, ca sa nu ramana stricat.
    read -r sboot last extra < "$OOM_STATE"
    if [[ "$sboot" =~ $OOM_BOOT_RE || "$sboot" = "-" ]] && [[ "$last" =~ ^[0-9]{1,15}$ ]] && [ -z "$extra" ]; then
      had=1; last=$((10#$last))
    else unknown cap:oom "starea contorului oom_kill din $OOM_STATE (baza refacuta; un kill de dinainte poate lipsi)"; fi
  fi
  if [ "$had" = 1 ]; then
    if [ "$boot" != "-" ] && [ "$sboot" != "-" ] && [ "$boot" != "$sboot" ]; then
      # Alta pornire: contorul a repornit de la 0, deci valoarea veche nu mai e o baza. Tot ce
      # arata acum s-a intamplat de la pornire, iar o valoare > 0 se anunta - chiar daca e egala
      # cu sau mai mica decat cea retinuta (asta era fereastra oarba a minutelor de dupa pornire).
      rebooted=1; last=0
    elif [ "$boot" != "-" ] && [ "$sboot" = "$boot" ] && [ "$cur" -lt "$last" ]; then
      # Aceeasi pornire si contorul a scazut: nu e o repornire, iar un contor al nucleului nu
      # scade in cursul unei porniri. Nu stiu ce s-a intamplat cu el - se spune, nu se tace.
      unknown cap:oom "contorul oom_kill (a scazut de la $last la $cur fara repornire; baza refacuta, un kill dintre timp poate lipsi)"
    fi
    # Nimic de spus si nimic de retinut: aceeasi valoare, aceeasi pornire (sau pornire
    # necitibila acum - atunci ramane scrisa cea veche, nu se inlocuieste cu `-`). O pornire
    # schimbata nu intra aici niciodata, chiar daca valoarea (0) a ramas egala: starea trebuie
    # sa retina pornirea noua.
    if [ "$cur" -eq "$last" ] && { [ "$sboot" = "$boot" ] || [ "$boot" = "-" ]; }; then return 0; fi
  fi
  # Valoarea noua se scrie intr-un temporar INAINTE de orice mesaj: daca nu se poate scrie,
  # fiecare rulare ar vedea aceeasi crestere si ar anunta-o din nou, in fiecare minut.
  if ! printf '%s %s\n' "$boot" "$cur" > "$tmp"; then
    unknown cap:oom "contorul oom_kill (nu pot scrie $tmp; nu anunt ca sa nu repet in fiecare minut)"; return 0
  fi
  # Prima rulare (nu exista valoare anterioara), repornire fara kill-uri (contor 0), contor scazut,
  # sau doar pornirea de retinut: baza noua, fara mesaj. Istoria dinaintea instalarii nu e un
  # eveniment de acum.
  if [ "$had" = 0 ] || [ "$cur" -le "$last" ]; then
    mv -f "$tmp" "$OOM_STATE" || { rm -f "$tmp"; unknown cap:oom "contorul oom_kill (nu pot scrie $OOM_STATE)"; }
    return 0
  fi
  # Crestere: nucleul a omorat ceva intre doua rulari. Fara canal configurat nu am cum sa
  # spun nimic, deci baza ramane: mesajul vine cand canalul exista.
  if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT" ]; then rm -f "$tmp"; return 0; fi
  delta=$((cur - last))
  while IFS='|' read -r ts pid rss name; do
    [ -n "$pid" ] || continue
    nfound=$((nfound + 1))
    names+=$'\n'"  • ${name:0:40} (pid ${pid}, $((10#$rss / 1024)) MB RSS) la ${ts:11:8}"
  done < <(oom_victims "$(( delta < OOM_NAMES_MAX ? delta : OOM_NAMES_MAX ))")
  msg="💀 VPS ${HOST}: nucleul a omorat ${delta} proces(e) din lipsa de memorie (oom_kill ${last} -> ${cur})."
  [ "$rebooted" = 1 ] && msg+=$'\n'"Gazda s-a repornit de la ultima rulare: contorul numara de la pornire, nu de la rularea anterioara."
  if [ "$nfound" -gt 0 ]; then msg+=$'\n'"Din jurnalul nucleului (ultimele ${OOM_LOOKBACK_MIN} min):${names}"
  else msg+=$'\n'"Numele victimei nu l-am gasit in jurnalul nucleului (ultimele ${OOM_LOOKBACK_MIN} min); contorul e dovada."; fi
  if send_try "$msg"; then
    mv -f "$tmp" "$OOM_STATE" || { rm -f "$tmp"; unknown cap:oom "contorul oom_kill (nu pot scrie $OOM_STATE; mesajul s-ar repeta)"; }
  else
    rm -f "$tmp"   # nelivrat: baza veche ramane, urmatoarea rulare reincearca
  fi
  return 0
}

# --- capacitate -------------------------------------------------------------
disk=$(df --output=pcent / 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -z "$disk" ]; then unknown cap:disk "ocuparea discului /"
elif [ "$disk" -ge "$DISK_PCT_MAX" ]; then add "cap:disk|💽 Disk / la ${disk}% (prag ${DISK_PCT_MAX}%)"; fi

# Banda moarta: sub MEM_CLEAR_AT_MB o alerta DEJA data nu se poate rezolva. `10#`:
# o valoare din conf cu zero in fata (`0800`) ar fi octala in $(( )).
MEM_CLEAR_AT_MB=$(( 10#$MEM_AVAIL_MIN_MB * (100 + MEM_CLEAR_MARGIN_PCT) / 100 ))
MEM_DEEP_MB=$(( 10#$MEM_AVAIL_MIN_MB * MEM_DEEP_PCT / 100 ))
IMMEDIATE_KEYS=""   # chei care, in rularea asta, se anunta fara confirmare
mem=$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024; exit }' "$PROC/meminfo" 2>/dev/null)
if ! [[ "$mem" =~ ^[0-9]+$ ]]; then unknown cap:mem "MemAvailable din $PROC/meminfo"
elif [ "$mem" -lt "$MEM_AVAIL_MIN_MB" ]; then
  add "cap:mem|🧠 RAM disponibil ${mem}MB (prag ${MEM_AVAIL_MIN_MB}MB)"
  # Scapare de adancime (sectiunea 5): sub MEM_DEEP_MB nu se asteapta confirmarea.
  [ "$mem" -lt "$MEM_DEEP_MB" ] && IMMEDIATE_KEYS+=" cap:mem"
elif [ "$mem" -lt "$MEM_CLEAR_AT_MB" ]; then carry cap:mem   # fara alerta deschisa, carry nu adauga nimic
fi

read_vmstat
check_paging
check_oom

cores=$(nproc); load1=$(awk '{ print $1; exit }' "$PROC/loadavg" 2>/dev/null)
if ! [[ "$load1" =~ ^[0-9]+(\.[0-9]+)?$ && "$cores" =~ ^[0-9]+$ ]]; then unknown cap:load "load-ul din $PROC/loadavg"
elif awk -v l="$load1" -v c="$cores" -v m="$LOAD_PER_CORE_MAX" 'BEGIN{exit !(l > c*m)}'; then
  add "cap:load|📈 Load1 ${load1} (>${LOAD_PER_CORE_MAX}x${cores} core)"
fi

# `curl -w` scrie singur 000 cand conexiunea cade; un `|| echo 000` dupa el dubla
# valoarea in "000000" si verificarea nu mai putea suna niciodata.
for d in $HEALTH_DOMAINS; do
  code=$(curl -s -o /dev/null -m "$CURL_TIMEOUT" -w '%{http_code}' "https://$d/api/health" 2>/dev/null || true)
  [ -n "$code" ] || code=000
  [ "$code" = "000" ] && add "net:$d|🌐 $d nu raspunde"
done

# --- diferenta pe identitate, cu histerezis ---------------------------------
# Un singur rand per cheie (primul castiga), fara randuri goale.
dedupe(){ printf '%s' "$problems" | awk 'NF { i = index($0, "|"); k = (i ? substr($0, 1, i - 1) : $0); if (!(k in s)) { s[k] = 1; print } }'; }

# hyst_blind MOTIV - contoarele de confirmare nu se pot tine. Raspunsul NU e sa
# astepte (ar ramane la "prima proba" pentru totdeauna = alerta de RAM amutita), ci
# sa renunte la confirmare si sa spuna asta.
HYST_OK=1
hyst_blind(){
  HYST_OK=0
  add "unk:hysteresis|❔ Nu pot tine contoarele de confirmare (${1}) - alertele de RAM se trimit fara confirmare, nu sunt intarziate"
}
NOW=$(date +%s)
if ! [[ "$NOW" =~ ^[0-9]+$ ]]; then hyst_blind "ceasul: date +%s a dat '${NOW}'"
elif [ -e "$HYST" ] && [ ! -f "$HYST" ]; then hyst_blind "$HYST nu e un fisier obisnuit"
fi

# engine MOD - noua/rezolvata din chei, cu confirmare si rezolvare cu numaratoare.
# MOD=1: contoarele conteaza; MOD=0: fiecare cheie se anunta/rezolva la prima proba.
# Intrari: starea anuntata (cu cheile retrase scoase), randurile de acum, contoarele.
# Iese: S|stare noua  N|noua  R|rezolvata  K|contor nou  si END|ok la sfarsit - fara
# el motorul a esuat si NIMIC din ce a tiparit nu se foloseste.
engine(){
  awk -v now="$NOW" -v stale="$HYST_STALE_S" -v pol="$HYST_POLICY" -v mod="$1" \
      -v pf="$2" -v cf="$3" -v hf="$HYST" -v imm="$IMMEDIATE_KEYS" '
    function key(l,  i) { i = index(l, "|"); return i ? substr(l, 1, i - 1) : l }
    BEGIN {
      n = split(pol, pa, " ")
      for (i = 1; i <= n; i++) { split(pa[i], kv, "="); split(kv[2], nk, "/"); cn[kv[1]] = nk[1] + 0; kn[kv[1]] = nk[2] + 0 }
      n = split(imm, ia, " "); for (i = 1; i <= n; i++) now_k[ia[i]] = 1
      while ((getline l < cf) > 0) if (l != "") { k = key(l); if (!(k in C)) { C[k] = l; ord[++no] = k } }
      close(cf)
      while ((getline l < pf) > 0) if (l != "") { k = key(l); if (!(k in P)) { P[k] = l; if (!(k in C)) ord[++no] = k } }
      close(pf)
      # Contor valid: 4 campuri, numere, nu din viitor, nu mai vechi de `stale`. Un contor
      # pend pentru o cheie deja anuntata (sau clear pentru una neanuntata) nu se citeste
      # niciodata: pend se foloseste doar la chei neanuntate, clear doar la anuntate.
      if (mod) while ((getline l < hf) > 0) {
        if (split(l, f, "|") != 4 || f[3] !~ /^[0-9]+$/ || f[4] !~ /^[0-9]+$/) continue
        age = now - f[4]; if (age < 0 || age > stale) continue
        if (f[2] == "pend") PN[f[1]] = f[3] + 0
        else if (f[2] == "clear") CN[f[1]] = f[3] + 0
      }
      for (i = 1; i <= no; i++) {
        k = ord[i]
        nc = (mod && (k in cn) && !(k in now_k)) ? cn[k] : 1
        nr = (mod && (k in kn)) ? kn[k] : 1
        if (k in P) {
          if (k in C) print "S|" C[k]
          else {
            c = CN[k] + 1
            if (c >= nr) print "R|" P[k]
            else { print "S|" P[k]; print "K|" k "|clear|" c "|" now }
          }
        } else {
          p = PN[k] + 1
          if (p >= nc) { print "S|" C[k]; print "N|" C[k] }
          else print "K|" k "|pend|" p "|" now
        }
      }
      print "END|ok"
    }'
}

cur=$(dedupe)
if [ "$SEED" = 1 ]; then
  # Prima rulare: nu exista "anuntat" fata de care sa numaram; baza ESTE anuntul.
  state_new="$cur"; newp=""; resp=""
else
  tag(){ printf '%s\n' "$out" | sed -n "s/^$1|//p"; }
  # Fara `END|ok` motorul a esuat: starea si contoarele raman cum erau, nu se trimite
  # nimic, iar iesirea nenula apare in `systemctl --failed`. Un `out` gol NU se
  # citeste ca "nicio problema" - ar sterge starea si ar "rezolva" tot.
  run_engine(){
    out=$(engine "$1" <(printf '%s\n' "$prev") <(printf '%s\n' "$cur")) || out=""
    printf '%s\n' "$out" | grep -qx 'END|ok' \
      || { echo "watchdog: motorul de diferente a esuat - starea ramane neschimbata, nu trimit nimic" >&2; exit 1; }
  }
  run_engine "$HYST_OK"
  if [ "$HYST_OK" = 1 ]; then
    # Contoarele se scriu INAINTE sa se foloseasca decizia: daca nu se pot persista,
    # decizia "inca astept" s-ar repeta la nesfarsit. Atunci se refac deciziile fara ele.
    if ! { tag K | sed '/^$/d' > "$HYST.tmp" && mv -f "$HYST.tmp" "$HYST"; }; then
      hyst_blind "nu pot scrie $HYST"; cur=$(dedupe); run_engine 0
    fi
  fi
  state_new=$(tag S); newp=$(tag N); resp=$(tag R)
fi
printf '%s\n' "$state_new" | sed '/^$/d' > "$STATE.tmp" && mv -f "$STATE.tmp" "$STATE"
if [ "$SEED" = 1 ]; then
  touch "$SEEDED"; n=$(printf '%s\n' "$cur" | sed '/^$/d' | grep -c . || true)
  msg="🛡️ VPS watchdog pornit pe ${HOST} - verific o data pe minut. Probleme deschise acum: ${n}"
  [ "$n" -gt 0 ] && msg+=$'\n'"$(printf '%s\n' "$cur" | sed '/^$/d' | cut -d'|' -f2-)"
  [ -n "$baseline_extra" ] && msg+=$'\n'"Remediabile automat:"$'\n'"${baseline_extra}"
  send "$msg"; exit 0
fi
[ -n "$newp" ] && send "🚨 VPS ${HOST} - problema noua:"$'\n'"$(printf '%s\n' "$newp" | sed '/^$/d' | cut -d'|' -f2-)"
[ -n "$resp" ] && send "✅ VPS ${HOST} - rezolvat:"$'\n'"$(printf '%s\n' "$resp" | sed '/^$/d' | cut -d'|' -f2-)"
exit 0
