# Cum se lucrează în acest repository

## Regula de proces: două treceri, obligatoriu

**Orice schimbare care modifică comportamentul trece prin doi agenți**, în
ordinea asta, înainte de commit:

1. **`code-writer`** scrie sau repară, și produce dovezile.
2. **`code-verifier`** încearcă să demonstreze că e greșit — rulează testele,
   le falsifică, și citește gazda de producție prin ssh (doar citire).

Se repară și se reia până trece. Dacă aceeași cauză e respinsă de două ori,
asta se spune operatorului — nu ca oprire, ca informare că abordarea se
învârte.

**Ce trece:** cod, configurații, scripturi de deploy, reguli auditd, SQL,
unități systemd, vhosturi nginx, TypeScript.
**Ce nu trece:** comentarii, documentație, mesaje de commit, texte în română.

Regula a fost cerută de operator pe 8 august 2026, după o zi în care un
diacritic într-un alias de comandă a oprit canalul de alertare timp de 24 de
ore, iar trei mecanisme separate au raportat succes fără să verifice efectul.

## De ce: tiparul care produce bug-urile de aici

Aproape fiecare defect livrat din acest repository are aceeași formă —
**confirmarea intenției în locul efectului**:

| Ce s-a scris | Ce se credea | Ce era |
|---|---|---|
| `augenrules --load 2>/dev/null` | reguli încărcate | nucleul le respinsese, eroarea la /dev/null |
| `systemctl enable --now` | serviciu actualizat | operație nulă; procesul rula codul vechi |
| `systemctl reload nginx` → 0 | configurație aplicată | semnalul trimis, configurația respinsă, trei zile |
| `is-active` verificat o dată | serviciu pornit | serviciu în buclă, prins în faza `active` |
| grep după un tipar în jurnal | „nimic în neregulă" | tiparul nu exista, deci n-a potrivit niciodată |

Înainte de orice linie care raportează succes: **ce fapt observabil dovedește
asta, și verific faptul sau propria mea intenție?**

Un cod de ieșire nu e dovadă de efect. Un fișier pe disc nu e dovadă că a fost
încărcat. Un serviciu activ o dată nu e dovadă că rămâne pornit.

## Testele

Fiecare test își numește în docstring eșecul pe care îl previne, în termeni de
ce se strică pentru operator.

**Apoi se falsifică:** reintroduci bug-ul, confirmi că testul pică, restaurezi.
Un test pe care nu l-ai văzut picând nu e scris. În repository-ul ăsta au trecut
teste care nu verificau nimic — un grep după un tipar inexistent, o aserțiune pe
prezența unui nume de variabilă în loc de pe decizia luată din el, o listă
parametrizată ieșită goală și sărită tăcut. Fiecare a costat o pană ca să fie
descoperit.

## Limba

Română pentru documentație, interfață, mesaje către operator și comentarii în
fișierele deja în română. Engleză pentru cod, identificatori, `SKILL.md` și
definițiile de agenți. Urmează fișierul în care ești.

## Serverul

Se atinge prin `deploy/` și `scripts/` — cod citit, testat și versionat. `ssh`
direct e permis pentru **diagnostic**, nu pentru schimbări: orice modifică gazda
trece prin scripturile revizuite, ca să poată fi repetată și revăzută.
