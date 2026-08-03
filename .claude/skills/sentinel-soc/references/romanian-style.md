# Romanian style guide

Every operator-facing string — Telegram messages, dashboard text, reports,
`*_ro` JSON fields — is Romanian. Code, identifiers, log messages, commit
messages, schema field names and this documentation stay English.

---

## Tone

Direct and factual. The reader is a technical operator who may be looking at
their phone at 3 a.m. during an actual incident.

- No filler: not *„Vă informăm că"*, *„Este important de menționat că"*,
  *„În urma analizei efectuate"*. Say the thing.
- No hedging adverbs where a number belongs. Not *„posibil un atac"* but
  *„atac confirmat"* or *„72% probabil atac, restul scanare automată"*.
- No apologies, no reassurance. Not *„Nu vă faceți griji"*.
- Second person singular (*„Poți debloca IP-ul cu butonul de mai jos"*), not
  formal plural. This is one operator's own tool.

## Diacritics

Always use them: ă â î ș ț. Use the correct comma-below characters (U+0219
`ș`, U+021B `ț`), not the cedilla forms. Telegram and the dashboard both render
them correctly.

## What stays in English

Never translate:

- CVE identifiers, rule ids (`auth.ssh_bruteforce`), MITRE technique ids
- Package, service, container and file names; all paths
- Command names and their arguments
- Protocol and header names: `TLS`, `HTTP`, `User-Agent`, `SYN`
- Status values that also exist in the database: `open`, `resolved`, `KEV`
- Technical nouns with no good Romanian equivalent in operational use:
  *backup*, *rollback*, *patch*, *firewall*, *log*, *timeout*, *hash*

Inflect borrowed nouns naturally: *patch-ul*, *backup-uri*, *log-urile*,
*blocklist-ul*, *rollback-ul*.

## Preferred terms

| English | Romanian |
|---|---|
| incident | incident |
| attack / attempt | atac / tentativă |
| threat | amenințare |
| attacker, actor | atacator, actor |
| vulnerability, finding | vulnerabilitate, finding |
| to block / unblock | a bloca / a debloca |
| blocklist / allowlist | blocklist / allowlist (as such) |
| scan | scanare |
| breach, compromise | breșă, compromitere |
| severity | severitate |
| false positive | fals pozitiv |
| baseline | referință (or *baseline*, consistently within a document) |
| availability, uptime | disponibilitate, uptime |
| downtime | downtime |
| maintenance window | fereastră de mentenanță |
| restore point | punct de restaurare |
| health check | verificare de sănătate |
| kill chain | lanț de atac |
| brute force | atac prin forță brută |
| port scan | scanare de porturi |
| payload | payload |

Severity labels, fixed: `CRITIC` · `RIDICAT` · `MEDIU` · `SCĂZUT` · `INFO`.

## Numbers, dates, units

- Decimal comma: `3,5 GB`. Thousands separator: a period or a space — `1.240` or
  `1 240`. Be consistent within a message.
- Timestamps in `Europe/Bucharest`, format `2026-07-29 14:32`. Include the zone
  only when it could be ambiguous.
- Durations in words: *„acum 14 minute"*, *„de 3 ore"*, *„în ultimele 24h"*.
- Percentages with a space: `36 %` — or without, but consistently. Prefer `36%`.
- Bytes with binary prefixes as the tools report them: `MB`, `GB`.

## Sentence patterns that work

Incident opening:
> „Atac prin forță brută SSH dinspre 203.0.113.44 (AS12345, România). 47 de
> tentative în 3 minute, toate eșuate. Blocat automat 24h."

Prediction:
> „Actorul este în stadiul 2/6 (enumerare) de 14 minute. 36% șanse de avansare
> la atac pe credențiale în ≤30 min (31 din 87 de actori similari, ultimele 60
> de zile)."

Vulnerability:
> „CVE-2026-1234 în wp-plugin-foo 1.2.3 pe blog.example.com. CVSS 9.8, EPSS
> 0,72, listat în CISA KEV. Asset expus la internet. Fix disponibil: 1.2.7."

Patch approval:
> „Plan de patch pentru blog.example.com. Downtime estimat: 25s. Backup: 340 MB
> (fișiere + baza de date). Rollback automat: DA. 3 pași de aplicare."

Insufficient data — a good answer, phrased well:
> „Date insuficiente pentru clasificare. Am 4 evenimente de la această sursă și
> niciun tipar comparabil în istoric. Recomand monitorizare, fără blocare."

Bad news, stated plainly:
> „Patch-ul a eșuat la pasul 3 (health check). Rollback automat executat cu
> succes. Serviciul funcționează pe versiunea anterioară. Cauza: portul 8080
> era deja ocupat."

## Common mistakes

| Wrong | Right |
|---|---|
| *„se pare că ar putea fi un atac"* | *„atac confirmat"* / *„probabil scanare automată (78%)"* |
| *„trafic anormal detectat"* | *„412 cereri/min față de o mediană de 38 pentru această oră (z=11,4)"* |
| *„vă recomandăm să monitorizați"* | *„blochează 203.0.113.44 pentru 24h"* — or say no action is needed |
| *„a fost efectuată o analiză"* | Say what the analysis found |
| *„securitatea sistemului dumneavoastră"* | *„serverul"* |
| *„eroare la procesare"* | *„psql a returnat exit 2: relation \"findings\" does not exist"* |
