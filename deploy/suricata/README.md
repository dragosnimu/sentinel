# Suricata (P6.3)

Sentinel folosește Suricata 7 ca NIDS în mod IDS (AF_PACKET), citind `eve.json`.
`step_suricata()` din `install.sh` face totul; nu înlocuiește `suricata.yaml` din
distribuție (e complet și trece `suricata -T`) — pune deasupra doar ce e specific
gazdei:

- **fișierul de OPTIONS al familiei** (`/etc/sysconfig/suricata` pe RHEL,
  `/etc/default/suricata` pe Debian) →
  `OPTIONS="--af-packet=<iface> -F <bpf> --set vars.address-groups.HOME_NET=[<ip-public>]"`.
  `HOME_NET` trebuie să conțină IP-ul public, altfel regulile `EXTERNAL_NET -> HOME_NET`
  nu se potrivesc niciodată (default-ul distribuției e doar RFC1918).
  **Un fișier scris nu înseamnă un fișier citit.** Pe RHEL unitatea împachetată are
  `EnvironmentFile=` și `ExecStart=… $OPTIONS`. Pe Debian nu are nici una, nici alta:
  măsurat pe Ubuntu 24.04.4, `systemctl show suricata -p EnvironmentFiles` nu tipărea
  nimic, iar demonul lua interfața din `suricata.yaml` — `eth0`, pe o gazdă cu
  `enp0s3`. Acolo drop-in-ul de mai jos adaugă `EnvironmentFile=` și rescrie
  `ExecStart`, ca setarea să ajungă în procesul care rulează.
- **`/etc/suricata/capture-filter.bpf`** → filtrul BPF care exclude fluxul dominant
  găsit de preflight (`not host <BPF_HINT>`). Pe această gazdă: fluxul UniFi udp/514.
  Se exclude în kernel, deci Suricata nici nu vede pachetele — protejează discul.
- **drop-in `suricata.service.d/sentinel.conf`** → `MemoryMax=1G` (VPS mic) pe ambele
  familii, plus `EnvironmentFile=` și `ExecStart=… $OPTIONS` doar pe Debian.
- **ACL** → `setfacl u:sentinel:rX` pe `/var/log/suricata`, ca `sentinel-ingest`
  (neprivilegiat) să citească `eve.json`.
- `suricata-update` aduce setul ET Open (~68k reguli).

## Cum se verifică că chiar capturează

Pasul 35 nu se mai bazează pe `systemctl is-active` — pe gazda de test unitatea era
`active` în timp ce demonul murea și renăștea la fiecare 2m20s. Se uită la:

- interfața din `cmdline`-ul procesului urmărit de systemd (`--af-packet=<dev>`;
  un `--af-packet` gol înseamnă „ia lista din yaml", adică nu se știe);
- `HOME_NET` din configurația efectivă (`suricata --dump-config` cu `--set`-urile din
  același cmdline), care trebuie să conțină IP-ul public;
- **creșterea lui `eve.json`** — trei fișiere de 0 octeți sunt exact dovada că nu se
  capturează nimic. Fereastra e `SURICATA_CAPTURE_WAIT_S`; pe gazda de test au trecut
  130 s de la repornire până la primii octeți, fiindcă încărcarea regulilor durează.

Dacă nu poate confirma captura, o spune — nu tipărește „IDS on <iface>".

## Fluxul de date

```
eth0 ─▶ suricata (AF_PACKET, BPF exclude udp/514) ─▶ /var/log/suricata/eve.json
       └▶ sentinel-ingest (collectors/suricata_eve.py, doar event_type=alert)
          └▶ raw_events (source='suricata') ─▶ detect (rules.suricata_alert)
             └▶ incidente IDS (severitate 1→high, 2→medium, 3=ignorat)
```

## Tuning

Suricata alertează și pe trafic legitim (ex. IP-ul de admin, propriile lookup-uri
DNS către api.telegram.org — clasificate sev 3 și deci neridicate ca incidente).
Fereastra de observare de 72h e exact pentru a găsi aceste fals-pozitive înainte
de a arma auto-block. Pentru a reduce zgomotul, adaugă surse de încredere în
`response.extra_allowlist` și, dacă e nevoie, dezactivează SID-uri zgomotoase prin
`/etc/suricata/disable.conf` + `suricata-update`.
