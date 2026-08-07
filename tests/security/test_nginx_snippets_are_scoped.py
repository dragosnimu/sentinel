"""Sentinel nu are voie să schimbe comportamentul site-urilor pe care le monitorizează.

`/etc/nginx/conf.d/*.conf` e inclus de nginx.conf în contextul `http`. Un fișier
de `add_header` pus acolo nu configurează un vhost — configurează TOATE
vhosturile de pe gazdă care nu-și definesc propriile antete, prin moștenire.

Sentinel își instala fragmentul de antete exact acolo. Efectul, măsurat pe
producție: fiecare site al operatorului a primit
`Content-Security-Policy: default-src 'self'` — deci orice script de CDN, font
extern sau pixel de analytics blocat — plus `Strict-Transport-Security` cu
`includeSubDomains` pe un an, memorat în browserele vizitatorilor.

S-a văzut fiindcă un răspuns 404 care NU venea din vhostul Sentinel purta totuși
antetele Sentinel.

Un agent de monitorizare care strică ce monitorizează e mai rău decât absent:
absența nu produce un raport de bug care duce în altă parte.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NGINX_DIR = REPO / "deploy" / "nginx"
INSTALL_SH = (REPO / "deploy" / "install.sh").read_text(encoding="utf-8")

# Directive care, la nivel `http`, se scurg în fiecare bloc `server`.
LEAKY = ("add_header", "proxy_set_header", "limit_req_zone", "map ", "server_tokens")


def _snippets() -> list[Path]:
    """Fișierele care nu sunt vhosturi întregi — fragmentele incluse.

    Căutat `server {`, nu cuvântul „server": prima variantă a acestui test
    filtra după cuvânt și a exclus tocmai fișierul de antete, fiindcă un
    comentariu din el spune „server-rendered". Rezultatul era o listă goală,
    un test sărit și o bifă verde care nu se uitase la nimic.
    """
    return [p for p in NGINX_DIR.glob("*.conf")
            if not re.search(r"^\s*server\s*\{", p.read_text(encoding="utf-8"), re.M)]


def test_snippets_are_not_installed_into_conf_d() -> None:
    """conf.d e spațiul comun al gazdei, nu al nostru."""
    bad = re.findall(r"/etc/nginx/conf\.d/sentinel-(?:security-headers|proxy-params)\.conf",
                     INSTALL_SH)
    # Apar doar în lista de curățare, ca un upgrade să șteargă locul vechi.
    installs = [ln for ln in INSTALL_SH.splitlines()
                if "conf.d/sentinel-security-headers" in ln or "conf.d/sentinel-proxy-params" in ln
                if re.search(r"\binstall\b|\bcp\b|\btee\b", ln)]
    assert not installs, f"fragment instalat în conf.d: {installs}"
    assert bad, "referințele vechi au dispărut cu totul — upgrade-ul nu mai curăță locul vechi"


def test_the_upgrade_removes_the_old_global_copy() -> None:
    """Repararea trebuie să atingă exact gazdele care au nevoie de ea.

    Un fișier lăsat în conf.d continuă să se aplice global oricât de corect ar
    fi locul nou.
    """
    assert "rm -f \"$stale\"" in INSTALL_SH
    assert "it applied to every site on this host" in INSTALL_SH


@pytest.mark.parametrize("tmpl", sorted(NGINX_DIR.glob("*.tmpl")), ids=lambda p: p.name)
def test_vhosts_include_snippets_from_the_private_directory(tmpl: Path) -> None:
    text = tmpl.read_text(encoding="utf-8")
    for inc in re.findall(r"include\s+(\S+);", text):
        if "sentinel" not in inc:
            continue
        assert not inc.startswith("/etc/nginx/conf.d/"), (
            f"{tmpl.name} include din conf.d: {inc} — pune-l în /etc/nginx/sentinel/")


@pytest.mark.parametrize("snippet", sorted(_snippets()), ids=lambda p: p.name)
def test_snippets_contain_only_directives_meant_to_be_scoped(snippet: Path) -> None:
    """Dacă un fragment conține directive care se moștenesc, el TREBUIE inclus
    dintr-un bloc `server` — niciodată lăsat la nivel http.

    Testul nu interzice directivele; interzice ca ele să ajungă globale. Cele
    două de mai sus verifică locul; asta verifică faptul că miza e reală, ca
    nimeni să nu mute fișierul înapoi crezând că e inofensiv.
    """
    text = snippet.read_text(encoding="utf-8")
    found = [d for d in LEAKY if re.search(rf"^\s*{re.escape(d.strip())}\b", text, re.M)]
    if not found:
        pytest.skip(f"{snippet.name} nu conține directive care se moștenesc")
    # Există miză: fișierul chiar are directive care s-ar scurge.
    assert f"/etc/nginx/sentinel/{snippet.stem.replace('sentinel-', '')}.conf" in \
           "\n".join(t.read_text(encoding="utf-8") for t in NGINX_DIR.glob("*.tmpl")), \
        f"{snippet.name} conține {found} dar niciun vhost nu îl include din directorul privat"


# --- reincarcarea trebuie dovedita, nu presupusa ---------------------------
#
# `systemctl reload nginx` intoarce 0 daca a reusit sa TRIMITA semnalul. Cand
# masterul respinge configuratia, isi pastreaza procesele vechi si continua sa
# serveasca versiunea precedenta, cu un [emerg] pe care nu-l citeste nimeni.
#
# Pe productie: o zona `limit_req` isi schimbase cheia, iar cheia unei zone de
# memorie partajata nu se poate schimba la reload. Patru reincarcari consecutive
# au raportat succes; procesele nginx erau de trei zile vechi. Doua reparatii
# livrate in ziua aceea pareau sa nu functioneze, si erau amandoua corecte.

def test_every_reload_goes_through_the_verified_helper() -> None:
    """Un `systemctl reload nginx` gol, oriunde in instalator, reintroduce bug-ul."""
    body = [ln for ln in INSTALL_SH.splitlines()
            if "systemctl reload nginx" in ln
            and not ln.strip().startswith("#")]
    # Unul singur, in interiorul helperului. Restul apeleaza helperul.
    assert len(body) <= 2, f"reload nginx neverificat: {body}"


def test_the_helper_proves_the_reload_by_new_processes() -> None:
    """Singura dovada e aparitia unor procese noi.

    Nu codul de iesire, nu absenta unei erori, nu `nginx -t` — acela trece
    tocmai in cazul care ne-a pacalit, fiindca verifica sintaxa unei analize
    noi, nu compatibilitatea cu zonele de memorie deja alocate.
    """
    assert "nginx_workers()" in INSTALL_SH
    assert "pgrep -f 'nginx: worker process'" in INSTALL_SH
    assert 'before="$(nginx_workers)"' in INSTALL_SH
    assert 'after="$(nginx_workers)"' in INSTALL_SH

    # Prezenta variabilelor nu e dovada ca din ele iese decizia. O prima
    # versiune a testului verifica doar numele, si a trecut cand am inlocuit
    # toata comparatia cu `new="da"` — adica exact presupunerea pe care regula
    # o interzice, imbracata in variabilele corecte.
    assert "for pid in $after" in INSTALL_SH
    assert '[[ " $before " == *" $pid "* ]]' in INSTALL_SH


def test_a_failed_reload_is_escalated_not_ignored() -> None:
    """Si nu se repornește orbeste: daca `nginx -t` nu trece, un restart ar lasa
    nginx OPRIT, iar acum inca serveste."""
    assert "a pastrat procesele vechi" in INSTALL_SH
    assert "systemctl restart nginx" in INSTALL_SH
    assert "Nu repornesc: ar lasa" in INSTALL_SH


def test_the_helper_is_not_recursive() -> None:
    """Prima varianta se apela pe sine in loc sa cheme systemctl.

    Ar fi trecut orice test care verifica doar prezenta numelui.
    """
    body = INSTALL_SH.split("reload_nginx() {", 1)[1].split("\n}", 1)[0]
    assert "systemctl reload nginx" in body
    assert "\n    reload_nginx\n" not in body
