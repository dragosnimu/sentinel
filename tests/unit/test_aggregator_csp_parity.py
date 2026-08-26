"""Politica de conținut a panoului agregator trebuie să fie geamăna celei de pe server.

Ștacheta e `deploy/nginx/sentinel-security-headers.conf`, iar planul o cere pe
nume: „aceeași strictețe... fără `unsafe-inline`, fără origini externe".

## Ce se strică dacă cele două se despart, și de ce nu se vede

Un `unsafe-inline` adăugat pe agregator nu produce niciun simptom în ziua în care
apare: panoul merge exact la fel. Ce se schimbă e că un XSS din panou capătă
dintr-o dată un loc de unde să încarce și unul unde să trimită — iar panoul ăsta
poartă istoricul derivat a N servere, pe o găzduire care n-are niciuna dintre
apărările serverului monitorizat.

Drumul prin care ajunge acolo e cunoscut și e scris în plan: cineva servește o
pagină cu un nonce, o versiune din cache poartă un nonce expirat, pagina se
strică pentru toată lumea deodată, și reparația evidentă sub presiune e
slăbirea politicii. Testul ăsta face ca pasul acela să înroșească suita.

## De ce se compară TEXTUL livrat, la ambele capete

Nu o listă de directive scrisă aici — aia ar fi o a treia copie, care ar putea să
se despartă de amândouă fără ca nimic să pice. Se citesc fișierele care ajung pe
gazde: vhostul nginx al serverului și constanta din `lib/auth/http.ts` pe care o
pune pe fiecare răspuns `securityHeaders()`.

Că antetul chiar AJUNGE pe răspuns nu se probează aici, ci în suita agregatorului
(`tests/auth-routes.test.ts`), citit dintr-un răspuns real. Cele două jumătăți
sunt necesare amândouă: una spune „politica e cea corectă", cealaltă „politica e
chiar emisă".
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
NGINX_HEADERS = REPO / "deploy" / "nginx" / "sentinel-security-headers.conf"
AGGREGATOR_HTTP = REPO / "aggregator" / "lib" / "auth" / "http.ts"


def _nginx_csp() -> str:
    text = NGINX_HEADERS.read_text(encoding="utf-8")
    found = re.search(
        r'add_header\s+Content-Security-Policy\s+"([^"]*)"', text
    )
    assert found, (
        f"{NGINX_HEADERS} nu mai conține un add_header Content-Security-Policy. "
        "Testul nu poate compara ce nu găsește, iar o potrivire care nu se face "
        "niciodată e chiar tiparul „grep după un tipar inexistent”."
    )
    return found.group(1)


def _aggregator_csp() -> str:
    text = AGGREGATOR_HTTP.read_text(encoding="utf-8")
    found = re.search(
        r"export const CONTENT_SECURITY_POLICY\s*=(.*?);\n", text, re.DOTALL
    )
    assert found, (
        f"{AGGREGATOR_HTTP} nu mai exportă CONTENT_SECURITY_POLICY în forma pe "
        "care o citește testul ăsta."
    )
    parts = re.findall(r'"([^"]*)"', found.group(1))
    assert parts, "constanta CSP a agregatorului a ieșit goală din citire"
    return "".join(parts)


def _directives(csp: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for chunk in csp.split(";"):
        cleaned = " ".join(chunk.split())
        if not cleaned:
            continue
        name, _, value = cleaned.partition(" ")
        out[name] = value
    assert out, "politica citită nu conține nicio directivă"
    return out


def test_the_two_policies_are_the_same_policy() -> None:
    """Fără asta, panoul agregator poate slăbi tăcut apărarea împotriva XSS.

    Un `unsafe-inline` sau o origine externă adăugate acolo n-ar schimba nimic
    vizibil — doar ar da unui XSS de unde să încarce și unde să trimită, pe
    aplicația care ține istoricul derivat a N servere.
    """
    server = _directives(_nginx_csp())
    aggregator = _directives(_aggregator_csp())
    assert aggregator == server, (
        "politica de conținut a agregatorului nu mai e aceeași cu a serverului.\n"
        f"  doar pe server:    {sorted(set(server) - set(aggregator))}\n"
        f"  doar pe agregator: {sorted(set(aggregator) - set(server))}\n"
        f"  valori diferite:   "
        f"{sorted(k for k in set(server) & set(aggregator) if server[k] != aggregator[k])}"
    )


@pytest.mark.parametrize("where", ["server", "agregator"])
def test_neither_policy_allows_inline_or_an_external_origin(where: str) -> None:
    """Fără asta, un XSS în panou capătă un loc de unde să încarce un payload.

    Ambele capete se verifică, nu doar cel nou: dacă ștacheta ar fi coborâtă,
    testul de egalitate de mai sus ar rămâne verde în timp ce amândouă politicile
    devin permisive.
    """
    csp = _nginx_csp() if where == "server" else _aggregator_csp()
    assert "unsafe-inline" not in csp, f"politica de pe {where} permite unsafe-inline"
    assert "unsafe-eval" not in csp, f"politica de pe {where} permite unsafe-eval"
    assert not re.search(r"https?://", csp), (
        f"politica de pe {where} numește o origine externă"
    )
    directives = _directives(csp)
    for required, expected in (
        ("default-src", "'self'"),
        ("script-src", "'self'"),
        ("frame-ancestors", "'none'"),
        ("form-action", "'self'"),
        ("base-uri", "'none'"),
        ("object-src", "'none'"),
    ):
        assert directives.get(required) == expected, (
            f"politica de pe {where} are {required} = "
            f"{directives.get(required)!r}, nu {expected!r}"
        )
