#!/usr/bin/env python3
"""Semnează aprobarea unui plan de patch — pe stația OPERATORULUI, nu pe gazdă.

De ce există. Aprobarea unui plan trebuie să ceară omul, nu gazda. Cheia cu care
executorul verifică o aprobare stă într-un fișier doar-root pe gazdă și, în
același timp, aici, la operator; nimic din ce rulează ca `sentinel` (botul de
Telegram, interfața web, conducta de detecție) n-o poate citi. Jetonul pe care îl
produce scriptul ăsta acoperă TREI lucruri deodată: hash-ul planului, rezumatul
(sha256) al comenzilor exacte și nonce-ul pe care executorul l-a emis pentru
această aprobare. De aici:

* un jeton nu se poate face fără cheie;
* e valabil pentru exact comenzile pentru care a fost calculat — un jeton pentru
  un plan nu înregistrează comenzile altui plan (asta e defectul vechi: jetonul
  acoperea doar hash-ul, iar `dnf -y remove openssh-server` a trecut sub hash-ul
  altui plan);
* e valabil O SINGURĂ DATĂ — executorul consumă nonce-ul la înregistrare, deci o
  copie a jetonului (istoricul unui chat, un jurnal, un rând din bază) nu mai
  autorizează nimic a doua oară.

Ce vezi înainte să semnezi. Scriptul NU are încredere în ce a scris botul în
mesajul lui: recalculează rezumatul din comenzile din cerere, îl compară cu cel
declarat, și TIPĂREȘTE fiecare comandă, în ordine. Un bot compromis poate minți în
Telegram despre ce face planul; nu poate pune în cerere altă comandă decât cea
pe care o citești AICI, fiindcă jetonul se leagă de ea. Confirmarea cere să
tastezi primele opt cifre ale rezumatului, nu un „da": un gest deliberat, nu unul
de reflex.

Folosire:

    python scripts/approve-plan.py init              # o singură dată: face cheia
    python scripts/approve-plan.py show-key          # o tipărește, ca s-o pui pe gazdă
    python scripts/approve-plan.py sign              # lipești cererea la prompt
    python scripts/approve-plan.py sign cerere.txt   # sau o dai ca fișier

`sign` scrie PE STDOUT doar jetonul (poate fi trimis la clipboard); tot ce e
pentru om — comenzile, întrebarea — merge pe stderr. Refuză să ruleze fără
terminal interactiv: o aprobare cere un om care citește ecranul.

Cheia: `~/.sentinel/approval.key` (sau `$SENTINEL_APPROVAL_KEY_FILE`), 64 de cifre
hex și un rând nou, exact formatul pe care îl așteaptă executorul. Pe Windows
`chmod 600` nu are efect: pune fișierul într-un profil care nu e partajat.

Stdlib, plus `executor/policy.py` din același depozit: rezumatul și jetonul se
calculează cu AȘA CEVA, nu cu o copie, ca semnatarul și verificatorul să nu poată
ajunge la două definiții ale „acestor comenzi".
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import sys
from pathlib import Path

REQUEST_PREFIX = "SENTINEL-APPROVAL-V1:"
KEY_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_policy():
    """`executor/policy.py` din depozitul în care stă scriptul. Fără el nu se
    semnează nimic: o definiție proprie a rezumatului ar putea să nu mai coincidă
    cu a executorului, iar jetonul ar fi respins fără ca omul să știe de ce."""
    executor_dir = Path(__file__).resolve().parent.parent / "executor"
    if not (executor_dir / "policy.py").is_file():
        sys.exit(f"nu găsesc {executor_dir / 'policy.py'}: rulează scriptul din depozitul Sentinel")
    sys.path.insert(0, str(executor_dir))
    import policy  # noqa: PLC0415 - după ce calea e pusă

    return policy


def key_file() -> Path:
    return Path(os.environ.get("SENTINEL_APPROVAL_KEY_FILE") or Path.home() / ".sentinel" / "approval.key")


def read_key(path: Path | None = None) -> bytes:
    path = path or key_file()
    try:
        text = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        sys.exit(f"nu există cheia {path}. Prima dată: python scripts/approve-plan.py init")
    except (OSError, UnicodeDecodeError) as exc:
        sys.exit(f"cheia {path} nu se poate citi: {exc}")
    if not KEY_RE.match(text):
        sys.exit(f"{path} nu conține 64 de cifre hex mici; nu e o cheie de aprobare")
    return bytes.fromhex(text)


def parse_request(text: str) -> dict:
    """Cererea de aprobare, așa cum o scrie botul: prefixul și JSON-ul compact în
    base64 url-safe, pe un singur rând. Refuză orice altceva, cu motivul."""
    line = "".join(text.split())
    if not line.startswith(REQUEST_PREFIX):
        raise ValueError(f"cererea trebuie să înceapă cu {REQUEST_PREFIX}")
    body = line[len(REQUEST_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"cererea nu se poate decoda: {exc}") from None
    if not isinstance(data, dict):
        raise ValueError("cererea nu e un obiect")
    for field in ("plan_hash", "nonce", "digest", "steps"):
        if field not in data:
            raise ValueError(f"cererea nu are câmpul {field!r}")
    return data


def make_token(policy, key: bytes, request: dict) -> tuple[str, str]:
    """(token, digest). Digest-ul se RECALCULEAZĂ din comenzi și trebuie să
    coincidă cu cel declarat în cerere; jetonul se leagă de cel recalculat."""
    steps = request["steps"]
    if not (isinstance(steps, list) and steps and all(
            isinstance(s, list) and s and all(isinstance(a, str) for a in s) for s in steps)):
        raise ValueError("`steps` trebuie să fie o listă nevidă de liste de șiruri")
    plan_hash, nonce = request["plan_hash"], request["nonce"]
    if not (isinstance(plan_hash, str) and re.fullmatch(r"[0-9a-f]{64}", plan_hash)):
        raise ValueError("plan_hash nu e un sha256 hex")
    if not (isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce)):
        raise ValueError("nonce nu e 32 de cifre hex")
    digest = policy.steps_digest(steps)
    if request["digest"] != digest:
        raise ValueError(
            "rezumatul din cerere NU corespunde comenzilor din cerere "
            f"(declarat {request['digest']!r}, recalculat {digest!r}); nu semnez")
    return policy.approval_token(key, plan_hash, digest, nonce), digest


def show_steps(policy, request: dict, digest: str, out) -> list[str]:
    """Tipărește comenzile, în ordine, și întoarce avertismentele (comenzi pe care
    executorul le-ar refuza oricum). Avertismentele nu opresc semnarea: omul
    decide, dar trebuie să știe că planul nu va merge."""
    warnings: list[str] = []
    print(f"\nPlan      {request['plan_hash']}", file=out)
    print(f"Rezumat   {digest}", file=out)
    print(f"Comenzi   {len(request['steps'])}, în ordinea în care vor putea rula:\n", file=out)
    for index, argv in enumerate(request["steps"]):
        print(f"  {index:>3}  {' '.join(argv)}", file=out)
        try:
            policy.check_argv(list(argv))
        except policy.PolicyRefusal as refusal:
            warnings.append(f"pasul {index}: executorul îl refuză ({refusal})")
    for warning in warnings:
        print(f"\n  ATENȚIE {warning}", file=out)
    print(file=out)
    return warnings


def cmd_init(_args) -> int:
    path = key_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"{path} există deja; nu o suprascriu (o cheie nouă ar invalida pe cea de pe gazdă).",
              file=sys.stderr)
        return 1
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(secrets.token_bytes(32).hex() + "\n")
    print(f"Cheia a fost creată în {path}.", file=sys.stderr)
    print("Pune-o pe gazdă, o singură dată (vezi docs/PATCHING.md, „Aprobarea unui plan”):\n"
          "  python scripts/approve-plan.py show-key        # tipărește cheia\n"
          "  apoi, pe gazdă:  sudo sh -c 'umask 077; read -r K && printf \"%s\\n\" \"$K\" > "
          "/var/lib/sentinel-executor/approval.key'", file=sys.stderr)
    return 0


def cmd_show_key(_args) -> int:
    print(read_key().hex())
    return 0


def _ask(prompt: str) -> str:
    """O întrebare către om, pe STDERR. `input(prompt)` scrie promptul pe stdout, iar
    stdout e rezervat jetonului: `sign | clip` ar fi pus întrebarea în clipboard."""
    print(prompt, end="", file=sys.stderr, flush=True)
    return input()


def cmd_sign(args) -> int:
    """Citește cererea (dintr-un fișier, sau lipită la prompt), arată comenzile,
    cere confirmarea de la tastatură și tipărește jetonul.

    Refuză să ruleze fără un terminal interactiv. Asta nu e comoditate: o
    semnătură care poate fi cerută dintr-un script, dintr-un pipe sau dintr-un
    proces pornit de altcineva ar fi aceeași gaură mutată pe stația operatorului —
    aprobarea trebuie să treacă prin cineva care citește ecranul.
    """
    if not sys.stdin.isatty():
        print("Refuz: aprobarea cere un om la tastatură (stdin nu e un terminal). "
              "Dă cererea ca fișier sau lipește-o la prompt.", file=sys.stderr)
        return 3
    policy = _load_policy()
    key = read_key()
    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    else:
        text = _ask("Lipește cererea de aprobare (un singur rând): ")
    try:
        request = parse_request(text)
        token, digest = make_token(policy, key, request)
    except ValueError as exc:
        print(f"Refuz: {exc}", file=sys.stderr)
        return 2
    show_steps(policy, request, digest, sys.stderr)
    want = digest[:8]
    answer = _ask(f"Ca să semnezi, tastează primele opt cifre ale rezumatului ({want}); "
                  "orice altceva anulează: ").strip()
    if answer != want:
        print("Anulat: nu s-a semnat nimic.", file=sys.stderr)
        return 1
    print(token)
    print("\nTrimite jetonul de mai sus botului, ca răspuns la cerere. Valabil o singură dată.",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    # O consolă Windows în cp1252/cp852 nu poate scrie „ă” și „ț”: fără asta
    # scriptul cade cu UnicodeEncodeError exact când omul are nevoie de el. Un
    # caracter înlocuit cu `?` e urât; un jeton care nu se tipărește e o pană.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="Semnează aprobarea unui plan de patch.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="creează cheia de aprobare (o singură dată)").set_defaults(func=cmd_init)
    sub.add_parser("show-key", help="tipărește cheia, ca să fie pusă pe gazdă").set_defaults(func=cmd_show_key)
    sign = sub.add_parser("sign", help="citește o cerere de aprobare și tipărește jetonul")
    sign.add_argument("file", nargs="?", help="fișierul cu cererea (implicit: o lipești la prompt)")
    sign.set_defaults(func=cmd_sign)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
