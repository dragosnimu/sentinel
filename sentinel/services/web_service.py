"""systemd entrypoint for the dashboard, plus the account-management CLI.

Account operations live here rather than in the web interface on purpose. A
dashboard that can create accounts, change roles or reset passwords turns an
interface compromise into a takeover: an attacker with a session could promote
themselves to `owner`. Doing it on the server means it requires shell access,
which is a much higher bar than a stolen cookie.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from collections.abc import Sequence

from sentinel import __version__
from sentinel.config import Config, Secrets, get_config, get_secrets
from sentinel.db.engine import Database
from sentinel.db.repo import audit, sessions, users
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.services import parse_service_args
from sentinel.web.security import (
    Authenticator,
    generate_totp_secret,
    hash_password,
    totp_provisioning_uri,
    verify_totp_code,
)

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------
def serve(cfg: Config) -> int:
    import uvicorn

    from sentinel.web.app import create_app

    if cfg.web.bind not in ("127.0.0.1", "::1", "localhost"):
        # Refused rather than warned about. nginx terminates TLS and applies the
        # rate limits and security headers; binding publicly would bypass all
        # three and there is no configuration in which that is what someone
        # actually wanted.
        log.error(
            "web.bind must stay on loopback; nginx proxies to it",
            extra={"bind": cfg.web.bind},
        )
        return 78

    uvicorn.run(
        create_app(cfg),
        host=cfg.web.bind,
        port=cfg.web.port,
        log_config=None,        # our own structured logging, not uvicorn's
        access_log=False,       # nginx already logs; two copies is noise
        server_header=False,    # do not advertise the server or its version
        date_header=True,
        proxy_headers=False,    # deps.client_ip reads X-Real-IP, which nginx pins
        forwarded_allow_ips=None,
        timeout_keep_alive=15,
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Called by `sentinel web [flags]`, with the flags the dispatcher did not use."""
    parser = argparse.ArgumentParser(prog="sentinel web", add_help=True)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--create-admin", action="store_true",
                       help="create the first owner account and enrol TOTP")
    group.add_argument("--enroll-totp", action="store_true",
                       help="re-enrol TOTP for an existing user (lost device)")
    group.add_argument("--set-password", action="store_true",
                       help="set a user's password and revoke their sessions")
    group.add_argument("--revoke-sessions", action="store_true",
                       help="revoke every session for a user")
    group.add_argument("--unlock", action="store_true",
                       help="clear a lockout")
    group.add_argument("--list-users", action="store_true")
    parser.add_argument("--username")
    parser.add_argument("--role", choices=users.ROLES, default="owner")
    # The dispatcher hands over what it did not consume. Slicing sys.argv[2:]
    # here was a guess at where this command's own flags began, and it was wrong
    # for `sentinel --log-level DEBUG web --list-users`: the slice started at
    # "DEBUG" and argparse rejected the subcommand name as an argument.
    args = parse_service_args(parser, argv)

    cfg = get_config()
    sec = get_secrets()

    if args.create_admin:
        return asyncio.run(_create_admin(cfg, sec, args.username, args.role))
    if args.enroll_totp:
        return asyncio.run(_enroll_totp(cfg, sec, args.username))
    if args.set_password:
        return asyncio.run(_set_password(cfg, args.username))
    if args.revoke_sessions:
        return asyncio.run(_revoke_sessions(cfg, args.username))
    if args.unlock:
        return asyncio.run(_unlock(cfg, args.username))
    if args.list_users:
        return asyncio.run(_list_users(cfg))

    setup_logging("sentinel-web", cfg.log_level)
    return serve(cfg)


# ---------------------------------------------------------------------------
# Account management
# ---------------------------------------------------------------------------
def _prompt_password(confirm: bool = True) -> str:
    while True:
        pw = getpass.getpass("Parolă (minim 12 caractere): ")
        if confirm:
            again = getpass.getpass("Repetă parola: ")
            if pw != again:
                print("Parolele nu corespund. Încearcă din nou.\n", file=sys.stderr)
                continue
        try:
            from sentinel.web.security import validate_password_strength

            validate_password_strength(pw)
        except ValueError as exc:
            print(f"{exc}\n", file=sys.stderr)
            continue
        return pw


def _print_totp_enrolment(uri: str, secret: str, username: str) -> None:
    """Print the QR once, in the terminal.

    Shown exactly once and never stored anywhere retrievable. The secret is
    encrypted at rest in the database, so there is no "show me the QR again" —
    losing it means re-enrolling, which is the correct trade for a second factor.
    """
    print()
    print("=" * 64)
    print(f"  ÎNROLARE AL DOILEA FACTOR — {username}")
    print("=" * 64)
    print()

    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)
    except Exception:  # noqa: BLE001 - the secret below is the real payload
        print("  (nu am putut desena codul QR — folosește secretul de mai jos)")

    print()
    print("  Scanează codul cu Google Authenticator, Aegis, 1Password sau")
    print("  echivalent. Dacă scanarea nu funcționează, introdu manual:")
    print()
    print(f"      {secret}")
    print()
    print("  ATENȚIE: acesta este afișat O SINGURĂ DATĂ. Secretul este stocat")
    print("  criptat în baza de date, deci nu poate fi reafișat. Dacă îl pierzi,")
    print("  rulează din nou --enroll-totp.")
    print()
    print("=" * 64)
    print()


async def _with_db(cfg: Config):
    db = Database(cfg)
    await db.connect()
    return db


async def _create_admin(
    cfg: Config, sec: Secrets, username: str | None, role: str
) -> int:
    db = await _with_db(cfg)
    try:
        existing = await users.count(db)
        if existing > 0 and not username:
            print(
                f"Există deja {existing} cont(uri). Pentru a adăuga altul, dă "
                "--username explicit.",
                file=sys.stderr,
            )
            return 1

        name = username or input("Utilizator: ").strip()
        if not name:
            print("Numele de utilizator este obligatoriu.", file=sys.stderr)
            return 1
        if await users.get_by_username(db, name):
            print(f"Utilizatorul {name!r} există deja.", file=sys.stderr)
            return 1

        password = _prompt_password()
        auth = Authenticator(db, cfg, sec)

        secret = generate_totp_secret()
        user_id = await users.create(
            db,
            username=name,
            password_hash=hash_password(password),
            role=role,
            totp_secret=auth.cipher.encrypt(secret),
        )

        issuer = cfg.web.domain or cfg.hostname or "Sentinel"
        _print_totp_enrolment(totp_provisioning_uri(secret, name, issuer), secret, name)

        # Enrolment is confirmed by proving a code can be produced from the
        # secret. Without this, an interrupted scan leaves an account that
        # requires a factor nobody has — locked out with no way in.
        if not await _confirm_enrolment(db, user_id, secret):
            print(
                "Înrolare neconfirmată. Contul a fost creat, dar al doilea factor "
                f"nu este activ. Rulează: sentinel web --enroll-totp --username {name}",
                file=sys.stderr,
            )
            return 1

        await audit.record(
            db, actor="cli", source="web", operation="create_user",
            target=name, params={"role": role}, result="ok",
        )
        print(f"Cont {name!r} creat cu rol {role}, al doilea factor activ.")
        print(f"Dashboard: https://{cfg.web.domain or '<host>'}")
        return 0
    finally:
        await db.close()


async def _confirm_enrolment(db: Database, user_id: int, secret: str) -> bool:
    for attempt in range(3):
        code = input("Introdu codul afișat de aplicație pentru confirmare: ").strip()
        counter = verify_totp_code(secret, code)
        if counter is not None:
            await users.confirm_totp(db, user_id)
            await users.record_totp_counter(db, user_id, counter)
            return True
        remaining = 2 - attempt
        if remaining:
            print(f"Cod incorect. Încercări rămase: {remaining}", file=sys.stderr)
    return False


async def _enroll_totp(cfg: Config, sec: Secrets, username: str | None) -> int:
    if not username:
        print("--username este obligatoriu.", file=sys.stderr)
        return 1

    db = await _with_db(cfg)
    try:
        user = await users.get_by_username(db, username)
        if user is None:
            print(f"Utilizatorul {username!r} nu există.", file=sys.stderr)
            return 1

        auth = Authenticator(db, cfg, sec)
        secret = generate_totp_secret()
        await users.set_totp_secret(db, user.id, auth.cipher.encrypt(secret))

        issuer = cfg.web.domain or cfg.hostname or "Sentinel"
        _print_totp_enrolment(totp_provisioning_uri(secret, username, issuer), secret, username)

        if not await _confirm_enrolment(db, user.id, secret):
            print("Înrolare neconfirmată. Al doilea factor rămâne inactiv.", file=sys.stderr)
            return 1

        # Re-enrolment usually means the old device is gone or compromised.
        # Existing sessions were established with the old factor and should not
        # survive it.
        revoked = await sessions.revoke_all_for_user(db, user.id)
        await users.unlock(db, username)
        await audit.record(
            db, actor="cli", source="web", operation="enroll_totp",
            target=username, params={"sessions_revoked": revoked}, result="ok",
        )
        print(f"Al doilea factor reînrolat. {revoked} sesiune/sesiuni revocate.")
        return 0
    finally:
        await db.close()


async def _set_password(cfg: Config, username: str | None) -> int:
    if not username:
        print("--username este obligatoriu.", file=sys.stderr)
        return 1

    db = await _with_db(cfg)
    try:
        user = await users.get_by_username(db, username)
        if user is None:
            print(f"Utilizatorul {username!r} nu există.", file=sys.stderr)
            return 1

        password = _prompt_password()
        await users.set_password(db, user.id, hash_password(password))
        # A password reset that leaves old sessions alive has not locked anyone
        # out. Revoking is the point of the reset.
        revoked = await sessions.revoke_all_for_user(db, user.id)
        await audit.record(
            db, actor="cli", source="web", operation="set_password",
            target=username, params={"sessions_revoked": revoked}, result="ok",
        )
        print(f"Parolă schimbată. {revoked} sesiune/sesiuni revocate.")
        return 0
    finally:
        await db.close()


async def _revoke_sessions(cfg: Config, username: str | None) -> int:
    if not username:
        print("--username este obligatoriu.", file=sys.stderr)
        return 1
    db = await _with_db(cfg)
    try:
        user = await users.get_by_username(db, username)
        if user is None:
            print(f"Utilizatorul {username!r} nu există.", file=sys.stderr)
            return 1
        revoked = await sessions.revoke_all_for_user(db, user.id)
        await audit.record(
            db, actor="cli", source="web", operation="revoke_sessions",
            target=username, params={"count": revoked}, result="ok",
        )
        print(f"{revoked} sesiune/sesiuni revocate.")
        return 0
    finally:
        await db.close()


async def _unlock(cfg: Config, username: str | None) -> int:
    if not username:
        print("--username este obligatoriu.", file=sys.stderr)
        return 1
    db = await _with_db(cfg)
    try:
        if not await users.unlock(db, username):
            print(f"Utilizatorul {username!r} nu există.", file=sys.stderr)
            return 1
        await audit.record(
            db, actor="cli", source="web", operation="unlock",
            target=username, result="ok",
        )
        print(f"Blocarea contului {username!r} a fost eliminată.")
        return 0
    finally:
        await db.close()


async def _list_users(cfg: Config) -> int:
    db = await _with_db(cfg)
    try:
        rows = await db.fetch(
            """
            SELECT username, role, totp_confirmed, disabled, failed_attempts,
                   locked_until, last_login_at, last_login_ip::text AS last_ip
              FROM users ORDER BY username
            """
        )
        if not rows:
            print("Niciun cont. Creează primul: sentinel web --create-admin")
            return 0

        print(f"{'UTILIZATOR':<20} {'ROL':<10} {'2FA':<5} {'STARE':<12} ULTIMA AUTENTIFICARE")
        print("-" * 78)
        for r in rows:
            if r["disabled"]:
                state = "dezactivat"
            elif r["locked_until"]:
                state = "blocat"
            else:
                state = "activ"
            last = (
                r["last_login_at"].strftime("%Y-%m-%d %H:%M")
                if r["last_login_at"] else "niciodată"
            )
            print(
                f"{r['username']:<20} {r['role']:<10} "
                f"{'da' if r['totp_confirmed'] else 'NU':<5} {state:<12} "
                f"{last}  {r['last_ip'] or ''}"
            )
        return 0
    finally:
        await db.close()


if __name__ == "__main__":
    raise SystemExit(main())
