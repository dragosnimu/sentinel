"""`scripts/compose-pin.sh` — fluxurile `recreate` și `restore`, etichetele flotante și pașii următori tipăriți după un pin.

Același lanț ca în `test_compose_pin_launcher.py` (ssh/sudo momeală care EXECUTĂ comanda, biblioteca reală de pe gazdă, docker momeală).
Ce NU dovedește: un ssh, un sudo sau o gazdă reale.
"""

from __future__ import annotations

import re
import shutil

import pytest

from _compose_pin_world import COMPOSE, TRAEFIK_ID, World, sha
from test_compose_pin_launcher import remote_runs, run_launcher

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="fără bash în PATH")

TRAEFIK_PIN = "traefik=traefik:v3.8.0"
N8N_UP = "n8n=docker.n8n.io/n8nio/n8n:2.49.7"


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def pin_then(w: World, *pins: str, extra=()):
    args = ["pin", "--file", w.fpath]
    for p in pins:
        args += ["--pin", p]
    return run_launcher(w, *args, *extra, "--yes")


def test_floating_tag_with_the_flag_reaches_the_host_and_warns(w):
    """Cu --allow-floating-tag operatorul alege o etichetă mutabilă; lansatorul o trimite, iar gazda spune că nu e un pin real."""
    w.load()
    w.state["known_pulls"]["traefik:v3.8"] = TRAEFIK_ID
    w.save()
    rc, out, log = run_launcher(w, "pin", "--file", w.fpath, "--pin", "traefik=traefik:v3.8", "--allow-floating-tag", "--yes")
    assert rc == 0, out
    assert "--allow-floating-tag" in remote_runs(log)[0] and "NU e un pin real" in out


def test_pure_pin_prints_the_exact_recreate_command_with_this_hosts_arguments(w):
    """După un pin pur, faza containers reține serviciul (hold-config-drift) și `--accept-drift` nu-l rezolvă: operatorul trebuie să vadă COMANDA
    `recreate` pe care să o ruleze, cu gazda, contul, portul și cheia lui, nu o frază generică."""
    rc, out, _ = pin_then(w, TRAEFIK_PIN)
    assert rc == 0, out
    assert re.search(r"PASUL URMĂTOR \(pin pur\).*hold-config-drift pentru: traefik", out)
    cmd = [l for l in out.splitlines() if "compose-pin.sh --host n8n.example.invalid --user dragos" in l and "recreate" in l]
    assert cmd and f"--port 2222" in cmd[0] and "--key" in cmd[0] and f"recreate --file {w.fpath} --service traefik" in cmd[0], out
    assert "--accept-drift NU ajută" in out
    assert "system-update.sh" not in "\n".join(l for l in out.splitlines() if l.startswith("[!]") and "recreate --file" in l)


def test_version_change_prints_the_accept_drift_command_and_not_recreate(w):
    """O versiune nouă e REȚINUTĂ de faza containers și se aplică prin `--accept-drift <proiect>` (dovedit de faza reală, vezi
    test_compose_pin_recreate); `recreate` ar duce proiectul în stale-baseline. Se tipărește comanda exactă system-update, întâi cu --dry-run."""
    rc, out, _ = pin_then(w, N8N_UP, extra=("--allow-version-change",))
    assert rc == 0, out
    assert re.search(r"PASUL URMĂTOR \(versiune nouă\).*REȚINE", out)
    lines = [l for l in out.splitlines() if "system-update.sh --host n8n.example.invalid --user dragos" in l]
    assert any("--port 2222" in l and "--phase containers --accept-drift root --dry-run" in l for l in lines), out
    assert any(l.rstrip().endswith("--phase containers --accept-drift root") for l in lines), out
    assert "compose-pin.sh --host n8n.example.invalid --user dragos --key" not in "".join(l for l in out.splitlines() if " recreate --file" in l)


def test_recreate_asks_for_confirmation_and_is_bound_to_the_plan(w):
    """Repornirea unui serviciu de producție cere «da» DUPĂ ce operatorul vede ce se oprește; scrierea pornește cu suma din plan. «nu»
    înseamnă că nu s-a repornit nimic."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    w.log_path.unlink()
    rc, out, log = run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", stdin="nu\n")
    assert rc == 1 and "anulat" in out and "va fi OPRIT și recreat" in out
    assert not [l for l in w.docker_lines() if " up " in l]
    rc, out, log = run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", stdin="da\n")
    assert rc == 0, out
    runs = remote_runs(log)
    assert "--plan" in runs[-2] and f"--expect-sha256 {sha(w.original)}" in runs[-1]
    assert len([l for l in w.docker_lines() if " up " in l]) == 1
    assert "DOVEDIT: traefik" in out


def test_recreate_failure_prints_the_rollback_with_this_hosts_arguments_and_exits_1(w):
    """Un recreate nedovedit iese cu 1 și spune cum se revine, cu comanda de restore completă; nu face rollback singur."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    w.patch(up_stale_label=True)
    rc, out, _ = run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", "--yes")
    assert rc == 1 and "RECREAREA NU E DOVEDITĂ" in out and "ROLLBACK (nu se face singur; `up` A RULAT" in out
    assert f"compose-pin.sh --host n8n.example.invalid --user dragos" in out and f"restore --file {w.fpath}" in out
    assert w.original != COMPOSE.encode(), "fișierul nu are voie să fie readus singur"


def test_restore_flow_confirms_and_restores(w):
    """`restore` cere «da», pune la loc copia, dovedește suma; fără «da» nu s-a atins nimic."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    pinned = w.original
    rc, out, _ = run_launcher(w, "restore", "--file", w.fpath, stdin="")
    assert rc == 1 and w.original == pinned
    rc, out, log = run_launcher(w, "restore", "--file", w.fpath, stdin="da\n")
    assert rc == 0, out
    assert w.original == COMPOSE.encode() and "restaurat și DOVEDIT" in out
    assert f"--expect-sha256 {sha(pinned)}" in remote_runs(log)[-1]


# ---------------------------------------------------------------------------------------------------------------
# rollback doar când `up` chiar a rulat
# ---------------------------------------------------------------------------------------------------------------

def recreate_launcher(w, *extra, env_extra=None):
    return run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", "--yes", *extra, env_extra=env_extra)


NO_UP_CASES = ["refusal_unpinned", "no_drift", "exit3_before_up", "plan_refusal_without_yes"]


@pytest.mark.parametrize("case", NO_UP_CASES)
def test_no_rollback_text_when_up_never_ran(w, case):
    """Un `recreate` refuzat sau oprit înainte de `up` n-a atins nimic: un «ROLLBACK … restore» tipărit atunci îl trimite pe operator să DESFACĂ un pin bun
    (fișierul se readuce, apare drift invers). Fără marcajul COMPOSE_PIN_UP_RAN=1 de la gazdă se tipărește motivul, nu rollback."""
    if case not in ("refusal_unpinned", "plan_refusal_without_yes"):
        assert pin_then(w, TRAEFIK_PIN)[0] == 0
    if case == "no_drift":
        assert recreate_launcher(w)[0] == 0
    if case == "exit3_before_up":
        w.load()
        w.state["containers"]["root-traefik-1"]["labels"]["com.docker.compose.config-hash"] = ""
        w.save()
    if case == "plan_refusal_without_yes":
        rc, out, log = run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", stdin="da\n")
    else:
        rc, out, log = recreate_launcher(w)
    assert rc in (1, 3), out
    assert "ROLLBACK" not in out and "restore --file" not in out, out
    assert "NU s-a repornit nimic" in out and "nimic de readus" in out
    assert "COMPOSE_PIN_UP_RAN" not in out


def test_no_rollback_text_when_ssh_drops_before_up_is_seen(w):
    """ssh căzut fără niciun marcaj: nu se știe dacă up a pornit, deci nu se recomandă nimic care schimbă fișierul; se spune să se citească starea."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    rc, out, _ = recreate_launcher(w, env_extra={"FAKE_SSH_DROP": "1"})
    assert rc == 255 and "ROLLBACK" not in out and "n-am văzut dacă" in out


def test_exit_4_after_up_says_up_ran_and_does_not_recommend_restore(w):
    """Cod 4 vine după up: ceva nenumit s-a schimbat. Starea nu e «verificarea a eșuat», deci nu se recomandă restore pe încredere; se spune că up A RULAT."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    w.add_hook(on="up", action="container", name="root-n8n-1", field="restart")
    rc, out, _ = recreate_launcher(w)
    assert rc == 4 and "A RULAT, dar rezultatul nu e dovedit (cod 4)" in out and "ROLLBACK" not in out


def test_rollback_text_is_present_when_up_ran_and_verification_failed(w):
    """Contrarul: `up` a pornit și verificarea a picat: rollback-ul e exact ce trebuie, cu comanda de restore completă."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    w.patch(up_stale_label=True)
    rc, out, _ = recreate_launcher(w)
    assert rc == 1 and out.count("COMPOSE_PIN_UP_RAN=1") == 1
    assert "ROLLBACK (nu se face singur; `up` A RULAT" in out and f"restore --file {w.fpath}" in out
    assert "NU s-a repornit nimic" not in out


# ---------------------------------------------------------------------------------------------------------------
# marcaj + cod 3 / 255: up a rulat, rezultatul nu e dovedit: nu se recomandă rollback
# ---------------------------------------------------------------------------------------------------------------

def test_marker_plus_exit_3_after_up_does_not_recommend_rollback(w):
    """`up` a pornit, apoi măsurarea hash-urilor a picat (cod 3): starea nu e dovedită, nici bună, nici rea. Un rollback recomandat atunci ar desface un pin pe
    încredere. Se spune că up A RULAT și se trimite la `show`."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    n = w.load().get("calls", {}).get("config-hash", 0)
    w.patch(config_hash_fail_on_call=n + 2)          # apelul 1 = înainte de up (hash0), apelul 2 = după up
    rc, out, _ = recreate_launcher(w)
    assert rc == 3 and out.count("COMPOSE_PIN_UP_RAN=1") == 1, out
    assert "ROLLBACK" not in out and "restore --file" not in out
    assert "A RULAT, dar rezultatul nu e dovedit (cod 3)" in out


def test_marker_plus_exit_255_after_the_host_ran_does_not_recommend_rollback(w):
    """ssh cade DUPĂ ce gazda a pornit up (marcajul a trecut prin conexiune): lansatorul nu știe cum s-a terminat, deci nu recomandă rollback; spune că up A RULAT."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    rc, out, _ = recreate_launcher(w, env_extra={"FAKE_SSH_DROP_AFTER": "1"})
    assert rc == 255 and out.count("COMPOSE_PIN_UP_RAN=1") == 1, out
    assert "ROLLBACK" not in out and "A RULAT, dar rezultatul nu e dovedit (cod 255)" in out


# ---------------------------------------------------------------------------------------------------------------
# planul unui pin trage imaginea: textul de anulare trebuie să fie adevărat
# ---------------------------------------------------------------------------------------------------------------

def test_cancelling_a_pin_says_the_plan_pulled_the_image(w):
    """`pin --plan` rulează `docker pull` (singura dovadă că REF e imaginea care rulează). La «nu», «nimic nu s-a schimbat pe gazdă» ar fi fals: imaginea e acum pe
    disc. Textul spune că fișierul și containerele sunt neatinse, dar că planul a tras imaginea; și o spune ÎNAINTE de întrebare."""
    rc, out, _ = run_launcher(w, "pin", "--file", w.fpath, "--pin", TRAEFIK_PIN, stdin="nu\n")
    assert rc == 1, out
    assert [l for l in w.docker_lines() if l.startswith("pull")], "ipoteza testului: planul chiar a tras imaginea"
    assert "nimic nu s-a schimbat pe gazdă" not in out
    assert "planul a rulat însă" in out and "imaginile pot fi acum pe disc" in out and "NU s-au atins" in out
    assert "Planul de mai sus a RULAT `docker pull`" in out, "textul dinainte de întrebare trebuie să spună că planul trage"
    assert w.original == COMPOSE.encode() and w.backups() == []


def test_cancelling_a_recreate_or_restore_keeps_the_plain_text_because_nothing_was_pulled(w):
    """Contrarul: planul lui recreate/restore nu trage nimic, deci «nimic nu s-a schimbat pe gazdă» rămâne adevărat și rămâne scris."""
    assert pin_then(w, TRAEFIK_PIN)[0] == 0
    w.log_path.unlink()
    rc, out, _ = run_launcher(w, "recreate", "--file", w.fpath, "--service", "traefik", stdin="nu\n")
    assert rc == 1 and "anulat — nimic nu s-a schimbat pe gazdă" in out and "docker pull" not in out
    assert not [l for l in w.docker_lines() if l.startswith("pull")]
