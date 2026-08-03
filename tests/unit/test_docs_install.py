"""The install documentation has to still describe the installer.

Docs drift silently: nothing fails when a guide keeps recommending a flag that
was renamed, or claims a distribution that is no longer the only one supported.
This file pins the handful of claims in DEPLOYMENT.md that are checkable against
the scripts themselves, so the next rename breaks a test instead of an operator.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEPLOYMENT = (REPO / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")
DEPANARE = (REPO / "docs" / "DEPANARE.md").read_text(encoding="utf-8")
README = (REPO / "README.md").read_text(encoding="utf-8")
WIZARD = (REPO / "scripts" / "wizard.sh").read_text(encoding="utf-8")
DISTRO = (REPO / "deploy" / "lib" / "distro.sh").read_text(encoding="utf-8")


def _wizard_flags() -> set[str]:
    """Long options the wizard's argument parser actually accepts.

    Each case arm is `--a|-b)`, so take every alternative, not just the last
    one before the paren.
    """
    body = WIZARD.split("while [[ $# -gt 0 ]]", 1)[1].split("\ndone", 1)[0]
    flags: set[str] = set()
    for arm in re.findall(r"^\s*([^\s(]+)\)", body, re.M):
        flags.update(a for a in arm.split("|") if a.startswith("--"))
    return flags


# --- the wizard is documented, and documented correctly --------------------
def test_deployment_guide_leads_with_the_wizard():
    """The one-command path has to come before the eight-argument one, or
    nobody finds it."""
    assert "./scripts/wizard.sh" in DEPLOYMENT
    assert DEPLOYMENT.index("scripts/wizard.sh") < DEPLOYMENT.index(
        "### 3.2 Calea manuală"
    )


def test_every_documented_wizard_flag_exists():
    flags = _wizard_flags()
    documented = set(re.findall(r"wizard\.sh (--[a-z-]+)", DEPLOYMENT + README))
    assert documented, "no wizard flags documented at all"
    unknown = documented - flags - {"--help"}
    assert not unknown, f"documented but not accepted by wizard.sh: {sorted(unknown)}"


def test_the_flags_that_change_safety_are_documented():
    """--dry-run and --config are the two that decide whether a run touches the
    host and whether it asks anything. Both must be in the guide."""
    for flag in ("--dry-run", "--config", "--save"):
        assert f"wizard.sh {flag}" in DEPLOYMENT, f"{flag} is undocumented"


def test_saved_answers_are_documented_as_secret_bearing():
    """--save writes the bot token to disk. An operator who does not know that
    will commit the file."""
    section = DEPLOYMENT.split("### 3.1", 1)[1].split("### 3.2", 1)[0]
    assert "0600" in section and "secret" in section.lower()


# --- claims about the supported hosts --------------------------------------
def test_documented_python_floor_matches_the_installer():
    minor = re.search(r"PYTHON_MIN_MINOR=(\d+)", DISTRO).group(1)
    assert f"3.{minor}" in DEPLOYMENT
    assert f"Python 3.{minor}" in README or f"3.{minor} or newer" in README


def test_no_document_still_claims_a_single_distribution():
    """The requirements table said 'AlmaLinux / RHEL 9.x' for several releases
    after Debian support landed."""
    for name, text in (("DEPLOYMENT.md", DEPLOYMENT), ("README.md", README)):
        assert "Debian" in text, f"{name} does not mention Debian support"
    assert "AlmaLinux / RHEL 9.x" not in DEPLOYMENT


def test_troubleshooting_covers_both_package_managers():
    """A Debian operator reading a dnf-only fix list concludes, correctly, that
    nobody tested their path."""
    step_table = DEPANARE.split("## 3. Instalarea a eșuat", 1)[1].split("\n## ", 1)[0]
    assert "apt-get" in step_table and "dnf" in step_table


# --- examples have to be runnable ------------------------------------------
def test_no_shell_example_contains_a_literal_backslash_n():
    r"""An earlier rewrite left `\n` inside two commands, where a real line
    continuation belonged. Copy-pasting either of them failed."""
    for name in ("DEPLOYMENT.md", "DEPANARE.md", "OPERARE.md", "TESTARE.md"):
        text = (REPO / "docs" / name).read_text(encoding="utf-8")
        for block in re.findall(r"```bash\n(.*?)```", text, re.S):
            assert "\\n" not in block, f"{name}: literal \\n in a shell example"


def test_section_numbers_are_unique():
    """Two different sections both numbered 2.1 make every cross-reference
    ambiguous."""
    for name in ("DEPLOYMENT.md", "DEPANARE.md"):
        text = (REPO / "docs" / name).read_text(encoding="utf-8")
        numbers = re.findall(r"^#{2,3} (\d+(?:\.\d+)?)[ .]", text, re.M)
        dupes = {n for n in numbers if numbers.count(n) > 1}
        assert not dupes, f"{name} reuses section numbers: {sorted(dupes)}"
