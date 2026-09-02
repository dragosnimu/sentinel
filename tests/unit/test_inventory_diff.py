"""`inventory.diff` — what `scripts/inventory-push.sh` shows before it writes.

Panele pe care le previne fiecare test, în termeni de operator:

  * **O retragere pe care operatorul n-o vede înainte s-o facă.** Retragerea
    scoate un activ din verificările de sănătate și din panou; dacă `diff`
    ar rata un nume care dispare, scriptul l-ar retrage tăcut.
  * **Un nume adăugat confundat cu unul păstrat, sau invers.** Cele trei liste
    trebuie să se excludă reciproc — un nume care apare în două dintre ele ar
    fi raportat greșit operatorului chiar în momentul în care cere confirmarea.
  * **O redenumire citită ca „retras + adăugat" fără avertisment separat** —
    NU e un defect de aici: `diff` compară pe NUME, la fel ca
    `assets_repo.retire_missing`, deci o redenumire chiar arată ca o pereche
    retragere/adăugare. Testat mai jos ca să rămână vizibil, nu ca regresie.
"""

from __future__ import annotations

from sentinel.scan.inventory import diff


def _spec(name: str) -> dict[str, str]:
    return {"name": name}


def test_asset_dropped_from_the_file_shows_up_as_retired():
    # Falsă dacă `diff` ar rata un nume dispărut din `proposed` — scriptul de
    # push ar scrie fișierul fără să fi arătat operatorului ce se stinge.
    current = [_spec("n8n"), _spec("sshd")]
    proposed = [_spec("sshd")]
    result = diff(current, proposed)
    assert result == {"added": [], "retired": ["n8n"], "kept": ["sshd"]}


def test_new_asset_in_the_file_shows_up_as_added_not_kept():
    current = [_spec("sshd")]
    proposed = [_spec("sshd"), _spec("qdrant")]
    result = diff(current, proposed)
    assert result == {"added": ["qdrant"], "retired": [], "kept": ["sshd"]}


def test_identical_lists_change_nothing():
    # Falsă dacă un push repetat, fără nicio editare reală, ar raporta orice
    # retragere sau adăugare — operatorul ar învăța să nu mai citească diff-ul.
    specs = [_spec("sshd"), _spec("postgresql")]
    result = diff(specs, list(specs))
    assert result == {"added": [], "retired": [], "kept": ["postgresql", "sshd"]}


def test_empty_current_treats_every_proposed_name_as_added_not_kept():
    # Prima instalare: nimic pe gazdă încă, deci totul e „adăugat", nu
    # amestecat cu „păstrat" sau cu „retras" — nu există nimic de retras.
    result = diff([], [_spec("sshd"), _spec("postgresql")])
    assert result == {"added": ["postgresql", "sshd"], "retired": [], "kept": []}


def test_a_rename_reads_as_one_retired_and_one_added_by_design():
    # Nu e o regresie de reparat: `diff` compară pe NUME, la fel ca
    # `assets_repo.retire_missing` — o schimbare de nume ȘI ESTE, din
    # perspectiva bazei, o retragere plus un activ nou.
    current = [_spec("blog-old.example")]
    proposed = [_spec("blog-new.example")]
    result = diff(current, proposed)
    assert result == {
        "added": ["blog-new.example"], "retired": ["blog-old.example"], "kept": [],
    }


def test_result_lists_are_sorted_and_mutually_exclusive():
    # Sortarea contează pentru operator (citește un raport, nu îl caută), iar
    # excluderea reciprocă e ceea ce dovedește că un nume nu poate ieși
    # raportat de două ori sub etichete contradictorii.
    current = [_spec("z-service"), _spec("a-service"), _spec("m-service")]
    proposed = [_spec("a-service"), _spec("m-service"), _spec("b-service")]
    result = diff(current, proposed)
    assert result["added"] == sorted(result["added"])
    assert result["retired"] == sorted(result["retired"])
    assert result["kept"] == sorted(result["kept"])
    all_names = set(result["added"]) | set(result["retired"]) | set(result["kept"])
    assert len(all_names) == len(result["added"]) + len(result["retired"]) + len(result["kept"])
