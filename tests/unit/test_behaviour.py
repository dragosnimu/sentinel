"""F04's novelty signal is a new `Dimension` in the existing behaviour-profile
engine (`predict/behaviour.py`), not a new detector. `detect/novelty.py`'s
`unseen_before` and `composition_shift` already iterate `bh.DIMENSIONS`
generically — if this dimension isn't registered there with the right
source/action/key, the "a destination never contacted before" signal the
whole feature is built around silently never fires, with no error to say so.
"""
from __future__ import annotations

from sentinel.predict import behaviour as bh


def test_outbound_dst_dimension_is_registered():
    dims = {d.name: d for d in bh.DIMENSIONS}
    assert "outbound_dst" in dims
    dim = dims["outbound_dst"]
    assert dim.source == "conntrack"
    assert dim.action == "connect"


def test_outbound_dst_key_is_the_destination_address():
    dim = bh.BY_NAME["outbound_dst"]
    row = {"dst_ip": "93.184.216.34"}
    assert dim.key_of(row) == "93.184.216.34"


def test_outbound_dst_key_is_none_without_a_destination():
    # A row from a different source/action pairing would not carry dst_ip at
    # all; the shared `_s` helper must treat that as "no key", not crash the
    # observe() loop for every other dimension sharing the same query.
    dim = bh.BY_NAME["outbound_dst"]
    assert dim.key_of({"dst_ip": None}) is None


def test_observe_query_selects_dst_ip():
    # `observe()` runs ONE shared SELECT for every dimension in the same
    # pass; if dst_ip isn't in that column list, `outbound_dst.key_of` above
    # raises on every real row instead of returning a key.
    import inspect

    src = inspect.getsource(bh.observe)
    assert "dst_ip" in src
