"""Response: blocking, allowlisting, and the anti-lockout watchdog.

`watchdog.py` is intentionally runnable as a standalone script by root, with no
dependency on the rest of this package being importable. It has to work when
everything else has failed — that is the whole point of it.
"""
