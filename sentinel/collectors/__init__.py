"""Log collectors (P3).

Each collector is split in two: a pure `parse_*` function that turns one log line
into a canonical Event (no I/O, fully testable), and a reader loop that feeds it
lines from journald or a tailed file. Keeping the parsing pure is what lets the
tricky part — the regexes that face attacker-controlled log text — be tested
without a running system.
"""
