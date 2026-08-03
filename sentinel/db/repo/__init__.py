"""Data access, one module per aggregate.

Everything that touches SQL lives here. The web routers, the detection engine
and the Telegram handlers call these functions; they never write SQL inline.
Two reasons: a query that appears in one place can be fixed in one place, and
parameter binding is not something to re-decide per call site.
"""
