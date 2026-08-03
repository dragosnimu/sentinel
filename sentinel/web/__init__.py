"""The dashboard.

Read-only against the database plus a live event stream. It never talks to the
privileged executor: destructive actions go into `action_requests` and require a
Telegram confirmation. That boundary is what keeps a dashboard compromise to a
data disclosure rather than a takeover.
"""
