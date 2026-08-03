"""The AI layer: deterministic detection hands off, Claude adds judgement.

Claude never computes a score or makes a block decision — those stay
deterministic and free. It receives the deterministic outputs and produces the
things a model is actually good at: a Romanian narrative, a severity call in the
ambiguous band, false-positive triage. Budgeted hard (see budget.py), degrades
gracefully when the API is unreachable, and treats every log line and path as
untrusted attacker input (see prompts.py).
"""
