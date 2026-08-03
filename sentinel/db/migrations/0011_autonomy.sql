-- 0011_autonomy: what the auto-block decider did about each incident.
--
-- P6 gives detection a response arm. The decider runs inside sentinel-detect and,
-- for a network incident, records here what it chose — WITHOUT the detect service
-- ever touching Telegram or the executor's socket directly. The Telegram push
-- loop reads this column and shapes the alert accordingly:
--
--   NULL / 'observed'   observe mode (auto_block disabled, or below the gate):
--                       the operator gets the alert with a one-tap BLOCK button.
--   'blocked'           armed mode: the decider already blocked the IP; the alert
--                       says so and offers UNBLOCK instead.
--   'skipped:<reason>'  armed, but a cap or guard stopped it (rate cap, allowlist,
--                       known scanner, cidr-not-allowed) — the operator is told
--                       why and can still block by hand.
--
-- Keeping the decision on the incident, not in a side channel, means the alert
-- and the action can never disagree, and the analytics page can later count how
-- often observe mode WOULD have blocked before it was armed.

ALTER TABLE incidents ADD COLUMN auto_action    text;
ALTER TABLE incidents ADD COLUMN auto_action_at timestamptz;

-- The would-block feed for the dashboard and for tuning the 72h observe window:
-- every decision, cheap to scan by time.
CREATE INDEX incidents_auto_action_idx ON incidents (auto_action_at DESC)
    WHERE auto_action IS NOT NULL;
