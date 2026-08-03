-- 0014_patch_notifications: make the patch pipeline reach the operator by itself.
--
-- Until now every patch-related message on Telegram was pulled: the operator had
-- to send `/patch <id>` to see a plan and its buttons. The plan generator, the
-- validator, the approval flow and the runner were all complete and tested — and
-- nothing connected them to the phone. A pipeline nobody is told about is a
-- pipeline nobody uses.
--
-- Same mechanism as incidents: a nullable timestamp the push loop claims. It is
-- deliberately NOT a boolean —
--
--   * NULL means "never sent", and that is also the state of every row that
--     existed before this migration, which is exactly right: those plans were
--     never pushed either;
--   * a timestamp answers "when did the operator learn about this?", which is
--     the question asked after an incident, and a boolean cannot answer it.
--
-- The partial indexes matter more than they look. Both queries run every 15
-- seconds, forever, and both are looking for the rare row in a table that only
-- grows. Without them this is two sequential scans a minute for the lifetime of
-- the installation.

ALTER TABLE patch_plans      ADD COLUMN IF NOT EXISTS notified_at timestamptz;
ALTER TABLE patch_executions ADD COLUMN IF NOT EXISTS notified_at timestamptz;

COMMENT ON COLUMN patch_plans.notified_at IS
    'When this plan was pushed to Telegram with its approval buttons. NULL = never.';
COMMENT ON COLUMN patch_executions.notified_at IS
    'When this execution''s outcome was announced. NULL = never.';

-- Only 'validated' plans are ever offered: an invalid plan must never carry an
-- approve button, so it has no business in the push queue either.
CREATE INDEX IF NOT EXISTS patch_plans_unnotified_idx
    ON patch_plans (created_at)
    WHERE notified_at IS NULL AND status = 'validated';

-- Only finished ones: a running execution has no outcome to report yet.
CREATE INDEX IF NOT EXISTS patch_executions_unnotified_idx
    ON patch_executions (finished_at)
    WHERE notified_at IS NULL AND finished_at IS NOT NULL;

-- Executions that finished before this migration are history. Announcing them
-- now would report runs the operator already looked at, and the first thing a
-- new feature must not do is cry wolf. Stamped, not announced.
UPDATE patch_executions SET notified_at = now()
    WHERE notified_at IS NULL AND finished_at IS NOT NULL;

-- Plans are deliberately NOT backfilled. A plan still sitting at 'validated' is
-- a decision waiting on a human who, until now, was never asked — which is the
-- exact gap this migration exists to close. The TTL filter in the query keeps
-- anything genuinely stale out.

