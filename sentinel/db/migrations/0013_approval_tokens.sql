-- 0013_approval_tokens: single-use confirmations for destructive actions.
--
-- A Telegram callback carries whatever string the bot put in the button, and
-- that string sits in a chat history forever. So the button must not BE the
-- authority — it must carry a reference to one, and the authority lives here.
--
-- Four properties, each closing a specific hole:
--
--   * bound to (chat_id, plan_id, plan_hash) — a token approved in one chat is
--     useless in another, and a token for one plan cannot approve a different
--     one. Binding the HASH is what makes a regenerated plan kill every button
--     that was already sent: the bytes changed, so the token no longer matches.
--   * single use — `used_at` is set inside the same UPDATE that consumes it, so
--     two taps on the same button cannot both win.
--   * short TTL — an approval is a decision about the machine as it is right
--     now, not a standing permission discovered in a chat log next month.
--   * `stage` — a first tap issues a stage-2 token rather than acting, which is
--     how "are you sure" becomes a real gate instead of a dialog someone
--     dismisses by reflex.

CREATE TABLE approval_tokens (
    token       text        PRIMARY KEY,
    purpose     text        NOT NULL,      -- patch_apply | patch_dry_run | ...
    stage       smallint    NOT NULL DEFAULT 1 CHECK (stage IN (1, 2)),

    chat_id     bigint,                    -- the Telegram chat that may use it
    plan_id     bigint      REFERENCES patch_plans(id) ON DELETE CASCADE,
    plan_hash   text,                      -- the exact bytes that were approved

    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by     text
);

CREATE INDEX approval_tokens_plan_idx ON approval_tokens (plan_id)
    WHERE used_at IS NULL;
-- Expired-token cleanup scans this; unused tokens are the only ones worth keeping.
CREATE INDEX approval_tokens_expiry_idx ON approval_tokens (expires_at)
    WHERE used_at IS NULL;
