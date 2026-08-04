-- 0015_quiet_hours: a per-chat quiet window the operator can set from the phone.
--
-- `telegram_chats.muted_until` has existed since 0006 and was never read — an
-- ad-hoc "quiet until this moment". What was missing is the recurring case,
-- which is what people actually mean by muting: every night, between these
-- hours, do not buzz.
--
-- Per chat rather than global. `telegram.quiet_hours` in the config is the
-- deployment-wide default, but the config file is root-owned and the bot runs
-- as `sentinel`, so a command that could only edit the config would not work at
-- all. It also happens to be the better model: two operators in different
-- timezones want different windows.
--
-- Stored as text ("22:00-06:00") and not as two `time` columns, because the
-- pair only means something together and half a window is not a state worth
-- being able to represent. The CHECK is deliberately loose — it keeps garbage
-- out of the column; `parse_window` in the application is the real parser.

ALTER TABLE telegram_chats
    ADD COLUMN IF NOT EXISTS quiet_hours text,
    ADD COLUMN IF NOT EXISTS quiet_set_at timestamptz,
    ADD COLUMN IF NOT EXISTS timezone text;

ALTER TABLE telegram_chats
    DROP CONSTRAINT IF EXISTS telegram_chats_quiet_hours_shape;
ALTER TABLE telegram_chats
    ADD CONSTRAINT telegram_chats_quiet_hours_shape
    CHECK (quiet_hours IS NULL OR quiet_hours ~ '^[0-2][0-9]:[0-5][0-9]-[0-2][0-9]:[0-5][0-9]$');

COMMENT ON COLUMN telegram_chats.quiet_hours IS
    'Recurring local-time window, e.g. "22:00-06:00". NULL = fall back to config.';
COMMENT ON COLUMN telegram_chats.muted_until IS
    'Ad-hoc mute expiry. Always bounded — there is no indefinite mute.';
COMMENT ON COLUMN telegram_chats.timezone IS
    'IANA zone the window is read in. NULL = the host''s own zone.';

-- Deliberately NOT setting a window for anyone here. A migration that quietly
-- silenced an existing installation's alerts overnight would be a security
-- change made without anybody asking for it. Operators set their own, from the
-- phone, with /mute.
