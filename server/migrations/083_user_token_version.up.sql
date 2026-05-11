-- Add token_version for server-side JWT revocation (JEE-17 / P1-4).
--
-- The Auth middleware now stamps the current value into every JWT as the
-- `tv` claim. A subsequent UPDATE that increments this column invalidates
-- every JWT minted before the bump, providing a real logout-all and an
-- option to force-revoke a leaked session without waiting 30 days for
-- exp. Logout, password / email changes, and explicit admin "kick"
-- actions are the expected mutators.
ALTER TABLE "user"
    ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
