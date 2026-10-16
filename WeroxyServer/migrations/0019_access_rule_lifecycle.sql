ALTER TABLE access_rules ADD COLUMN expires_at TEXT;
ALTER TABLE access_rules ADD COLUMN kernel_status TEXT NOT NULL DEFAULT 'unsupported'
    CHECK (kernel_status IN ('not_requested', 'pending', 'applied', 'failed', 'unsupported'));
ALTER TABLE access_rules ADD COLUMN kernel_retry_count INTEGER NOT NULL DEFAULT 0 CHECK (kernel_retry_count >= 0);
ALTER TABLE access_rules ADD COLUMN policy_generation INTEGER NOT NULL DEFAULT 0 CHECK (policy_generation >= 0);
CREATE INDEX access_rules_expiry ON access_rules(expires_at) WHERE expires_at IS NOT NULL;
