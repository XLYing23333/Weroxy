UPDATE access_policies
SET max_active = NULL,
    max_pending = NULL,
    max_per_ip = NULL,
    rate_per_sec = NULL,
    burst = NULL,
    bandwidth = NULL
WHERE scope = 'global' AND scope_key = '';
