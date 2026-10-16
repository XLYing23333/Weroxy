-- Existing invalid values are detected by runtime reads, not silently rewritten.
CREATE TRIGGER access_policy_validate_insert BEFORE INSERT ON access_policies
WHEN NEW.max_pending < 0 OR
 NEW.max_per_ip < 0 OR
 NEW.rate_per_sec < 0 OR
 NEW.burst < 0 OR
 NEW.idle_sec < 0 OR
 NEW.connect_sec < 0 OR
 NEW.wait_sec < 0 OR
 NEW.bandwidth < 0 OR
 NEW.idle_sec > 9223372036 OR
 NEW.connect_sec > 9223372036 OR
 NEW.wait_sec > 9223372036
BEGIN SELECT RAISE(ABORT, 'invalid numeric policy'); END;
CREATE TRIGGER access_policy_validate_update BEFORE UPDATE ON access_policies
WHEN NEW.max_pending < 0 OR
 NEW.max_per_ip < 0 OR
 NEW.rate_per_sec < 0 OR
 NEW.burst < 0 OR
 NEW.idle_sec < 0 OR
 NEW.connect_sec < 0 OR
 NEW.wait_sec < 0 OR
 NEW.bandwidth < 0 OR
 NEW.idle_sec > 9223372036 OR
 NEW.connect_sec > 9223372036 OR
 NEW.wait_sec > 9223372036
BEGIN SELECT RAISE(ABORT, 'invalid numeric policy'); END;
