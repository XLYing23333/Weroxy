ALTER TABLE access_policies ADD COLUMN idle_sec INTEGER;
ALTER TABLE access_policies ADD COLUMN connect_sec INTEGER;
ALTER TABLE access_policies ADD COLUMN wait_sec INTEGER;
ALTER TABLE access_policies ADD COLUMN bandwidth INTEGER;

INSERT INTO access_policies(scope, scope_key, idle_sec, connect_sec, wait_sec)
SELECT 'global', '', 86400, 30, 120
WHERE NOT EXISTS (SELECT 1 FROM access_policies WHERE scope = 'global' AND scope_key = '');

UPDATE access_policies
SET idle_sec = 86400
WHERE scope = 'global' AND scope_key = '' AND idle_sec IS NULL;

UPDATE access_policies
SET connect_sec = 30
WHERE scope = 'global' AND scope_key = '' AND connect_sec IS NULL;

UPDATE access_policies
SET wait_sec = 120
WHERE scope = 'global' AND scope_key = '' AND wait_sec IS NULL;
