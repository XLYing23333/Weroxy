-- IDs survive deletion, rollback of configuration and protocol switches.
CREATE TABLE entity_id_sequences (
 entity TEXT PRIMARY KEY CHECK(entity IN ('legacy_devices','legacy_forwards','weroxy_devices','weroxy_forwards')),
 last_id INTEGER NOT NULL CHECK(typeof(last_id)='integer' AND last_id>=0)
);
INSERT INTO entity_id_sequences VALUES('legacy_devices',max(coalesce((SELECT max(id) FROM legacy_devices),0),coalesce((SELECT max(entity_id) FROM metric_totals WHERE scope='device' AND protocol='legacy'),0),coalesce((SELECT max(device_id) FROM connection_details WHERE protocol='legacy'),0)));
CREATE TRIGGER legacy_devices_id_high_water AFTER INSERT ON legacy_devices BEGIN UPDATE entity_id_sequences SET last_id=max(last_id,NEW.id) WHERE entity='legacy_devices'; END;
INSERT INTO entity_id_sequences VALUES('legacy_forwards',max(coalesce((SELECT max(id) FROM legacy_forwards),0),coalesce((SELECT max(entity_id) FROM metric_totals WHERE scope='forward' AND protocol='legacy'),0),coalesce((SELECT max(forward_id) FROM connection_details WHERE protocol='legacy'),0)));
CREATE TRIGGER legacy_forwards_id_high_water AFTER INSERT ON legacy_forwards BEGIN UPDATE entity_id_sequences SET last_id=max(last_id,NEW.id) WHERE entity='legacy_forwards'; END;
INSERT INTO entity_id_sequences VALUES('weroxy_devices',max(coalesce((SELECT max(id) FROM weroxy_devices),0),coalesce((SELECT max(entity_id) FROM metric_totals WHERE scope='device' AND protocol='weroxy'),0),coalesce((SELECT max(device_id) FROM connection_details WHERE protocol='weroxy'),0)));
CREATE TRIGGER weroxy_devices_id_high_water AFTER INSERT ON weroxy_devices BEGIN UPDATE entity_id_sequences SET last_id=max(last_id,NEW.id) WHERE entity='weroxy_devices'; END;
INSERT INTO entity_id_sequences VALUES('weroxy_forwards',max(coalesce((SELECT max(id) FROM weroxy_forwards),0),coalesce((SELECT max(entity_id) FROM metric_totals WHERE scope='forward' AND protocol='weroxy'),0),coalesce((SELECT max(forward_id) FROM connection_details WHERE protocol='weroxy'),0)));
CREATE TRIGGER weroxy_forwards_id_high_water AFTER INSERT ON weroxy_forwards BEGIN UPDATE entity_id_sequences SET last_id=max(last_id,NEW.id) WHERE entity='weroxy_forwards'; END;
