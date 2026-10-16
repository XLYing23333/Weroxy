CREATE TABLE device_status_samples (
  protocol TEXT NOT NULL,
  device TEXT NOT NULL,
  at TEXT NOT NULL,
  duration_sec INTEGER NOT NULL CHECK(duration_sec IN (60,300)),
  state TEXT NOT NULL CHECK(state IN ('online','idle','offline')),
  sessions INTEGER NOT NULL,
  up_bytes INTEGER NOT NULL,
  down_bytes INTEGER NOT NULL,
  PRIMARY KEY(protocol,device,at)
);
CREATE INDEX device_status_time ON device_status_samples(at);
