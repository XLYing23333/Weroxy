CREATE TABLE history_retention (
 id INTEGER PRIMARY KEY CHECK(id=1),
 fine_days INTEGER NOT NULL CHECK(fine_days BETWEEN 1 AND 7),
 five_minute_days INTEGER NOT NULL CHECK(five_minute_days BETWEEN 1 AND 90),
 hourly_days INTEGER NOT NULL CHECK(hourly_days BETWEEN 1 AND 365),
 connection_days INTEGER NOT NULL CHECK(connection_days BETWEEN 1 AND 90)
);
INSERT INTO history_retention VALUES(1,1,7,90,7);
