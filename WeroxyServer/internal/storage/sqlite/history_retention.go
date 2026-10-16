package sqlite

import "context"

type HistoryRetention struct {
	FineDays       int `json:"fine_days"`
	FiveMinuteDays int `json:"five_minute_days"`
	HourlyDays     int `json:"hourly_days"`
	ConnectionDays int `json:"connection_days"`
}

func (s HistoryRetention) Valid() bool {
	return s.FineDays >= 1 && s.FineDays <= 7 && s.FiveMinuteDays >= s.FineDays && s.FiveMinuteDays <= 90 && s.HourlyDays >= s.FiveMinuteDays && s.HourlyDays <= 365 && s.ConnectionDays >= 1 && s.ConnectionDays <= 90
}
func (db *DB) HistoryRetention(ctx context.Context) (HistoryRetention, error) {
	var s HistoryRetention
	err := db.QueryRow(ctx, `SELECT fine_days,five_minute_days,hourly_days,connection_days FROM history_retention WHERE id=1`).Scan(&s.FineDays, &s.FiveMinuteDays, &s.HourlyDays, &s.ConnectionDays)
	return s, err
}
