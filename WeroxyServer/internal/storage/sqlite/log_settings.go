package sqlite

import "context"

type LogSettings struct {
	MaxFileMiB  int   `json:"max_file_mib"`
	MaxTotalMiB int   `json:"max_total_mib"`
	MaxFiles    int   `json:"max_files"`
	RetainDays  int   `json:"retain_days"`
	Revision    int64 `json:"-"`
}

func (s LogSettings) Valid() bool {
	return s.MaxFileMiB >= 1 && s.MaxFileMiB <= 128 && s.MaxTotalMiB >= 16 && s.MaxTotalMiB <= 1024 && s.MaxTotalMiB >= s.MaxFileMiB && s.MaxFiles >= 2 && s.MaxFiles <= 64 && s.RetainDays >= 1 && s.RetainDays <= 365
}
func (db *DB) LogSettings(ctx context.Context) (LogSettings, error) {
	var s LogSettings
	err := db.QueryRow(ctx, `SELECT l.max_file_mib,l.max_total_mib,l.max_files,l.retain_days,r.desired_revision FROM log_settings l JOIN config_revisions r ON r.domain='logging' WHERE l.id=1`).Scan(&s.MaxFileMiB, &s.MaxTotalMiB, &s.MaxFiles, &s.RetainDays, &s.Revision)
	return s, err
}
