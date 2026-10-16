package sqlite

import (
	"errors"
	"path/filepath"
	"time"
)

var ErrTelemetryDisk = errors.New("telemetry paused by disk protection")

const diskPauseBytes uint64 = 128 * 1024 * 1024
const diskResumeBytes uint64 = 256 * 1024 * 1024

type DiskStatus struct {
	CheckedAt        time.Time `json:"checked_at"`
	AvailableBytes   uint64    `json:"available_bytes"`
	PauseBelowBytes  uint64    `json:"pause_below_bytes"`
	ResumeAboveBytes uint64    `json:"resume_above_bytes"`
	TelemetryPaused  bool      `json:"telemetry_paused"`
	FailureReason    string    `json:"failure_reason"`
}

// Probe the database volume; privileged/configuration writes remain independent.
// Hysteresis avoids oscillation around the low water mark. Probe failure pauses
// optional telemetry rather than assuming unlimited disk space.
func (db *DB) RefreshDisk() DiskStatus {
	available, err := diskAvailable(filepath.Dir(db.path))
	db.checkpointMu.Lock()
	defer db.checkpointMu.Unlock()
	paused := db.disk.TelemetryPaused
	reason := ""
	if err != nil {
		paused = true
		reason = "disk_probe_failed"
	} else if available < diskPauseBytes {
		paused = true
	} else if available >= diskResumeBytes {
		paused = false
	}
	db.disk = DiskStatus{CheckedAt: time.Now().UTC(), AvailableBytes: available, PauseBelowBytes: diskPauseBytes, ResumeAboveBytes: diskResumeBytes, TelemetryPaused: paused, FailureReason: reason}
	return db.disk
}
func (db *DB) TelemetryAllowed() bool {
	db.checkpointMu.Lock()
	status := db.disk
	db.checkpointMu.Unlock()
	if status.CheckedAt.IsZero() || time.Since(status.CheckedAt) > time.Minute {
		status = db.RefreshDisk()
	}
	return !status.TelemetryPaused
}
