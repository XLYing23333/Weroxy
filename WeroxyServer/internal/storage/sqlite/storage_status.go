package sqlite

import (
	"context"
	"database/sql"
	"time"
)

// CheckpointStatus describes SQLite's passive WAL checkpoint result. A busy
// result can be caused by a concurrent reader; it is not a liveness failure.
type CheckpointStatus struct {
	At                 time.Time `json:"at"`
	Busy               int       `json:"busy"`
	LogFrames          int       `json:"log_frames"`
	CheckpointedFrames int       `json:"checkpointed_frames"`
	FailureReason      string    `json:"failure_reason"`
}

// CheckpointPassive never deletes an active WAL or blocks waiting for readers.
func (db *DB) CheckpointPassive(ctx context.Context) error {
	at := time.Now().UTC()
	status := CheckpointStatus{At: at}
	completed := make(chan CheckpointStatus, 1)
	err := db.WithConn(ctx, func(conn *sql.Conn) error {
		// WithConn may return on cancellation while the writer is completing.
		// Never share the caller's status object with that late callback.
		result := CheckpointStatus{At: at}
		err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).Scan(&result.Busy, &result.LogFrames, &result.CheckpointedFrames)
		completed <- result
		return err
	})
	if err != nil {
		status.FailureReason = "checkpoint_failed"
	} else {
		status = <-completed
	}
	db.checkpointMu.Lock()
	db.checkpoint = status
	db.checkpointMu.Unlock()
	return err
}
