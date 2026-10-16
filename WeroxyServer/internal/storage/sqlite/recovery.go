package sqlite

func (db *DB) requireRecovery() {
	db.recoveryRequired.Store(true)
	db.recoveryOnce.Do(func() { close(db.recoveryFailed) })
}

// RecoveryFailure wakes the owner to stop accepting connections. A damaged
// database cannot continue serving cached device credentials after rollback fails.
func (db *DB) RecoveryFailure() <-chan struct{} { return db.recoveryFailed }
