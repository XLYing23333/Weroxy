package sqlite

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"modernc.org/sqlite"
)

const (
	backupKeep                = 7
	backupSingleBytes   int64 = 256 << 20
	backupRetainedBytes int64 = 512 << 20
	backupPeakBytes     int64 = 768 << 20
)

var ErrBackupBudget = errors.New("backup capacity exceeded")

type onlineBackup interface {
	NewBackup(string) (*sqlite.Backup, error)
	NewRestore(string) (*sqlite.Backup, error)
}

// BackupFile copies the live database, including WAL, into dir and checks it.
func (db *DB) BackupFile(ctx context.Context, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	if err := BackupSpace(dir, backupSingleBytes); err != nil {
		return "", err
	}
	name := "weroxy-" + time.Now().UTC().Format("20060102T150405.000000000Z") + ".db"
	path := filepath.Join(dir, name)
	temp := path + ".tmp"
	defer os.Remove(temp)
	if err := db.WithConn(ctx, func(conn *sql.Conn) error {
		return backupToContext(ctx, conn, temp)
	}); err != nil {
		return "", err
	}
	if err := integrity(temp); err != nil {
		return "", err
	}
	if info, err := os.Stat(temp); err != nil || info.Size() > backupSingleBytes {
		return "", ErrBackupBudget
	}
	if err := os.Rename(temp, path); err != nil {
		return "", err
	}
	if err := pruneBackups(dir); err != nil {
		return "", err
	}
	return name, nil
}

func backupTo(conn *sql.Conn, path string) error {
	return backupToContext(context.Background(), conn, path)
}

func backupToContext(ctx context.Context, conn *sql.Conn, path string) error {
	return conn.Raw(func(driverConn any) error {
		tool, ok := driverConn.(onlineBackup)
		if !ok {
			return errors.New("sqlite backup")
		}
		job, err := tool.NewBackup(path)
		if err != nil {
			return err
		}
		for more := true; more; {
			var stepErr error
			more, stepErr = job.Step(128)
			if stepErr != nil {
				_ = job.Finish()
				return stepErr
			}
			if err := ctx.Err(); err != nil {
				_ = job.Finish()
				return err
			}
			if info, err := os.Stat(path); err == nil && info.Size() > backupSingleBytes {
				_ = job.Finish()
				return ErrBackupBudget
			}
		}
		return job.Finish()
	})
}

func restoreFrom(ctx context.Context, conn *sql.Conn, path string) error {
	return restoreSteps(ctx, conn, path, nil)
}

func restoreSteps(ctx context.Context, conn *sql.Conn, path string, progress func() error) error {
	return conn.Raw(func(driverConn any) error {
		tool, ok := driverConn.(onlineBackup)
		if !ok {
			return errors.New("sqlite backup")
		}
		job, err := tool.NewRestore(path)
		if err != nil {
			return err
		}
		for more := true; more; {
			var stepErr error
			more, stepErr = job.Step(128)
			if stepErr != nil {
				_ = job.Finish()
				return stepErr
			}
			if err := ctx.Err(); err != nil {
				_ = job.Finish()
				return err
			}
			if progress != nil {
				if err := progress(); err != nil {
					_ = job.Finish()
					return err
				}
			}
		}
		return job.Finish()
	})
}

func integrity(path string) error {
	check, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer check.Close()
	var result string
	if err := check.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return err
	}
	if result != "ok" {
		return fmt.Errorf("integrity %s", result)
	}
	return nil
}

func BackupReadPath(dir, name string) (string, error) { return backupPath(dir, name) }

func backupPath(dir, name string) (string, error) {
	if name == "" || name != filepath.Base(name) || filepath.Ext(name) != ".db" {
		return "", errors.New("backup name")
	}
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > backupSingleBytes {
		return "", errors.New("backup name")
	}
	return path, nil
}

// BackupSpace reserves a bounded amount for one new backup or upload.
// The retained and peak budgets include completed files and temp copies.
func BackupSpace(dir string, incoming int64) error {
	if incoming < 0 || incoming > backupSingleBytes {
		return ErrBackupBudget
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".db") && !strings.HasSuffix(entry.Name(), ".db.tmp") {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return ErrBackupBudget
		}
		if strings.HasPrefix(entry.Name(), "weroxy-") && strings.HasSuffix(entry.Name(), ".db.tmp") && time.Since(info.ModTime()) > time.Hour {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if info.Size() > backupSingleBytes {
			return ErrBackupBudget
		}
		total += info.Size()
		if total > backupPeakBytes {
			return ErrBackupBudget
		}
	}
	if total+incoming > backupPeakBytes {
		return ErrBackupBudget
	}
	return nil
}

type backupEntry struct {
	name     string
	size     int64
	modified time.Time
}

// PruneBackupFiles limits completed backups after a successful backup or import.
func PruneBackupFiles(dir string) error { return pruneBackups(dir) }

func pruneBackups(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []backupEntry
	var total int64
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".db" {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return ErrBackupBudget
		}
		files = append(files, backupEntry{name: entry.Name(), size: info.Size(), modified: info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modified.Equal(files[j].modified) {
			return files[i].name < files[j].name
		}
		return files[i].modified.Before(files[j].modified)
	})
	for len(files) > backupKeep || total > backupRetainedBytes {
		if len(files) == 0 {
			break
		}
		item := files[0]
		if err := os.Remove(filepath.Join(dir, item.name)); err != nil {
			return err
		}
		total -= item.size
		files = files[1:]
	}
	return nil
}

func backupSealMatches(path string, key []byte) error {
	check, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer check.Close()
	var saved []byte
	if err := check.QueryRow(`SELECT seal_check FROM credential_store WHERE id = 1`).Scan(&saved); err != nil {
		return errors.New("backup lacks a compatible device seal")
	}
	if subtle.ConstantTimeCompare(saved, sealCheck(key)) != 1 {
		return errors.New("backup belongs to a different device seal")
	}
	return nil
}
