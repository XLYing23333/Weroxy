// Package logging writes size-capped structured logs and redacts secrets.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxFile is the default size of one application log file.
	DefaultMaxFile int64 = 32 << 20
	// DefaultMaxTotal is the default size of all application log files.
	DefaultMaxTotal int64 = 256 << 20
	// DefaultMaxFiles counts the active file and closed rotations.
	DefaultMaxFiles = 16
	// DefaultRetain is how long a closed log file is kept.
	DefaultRetain = 30 * 24 * time.Hour
	// DefaultMaxRecord is the maximum encoded record size.
	DefaultMaxRecord = 8192

	activeName = "weroxy.log"
)

var secretPair = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|client[-_ ]?key|api[-_ ]?key)\s*[:=]\s*([^\s,"']+)`)

// Options configures a Logger. Zero values select the defaults.
type Options struct {
	Dir       string
	MaxFile   int64
	MaxTotal  int64
	MaxFiles  int
	MaxRecord int
	Retain    time.Duration
	Err       io.Writer
	Now       func() time.Time
}

// Logger writes JSON lines to a rotating file.
type Logger struct {
	eventMu    sync.Mutex
	events     map[string]eventWindow
	suppressed atomic.Uint64
	mu         sync.Mutex
	dir        string
	maxFile    int64
	maxTotal   int64
	maxFiles   int
	maxRecord  int
	retain     time.Duration
	errOut     io.Writer
	now        func() time.Time
	file       *os.File
	lastFail   time.Time
	seq        int
}

// New creates a logger. The directory is created on first write when possible.
func New(opt Options) *Logger {
	if opt.MaxFile <= 0 {
		opt.MaxFile = DefaultMaxFile
	}
	if opt.MaxTotal <= 0 {
		opt.MaxTotal = DefaultMaxTotal
	}
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = DefaultMaxFiles
	}
	if opt.MaxRecord <= 0 {
		opt.MaxRecord = DefaultMaxRecord
	}
	if opt.Retain <= 0 {
		opt.Retain = DefaultRetain
	}
	if opt.Err == nil {
		opt.Err = os.Stderr
	}
	if opt.Now == nil {
		opt.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Logger{
		dir:       opt.Dir,
		maxFile:   opt.MaxFile,
		maxTotal:  opt.MaxTotal,
		maxFiles:  opt.MaxFiles,
		maxRecord: opt.MaxRecord,
		retain:    opt.Retain,
		errOut:    opt.Err,
		now:       opt.Now,
	}
}

// Info writes an INFO record. Debug is intentionally not provided at the default level.
func (l *Logger) Info(msg string, fields map[string]string) {
	l.write("INFO", msg, fields)
}

// Error writes an ERROR record.
func (l *Logger) Error(msg string, fields map[string]string) {
	l.write("ERROR", msg, fields)
}

// Close closes the active file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeLocked()
}

func (l *Logger) write(level, msg string, fields map[string]string) {
	line := l.encode(level, msg, fields)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.ensureLocked(); err != nil {
		l.failLocked(err)
		return
	}
	if err := l.prepareLocked(int64(len(line))); err != nil {
		l.failLocked(err)
		return
	}
	if _, err := l.file.Write(line); err != nil {
		l.failLocked(err)
	}
}

func (l *Logger) encode(level, msg string, fields map[string]string) []byte {
	clean := make(map[string]string, len(fields))
	for key, value := range fields {
		if sensitiveName(key) {
			clean[key] = "[redacted]"
			continue
		}
		clean[key] = secretPair.ReplaceAllString(value, "$1=[redacted]")
	}
	msg = secretPair.ReplaceAllString(msg, "$1=[redacted]")
	rec := struct {
		Time   string            `json:"time"`
		Level  string            `json:"level"`
		Msg    string            `json:"msg"`
		Fields map[string]string `json:"fields,omitempty"`
	}{
		Time:   l.now().Format(time.RFC3339Nano),
		Level:  level,
		Msg:    msg,
		Fields: clean,
	}
	body, err := json.Marshal(rec)
	if err != nil {
		body = []byte(`{"level":"ERROR","msg":"log record dropped"}`)
	}
	if len(body) > l.maxRecord {
		body = []byte(`{"level":"ERROR","msg":"log record truncated"}`)
	}
	return append(body, '\n')
}

func (l *Logger) ensureLocked() error {
	if l.file != nil {
		return nil
	}
	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(l.dir, activeName), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	l.file = f
	return nil
}

func (l *Logger) prepareLocked(incoming int64) error {
	if l.file != nil {
		info, err := l.file.Stat()
		if err != nil {
			return err
		}
		if info.Size() > 0 && info.Size()+incoming > l.maxFile {
			if err := l.rotateLocked(); err != nil {
				return err
			}
		}
	}
	l.dropExpiredLocked()
	if err := l.dropOverCountLocked(); err != nil {
		return err
	}
	if err := l.dropOverBudgetLocked(incoming); err != nil {
		return err
	}
	total, err := l.totalLocked()
	if err != nil {
		return err
	}
	if total+incoming > l.maxTotal {
		return fmt.Errorf("log budget exhausted")
	}
	return nil
}

func (l *Logger) rotateLocked() error {
	if err := l.closeLocked(); err != nil {
		return err
	}
	active := filepath.Join(l.dir, activeName)
	l.seq++
	name := fmt.Sprintf("weroxy-%s-%d.log", l.now().Format("20060102T150405.000000000Z"), l.seq)
	if err := os.Rename(active, filepath.Join(l.dir, name)); err != nil {
		return err
	}
	f, err := os.OpenFile(active, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	l.file = f
	return nil
}

func (l *Logger) dropExpiredLocked() {
	cutoff := l.now().Add(-l.retain)
	for _, file := range l.closedLocked() {
		if file.mod.Before(cutoff) {
			_ = os.Remove(file.path)
		}
	}
}

func (l *Logger) dropOverCountLocked() error {
	for {
		closed := l.closedLocked()
		if len(closed)+1 <= l.maxFiles {
			return nil
		}
		if err := os.Remove(closed[0].path); err != nil {
			return err
		}
	}
}

// Cleanup failure ends the write attempt; it must not spin while holding the
// logger mutex when a rotation cannot be removed (permissions or I/O failure).
func (l *Logger) dropOverBudgetLocked(incoming int64) error {
	for {
		total, err := l.totalLocked()
		if err != nil {
			return err
		}
		if total+incoming <= l.maxTotal {
			return nil
		}
		closed := l.closedLocked()
		if len(closed) == 0 {
			return fmt.Errorf("log budget exhausted")
		}
		if err := os.Remove(closed[0].path); err != nil {
			return err
		}
	}
}

type closedFile struct {
	path string
	mod  time.Time
	size int64
}

func (l *Logger) closedLocked() []closedFile {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil
	}
	var out []closedFile
	for _, entry := range entries {
		name := entry.Name()
		if name == activeName || !strings.HasPrefix(name, "weroxy-") || !strings.HasSuffix(name, ".log") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, closedFile{
			path: filepath.Join(l.dir, name),
			mod:  info.ModTime(),
			size: info.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].mod.Before(out[j].mod) })
	return out
}

func (l *Logger) totalLocked() (int64, error) {
	var total int64
	if l.file != nil {
		info, err := l.file.Stat()
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	for _, file := range l.closedLocked() {
		total += file.size
	}
	return total, nil
}

func (l *Logger) closeLocked() error {
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *Logger) failLocked(err error) {
	if !l.lastFail.IsZero() && l.now().Sub(l.lastFail) < time.Minute {
		return
	}
	l.lastFail = l.now()
	fmt.Fprintf(l.errOut, "log write degraded\n")
	_ = err
}

func sensitiveName(name string) bool {
	n := strings.ToLower(name)
	n = strings.ReplaceAll(n, "_", "")
	n = strings.ReplaceAll(n, "-", "")
	switch {
	case strings.Contains(n, "password"),
		strings.Contains(n, "passwd"),
		strings.Contains(n, "secret"),
		strings.Contains(n, "token"),
		strings.Contains(n, "authorization"),
		strings.Contains(n, "clientkey"),
		strings.Contains(n, "apikey"),
		n == "key":
		return true
	default:
		return false
	}
}

// BudgetStatus reports application-owned logs, never Docker daemon files.
type BudgetStatus struct {
	SuppressedEvents uint64 `json:"suppressed_events"`
	Enabled          bool   `json:"enabled"`
	MaxFile          int64  `json:"max_file_bytes"`
	MaxTotal         int64  `json:"max_total_bytes"`
	MaxFiles         int    `json:"max_files"`
	MaxRecord        int    `json:"max_record_bytes"`
	RetainDays       int    `json:"retain_days"`
	UsedBytes        int64  `json:"used_bytes"`
	FailureReason    string `json:"failure_reason"`
}

func (l *Logger) BudgetStatus() BudgetStatus {
	if l == nil {
		return BudgetStatus{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := BudgetStatus{SuppressedEvents: l.suppressed.Load(), Enabled: true, MaxFile: l.maxFile, MaxTotal: l.maxTotal, MaxFiles: l.maxFiles, MaxRecord: l.maxRecord, RetainDays: int(l.retain / (24 * time.Hour))}
	if l.file == nil {
		info, err := os.Lstat(filepath.Join(l.dir, activeName))
		if err == nil && info.Mode().IsRegular() {
			out.UsedBytes = info.Size()
		} else if err != nil && !os.IsNotExist(err) {
			out.FailureReason = "log_usage_unavailable"
		}
	}
	used, err := l.totalLocked()
	if err != nil {
		out.FailureReason = "log_usage_unavailable"
	} else {
		out.UsedBytes += used
	}
	return out
}

// SetBudget changes policy under the logger lock. Existing files are processed
// by the next write; applying policy is not a claim of immediate disk reclamation.
func (l *Logger) SetBudget(fileMiB, totalMiB, files, days int) error {
	if l == nil || fileMiB < 1 || fileMiB > 128 || totalMiB < 16 || totalMiB > 1024 || totalMiB < fileMiB || files < 2 || files > 64 || days < 1 || days > 365 {
		return fmt.Errorf("invalid log budget")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxFile = int64(fileMiB) << 20
	l.maxTotal = int64(totalMiB) << 20
	l.maxFiles = files
	l.retain = time.Duration(days) * 24 * time.Hour
	return nil
}

type eventWindow struct {
	start      time.Time
	emitted    int
	suppressed uint64
}

// InfoLimited limits protocol diagnostics by event class, not attacker-controlled
// IP/device values. Only counts are retained; secrets or full fields are not cached.
func (l *Logger) InfoLimited(msg string, fields map[string]string) { l.limited("INFO", msg, fields) }

func (l *Logger) limited(level, msg string, fields map[string]string) {
	if l == nil {
		return
	}
	key := level + ":" + msg
	if len(key) > 128 {
		key = key[:128]
	}
	now := l.now()
	l.eventMu.Lock()
	if l.events == nil {
		l.events = make(map[string]eventWindow)
	}
	if _, exists := l.events[key]; !exists && len(l.events) >= 64 {
		key = "overflow"
	}
	window := l.events[key]
	prior := uint64(0)
	if window.start.IsZero() || now.Before(window.start) || now.Sub(window.start) >= time.Minute {
		prior = window.suppressed
		window = eventWindow{start: now}
	}
	if window.emitted >= 10 {
		window.suppressed++
		l.events[key] = window
		l.suppressed.Add(1)
		l.eventMu.Unlock()
		return
	}
	window.emitted++
	l.events[key] = window
	l.eventMu.Unlock()
	if prior > 0 {
		copied := make(map[string]string, len(fields)+1)
		for k, v := range fields {
			copied[k] = v
		}
		copied["suppressed_previous_window"] = fmt.Sprint(prior)
		fields = copied
	}
	l.write(level, msg, fields)
}
