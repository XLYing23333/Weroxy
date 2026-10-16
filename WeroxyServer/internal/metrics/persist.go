package metrics

import (
	"sync/atomic"
	"time"
)

// PersistStatus is diagnostic state for the low-priority metric writer.
// It contains no database error text or secret-bearing values.
type PersistStatus struct {
	lastSample   atomic.Int64
	lastWrite    atomic.Int64
	writeDelayMS atomic.Int64
	dropped      atomic.Uint64
	failure      atomic.Value
}

type PersistView struct {
	LastSampleAt   time.Time `json:"last_sample_at"`
	LastWriteAt    time.Time `json:"last_write_at"`
	WriteDelayMS   int64     `json:"write_delay_ms"`
	DroppedBatches uint64    `json:"dropped_batches"`
	FailureReason  string    `json:"failure_reason"`
}

func NewPersistStatus() *PersistStatus {
	p := &PersistStatus{}
	p.failure.Store("")
	return p
}

func (p *PersistStatus) Record(sampledAt time.Time, errCode string) {
	if p == nil {
		return
	}
	p.lastSample.Store(sampledAt.UnixNano())
	if errCode != "" {
		p.dropped.Add(1)
		p.failure.Store(errCode)
		return
	}
	now := time.Now().UTC()
	p.lastWrite.Store(now.UnixNano())
	p.writeDelayMS.Store(now.Sub(sampledAt).Milliseconds())
	p.failure.Store("")
}

func (p *PersistStatus) Snapshot() PersistView {
	if p == nil {
		return PersistView{}
	}
	out := PersistView{WriteDelayMS: p.writeDelayMS.Load(), DroppedBatches: p.dropped.Load(), FailureReason: p.failure.Load().(string)}
	if n := p.lastSample.Load(); n != 0 {
		out.LastSampleAt = time.Unix(0, n).UTC()
	}
	if n := p.lastWrite.Load(); n != 0 {
		out.LastWriteAt = time.Unix(0, n).UTC()
	}
	return out
}
