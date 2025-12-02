package server

import (
	"sync"
	"time"
)

// quotaTracker 用于简单的配额限制（按 actor+namespace+resource+action）。
type quotaTracker struct {
	mu        sync.Mutex
	limits    map[string]*quotaEntry
	ttl       time.Duration
	lastSweep time.Time
}

type quotaEntry struct {
	remain int
	reset  time.Time
}

func newQuotaTracker(ttl time.Duration) *quotaTracker {
	return &quotaTracker{
		limits:    make(map[string]*quotaEntry),
		ttl:       ttl,
		lastSweep: time.Now(),
	}
}

// allow 返回是否允许并扣减。
func (q *quotaTracker) allow(key string, limit int) bool {
	if limit <= 0 {
		return true
	}
	now := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()
	ent, ok := q.limits[key]
	if !ok || now.After(ent.reset) {
		q.limits[key] = &quotaEntry{
			remain: limit - 1,
			reset:  now.Add(q.ttl),
		}
		return true
	}
	if ent.remain <= 0 {
		return false
	}
	ent.remain--
	return true
}

func (q *quotaTracker) cleanup() {
	now := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()
	for k, v := range q.limits {
		if now.After(v.reset) {
			delete(q.limits, k)
		}
	}
}
