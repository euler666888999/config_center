package server

import (
	"sync"
	"time"
)

// idempotencyStore 简易幂等键存储，短期内拒绝重复提交。
type idempotencyStore struct {
	mu        sync.Mutex
	items     map[string]time.Time
	ttl       time.Duration
	lastSweep time.Time
}

func newIdempotencyStore(ttl time.Duration) *idempotencyStore {
	return &idempotencyStore{
		items:     make(map[string]time.Time),
		ttl:       ttl,
		lastSweep: time.Now(),
	}
}

// checkAndSet 返回是否首次出现，后续重复则返回 false。
func (s *idempotencyStore) checkAndSet(key string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.items[key]; ok && now.Before(exp) {
		return false
	}
	s.items[key] = now.Add(s.ttl)
	return true
}

func (s *idempotencyStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, exp := range s.items {
		if now.After(exp) {
			delete(s.items, k)
		}
	}
}
