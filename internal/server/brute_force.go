package server

import (
	"sync"
	"time"
)

// bruteForceGuard 防爆破：记录失败次数，超阈值后封禁一段时间。
type bruteForceGuard struct {
	mu        sync.Mutex
	failures  map[string]int
	blocked   map[string]time.Time
	threshold int
	blockFor  time.Duration
}

// newBruteForceGuard 创建按 key 计数的防爆破器。
func newBruteForceGuard(threshold int, blockFor time.Duration) *bruteForceGuard {
	return &bruteForceGuard{
		failures:  make(map[string]int),
		blocked:   make(map[string]time.Time),
		threshold: threshold,
		blockFor:  blockFor,
	}
}

// allow 返回是否允许继续尝试。
func (b *bruteForceGuard) allow(key string) bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if until, ok := b.blocked[key]; ok && now.Before(until) {
		return false
	}
	delete(b.blocked, key)
	return true
}

// onFailure 增加失败计数。
func (b *bruteForceGuard) onFailure(key string) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures[key]++
	if b.failures[key] >= b.threshold && b.threshold > 0 {
		b.blocked[key] = now.Add(b.blockFor)
		b.failures[key] = 0
	}
}

// reset 在成功时清理计数。
func (b *bruteForceGuard) reset(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.failures, key)
}
