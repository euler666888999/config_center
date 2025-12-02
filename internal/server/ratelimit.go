package server

import (
	"sync"
	"time"
)

// rateLimiter 简易令牌桶，按主体维度限流，防止暴力调用。
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	rate      int           // 每秒令牌
	burst     int           // 桶容量
	ttl       time.Duration // 桶空闲回收
	lastSweep time.Time     // 上次清理时间
}

type bucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

func newRateLimiter(rate, burst int, ttl time.Duration) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		rate:      rate,
		burst:     burst,
		ttl:       ttl,
		lastSweep: time.Now(),
	}
}

func (r *rateLimiter) allow(key string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if b, ok := r.buckets[key]; ok {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * float64(r.rate)
		if b.tokens > float64(r.burst) {
			b.tokens = float64(r.burst)
		}
		b.last = now
		b.lastSeen = now
		if b.tokens >= 1 {
			b.tokens--
			return true
		}
		return false
	}
	r.buckets[key] = &bucket{
		tokens:   float64(r.burst - 1),
		last:     now,
		lastSeen: now,
	}
	return true
}

// cleanup 移除闲置桶。
func (r *rateLimiter) cleanup() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.buckets {
		if now.Sub(b.lastSeen) > r.ttl {
			delete(r.buckets, k)
		}
	}
}
