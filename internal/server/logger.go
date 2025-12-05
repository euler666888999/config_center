package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// loggingMiddleware 对请求做简单脱敏日志。
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := r.URL.Path
		method := r.Method
		client := clientIP(r)
		// 脱敏 headers 中的敏感信息
		auth := redactedHeader(r.Header.Get("Authorization"))
		trace := r.Header.Get("X-Trace-ID")
		if trace == "" {
			trace = newTraceID()
			r.Header.Set("X-Trace-ID", trace)
		}
		w.Header().Set("X-Trace-ID", trace)
		bodyHint := bodyHintForPath(path)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		latency := time.Since(start)
		log.Printf("[access] %s %s client=%s auth=%s trace=%s body=%s status=%d latency=%s", method, path, client, auth, trace, bodyHint, rec.status, latency)
		s.incMetric("requests_total", 1)
		s.incMetric(fmt.Sprintf("status_%d", rec.status), 1)
		s.incMetric("latency_ms_total", latency.Milliseconds())
		s.incMetric(latencyBucketKey(latency), 1)
		if rec.status >= 400 {
			s.incMetric("requests_failed", 1)
		}
	})
}

func redactedHeader(v string) string {
	if v == "" {
		return ""
	}
	return "REDACTED"
}

// newTraceID 生成简易 16 字节十六进制 Trace ID。
func newTraceID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("trace-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func bodyHintForPath(path string) string {
	if strings.Contains(path, "/secrets") || strings.Contains(path, "/authz") {
		return "REDACTED"
	}
	return ""
}

// latencyBucketKey 返回延迟桶计数 key。
func latencyBucketKey(d time.Duration) string {
	ms := d.Milliseconds()
	switch {
	case ms <= 50:
		return "latency_bucket_le_50ms"
	case ms <= 100:
		return "latency_bucket_le_100ms"
	case ms <= 200:
		return "latency_bucket_le_200ms"
	case ms <= 500:
		return "latency_bucket_le_500ms"
	case ms <= 1000:
		return "latency_bucket_le_1000ms"
	default:
		return "latency_bucket_gt_1000ms"
	}
}

// statusRecorder 记录返回状态码，便于统计。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader 记录状态码后再调用底层 ResponseWriter。
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
