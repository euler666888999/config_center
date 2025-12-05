package server

import (
	"fmt"
	"net/http"
	"strings"
)

// handleMetrics 暴露简易指标，便于监控。
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	metrics := map[string]any{
		"store":  s.store.Metrics(),
		"kms":    s.kms.Metrics(),
		"server": s.metricsSnapshot(),
	}
	respondJSON(w, http.StatusOK, metrics)
}

// handleMetricsProm 以 Prometheus 文本暴露指标。
func (s *Server) handleMetricsProm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	serverMetrics := s.metricsSnapshot()
	for k, v := range serverMetrics {
		if strings.HasPrefix(k, "status_") {
			code := strings.TrimPrefix(k, "status_")
			fmt.Fprintf(w, "config_center_http_requests_total{code=\"%s\"} %d\n", code, v)
		}
		if strings.HasPrefix(k, "latency_bucket_") {
			bucket := strings.TrimPrefix(k, "latency_bucket_")
			fmt.Fprintf(w, "config_center_latency_bucket_total{le=\"%s\"} %d\n", bucket, v)
		}
	}
	writeGauge := func(name string, labels string, value int64) {
		fmt.Fprintf(w, "%s%s %d\n", name, labels, value)
	}
	if v, ok := serverMetrics["requests_total"]; ok {
		writeGauge("config_center_requests_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["requests_failed"]; ok {
		writeGauge("config_center_requests_failed_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["latency_ms_total"]; ok {
		writeGauge("config_center_latency_ms_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["auth_success"]; ok {
		writeGauge("config_center_auth_success_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["auth_fail"]; ok {
		writeGauge("config_center_auth_fail_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["authz_deny"]; ok {
		writeGauge("config_center_authz_deny_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["auth_ip_deny"]; ok {
		writeGauge("config_center_ip_deny_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["auth_brute_block"]; ok {
		writeGauge("config_center_bruteforce_block_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["auth_ratelimit_block"]; ok {
		writeGauge("config_center_ratelimit_block_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["kms_rotate_fail"]; ok {
		writeGauge("config_center_kms_rotate_fail_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["kms_rotate_success"]; ok {
		writeGauge("config_center_kms_rotate_success_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["kms_rewrap_fail"]; ok {
		writeGauge("config_center_kms_rewrap_fail_total", "{component=\"server\"}", v)
	}
	if v, ok := serverMetrics["kms_rewrap_success"]; ok {
		writeGauge("config_center_kms_rewrap_success_total", "{component=\"server\"}", v)
	}

	for k, v := range s.store.Metrics() {
		writeGauge("config_center_store_metric", fmt.Sprintf("{key=\"%s\"}", k), v)
	}
	for k, v := range s.kms.Metrics() {
		writeGauge("config_center_kms_metric", fmt.Sprintf("{key=\"%s\"}", k), v)
	}
}
