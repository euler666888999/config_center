package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/model"
	"config_center/internal/server"
	"config_center/internal/store"
)

// 迷你 E2E：使用内存存储 + local KMS，覆盖 CRUD/轮换/授权拒绝基本流程。
func TestCRUDRotateWatch(t *testing.T) {
	cfg := config.Config{
		Addr:                ":0",
		DBDriver:            "memory",
		BearerToken:         "test-token",
		AllowInsecureHTTP:   true,
		AllowInsecureActor:  true,
		KMSProvider:         "local",
		AllowLocalKMS:       true,
		BootstrapEnabled:    true,
		BootstrapNamespace:  "test-ns",
		BootstrapNamespaces: []string{"test-ns"},
		BootstrapSubjects:   []string{"admin"},
	}
	mem := store.NewMemoryStore()
	if err := mem.CreateNamespace(context.Background(), "test-ns", "e2e"); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	baseKMS, err := kms.NewLocalKMS("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	if err != nil {
		t.Fatalf("init kms: %v", err)
	}
	k := kms.NewCachedKMS(baseKMS)
	s := server.NewServer(mem, cfg, k)
	// 手动添加允许 admin 管理 test-ns 的策略
	_, _ = mem.AddPolicy(context.Background(), &model.Policy{
		Name:      "e2e-admin",
		Namespace: "test-ns",
		Subjects:  []string{"admin"},
		Resources: []string{"secrets/*"},
		Actions:   []string{"*"},
		Effect:    "allow",
		Approved:  true,
	})
	s.Init(context.Background())
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	authHeader := "Bearer test-token"

	postJSON := func(path string, body string) *http.Response {
		req, _ := http.NewRequest("POST", ts.URL+path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("X-Actor", "admin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %s err: %v", path, err)
		}
		return resp
	}

	// Create secret active
	resp := postJSON("/v1/namespaces/test-ns/secrets", `{"name":"db-pass","plaintext":"secret123","key_id":"k1","status":"active"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create secret status=%d body=%s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// Get secret
	resp = postJSON("/v1/namespaces/test-ns/secrets/db-pass:get", `{}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("get secret status=%d body=%s", resp.StatusCode, string(b))
	}
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got["plaintext"] != "secret123" {
		t.Fatalf("plaintext mismatch: %v", got["plaintext"])
	}

	// Rotate to staged
	resp = postJSON("/v1/namespaces/test-ns/secrets/db-pass:rotate", `{"plaintext":"secret456"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("rotate secret status=%d body=%s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// Activate new version (v2)
	resp = postJSON("/v1/namespaces/test-ns/secrets/db-pass/versions/2:activate", `{}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("activate status=%d body=%s", resp.StatusCode, string(b))
	}
	resp.Body.Close()

	// Watch endpoint should report active version 2
	resp = postJSON("/v1/namespaces/test-ns/secrets/db-pass:watch", `{}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("watch status=%d body=%s", resp.StatusCode, string(b))
	}
	var watch map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&watch)
	resp.Body.Close()
	if v, ok := watch["version"].(float64); !ok || int(v) != 2 {
		t.Fatalf("watch version mismatch: %v", watch["version"])
	}

	// Authorization deny: missing token
	req, _ := http.NewRequest("POST", ts.URL+"/v1/namespaces/test-ns/secrets/db-pass:get", bytes.NewBufferString(`{}`))
	req.Header.Set("X-Actor", "admin")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request no token err: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected auth failure, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
