//go:build e2e_mysql

package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/model"
	"config_center/internal/server"
	"config_center/internal/store"
)

// MySQL E2E：需要环境变量 E2E_MYSQL_DSN，并预置 mysql:8.0 服务。
func TestMySQLCRUD(t *testing.T) {
	dsn := os.Getenv("E2E_MYSQL_DSN")
	if dsn == "" {
		t.Skip("E2E_MYSQL_DSN 未配置，跳过 MySQL E2E")
	}
	schema, err := os.ReadFile("databases/config_center_schema.sql")
	if err != nil {
		t.Fatalf("读取 schema 失败: %v", err)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("连接 MySQL 失败: %v", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("执行 schema 失败: %v", err)
	}
	_ = db.Close()

	cfg := config.Config{
		Addr:               ":0",
		DBDriver:           "mysql",
		MySQLDSN:           dsn,
		BearerToken:        "test-token",
		AllowInsecureHTTP:  true,
		AllowInsecureActor: true,
		KMSProvider:        "local",
		AllowLocalKMS:      true,
	}
	st, err := store.NewMySQLStore(dsn)
	if err != nil {
		t.Fatalf("init mysql store: %v", err)
	}
	defer st.Close()

	if err := st.CreateNamespace(context.Background(), "e2e-mysql", "e2e"); err != nil {
		t.Fatalf("create ns: %v", err)
	}
	_, _ = st.AddPolicy(context.Background(), &model.Policy{
		Name:      "mysql-admin",
		Namespace: "e2e-mysql",
		Subjects:  []string{"admin"},
		Resources: []string{"secrets/*"},
		Actions:   []string{"*"},
		Effect:    "allow",
		Approved:  true,
	})

	baseKMS, err := kms.NewLocalKMS("MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=")
	if err != nil {
		t.Fatalf("init kms: %v", err)
	}
	k := kms.NewCachedKMS(baseKMS)
	s := server.NewServer(st, cfg, k)
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

	resp := postJSON("/v1/namespaces/e2e-mysql/secrets", `{"name":"db-pass","plaintext":"secret123","key_id":"k1","status":"active"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create secret status=%d body=%s", resp.StatusCode, string(b))
	}
	resp.Body.Close()
	resp = postJSON("/v1/namespaces/e2e-mysql/secrets/db-pass:get", `{}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("get secret status=%d body=%s", resp.StatusCode, string(b))
	}
	resp.Body.Close()
}
