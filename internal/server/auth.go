package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"config_center/internal/model"
)

// authorize 按策略检查主体是否有权限访问资源，默认拒绝。
func (s *Server) authorize(ctx context.Context, namespace, name, action, actor string) error {
	// 默认拒绝，必须命中策略
	allPolicies, err := s.store.ListPolicies(ctx, "")
	if err != nil {
		return fmt.Errorf("读取策略失败: %w", err)
	}

	nsPolicies, err := s.store.ListPolicies(ctx, namespace)
	if err != nil {
		return fmt.Errorf("读取策略失败: %w", err)
	}
	policies := append(allPolicies, nsPolicies...)

	allowed := false
	for _, p := range policies {
		if !matchSubject(p.Subjects, actor) {
			continue
		}
		if !matchAction(p.Actions, action) {
			continue
		}
		if !matchResource(p.Resources, name) {
			continue
		}
		if p.Effect == "deny" {
			return errors.New("访问被策略拒绝")
		}
		allowed = true
	}
	if !allowed {
		return errors.New("无访问权限，请检查策略配置")
	}
	return nil
}

func matchSubject(subjects []string, actor string) bool {
	for _, s := range subjects {
		if s == "*" || s == actor {
			return true
		}
	}
	return false
}

func matchAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == "*" || strings.EqualFold(a, action) {
			return true
		}
	}
	return false
}

// matchResource 支持 "secrets/*"、"secrets/{name}"、"*"。
func matchResource(resources []string, name string) bool {
	target := "secrets/" + name
	for _, r := range resources {
		if r == "*" || r == "secrets/*" || r == target {
			return true
		}
	}
	return false
}

// seedBootstrapPolicy 当策略为空且指定了 Bootstrap 主体时写入一条全权限策略。
func (s *Server) seedBootstrapPolicy(ctx context.Context) {
	all, err := s.store.ListPolicies(ctx, "")
	if err != nil {
		return
	}
	if len(all) > 0 || len(s.cfg.BootstrapSubjects) == 0 {
		return
	}
	p := &model.Policy{
		Name:       "bootstrap-admin",
		Namespace:  "",
		Subjects:   s.cfg.BootstrapSubjects,
		Resources:  []string{"*"},
		Actions:    []string{"*"},
		Effect:     "allow",
		Conditions: map[string]any{"bootstrap": time.Now().Format(time.RFC3339)},
		CreatedBy:  "system",
	}
	if _, err := s.store.AddPolicy(ctx, p); err != nil {
		return
	}
}

// authenticate 校验身份，优先使用 mTLS 证书，其次使用 Authorization Bearer 或 X-Actor。
func (s *Server) authenticate(r *http.Request) (string, error) {
	var actor string
	// mTLS 证书优先
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
		actor = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	if actor == "" {
		actor = r.Header.Get("X-Actor")
	}
	authHeader := r.Header.Get("Authorization")
	token := ""
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		token = strings.TrimSpace(authHeader[7:])
	}

	// Bearer Token 校验（如果配置）
	if s.cfg.BearerToken != "" && token != s.cfg.BearerToken {
		// 若有 mTLS 已校验通过，可放行；否则要求 token
		if actor == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return "", errors.New("缺少或无效的 Bearer Token")
		}
	}

	// 强制客户端证书
	if s.cfg.RequireClientCert && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		return "", errors.New("缺少有效客户端证书")
	}

	if actor == "" {
		actor = "unknown"
	}
	return actor, nil
}
