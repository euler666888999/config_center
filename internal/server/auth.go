package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"config_center/internal/abac"
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
		// ABAC 条件匹配
		reqCtx := abac.Request{
			Actor:     actor,
			Namespace: namespace,
			Resource:  name,
			Action:    action,
			Labels:    map[string]string{},
			Attrs:     map[string]string{},
		}
		if !abac.Condition(toStringMap(p.Conditions)).Match(reqCtx) {
			continue
		}

		// 配额控制（若设置）
		if p.Quota > 0 && s.quota != nil {
			key := fmt.Sprintf("%s|%s|%s|%s|%s", p.Namespace, name, action, p.Name, actor)
			if !s.quota.allow(key, p.Quota) {
				return errors.New("超出策略配额限制")
			}
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

func toStringMap(m map[string]any) map[string]string {
	res := make(map[string]string, len(m))
	for k, v := range m {
		if str, ok := v.(string); ok {
			res[k] = str
		}
	}
	return res
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

// authenticate 校验身份，优先使用 mTLS 证书，其次使用 Authorization Bearer (OIDC/Static) 或 X-Actor。
func (s *Server) authenticate(r *http.Request) (string, error) {
	// 清理限流/幂等缓存，防止长期占用
	if s.rateLimiter != nil && time.Since(s.rateLimiter.lastSweep) > time.Minute {
		s.rateLimiter.cleanup()
		s.rateLimiter.lastSweep = time.Now()
	}
	if s.idemStore != nil && time.Since(s.idemStore.lastSweep) > time.Minute {
		s.idemStore.cleanup()
		s.idemStore.lastSweep = time.Now()
	}
	if s.quota != nil && time.Since(s.quota.lastSweep) > time.Minute {
		s.quota.cleanup()
		s.quota.lastSweep = time.Now()
	}

	var actor string
	// 1. mTLS 证书优先
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
		actor = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	// 2. 开发/调试用的 X-Actor 头 (仅非生产环境或特定配置下允许，此处保留逻辑但建议生产禁用)
	if actor == "" {
		actor = r.Header.Get("X-Actor")
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := ""
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		tokenString = strings.TrimSpace(authHeader[7:])
	}

	// 3. Bearer Token 校验
	if tokenString != "" {
		// 3.1 静态 Token 校验 (兼容旧逻辑)
		if s.cfg.BearerToken != "" && tokenString == s.cfg.BearerToken {
			// 静态 Token 验证通过，若 actor 为空则标记为 system 或保留 unknown
			if actor == "" {
				actor = "system-static"
			}
		} else {
			// 3.2 OIDC JWT 校验
			if s.cfg.OIDCPublicKey != "" || s.cfg.OIDCJWKSURL != "" {
				sub, err := s.verifyOIDCToken(tokenString)
				if err != nil {
					return "", fmt.Errorf("OIDC 校验失败: %v", err)
				}
				if sub != "" && actor == "" {
					actor = sub
				}
			} else if s.cfg.BearerToken != "" {
				return "", errors.New("无效的 Token")
			}
		}
	} else if s.cfg.BearerToken != "" || s.cfg.OIDCPublicKey != "" || s.cfg.OIDCJWKSURL != "" {
		// 配置了 Token 校验但未携带，若没有 mTLS 则拒绝
		if actor == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return "", errors.New("缺少 Bearer Token")
		}
	}

	// 强制客户端证书
	if s.cfg.RequireClientCert && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		return "", errors.New("缺少有效客户端证书")
	}

	if actor == "" {
		actor = "unknown"
	}
	// 简单限流，按主体+IP
	key := actor
	if key == "" {
		key = clientIP(r)
	}
	if s.rateLimiter != nil && !s.rateLimiter.allow(key) {
		return "", errors.New("请求过于频繁")
	}
	return actor, nil
}
