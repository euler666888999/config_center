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
func (s *Server) authorize(ctx context.Context, namespace, name, action, actor string, labels map[string]string) error {
	// 引导主体兜底：开发/引导场景，若命中引导主体则放行（避免因配置未加载导致阻塞）。
	if (s.cfg.BootstrapEnabled || s.cfg.AllowInsecureActor) && matchSubject(s.cfg.BootstrapSubjects, actor) {
		s.incMetric("authz_bootstrap_allow", 1)
		return nil
	}
	// 开发兜底：显式允许不安全 Actor 时，给 admin 兜底放行（防止缺省引导主体未加载）。
	if s.cfg.AllowInsecureActor && actor == "admin" {
		s.incMetric("authz_insecure_admin_allow", 1)
		return nil
	}
	if namespace != "" && labels != nil {
		if tenant, ok := labels["tenant"]; ok && tenant != "" && tenant != namespace {
			return errors.New("跨租户访问被拒绝")
		}
	}
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
		if !p.Approved || p.ApprovalState != "approved" {
			continue
		}
		// 全局策略必须匹配租户标签，防止跨租户冒用
		if p.Namespace == "" && labels != nil {
			if tenantLabel, ok := labels["tenant"]; ok {
				if condTenant, ok2 := p.Conditions["tenant"]; ok2 {
					if fmt.Sprint(condTenant) != tenantLabel {
						continue
					}
				} else {
					continue
				}
			}
		}
		// ABAC 条件匹配
		attrs := map[string]string{
			"namespace": namespace,
			"actor":     actor,
			"action":    action,
		}
		if labels != nil {
			if tenant, ok := labels["tenant"]; ok {
				attrs["tenant"] = tenant
			}
		}
		reqCtx := abac.Request{
			Actor:     actor,
			Namespace: namespace,
			Resource:  name,
			Action:    action,
			Labels:    labels,
			Attrs:     attrs,
		}
		if !abac.Condition(toStringMap(p.Conditions)).Match(reqCtx) {
			continue
		}

		// 配额控制（若设置），使用持久化存储，窗口默认 cfg.QuotaWindowSecs
		if p.Quota > 0 {
			window := time.Duration(s.cfg.QuotaWindowSecs) * time.Second
			allowed, err := s.store.UpdateQuota(ctx, p.ID, actor, namespace, name, action, p.Quota, window)
			if err != nil {
				return fmt.Errorf("配额检查失败: %w", err)
			}
			if !allowed {
				return errors.New("超出策略配额限制")
			}
		}

		if p.Effect == "deny" {
			return errors.New("访问被策略拒绝")
		}
		allowed = true
	}
	if !allowed {
		s.incMetric("authz_deny", 1)
		return errors.New("无访问权限，请检查策略配置")
	}
	s.incMetric("authz_allow", 1)
	return nil
}

// matchSubject 判断主体是否命中策略主体或通配符。
func matchSubject(subjects []string, actor string) bool {
	for _, s := range subjects {
		if s == "*" || s == actor {
			return true
		}
	}
	return false
}

// matchAction 判断请求动作是否命中策略动作或通配符。
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

// toStringMap 将任意类型的条件值转换为字符串 map。
func toStringMap(m map[string]any) map[string]string {
	res := make(map[string]string, len(m))
	for k, v := range m {
		if str, ok := v.(string); ok {
			res[k] = str
		}
	}
	return res
}

// detectPolicyConflict 检测策略是否与已存在的策略冲突（主体/资源/动作重叠且 effect 不同或版本冲突）。
func detectPolicyConflict(newP *model.Policy, existing []*model.Policy) error {
	for _, p := range existing {
		if newP.ID != 0 && p.ID == newP.ID {
			continue
		}
		if p.Namespace != newP.Namespace {
			continue
		}
		if p.Name == newP.Name {
			return fmt.Errorf("同名策略已存在")
		}
		if !p.Approved {
			continue
		}
		if overlap(p.Subjects, newP.Subjects) && overlap(p.Resources, newP.Resources) && overlap(p.Actions, newP.Actions) {
			if p.Effect != newP.Effect {
				return fmt.Errorf("策略冲突：%s(%s) 与 %s(%s) 在相同主体/资源/动作上效果不同", p.Name, p.Effect, newP.Name, newP.Effect)
			}
			if p.Version >= newP.Version {
				return fmt.Errorf("策略版本冲突：现有版本 %d，请提升版本并重新审批", p.Version)
			}
		}
	}
	return nil
}

// overlap 判断两个字符串切片是否存在通配符或相同值的交集。
func overlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == "*" || y == "*" || strings.EqualFold(x, y) {
				return true
			}
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

	var actor string
	// 1. mTLS 证书优先
	if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.PeerCertificates) > 0 {
		actor = r.TLS.PeerCertificates[0].Subject.CommonName
	}
	// 2. 开发/调试用的 X-Actor 头（需显式允许）
	if actor == "" && s.cfg.AllowInsecureActor {
		actor = r.Header.Get("X-Actor")
	}

	authHeader := r.Header.Get("Authorization")
	tokenString := ""
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		tokenString = strings.TrimSpace(authHeader[7:])
	}
	client := clientIP(r)

	// 强制 TLS（除非显式放宽）
	if !s.cfg.AllowInsecureHTTP && r.TLS == nil {
		s.incMetric("auth_tls_required", 1)
		return "", errors.New("必须使用 HTTPS/mTLS")
	}

	// IP 黑白名单
	if len(s.cfg.IPBlocklist) > 0 {
		for _, ip := range s.cfg.IPBlocklist {
			if client == ip {
				s.incMetric("auth_ip_block", 1)
				return "", errors.New("IP 被拒绝访问")
			}
		}
	}
	if len(s.cfg.IPAllowlist) > 0 {
		allowed := false
		for _, ip := range s.cfg.IPAllowlist {
			if client == ip {
				allowed = true
				break
			}
		}
		if !allowed {
			s.incMetric("auth_ip_deny", 1)
			return "", errors.New("IP 不在允许列表")
		}
	}

	// 防爆破
	if s.bruteGuard != nil && !s.bruteGuard.allow(client) {
		s.incMetric("auth_brute_block", 1)
		return "", errors.New("尝试过于频繁，已暂时封禁")
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
					s.incMetric("auth_fail", 1)
					return "", fmt.Errorf("OIDC 校验失败: %v", err)
				}
				if sub != "" && actor == "" {
					actor = sub
				}
			} else if s.cfg.BearerToken != "" {
				s.incMetric("auth_fail", 1)
				return "", errors.New("无效的 Token")
			}
		}
	} else if s.cfg.BearerToken != "" || s.cfg.OIDCPublicKey != "" || s.cfg.OIDCJWKSURL != "" {
		// 配置了 Token 校验但未携带，若没有 mTLS 则拒绝
		if actor == "" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			s.incMetric("auth_fail", 1)
			return "", errors.New("缺少 Bearer Token")
		}
	}

	// 强制客户端证书
	if s.cfg.RequireClientCert && (r.TLS == nil || len(r.TLS.VerifiedChains) == 0) {
		s.incMetric("auth_fail", 1)
		return "", errors.New("缺少有效客户端证书")
	}

	if actor == "" {
		s.incMetric("auth_fail", 1)
		return "", errors.New("缺少有效身份，请使用 mTLS 或 Bearer/OIDC")
	}
	// 简单限流，按主体+IP
	key := actor
	if key == "" {
		key = client
	}
	if s.rateLimiter != nil && !s.rateLimiter.allow(key) {
		s.incMetric("auth_ratelimit_block", 1)
		return "", errors.New("请求过于频繁")
	}
	if s.bruteGuard != nil {
		s.bruteGuard.reset(client)
	}
	s.incMetric("auth_success", 1)
	return actor, nil
}
