package server

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/model"
	"config_center/internal/store"
)

// Server 聚合路由与存储。
type Server struct {
	store       store.Store
	cfg         config.Config
	kms         kms.KMS
	watcher     *Watcher
	jwks        *jwksCache
	oidcPub     *rsa.PublicKey
	rateLimiter *rateLimiter
	idemStore   *idempotencyStore
	bruteGuard  *bruteForceGuard
	metricsMu   sync.Mutex
	metrics     map[string]int64
	kmsTicker   *time.Ticker
}

// NewServer 创建服务器实例。
func NewServer(store store.Store, cfg config.Config, kms kms.KMS) *Server {
	s := &Server{
		store:       store,
		cfg:         cfg,
		kms:         kms,
		watcher:     NewWatcher(),
		rateLimiter: newRateLimiter(20, 50, time.Minute*5),
		idemStore:   newIdempotencyStore(time.Minute * 10),
		bruteGuard:  newBruteForceGuard(cfg.BruteForceThresh, time.Duration(cfg.BruteForceBlock)*time.Second),
		metrics:     make(map[string]int64),
	}
	if cfg.OIDCJWKSURL != "" {
		s.jwks = newJWKSCache(cfg.OIDCJWKSURL)
	}
	if cfg.OIDCPublicKey != "" {
		key, err := parsePEMPublicKey(cfg.OIDCPublicKey)
		if err != nil {
			panic(fmt.Sprintf("解析 OIDC_PUBLIC_KEY 失败: %v", err))
		}
		s.oidcPub = key
	}
	if cfg.CertReloadSecs > 0 {
		// 证书热更由 main 中的 CertReloader 完成，此处不再重复启动
	}
	if cfg.QuotaResetSecs > 0 {
		go s.quotaResetLoop(time.Duration(cfg.QuotaResetSecs) * time.Second)
	}
	if cfg.KMSRotateHours > 0 {
		s.kmsTicker = time.NewTicker(time.Duration(cfg.KMSRotateHours) * time.Hour)
		go s.kmsRotateLoop()
	}
	return s
}

// Router 返回注册好路由的 mux。
func (s *Server) Router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/metrics/prom", s.handleMetricsProm)
	mux.HandleFunc("/v1/audit/query", s.handleAuditQuery)
	mux.HandleFunc("/v1/audit/verify", s.handleAuditVerify)
	mux.HandleFunc("/v1/authz/policies", s.handlePolicies)
	mux.HandleFunc("/v1/admin/namespaces", s.handleNamespaceAdmin)
	mux.HandleFunc("/v1/admin/rewrap", s.handleRewrap)
	mux.HandleFunc("/v1/namespaces/", s.handleNamespaces)
	// 外层包装日志中间件
	logMux := http.NewServeMux()
	logMux.Handle("/", s.loggingMiddleware(mux))
	return logMux
}

// Init 执行启动时的引导操作（如注入初始策略）。
func (s *Server) Init(ctx context.Context) {
	if !s.cfg.BootstrapEnabled {
		return
	}
	hasPolicy, err := s.store.HasPolicies(ctx)
	if err != nil || hasPolicy {
		return
	}
	nsSet := make(map[string]struct{})
	if s.cfg.BootstrapNamespace != "" {
		nsSet[s.cfg.BootstrapNamespace] = struct{}{}
	}
	for _, ns := range s.cfg.BootstrapNamespaces {
		if ns != "" {
			nsSet[ns] = struct{}{}
		}
	}
	for ns := range nsSet {
		_ = s.store.CreateNamespace(ctx, ns, "bootstrap")
	}
	p := &model.Policy{
		Name:              "bootstrap-admin",
		Namespace:         "",
		Subjects:          s.cfg.BootstrapSubjects,
		Resources:         []string{"*"},
		Actions:           []string{"*"},
		Effect:            "allow",
		Conditions:        map[string]any{"bootstrap": time.Now().Format(time.RFC3339)},
		CreatedBy:         "system",
		CreatedAt:         time.Now(),
		RequiredApprovals: 1,
		Approved:          true,
		ApprovalState:     "approved",
		ApprovedSteps:     1,
	}
	_, _ = s.store.AddPolicy(ctx, p)
}

// handleHealthz 健康探针。
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz 检查依赖（DB、KMS）。
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	ctx := r.Context()
	if _, err := s.store.ListPolicies(ctx, ""); err != nil {
		respondError(w, http.StatusServiceUnavailable, "存储不可用")
		return
	}
	if s.kms == nil {
		respondError(w, http.StatusServiceUnavailable, "KMS 未初始化")
		return
	}
	if err := s.store.Ping(ctx); err != nil {
		respondError(w, http.StatusServiceUnavailable, "存储不可用")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleNamespaces 路由所有命名空间相关接口。
func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// 预期格式：/v1/namespaces/{ns}/secrets...
	if len(segments) < 4 || segments[0] != "v1" || segments[1] != "namespaces" || segments[3] != "secrets" {
		respondError(w, http.StatusNotFound, "路径不匹配，检查命名空间与资源名称")
		return
	}
	namespace := segments[2]
	exists, err := s.store.NamespaceExists(r.Context(), namespace)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("校验命名空间失败: %v", err))
		return
	}
	if !exists {
		respondError(w, http.StatusForbidden, "命名空间不存在或未授权")
		return
	}

	// 创建密钥：/v1/namespaces/{ns}/secrets
	if len(segments) == 4 {
		ctx := context.WithValue(r.Context(), ctxActorKey{}, actor)
		if isListIntent(r) {
			s.handleListSecrets(w, r.WithContext(ctx), namespace)
			return
		}
		s.handleCreateSecret(w, r.WithContext(ctx), namespace)
		return
	}

	// 后续段落处理 /secrets/{name}...
	nameSegment := segments[4]
	switch {
	case strings.HasSuffix(nameSegment, ":get"):
		name := strings.TrimSuffix(nameSegment, ":get")
		s.handleGetSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
		return
	case strings.HasSuffix(nameSegment, ":rotate"):
		name := strings.TrimSuffix(nameSegment, ":rotate")
		if ok, cached := s.checkIdempotency(r, actor, namespace, "rotate:"+name); !ok {
			if cached != nil {
				respondJSON(w, http.StatusOK, cached)
			} else {
				respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
			}
			return
		}
		s.handleRotateSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
		return
	case strings.HasSuffix(nameSegment, ":watch"):
		name := strings.TrimSuffix(nameSegment, ":watch")
		s.handleWatchSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
		return
	case strings.HasSuffix(nameSegment, ":sse"):
		name := strings.TrimSuffix(nameSegment, ":sse")
		s.handleWatchSSE(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
		return
	}

	// 激活版本：/v1/namespaces/{ns}/secrets/{name}/versions/{v}:activate
	if len(segments) == 7 && segments[5] == "versions" && strings.HasSuffix(segments[6], ":activate") {
		name := segments[4]
		versionStr := strings.TrimSuffix(segments[6], ":activate")
		version, err := strconv.Atoi(versionStr)
		if err != nil || version <= 0 {
			respondError(w, http.StatusBadRequest, "版本号必须为正整数")
			return
		}
		if ok, cached := s.checkIdempotency(r, actor, namespace, fmt.Sprintf("activate:%s:%d", name, version)); !ok {
			if cached != nil {
				respondJSON(w, http.StatusOK, cached)
			} else {
				respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
			}
			return
		}
		s.handleActivateVersion(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name, version)
		return
	}

	respondError(w, http.StatusNotFound, "未找到匹配的接口")
}

// isListIntent 根据请求体判断是否为列表查询，默认空体/空 name/action=list 视为列表。
func isListIntent(r *http.Request) bool {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return true
	}
	defer func() { r.Body = io.NopCloser(bytes.NewBuffer(data)) }()
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("{}")) {
		return true
	}
	var probe struct {
		Action string `json:"action"`
		Name   string `json:"name"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if strings.ToLower(probe.Action) == "list" {
		return true
	}
	return probe.Name == ""
}

// handleCreateSecret 创建或更新密钥版本，支持幂等与自动加密。
func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, namespace string) {
	ctx := r.Context()
	var req model.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	if req.Plaintext == "" && req.Ciphertext == "" {
		respondError(w, http.StatusBadRequest, "name/plaintext 或 ciphertext/key_id 必填")
		return
	}
	if !validateSecretCreate(w, &req) {
		return
	}
	status := req.Status
	if status == "" {
		status = "staged"
	}
	if !isValidStatus(status) {
		respondError(w, http.StatusBadRequest, "状态不合法，需为 staged/active/deprecated/disabled")
		return
	}
	now := time.Now()
	var expirePtr *time.Time
	if req.ExpireAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpireAt)
		if err != nil {
			respondError(w, http.StatusBadRequest, "expire_at 需为 RFC3339 格式")
			return
		}
		expirePtr = &t
	}
	actor := getActor(r)

	if err := s.authorize(ctx, namespace, req.Name, "write", actor, req.Labels); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	// 幂等校验
	if ok, cached := s.checkIdempotency(r, actor, namespace, "create:"+req.Name); !ok {
		if cached != nil {
			respondJSON(w, http.StatusOK, cached)
		} else {
			respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
		}
		return
	}

	// 加密明文，禁止直接落盘
	ciphertext := req.Ciphertext
	if req.Plaintext != "" {
		enc, err := s.kms.Encrypt([]byte(req.Plaintext))
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("加密失败: %v", err))
			return
		}
		ciphertext = enc
	}

	sv := &model.SecretVersion{
		Namespace:  namespace,
		Name:       req.Name,
		Ciphertext: ciphertext,
		KeyID:      req.KeyID,
		Labels:     req.Labels,
		Status:     status,
		ExpireAt:   expirePtr,
		CreatedBy:  actor,
		UpdatedBy:  actor,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	version, err := s.store.AppendSecretVersion(ctx, sv)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("创建密钥失败: %v", err))
		return
	}
	s.recordAudit(ctx, r, &model.AuditLog{
		Namespace: namespace,
		Name:      req.Name,
		Action:    "write",
		Actor:     actor,
		ClientIP:  clientIP(r),
		Version:   version,
		Result:    "success",
		Detail:    "创建/更新密钥",
		CreatedAt: now,
	})

	resp := map[string]any{
		"name":    req.Name,
		"version": version,
		"status":  status,
	}
	_ = s.store.SaveIdempotencyResponse(ctx, namespace+"|"+"create:"+req.Name, r.Header.Get("Idempotency-Key"), resp)
	respondJSON(w, http.StatusOK, resp)
	// 如果直接创建为 active，通知监听者
	if status == "active" {
		s.watcher.Notify(namespace, req.Name, version)
	}
}

// handleListSecrets 列出指定命名空间下的所有密钥。
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request, namespace string) {
	ctx := r.Context()
	actor := getActor(r)
	// 列表权限校验：需要 list 权限
	if err := s.authorize(ctx, namespace, "*", "list", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	names, err := s.store.ListSecrets(ctx, namespace)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询密钥列表失败: %v", err))
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"namespace": namespace,
		"secrets":   names,
		"total":     len(names),
	})
}

// handleRewrap 重新包裹指定密钥版本，生成新的版本密文。
func (s *Server) handleRewrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !s.cfg.AllowAdminRewrap {
		respondError(w, http.StatusForbidden, "未开启 ALLOW_ADMIN_REWRAP，生产默认关闭，请在受控窗口与审批后启用")
		return
	}
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := context.WithValue(r.Context(), ctxActorKey{}, actor)
	var req struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Version   int    `json:"version"` // 可选，默认最新
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Namespace == "" || req.Name == "" {
		respondError(w, http.StatusBadRequest, "namespace/name 必填，version 可选")
		return
	}
	ticket := r.Header.Get("X-Ticket-ID")
	if ticket == "" {
		ticket = r.URL.Query().Get("ticket_id")
	}
	if ticket == "" {
		respondError(w, http.StatusBadRequest, "重包裹需要提供工单/审批号（Header: X-Ticket-ID 或 ?ticket_id）")
		return
	}
	if err := s.authorize(ctx, req.Namespace, req.Name, "manage", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	if ok, cached := s.checkIdempotency(r, actor, req.Namespace, "rewrap:"+req.Name); !ok {
		if cached != nil {
			respondJSON(w, http.StatusOK, cached)
		} else {
			respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
		}
		return
	}
	var target *model.SecretVersion
	if req.Version > 0 {
		target, err = s.store.FindByVersion(ctx, req.Namespace, req.Name, req.Version)
	} else {
		target, err = s.store.Latest(ctx, req.Namespace, req.Name)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取版本失败: %v", err))
		return
	}
	if target == nil {
		respondError(w, http.StatusNotFound, "未找到指定版本")
		return
	}
	plain, err := s.kms.Decrypt(target.Ciphertext)
	if err != nil {
		s.incMetric("kms_rewrap_fail", 1)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("解密失败: %v", err))
		return
	}
	newCipher, err := s.kms.Encrypt(plain)
	if err != nil {
		s.incMetric("kms_rewrap_fail", 1)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("加密失败: %v", err))
		return
	}
	now := time.Now()
	newVersion := &model.SecretVersion{
		Namespace:  target.Namespace,
		Name:       target.Name,
		Ciphertext: newCipher,
		KeyID:      target.KeyID,
		Labels:     target.Labels,
		Status:     target.Status,
		ExpireAt:   target.ExpireAt,
		CreatedBy:  actor,
		UpdatedBy:  actor,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	versionNum, err := s.store.AppendSecretVersion(ctx, newVersion)
	if err != nil {
		s.incMetric("kms_rewrap_fail", 1)
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("写入新版本失败: %v", err))
		return
	}
	s.incMetric("kms_rewrap_success", 1)
	s.recordAudit(ctx, r, &model.AuditLog{
		Namespace: req.Namespace,
		Name:      req.Name,
		Action:    "rotate",
		Actor:     actor,
		ClientIP:  clientIP(r),
		Version:   versionNum,
		Result:    "success",
		Detail:    fmt.Sprintf("rewrap from version %d ticket=%s", target.Version, ticket),
		CreatedAt: now,
	})
	resp := map[string]any{
		"name":          req.Name,
		"old_version":   target.Version,
		"new_version":   versionNum,
		"status":        target.Status,
		"rewrap_key_id": target.KeyID,
	}
	respondJSON(w, http.StatusOK, resp)
	s.watcher.Notify(req.Namespace, req.Name, versionNum)
}

// handleGetSecret 读取指定命名空间的密钥，支持按版本或 active/staged 回退。
func (s *Server) handleGetSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	var body struct {
		Version int `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	actor := getActor(r)
	var target *model.SecretVersion
	var err error
	if body.Version > 0 {
		target, err = s.store.FindByVersion(ctx, namespace, name, body.Version)
	} else {
		target, err = s.store.FindActive(ctx, namespace, name)
		if target == nil {
			target, err = s.store.Latest(ctx, namespace, name)
		}
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询失败: %v", err))
		return
	}
	if target == nil {
		respondError(w, http.StatusNotFound, "未找到对应版本")
		return
	}
	if err := s.authorize(ctx, namespace, name, "read", actor, target.Labels); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	if target.Status == "disabled" {
		respondError(w, http.StatusForbidden, "该密钥已被禁用")
		return
	}
	if target.ExpireAt != nil && time.Now().After(*target.ExpireAt) {
		respondError(w, http.StatusGone, "该密钥已过期")
		return
	}

	plaintext, err := s.kms.Decrypt(target.Ciphertext)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("解密失败: %v", err))
		return
	}

	s.recordAudit(ctx, r, &model.AuditLog{
		Namespace: namespace,
		Name:      name,
		Action:    "read",
		Actor:     actor,
		ClientIP:  clientIP(r),
		Version:   target.Version,
		Result:    "success",
		Detail:    "读取密钥",
		CreatedAt: time.Now(),
	})

	respondJSON(w, http.StatusOK, map[string]any{
		"name":      target.Name,
		"version":   target.Version,
		"key_id":    target.KeyID,
		"status":    target.Status,
		"labels":    target.Labels,
		"expire_at": target.ExpireAt,
		"plaintext": string(plaintext),
	})
}

// handleActivateVersion 将指定版本标记为 active，并触发幂等与通知。
func (s *Server) handleActivateVersion(w http.ResponseWriter, r *http.Request, namespace, name string, version int) {
	ctx := r.Context()
	actor := getActor(r)
	if err := s.authorize(ctx, namespace, name, "activate", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	if ok, cached := s.checkIdempotency(r, actor, namespace, fmt.Sprintf("activate:%s:%d", name, version)); !ok {
		if cached != nil {
			respondJSON(w, http.StatusOK, cached)
		} else {
			respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
		}
		return
	}
	newActive, oldActive, err := s.store.SetActive(ctx, namespace, name, version, actor)
	if err != nil {
		if strings.Contains(err.Error(), "未找到") {
			respondError(w, http.StatusNotFound, err.Error())
		} else {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("激活失败: %v", err))
		}
		return
	}
	now := time.Now()
	s.recordAudit(ctx, r, &model.AuditLog{
		Namespace: namespace,
		Name:      name,
		Action:    "activate",
		Actor:     actor,
		ClientIP:  clientIP(r),
		Version:   version,
		Result:    "success",
		Detail:    fmt.Sprintf("激活版本 %d，旧 active 版本 %d", version, versionOrZero(oldActive)),
		CreatedAt: now,
	})

	newActive.UpdatedBy = actor
	newActive.UpdatedAt = now
	resp := map[string]any{
		"name":    name,
		"version": version,
		"status":  "active",
	}
	_ = s.store.SaveIdempotencyResponse(ctx, namespace+"|"+"activate:"+name, r.Header.Get("Idempotency-Key"), resp)
	respondJSON(w, http.StatusOK, resp)
	s.watcher.Notify(namespace, name, version)
}

// handleRotateSecret 基于最新版本生成 staged 版本，实现轮换与灰度。
func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	var req model.RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	if !validateRotate(w, &req) {
		return
	}
	now := time.Now()
	actor := getActor(r)

	if ok, cached := s.checkIdempotency(r, actor, namespace, "rotate:"+name); !ok {
		if cached != nil {
			respondJSON(w, http.StatusOK, cached)
		} else {
			respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
		}
		return
	}

	latest, err := s.store.Latest(ctx, namespace, name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询当前版本失败: %v", err))
		return
	}
	if latest == nil {
		respondError(w, http.StatusNotFound, "未找到可轮换的密钥")
		return
	}
	if err := s.authorize(ctx, namespace, name, "rotate", actor, latest.Labels); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	var oldActiveVersion int
	active, err := s.store.FindActive(ctx, namespace, name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询 active 失败: %v", err))
		return
	}
	if active != nil {
		oldActiveVersion = active.Version
	}
	// 轮换生成新版本，要求客户端提供明文或密文，服务端做封装以避免落盘明文
	ciphertext := req.Ciphertext
	if req.Plaintext != "" {
		enc, err := s.kms.Encrypt([]byte(req.Plaintext))
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("加密新版本失败: %v", err))
			return
		}
		ciphertext = enc
	}
	keyID := latest.KeyID
	if req.KeyID != "" {
		keyID = req.KeyID
	}
	newSecret := &model.SecretVersion{
		Namespace:  namespace,
		Name:       name,
		Ciphertext: ciphertext,
		KeyID:      keyID,
		Labels:     latest.Labels,
		Status:     "staged",
		CreatedBy:  actor,
		UpdatedBy:  actor,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	newVersion, err := s.store.AppendSecretVersion(ctx, newSecret)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("轮换失败: %v", err))
		return
	}
	s.recordAudit(ctx, r, &model.AuditLog{
		Namespace: namespace,
		Name:      name,
		Action:    "rotate",
		Actor:     actor,
		ClientIP:  clientIP(r),
		Version:   newVersion,
		Result:    "success",
		Detail:    fmt.Sprintf("grace_period_hours=%d", req.GracePeriodHours),
		CreatedAt: now,
	})

	resp := map[string]any{
		"name":        name,
		"new_version": newVersion,
		"old_version": versionOrZeroPointer(oldActiveVersion),
		"status":      "staged",
		"kms":         s.kms.Name(),
	}
	_ = s.store.SaveIdempotencyResponse(ctx, namespace+"|"+"rotate:"+name, r.Header.Get("Idempotency-Key"), resp)
	respondJSON(w, http.StatusOK, resp)
}

// etagValue 生成包含 active/staged 版本号的弱 ETag。
func etagValue(namespace, name string, active, staged int) string {
	return `W/"` + namespace + "|" + name + "|" + strconv.Itoa(active) + "|" + strconv.Itoa(staged) + `"`
}

// recordAudit 统一生成签名并写入审计。
func (s *Server) recordAudit(ctx context.Context, r *http.Request, a *model.AuditLog) {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	if s.cfg.AuditHMACKey != "" {
		a.Signature = signAudit(a, s.cfg.AuditHMACKey)
	}
	if err := s.store.RecordAudit(ctx, a); err != nil {
		log.Printf("[audit] 记录失败: %v", err)
		s.incMetric("audit_record_fail", 1)
		return
	}
	s.incMetric("audit_record_ok", 1)
}

// checkIdempotency 检查幂等键，返回是否可继续以及是否有缓存响应。
func (s *Server) checkIdempotency(r *http.Request, actor, namespace, action string) (bool, map[string]any) {
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		return true, nil
	}
	scope := namespace + "|" + action
	if s.idemStore != nil && !s.idemStore.checkAndSet(actor+"|"+namespace+"|"+action+"|"+key) {
		if resp, ok, _ := s.store.GetIdempotencyResponse(r.Context(), scope, key); ok && resp != nil {
			return false, resp
		}
		return false, nil
	}
	ok, err := s.store.ReserveIdempotency(r.Context(), scope, key)
	if err != nil {
		return false, nil
	}
	if !ok {
		if resp, ok2, _ := s.store.GetIdempotencyResponse(r.Context(), scope, key); ok2 && resp != nil {
			return false, resp
		}
		return false, nil
	}
	return true, nil
}

// handleAuditQuery 查询审计日志，支持分页与时间过滤。
func (s *Server) handleAuditQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	ctx := r.Context()
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx = context.WithValue(ctx, ctxActorKey{}, actor)
	if err := s.authorize(ctx, "", "", "audit", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	var req model.AuditQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 || req.PageSize > 200 {
		req.PageSize = 50
	}
	if req.FromRaw != "" {
		if t, err := time.Parse(time.RFC3339, req.FromRaw); err == nil {
			req.From = t
		}
	}
	if req.ToRaw != "" {
		if t, err := time.Parse(time.RFC3339, req.ToRaw); err == nil {
			req.To = t
		}
	}

	all, err := s.store.ListAudits(ctx, req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询审计失败: %v", err))
		return
	}
	start := (req.Page - 1) * req.PageSize
	if start >= len(all) {
		respondJSON(w, http.StatusOK, map[string]any{"items": []model.AuditLog{}, "total": len(all)})
		return
	}
	end := start + req.PageSize
	if end > len(all) {
		end = len(all)
	}
	items := all[start:end]
	for _, it := range items {
		it.Detail = ""    // 返回时默认隐藏 detail 以避免敏感信息，可按需放开
		it.Signature = "" // 不下发签名，避免泄露密钥结构
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": len(all),
	})
}

// handleAuditVerify 对审计日志进行签名校验（抽样或按过滤条件）。
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if s.cfg.AuditHMACKey == "" {
		respondError(w, http.StatusBadRequest, "未配置 AUDIT_HMAC_KEY，无法校验")
		return
	}
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := context.WithValue(r.Context(), ctxActorKey{}, actor)
	if err := s.authorize(ctx, "", "", "audit", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	var req model.AuditQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	// 复用查询过滤
	all, err := s.store.ListAudits(ctx, req)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询审计失败: %v", err))
		return
	}
	sampleSize := 50
	if req.PageSize > 0 && req.PageSize < sampleSize {
		sampleSize = req.PageSize
	}
	failCount := 0
	checked := 0
	for i, a := range all {
		if i >= sampleSize {
			break
		}
		if !verifyAudit(a, s.cfg.AuditHMACKey) {
			failCount++
		}
		checked++
	}
	status := "ok"
	if failCount > 0 {
		s.incMetric("audit_verify_failed_total", int64(failCount))
		status = "mismatch"
	} else {
		s.incMetric("audit_verify_ok_total", int64(checked))
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"checked":    checked,
		"failed":     failCount,
		"status":     status,
		"sampleSize": sampleSize,
	})
}

// handleNamespaceAdmin 管理命名空间的创建与查询。
func (s *Server) handleNamespaceAdmin(w http.ResponseWriter, r *http.Request) {
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx := context.WithValue(r.Context(), ctxActorKey{}, actor)
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if err := s.authorize(ctx, "", "*", "manage", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	var req struct {
		Action string `json:"action"`
		Name   string `json:"name"`
		Desc   string `json:"description"`
		Ticket string `json:"ticket_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	action := req.Action
	if action == "" {
		if req.Name == "" {
			action = "list"
		} else {
			action = "create"
		}
	}
	switch action {
	case "list":
		all, err := s.store.ListNamespaces(ctx)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取命名空间失败: %v", err))
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"items": all, "total": len(all)})
	case "create":
		if req.Name == "" {
			respondError(w, http.StatusBadRequest, "name 必填且需 JSON")
			return
		}
		if ok, cached := s.checkIdempotency(r, actor, "", "namespace:"+req.Name); !ok {
			if cached != nil {
				respondJSON(w, http.StatusOK, cached)
			} else {
				respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
			}
			return
		}
		if err := s.store.CreateNamespace(ctx, req.Name, req.Desc); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("创建命名空间失败: %v", err))
			return
		}
		_ = s.store.RecordAudit(ctx, &model.AuditLog{
			Namespace: req.Name,
			Action:    "manage",
			Actor:     actor,
			ClientIP:  clientIP(r),
			Result:    "success",
			Detail:    fmt.Sprintf("创建命名空间 ticket=%s", req.Ticket),
			CreatedAt: time.Now(),
		})
		resp := map[string]any{"name": req.Name}
		_ = s.store.SaveIdempotencyResponse(ctx, "namespace|"+req.Name, r.Header.Get("Idempotency-Key"), resp)
		respondJSON(w, http.StatusOK, resp)
	default:
		respondError(w, http.StatusBadRequest, "action 仅支持 list/create")
	}
}

// handlePolicies 处理策略创建、审批、查询与配额重置。
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	ctx := r.Context()
	actor, err := s.authenticate(r)
	if err != nil {
		respondError(w, http.StatusUnauthorized, err.Error())
		return
	}
	ctx = context.WithValue(ctx, ctxActorKey{}, actor)
	var req model.PolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	action := req.Action
	// 根据请求内容自动推断动作：显式 decision -> approve，显式 action 优先
	if action == "" {
		if req.Decision != "" {
			action = "approve"
		} else if req.Name != "" {
			action = "create"
		} else {
			action = "list"
		}
	}
	if req.CreatedBy != "" {
		actor = req.CreatedBy
	}
	if err := s.authorize(ctx, req.Namespace, "*", "manage", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	switch action {
	case "create":
		if ok, cached := s.checkIdempotency(r, actor, req.Namespace, "policy:"+req.Name); !ok {
			if cached != nil {
				respondJSON(w, http.StatusOK, cached)
			} else {
				respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
			}
			return
		}
		if !validatePolicy(w, &req) {
			return
		}
		if req.Effect == "" {
			req.Effect = "allow"
		}
		now := time.Now()
		p := &model.Policy{
			Name:              req.Name,
			Namespace:         req.Namespace,
			Subjects:          req.Subjects,
			Resources:         req.Resources,
			Actions:           req.Operations,
			Effect:            req.Effect,
			Conditions:        map[string]any{},
			CreatedBy:         actor,
			CreatedAt:         now,
			ApprovalState:     "pending",
			RequiredApprovals: req.RequiredApprovals,
			Approvers:         req.Approvers,
			TicketID:          req.TicketID,
			Approved:          false,
		}
		if p.RequiredApprovals <= 0 {
			p.RequiredApprovals = 1
		}
		if len(req.Approvers) > 0 && p.RequiredApprovals > len(req.Approvers) {
			p.RequiredApprovals = len(req.Approvers)
		}
		if len(req.Conditions) > 0 {
			for k, v := range req.Conditions {
				p.Conditions[k] = v
			}
		}
		existing, err := s.store.ListPolicies(ctx, req.Namespace)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("读取现有策略失败: %v", err))
			return
		}
		if err = detectPolicyConflict(p, existing); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
		p, err = s.store.AddPolicy(ctx, p)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("创建策略失败: %v", err))
			return
		}
		_ = s.store.RecordAudit(ctx, &model.AuditLog{
			Namespace: req.Namespace,
			Action:    "manage",
			Actor:     actor,
			ClientIP:  clientIP(r),
			Result:    "success",
			Detail:    fmt.Sprintf("创建策略 %s", req.Name),
			CreatedAt: now,
		})
		_ = s.store.SaveIdempotencyResponse(ctx, req.Namespace+"|"+"policy:"+req.Name, r.Header.Get("Idempotency-Key"), map[string]any{
			"policy": p,
		})
		respondJSON(w, http.StatusOK, p)
	case "approve":
		if req.Name == "" && req.Namespace == "" {
			respondError(w, http.StatusBadRequest, "审批需要提供策略名称与命名空间")
			return
		}
		// 简单按 name+namespace 查找并审批
		policies, err := s.store.ListPolicies(ctx, req.Namespace)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询策略失败: %v", err))
			return
		}
		var target *model.Policy
		for _, p := range policies {
			if p.Name == req.Name {
				target = p
				break
			}
		}
		if target == nil {
			respondError(w, http.StatusNotFound, "未找到策略")
			return
		}
		decision := strings.ToLower(req.Decision)
		if decision == "" {
			decision = "approve"
		}
		if decision != "approve" && decision != "reject" {
			respondError(w, http.StatusBadRequest, "decision 仅支持 approve/reject")
			return
		}
		if decision == "approve" {
			if err := detectPolicyConflict(target, policies); err != nil {
				respondError(w, http.StatusConflict, "审批前冲突检测失败: "+err.Error())
				return
			}
		}
		if ok, cached := s.checkIdempotency(r, actor, req.Namespace, decision+":"+req.Name); !ok {
			if cached != nil {
				respondJSON(w, http.StatusOK, cached)
			} else {
				respondError(w, http.StatusConflict, "重复的 Idempotency-Key")
			}
			return
		}
		reason := req.Reason
		updated, ok, err := s.store.UpdatePolicyApproval(ctx, target.ID, req.Version, actor, decision == "approve", reason, req.TicketID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("审批失败: %v", err))
			return
		}
		if !ok {
			respondError(w, http.StatusConflict, "策略版本冲突或未找到，需重试")
			return
		}
		actionWord := "approve"
		if decision != "approve" {
			actionWord = "reject"
		}
		_ = s.store.SaveIdempotencyResponse(ctx, req.Namespace+"|"+decision+":"+req.Name, r.Header.Get("Idempotency-Key"), map[string]any{
			"policy": updated,
		})
		_ = s.store.RecordAudit(ctx, &model.AuditLog{
			Namespace: req.Namespace,
			Action:    "manage",
			Actor:     actor,
			ClientIP:  clientIP(r),
			Result:    "success",
			Detail:    fmt.Sprintf("%s policy %s", actionWord, req.Name),
			CreatedAt: time.Now(),
		})
		respondJSON(w, http.StatusOK, updated)
	case "list":
		policies, err := s.store.ListPolicies(ctx, req.Namespace)
		if err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询策略失败: %v", err))
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"items": policies,
			"total": len(policies),
		})
	case "reset_quota":
		if err := s.store.ResetQuotas(ctx, req.Namespace); err != nil {
			respondError(w, http.StatusInternalServerError, fmt.Sprintf("配额重置失败: %v", err))
			return
		}
		respondJSON(w, http.StatusOK, map[string]string{"message": "配额已重置"})
	default:
		respondError(w, http.StatusBadRequest, "action 仅支持 create/approve/list/reset_quota")
	}
}

// incMetric 累加服务端指标。
func (s *Server) incMetric(key string, delta int64) {
	if delta == 0 {
		return
	}
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	s.metrics[key] += delta
}

// metricsSnapshot 返回当前服务端指标。
func (s *Server) metricsSnapshot() map[string]int64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	out := make(map[string]int64, len(s.metrics))
	for k, v := range s.metrics {
		out[k] = v
	}
	return out
}

// quotaResetLoop 定期清理配额计数，防止跨租户/跨窗口配额累积。
func (s *Server) quotaResetLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		_ = s.store.ResetQuotas(ctx, "")
		cancel()
	}
}

// kmsRotateLoop 定期触发 KMS 轮换，失败计数便于告警。
func (s *Server) kmsRotateLoop() {
	for range s.kmsTicker.C {
		if err := s.kms.RotateKey(); err != nil {
			s.incMetric("kms_rotate_fail", 1)
		} else {
			s.incMetric("kms_rotate_success", 1)
		}
	}
}
