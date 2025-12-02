package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/model"
	"config_center/internal/store"
)

// Server 聚合路由与存储。
type Server struct {
	store store.Store
	cfg   config.Config
	kms   *kms.EnvelopeKMS
}

// NewServer 创建服务器实例。
func NewServer(store store.Store, cfg config.Config, kms *kms.EnvelopeKMS) *Server {
	return &Server{store: store, cfg: cfg, kms: kms}
}

// Router 返回注册好路由的 mux。
func (s *Server) Router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.readyz)
	mux.HandleFunc("/v1/audit/query", s.handleAuditQuery)
	mux.HandleFunc("/v1/authz/policies", s.handlePolicies)
	mux.HandleFunc("/v1/namespaces/", s.handleNamespaces)
	return mux
}

// Init 执行启动时的引导操作（如注入初始策略）。
func (s *Server) Init(ctx context.Context) {
	s.seedBootstrapPolicy(ctx)
}

// handleHealthz 健康探针。
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz 检查依赖（DB、KMS）。
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondError(w, http.StatusMethodNotAllowed, "仅支持 GET")
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
		respondError(w, http.StatusMethodNotAllowed, "所有接口均需 POST")
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
		s.handleCreateSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace)
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
		s.handleRotateSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
		return
	case strings.HasSuffix(nameSegment, ":watch"):
		name := strings.TrimSuffix(nameSegment, ":watch")
		s.handleWatchSecret(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name)
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
		s.handleActivateVersion(w, r.WithContext(context.WithValue(r.Context(), ctxActorKey{}, actor)), namespace, name, version)
		return
	}

	respondError(w, http.StatusNotFound, "未找到匹配的接口")
}

func (s *Server) handleCreateSecret(w http.ResponseWriter, r *http.Request, namespace string) {
	ctx := r.Context()
	var req model.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	if req.Name == "" || (req.Plaintext == "" && req.Ciphertext == "") || req.KeyID == "" {
		respondError(w, http.StatusBadRequest, "name/plaintext 或 ciphertext/key_id 必填")
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

	if err := s.authorize(ctx, namespace, req.Name, "write", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
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
	_ = s.store.RecordAudit(ctx, &model.AuditLog{
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

	respondJSON(w, http.StatusOK, map[string]any{
		"name":    req.Name,
		"version": version,
		"status":  status,
	})
}

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
	if err := s.authorize(ctx, namespace, name, "read", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}

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
	target.Ciphertext = "" // 避免在日志中泄露

	_ = s.store.RecordAudit(ctx, &model.AuditLog{
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

func (s *Server) handleActivateVersion(w http.ResponseWriter, r *http.Request, namespace, name string, version int) {
	ctx := r.Context()
	actor := getActor(r)
	if err := s.authorize(ctx, namespace, name, "activate", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
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
	_ = s.store.RecordAudit(ctx, &model.AuditLog{
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
	respondJSON(w, http.StatusOK, map[string]any{
		"name":    name,
		"version": version,
		"status":  "active",
	})
}

func (s *Server) handleRotateSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	var req model.RotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "请求体必须为 JSON")
		return
	}
	if req.Plaintext == "" && req.Ciphertext == "" {
		respondError(w, http.StatusBadRequest, "轮换需提供 plaintext 或 ciphertext")
		return
	}
	now := time.Now()
	actor := getActor(r)

	if err := s.authorize(ctx, namespace, name, "rotate", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
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
	_ = s.store.RecordAudit(ctx, &model.AuditLog{
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

	respondJSON(w, http.StatusOK, map[string]any{
		"name":        name,
		"new_version": newVersion,
		"old_version": versionOrZeroPointer(oldActiveVersion),
		"status":      "staged",
	})
}

// handleWatchSecret 使用长轮询，若无变更返回 304。
func (s *Server) handleWatchSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	actor := getActor(r)
	if err := s.authorize(ctx, namespace, name, "watch", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	timeout := 25 * time.Second
	deadline := time.Now().Add(timeout)
	etag := r.Header.Get("If-None-Match")
	var lastHash string
	for {
		active, _ := s.store.FindActive(ctx, namespace, name)
		versions, _ := s.store.ListVersions(ctx, namespace, name)
		var stagedVersion int
		for _, v := range versions {
			if v.Status == "staged" {
				stagedVersion = v.Version
				break
			}
		}
		current := versionOrZero(active)
		hash := etagValue(namespace, name, current, stagedVersion)
		if hash != etag && hash != lastHash {
			w.Header().Set("ETag", hash)
			_ = s.store.RecordAudit(ctx, &model.AuditLog{
				Namespace: namespace,
				Name:      name,
				Action:    "read",
				Actor:     actor,
				ClientIP:  clientIP(r),
				Version:   current,
				Result:    "success",
				Detail:    "watch 长轮询返回快照",
				CreatedAt: time.Now(),
			})
			respondJSON(w, http.StatusOK, map[string]any{
				"name":           name,
				"namespace":      namespace,
				"active_version": current,
				"staged_version": stagedVersion,
				"timestamp":      time.Now().Format(time.RFC3339),
			})
			return
		}
		if time.Now().After(deadline) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		lastHash = hash
		time.Sleep(2 * time.Second)
	}
}

func etagValue(namespace, name string, active, staged int) string {
	return `W/"` + namespace + "|" + name + "|" + strconv.Itoa(active) + "|" + strconv.Itoa(staged) + `"`
}

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
	if err := s.authorize(ctx, "", "", "audit", actor); err != nil {
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
	respondJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": len(all),
	})
}

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
	if action == "" {
		if req.Name != "" {
			action = "create"
		} else {
			action = "list"
		}
	}
	if req.CreatedBy != "" {
		actor = req.CreatedBy
	}
	if err := s.authorize(ctx, req.Namespace, "*", "manage", actor); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	switch action {
	case "create":
		if req.Name == "" || req.Namespace == "" || len(req.Subjects) == 0 || len(req.Resources) == 0 || len(req.Operations) == 0 {
			respondError(w, http.StatusBadRequest, "创建策略时 name/namespace/subjects/resources/actions 必填")
			return
		}
		if req.Effect == "" {
			req.Effect = "allow"
		}
		now := time.Now()
		p := &model.Policy{
			Name:       req.Name,
			Namespace:  req.Namespace,
			Subjects:   req.Subjects,
			Resources:  req.Resources,
			Actions:    req.Operations,
			Effect:     req.Effect,
			Conditions: map[string]any{},
			CreatedBy:  actor,
			CreatedAt:  now,
		}
		if len(req.Conditions) > 0 {
			for k, v := range req.Conditions {
				p.Conditions[k] = v
			}
		}
		p, err := s.store.AddPolicy(ctx, p)
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
		respondJSON(w, http.StatusOK, p)
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
	default:
		respondError(w, http.StatusBadRequest, "action 仅支持 create 或 list")
	}
}
