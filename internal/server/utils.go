package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"config_center/internal/model"
)

// ctxActorKey 用于在请求上下文中传递已认证的主体。
type ctxActorKey struct{}

// respondJSON 输出 JSON 响应。
func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// respondError 输出错误信息，使用中文提示。
func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]any{
		"error":      msg,
		"code":       status,
		"error_code": errorCode(status),
		"message":    msg,
	})
}

// errorCode 提供统一错误码（国际化可扩展）。
func errorCode(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "INVALID_ARGUMENT"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusTooManyRequests:
		return "RATE_LIMITED"
	default:
		if status >= 500 {
			return "INTERNAL"
		}
		return "UNKNOWN"
	}
}

// getActor 优先从上下文读取已认证主体，退化到 header。
func getActor(r *http.Request) string {
	if v := r.Context().Value(ctxActorKey{}); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	actor := r.Header.Get("X-Actor")
	if actor == "" {
		actor = "demo-client"
	}
	return actor
}

// clientIP 尝试从 X-Forwarded-For 或远端地址提取 IP。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isValidStatus 校验密钥状态是否合法。
func isValidStatus(status string) bool {
	switch status {
	case "staged", "active", "deprecated", "disabled":
		return true
	default:
		return false
	}
}

// versionOrZero 将 SecretVersion 指针转换为版本号，nil 返回 0。
func versionOrZero(sv *model.SecretVersion) int {
	if sv == nil {
		return 0
	}
	return sv.Version
}

// versionOrZeroPointer 将 0 转为空接口 nil，用于响应体。
func versionOrZeroPointer(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

// signAudit 生成审计日志的 HMAC-SHA256 签名，确保防篡改。
func signAudit(a *model.AuditLog, key string) string {
	if key == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(key))
	payload := []string{
		a.Namespace,
		a.Name,
		a.Action,
		a.Actor,
		a.ClientIP,
		fmt.Sprintf("%d", a.Version),
		a.Result,
		a.Detail,
		a.CreatedAt.Format(time.RFC3339Nano),
	}
	mac.Write([]byte(strings.Join(payload, "|")))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// verifyAudit 对比签名。
func verifyAudit(a *model.AuditLog, key string) bool {
	if key == "" || a.Signature == "" {
		return false
	}
	return hmac.Equal([]byte(a.Signature), []byte(signAudit(a, key)))
}
