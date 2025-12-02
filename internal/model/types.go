package model

import "time"

// SecretVersion 表示单个密钥/配置版本的元数据与密文。
type SecretVersion struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Version    int               `json:"version"`
	Ciphertext string            `json:"ciphertext"`
	KeyID      string            `json:"key_id"`
	Labels     map[string]string `json:"labels,omitempty"`
	Status     string            `json:"status"`
	ExpireAt   *time.Time        `json:"expire_at,omitempty"`
	CreatedBy  string            `json:"created_by"`
	UpdatedBy  string            `json:"updated_by"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// AuditLog 记录审计事件，方便追踪访问与变更。
type AuditLog struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name,omitempty"`
	Action    string    `json:"action"`
	Actor     string    `json:"actor"`
	ClientIP  string    `json:"client_ip"`
	Version   int       `json:"version,omitempty"`
	Result    string    `json:"result"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Policy 表示简单的 RBAC/ABAC 策略。
type Policy struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Namespace  string         `json:"namespace"`
	Subjects   []string       `json:"subjects"`
	Resources  []string       `json:"resources"`
	Actions    []string       `json:"actions"`
	Effect     string         `json:"effect"`
	Conditions map[string]any `json:"conditions,omitempty"`
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
}

// CreateSecretRequest 创建密钥的请求体。
type CreateSecretRequest struct {
	Name       string            `json:"name"`
	Plaintext  string            `json:"plaintext"`
	Ciphertext string            `json:"ciphertext"`
	KeyID      string            `json:"key_id"`
	Labels     map[string]string `json:"labels"`
	Status     string            `json:"status"`
	ExpireAt   string            `json:"expire_at"`
}

// RotateRequest 触发轮换请求。
type RotateRequest struct {
	GracePeriodHours int `json:"grace_period_hours"`
}

// AuditQueryRequest 审计查询请求。
type AuditQueryRequest struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	From      time.Time `json:"-"`
	To        time.Time `json:"-"`
	FromRaw   string    `json:"from"`
	ToRaw     string    `json:"to"`
	Page      int       `json:"page"`
	PageSize  int       `json:"page_size"`
}

// PolicyRequest 管理策略请求体。
type PolicyRequest struct {
	Action     string            `json:"action"`
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Subjects   []string          `json:"subjects"`
	Resources  []string          `json:"resources"`
	Operations []string          `json:"actions"`
	Effect     string            `json:"effect"`
	Conditions map[string]string `json:"conditions"`
	CreatedBy  string            `json:"created_by"`
}
