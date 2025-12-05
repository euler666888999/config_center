package store

import (
	"context"
	"time"

	"config_center/internal/model"
)

// Store 定义存储层通用接口，便于切换内存与 MySQL 实现。
type Store interface {
	AppendSecretVersion(ctx context.Context, sv *model.SecretVersion) (int, error)
	FindActive(ctx context.Context, namespace, name string) (*model.SecretVersion, error)
	FindByVersion(ctx context.Context, namespace, name string, version int) (*model.SecretVersion, error)
	Latest(ctx context.Context, namespace, name string) (*model.SecretVersion, error)
	ListSecrets(ctx context.Context, namespace string) ([]string, error)
	ListVersions(ctx context.Context, namespace, name string) ([]*model.SecretVersion, error)
	SetActive(ctx context.Context, namespace, name string, version int, actor string) (*model.SecretVersion, *model.SecretVersion, error)

	RecordAudit(ctx context.Context, a *model.AuditLog) error
	ListAudits(ctx context.Context, filter model.AuditQueryRequest) ([]*model.AuditLog, error)

	AddPolicy(ctx context.Context, p *model.Policy) (*model.Policy, error)
	ListPolicies(ctx context.Context, namespace string) ([]*model.Policy, error)
	HasPolicies(ctx context.Context) (bool, error)
	UpdatePolicyApproval(ctx context.Context, id int64, version int, approver string, approve bool, reason string, ticket string) (*model.Policy, bool, error)

	NamespaceExists(ctx context.Context, namespace string) (bool, error)
	CreateNamespace(ctx context.Context, namespace, desc string) error
	ListNamespaces(ctx context.Context) ([]string, error)
	Ping(ctx context.Context) error
	Close() error

	// 幂等与配额
	ReserveIdempotency(ctx context.Context, scope, key string) (bool, error)
	SaveIdempotencyResponse(ctx context.Context, scope, key string, resp map[string]any) error
	GetIdempotencyResponse(ctx context.Context, scope, key string) (map[string]any, bool, error)
	UpdateQuota(ctx context.Context, policyID int64, actor, namespace, resource, action string, limit int, window time.Duration) (bool, error)
	ResetQuotas(ctx context.Context, namespace string) error

	// Metrics（可选）
	Metrics() map[string]int64
}
