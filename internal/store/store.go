package store

import (
	"context"

	"config_center/internal/model"
)

// Store 定义存储层通用接口，便于切换内存与 MySQL 实现。
type Store interface {
	AppendSecretVersion(ctx context.Context, sv *model.SecretVersion) (int, error)
	FindActive(ctx context.Context, namespace, name string) (*model.SecretVersion, error)
	FindByVersion(ctx context.Context, namespace, name string, version int) (*model.SecretVersion, error)
	Latest(ctx context.Context, namespace, name string) (*model.SecretVersion, error)
	ListVersions(ctx context.Context, namespace, name string) ([]*model.SecretVersion, error)
	SetActive(ctx context.Context, namespace, name string, version int, actor string) (*model.SecretVersion, *model.SecretVersion, error)

	RecordAudit(ctx context.Context, a *model.AuditLog) error
	ListAudits(ctx context.Context, filter model.AuditQueryRequest) ([]*model.AuditLog, error)

	AddPolicy(ctx context.Context, p *model.Policy) (*model.Policy, error)
	ListPolicies(ctx context.Context, namespace string) ([]*model.Policy, error)
	HasPolicies(ctx context.Context) (bool, error)

	NamespaceExists(ctx context.Context, namespace string) (bool, error)
	Ping(ctx context.Context) error
	Close() error
}
