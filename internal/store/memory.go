package store

import (
	"context"
	"fmt"
	"sync"
	"time"

	"config_center/internal/model"
)

// MemoryStore 使用内存实现的简易存储，方便本地演示与接口验证。
type MemoryStore struct {
	mu       sync.RWMutex
	secrets  map[string][]*model.SecretVersion // key = namespace|name
	audits   []*model.AuditLog
	policies []*model.Policy
	policyID int64
}

// NewMemoryStore 初始化内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		secrets: make(map[string][]*model.SecretVersion),
	}
}

// key 生成命名空间下名称的唯一键。
func (m *MemoryStore) key(namespace, name string) string {
	return fmt.Sprintf("%s|%s", namespace, name)
}

// AppendSecretVersion 生成新版本号并写入存储，返回版本号。
func (m *MemoryStore) AppendSecretVersion(_ context.Context, sv *model.SecretVersion) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(sv.Namespace, sv.Name)
	sv.Version = len(m.secrets[key]) + 1
	m.secrets[key] = append(m.secrets[key], sv)
	return sv.Version, nil
}

// FindActive 查找当前 active 版本。
func (m *MemoryStore) FindActive(_ context.Context, namespace, name string) (*model.SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := m.key(namespace, name)
	for _, v := range m.secrets[key] {
		if v.Status == "active" {
			return v, nil
		}
	}
	return nil, nil
}

// FindByVersion 根据版本查找。
func (m *MemoryStore) FindByVersion(_ context.Context, namespace, name string, version int) (*model.SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := m.key(namespace, name)
	for _, v := range m.secrets[key] {
		if v.Version == version {
			return v, nil
		}
	}
	return nil, nil
}

// Latest 获取最新版本（按插入顺序）。
func (m *MemoryStore) Latest(_ context.Context, namespace, name string) (*model.SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := m.key(namespace, name)
	versions := m.secrets[key]
	if len(versions) == 0 {
		return nil, nil
	}
	return versions[len(versions)-1], nil
}

// ListVersions 返回指定密钥的全部版本切片副本。
func (m *MemoryStore) ListVersions(_ context.Context, namespace, name string) ([]*model.SecretVersion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := m.key(namespace, name)
	versions := m.secrets[key]
	res := make([]*model.SecretVersion, 0, len(versions))
	res = append(res, versions...)
	return res, nil
}

// SetActive 将指定版本切换为 active，同时把旧 active 标记为 deprecated。
func (m *MemoryStore) SetActive(_ context.Context, namespace, name string, version int, actor string) (*model.SecretVersion, *model.SecretVersion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := m.key(namespace, name)
	var (
		newActive *model.SecretVersion
		oldActive *model.SecretVersion
	)
	for _, v := range m.secrets[key] {
		if v.Version == version {
			newActive = v
		}
		if v.Status == "active" {
			oldActive = v
		}
	}
	if newActive == nil {
		return nil, nil, fmt.Errorf("未找到版本 %d", version)
	}
	for _, v := range m.secrets[key] {
		if v.Version == version {
			v.Status = "active"
			v.UpdatedAt = time.Now()
			v.UpdatedBy = actor
		} else if v.Status == "active" {
			v.Status = "deprecated"
			v.UpdatedAt = time.Now()
			v.UpdatedBy = actor
		}
	}
	return newActive, oldActive, nil
}

// RecordAudit 记录审计事件。
func (m *MemoryStore) RecordAudit(_ context.Context, a *model.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audits = append(m.audits, a)
	return nil
}

// ListAudits 简单过滤审计日志。
func (m *MemoryStore) ListAudits(_ context.Context, filter model.AuditQueryRequest) ([]*model.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var result []*model.AuditLog
	for _, a := range m.audits {
		if filter.Namespace != "" && a.Namespace != filter.Namespace {
			continue
		}
		if filter.Name != "" && a.Name != filter.Name {
			continue
		}
		if filter.Action != "" && a.Action != filter.Action {
			continue
		}
		if filter.Result != "" && a.Result != filter.Result {
			continue
		}
		if !filter.From.IsZero() && a.CreatedAt.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && a.CreatedAt.After(filter.To) {
			continue
		}
		result = append(result, a)
	}
	return result, nil
}

// AddPolicy 添加策略。
func (m *MemoryStore) AddPolicy(_ context.Context, p *model.Policy) (*model.Policy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyID++
	p.ID = m.policyID
	m.policies = append(m.policies, p)
	return p, nil
}

// ListPolicies 列出策略，可按命名空间过滤。
func (m *MemoryStore) ListPolicies(_ context.Context, namespace string) ([]*model.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if namespace == "" {
		return m.policies, nil
	}
	var res []*model.Policy
	for _, p := range m.policies {
		if p.Namespace == namespace {
			res = append(res, p)
		}
	}
	return res, nil
}

// HasPolicies 判断是否存在任何策略。
func (m *MemoryStore) HasPolicies(_ context.Context) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.policies) > 0, nil
}

// NamespaceExists 内存模式认为命名空间必须显式创建。
func (m *MemoryStore) NamespaceExists(_ context.Context, namespace string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, versions := range m.secrets {
		if len(versions) == 0 {
			continue
		}
		if versions[0].Namespace == namespace {
			return true, nil
		}
	}
	return false, nil
}

// Ping 内存存储恒定可用。
func (m *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// Close 内存实现无资源需关闭。
func (m *MemoryStore) Close() error {
	return nil
}

// 确保实现接口。
var _ Store = (*MemoryStore)(nil)
