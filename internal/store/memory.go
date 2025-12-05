package store

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"config_center/internal/model"
)

// MemoryStore 使用内存实现的简易存储，方便本地演示与接口验证。
type MemoryStore struct {
	mu         sync.RWMutex
	secrets    map[string][]*model.SecretVersion // key = namespace|name
	audits     []*model.AuditLog
	policies   []*model.Policy
	policyID   int64
	idemKeys   map[string]time.Time
	idemResp   map[string]map[string]any
	quota      map[string]quotaRecord
	metrics    map[string]int64
	namespaces map[string]string // namespace -> description
}

type quotaRecord struct {
	used int
	exp  time.Time
}

// NewMemoryStore 初始化内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		secrets:    make(map[string][]*model.SecretVersion),
		idemKeys:   make(map[string]time.Time),
		idemResp:   make(map[string]map[string]any),
		quota:      make(map[string]quotaRecord),
		metrics:    make(map[string]int64),
		namespaces: make(map[string]string),
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
	if _, ok := m.namespaces[sv.Namespace]; !ok {
		return 0, fmt.Errorf("命名空间 %s 不存在", sv.Namespace)
	}
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
	versions := m.secrets[key]
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
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

// ListSecrets 列出指定命名空间下的所有密钥名称。
func (m *MemoryStore) ListSecrets(_ context.Context, namespace string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[string]struct{})
	for key := range m.secrets {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) == 2 && parts[0] == namespace {
			seen[parts[1]] = struct{}{}
		}
	}
	res := make([]string, 0, len(seen))
	for name := range seen {
		res = append(res, name)
	}
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
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
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
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Approved && p.ApprovalState == "" {
		p.ApprovalState = "approved"
	}
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

// UpdatePolicyApproval 更新策略审批状态，返回更新后的策略及是否生效。
func (m *MemoryStore) UpdatePolicyApproval(_ context.Context, id int64, version int, approver string, approve bool, reason string, ticket string) (*model.Policy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.policies {
		if p.ID == id {
			if version > 0 && p.Version != version {
				return nil, false, nil
			}
			if p.ApprovalState == "approved" || p.ApprovalState == "rejected" {
				return p, false, nil
			}
			if p.RequiredApprovals <= 0 {
				p.RequiredApprovals = 1
			}
			// 审批人校验：若指定 approvers，仅允许名单内审批
			if len(p.Approvers) > 0 && approver != "" && !containsIgnoreCase(p.Approvers, approver) {
				return nil, false, fmt.Errorf("审批人不在 approvers 名单中")
			}
			if approver != "" && !containsIgnoreCase(p.ApprovedBy, approver) {
				p.ApprovedBy = append(p.ApprovedBy, approver)
			}
			p.TicketID = ticket
			p.Reason = reason
			if approve {
				p.ApprovedSteps++
				if p.ApprovedSteps >= p.RequiredApprovals {
					now := time.Now()
					p.ApprovalState = "approved"
					p.Approved = true
					p.ApprovedAt = &now
				} else {
					p.ApprovalState = "pending"
				}
			} else {
				now := time.Now()
				p.ApprovalState = "rejected"
				p.Approved = false
				p.ApprovedAt = &now
			}
			p.Version++
			return p, true, nil
		}
	}
	return nil, false, fmt.Errorf("未找到策略")
}

// NamespaceExists 内存模式认为命名空间必须显式创建。
func (m *MemoryStore) NamespaceExists(_ context.Context, namespace string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.namespaces[namespace]
	return ok, nil
}

// Ping 内存存储恒定可用。
func (m *MemoryStore) Ping(_ context.Context) error {
	return nil
}

// ReserveIdempotency 记录幂等键，重复返回 false。
func (m *MemoryStore) ReserveIdempotency(_ context.Context, scope, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	full := scope + "|" + key
	if _, ok := m.idemKeys[full]; ok {
		return false, nil
	}
	m.idemKeys[full] = time.Now()
	return true, nil
}

// SaveIdempotencyResponse 更新幂等键响应。
func (m *MemoryStore) SaveIdempotencyResponse(_ context.Context, scope, key string, resp map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idemResp[scope+"|"+key] = resp
	m.metrics["idempotency_saved"]++
	return nil
}

// GetIdempotencyResponse 读取幂等键响应。
func (m *MemoryStore) GetIdempotencyResponse(_ context.Context, scope, key string) (map[string]any, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if resp, ok := m.idemResp[scope+"|"+key]; ok {
		return resp, true, nil
	}
	_, ok := m.idemKeys[scope+"|"+key]
	return nil, ok, nil
}

// UpdateQuota 更新配额，返回是否允许。
func (m *MemoryStore) UpdateQuota(_ context.Context, policyID int64, actor, namespace, resource, action string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil
	}
	key := fmt.Sprintf("%d|%s|%s|%s|%s", policyID, actor, namespace, resource, action)
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.quota[key]
	if !ok || now.After(rec.exp) {
		m.quota[key] = quotaRecord{used: 1, exp: now.Add(window)}
		return true, nil
	}
	if rec.used >= limit {
		return false, nil
	}
	rec.used++
	m.quota[key] = rec
	m.metrics["quota_calls"]++
	return true, nil
}

// ResetQuotas 清理配额记录，支持按命名空间治理。
func (m *MemoryStore) ResetQuotas(_ context.Context, namespace string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if namespace == "" {
		m.quota = make(map[string]quotaRecord)
		return nil
	}
	for k := range m.quota {
		if strings.Contains(k, "|"+namespace+"|") {
			delete(m.quota, k)
		}
	}
	return nil
}

// Metrics 返回内存存储的指标快照。
func (m *MemoryStore) Metrics() map[string]int64 {
	out := make(map[string]int64, len(m.metrics))
	for k, v := range m.metrics {
		out[k] = v
	}
	return out
}

// CreateNamespace 创建命名空间（存在时忽略）。
func (m *MemoryStore) CreateNamespace(_ context.Context, namespace, desc string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if namespace == "" {
		return fmt.Errorf("命名空间不能为空")
	}
	if _, ok := m.namespaces[namespace]; !ok {
		m.namespaces[namespace] = desc
	}
	return nil
}

// ListNamespaces 返回全部命名空间名称。
func (m *MemoryStore) ListNamespaces(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]string, 0, len(m.namespaces))
	for ns := range m.namespaces {
		res = append(res, ns)
	}
	return res, nil
}

// Close 内存实现无资源需关闭。
func (m *MemoryStore) Close() error {
	return nil
}

// 确保实现接口。
var _ Store = (*MemoryStore)(nil)
