package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"config_center/internal/model"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLStore 基于 MySQL 8.0 的存储实现，对应 databases/config_center_schema.sql。
type MySQLStore struct {
	db *sql.DB
}

// NewMySQLStore 初始化 MySQL 连接。
func NewMySQLStore(dsn string) (*MySQLStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("连接 MySQL 失败: %w", err)
	}
	db.SetConnMaxLifetime(time.Minute * 5)
	db.SetConnMaxIdleTime(time.Minute * 5)
	db.SetMaxIdleConns(5)
	db.SetMaxOpenConns(20)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("MySQL ping 失败: %w", err)
	}
	return &MySQLStore{db: db}, nil
}

// Ping 提供健康检查。
func (m *MySQLStore) Ping(ctx context.Context) error {
	return m.db.PingContext(ctx)
}

func (m *MySQLStore) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

func (m *MySQLStore) AppendSecretVersion(ctx context.Context, sv *model.SecretVersion) (int, error) {
	now := time.Now()
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	nsID, err := m.ensureNamespace(ctx, tx, sv.Namespace)
	if err != nil {
		return 0, err
	}
	var nextVersion int
	err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(version),0)+1 FROM secrets WHERE namespace_id=? AND name=?", nsID, sv.Name).Scan(&nextVersion)
	if err != nil {
		return 0, err
	}
	labelsJSON, _ := json.Marshal(sv.Labels)
	var expireVal any
	if sv.ExpireAt != nil {
		expireVal = *sv.ExpireAt
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO secrets(namespace_id,name,version,ciphertext,key_id,labels,status,expire_at,created_by,updated_by,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		nsID, sv.Name, nextVersion, sv.Ciphertext, sv.KeyID, labelsJSON, sv.Status, expireVal, sv.CreatedBy, sv.UpdatedBy, now, now)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	sv.Version = nextVersion
	sv.CreatedAt = now
	sv.UpdatedAt = now
	return nextVersion, nil
}

func (m *MySQLStore) FindActive(ctx context.Context, namespace, name string) (*model.SecretVersion, error) {
	return m.fetchOne(ctx, namespace, name, "active", 0)
}

func (m *MySQLStore) FindByVersion(ctx context.Context, namespace, name string, version int) (*model.SecretVersion, error) {
	return m.fetchOne(ctx, namespace, name, "", version)
}

func (m *MySQLStore) Latest(ctx context.Context, namespace, name string) (*model.SecretVersion, error) {
	row := m.db.QueryRowContext(ctx, `
SELECT n.namespace,s.name,s.version,s.ciphertext,s.key_id,s.labels,s.status,s.expire_at,s.created_by,s.updated_by,s.created_at,s.updated_at
FROM secrets s
JOIN namespaces n ON n.id = s.namespace_id
WHERE n.namespace=? AND s.name=?
ORDER BY s.version DESC LIMIT 1`, namespace, name)
	return scanSecret(row)
}

func (m *MySQLStore) ListVersions(ctx context.Context, namespace, name string) ([]*model.SecretVersion, error) {
	rows, err := m.db.QueryContext(ctx, `
SELECT n.namespace,s.name,s.version,s.ciphertext,s.key_id,s.labels,s.status,s.expire_at,s.created_by,s.updated_by,s.created_at,s.updated_at
FROM secrets s
JOIN namespaces n ON n.id = s.namespace_id
WHERE n.namespace=? AND s.name=?
ORDER BY s.version ASC`, namespace, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var res []*model.SecretVersion
	for rows.Next() {
		sv, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		res = append(res, sv)
	}
	return res, rows.Err()
}

func (m *MySQLStore) SetActive(ctx context.Context, namespace, name string, version int, actor string) (*model.SecretVersion, *model.SecretVersion, error) {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	nsID, err := m.ensureNamespace(ctx, tx, namespace)
	if err != nil {
		return nil, nil, err
	}
	// 找到目标版本与当前 active
	var targetID int64
	err = tx.QueryRowContext(ctx, "SELECT id FROM secrets WHERE namespace_id=? AND name=? AND version=?", nsID, name, version).Scan(&targetID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("未找到版本 %d", version)
	}
	if err != nil {
		return nil, nil, err
	}
	var oldActiveVersion *int
	err = tx.QueryRowContext(ctx, "SELECT version FROM secrets WHERE namespace_id=? AND name=? AND status='active' ORDER BY version DESC LIMIT 1", nsID, name).Scan(&oldActiveVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	now := time.Now()
	// 更新状态
	if _, err := tx.ExecContext(ctx, "UPDATE secrets SET status='deprecated', updated_at=?, updated_by=? WHERE namespace_id=? AND name=? AND status='active'", now, actor, nsID, name); err != nil {
		return nil, nil, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE secrets SET status='active', updated_at=?, updated_by=? WHERE id=?", now, actor, targetID); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	newActive, _ := m.FindByVersion(ctx, namespace, name, version)
	var oldActive *model.SecretVersion
	if oldActiveVersion != nil {
		oldActive, _ = m.FindByVersion(ctx, namespace, name, *oldActiveVersion)
	}
	return newActive, oldActive, nil
}

func (m *MySQLStore) RecordAudit(ctx context.Context, a *model.AuditLog) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	_, err := m.db.ExecContext(ctx, `
INSERT INTO audit_logs(namespace,name,action,actor,client_ip,version,result,detail,signature,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`,
		a.Namespace, a.Name, a.Action, a.Actor, a.ClientIP, a.Version, a.Result, a.Detail, a.Signature, a.CreatedAt)
	return err
}

func (m *MySQLStore) ListAudits(ctx context.Context, filter model.AuditQueryRequest) ([]*model.AuditLog, error) {
	query := `SELECT namespace,name,action,actor,client_ip,version,result,detail,created_at FROM audit_logs WHERE 1=1`
	args := make([]any, 0)
	if filter.Namespace != "" {
		query += " AND namespace=?"
		args = append(args, filter.Namespace)
	}
	if filter.Name != "" {
		query += " AND name=?"
		args = append(args, filter.Name)
	}
	if filter.Action != "" {
		query += " AND action=?"
		args = append(args, filter.Action)
	}
	if filter.Result != "" {
		query += " AND result=?"
		args = append(args, filter.Result)
	}
	if !filter.From.IsZero() {
		query += " AND created_at>=?"
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		query += " AND created_at<=?"
		args = append(args, filter.To)
	}
	query += " ORDER BY created_at DESC"
	if filter.PageSize <= 0 || filter.PageSize > 500 {
		filter.PageSize = 100
	}
	offset := 0
	if filter.Page > 1 {
		offset = (filter.Page - 1) * filter.PageSize
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", filter.PageSize, offset)

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var res []*model.AuditLog
	for rows.Next() {
		var detail sql.NullString
		a := &model.AuditLog{}
		if err := rows.Scan(&a.Namespace, &a.Name, &a.Action, &a.Actor, &a.ClientIP, &a.Version, &a.Result, &detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		if detail.Valid {
			a.Detail = detail.String
		}
		res = append(res, a)
	}
	return res, rows.Err()
}

func (m *MySQLStore) AddPolicy(ctx context.Context, p *model.Policy) (*model.Policy, error) {
	now := time.Now()
	subjectsJSON, _ := json.Marshal(p.Subjects)
	resourcesJSON, _ := json.Marshal(p.Resources)
	actionsJSON, _ := json.Marshal(p.Actions)
	conditionsJSON, _ := json.Marshal(p.Conditions)
	r, err := m.db.ExecContext(ctx, `
INSERT INTO policies(name,namespace,subjects,resources,actions,effect,conditions,created_by,created_at)
VALUES(?,?,?,?,?,?,?,?,?)`,
		p.Name, p.Namespace, subjectsJSON, resourcesJSON, actionsJSON, p.Effect, conditionsJSON, p.CreatedBy, now)
	if err != nil {
		return nil, err
	}
	id, _ := r.LastInsertId()
	p.ID = id
	p.CreatedAt = now
	return p, nil
}

func (m *MySQLStore) ListPolicies(ctx context.Context, namespace string) ([]*model.Policy, error) {
	query := "SELECT id,name,namespace,subjects,resources,actions,effect,conditions,created_by,created_at FROM policies"
	args := make([]any, 0)
	if namespace != "" {
		query += " WHERE namespace=?"
		args = append(args, namespace)
	}
	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var res []*model.Policy
	for rows.Next() {
		var subjects, resources, actions, conditions []byte
		p := &model.Policy{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Namespace, &subjects, &resources, &actions, &p.Effect, &conditions, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(subjects, &p.Subjects)
		_ = json.Unmarshal(resources, &p.Resources)
		_ = json.Unmarshal(actions, &p.Actions)
		if len(conditions) > 0 {
			_ = json.Unmarshal(conditions, &p.Conditions)
		}
		res = append(res, p)
	}
	return res, rows.Err()
}

func (m *MySQLStore) HasPolicies(ctx context.Context) (bool, error) {
	var count int
	if err := m.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM policies").Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (m *MySQLStore) NamespaceExists(ctx context.Context, namespace string) (bool, error) {
	var count int
	err := m.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM namespaces WHERE namespace=?", namespace).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ensureNamespace 返回命名空间 ID，生产模式要求预先创建命名空间。
func (m *MySQLStore) ensureNamespace(ctx context.Context, tx *sql.Tx, namespace string) (int64, error) {
	var id int64
	err := tx.QueryRowContext(ctx, "SELECT id FROM namespaces WHERE namespace=?", namespace).Scan(&id)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("命名空间 %s 不存在，请先创建", namespace)
	}
	return 0, err
}

// fetchOne 按状态或版本读取单条密钥。
func (m *MySQLStore) fetchOne(ctx context.Context, namespace, name string, status string, version int) (*model.SecretVersion, error) {
	query := `
SELECT n.namespace,s.name,s.version,s.ciphertext,s.key_id,s.labels,s.status,s.expire_at,s.created_by,s.updated_by,s.created_at,s.updated_at
FROM secrets s
JOIN namespaces n ON n.id = s.namespace_id
WHERE n.namespace=? AND s.name=?`
	args := []any{namespace, name}
	if status != "" {
		query += " AND s.status=?"
		args = append(args, status)
	}
	if version > 0 {
		query += " AND s.version=?"
		args = append(args, version)
	}
	query += " ORDER BY s.version DESC LIMIT 1"
	row := m.db.QueryRowContext(ctx, query, args...)
	sv, err := scanSecret(row)
	if err != nil {
		return nil, err
	}
	return sv, nil
}

func scanSecret(scanner interface {
	Scan(dest ...any) error
}) (*model.SecretVersion, error) {
	sv := &model.SecretVersion{}
	var labelsRaw []byte
	var expire sql.NullTime
	if err := scanner.Scan(&sv.Namespace, &sv.Name, &sv.Version, &sv.Ciphertext, &sv.KeyID, &labelsRaw, &sv.Status, &expire, &sv.CreatedBy, &sv.UpdatedBy, &sv.CreatedAt, &sv.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	if len(labelsRaw) > 0 {
		_ = json.Unmarshal(labelsRaw, &sv.Labels)
	}
	if expire.Valid {
		sv.ExpireAt = &expire.Time
	}
	return sv, nil
}

// 确保实现接口。
var _ Store = (*MySQLStore)(nil)
