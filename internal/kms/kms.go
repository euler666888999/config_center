package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// KMS 定义密钥管理服务接口。
type KMS interface {
	// Encrypt 加密数据。
	Encrypt(plaintext []byte) (string, error)
	// Decrypt 解密数据。
	Decrypt(ciphertext string) ([]byte, error)
	// RotateKey 触发密钥轮换（若支持）。
	RotateKey() error
	// Name 返回 KMS 名称。
	Name() string
	// Metrics 返回简单指标，便于监控。
	Metrics() map[string]int64
}

// CachedKMS 为底层 KMS 增加会话缓存、重试与简单限流。
type CachedKMS struct {
	delegate KMS
	cache    *sessionCache
	limiter  *callLimiter
}

// NewCachedKMS 包装 KMS。
func NewCachedKMS(delegate KMS) *CachedKMS {
	return &CachedKMS{
		delegate: delegate,
		cache:    newSessionCache(),
		limiter:  newCallLimiter(50, time.Second), // 默认每秒 50 次
	}
}

// Encrypt 使用底层 KMS 加密并做简单缓存与重试，命中缓存可直接返回。
func (c *CachedKMS) Encrypt(plaintext []byte) (string, error) {
	if !c.limiter.allow() {
		c.cache.addMetric("rate_limited", 1)
		return "", errors.New("KMS 调用过于频繁，请稍后重试")
	}
	// 使用明文哈希作为缓存 key，避免明文直接作为标识
	key := hashKey(plaintext)
	if val, ok := c.cache.get(key); ok {
		return string(val), nil
	}
	var lastErr error
	for i := 0; i < 3; i++ {
		enc, err := c.delegate.Encrypt(plaintext)
		if err == nil {
			c.cache.set(key, []byte(enc))
			c.cache.addMetric("encrypt_hits", 1)
			return enc, nil
		}
		c.cache.addMetric("encrypt_retries", 1)
		lastErr = err
		time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
	}
	c.cache.addMetric("encrypt_fail", 1)
	return "", lastErr
}

// Decrypt 读取缓存或调用底层 KMS 解密，并带重试与限流。
func (c *CachedKMS) Decrypt(ciphertext string) ([]byte, error) {
	if !c.limiter.allow() {
		c.cache.addMetric("rate_limited", 1)
		return nil, errors.New("KMS 调用过于频繁，请稍后重试")
	}
	if val, ok := c.cache.get("dec:" + ciphertext); ok {
		c.cache.addMetric("decrypt_hits", 1)
		return val, nil
	}
	var lastErr error
	for i := 0; i < 3; i++ {
		dec, err := c.delegate.Decrypt(ciphertext)
		if err == nil {
			c.cache.set("dec:"+ciphertext, dec)
			return dec, nil
		}
		c.cache.addMetric("decrypt_retries", 1)
		lastErr = err
		time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
	}
	c.cache.addMetric("decrypt_fail", 1)
	return nil, lastErr
}

// RotateKey 清空缓存后调用底层 KMS 轮换。
func (c *CachedKMS) RotateKey() error {
	c.cache.clear()
	return c.delegate.RotateKey()
}

// Name 返回带缓存标识的 KMS 名称。
func (c *CachedKMS) Name() string {
	return "cached-" + c.delegate.Name()
}

// Metrics 汇总缓存与底层 KMS 的指标。
func (c *CachedKMS) Metrics() map[string]int64 {
	m := c.cache.metrics()
	// 可合并底层指标（如果有）
	for k, v := range c.delegate.Metrics() {
		m["delegate."+k] = v
	}
	return m
}

// callLimiter 简单按窗口计数。
type callLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	count   int
	resetAt time.Time
}

// newCallLimiter 创建按时间窗口限流的计数器。
func newCallLimiter(limit int, window time.Duration) *callLimiter {
	return &callLimiter{
		limit:   limit,
		window:  window,
		resetAt: time.Now().Add(window),
	}
}

// allow 判断当前调用是否在窗口限制内，超限返回 false。
func (c *callLimiter) allow() bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.After(c.resetAt) {
		c.count = 0
		c.resetAt = now.Add(c.window)
	}
	if c.count >= c.limit {
		return false
	}
	c.count++
	return true
}

// LocalKMS 提供本地 AES-GCM 包裹的简易 KMS，生产环境应替换为真实 KMS/HSM。
type LocalKMS struct {
	masterKey  []byte
	version    int
	metrics    map[string]int64
	persistKey string // 可选：持久化 master key 的文件路径
	lastRotate time.Time
}

type envelope struct {
	DataKeyCipher   string `json:"dk"`           // 主 KMS 包裹的 data key 密文
	BackupKeyCipher string `json:"bk,omitempty"` // 备份 KMS 包裹的 data key 密文，可用于主 Key 故障时解封装
	Nonce           string `json:"nonce"`
	Payload         string `json:"ct"`
	KeyID           string `json:"key,omitempty"` // 产生密文的主 Key 标识
	CreatedAt       int64  `json:"ts,omitempty"`  // 生成时间戳，便于轮换窗口判断
}

// NewLocalKMS 从 Base64 master key 创建实例，key 长度需为 32 字节（AES-256）。
func NewLocalKMS(base64Key string) (*LocalKMS, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("解码 KMS_MASTER_KEY 失败: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("KMS_MASTER_KEY 长度必须为 32 字节（Base64 后长度 44）")
	}
	return &LocalKMS{masterKey: key, version: 1, metrics: make(map[string]int64)}, nil
}

// NewLocalKMSFromFile 从文件读取 Base64 master key，不存在则生成并写入。
func NewLocalKMSFromFile(path string) (*LocalKMS, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// 不存在则生成新的 master key
		newKey := make([]byte, 32)
		if _, errGen := rand.Read(newKey); errGen != nil {
			return nil, fmt.Errorf("生成本地 KMS master key 失败: %w", errGen)
		}
		enc := base64.StdEncoding.EncodeToString(newKey)
		if errWrite := os.WriteFile(path, []byte(enc), 0600); errWrite != nil {
			return nil, fmt.Errorf("写入 master key 文件失败: %w", errWrite)
		}
		return &LocalKMS{masterKey: newKey, version: 1, metrics: make(map[string]int64), persistKey: path}, nil
	}
	base64Key := strings.TrimSpace(string(raw))
	k, err := NewLocalKMS(base64Key)
	if err != nil {
		return nil, err
	}
	k.persistKey = path
	return k, nil
}

// Encrypt 封装数据，返回 Base64 编码的密文。
func (k *LocalKMS) Encrypt(plaintext []byte) (string, error) {
	k.metrics["encrypt"]++
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		k.metrics["encrypt_err"]++
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		k.metrics["encrypt_err"]++
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解封装密文。
func (k *LocalKMS) Decrypt(ciphertext string) ([]byte, error) {
	k.metrics["decrypt"]++
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		k.metrics["decrypt_err"]++
		return nil, err
	}
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		k.metrics["decrypt_err"]++
		return nil, errors.New("密文长度不足")
	}
	nonce := raw[:gcm.NonceSize()]
	data := raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}

// RotateKey 生成新的 master key 并更新版本号，模拟本地轮换行为。
func (k *LocalKMS) RotateKey() error {
	// 仅示意：本地生成新 masterKey，实际应持久化并迁移密文
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		k.metrics["rotate_err"]++
		return err
	}
	k.masterKey = newKey
	k.version++
	if k.persistKey != "" {
		enc := base64.StdEncoding.EncodeToString(newKey)
		if err := os.WriteFile(k.persistKey, []byte(enc), 0600); err != nil {
			k.metrics["rotate_err"]++
			return fmt.Errorf("写入持久化 master key 失败: %w", err)
		}
	}
	k.metrics["rotate"]++
	k.lastRotate = time.Now()
	return nil
}

// Name 返回本地 KMS 名称与版本。
func (k *LocalKMS) Name() string {
	return fmt.Sprintf("local-v%d", k.version)
}

// Metrics 返回当前指标快照。
func (k *LocalKMS) Metrics() map[string]int64 {
	out := make(map[string]int64, len(k.metrics)+1)
	for k1, v := range k.metrics {
		out[k1] = v
	}
	if !k.lastRotate.IsZero() {
		out["last_rotate_unix"] = k.lastRotate.Unix()
	}
	return out
}

// CloudKMS 云厂商 KMS 存根实现。
type CloudKMS struct {
	provider string
	region   string
	cache    *sessionCache
}

// NewCloudKMS 创建云 KMS 客户端存根。
func NewCloudKMS(provider, region string) *CloudKMS {
	return &CloudKMS{
		provider: provider,
		region:   region,
		cache:    newSessionCache(),
	}
}

// Encrypt 作为云 KMS 存根，返回未实现错误占位。
func (c *CloudKMS) Encrypt(plaintext []byte) (string, error) {
	// TODO: 对接真实云厂商 SDK (如 Aliyun KMS / AWS KMS)，使用 data key 缓存提升性能
	return "", fmt.Errorf("CloudKMS (%s) 尚未实现", c.provider)
}

// Decrypt 作为云 KMS 存根，返回未实现错误占位。
func (c *CloudKMS) Decrypt(ciphertext string) ([]byte, error) {
	// TODO: 对接真实云厂商 SDK
	return nil, fmt.Errorf("CloudKMS (%s) 尚未实现", c.provider)
}

// RotateKey 清理缓存并提示云端轮换尚未实现。
func (c *CloudKMS) RotateKey() error {
	// TODO: 触发云 KMS 轮换，并刷新缓存
	c.cache.clear()
	return fmt.Errorf("CloudKMS (%s) 轮换未实现", c.provider)
}

// Name 返回云 KMS 的提供商名称。
func (c *CloudKMS) Name() string {
	return c.provider
}

// sessionCache 用于缓存数据密钥/会话信息，减少云 KMS 调用。
type sessionCache struct {
	mu         sync.Mutex
	data       map[string]cacheItem
	defaultTTL time.Duration
	stats      map[string]int64
}

type cacheItem struct {
	val    []byte
	expire time.Time
}

// newSessionCache 创建带默认 TTL 的缓存实例。
func newSessionCache() *sessionCache {
	return &sessionCache{
		data:       make(map[string]cacheItem),
		defaultTTL: 5 * time.Minute,
		stats:      make(map[string]int64),
	}
}

func hashKey(data []byte) string {
	h := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(h[:])
}

// get 尝试读取缓存，过期或不存在返回 false。
func (c *sessionCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	item, ok := c.data[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(item.expire) {
		delete(c.data, key)
		return nil, false
	}
	return item.val, true
}

func (c *sessionCache) set(key string, val []byte) {
	c.setWithTTL(key, val, c.defaultTTL)
}

func (c *sessionCache) setWithTTL(key string, val []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = cacheItem{val: val, expire: time.Now().Add(ttl)}
	c.stats["cache_set"]++
}

func (c *sessionCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]cacheItem)
	c.stats["cache_clear"]++
}

func (c *sessionCache) addMetric(key string, delta int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats[key] += delta
}

func (c *sessionCache) metrics() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.stats))
	for k, v := range c.stats {
		out[k] = v
	}
	return out
}
