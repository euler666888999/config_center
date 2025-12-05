package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	aliyun "github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

// AliyunKMS 阿里云 KMS 实现，内置数据密钥缓存、备份加密与轮换调用。
type AliyunKMS struct {
	client      *aliyun.Client
	keyID       string
	backupKeyID string
	cache       *sessionCache
	dataKeyTTL  time.Duration
	metrics     map[string]int64
	mu          sync.Mutex
	lastRotate  time.Time
}

// NewAliyunKMS 创建阿里云 KMS 客户端。
// 需环境变量: ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET, ALIBABA_CLOUD_REGION_ID, KMS_KEY_ID
// 可选: KMS_BACKUP_KEY_ID 用于备份包裹 data key；KMS_DATAKEY_TTL_SECONDS 控制缓存窗口。
func NewAliyunKMS() (*AliyunKMS, error) {
	regionID := os.Getenv("ALIBABA_CLOUD_REGION_ID")
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	keyID := os.Getenv("KMS_KEY_ID")
	backupKeyID := os.Getenv("KMS_BACKUP_KEY_ID")

	if regionID == "" || accessKeyID == "" || accessKeySecret == "" || keyID == "" {
		return nil, fmt.Errorf("阿里云 KMS 配置缺失，请检查环境变量")
	}

	client, err := aliyun.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云 KMS 客户端失败: %w", err)
	}

	return &AliyunKMS{
		client:      client,
		keyID:       keyID,
		backupKeyID: backupKeyID,
		cache:       newSessionCache(),
		dataKeyTTL:  parseDurationSeconds("KMS_DATAKEY_TTL_SECONDS", 300),
		metrics:     make(map[string]int64),
	}, nil
}

// Encrypt 生成数据密钥并使用 AES-GCM 进行信封加密，支持备份 key 双重包裹。
func (k *AliyunKMS) Encrypt(plaintext []byte) (string, error) {
	k.metric("encrypt_calls", 1)
	dataKeyPlain, dataKeyCipher, err := k.getDataKey()
	if err != nil {
		k.metric("encrypt_fail", 1)
		return "", err
	}
	block, err := aes.NewCipher(dataKeyPlain)
	if err != nil {
		k.metric("encrypt_fail", 1)
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		k.metric("encrypt_fail", 1)
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		k.metric("encrypt_fail", 1)
		return "", err
	}
	payload := gcm.Seal(nil, nonce, plaintext, nil)

	env := envelope{
		DataKeyCipher: dataKeyCipher,
		Nonce:         base64.StdEncoding.EncodeToString(nonce),
		Payload:       base64.StdEncoding.EncodeToString(payload),
		KeyID:         k.keyID,
		CreatedAt:     time.Now().Unix(),
	}
	if k.backupKeyID != "" {
		if backupCipher, err := k.wrapBackupKey(dataKeyPlain); err == nil {
			env.BackupKeyCipher = backupCipher
		} else {
			k.metric("backup_wrap_fail", 1)
		}
	}
	raw, _ := json.Marshal(env)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt 解密密文：优先使用主 Key 解包数据密钥，失败时降级使用备份 Key。
func (k *AliyunKMS) Decrypt(ciphertext string) ([]byte, error) {
	k.metric("decrypt_calls", 1)
	rawCipher, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(rawCipher, &env); err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	cacheKey := "dec:" + env.DataKeyCipher
	var dataKey []byte
	if val, ok := k.cache.get(cacheKey); ok {
		dataKey = val
		k.metric("decrypt_cache_hit", 1)
	} else {
		dataKey, err = k.decryptDataKey(env.DataKeyCipher, "")
		if err != nil && env.BackupKeyCipher != "" {
			dataKey, err = k.decryptDataKey(env.BackupKeyCipher, k.backupKeyID)
		}
		if err != nil {
			k.metric("decrypt_fail", 1)
			return nil, fmt.Errorf("阿里云 KMS 解密数据密钥失败: %w", err)
		}
		k.cache.setWithTTL(cacheKey, dataKey, k.dataKeyTTL)
		k.metric("datakey_cache_miss", 1)
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		k.metric("decrypt_fail", 1)
		return nil, err
	}
	return gcm.Open(nil, nonce, payload, nil)
}

// RotateKey 启用 KMS 侧自动轮换并刷新缓存。
func (k *AliyunKMS) RotateKey() error {
	// 尝试调用通用 API 触发轮换（部分版本无封装），失败不影响后续重包裹工具。
	req := requests.NewCommonRequest()
	req.Scheme = "https"
	req.Method = "POST"
	req.ApiName = "EnableKeyRotation"
	req.Version = "2016-01-20"
	req.Product = "Kms"
	req.QueryParams["KeyId"] = k.keyID
	_, err := k.client.ProcessCommonRequest(req)
	if err != nil {
		k.metric("rotate_fail", 1)
		// 返回错误便于告警，但不阻断调用方使用
		return fmt.Errorf("调用 EnableKeyRotation 失败: %w", err)
	}
	k.cache.clear()
	k.metric("rotate_success", 1)
	k.lastRotate = time.Now()
	return nil
}

// Name 返回标识。
func (k *AliyunKMS) Name() string {
	if k.backupKeyID != "" {
		return "aliyun-kms-with-backup"
	}
	return "aliyun-kms"
}

// Metrics 汇总缓存与内部计数指标，便于外部观测。
func (k *AliyunKMS) Metrics() map[string]int64 {
	out := k.cache.metrics()
	k.mu.Lock()
	for k1, v := range k.metrics {
		out[k1] = v
	}
	if !k.lastRotate.IsZero() {
		out["last_rotate_unix"] = k.lastRotate.Unix()
	}
	k.mu.Unlock()
	return out
}

// getDataKey 返回缓存或 freshly 生成的数据密钥。
func (k *AliyunKMS) getDataKey() ([]byte, string, error) {
	if dk, ok := k.cache.get("datakey_plain"); ok {
		if cipherVal, ok2 := k.cache.get("datakey_cipher"); ok2 {
			k.metric("datakey_cache_hit", 1)
			return dk, string(cipherVal), nil
		}
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		req := aliyun.CreateGenerateDataKeyRequest()
		req.Scheme = "https"
		req.KeyId = k.keyID
		req.KeySpec = "AES_256"
		resp, err := k.client.GenerateDataKey(req)
		if err != nil {
			lastErr = err
			k.metric("datakey_retry", 1)
			time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
			continue
		}
		dkPlain, err := base64.StdEncoding.DecodeString(resp.Plaintext)
		if err != nil {
			lastErr = err
			continue
		}
		k.cache.setWithTTL("datakey_plain", dkPlain, k.dataKeyTTL)
		k.cache.setWithTTL("datakey_cipher", []byte(resp.CiphertextBlob), k.dataKeyTTL)
		k.metric("datakey_fresh", 1)
		return dkPlain, resp.CiphertextBlob, nil
	}
	return nil, "", fmt.Errorf("阿里云 KMS 生成数据密钥失败: %w", lastErr)
}

// decryptDataKey 使用指定 Key 解包 data key。
func (k *AliyunKMS) decryptDataKey(cipherBlob string, keyID string) ([]byte, error) {
	for i := 0; i < 3; i++ {
		req := aliyun.CreateDecryptRequest()
		req.Scheme = "https"
		req.CiphertextBlob = cipherBlob
		resp, err := k.client.Decrypt(req)
		if err == nil {
			return base64.StdEncoding.DecodeString(resp.Plaintext)
		}
		k.metric("decrypt_retry", 1)
		time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
	}
	return nil, fmt.Errorf("解密 data key 失败")
}

// wrapBackupKey 使用备份 Key 对 data key 再包裹一次，便于灾备。
func (k *AliyunKMS) wrapBackupKey(dataKey []byte) (string, error) {
	if k.backupKeyID == "" {
		return "", nil
	}
	req := aliyun.CreateEncryptRequest()
	req.Scheme = "https"
	req.KeyId = k.backupKeyID
	req.Plaintext = base64.StdEncoding.EncodeToString(dataKey)
	resp, err := k.client.Encrypt(req)
	if err != nil {
		return "", err
	}
	return resp.CiphertextBlob, nil
}

// metric 累加内部计数指标。
func (k *AliyunKMS) metric(key string, delta int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.metrics[key] += delta
}

// parseDurationSeconds 从环境变量读取秒级时长，非法值返回默认值。
func parseDurationSeconds(envKey string, def int) time.Duration {
	raw := os.Getenv(envKey)
	if raw == "" {
		return time.Duration(def) * time.Second
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return time.Duration(def) * time.Second
	}
	return time.Duration(v) * time.Second
}
