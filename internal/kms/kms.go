package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// KMS 定义密钥管理服务接口。
type KMS interface {
	// Encrypt 加密数据。
	Encrypt(plaintext []byte) (string, error)
	// Decrypt 解密数据。
	Decrypt(ciphertext string) ([]byte, error)
}

// LocalKMS 提供本地 AES-GCM 包裹的简易 KMS，生产环境应替换为真实 KMS/HSM。
type LocalKMS struct {
	masterKey []byte
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
	return &LocalKMS{masterKey: key}, nil
}

// Encrypt 封装数据，返回 Base64 编码的密文。
func (k *LocalKMS) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(k.masterKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解封装密文。
func (k *LocalKMS) Decrypt(ciphertext string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
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
		return nil, errors.New("密文长度不足")
	}
	nonce := raw[:gcm.NonceSize()]
	data := raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, nil)
}

// CloudKMS 云厂商 KMS 存根实现。
type CloudKMS struct {
	provider string
	region   string
}

// NewCloudKMS 创建云 KMS 客户端存根。
func NewCloudKMS(provider, region string) *CloudKMS {
	return &CloudKMS{
		provider: provider,
		region:   region,
	}
}

func (c *CloudKMS) Encrypt(plaintext []byte) (string, error) {
	// TODO: 对接真实云厂商 SDK (如 Aliyun KMS / AWS KMS)
	return "", fmt.Errorf("CloudKMS (%s) 尚未实现", c.provider)
}

func (c *CloudKMS) Decrypt(ciphertext string) ([]byte, error) {
	// TODO: 对接真实云厂商 SDK
	return nil, fmt.Errorf("CloudKMS (%s) 尚未实现", c.provider)
}
