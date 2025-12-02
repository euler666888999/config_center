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

// EnvelopeKMS 提供本地 AES-GCM 包裹的简易 KMS，生产环境应替换为真实 KMS/HSM。
type EnvelopeKMS struct {
	masterKey []byte
}

// NewEnvelopeKMS 从 Base64 master key 创建实例，key 长度需为 32 字节（AES-256）。
func NewEnvelopeKMS(base64Key string) (*EnvelopeKMS, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("解码 KMS_MASTER_KEY 失败: %w", err)
	}
	if len(key) != 32 {
		return nil, errors.New("KMS_MASTER_KEY 长度必须为 32 字节（Base64 后长度 44）")
	}
	return &EnvelopeKMS{masterKey: key}, nil
}

// Encrypt 封装数据，返回 Base64 编码的密文。
func (k *EnvelopeKMS) Encrypt(plaintext []byte) (string, error) {
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
func (k *EnvelopeKMS) Decrypt(ciphertext string) ([]byte, error) {
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
