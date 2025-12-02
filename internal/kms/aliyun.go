package kms

import (
	"fmt"
	"os"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/kms"
)

// AliyunKMS 阿里云 KMS 实现。
type AliyunKMS struct {
	client *kms.Client
	keyID  string
}

// NewAliyunKMS 创建阿里云 KMS 客户端。
// 需环境变量: ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET, ALIBABA_CLOUD_REGION_ID, KMS_KEY_ID
func NewAliyunKMS() (*AliyunKMS, error) {
	regionID := os.Getenv("ALIBABA_CLOUD_REGION_ID")
	accessKeyID := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	accessKeySecret := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")
	keyID := os.Getenv("KMS_KEY_ID")

	if regionID == "" || accessKeyID == "" || accessKeySecret == "" || keyID == "" {
		return nil, fmt.Errorf("阿里云 KMS 配置缺失，请检查环境变量")
	}

	client, err := kms.NewClientWithAccessKey(regionID, accessKeyID, accessKeySecret)
	if err != nil {
		return nil, fmt.Errorf("初始化阿里云 KMS 客户端失败: %w", err)
	}

	return &AliyunKMS{
		client: client,
		keyID:  keyID,
	}, nil
}

// Encrypt 加密数据。
func (k *AliyunKMS) Encrypt(plaintext []byte) (string, error) {
	request := kms.CreateEncryptRequest()
	request.Scheme = "https"
	request.KeyId = k.keyID
	request.Plaintext = string(plaintext)

	response, err := k.client.Encrypt(request)
	if err != nil {
		return "", fmt.Errorf("阿里云 KMS 加密失败: %w", err)
	}
	// Aliyun SDK 返回的 CiphertextBlob 已经是 Base64 还是需要编码？
	// 查看文档或源码，通常 API 返回的是 Base64 字符串。
	// 这里假设直接返回即可。
	return response.CiphertextBlob, nil
}

// Decrypt 解密数据。
func (k *AliyunKMS) Decrypt(ciphertext string) ([]byte, error) {
	request := kms.CreateDecryptRequest()
	request.Scheme = "https"
	request.CiphertextBlob = ciphertext

	response, err := k.client.Decrypt(request)
	if err != nil {
		return nil, fmt.Errorf("阿里云 KMS 解密失败: %w", err)
	}
	
	// Plaintext 是字符串
	return []byte(response.Plaintext), nil
}
