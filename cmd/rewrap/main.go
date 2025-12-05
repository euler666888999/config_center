package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"config_center/internal/kms"
)

// 简易重包裹工具：读取输入密文，使用当前 KMS 解密再重新加密，便于密钥轮换。
// 用法示例：
//
//	KMS_PROVIDER=aliyun KMS_KEY_ID=xxx ALIBABA_CLOUD_* go run cmd/rewrap/main.go -cipher "<base64_cipher>"
//
// main 执行重包裹流程：解析参数、调用 KMS 解密并重新加密输出。
func main() {
	cipher := flag.String("cipher", "", "需要重包裹的密文（Base64）")
	outFile := flag.String("out", "", "输出到文件，留空则打印")
	batchFile := flag.String("batch", "", "JSON 行批量密文输入文件，每行 {\"name\":\"...\",\"ciphertext\":\"...\"}")
	webhook := flag.String("webhook", "", "重包裹完成后回调 URL，POST JSON 结果（可用于告警/审计）")
	flag.Parse()
	if *cipher == "" && *batchFile == "" {
		log.Fatal("必须提供 -cipher 或 -batch")
	}

	kmsClient, err := buildKMS()
	if err != nil {
		log.Fatalf("初始化 KMS 失败: %v", err)
	}
	var result any
	if *batchFile != "" {
		res, err := rewrapBatch(kmsClient, *batchFile)
		if err != nil {
			log.Fatalf("批量重包裹失败: %v", err)
		}
		result = res
		if err := writeOut(res, *outFile); err != nil {
			log.Fatalf("写出失败: %v", err)
		}
	} else {
		plaintext, err := kmsClient.Decrypt(*cipher)
		if err != nil {
			log.Fatalf("解密失败，可能使用了旧 key: %v", err)
		}
		newCipher, err := kmsClient.Encrypt(plaintext)
		if err != nil {
			log.Fatalf("重包裹失败: %v", err)
		}
		payload := map[string]string{"ciphertext": newCipher}
		result = payload
		if err := writeOut(payload, *outFile); err != nil {
			log.Fatalf("写出失败: %v", err)
		}
	}
	if *webhook != "" && result != nil {
		notifyWebhook(*webhook, result)
	}
}

// buildKMS 根据环境变量选择并初始化对应的 KMS 客户端。
func buildKMS() (kms.KMS, error) {
	switch os.Getenv("KMS_PROVIDER") {
	case "aliyun":
		return kms.NewAliyunKMS()
	case "local":
		if path := os.Getenv("KMS_MASTER_KEY_FILE"); path != "" {
			return kms.NewLocalKMSFromFile(path)
		}
		key := os.Getenv("KMS_MASTER_KEY")
		if key == "" {
			return nil, fmt.Errorf("local KMS 需配置 KMS_MASTER_KEY 或 KMS_MASTER_KEY_FILE")
		}
		return kms.NewLocalKMS(key)
	default:
		return nil, fmt.Errorf("不支持的 KMS_PROVIDER")
	}
}

// rewrapBatch 批量重包裹，读入 JSON 行格式。
func rewrapBatch(k kms.KMS, inFile string) ([]map[string]string, error) {
	data, err := os.ReadFile(inFile)
	if err != nil {
		return nil, fmt.Errorf("读取批量文件失败: %w", err)
	}
	lines := bytes.Split(data, []byte("\n"))
	out := make([]map[string]string, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var item struct {
			Name       string `json:"name"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.Unmarshal(line, &item); err != nil {
			return nil, fmt.Errorf("解析行失败: %w", err)
		}
		plain, err := k.Decrypt(item.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("解密 %s 失败: %w", item.Name, err)
		}
		newCipher, err := k.Encrypt(plain)
		if err != nil {
			return nil, fmt.Errorf("重包裹 %s 失败: %w", item.Name, err)
		}
		out = append(out, map[string]string{
			"name":       item.Name,
			"ciphertext": newCipher,
			"ts":         time.Now().Format(time.RFC3339Nano),
		})
	}
	return out, nil
}

func writeOut(v any, outFile string) error {
	if outFile == "" {
		out, _ := json.Marshal(v)
		fmt.Println(string(out))
		return nil
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return os.WriteFile(outFile, b, 0600)
}

func notifyWebhook(url string, payload any) {
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Webhook 通知失败: %v", err)
		return
	}
	resp.Body.Close()
}
