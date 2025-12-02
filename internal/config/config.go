package config

import (
	"log"
	"os"
	"strings"
)

// Config 统一管理服务运行所需配置，便于切换内存/数据库与安全策略。
type Config struct {
	Addr              string   // 监听地址，默认 :8080
	DBDriver          string   // memory 或 mysql
	MySQLDSN          string   // MySQL 连接串
	TLSCertFile       string   // 服务端证书路径
	TLSKeyFile        string   // 服务端私钥路径
	TLSClientCA       string   // 客户端 CA 证书，用于 mTLS
	RequireClientCert bool     // 是否强制校验客户端证书
	BearerToken       string   // 可选静态 Bearer Token 校验
	OIDCPublicKey     string   // OIDC 公钥 (PEM)，用于 JWT 验签（静态）
	OIDCJWKSURL       string   // OIDC JWKS 地址，动态拉取公钥
	OIDCAudience      string   // OIDC 期望 audience
	KMSProvider       string   // KMS 提供商: local, aliyun
	BootstrapSubjects []string // 初始允许全权限的主体列表，便于冷启动配置策略
	RequestLogSample  bool     // 是否输出简单访问日志
	AuditHMACKey      string   // 审计日志 HMAC 签名密钥（Base64）
}

// Load 从环境变量加载配置。
func Load() Config {
	cfg := Config{
		Addr:              getenvOrDefault("ADDR", ":8080"),
		DBDriver:          strings.ToLower(getenvOrDefault("DB_DRIVER", "mysql")),
		MySQLDSN:          os.Getenv("MYSQL_DSN"),
		TLSCertFile:       os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:        os.Getenv("TLS_KEY_FILE"),
		TLSClientCA:       os.Getenv("TLS_CLIENT_CA"),
		RequireClientCert: strings.ToLower(os.Getenv("TLS_REQUIRE_CLIENT_CERT")) == "true",
		BearerToken:       os.Getenv("AUTH_BEARER_TOKEN"),
		OIDCPublicKey:     os.Getenv("OIDC_PUBLIC_KEY"),
		OIDCJWKSURL:       os.Getenv("OIDC_JWKS_URL"),
		OIDCAudience:      os.Getenv("OIDC_AUDIENCE"),
		KMSProvider:       strings.ToLower(getenvOrDefault("KMS_PROVIDER", "local")),
		RequestLogSample:  strings.ToLower(os.Getenv("REQUEST_LOG")) == "true",
		AuditHMACKey:      os.Getenv("AUDIT_HMAC_KEY"),
	}
	bootstrap := os.Getenv("AUTH_BOOTSTRAP_SUBJECTS")
	if bootstrap == "" {
		cfg.BootstrapSubjects = []string{"demo-cli"}
	} else {
		cfg.BootstrapSubjects = splitAndTrim(bootstrap)
	}
	return cfg
}

func getenvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitAndTrim(val string) []string {
	parts := strings.Split(val, ",")
	res := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			res = append(res, t)
		}
	}
	return res
}

// Warn 如果是高风险或不完整配置，输出一次警告。
func (c Config) Warn() {
	if c.DBDriver != "mysql" {
		log.Println("警告：DB_DRIVER 必须为 mysql 才符合生产要求，请检查配置")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		log.Println("警告：未启用 TLS，传输未加密且缺少 mTLS 校验，生产环境请提供 TLS_CERT_FILE 和 TLS_KEY_FILE")
	} else if c.RequireClientCert && c.TLSClientCA == "" {
		log.Println("警告：已要求客户端证书但未配置 TLS_CLIENT_CA，无法校验客户端身份")
	}
	if c.BearerToken == "" && c.OIDCPublicKey == "" {
		log.Println("提示：未配置 AUTH_BEARER_TOKEN / OIDC_PUBLIC_KEY / OIDC_JWKS_URL，除 mTLS 外不会校验 Bearer Token，建议生产开启 OIDC")
	}
	if c.AuditHMACKey == "" {
		log.Println("提示：未配置 AUDIT_HMAC_KEY，审计日志缺少防篡改签名")
	}
}
