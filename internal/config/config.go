package config

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

// Config 统一管理服务运行所需配置，便于切换内存/数据库与安全策略。
type Config struct {
	Addr                 string   // 监听地址，默认 :8080
	DBDriver             string   // memory 或 mysql
	MySQLDSN             string   // MySQL 连接串
	TLSCertFile          string   // 服务端证书路径
	TLSKeyFile           string   // 服务端私钥路径
	TLSClientCA          string   // 客户端 CA 证书，用于 mTLS
	RequireClientCert    bool     // 是否强制校验客户端证书
	BearerToken          string   // 可选静态 Bearer Token 校验
	OIDCPublicKey        string   // OIDC 公钥 (PEM)，用于 JWT 验签（静态）
	OIDCJWKSURL          string   // OIDC JWKS 地址，动态拉取公钥
	OIDCAudience         string   // OIDC 期望 audience
	KMSProvider          string   // KMS 提供商: local, aliyun
	BootstrapSubjects    []string // 初始允许全权限的主体列表，便于冷启动配置策略
	RequestLogSample     bool     // 是否输出简单访问日志
	AuditHMACKey         string   // 审计日志 HMAC 签名密钥（Base64）
	IPAllowlist          []string // IP 白名单，非空时未命中拒绝
	IPBlocklist          []string // IP 黑名单，命中拒绝
	CertReloadSecs       int      // 证书轮询重载周期（秒），默认 300
	BruteForceThresh     int      // 认证失败阈值
	BruteForceBlock      int      // 认证失败封禁时间（秒）
	QuotaWindowSecs      int      // 配额窗口秒数，默认 3600
	QuotaResetSecs       int      // 配额重置周期（秒），默认 86400
	KMSRotateHours       int      // KMS 自动轮换周期（小时），0 表示不自动轮换
	AllowInsecureHTTP    bool     // 是否允许非 TLS 访问（仅开发）
	AllowInsecureActor   bool     // 是否允许使用 X-Actor 等弱身份兜底
	BootstrapEnabled     bool     // 是否启用引导命名空间/策略（生产建议关闭）
	BootstrapNamespace   string   // 引导主命名空间
	BootstrapNamespaces  []string // 引导额外命名空间
	AllowLocalKMS        bool     // 是否允许 LocalKMS
	AllowAdminRewrap     bool     // 是否允许 /v1/admin/rewrap 接口（生产默认关闭）
	Environment          string   // 环境标识：dev/stage/prod
	EnableSecurityChecks bool     // 是否启用安全配置校验（测试可关闭）
	AllowDevWeakKMSKey   bool     // 是否允许在开发/测试使用内置弱 KMS 密钥（生产禁止）
}

// Load 从环境变量加载配置。
func Load() Config {
	loadDotEnv()
	env := strings.ToLower(getenvOrDefault("ENV", getenvOrDefault("APP_ENV", "dev")))
	// 根据环境选择默认值：非 prod 默认放宽以便开发启动，prod 默认为安全值。
	defAllowInsecureHTTP := "false"
	defAllowInsecureActor := "false"
	defAllowLocalKMS := "false"
	defAllowDevWeakKey := "false"
	defSecurityChecks := "true"
	if env != "prod" {
		defAllowInsecureHTTP = "true"
		defAllowInsecureActor = "true"
		defAllowLocalKMS = "true"
		defAllowDevWeakKey = "true"
		defSecurityChecks = "false"
	}
	cfg := Config{
		Addr:                 getenvOrDefault("ADDR", ":8080"),
		DBDriver:             strings.ToLower(getenvOrDefault("DB_DRIVER", "mysql")),
		MySQLDSN:             os.Getenv("MYSQL_DSN"),
		TLSCertFile:          os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:           os.Getenv("TLS_KEY_FILE"),
		TLSClientCA:          os.Getenv("TLS_CLIENT_CA"),
		RequireClientCert:    strings.ToLower(os.Getenv("TLS_REQUIRE_CLIENT_CERT")) == "true",
		BearerToken:          os.Getenv("AUTH_BEARER_TOKEN"),
		OIDCPublicKey:        os.Getenv("OIDC_PUBLIC_KEY"),
		OIDCJWKSURL:          os.Getenv("OIDC_JWKS_URL"),
		OIDCAudience:         os.Getenv("OIDC_AUDIENCE"),
		KMSProvider:          strings.ToLower(getenvOrDefault("KMS_PROVIDER", "local")),
		RequestLogSample:     strings.ToLower(os.Getenv("REQUEST_LOG")) == "true",
		AuditHMACKey:         os.Getenv("AUDIT_HMAC_KEY"),
		IPAllowlist:          splitAndTrim(os.Getenv("IP_ALLOWLIST")),
		IPBlocklist:          splitAndTrim(os.Getenv("IP_BLOCKLIST")),
		AllowInsecureHTTP:    strings.ToLower(getenvOrDefault("ALLOW_INSECURE_HTTP", defAllowInsecureHTTP)) == "true",
		AllowInsecureActor:   strings.ToLower(getenvOrDefault("ALLOW_INSECURE_ACTOR", defAllowInsecureActor)) == "true",
		BootstrapEnabled:     strings.ToLower(getenvOrDefault("BOOTSTRAP_ENABLED", "false")) == "true",
		BootstrapNamespace:   getenvOrDefault("BOOTSTRAP_NAMESPACE", "default"),
		AllowLocalKMS:        strings.ToLower(getenvOrDefault("ALLOW_LOCAL_KMS", defAllowLocalKMS)) == "true",
		AllowAdminRewrap:     strings.ToLower(getenvOrDefault("ALLOW_ADMIN_REWRAP", "false")) == "true",
		Environment:          env,
		EnableSecurityChecks: strings.ToLower(getenvOrDefault("SECURITY_CHECKS_ENABLED", defSecurityChecks)) == "true",
		AllowDevWeakKMSKey:   strings.ToLower(getenvOrDefault("ALLOW_DEV_WEAK_KMS_KEY", defAllowDevWeakKey)) == "true",
	}
	cfg.CertReloadSecs = intFromEnv("CERT_RELOAD_SECS", 300)
	cfg.BruteForceThresh = intFromEnv("AUTH_BRUTE_FORCE_THRESHOLD", 5)
	cfg.BruteForceBlock = intFromEnv("AUTH_BRUTE_FORCE_BLOCK", 600)
	cfg.QuotaWindowSecs = intFromEnv("QUOTA_WINDOW_SECS", 3600)
	cfg.QuotaResetSecs = intFromEnv("QUOTA_RESET_SECS", 86400)
	cfg.KMSRotateHours = intFromEnv("KMS_ROTATE_INTERVAL_HOURS", 0)
	bootstrap := os.Getenv("AUTH_BOOTSTRAP_SUBJECTS")
	if bootstrap == "" {
		cfg.BootstrapSubjects = []string{"demo-cli"}
	} else {
		cfg.BootstrapSubjects = splitAndTrim(bootstrap)
	}
	namespaces := os.Getenv("BOOTSTRAP_NAMESPACES")
	if namespaces == "" {
		cfg.BootstrapNamespaces = []string{"default", "test-ns"}
	} else {
		cfg.BootstrapNamespaces = splitAndTrim(namespaces)
	}
	return cfg
}

// loadDotEnv 尝试加载项目根目录 .env 文件，便于开发无需手动 export。
// 若环境变量已存在，不会覆盖现有值。
func loadDotEnv() {
	paths := make([]string, 0, 6)
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 5; i++ {
			paths = append(paths, dir+"/.env")
			parent := strings.TrimSuffix(dir, "/")
			if parent == dir || parent == "" {
				break
			}
			if idx := strings.LastIndex(parent, "/"); idx >= 0 {
				dir = parent[:idx]
			} else {
				dir = parent
			}
		}
	} else {
		paths = append(paths, ".env")
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = stripQuotes(val)
			if key == "" {
				continue
			}
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
			_ = os.Setenv(key, val)
		}
		f.Close()
		break
	}
}

// getenvOrDefault 读取环境变量，若未设置则返回默认值。
func getenvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// intFromEnv 读取整型环境变量，解析失败返回默认值。
func intFromEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if iv, err := strconv.Atoi(v); err == nil {
			return iv
		}
	}
	return def
}

// splitAndTrim 以逗号分隔字符串并去除空白，返回非空段列表。
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

// stripQuotes 去掉成对的单/双引号，兼容 .env 中包裹的值。
func stripQuotes(val string) string {
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			return val[1 : len(val)-1]
		}
	}
	return val
}

// Warn 如果是高风险或不完整配置，输出一次警告。
func (c Config) Warn() {
	if !c.EnableSecurityChecks {
		log.Println("提示：SECURITY_CHECKS_ENABLED=false，已跳过安全配置校验，仅限开发/测试使用")
		return
	}
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
	if c.AllowInsecureHTTP {
		log.Println("警告：ALLOW_INSECURE_HTTP 已开启，仅用于开发调试，生产请关闭")
	}
	if c.AllowInsecureActor {
		log.Println("警告：ALLOW_INSECURE_ACTOR 已开启，允许未认证的 X-Actor，生产请关闭")
	}
	if c.BootstrapEnabled {
		log.Println("提示：BOOTSTRAP_ENABLED 已开启，仅建议开发/首启使用，生产请关闭并走审批化最小权限策略")
	}
	if c.AllowAdminRewrap {
		log.Println("提示：ALLOW_ADMIN_REWRAP 已开启，允许后台重包裹 API，生产建议仅在受控窗口开启且有审批/工单")
	}
	if c.Environment == "prod" {
		if c.BootstrapEnabled {
			log.Fatal("生产环境禁止开启 BOOTSTRAP_ENABLED")
		}
		if c.AllowInsecureHTTP || c.AllowInsecureActor {
			log.Fatal("生产环境禁止开启 ALLOW_INSECURE_HTTP/ALLOW_INSECURE_ACTOR")
		}
		if c.AllowLocalKMS {
			log.Fatal("生产环境禁止 ALLOW_LOCAL_KMS")
		}
		if c.AllowAdminRewrap {
			log.Fatal("生产环境禁止默认开启 ALLOW_ADMIN_REWRAP，请在审批窗口显式开启")
		}
	}
}
