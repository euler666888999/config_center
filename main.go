package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/server"
	"config_center/internal/store"
)

// main 启动服务，生产强制 MySQL+TLS，开发可回落内存存储/跳过 TLS。
func main() {
	cfg := config.Load()
	cfg.Warn()

	var st store.Store
	var err error
	if cfg.Environment == "prod" {
		if cfg.DBDriver != "mysql" {
			log.Fatalf("生产环境 DB_DRIVER 必须为 mysql")
		}
		if cfg.MySQLDSN == "" {
			log.Fatalf("必须提供 MYSQL_DSN 才能使用 MySQL 持久化存储")
		}
	} else if cfg.DBDriver == "memory" {
		log.Println("开发模式显式选择内存存储（仅用于测试），生产请使用 MySQL")
		st = store.NewMemoryStore()
	} else {
		if cfg.MySQLDSN == "" {
			log.Fatalf("开发/测试环境亦需配置 MYSQL_DSN（或显式设置 DB_DRIVER=memory 用于单测）")
		}
	}
	if st == nil {
		st, err = store.NewMySQLStore(cfg.MySQLDSN)
		if err != nil {
			log.Fatalf("初始化 MySQL 存储失败: %v", err)
		}
	}
	defer st.Close()

	var kmsClient kms.KMS
	var errKms error

	if cfg.KMSProvider == "local" && !cfg.AllowLocalKMS {
		log.Fatalf("禁止使用 local KMS，请在配置中显式设置 ALLOW_LOCAL_KMS=true 仅用于开发/测试，生产必须使用云 KMS")
	}
	switch cfg.KMSProvider {
	case "local":
		masterFile := os.Getenv("KMS_MASTER_KEY_FILE")
		if masterFile != "" {
			kmsClient, errKms = kms.NewLocalKMSFromFile(masterFile)
		} else {
			key := os.Getenv("KMS_MASTER_KEY")
			if key == "" && cfg.AllowDevWeakKMSKey && cfg.Environment != "prod" {
				log.Println("开发/测试环境已启用 ALLOW_DEV_WEAK_KMS_KEY，使用内置弱密钥，仅用于本地调试")
				key = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=" // 32 字节 base64，开发弱密钥
			}
			if key == "" {
				log.Fatalf("使用 local KMS 必须设置 KMS_MASTER_KEY(Base64 32 字节) 或 KMS_MASTER_KEY_FILE；如需临时使用弱密钥，请设置 ALLOW_DEV_WEAK_KMS_KEY=true（仅限开发）")
			}
			kmsClient, errKms = kms.NewLocalKMS(key)
		}
	case "aliyun":
		kmsClient, errKms = kms.NewAliyunKMS()
	default:
		log.Fatalf("不支持的 KMS_PROVIDER: %s", cfg.KMSProvider)
	}

	if errKms != nil {
		log.Fatalf("初始化 KMS 客户端失败: %v", errKms)
	}
	// 包装会话缓存/限流/重试
	kmsClient = kms.NewCachedKMS(kmsClient)

	srv := server.NewServer(st, cfg, kmsClient)
	srv.Init(context.Background())

	var (
		tlsCfg     *tls.Config
		useTLS     = !cfg.AllowInsecureHTTP
		httpServer = &http.Server{
			Addr:         cfg.Addr,
			Handler:      srv.Router(),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
	)

	if useTLS {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			log.Fatalf("未提供 TLS 证书，生产必须开启 TLS；测试/联调可设置 ALLOW_INSECURE_HTTP=true 跳过证书校验")
		}
		// 动态证书/CA 重载
		certReloader, certErr := server.NewCertReloader(cfg.TLSCertFile, cfg.TLSKeyFile)
		if certErr != nil {
			log.Fatalf("加载证书失败: %v", certErr)
		}
		var caReloader *server.CAReloader
		if cfg.TLSClientCA != "" {
			caReloader, certErr = server.NewCAReloader(cfg.TLSClientCA)
			if certErr != nil {
				log.Fatalf("加载客户端 CA 失败: %v", certErr)
			}
		}
		if cfg.CertReloadSecs > 0 {
			certReloader.StartWatch(time.Duration(cfg.CertReloadSecs) * time.Second)
			if caReloader != nil {
				caReloader.StartWatch(time.Duration(cfg.CertReloadSecs) * time.Second)
			}
		}

		tlsCfg = &tls.Config{
			GetCertificate: certReloader.GetCertificate,
		}
		if caReloader != nil {
			tlsCfg.ClientCAs = caReloader.Pool()
			if cfg.RequireClientCert {
				tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			} else {
				tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
			}
		} else if cfg.RequireClientCert {
			log.Fatalf("已要求客户端证书但未配置 TLS_CLIENT_CA")
		}
		httpServer.TLSConfig = tlsCfg
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("优雅关闭失败: %v", err)
		}
	}()

	if useTLS {
		log.Printf("配置中心启动 HTTPS/mTLS，监听 %s", cfg.Addr)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS 服务异常退出，错误：%v", err)
		}
		return
	}

	log.Printf("配置中心启动 HTTP（仅开发/测试，ALLOW_INSECURE_HTTP=true），监听 %s", cfg.Addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP 服务异常退出，错误：%v", err)
	}
}
