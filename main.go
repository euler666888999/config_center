package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"

	"config_center/internal/config"
	"config_center/internal/kms"
	"config_center/internal/server"
	"config_center/internal/store"
)

// main 启动示例服务，采用内存存储以便快速验证接口行为。
func main() {
	cfg := config.Load()
	cfg.Warn()

	if cfg.DBDriver != "mysql" {
		log.Fatalf("DB_DRIVER 仅支持 mysql，生产环境禁止使用内存模式")
	}
	if cfg.MySQLDSN == "" {
		log.Fatalf("必须提供 MYSQL_DSN 才能使用 MySQL 持久化存储")
	}
	st, err := store.NewMySQLStore(cfg.MySQLDSN)
	if err != nil {
		log.Fatalf("初始化 MySQL 存储失败: %v", err)
	}
	defer st.Close()

	if os.Getenv("KMS_MASTER_KEY") == "" {
		log.Fatalf("必须设置 KMS_MASTER_KEY(Base64 32 字节) 以启用静态加密")
	}
	kmsClient, err := kms.NewEnvelopeKMS(os.Getenv("KMS_MASTER_KEY"))
	if err != nil {
		log.Fatalf("初始化 KMS 客户端失败: %v", err)
	}

	srv := server.NewServer(st, cfg, kmsClient)
	srv.Init(context.Background())

	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Router(),
	}

	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		log.Fatalf("必须提供 TLS_CERT_FILE 与 TLS_KEY_FILE，生产环境禁止明文 HTTP")
	}
	tlsCfg := &tls.Config{}
	if cfg.TLSClientCA != "" {
		caCert, err := os.ReadFile(cfg.TLSClientCA)
		if err != nil {
			log.Fatalf("读取客户端 CA 失败: %v", err)
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(caCert)
		tlsCfg.ClientCAs = caPool
		if cfg.RequireClientCert {
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if cfg.RequireClientCert {
		log.Fatalf("已要求客户端证书但未配置 TLS_CLIENT_CA")
	}
	httpServer.TLSConfig = tlsCfg
	log.Printf("配置中心启动 HTTPS/mTLS，监听 %s", cfg.Addr)
	if err := httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		log.Fatalf("HTTPS 服务异常退出，错误：%v", err)
	}
}
