package server

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"log"
	"os"
	"sync/atomic"
	"time"
)

// CertReloader 支持 TLS 证书热重载。
type CertReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Value // *tls.Certificate
	modTime  time.Time
}

// NewCertReloader 创建证书重载器并立即加载一次证书。
func NewCertReloader(certPath, keyPath string) (*CertReloader, error) {
	r := &CertReloader{certPath: certPath, keyPath: keyPath}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload 如果证书文件有更新则重新加载。
func (r *CertReloader) reload() error {
	info, err := os.Stat(r.certPath)
	if err != nil {
		return err
	}
	if !info.ModTime().After(r.modTime) && r.cert.Load() != nil {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("加载证书失败: %w", err)
	}
	r.cert.Store(&cert)
	r.modTime = info.ModTime()
	log.Printf("证书已热加载: %s (mtime=%s)", r.certPath, r.modTime.Format(time.RFC3339))
	return nil
}

// StartWatch 启动证书文件轮询，发现更新时自动重载。
func (r *CertReloader) StartWatch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			_ = r.reload()
		}
	}()
}

// GetCertificate 返回当前内存中的证书，供 tls.Config 回调使用。
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	val := r.cert.Load()
	if val == nil {
		return nil, fs.ErrNotExist
	}
	return val.(*tls.Certificate), nil
}
