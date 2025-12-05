package server

import (
	"crypto/x509"
	"log"
	"os"
	"sync/atomic"
	"time"
)

// CAReloader 支持客户端 CA 证书热加载。
type CAReloader struct {
	caPath  string
	caPool  atomic.Value // *x509.CertPool
	modTime time.Time
}

// NewCAReloader 创建 CA 热加载器并立即加载一次。
func NewCAReloader(path string) (*CAReloader, error) {
	r := &CAReloader{caPath: path}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload 如果文件有更新则重新解析 CA 证书。
func (r *CAReloader) reload() error {
	info, err := os.Stat(r.caPath)
	if err != nil {
		return err
	}
	if !info.ModTime().After(r.modTime) && r.caPool.Load() != nil {
		return nil
	}
	data, err := os.ReadFile(r.caPath)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data)
	r.caPool.Store(pool)
	r.modTime = info.ModTime()
	log.Printf("CA 已热加载: %s (mtime=%s)", r.caPath, r.modTime.Format(time.RFC3339))
	return nil
}

// Pool 返回当前生效的 CA 证书池。
func (r *CAReloader) Pool() *x509.CertPool {
	val := r.caPool.Load()
	if val == nil {
		return nil
	}
	return val.(*x509.CertPool)
}

// StartWatch 定期检测 CA 变更。
func (r *CAReloader) StartWatch(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			_ = r.reload()
		}
	}()
}
