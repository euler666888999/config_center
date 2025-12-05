package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksCache 缓存 JWKS 公钥，减少频繁拉取。
type jwksCache struct {
	url     string
	client  *http.Client
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	expires time.Time
}

// newJWKSCache 创建 JWKS 缓存客户端，设置默认超时时间。
func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
		keys:   make(map[string]*rsa.PublicKey),
	}
}

// getKey 从缓存或远端拉取 JWKS，返回指定 kid 的公钥。
func (c *jwksCache) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	if key, ok := c.keys[kid]; ok && time.Now().Before(c.expires) {
		c.mu.RUnlock()
		return key, nil
	}
	c.mu.RUnlock()
	if err := c.refresh(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("JWKS 中未找到 kid=%s", kid)
	}
	return key, nil
}

// refresh 拉取最新 JWKS 文档并刷新本地缓存。
func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSA(k.N, k.E)
		if err == nil {
			keys[k.Kid] = pub
		}
	}
	c.mu.Lock()
	c.keys = keys
	c.expires = time.Now().Add(10 * time.Minute)
	c.mu.Unlock()
	return nil
}

// jwkToRSA 将 JWKS 中的 N/E 字段解析为 RSA 公钥。
func jwkToRSA(n, e string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, err
	}
	var eInt int
	for _, b := range eb {
		eInt = eInt<<8 + int(b)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: eInt,
	}, nil
}

// parsePEMPublicKey 解析 PEM 文本。
func parsePEMPublicKey(pemData string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("无效 PEM 公钥")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("仅支持 RSA 公钥")
	}
	return rsaPub, nil
}

// verifyOIDCToken 校验 JWT，优先 JWKS，其次静态公钥。
func (s *Server) verifyOIDCToken(tokenString string) (string, error) {
	if tokenString == "" {
		return "", errors.New("缺少 Bearer Token")
	}
	parser := jwt.NewParser(jwt.WithAudience(s.cfg.OIDCAudience))
	claims := jwt.MapClaims{}
	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if kid, _ := t.Header["kid"].(string); kid != "" && s.jwks != nil {
			return s.jwks.getKey(kid)
		}
		if s.oidcPub != nil {
			return s.oidcPub, nil
		}
		return nil, errors.New("无法获取公钥")
	}
	_, err := parser.ParseWithClaims(tokenString, claims, keyFunc)
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", errors.New("token 缺少 sub")
	}
	return sub, nil
}
