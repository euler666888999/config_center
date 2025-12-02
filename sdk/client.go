package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client 提供 Go SDK，支持缓存、重试与双版本访问。
type Client struct {
	baseURL    string
	namespace  string
	httpClient *http.Client
	actor      string
	bearer     string
	cacheTTL   time.Duration

	mu    sync.RWMutex
	cache map[string]cacheItem
}

type cacheItem struct {
	val       SecretResponse
	expiresAt time.Time
}

// SecretResponse 与服务端读取响应对应。
type SecretResponse struct {
	Name      string            `json:"name"`
	Version   int               `json:"version"`
	KeyID     string            `json:"key_id"`
	Status    string            `json:"status"`
	Labels    map[string]string `json:"labels"`
	ExpireAt  *time.Time        `json:"expire_at"`
	Plaintext string            `json:"plaintext"`
}

// New 创建客户端，cacheTTL 控制缓存有效期。
func New(baseURL, namespace, actor, bearer string, cacheTTL time.Duration) *Client {
	return &Client{
		baseURL:    baseURL,
		namespace:  namespace,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		actor:      actor,
		bearer:     bearer,
		cacheTTL:   cacheTTL,
		cache:      make(map[string]cacheItem),
	}
}

// GetSecret 支持缓存与指数重试。
func (c *Client) GetSecret(ctx context.Context, name string, version int) (SecretResponse, error) {
	cacheKey := fmt.Sprintf("%s:%d", name, version)
	if v, ok := c.fromCache(cacheKey); ok {
		return v, nil
	}
	body := map[string]int{}
	if version > 0 {
		body["version"] = version
	}
	var resp SecretResponse
	err := c.do(ctx, fmt.Sprintf("/v1/namespaces/%s/secrets/%s:get", c.namespace, name), body, &resp)
	if err != nil {
		return SecretResponse{}, err
	}
	c.saveCache(cacheKey, resp)
	return resp, nil
}

func (c *Client) do(ctx context.Context, path string, payload any, out any) error {
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.actor != "" {
		req.Header.Set("X-Actor", c.actor)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	var lastErr error
	for i := 0; i < 3; i++ {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("服务端错误: %s", resp.Status)
			time.Sleep(time.Duration(1<<i) * 100 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("请求失败: %s, %s", resp.Status, string(b))
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
	if lastErr == nil {
		lastErr = errors.New("请求失败")
	}
	return lastErr
}

func (c *Client) fromCache(key string) (SecretResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.cache[key]
	if !ok || time.Now().After(item.expiresAt) {
		return SecretResponse{}, false
	}
	return item.val, true
}

func (c *Client) saveCache(key string, val SecretResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = cacheItem{val: val, expiresAt: time.Now().Add(c.cacheTTL)}
}
