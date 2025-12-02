package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Config SDK 配置。
type Config struct {
	Endpoint   string // 配置中心地址，如 https://config-center.prod:8080
	Namespace  string // 命名空间
	AppID      string // 应用标识 (Actor)
	AppSecret  string // 应用密钥 (Bearer Token)
	ClientCert string // mTLS 客户端证书路径 (可选)
	ClientKey  string // mTLS 客户端密钥路径 (可选)
}

// Secret 密钥数据。
type Secret struct {
	Name      string            `json:"name"`
	Version   int               `json:"version"`
	Status    string            `json:"status"`
	Plaintext string            `json:"plaintext"` // 解密后的明文
	Labels    map[string]string `json:"labels"`
}

// Client 配置中心客户端。
type Client struct {
	cfg        Config
	httpClient *http.Client
	cache      sync.Map // map[string]*Secret
	cancel     context.CancelFunc
	ctx        context.Context
}

// NewClient 创建客户端。
func NewClient(cfg Config) (*Client, error) {
	// TODO: 支持 mTLS 证书加载
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Get 获取密钥，优先读缓存。
func (c *Client) Get(name string) (*Secret, error) {
	if v, ok := c.cache.Load(name); ok {
		return v.(*Secret), nil
	}
	return c.fetchAndCache(name)
}

// Watch 监听密钥变更（后台长轮询）。
func (c *Client) Watch(name string) {
	go c.watchLoop(name)
}

// Close 关闭客户端。
func (c *Client) Close() {
	c.cancel()
}

func (c *Client) fetchAndCache(name string) (*Secret, error) {
	// 1. 请求 API
	url := fmt.Sprintf("%s/v1/namespaces/%s/secrets/%s:get", c.cfg.Endpoint, c.cfg.Namespace, name)
	reqBody, _ := json.Marshal(map[string]int{"version": 0}) // 0 表示获取 active
	req, err := http.NewRequestWithContext(c.ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API 错误: %d %s", resp.StatusCode, string(body))
	}

	// 2. 解析响应
	var s Secret
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}

	// 3. 更新缓存
	c.cache.Store(name, &s)
	return &s, nil
}

func (c *Client) watchLoop(name string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// 获取当前缓存版本
			currentVersion := 0
			if v, ok := c.cache.Load(name); ok {
				currentVersion = v.(*Secret).Version
			}

			// 发起长轮询
			url := fmt.Sprintf("%s/v1/namespaces/%s/secrets/%s:watch?version=%d", c.cfg.Endpoint, c.cfg.Namespace, name, currentVersion)
			req, _ := http.NewRequestWithContext(c.ctx, "POST", url, nil)
			c.setAuthHeaders(req)

			// 长轮询超时设置较长
			client := &http.Client{Timeout: 40 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				// 网络错误，退避重试
				time.Sleep(5 * time.Second)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var s Secret
				body, _ := io.ReadAll(resp.Body)
				if err := json.Unmarshal(body, &s); err == nil {
					// 收到新版本，更新缓存
					if s.Version > currentVersion {
						c.cache.Store(name, &s)
					}
				}
			} else if resp.StatusCode == http.StatusNotModified {
				// 无变更，继续下一轮
			} else {
				// 其他错误，退避
				time.Sleep(5 * time.Second)
			}
		}
	}
}

func (c *Client) setAuthHeaders(req *http.Request) {
	if c.cfg.AppSecret != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AppSecret)
	}
	if c.cfg.AppID != "" {
		req.Header.Set("X-Actor", c.cfg.AppID)
	}
}

// GetCandidate 获取灰度版本 (staged)，不走缓存，直接穿透查询。
func (c *Client) GetCandidate(name string) (*Secret, error) {
	// 步骤 1: 获取 staged version
	url := fmt.Sprintf("%s/v1/namespaces/%s/secrets/%s:watch", c.cfg.Endpoint, c.cfg.Namespace, name)
	req, _ := http.NewRequestWithContext(c.ctx, "POST", url, nil)
	c.setAuthHeaders(req)
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("查询 staged 版本失败: %d", resp.StatusCode)
	}
	
	var watchRes struct {
		StagedVersion int `json:"staged_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&watchRes); err != nil {
		return nil, err
	}
	
	if watchRes.StagedVersion == 0 {
		return nil, nil // 无灰度版本
	}
	
	// 步骤 2: 获取具体内容
	return c.GetByVersion(name, watchRes.StagedVersion)
}

// GetByVersion 获取指定版本。
func (c *Client) GetByVersion(name string, version int) (*Secret, error) {
	url := fmt.Sprintf("%s/v1/namespaces/%s/secrets/%s:get", c.cfg.Endpoint, c.cfg.Namespace, name)
	reqBody, _ := json.Marshal(map[string]int{"version": version})
	req, err := http.NewRequestWithContext(c.ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 错误: %d", resp.StatusCode)
	}

	var s Secret
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// VerifyResult 验证结果。
type VerifyResult struct {
	ActivePassed    bool
	CandidatePassed bool
	ActiveErr       error
	CandidateErr    error
}

// Verify 双版本验证辅助函数。
// validator: 业务自定义校验逻辑，返回 true 表示配置可用。
func (c *Client) Verify(name string, validator func(s *Secret) bool) VerifyResult {
	res := VerifyResult{}
	var wg sync.WaitGroup
	wg.Add(2)

	// 验证 Active
	go func() {
		defer wg.Done()
		s, err := c.Get(name)
		if err != nil {
			res.ActiveErr = err
			return
		}
		res.ActivePassed = validator(s)
	}()

	// 验证 Candidate
	go func() {
		defer wg.Done()
		s, err := c.GetCandidate(name)
		if err != nil {
			res.CandidateErr = err
			return
		}
		if s == nil {
			// 无 candidate，视为通过
			res.CandidatePassed = true
			return 
		}
		res.CandidatePassed = validator(s)
	}()

	wg.Wait()
	return res
}
