package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"config_center/internal/model"
)

// Watcher 管理长轮询连接。
type Watcher struct {
	mu        sync.RWMutex
	listeners map[string][]chan int // key: "namespace/name", value: list of channels
}

// NewWatcher 创建 Watcher。
func NewWatcher() *Watcher {
	return &Watcher{
		listeners: make(map[string][]chan int),
	}
}

// Notify 通知变更，传入新版本号。
func (w *Watcher) Notify(namespace, name string, newVersion int) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	w.mu.Lock()
	defer w.mu.Unlock()
	chans, ok := w.listeners[key]
	if !ok {
		return
	}
	for _, ch := range chans {
		// 非阻塞发送，防止阻塞主流程
		select {
		case ch <- newVersion:
		default:
		}
	}
	// 通知后清空监听列表（长轮询是一次性的，客户端收到后需重新发起）
	delete(w.listeners, key)
}

// handleWatchSecret 处理长轮询请求。
func (s *Server) handleWatchSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()

	// 解析客户端当前版本
	clientVersionStr := r.URL.Query().Get("version")
	clientVersion := 0
	if clientVersionStr != "" {
		v, err := strconv.Atoi(clientVersionStr)
		if err == nil {
			clientVersion = v
		}
	}

	// 检查当前最新 active 版本
	active, err := s.store.FindActive(ctx, namespace, name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询失败: %v", err))
		return
	}

	// 查找 staged 版本
	versions, _ := s.store.ListVersions(ctx, namespace, name)
	stagedVersion := 0
	for _, v := range versions {
		if v.Status == "staged" {
			stagedVersion = v.Version
			break
		}
	}

	currentVersion := 0
	if active != nil {
		currentVersion = active.Version
	}

	// 如果客户端版本落后，立即返回最新配置
	// 或者如果客户端请求的是 staged (通过 GetCandidate 逻辑，通常不带 version 或带 0)，
	// 只要有 active 或 staged，都应该返回状态？
	// SDK GetCandidate 逻辑是: watch -> get staged_version -> get(version)
	// 所以这里只要返回当前状态即可。
	// 如果 clientVersion < currentVersion，返回 active + staged
	// 如果 clientVersion == currentVersion，等待变更

	if currentVersion > clientVersion {
		s.respondWatchResult(w, active, stagedVersion)
		return
	}

	// 否则挂起连接，等待变更或超时
	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan int, 1)
	key := fmt.Sprintf("%s/%s", namespace, name)

	s.watcher.mu.Lock()
	s.watcher.listeners[key] = append(s.watcher.listeners[key], ch)
	s.watcher.mu.Unlock()

	// 清理函数：确保连接断开或超时后移除 channel
	defer func() {
		s.watcher.mu.Lock()
		defer s.watcher.mu.Unlock()
		listeners := s.watcher.listeners[key]
		for i, c := range listeners {
			if c == ch {
				// 移除当前 channel
				s.watcher.listeners[key] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
	}()

	select {
	case newVersion := <-ch:
		// 收到变更通知，查询新版本数据返回
		newActive, err := s.store.FindActive(ctx, namespace, name)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "获取新版本失败")
			return
		}

		// 重新查询 staged
		newVersions, _ := s.store.ListVersions(ctx, namespace, name)
		newStaged := 0
		for _, v := range newVersions {
			if v.Status == "staged" {
				newStaged = v.Version
				break
			}
		}

		// 再次确认版本
		if newActive != nil && newActive.Version == newVersion {
			s.respondWatchResult(w, newActive, newStaged)
		} else {
			s.respondWatchResult(w, newActive, newStaged)
		}
	case <-ctx.Done():
		// 超时或取消，返回 304 Not Modified 或当前状态
		w.WriteHeader(http.StatusNotModified)
	}
}

func (s *Server) respondWatchResult(w http.ResponseWriter, sv *model.SecretVersion, stagedVersion int) {
	if sv == nil {
		// 可能只有 staged 没有 active
		respondJSON(w, http.StatusOK, map[string]any{
			"version":        0,
			"status":         "none",
			"staged_version": stagedVersion,
		})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"name":           sv.Name,
		"version":        sv.Version,
		"status":         sv.Status,
		"plaintext":      "", // Watch 不返回敏感明文，避免泄露
		"labels":         sv.Labels,
		"staged_version": stagedVersion,
	})
}
