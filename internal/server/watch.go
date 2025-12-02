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
		select {
		case ch <- newVersion:
		default:
		}
	}
	delete(w.listeners, key)
}

// handleWatchSecret 处理长轮询请求。
func (s *Server) handleWatchSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()

	clientVersionStr := r.URL.Query().Get("version")
	clientVersion := 0
	if clientVersionStr != "" {
		if v, err := strconv.Atoi(clientVersionStr); err == nil {
			clientVersion = v
		}
	}

	active, err := s.store.FindActive(ctx, namespace, name)
	if err != nil {
		respondError(w, http.StatusInternalServerError, fmt.Sprintf("查询失败: %v", err))
		return
	}

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

	if currentVersion > clientVersion {
		s.respondWatchResult(w, active, stagedVersion)
		return
	}

	timeout := 30 * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan int, 1)
	key := fmt.Sprintf("%s/%s", namespace, name)

	s.watcher.mu.Lock()
	s.watcher.listeners[key] = append(s.watcher.listeners[key], ch)
	s.watcher.mu.Unlock()
	defer func() {
		s.watcher.mu.Lock()
		defer s.watcher.mu.Unlock()
		listeners := s.watcher.listeners[key]
		for i, c := range listeners {
			if c == ch {
				s.watcher.listeners[key] = append(listeners[:i], listeners[i+1:]...)
				break
			}
		}
	}()

	select {
	case <-ch:
		newActive, err := s.store.FindActive(ctx, namespace, name)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "获取新版本失败")
			return
		}
		newVersions, _ := s.store.ListVersions(ctx, namespace, name)
		newStaged := 0
		for _, v := range newVersions {
			if v.Status == "staged" {
				newStaged = v.Version
				break
			}
		}
		s.respondWatchResult(w, newActive, newStaged)
	case <-ctx.Done():
		w.WriteHeader(http.StatusNotModified)
	}
}

func (s *Server) respondWatchResult(w http.ResponseWriter, sv *model.SecretVersion, stagedVersion int) {
	if sv == nil {
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
		"plaintext":      "", // Watch 不返回敏感明文
		"labels":         sv.Labels,
		"staged_version": stagedVersion,
	})
}
