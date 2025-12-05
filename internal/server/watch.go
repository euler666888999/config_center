package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"config_center/internal/model"
	"github.com/gorilla/websocket"
)

// Watcher 管理长轮询、SSE 与 WebSocket 连接。
type Watcher struct {
	mu        sync.RWMutex
	listeners map[string][]chan int // key: "namespace/name"
	ws        map[string][]*wsConn  // WebSocket 订阅列表
}

// NewWatcher 创建 Watcher。
func NewWatcher() *Watcher {
	return &Watcher{
		listeners: make(map[string][]chan int),
		ws:        make(map[string][]*wsConn),
	}
}

// Subscribe 返回通知通道和取消函数（长轮询/SSE 使用）。
func (w *Watcher) Subscribe(namespace, name string) (chan int, func()) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	ch := make(chan int, 1)
	w.mu.Lock()
	w.listeners[key] = append(w.listeners[key], ch)
	w.mu.Unlock()
	cancel := func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		listeners := w.listeners[key]
		for i, c := range listeners {
			if c == ch {
				w.listeners[key] = append(listeners[:i], listeners[i+1:]...)
				close(c)
				break
			}
		}
		if len(w.listeners[key]) == 0 {
			delete(w.listeners, key)
		}
	}
	return ch, cancel
}

// Notify 通知变更，传入新版本号。
func (w *Watcher) Notify(namespace, name string, newVersion int) {
	key := fmt.Sprintf("%s/%s", namespace, name)
	w.mu.Lock()
	chans := w.listeners[key]
	conns := w.ws[key]
	delete(w.listeners, key)
	w.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- newVersion:
		default:
		}
	}
	for _, c := range conns {
		_ = c.write(newVersion)
	}
}

// handleWatchSecret 处理长轮询请求。
func (s *Server) handleWatchSecret(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	actor := getActor(r)
	if err := s.authorize(ctx, namespace, name, "watch", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}

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

	ch, cancelSub := s.watcher.Subscribe(namespace, name)
	defer cancelSub()

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

// handleWatchSSE 基于 SSE 推送变更。
func (s *Server) handleWatchSSE(w http.ResponseWriter, r *http.Request, namespace, name string) {
	ctx := r.Context()
	flusher, ok := w.(http.Flusher)
	if !ok {
		respondError(w, http.StatusInternalServerError, "SSE 不被支持")
		return
	}
	actor := getActor(r)
	if err := s.authorize(ctx, namespace, name, "watch", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// 初始状态推送
	active, _ := s.store.FindActive(ctx, namespace, name)
	versions, _ := s.store.ListVersions(ctx, namespace, name)
	stagedVersion := 0
	for _, v := range versions {
		if v.Status == "staged" {
			stagedVersion = v.Version
			break
		}
	}
	fmt.Fprintf(w, "event: snapshot\ndata: {\"active_version\":%d,\"staged_version\":%d}\n\n", versionOrZero(active), stagedVersion)
	flusher.Flush()

	ch, cancel := s.watcher.Subscribe(namespace, name)
	defer cancel()
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 心跳
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case <-ch:
			newActive, _ := s.store.FindActive(ctx, namespace, name)
			newVersions, _ := s.store.ListVersions(ctx, namespace, name)
			newStaged := 0
			for _, v := range newVersions {
				if v.Status == "staged" {
					newStaged = v.Version
					break
				}
			}
			fmt.Fprintf(w, "event: update\ndata: {\"active_version\":%d,\"staged_version\":%d}\n\n", versionOrZero(newActive), newStaged)
			flusher.Flush()
		}
	}
}

// handleWatchWS 基于 WebSocket 推送变更，支持断线重连。
func (s *Server) handleWatchWS(w http.ResponseWriter, r *http.Request, namespace, name string) {
	actor := getActor(r)
	if err := s.authorize(r.Context(), namespace, name, "watch", actor, nil); err != nil {
		respondError(w, http.StatusForbidden, err.Error())
		return
	}
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%s/%s", namespace, name)
	s.watcher.mu.Lock()
	s.watcher.ws[key] = append(s.watcher.ws[key], ws)
	s.watcher.mu.Unlock()
	defer func() {
		s.watcher.mu.Lock()
		list := s.watcher.ws[key]
		for i, c := range list {
			if c == ws {
				s.watcher.ws[key] = append(list[:i], list[i+1:]...)
				break
			}
		}
		s.watcher.mu.Unlock()
		_ = ws.Close()
	}()

	// 初始快照
	active, _ := s.store.FindActive(r.Context(), namespace, name)
	versions, _ := s.store.ListVersions(r.Context(), namespace, name)
	staged := 0
	for _, v := range versions {
		if v.Status == "staged" {
			staged = v.Version
			break
		}
	}
	_ = ws.writeSnapshot(versionOrZero(active), staged)

	// 读 loop（保持连接，接收客户端心跳）
	for {
		if err := ws.ReadPing(); err != nil {
			return
		}
	}
}

// wsConn 封装 WebSocket 连接的写入/读取。
type wsConn struct {
	conn *websocket.Conn
}

// write 发送版本更新事件。
func (w *wsConn) write(version int) error {
	return w.conn.WriteJSON(map[string]any{
		"event":   "update",
		"version": version,
		"time":    time.Now().Format(time.RFC3339Nano),
	})
}

// writeSnapshot 发送当前快照事件。
func (w *wsConn) writeSnapshot(active, staged int) error {
	return w.conn.WriteJSON(map[string]any{
		"event":          "snapshot",
		"active_version": active,
		"staged_version": staged,
		"time":           time.Now().Format(time.RFC3339Nano),
	})
}

// ReadPing 读取一条消息以保持连接活跃，读取失败视为断开。
func (w *wsConn) ReadPing() error {
	if err := w.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}
	w.conn.SetPongHandler(func(string) error {
		return w.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	})
	_, _, err := w.conn.ReadMessage()
	return err
}

// Close 关闭底层连接。
func (w *wsConn) Close() error {
	return w.conn.Close()
}

// upgradeWebSocket 将 HTTP 连接升级为 WebSocket。
func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return nil, err
	}
	return &wsConn{conn: conn}, nil
}
