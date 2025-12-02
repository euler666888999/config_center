package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// 一个极简 Portal 占位：提供静态首页与健康探针，提示使用 API 或后续接入前端。
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><h2>配置/密钥中心 Portal 占位</h2><p>请使用 API/SDK 进行管理，前端控制台待实现。</p></body></html>`))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	addr := ":8090"
	log.Printf("Portal 占位服务监听 %s（后续可替换为完整 Web 控制台）", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
