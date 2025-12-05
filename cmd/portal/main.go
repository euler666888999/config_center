package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

// 生产可用的最简 Portal：使用 HMAC 签名会话+CSRF（双重提交），不依赖内存。
func main() {
	loadDotEnv()
	api := getenv("API_ENDPOINT", "https://localhost:8443")
	addr := getenv("PORTAL_ADDR", ":9090")
	secret := getenv("PORTAL_SECRET", "")
	if len(secret) < 48 {
		log.Fatal("必须提供 PORTAL_SECRET（长度>=48），用于签名会话/CSRF，请使用强随机值")
	}
	// 开发场景可通过 PORTAL_REQUIRE_AUTH 控制是否强制上游 Authorization（默认为 true）。
	requireAuthEnv := strings.ToLower(getenv("PORTAL_REQUIRE_AUTH", "true")) == "true"
	requireAuth := flag.Bool("require_auth", requireAuthEnv, "是否必须提供上游 Authorization (OIDC/Bearer)")
	allowLocalLogin := getenv("PORTAL_ALLOW_LOCAL_LOGIN", "") == "true"
	defaultUser := os.Getenv("PORTAL_USER")
	defaultPass := os.Getenv("PORTAL_PASS")
	staticBearer := normalizeBearer(getenv("PORTAL_STATIC_BEARER", getenv("AUTH_BEARER_TOKEN", "")))
	if allowLocalLogin {
		if defaultUser == "" || defaultPass == "" || defaultUser == "admin" || defaultPass == "admin123" {
			log.Fatal("启用 PORTAL_ALLOW_LOCAL_LOGIN 时必须设置安全的 PORTAL_USER/PORTAL_PASS")
		}
	}
	flag.Parse()
	if *requireAuth && staticBearer == "" {
		log.Fatal("require_auth=true 但未配置 PORTAL_STATIC_BEARER/AUTH_BEARER_TOKEN，无法透传 Bearer，请在环境变量或 .env 中配置")
	}

	// 静态文件服务
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	if staticBearer != "" {
		log.Printf("Portal: 已加载静态 Bearer（来自 PORTAL_STATIC_BEARER 或 AUTH_BEARER_TOKEN），长度=%d，将默认透传到 API", len(stripBearerPrefix(staticBearer)))
	} else {
		log.Println("Portal: 未配置静态 Bearer，如需透传 AUTH_BEARER_TOKEN 请在环境变量中设置")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// API 代理或特殊路径不走静态文件
		if strings.HasPrefix(r.URL.Path, "/proxy/") || strings.HasPrefix(r.URL.Path, "/login") {
			return
		}

		// 确保存储 Session/CSRF Cookie，前端需自行携带 Authorization
		ensureSession(w, r, secret, r.Header.Get("Authorization"), staticBearer)

		fileServer.ServeHTTP(w, r)
	})

	// 本地登录：表单提交用户名密码，校验后生成会话并颁发 Bearer (伪) 供后端透传
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if !allowLocalLogin {
			http.Error(w, "未启用本地登录，请使用 OIDC/Bearer", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
			return
		}
		var creds struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "请求体错误", http.StatusBadRequest)
			return
		}
		if creds.User != defaultUser || creds.Pass != defaultPass {
			http.Error(w, "认证失败", http.StatusUnauthorized)
			return
		}
		// 颁发内部 Bearer（前端存储，透传给 API）
		bearer := "Bearer " + randomToken()
		sid, csrf := ensureSession(w, r, secret, bearer, staticBearer)
		resp := map[string]string{"token": bearer, "csrf": csrf, "sid": sid}
		b, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})

	// 审计查询透传（需 CSRF + Auth）
	http.HandleFunc("/proxy/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
			return
		}
		if !checkAuth(w, r, secret, *requireAuth, staticBearer) {
			return
		}
		if !checkCSRF(w, r, secret) {
			return
		}
		req, _ := http.NewRequest("POST", api+"/v1/audit/query", r.Body)
		if bearer := sessionBearer(r, secret, staticBearer); bearer != "" {
			req.Header.Set("Authorization", bearer)
		}
		if actor := r.Header.Get("X-Actor"); actor != "" {
			req.Header.Set("X-Actor", actor)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// 策略审批透传，带简单频控
	var lastApprove time.Time
	http.HandleFunc("/proxy/approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
			return
		}
		if !checkAuth(w, r, secret, *requireAuth, staticBearer) {
			return
		}
		if !checkCSRF(w, r, secret) {
			return
		}
		if time.Since(lastApprove) < time.Second {
			http.Error(w, "请求过于频繁", http.StatusTooManyRequests)
			return
		}
		lastApprove = time.Now()
		body, _ := io.ReadAll(r.Body)
		req, _ := http.NewRequest("POST", api+"/v1/authz/policies", bytes.NewBuffer(body))
		if bearer := sessionBearer(r, secret, staticBearer); bearer != "" {
			req.Header.Set("Authorization", bearer)
		}
		if actor := r.Header.Get("X-Actor"); actor != "" {
			req.Header.Set("X-Actor", actor)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	// 通用 API 代理 (用于前端直接调用后端 API)
	// 前端请求 /v1/... -> 代理到 API /v1/...
	http.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
			return
		}
		// 1. 认证检查 (对所有请求)
		if !checkAuth(w, r, secret, *requireAuth, staticBearer) {
			return
		}

		// 2. CSRF 检查（全部 POST）
		if !checkCSRF(w, r, secret) {
			return
		}

		targetURL := api + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		req, _ := http.NewRequest(r.Method, targetURL, r.Body)
		bearer := sessionBearer(r, secret, staticBearer)
		if bearer != "" {
			req.Header.Set("Authorization", bearer)
		}
		// 透传 X-Actor，便于后端在开发场景识别主体（ALLOW_INSECURE_ACTOR=true）
		if actor := r.Header.Get("X-Actor"); actor != "" {
			req.Header.Set("X-Actor", actor)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// 复制响应头
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	log.Printf("Portal 启动于 %s，指向 API: %s", addr, api)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// 会话与 CSRF：session cookie (HttpOnly, SameSite=Lax) + csrf cookie (可读)，值均为签名 token。
// 若未显式携带 Authorization 且配置了 staticBearer，则自动注入，便于 curl 仅带 Cookie 也能透传。
func ensureSession(w http.ResponseWriter, r *http.Request, secret string, bearer string, staticBearer string) (string, string) {
	sid, csrf, existingBearer, ok := parseSession(r, secret)
	// 优先使用请求头，其次沿用已有会话，再回落静态 Bearer；内部存储去掉前缀，避免 Cookie 中出现空格。
	token := stripBearerPrefix(bearer)
	if token == "" {
		token = stripBearerPrefix(existingBearer)
	}
	if token == "" {
		token = stripBearerPrefix(staticBearer)
	}
	// 如果已有会话且 bearer 未变化，直接复用
	if ok && token != "" && token == stripBearerPrefix(existingBearer) {
		return sid, csrf
	}
	// 否则生成新会话或更新 bearer
	if sid == "" {
		sid = randomToken()
	}
	if csrf == "" {
		csrf = randomToken()
	}

	exp := time.Now().Add(8 * time.Hour)
	signed := signValues(secret, sid, csrf, exp, token)
	http.SetCookie(w, &http.Cookie{
		Name:     "PORTAL_SESS",
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "PORTAL_CSRF",
		Value:    csrf,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
	return sid, csrf
}

func parseSession(r *http.Request, secret string) (string, string, string, bool) {
	c, err := r.Cookie("PORTAL_SESS")
	if err != nil || c.Value == "" {
		return "", "", "", false
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 5 {
		return "", "", "", false
	}
	sid, csrf, expStr, token, sig := parts[0], parts[1], parts[2], parts[3], parts[4]
	if !verifySignature(secret, strings.Join(parts[:4], "|"), sig) {
		return "", "", "", false
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Unix(expUnix, 0).Before(time.Now()) {
		return "", "", "", false
	}
	bearer := formatBearer(token)
	return sid, csrf, bearer, bearer != ""
}

func checkAuth(w http.ResponseWriter, r *http.Request, secret string, requireAuth bool, staticBearer string) bool {
	// 先尝试从 Session 恢复 Bearer
	_, _, existingBearer, _ := parseSession(r, secret)
	headerBearer := r.Header.Get("Authorization")

	if requireAuth {
		if headerBearer == "" && existingBearer == "" {
			http.Error(w, "缺少 Authorization 或会话失效", http.StatusUnauthorized)
			return false
		}
		if headerBearer != "" {
			// 标准化前缀
			r.Header.Set("Authorization", normalizeBearer(headerBearer))
		}
	}
	return true
}

func checkCSRF(w http.ResponseWriter, r *http.Request, secret string) bool {
	_, csrf, _, ok := parseSession(r, secret)
	if !ok {
		http.Error(w, "会话失效", http.StatusUnauthorized)
		return false
	}
	if r.Header.Get("X-CSRF-Token") == "" || r.Header.Get("X-CSRF-Token") != csrf {
		http.Error(w, "CSRF 校验失败", http.StatusForbidden)
		return false
	}
	return true
}

func signValues(secret, sid, csrf string, exp time.Time, bearer string) string {
	data := sid + "|" + csrf + "|" + strconv.FormatInt(exp.Unix(), 10) + "|" + bearer
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return data + "|" + sig
}

// sessionBearer 返回会话内的 Authorization（若存在）或请求头中的 Authorization，若仍为空且配置了 staticBearer，则回落。
func sessionBearer(r *http.Request, secret string, staticBearer string) string {
	_, _, bearer, ok := parseSession(r, secret)
	if ok && bearer != "" {
		return bearer
	}
	if hdr := r.Header.Get("Authorization"); hdr != "" {
		return hdr
	}
	return staticBearer
}

func verifySignature(secret, data, sig string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hmac.Equal(raw, mac.Sum(nil))
}

func randomToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadDotEnv 读取 .env（若存在），搜索顺序：
// 1) 当前工作目录逐级向上最多 5 层
// 2) 可执行文件所在目录
// 3) 可执行文件上级目录
// 若环境变量已存在则不覆盖。
func loadDotEnv() {
	paths := make([]string, 0, 8)
	// 1) 当前工作目录向上递归查找
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for i := 0; i < 5; i++ {
			paths = append(paths, filepath.Join(dir, ".env"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	} else {
		paths = append(paths, ".env")
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		paths = append(paths, filepath.Join(exeDir, ".env"), filepath.Join(exeDir, "..", ".env"))
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		log.Printf("Portal: 读取环境变量文件 %s", p)
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := stripQuotes(strings.TrimSpace(parts[1]))
			if key == "" {
				continue
			}
			if _, exists := os.LookupEnv(key); exists {
				continue
			}
			_ = os.Setenv(key, val)
		}
		// 只要有一个 .env 被读取就结束
		break
	}
}

// normalizeBearer 确保带上 "Bearer " 前缀（若非空），便于直接透传。
func normalizeBearer(token string) string {
	if token == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		return token
	}
	return "Bearer " + token
}

// stripBearerPrefix 移除可选的 Bearer 前缀，返回纯 token。
func stripBearerPrefix(token string) string {
	t := strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(t), "bearer ") {
		return strings.TrimSpace(t[7:])
	}
	return t
}

// formatBearer 将纯 token 加上 Bearer 前缀（若非空）。
func formatBearer(token string) string {
	if token == "" {
		return ""
	}
	return "Bearer " + token
}

// stripQuotes 去掉首尾成对的引号，兼容 .env 包裹写法。
func stripQuotes(val string) string {
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			return val[1 : len(val)-1]
		}
	}
	return val
}

const indexHTML = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Config Center Portal</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    input, button, textarea { margin: 4px 0; width: 100%; padding: 6px; }
    section { margin-bottom: 24px; border: 1px solid #ccc; padding: 12px; border-radius: 6px;}
  </style>
</head>
<body>
  <h2>配置/密钥中心 Portal (最小演示)</h2>
  <p>API: {{.API}}</p>

  <section>
    <h3>密钥读取</h3>
    <label>命名空间</label><input id="ns" value="dev">
    <label>名称</label><input id="name" value="example">
    <button onclick="getSecret()">读取</button>
    <pre id="secret"></pre>
  </section>

  <section>
    <h3>策略审批</h3>
    <label>命名空间</label><input id="pns" value="">
    <label>策略名称</label><input id="pname" value="">
    <label>决策 approve/reject</label><input id="decision" value="approve">
    <button onclick="approve()">提交</button>
    <pre id="policy"></pre>
  </section>

  <section>
    <h3>审计查询</h3>
    <label>命名空间</label><input id="ans" value="">
    <label>资源名</label><input id="aname" value="">
    <button onclick="audit()">查询</button>
    <pre id="audit"></pre>
  </section>

<script>
const API = "{{.API}}";

function headers() {
  const token = localStorage.getItem("token") || "";
  return token ? {"Authorization": "Bearer "+token, "Content-Type":"application/json"} : {"Content-Type":"application/json"};
}

async function getSecret() {
  const ns = document.getElementById("ns").value;
  const name = document.getElementById("name").value;
  const res = await fetch(API+"/v1/namespaces/"+ns+"/secrets/"+name+":get", {
    method:"POST",
    headers: headers(),
    body: JSON.stringify({version:0})
  });
  document.getElementById("secret").textContent = await res.text();
}

async function approve() {
  const ns = document.getElementById("pns").value;
  const name = document.getElementById("pname").value;
  const decision = document.getElementById("decision").value;
  const csrf = getCsrf();
  const res = await fetch("/proxy/approve", {
    method:"POST",
    headers: {
      ...headers(),
      "X-CSRF-Token": csrf
    },
    body: JSON.stringify({namespace:ns, name:name, action:"approve", decision:decision})
  });
  document.getElementById("policy").textContent = await res.text();
}

async function audit() {
  const ns = document.getElementById("ans").value;
  const name = document.getElementById("aname").value;
  const csrf = getCsrf();
  const res = await fetch("/proxy/audit", {
    method:"POST",
    headers: {
      ...headers(),
      "X-CSRF-Token": csrf
    },
    body: JSON.stringify({namespace:ns, name:name, page_size:20})
  });
  document.getElementById("audit").textContent = await res.text();
}

function getCsrf() {
  const cookie = document.cookie.split(";").map(s=>s.trim()).find(c=>c.startsWith("PORTAL_CSRF="));
  return cookie ? decodeURIComponent(cookie.split("=")[1]) : "";
}
</script>
</body>
</html>
`
