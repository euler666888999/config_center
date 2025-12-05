package abac

import (
	"strings"
)

// Request 表示授权请求上下文。
type Request struct {
	Actor     string
	Namespace string
	Resource  string
	Action    string
	Labels    map[string]string // 资源标签
	Attrs     map[string]string // 请求方属性（如 IP/UA/env）
}

// Condition 简化版 ABAC 条件，支持 key==value 与 in 列表（逗号分隔），默认 AND。
type Condition map[string]string

// Match 判断条件是否满足请求上下文。
func (c Condition) Match(req Request) bool {
	if len(c) == 0 {
		return true
	}
	for k, v := range c {
		key := k
		val := v
		target := ""
		if strings.HasPrefix(key, "label:") {
			target = req.Labels[strings.TrimPrefix(key, "label:")]
		} else {
			target = req.Attrs[key]
		}
		if target == "" {
			return false
		}
		// 支持逗号分隔列表
		items := strings.Split(val, ",")
		match := false
		for _, it := range items {
			if strings.EqualFold(strings.TrimSpace(it), target) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}
