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

// Condition 简化版 ABAC 条件，目前支持 key==value 的 AND 关系。
type Condition map[string]string

// Match 判断条件是否满足请求上下文。
func (c Condition) Match(req Request) bool {
	if len(c) == 0 {
		return true
	}
	for k, v := range c {
		// 优先匹配请求属性，然后匹配标签
		if val, ok := req.Attrs[k]; ok {
			if !strings.EqualFold(val, v) {
				return false
			}
			continue
		}
		if val, ok := req.Labels[k]; ok {
			if !strings.EqualFold(val, v) {
				return false
			}
			continue
		}
		// 未命中则视为不满足
		return false
	}
	return true
}
