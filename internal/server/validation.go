package server

import (
	"config_center/internal/model"
	"net/http"
	"regexp"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// validateSecretCreate 校验创建密钥请求的必填项与长度。
func validateSecretCreate(w http.ResponseWriter, req *model.CreateSecretRequest) bool {
	if req.Name == "" || req.KeyID == "" {
		respondError(w, http.StatusBadRequest, "name/key_id 必填")
		return false
	}
	if !namePattern.MatchString(req.Name) {
		respondError(w, http.StatusBadRequest, "name 仅支持字母数字._-，长度 <=128")
		return false
	}
	if len(req.KeyID) > 128 {
		respondError(w, http.StatusBadRequest, "key_id 长度需 <=128")
		return false
	}
	return true
}

// validateRotate 校验轮换请求的字段合法性。
func validateRotate(w http.ResponseWriter, req *model.RotateRequest) bool {
	if req.Plaintext == "" && req.Ciphertext == "" {
		respondError(w, http.StatusBadRequest, "轮换需提供 plaintext 或 ciphertext")
		return false
	}
	if req.KeyID != "" && len(req.KeyID) > 128 {
		respondError(w, http.StatusBadRequest, "key_id 长度需 <=128")
		return false
	}
	return true
}

// validatePolicy 校验策略创建/审批请求的必填字段与长度。
func validatePolicy(w http.ResponseWriter, req *model.PolicyRequest) bool {
	if req.Name == "" || req.Namespace == "" || len(req.Subjects) == 0 || len(req.Resources) == 0 || len(req.Operations) == 0 {
		respondError(w, http.StatusBadRequest, "创建策略时 name/namespace/subjects/resources/actions 必填")
		return false
	}
	if len(req.Name) > 128 || len(req.Namespace) > 64 {
		respondError(w, http.StatusBadRequest, "策略名称或命名空间过长")
		return false
	}
	if req.RequiredApprovals < 0 {
		respondError(w, http.StatusBadRequest, "required_approvals 需为非负数")
		return false
	}
	if len(req.TicketID) > 128 {
		respondError(w, http.StatusBadRequest, "ticket_id 长度需 <=128")
		return false
	}
	return true
}
