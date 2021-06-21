package controller

import (
	"hsserver/model"
)

type HostUserIdPair struct {
	HostId uint64 `json:"host_id" form:"host_id" binding:"required"`
	UserId uint64 `json:"user_id" form:"user_id" binding:"required"`
}

type HostnamePwdPair struct {
	Hostname string `json:"hostname" form:"hostname" binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type HostAlarmRequest struct {
	HostId uint64         `json:"host_id" form:"host_id" binding:"required"`
	Type   int            `json:"type"    form:"type"    binding:"required"`
	Desc   string         `json:"desc"    form:"desc"    binding:"required"`
	Time   model.JsonTime `json:"time"    form:"time"    binding:"required"`
}

type UserBindingRequest struct {
	Mode int `json:"mode" form:"mode" binding:"required"`
	HostUserIdPair
}

type UserMonitoringStartRequest struct {
	SavingMode int `json:"saving_mode" form:"saving_mode" binding:"required"`
	HostUserIdPair
}

type UserRegSendCodeRequest struct {
	Username string `json:"username" form:"username" binding:"required"`
	Email    string `json:"email"    form:"email"    binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type UserRegVerificationRequest struct {
	Username string `json:"username" form:"username" binding:"required"`
	Code     string `json:"code"     form:"code"     binding:"required"`
}

type UserLoginRequest struct {
	IdentifierPair
	Password string `json:"password" form:"password" binding:"required"`
}

type IdentifierPair struct {
	IdtfType   int    `json:"idtf_type"  form:"idtf_type"  binding:"required"`
	Identifier string `json:"identifier" form:"identifier" binding:"required"`
}

type UserFgtPwdVerificationRequest struct {
	UserId uint64 `json:"user_id" form:"user_id" binding:"required"`
	Code   string `json:"code"    form:"code"    binding:"required"`
}

type UserFgtPwdResetRequest struct {
	UserId   uint64 `json:"user_id"  form:"user_id"  binding:"required"`
	Password string `json:"password" form:"password" binding:"required"`
}

type UserResetPasswordRequest struct {
	UserId uint64 `json:"user_id" form:"user_id" binding:"required"`
	Old    string `json:"old"     form:"old"     binding:"required"`
	New    string `json:"new"     form:"new"     binding:"required"`
}

type UserPullAlarmsRequest struct {
	UserId   uint64 `json:"user_id"   form:"user_id"   binding:"required"`
	HostId   uint64 `json:"host_id"   form:"host_id"`
	Offset   *int   `json:"offset"    form:"offset"    binding:"required"`
	PageSize int    `json:"page_size" form:"page_size" binding:"required"`
}

type UserGetAlarmRequest struct {
	UserId  uint64 `json:"user_id"  form:"user_id"  binding:"required"`
	AlarmId uint64 `json:"alarm_id" form:"alarm_id" binding:"required"`
}

type UserGetAlarmImgRequest struct {
	UserId uint64 `json:"user_id" form:"user_id" binding:"required"`
	Image  string `json:"image"   form:"image"   binding:"required"`
}

type UserUpdateHostInfoRequest struct {
	UserId     uint64 `json:"user_id"     form:"user_id"     binding:"required"`
	HostId     uint64 `json:"host_id"     form:"host_id"     binding:"required"`
	ScreenName string `json:"screen_name" form:"screen_name" binding:"required"`
}

type AuthenticationRequest struct {
	Id     uint64 `json:"id"      form:"id"`
	Jwt    string `json:"jwt"     form:"jwt"    binding:"required"`
	Verify bool   `json:"verify"  form:"verify" binding:"required"`
}
