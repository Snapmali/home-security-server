package controller

import "hsserver/model"

type BaseResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type UserPullAlarmsResponse struct {
	BaseResponse
	Offset int            `json:"offset"`
	Alarms *[]model.Alarm `json:"alarms"`
}

type UserGetAlarmResponse struct {
	BaseResponse
	Alarm model.Alarm `json:"alarm"`
}

type HostInfo struct {
	HostId     uint64         `json:"host_id"`
	ScreenName string         `json:"screen_name"`
	CreatedAt  model.JsonTime `json:"created_at"`
	Online     bool           `json:"online"     gorm:"-"`
	Streaming  bool           `json:"streaming"  gorm:"-"`
	Monitoring bool           `json:"monitoring" gorm:"-"`
}

type UserPullHostsResponse struct {
	BaseResponse
	Hosts *[]HostInfo `json:"hosts"`
}

type UserGetHostResponse struct {
	BaseResponse
	Host HostInfo `json:"host"`
}
