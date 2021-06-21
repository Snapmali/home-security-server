package wsserver

import (
	"hsserver/model"
)

type WsMessage struct {
	Type    int                    `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

type HostStatus2UserMessage struct {
	Type    int               `json:"type"`
	Payload HostStatusPayload `json:"payload"`
}

type HostStatusPayload struct {
	HostId     uint64 `json:"host_id"`
	Online     bool   `json:"online"`
	Streaming  bool   `json:"streaming"`
	Monitoring bool   `json:"monitoring"`
}

type Alarm2UserMessage struct {
	Type    int         `json:"type"`
	Payload model.Alarm `json:"payload"`
}
