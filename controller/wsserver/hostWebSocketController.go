package wsserver

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"hsserver/database"
	"hsserver/model"
	"sync"
)

const (
	HostTypeInit            = 1
	HostTypeStartStreaming  = 2
	HostTypeStopStreaming   = 3
	HostTypeStartMonitoring = 4
	HostTypeStopMonitoring  = 5
	HostTypeBinding         = 6
	HostTypeUnbinding       = 7

	CaptureAlwaysSave     = 1
	CaptureSaveWhenMoving = 2
)

var (
	HostWsConnMap sync.Map
)

type HostRecord struct {
	WsConn *HostWsConn
	ID     uint64
	UserId uint64
	Status HostStatus
}

type HostStatus struct {
	Monitoring bool
	Streaming  bool
}

func initHost(hostId uint64) error {
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", hostId).First(&binding)
	record, err := GetHostRecord(hostId)
	if err != nil {
		return err
	}
	record.UserId = uint64(binding.UserID)
	message := WsMessage{
		Type:    HostTypeInit,
		Payload: map[string]interface{}{"user_id": binding.UserID},
	}
	data, _ := json.Marshal(message)
	return record.WsConn.WriteMessage(websocket.TextMessage, data)
}

func PushMessage2Host(hostID uint64, message interface{}) error {
	record, err := GetHostRecord(hostID)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(message)
	return record.WsConn.WriteMessage(websocket.TextMessage, data)
}

func registerHostWsConn(hostID uint64, hostWsConn *HostWsConn) {
	HostWsConnMap.Store(hostID, &HostRecord{
		WsConn: hostWsConn,
		ID:     hostID,
		Status: HostStatus{
			Streaming:  false,
			Monitoring: false,
		},
	})
}

func updateHostStatus(hostID uint64, status HostStatus) error {
	record, err := GetHostRecord(hostID)
	if err != nil {
		return err
	}
	record.Status = status
	return nil
}

func reportHostStatus2User(hostID uint64) error {
	record, err := GetHostRecord(hostID)
	if err != nil {
		return err
	}
	status := HostStatusPayload{
		HostId:     hostID,
		Online:     true,
		Streaming:  record.Status.Streaming,
		Monitoring: record.Status.Monitoring,
	}
	return PushHostStatus2User(record.UserId, status)
}

func GetHostStatus(hostID uint64) (HostStatus, error) {
	record, err := GetHostRecord(hostID)
	if err != nil {
		return HostStatus{}, err
	}
	return record.Status, nil
}

func GetHostRecord(hostID uint64) (*HostRecord, error) {
	data, ok := HostWsConnMap.Load(hostID)
	if !ok {
		return nil, errors.New("host is offline")
	}
	return data.(*HostRecord), nil
}

func IsHostOnline(hostID uint64) bool {
	_, ok := HostWsConnMap.Load(hostID)
	return ok
}

func dropHostWsConnItem(hostID uint64) error {
	record, err := GetHostRecord(hostID)
	if err != nil {
		return err
	}
	status := HostStatusPayload{
		HostId:     hostID,
		Online:     false,
		Streaming:  false,
		Monitoring: false,
	}
	_ = PushHostStatus2User(record.UserId, status)
	HostWsConnMap.Delete(hostID)
	return nil
}
