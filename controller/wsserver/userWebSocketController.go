package wsserver

import (
	"encoding/json"
	"errors"
	"github.com/gorilla/websocket"
	"hsserver/model"
	"sync"
)

const (
	UserTypeHostStatus = 1
	UserTypeAlarm      = 2
)

var (
	UserWsConnMap sync.Map
)

type UserRecord struct {
	WsConn *UserWsConn
	ID     uint64
}

func registerUserWsConn(userID uint64, userWsConn *UserWsConn) {
	UserWsConnMap.Store(userID, &UserRecord{
		WsConn: userWsConn,
		ID:     userID,
	})
}

func dropUserWsConnItem(userID uint64) error {
	UserWsConnMap.Delete(userID)
	return nil
}

func PushAlarm2User(userID uint64, alarm model.Alarm) error {
	message := Alarm2UserMessage{
		Type:    UserTypeAlarm,
		Payload: alarm,
	}
	return PushMessage2User(userID, message)
}

func PushHostStatus2User(userId uint64, status HostStatusPayload) error {
	message := HostStatus2UserMessage{
		Type:    UserTypeHostStatus,
		Payload: status,
	}
	return PushMessage2User(userId, message)
}

func PushMessage2User(userID uint64, message interface{}) error {
	record, err := GetUserWsConn(userID)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(message)
	return record.WsConn.WriteMessage(websocket.TextMessage, data)
}

func GetUserWsConn(userID uint64) (*UserRecord, error) {
	data, ok := UserWsConnMap.Load(userID)
	if !ok {
		return nil, errors.New("user is offline")
	}
	return data.(*UserRecord), nil
}

func CloseUserWsConn(userId uint64) error {
	record, err := GetUserWsConn(userId)
	if err != nil {
		return err
	}
	record.WsConn.wsClose(false)
	return nil
}
