package wsserver

import (
	"bytes"
	"errors"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"net/http"
	"sync"
	"time"

	"hsserver/logger"
)

type DropWsConnItemFunc func(id uint64) error

type WsData struct {
	messageType int
	data        []byte
}

type WsConnection struct {
	wsSocket  *websocket.Conn
	readChan  chan *WsData
	writeChan chan *WsData
	hbChan    chan string
	id        uint64

	log       *logrus.Entry
	mutex     sync.Mutex
	isClosed  bool
	closeSent bool
	closeChan chan byte

	dropConnItemFunc DropWsConnItemFunc
}

var (
	serverClose = []byte("server Close")
	clientClose = []byte("client close")
)

const (
	heartBeatTimeout = 30
)

var WsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 1024,
	// 跨域校验
	CheckOrigin: func(r *http.Request) bool {
		if r.Method != "GET" {
			logger.Log.WithFields(logrus.Fields{"conn-type": "websocket", "addr": r.RemoteAddr}).
				Error("Request method is not GET, but \"%s\"\n", r.Method)
			return false
		}
		return true
	},
}

func (wsConn *WsConnection) wsReadLoop() {
	for {
		msgType, data, err := wsConn.wsSocket.ReadMessage()
		if err != nil {
			wsConn.wsClose(false)
			return
		}
		msg := &WsData{
			msgType,
			data,
		}
		select {
		case wsConn.readChan <- msg:
		case <-wsConn.closeChan:
			return
		}
	}
}

func (wsConn *WsConnection) wsWriteLoop() {
	for {
		select {
		case msg := <-wsConn.writeChan:
			err := wsConn.wsSocket.WriteMessage(msg.messageType, msg.data)
			if err != nil {
				wsConn.wsClose(false)
				return
			}
		case <-wsConn.closeChan:
			return
		}
	}
}

func (wsConn *WsConnection) wsReadMessage() (int, []byte, error) {
	select {
	case msg := <-wsConn.readChan:
		return msg.messageType, msg.data, nil
	case <-wsConn.closeChan:

	}
	return 0, nil, errors.New("websocket closed")
}

func (wsConn *WsConnection) WriteMessage(messageType int, data []byte) error {
	select {
	case wsConn.writeChan <- &WsData{messageType: messageType, data: data}:
	case <-wsConn.closeChan:
		return errors.New("websocket closed")
	}
	return nil
}

func (wsConn *WsConnection) wsReadProcLoop() {
	for {
		_, data, err := wsConn.wsReadMessage()
		if err != nil {
			wsConn.log.Error("Read error: ", err)
			return
		}
		if bytes.Equal(data, clientClose) {
			wsConn.log.Info(" Websocket closed by client")
			wsConn.wsClose(false)
		}
		_ = wsConn.WriteMessage(websocket.TextMessage, append(data, " received!"...))
	}
}

func (wsConn *WsConnection) wsHeartbeatHandler(message string) error {
	wsConn.hbChan <- message
	if err := wsConn.WriteMessage(websocket.PongMessage, []byte(message)); err != nil {
		wsConn.log.Error("Heartbeat error: ", err)
		return err
	}
	return nil
}

func (wsConn *WsConnection) wsHeartbeat() {
	for {
		select {
		case <-wsConn.hbChan:
			continue
		case <-time.After(heartBeatTimeout * time.Second):
			wsConn.log.Error("Heartbeat timeout")
			wsConn.wsClose(false)
			return
		case <-wsConn.closeChan:
			return
		}
	}
}

func (wsConn *WsConnection) wsClose(sendClose bool) {
	_ = wsConn.wsSocket.Close()
	wsConn.mutex.Lock()
	if !wsConn.isClosed {
		wsConn.isClosed = true
		if sendClose {
			wsConn.closeSent = true
			_ = wsConn.WriteMessage(websocket.CloseMessage, serverClose)
		}
		close(wsConn.closeChan)
		err := wsConn.dropConnItemFunc(wsConn.id)
		if err != nil {
			wsConn.log.Warn("Failed to remove connecting record: ", err)
		}
		wsConn.log.Info("Websocket closed")
	}
	wsConn.mutex.Unlock()
}
