package wsserver

import (
	"bytes"
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"hsserver/authentication"
	"hsserver/logger"
	"time"
)

type HostWsConn struct {
	WsConnection
}

const (
	HostTypeHostStatus = 1
)

func (wsh *HostWsConn) wsReadProcLoop() {
	for {
		_, data, err := wsh.wsReadMessage()
		if err != nil {
			wsh.log.Error("Read error: ", err)
			return
		}
		if bytes.Equal(data, clientClose) {
			wsh.log.Info("Websocket closed by client")
			wsh.wsClose(false)
		}
		var msg WsMessage
		err = json.Unmarshal(data, &msg)
		if err != nil {
			wsh.log.Error("Parsing data error: ", err)
			continue
		}
		switch msg.Type {
		case HostTypeHostStatus:
			status := HostStatus{
				Monitoring: msg.Payload["monitoring"].(bool),
				Streaming:  msg.Payload["streaming"].(bool),
			}
			updateHostStatus(wsh.id, status)
			_ = reportHostStatus2User(wsh.id)
		default:
			wsh.log.Error("Wrong message type")
		}
	}
}

func WsHomeHostHandler(c *gin.Context) {

	log := logger.Log.WithFields(logrus.Fields{"conn-type": "websocket", "api": "host", "addr": c.Request.RemoteAddr})
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	hostID := claims.UserId
	wsSocket, err := WsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error("Websocket error: ", err)
		return
	}
	log.Info("Websocket established")

	wsConn := &HostWsConn{
		WsConnection{
			wsSocket:         wsSocket,
			readChan:         make(chan *WsData, 1000),
			writeChan:        make(chan *WsData, 1000),
			hbChan:           make(chan string, 100),
			closeChan:        make(chan byte),
			log:              log,
			isClosed:         false,
			closeSent:        false,
			id:               hostID,
			dropConnItemFunc: dropHostWsConnItem,
		},
	}
	registerHostWsConn(hostID, wsConn)
	wsConn.wsSocket.SetPingHandler(wsConn.wsHeartbeatHandler)
	wsConn.wsSocket.SetCloseHandler(
		func(code int, text string) error {
			if !wsConn.isClosed {
				wsConn.isClosed = true
				message := websocket.FormatCloseMessage(code, "")
				_ = wsConn.wsSocket.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
				err = wsConn.dropConnItemFunc(hostID)
				if err != nil {
					wsConn.log.Warn("Failed to remove connecting record: ", err)
				}
				wsConn.log.Info("Websocket closed")
			}
			return nil
		})

	go wsConn.wsReadLoop()
	go wsConn.wsWriteLoop()
	go wsConn.wsHeartbeat()
	go wsConn.wsReadProcLoop()

	_ = initHost(hostID)
}
