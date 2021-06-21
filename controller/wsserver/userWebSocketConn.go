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

type UserWsConn struct {
	WsConnection
}

func (wsu *UserWsConn) wsReadProcLoop() {
	for {
		_, data, err := wsu.wsReadMessage()
		if err != nil {
			wsu.log.Error("Read error: ", err)
			return
		}
		if bytes.Equal(data, clientClose) {
			wsu.log.Info("Websocket closed by client")
			wsu.wsClose(false)
		}
		var msg WsMessage
		err = json.Unmarshal(data, &msg)
		if err != nil {
			wsu.log.Error("Parsing data error: ", err)
			continue
		}
		switch msg.Type {
		default:
			wsu.log.Error("Wrong message type")
		}
	}
}

func WsUserHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "websocket", "api": "user", "addr": c.Request.RemoteAddr})
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	userID := claims.UserId
	wsSocket, err := WsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Error("Websocket error: ", err)
		return
	}
	log.Info("Websocket established")

	wsConn := &UserWsConn{
		WsConnection{
			wsSocket:         wsSocket,
			readChan:         make(chan *WsData, 1000),
			writeChan:        make(chan *WsData, 1000),
			hbChan:           make(chan string, 100),
			closeChan:        make(chan byte),
			log:              log,
			isClosed:         false,
			closeSent:        false,
			id:               userID,
			dropConnItemFunc: dropUserWsConnItem,
		},
	}
	registerUserWsConn(userID, wsConn)
	wsConn.wsSocket.SetPingHandler(wsConn.wsHeartbeatHandler)
	wsConn.wsSocket.SetCloseHandler(
		func(code int, text string) error {
			if !wsConn.isClosed {
				wsConn.isClosed = true
				message := websocket.FormatCloseMessage(code, "")
				_ = wsConn.wsSocket.WriteControl(websocket.CloseMessage, message, time.Now().Add(time.Second))
				_ = wsConn.dropConnItemFunc(userID)
				wsConn.log.Info("Websocket closed")
			}
			return nil
		})

	go wsConn.wsReadLoop()
	go wsConn.wsWriteLoop()
	go wsConn.wsHeartbeat()
	go wsConn.wsReadProcLoop()
}
