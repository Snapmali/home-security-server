package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"hsserver/authentication"
	"hsserver/database"
	"hsserver/router"
)

func main() {
	database.MysqlConnect()
	database.RedisConnect()
	go authentication.ClearExpiredRecords(context.Background())
	app := gin.Default()
	router.InitRouter(app)
	_ = app.Run("0.0.0.0:7777")
}
