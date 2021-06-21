package database

import (
	"fmt"
	"github.com/go-redis/redis/v8"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"hsserver/config"
	"hsserver/model"
)

var GormDB *gorm.DB
var TokenDB *redis.Client
var CodeDB *redis.Client
var RegisterDB *redis.Client

func MysqlConnect() {
	cfg := config.Config.MySql
	conn, err := gorm.Open(
		mysql.Open(
			fmt.Sprintf(
				"%s:%s@tcp(%s)/%s?charset=utf8&parseTime=true",
				cfg.User,
				cfg.Password,
				cfg.Addr,
				cfg.Database)), &gorm.Config{})
	if err != nil {
		panic("Could not connect to the database!")
	}
	GormDB = conn

	_ = conn.AutoMigrate(&model.User{})
	_ = conn.AutoMigrate(&model.HomeHost{})
	_ = conn.AutoMigrate(&model.HostBinding{})
	_ = conn.AutoMigrate(&model.Alarm{})
}

func RedisConnect() {
	cfg := config.Config.Redis
	TokenDB = redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.Databases.Token,
	})
	CodeDB = redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.Databases.VerificationCode,
	})
	RegisterDB = redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.Databases.Register,
	})
}
