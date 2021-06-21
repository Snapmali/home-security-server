package controller

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"hsserver/authentication"
	"hsserver/controller/wsserver"
	"hsserver/database"
	"hsserver/logger"
	"hsserver/model"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func HostRegisterHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "host_register", "addr": c.Request.RemoteAddr})
	log.Info("Host register")
	var data HostnamePwdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Decoding body error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	// 用户名密码合法性检查
	if !CheckUsername(data.Hostname) {
		log.Info(fmt.Sprintf("Invalid hostname: %s", data.Hostname))
		c.JSON(http.StatusForbidden, InvalidUsernameResponse)
		return
	}
	if !CheckPassword(data.Password) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	password, _ := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	host := model.HomeHost{
		Hostname: data.Hostname,
		Password: password,
	}
	result := database.GormDB.Create(&host)
	if result.Error != nil {
		log.Info("Registering hostname already exists")
		var response = BaseResponse{
			Message: "hostname already exists",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("Host register replied")
}

func HostLoginHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "host_login", "addr": c.Request.RemoteAddr})
	log.Info("Host login")
	var data HostnamePwdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Decoding body error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	// 用户名密码合法性检查
	if !CheckUsername(data.Hostname) {
		log.Info(fmt.Sprintf("Invalid hostname: %s", data.Hostname))
		c.JSON(http.StatusForbidden, InvalidUsernameResponse)
		return
	}
	if !CheckPassword(data.Password) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	var host model.HomeHost
	database.GormDB.Where("hostname = ?", data.Hostname).First(&host)
	if host.ID == 0 {
		log.Info("Host unregistered")
		var response = BaseResponse{
			Message: "host unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	err = bcrypt.CompareHashAndPassword(host.Password, []byte(data.Password))
	if err != nil {
		log.Info("Wrong password")
		var response = BaseResponse{
			Message: "wrong password",
			Code:    2,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	claims := authentication.Claims{
		UserId:         uint64(host.ID),
		StandardClaims: jwt.StandardClaims{Audience: "host"},
	}
	token := authentication.GenerateToken(&claims, 48*time.Hour)
	var binding model.HostBinding
	database.GormDB.Where("user_id = ?", host.ID).First(&binding)
	c.JSON(http.StatusOK, gin.H{
		"message": "success",
		"code":    Success,
		"host_id": host.ID,
		"user_id": binding.UserID,
		"token":   token,
	})
	log.Info("Host login replied")
}

func HostAlarmHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "host_alarm", "addr": c.Request.RemoteAddr})
	log.Info("Alarm received")
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	var data HostAlarmRequest
	err := json.Unmarshal([]byte(c.PostForm("data")), &data)
	if err != nil {
		log.Error("Parsing data error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	if claims.UserId != data.HostId {
		log.Warn("Host id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	img, err := c.FormFile("img")
	if err != nil {
		log.Error("Img receiving error: ", err)
		var response = BaseResponse{
			Message: "image receiving error",
			Code:    ParameterError,
		}
		c.JSON(http.StatusBadRequest, response)
		return
	}
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if binding.UserID == 0 {
		log.Error("Host id not found")
		var response = BaseResponse{
			Message: "host unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	alarm := model.Alarm{
		UserID: binding.UserID,
		HostID: uint(data.HostId),
		Type:   data.Type,
		Desc:   data.Desc,
		Img:    img.Filename,
		Time:   data.Time,
	}
	ext := strings.ToLower(path.Ext(img.Filename))
	if ext != ".jpg" && ext != ".png" {
		log.Warn("Img format error")
		var response = BaseResponse{
			Message: "image format error",
			Code:    ParameterError,
		}
		c.JSON(http.StatusBadRequest, response)
		return
	}
	dir := fmt.Sprintf("img/%d/", binding.UserID)
	_, err = os.Stat(dir)
	if err != nil {
		err = os.Mkdir(dir, 0755)
		if err != nil {
			log.Error("Failed to create img file")
			var response = BaseResponse{
				Message: "server failed to save image",
				Code:    InternalError,
			}
			c.JSON(http.StatusInternalServerError, response)
			return
		}
	}
	err = c.SaveUploadedFile(img, dir+img.Filename)
	if err != nil {
		log.Error("Failed to create img file")
		var response = BaseResponse{
			Message: "server failed to save image",
			Code:    InternalError,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	err = database.GormDB.Create(&alarm).Error
	if err != nil {
		log.Error("Database failed when inserting alarm: ", err)
		var response = BaseResponse{
			Message: "database failed",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	_ = wsserver.PushAlarm2User(uint64(alarm.UserID), alarm)
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("Alarm replied")
}

func HostBindingHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_binding", "addr": c.Request.RemoteAddr})
	log.Info("Binding")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.HostId {
		log.Warn("Host id does not match claim id: ", err)
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	binding := model.HostBinding{
		HostID: uint(data.HostId),
		UserID: uint(data.UserId),
	}
	err = database.GormDB.Create(&binding).Error
	if err != nil {
		log.Warn("Failed to create binding record: ", err)
		var response = BaseResponse{
			Message: "failed to create binding record",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("Binding succeed")
}
