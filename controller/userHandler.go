package controller

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"hsserver/authentication"
	"hsserver/controller/streaming"
	"hsserver/controller/wsserver"
	"hsserver/database"
	"hsserver/email"
	"hsserver/logger"
	"hsserver/model"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func UserRegisterSendCodeHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_register_send_code", "addr": c.Request.RemoteAddr})
	log.Info("User register: send verification code")
	var data UserRegSendCodeRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	// 用户名邮箱密码合法性检查
	if !CheckUsername(data.Username) {
		log.Info(fmt.Sprintf("Invalid username: %s", data.Username))
		c.JSON(http.StatusForbidden, InvalidUsernameResponse)
		return
	}
	if !CheckEmail(data.Email) {
		log.Info(fmt.Sprintf("Invalid email: %s", data.Email))
		c.JSON(http.StatusForbidden, InvalidEmailResponse)
		return
	}
	if !CheckPassword(data.Password) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	var user model.User
	database.GormDB.Where("username = ?", data.Username).First(&user)
	if user.ID != 0 {
		log.Info("Registering username already exists")
		var response = BaseResponse{
			Message: "username has been registered",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	database.GormDB.Where("email = ?", data.Email).First(&user)
	if user.ID != 0 {
		log.Info("Registering email already exists")
		var response = BaseResponse{
			Message: "email address has been registered",
			Code:    2,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	code := authentication.GenerateVerificationCode(6)
	password, _ := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	record := model.RegisterRecord{
		Code:     string(code),
		Username: data.Username,
		Email:    data.Email,
		Password: password,
	}
	err = authentication.RecordRegister(record, 15*time.Minute)
	if err != nil {
		log.Error("Unable to store the register record to redis: ", err)
		var response = BaseResponse{
			Message: "unable to store the register record",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	user = model.User{
		Username: data.Username,
		Email:    data.Email,
	}
	err = email.SendVerificationCode(user, "家庭安防-注册验证", code)
	if err != nil {
		log.Error("Unable send the email: ", err)
		var response = BaseResponse{
			Message: "unable to send the verification code via email",
			Code:    EmailFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("User register: verification code sent")
}

func UserRegisterVerificationHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_register_verification", "addr": c.Request.RemoteAddr})
	log.Info("User register: code verification")
	var data UserRegVerificationRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	// 用户名验证码合法性检查
	if !CheckUsername(data.Username) {
		log.Info(fmt.Sprintf("Invalid username: %s", data.Username))
		c.JSON(http.StatusForbidden, InvalidUsernameResponse)
		return
	}
	if !CheckVerificationCode(data.Code) {
		log.Info(fmt.Sprintf("Invalid verification code: %s", data.Code))
		c.JSON(http.StatusForbidden, InvalidVerificationCodeResponse)
		return
	}
	r, err := authentication.GetRegisterRecord(data.Username)
	if err != nil {
		log.Error("Unable to get the register record from redis: ", err)
		var response = BaseResponse{
			Message: "unable to get the register record",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if r.Code == "" {
		log.Warn("Register record not found")
		var response = BaseResponse{
			Message: "register record not found",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	code := strings.ToUpper(data.Code)
	if r.Code != code {
		log.Info("Wrong verification code")
		var response = BaseResponse{
			Message: "wrong verification code",
			Code:    2,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	user := model.User{
		Username: r.Username,
		Email:    r.Email,
		Password: r.Password,
	}
	result := database.GormDB.Create(&user)
	if result.Error != nil {
		log.Info("Registering username already exists")
		var response = BaseResponse{
			Message: "user has been registered",
			Code:    3,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("User register succeed")
}

func UserLoginHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_login", "addr": c.Request.RemoteAddr})
	log.Info("User login")
	var data UserLoginRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	var user model.User
	if data.IdtfType == IdtfUsername {
		if !CheckUsername(data.Identifier) {
			log.Info(fmt.Sprintf("Invalid username: %s", data.Identifier))
			c.JSON(http.StatusForbidden, InvalidUsernameResponse)
			return
		}
		if !CheckPassword(data.Password) {
			log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
			c.JSON(http.StatusForbidden, InvalidPasswordResponse)
			return
		}
		database.GormDB.Where("username = ?", data.Identifier).First(&user)
	} else if data.IdtfType == IdtfEmail {
		if !CheckEmail(data.Identifier) {
			log.Info(fmt.Sprintf("Invalid email: %s", data.Identifier))
			c.JSON(http.StatusForbidden, InvalidEmailResponse)
			return
		}
		if !CheckPassword(data.Password) {
			log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
			c.JSON(http.StatusForbidden, InvalidPasswordResponse)
			return
		}
		database.GormDB.Where("email = ?", data.Identifier).First(&user)
	} else {
		c.JSON(http.StatusBadRequest, InvalidIdentifierTypeResponse)
		return
	}
	if user.ID == 0 {
		log.Info("User unregistered")
		var response = BaseResponse{
			Message: "user unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(data.Password))
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
		UserId:         uint64(user.ID),
		StandardClaims: jwt.StandardClaims{Audience: "user"},
	}
	token := authentication.GenerateToken(&claims, 48*time.Hour)
	err = authentication.RecordToken(uint64(user.ID), claims.Id, claims.ExpiresAt)
	if err != nil {
		log.Error("Unable to store the token to redis: ", err)
		var response = BaseResponse{
			Message: "unable to store the token",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":  "success",
		"code":     Success,
		"username": user.Username,
		"user_id":  user.ID,
		"token":    token,
	})
	log.Info("User login succeed")
}

func UserForgetPasswordSendCodeHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_forget_send_code", "addr": c.Request.RemoteAddr})
	log.Info("User forget password: send verification code")
	var data IdentifierPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	var user model.User
	if data.IdtfType == IdtfUsername {
		if !CheckUsername(data.Identifier) {
			log.Info(fmt.Sprintf("Invalid username: %s", data.Identifier))
			c.JSON(http.StatusForbidden, InvalidUsernameResponse)
			return
		}
		database.GormDB.Where("username = ?", data.Identifier).First(&user)
	} else if data.IdtfType == IdtfEmail {
		if !CheckEmail(data.Identifier) {
			log.Info(fmt.Sprintf("Invalid email: %s", data.Identifier))
			c.JSON(http.StatusForbidden, InvalidEmailResponse)
			return
		}
		database.GormDB.Where("email = ?", data.Identifier).First(&user)
	} else {
		log.Warn("Wrong identifier type")
		c.JSON(http.StatusBadRequest, InvalidIdentifierTypeResponse)
		return
	}
	if user.ID == 0 {
		log.Info("User unregistered")
		var response = BaseResponse{
			Message: "user unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	code := authentication.GenerateVerificationCode(6)
	err = authentication.RecordVerificationCode(strconv.FormatUint(uint64(user.ID), 10), string(code), 15*time.Minute)
	if err != nil {
		log.Error("Unable to store the verification code to redis: ", err)
		var response = BaseResponse{
			Message: "unable to store the verification code",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	err = email.SendVerificationCode(user, "家庭安防-找回密码验证", code)
	if err != nil {
		log.Error("Unable send the email: ", err)
		var response = BaseResponse{
			Message: "unable to send the verification code via email",
			Code:    EmailFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "success", "code": Success, "user_id": user.ID})
	log.Info("User forget password: verification code sent")
}

func UserForgetPasswordVerificationHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_forget_verification", "addr": c.Request.RemoteAddr})
	log.Info("User forget password: code verification")
	var data UserFgtPwdVerificationRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	if !CheckVerificationCode(data.Code) {
		log.Info(fmt.Sprintf("Invalid verification code: %s", data.Code))
		c.JSON(http.StatusForbidden, InvalidVerificationCodeResponse)
		return
	}
	code := strings.ToUpper(data.Code)
	ok, err := authentication.DoesVerificationCodeExist(strconv.FormatUint(data.UserId, 10), code)
	if err != nil {
		log.Error("Failed to check verification code: ", err)
		var response = BaseResponse{
			Message: err.Error(),
			Code:    InternalError,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if !ok {
		log.Info("Wrong verification code")
		var response = BaseResponse{
			Message: "wrong verification code",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	claims := authentication.Claims{
		UserId:         data.UserId,
		StandardClaims: jwt.StandardClaims{Audience: "register"},
	}
	token := authentication.GenerateToken(&claims, 5*time.Minute)
	c.JSON(http.StatusOK, gin.H{"message": "success", "code": Success, "token": token})
	log.Info("User forget password: verification code verified")
}

func UserForgetPasswordResetHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_forget_reset", "addr": c.Request.RemoteAddr})
	log.Info("User forget password: password reset")
	var data UserFgtPwdResetRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	if !CheckPassword(data.Password) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.Password))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	err = authentication.ClearTokenRecords(data.UserId)
	if err != nil {
		log.Error("Failed to clear existing tokens: ", err)
		var response = BaseResponse{
			Message: "failed to clear existing tokens",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	user := model.User{ID: uint(data.UserId)}
	passwordByte, _ := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	result := database.GormDB.Model(&user).Update("password", passwordByte)
	if result.Error != nil {
		log.Error("Failed to update the password: ", result.Error)
		var response = BaseResponse{
			Message: "failed to reset the password",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if result.RowsAffected == 0 {
		log.Warn("User id not found")
		var response = BaseResponse{
			Message: "user unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("User forget password: password reset successfully")
}

func UserResetPasswordHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_reset_password", "addr": c.Request.RemoteAddr})
	log.Info("User reset password")
	var data UserResetPasswordRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	if !CheckPassword(data.Old) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.Old))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	if !CheckPassword(data.New) {
		log.Info(fmt.Sprintf("Invalid password: %s", data.New))
		c.JSON(http.StatusForbidden, InvalidPasswordResponse)
		return
	}
	var user model.User
	database.GormDB.Where("id = ?", data.UserId).First(&user)
	if user.ID == 0 {
		log.Warn("User id not found")
		var response = BaseResponse{
			Message: "user unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	err = bcrypt.CompareHashAndPassword(user.Password, []byte(data.Old))
	if err != nil {
		log.Info("Wrong password")
		var response = BaseResponse{
			Message: "wrong password",
			Code:    2,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	err = authentication.ClearTokenRecords(uint64(user.ID))
	if err != nil {
		log.Error("Failed to clear existing tokens: ", err)
		var response = BaseResponse{
			Message: "failed to clear existing tokens",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	_ = wsserver.CloseUserWsConn(uint64(user.ID))
	password, _ := bcrypt.GenerateFromPassword([]byte(data.New), bcrypt.DefaultCost)
	result := database.GormDB.Model(&user).Update("password", password)
	if result.Error != nil {
		log.Error("Failed to update the password: ", result.Error)
		var response = BaseResponse{
			Message: "failed to reset the password",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if result.RowsAffected == 0 {
		log.Warn("User id not found while updating password")
		var response = BaseResponse{
			Message: "user unregistered",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("User password reset successfully")
}

func UserUnbindingHandler(c *gin.Context) {
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
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id: ", err)
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	binding := model.HostBinding{
		HostID: uint(data.HostId),
		UserID: uint(data.UserId),
	}
	result := database.GormDB.Where("user_id = ?", binding.UserID).Delete(&binding)
	if result.Error != nil {
		log.Error("Failed to unbind the host: ", result.Error)
		var response = BaseResponse{
			Message: "failed to unbind the host",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if result.RowsAffected == 0 {
		log.Warn("User is not bound to the host")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	message := wsserver.WsMessage{
		Type:    wsserver.HostTypeUnbinding,
		Payload: map[string]interface{}{},
	}
	_ = wsserver.PushMessage2Host(data.HostId, message)
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("Unbinding succeed")
}

func UserStreamingStartHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_start_streaming", "addr": c.Request.RemoteAddr})
	log.Info("User streaming request")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	// 判断绑定关系
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if uint64(binding.UserID) != data.UserId {
		log.Warn("Host is not bound with the user")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	// 请求直播key
	key, err := streaming.GetRoomKey(data.HostId)
	if err != nil {
		log.Error("Can't get the streaming key: ", err)
		var response = BaseResponse{
			Message: "can't get the streaming key",
			Code:    InternalError,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	// 向主机发送websocket消息请求直播
	message := wsserver.WsMessage{
		Type:    wsserver.HostTypeStartStreaming,
		Payload: map[string]interface{}{"key": key},
	}
	err = wsserver.PushMessage2Host(data.HostId, message)
	if err != nil {
		log.Info(fmt.Sprintf("Host is offline: %d", data.HostId))
		var response = BaseResponse{
			Message: "host is offline",
			Code:    2,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "start streaming request sent", "code": SuccessResponse})
	log.Info("Start streaming request sent")
}

func UserStreamingStopHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_stop_streaming", "addr": c.Request.RemoteAddr})
	log.Info("User stop streaming")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	// 判断绑定关系
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if uint64(binding.UserID) != data.UserId {
		log.Warn("Host is not bound with the user")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	// 查询是否仍有其他观看者
	stat, err := streaming.GetRoomStat(data.HostId)
	if err != nil {
		log.Error("Can't get the streaming room statics: ", err)
		var response = BaseResponse{
			Message: "can't get the streaming key",
			Code:    InternalError,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if stat.Players == nil {
		// 向主机发送websocket消息停止直播
		message := wsserver.WsMessage{
			Type:    wsserver.HostTypeStopStreaming,
			Payload: map[string]interface{}{},
		}
		err = wsserver.PushMessage2Host(data.HostId, message)
		if err != nil {
			log.Info(fmt.Sprintf("Host is offline: %d", data.HostId))
			var response = BaseResponse{
				Message: "host is offline",
				Code:    2,
			}
			c.JSON(http.StatusNotFound, response)
			return
		}
		// 请求删除房间
		_, err = streaming.DeleteRoom(data.HostId)
		if err != nil {
			log.Info(fmt.Sprintf("Host isn't streaming: %d", data.HostId))
			var response = BaseResponse{
				Message: "host is not streaming",
				Code:    3,
			}
			c.JSON(http.StatusNotFound, response)
			return
		}
		c.JSON(http.StatusAccepted, gin.H{"message": "stop streaming request sent", "code": Success})
		log.Info("Stop streaming request sent")
	} else {
		c.JSON(http.StatusAccepted, gin.H{"message": "other viewers exist, streaming won't be stopped", "code": Success})
		log.Info("Other viewers exist, streaming won't be stopped")
	}
}

func UserMonitoringStartHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_start_monitoring", "addr": c.Request.RemoteAddr})
	log.Info("User start monitoring")
	var data UserMonitoringStartRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	if data.SavingMode != wsserver.CaptureAlwaysSave && data.SavingMode != wsserver.CaptureSaveWhenMoving {
		log.Error("Parameter error")
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	// 判断绑定关系
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if uint64(binding.UserID) != data.UserId {
		log.Warn("Host is not bound with the user")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	message := wsserver.WsMessage{
		Type:    wsserver.HostTypeStartMonitoring,
		Payload: map[string]interface{}{"save_mode": data.SavingMode},
	}
	err = wsserver.PushMessage2Host(data.HostId, message)
	if err != nil {
		log.Info(fmt.Sprintf("Host is offline: %d", data.HostId))
		var response = BaseResponse{
			Message: "host is offline",
			Code:    2,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "start monitoring request sent", "code": Success})
	log.Info("Start monitoring request sent")
}

func UserMonitoringStopHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_stop_monitoring", "addr": c.Request.RemoteAddr})
	log.Info("User stop monitoring")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	// 判断绑定关系
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if uint64(binding.UserID) != data.UserId {
		log.Warn("Host is not bound with the user")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	message := wsserver.WsMessage{
		Type:    wsserver.HostTypeStopMonitoring,
		Payload: map[string]interface{}{},
	}
	err = wsserver.PushMessage2Host(data.HostId, message)
	if err != nil {
		log.Info(fmt.Sprintf("Host is offline: %d", data.HostId))
		var response = BaseResponse{
			Message: "host is offline",
			Code:    2,
		}
		c.JSON(http.StatusNotFound, response)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "stop monitoring request sent", "code": Success})
	log.Info("Stop monitoring request sent")
}

func UserPullAlarmsHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_pull_alarms", "addr": c.Request.RemoteAddr})
	log.Info("User pulling alarms")
	var data UserPullAlarmsRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	offset := data.Offset
	var alarms []model.Alarm
	if *offset == -1 {
		var total int64
		db := database.GormDB.Model(&model.Alarm{}).Where("user_id = ?", data.UserId)
		if data.HostId != 0 {
			db = db.Where("host_id = ?", data.HostId)
		}
		db.Count(&total)
		*offset = int(total) - data.PageSize
		if *offset < 0 {
			*offset = 0
		}
		db.Scopes(Paginate(*offset, data.PageSize)).Find(&alarms)
	} else {
		db := database.GormDB.Model(&model.Alarm{}).Where("user_id = ?", data.UserId)
		if data.HostId != 0 {
			db = db.Where("host_id = ?", data.HostId)
		}
		db.Scopes(Paginate(*offset, data.PageSize)).Find(&alarms)
	}
	if len(alarms) == 0 {
		c.JSON(http.StatusOK, UserPullAlarmsResponse{
			BaseResponse: BaseResponse{
				Message: "no alarms found",
				Code:    Success,
			},
			Offset: *offset,
			Alarms: &[]model.Alarm{},
		})
		log.Info("User alarms list sent")
		return
	}
	response := UserPullAlarmsResponse{
		BaseResponse: SuccessResponse,
		Offset:       *offset,
		Alarms:       &alarms,
	}
	c.JSON(http.StatusOK, response)
	log.Info("User alarms list sent")
}

func UserGetAlarmHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_get_alarm", "addr": c.Request.RemoteAddr})
	log.Info("User get alarm")
	var data UserGetAlarmRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	var alarm model.Alarm
	result := database.GormDB.Model(&model.Alarm{}).Where("id", data.AlarmId).First(&alarm)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Warn("Alarm record not found: ", data.AlarmId)
		var response = BaseResponse{
			Message: "alarm record not found",
			Code:    1,
		}
		c.JSON(http.StatusNotFound, response)
		return
	} else if result.Error != nil {
		log.Error("Failed to get the alarm record: ", result.Error)
		var response = BaseResponse{
			Message: "failed to get the alarm record",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if uint64(alarm.UserID) != data.UserId {
		log.Warn("Alarm record does not belong to the user")
		var response = BaseResponse{
			Message: "alarm record does not belong to the user",
			Code:    2,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	response := UserGetAlarmResponse{
		BaseResponse: SuccessResponse,
		Alarm:        alarm,
	}
	c.JSON(http.StatusOK, response)
	database.GormDB.Model(&model.Alarm{ID: alarm.ID}).Update("viewed", true)
	log.Info("Alarm record sent")
}

func UserGetAlarmImgHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_alarm_image", "addr": c.Request.RemoteAddr})
	log.Info("User get alarm image")
	var data UserGetAlarmImgRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	filepath := fmt.Sprintf("img/%d/%s", data.UserId, data.Image)
	c.File(filepath)
	log.Info("Alarm image sent")
}

func UserPullHostsHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_pull_hosts", "addr": c.Request.RemoteAddr})
	log.Info("User pull host info list")
	userId, err := strconv.ParseUint(c.Query("user_id"), 0, 64)
	if err != nil {
		log.Error("parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != userId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	var hosts []HostInfo
	database.GormDB.Model(&model.HostBinding{}).Where("user_id = ?", userId).Find(&hosts)
	if len(hosts) == 0 {
		c.JSON(http.StatusOK, UserPullHostsResponse{
			BaseResponse: BaseResponse{
				Message: "no hosts found",
				Code:    Success,
			},
			Hosts: &[]HostInfo{},
		})
		log.Info("User host info list sent")
		return
	}
	for i := range hosts {
		status, err := wsserver.GetHostStatus(hosts[i].HostId)
		if err != nil {
			hosts[i].Online = false
			hosts[i].Monitoring = false
			hosts[i].Streaming = false
		} else {
			hosts[i].Online = true
			hosts[i].Monitoring = status.Monitoring
			hosts[i].Streaming = status.Streaming
		}
	}
	response := UserPullHostsResponse{
		BaseResponse: SuccessResponse,
		Hosts:        &hosts,
	}
	c.JSON(http.StatusOK, response)
	log.Info("User host info list sent")
}

func UserGetHostHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_get_host", "addr": c.Request.RemoteAddr})
	log.Info("User get host info")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	var host HostInfo
	database.GormDB.Model(&model.HostBinding{}).Where("user_id = ?", data.UserId).First(&host, data.HostId)
	if host.HostId == 0 {
		log.Warn("User is not bound to the host")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	status, err := wsserver.GetHostStatus(host.HostId)
	if err != nil {
		host.Online = false
		host.Monitoring = false
		host.Streaming = false
	} else {
		host.Online = true
		host.Monitoring = status.Monitoring
		host.Streaming = status.Monitoring
	}
	response := UserGetHostResponse{
		BaseResponse: SuccessResponse,
		Host:         host,
	}
	c.JSON(http.StatusOK, response)
	log.Info("User host info sent")
}

func UserUpdateHostInfoHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "user_host_update", "addr": c.Request.RemoteAddr})
	log.Info("User update host info")
	var data UserUpdateHostInfoRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	claimsInterface, _ := c.Get("claims")
	claims := claimsInterface.(*authentication.Claims)
	if claims.UserId != data.UserId {
		log.Warn("User id does not match claim id")
		c.JSON(http.StatusBadRequest, ClaimNotMatchIdResponse)
		return
	}
	if !CheckScreenName(data.ScreenName) {
		log.Info(fmt.Sprintf("Invalid screen name: %s", data.ScreenName))
		c.JSON(http.StatusForbidden, InvalidScreenNameResponse)
		return
	}
	binding := model.HostBinding{HostID: uint(data.HostId)}
	result := database.GormDB.Model(&binding).Where("user_id = ?", data.UserId).Update("screen_name", data.ScreenName)
	if result.Error != nil {
		log.Error("Failed to update the host info: ", result.Error)
		var response = BaseResponse{
			Message: "failed to update the host info",
			Code:    DatabaseFailure,
		}
		c.JSON(http.StatusInternalServerError, response)
		return
	}
	if result.RowsAffected == 0 {
		log.Warn("User is not bound to the host")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusForbidden, response)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse)
	log.Info("User successfully updated host info")
}

// GORM查询分页器
func Paginate(offset int, pageSize int) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {

		if offset < 0 {
			offset = 0
		}

		switch {
		case pageSize > 100:
			pageSize = 100
		case pageSize <= 0:
			pageSize = 10
		}

		return db.Offset(offset).Limit(pageSize)
	}
}
