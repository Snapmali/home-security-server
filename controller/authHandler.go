package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"hsserver/authentication"
	"hsserver/database"
	"hsserver/logger"
	"hsserver/model"
	"net/http"
)

func AuthenticationHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "authentication", "addr": c.Request.RemoteAddr})
	log.Info("Authentication request")
	var data AuthenticationRequest
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}

	claims, err := authentication.ParseToken(data.Jwt)
	if err != nil {
		log.Info("Invalid token: ", err)
		c.JSON(http.StatusOK, BaseResponse{
			Message: err.Error(),
			Code:    InvalidToken,
		})
		return
	}
	if data.Verify {
		ok, err := authentication.DoesTokenRecordExist(claims.UserId, claims.Id)
		if err != nil {
			log.Error("Failed to check the token record in redis: ", err)
			c.JSON(http.StatusInternalServerError, BaseResponse{
				Message: err.Error(),
				Code:    DatabaseFailure,
			})
			c.Abort()
			return
		}
		if !ok {
			log.Info("Token is not available")
			c.JSON(http.StatusOK, BaseResponse{
				Message: "token is invalid, please log in again",
				Code:    LoginAgainNeeded,
			})
			c.Abort()
			return
		}
	}
	if data.Id != 0 {
		if claims.UserId != data.Id {
			log.Info("Id does not match claim id")
			c.JSON(http.StatusOK, ClaimNotMatchIdResponse)
			return
		}
	}
	c.JSON(Success, SuccessResponse)
	log.Info("Auth result sent")
}

func CheckBindingHandler(c *gin.Context) {
	log := logger.Log.WithFields(logrus.Fields{"conn-type": "http", "api": "binding_check", "addr": c.Request.RemoteAddr})
	log.Info("Binding check request")
	var data HostUserIdPair
	err := c.ShouldBind(&data)
	if err != nil {
		log.Error("Parameter error: ", err)
		c.JSON(http.StatusBadRequest, ParameterErrorResponse)
		return
	}
	var binding model.HostBinding
	database.GormDB.Where("host_id = ?", data.HostId).First(&binding)
	if uint64(binding.UserID) != data.UserId {
		log.Warn("Host is not bound with the user")
		var response = BaseResponse{
			Message: "user is not bound to the host",
			Code:    1,
		}
		c.JSON(http.StatusOK, response)
		return
	}
	c.JSON(Success, SuccessResponse)
	log.Info("Check result sent")
}
