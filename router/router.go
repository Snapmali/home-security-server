package router

import (
	"github.com/gin-gonic/gin"
	"hsserver/authentication"
	"hsserver/controller"
	"hsserver/controller/wsserver"
)

func InitRouter(app *gin.Engine) {
	app.GET("/ws/home_host", authentication.Middleware, wsserver.WsHomeHostHandler)
	app.GET("/ws/user", authentication.MiddlewareWithAvailableControl, wsserver.WsUserHandler)

	app.POST("/auth/auth_jwt", controller.AuthenticationHandler)
	app.POST("/auth/verify_binding", controller.CheckBindingHandler)

	authHostGroup := app.Group("/auth/home_host")
	authHostGroup.POST("/register", controller.HostRegisterHandler)
	authHostGroup.POST("/login", controller.HostLoginHandler)

	authUserGroup := app.Group("/auth/user")
	authUserGroup.POST("/register", controller.UserRegisterSendCodeHandler)
	authUserGroup.POST("/register/verification", controller.UserRegisterVerificationHandler)
	authUserGroup.POST("/login", controller.UserLoginHandler)
	authUserGroup.POST("/fgt_pwd", controller.UserForgetPasswordSendCodeHandler)
	authUserGroup.POST("/fgt_pwd/verification", controller.UserForgetPasswordVerificationHandler)
	authUserGroup.POST("/fgt_pwd/reset", authentication.Middleware, controller.UserForgetPasswordResetHandler)

	userGroup := app.Group("/user")
	userGroup.GET("/home_host/pull", authentication.MiddlewareWithAvailableControl, controller.UserPullHostsHandler)
	userGroup.GET("/home_host/get", authentication.MiddlewareWithAvailableControl, controller.UserGetHostHandler)
	userGroup.POST("/home_host/rename", authentication.MiddlewareWithAvailableControl, controller.UserUpdateHostInfoHandler)
	userGroup.POST("/home_host/unbinding", authentication.MiddlewareWithAvailableControl, controller.UserUnbindingHandler)

	userGroup.POST("/rst_pwd", authentication.MiddlewareWithAvailableControl, controller.UserResetPasswordHandler)
	userGroup.POST("/streaming/start", authentication.MiddlewareWithAvailableControl, controller.UserStreamingStartHandler)
	userGroup.POST("/streaming/stop", authentication.MiddlewareWithAvailableControl, controller.UserStreamingStopHandler)
	userGroup.POST("/monitoring/start", authentication.MiddlewareWithAvailableControl, controller.UserMonitoringStartHandler)
	userGroup.POST("/monitoring/stop", authentication.MiddlewareWithAvailableControl, controller.UserMonitoringStopHandler)

	userGroup.GET("/alarm/pull", authentication.MiddlewareWithAvailableControl, controller.UserPullAlarmsHandler)
	userGroup.GET("/alarm/get", authentication.MiddlewareWithAvailableControl, controller.UserGetAlarmHandler)
	userGroup.GET("/alarm/img", authentication.MiddlewareWithAvailableControl, controller.UserGetAlarmImgHandler)

	hostGroup := app.Group("/home_host")
	hostGroup.POST("/sensor_alarm", authentication.Middleware, controller.HostAlarmHandler)
	hostGroup.POST("/binding", authentication.Middleware, controller.HostBindingHandler)
}
