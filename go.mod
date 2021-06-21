module hsserver

go 1.15

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/go-redis/redis/v8 v8.7.1
	github.com/gorilla/websocket v1.4.2
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	gopkg.in/alexcesaro/quotedprintable.v3 v3.0.0-20150716171945-2caba252f4dc // indirect
	gopkg.in/gomail.v2 v2.0.0-20160411212932-81ebce5c23df
	gopkg.in/yaml.v2 v2.3.0
	gorm.io/driver/mysql v1.0.4
	gorm.io/gorm v1.21.3
)
