package authentication

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

const (
	InvalidToken     = 301
	LoginAgainNeeded = 302

	DatabaseFailure = 501
)

// Authentication middleware without token available control.
// It also stores claims as key/value pair for this context. You can get it with c.Get("claims").
func Middleware(c *gin.Context) {
	claims, err := authAndGetClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error(), "code": InvalidToken})
		c.Abort()
		return
	}
	c.Set("claims", claims)
	c.Next()
}

// Authentication middleware with token available control using redis.
// It also stores claims as key/value pair for this context. You can get it with c.Get("claims").
func MiddlewareWithAvailableControl(c *gin.Context) {
	claims, err := authAndGetClaims(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error(), "code": InvalidToken})
		c.Abort()
		return
	}
	ok, err := DoesTokenRecordExist(claims.UserId, claims.Id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error(), "code": DatabaseFailure})
		c.Abort()
		return
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "token is invalid, please log in again", "code": LoginAgainNeeded})
		c.Abort()
		return
	}
	c.Set("claims", claims)
	c.Next()
}

func authAndGetClaims(c *gin.Context) (*Claims, error) {
	tokenString, err := GetTokenString(c.Request)
	if err != nil {
		return nil, err
	}
	claims, err := ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	return claims, nil
}
