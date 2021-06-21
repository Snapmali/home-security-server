package authentication

import (
	"context"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
	"github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"hsserver/database"
	"hsserver/logger"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const salt = "the quick brown fox jumps over a lazy dog"

type Claims struct {
	jwt.StandardClaims
	UserId uint64 `json:"user_id"`
}

// Generate JWT with jwt.StandardClaims.
// IssuedAt and ExpiresAt fields are automatically added.
func GenerateToken(claims *Claims, d time.Duration) string {
	claims.IssuedAt = time.Now().Unix()
	claims.ExpiresAt = time.Now().Add(d).Unix()
	claims.Id = uuid.NewV4().String()
	signedClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, _ := signedClaims.SignedString([]byte(salt))
	return token
}

func RecordToken(userId uint64, tokenId string, expireTime int64) error {
	ctx := context.Background()
	record := &redis.Z{
		Score:  float64(expireTime),
		Member: tokenId,
	}
	userIdStr := strconv.FormatUint(userId, 10)
	_, err := database.TokenDB.ZAdd(ctx, userIdStr, record).Result()
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	_, err = database.TokenDB.ZRemRangeByScore(ctx, userIdStr, strconv.Itoa(0), timestamp).Result()
	return nil
}

func ClearTokenRecords(userId uint64) error {
	ctx := context.Background()
	_, err := database.TokenDB.Del(ctx, strconv.FormatUint(userId, 10)).Result()
	if err != nil {
		return err
	}
	return nil
}

func ClearExpiredRecords(ctx context.Context) {
	log := logger.Log.WithFields(logrus.Fields{"func": "clean_expired tokens"})
	tick := time.NewTicker(12 * time.Hour).C
	for {
		select {
		case t := <-tick:
			keys, err := database.TokenDB.Keys(ctx, "*").Result()
			if err == nil {
				total := 0
				for _, key := range keys {
					select {
					case <-ctx.Done():
						return
					default:
						timestamp := strconv.FormatInt(time.Now().Unix(), 10)
						c, err := database.TokenDB.ZRemRangeByScore(ctx, key, strconv.Itoa(0), timestamp).Result()
						if err == nil {
							total += int(c)
						}
					}
				}
				log.Info(fmt.Sprintf("%d expired tokens have been cleared this time. Next Time: %s",
					total, t.Add(12*time.Hour).Format("2006-01-02 15:04:05 -0700 MST")))
			}
		case <-ctx.Done():
			return
		}
	}
}

// Get token string from HTTP Authorization request header
func GetTokenString(q *http.Request) (string, error) {
	data, ok := q.Header["Authorization"]
	if !ok {
		return "", errors.New("no auth method found")
	}
	tokenString := data[0]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return "", errors.New("token format error")
	}
	tokenString = tokenString[7:]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	return tokenString, nil
}

// Parse JWT string and get the claims.
func ParseToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, errors.New("token not found")
	}
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(salt), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.New("token is not valid")
	}
}

func DoesTokenRecordExist(userId uint64, tokenId string) (bool, error) {
	ctx := context.Background()
	_, err := database.TokenDB.ZRank(ctx, strconv.FormatUint(userId, 10), tokenId).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
