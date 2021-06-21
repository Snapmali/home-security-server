package authentication

import (
	"context"
	"github.com/go-redis/redis/v8"
	"hsserver/database"
	"math/rand"
	"time"
)

var VerificationCodeLetters = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func GenerateVerificationCode(length int) []byte {
	code := make([]byte, length)
	rand.Seed(time.Now().UnixNano())
	for i := range code {
		code[i] = VerificationCodeLetters[rand.Intn(len(VerificationCodeLetters))]
	}
	return code
}

func RecordVerificationCode(key string, code string, d time.Duration) error {
	ctx := context.Background()
	_, err := database.CodeDB.Set(ctx, key, code, d).Result()
	return err
}

func DoesVerificationCodeExist(key string, code string) (bool, error) {
	value, err := GetKeyValue(database.CodeDB, key)
	if err != nil {
		return false, err
	}
	if value == code {
		return true, nil
	}
	return false, nil
}

func GetKeyValue(db *redis.Client, key string) (string, error) {
	ctx := context.Background()
	value, err := db.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return value, nil
}
