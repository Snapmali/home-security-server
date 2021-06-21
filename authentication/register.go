package authentication

import (
	"context"
	"hsserver/database"
	"hsserver/model"
	"time"
)

func RecordRegister(r model.RegisterRecord, d time.Duration) error {
	ctx := context.Background()
	_, err := database.RegisterDB.Del(ctx, r.Username).Result()
	if err != nil {
		return err
	}
	_, err = database.RegisterDB.RPush(ctx, r.Username, r.Code, r.Email, r.Password).Result()
	if err != nil {
		return err
	}
	_, err = database.RegisterDB.Expire(ctx, r.Username, d).Result()
	if err != nil {
		return err
	}
	return nil
}

func GetRegisterRecord(username string) (model.RegisterRecord, error) {
	ctx := context.Background()
	record, err := database.RegisterDB.LRange(ctx, username, 0, 2).Result()
	if err != nil {
		return model.RegisterRecord{}, err
	}
	if len(record) == 0 {
		return model.RegisterRecord{}, nil
	}
	r := model.RegisterRecord{
		Code:     record[0],
		Username: username,
		Email:    record[1],
		Password: []byte(record[2]),
	}
	return r, err
}
