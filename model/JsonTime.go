package model

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"time"
)

type JsonTime struct {
	time.Time
}

func (jt JsonTime) MarshalJSON() ([]byte, error) {
	stamp := strconv.FormatInt(jt.Time.Unix(), 10)
	return []byte(stamp), nil
}

func (jt *JsonTime) UnmarshalJSON(b []byte) error {
	timeStamp, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("can not convert %s to timestamp", string(b))
	}
	*jt = JsonTime{Time: time.Unix(int64(timeStamp), 0)}
	return nil
}

func (jt JsonTime) Value() (driver.Value, error) {
	var zeroTime time.Time
	if jt.Time.UnixNano() == zeroTime.UnixNano() {
		return nil, nil
	}
	return jt.Time, nil
}

func (jt *JsonTime) Scan(v interface{}) error {
	value, ok := v.(time.Time)
	if ok {
		*jt = JsonTime{Time: value}
		return nil
	}
	return fmt.Errorf("can not convert %s to timestamp", v)
}
