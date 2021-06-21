package streaming

import (
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"hsserver/config"
	"hsserver/logger"
	"net/http"
	"net/url"
	"strconv"
)

type RoomStatResponse struct {
	Status int      `json:"status"`
	Data   RoomStat `json:"data"`
}

type RoomStat struct {
	Key       string        `json:"key"`
	Publisher string        `json:"publisher"`
	Players   []interface{} `json:"players"`
}

func streamApiRequest(apiPath string, params *url.Values) (map[string]interface{}, error, int) {
	parseUrl, err := url.Parse(config.Config.Stream.ApiUrl + apiPath)
	if err != nil {
		return nil, err, 0
	}
	parseUrl.RawQuery = params.Encode()
	resp, err := http.Get(parseUrl.String())
	if err != nil {
		return nil, err, 0
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return nil, err, 0
	}
	return data, nil, resp.StatusCode
}

// Get stream room key or create a new room
func GetRoomKey(roomId uint64) (string, error) {
	log := logger.Log.WithFields(
		logrus.Fields{
			"conn-type": "http",
			"api":       "get_room",
			"id":        roomId})
	params := url.Values{}
	params.Set("room", strconv.FormatUint(roomId, 10))
	data, err, status := streamApiRequest("/control/get", &params)
	if err != nil {
		log.Error("Request api error: ", err)
		return "", err
	}
	if status != http.StatusOK {
		log.Error("Request api error: " + strconv.Itoa(status) + " " + data["data"].(string))
		return "", errors.New(data["data"].(string))
	}
	return data["data"].(string), nil
}

// Delete a stream room
func DeleteRoom(roomId uint64) (string, error) {
	log := logger.Log.WithFields(
		logrus.Fields{
			"conn-type": "http",
			"api":       "delete_room",
			"host-id":   roomId})
	params := url.Values{}
	params.Set("room", strconv.FormatUint(roomId, 10))
	data, err, status := streamApiRequest("/control/delete", &params)
	if err != nil {
		log.Error("Request api error: ", err)
		return "", err
	}
	if status == http.StatusNotFound {
		log.Warn("Room not found")
		return "", errors.New("room not found")
	} else if status != http.StatusOK {
		log.Error("Request api error: " + strconv.Itoa(status) + " " + data["data"].(string))
		return "", errors.New(data["data"].(string))
	}
	return data["data"].(string), nil
}

// Reset stream room key or create a new room
func ResetRoomKey(roomId uint64) (string, error) {
	log := logger.Log.WithFields(
		logrus.Fields{
			"conn-type": "http",
			"api":       "reset_room",
			"host-id":   roomId})
	params := url.Values{}
	params.Set("room", strconv.FormatUint(roomId, 10))
	data, err, status := streamApiRequest("/control/reset", &params)
	if err != nil {
		log.Error("Request api error: ", err)
		return "", err
	}
	if status != http.StatusOK {
		log.Error("Request api error: " + strconv.Itoa(status) + " " + data["data"].(string))
		return "", errors.New(data["data"].(string))
	}
	return data["data"].(string), nil
}

func GetRoomStat(roomId uint64) (*RoomStat, error) {
	log := logger.Log.WithFields(
		logrus.Fields{
			"conn-type": "http",
			"api":       "room_stat",
			"host-id":   roomId})
	params := url.Values{}
	params.Set("app", "live")
	params.Set("room", strconv.FormatUint(roomId, 10))
	data, err, status := streamApiRequest("/stat/roomstat", &params)
	if err != nil {
		log.Error("Request api error: ", err)
		return nil, err
	}
	if status != http.StatusOK {
		log.Error("Request api error: " + strconv.Itoa(status) + " " + data["data"].(string))
		return nil, errors.New(data["data"].(string))
	}
	data = data["data"].(map[string]interface{})
	stat := RoomStat{
		Key:       data["key"].(string),
		Publisher: data["publisher"].(string),
	}
	if data["players"] != nil {
		stat.Players = data["players"].([]interface{})
	}
	return &stat, nil
}
