package config

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"hsserver/logger"
	"io/ioutil"
)

var Config *ServerCfg

func init() {
	log := logger.Log.WithFields(logrus.Fields{"func": "config"})
	configFile, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Error("Can't read the config file: ", err)
		panic("Can't read the config file")
	}
	err = yaml.Unmarshal(configFile, &Config)
	if err != nil {
		log.Error("Config file format error: ", err)
		panic("Config file format error")
	}
}
