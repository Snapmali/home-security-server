package config

type ServerCfg struct {
	Stream Stream
	MySql  MySql
	Redis  Redis
	Email  Email
}

type Stream struct {
	ApiUrl string
}

type MySql struct {
	Addr     string
	Database string
	User     string
	Password string
}

type Redis struct {
	Addr      string
	Databases struct {
		Token            int
		VerificationCode int
		Register         int
	}
	Password string
}

type Email struct {
	User     string
	Password string
	Name     string
	Host     string
	Port     int
}
