package model

type HomeHost struct {
	ID       uint   `json:"id"          gorm:"primary_key"`
	Hostname string `json:"hostname"    gorm:"unique"`
	Password []byte `json:"-"`
}
