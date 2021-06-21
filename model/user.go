package model

type User struct {
	ID       uint   `json:"id"    gorm:"primary_key"`
	Username string `json:"username"`
	Email    string `json:"email" gorm:"unique"`
	Password []byte `json:"-"`
}
