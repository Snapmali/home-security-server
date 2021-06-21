package model

type RegisterRecord struct {
	Code     string
	Username string
	Email    string
	Password []byte
}
