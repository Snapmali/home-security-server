package controller

import "regexp"

func CheckPassword(password string) bool {
	if ok, _ := regexp.MatchString(`^[\w.!@#$%^&*]{4,16}$`, password); !ok {
		return false
	}
	return true
}

func CheckUsername(username string) bool {
	if ok, _ := regexp.MatchString(`^[a-zA-Z][\w]{3,15}$`, username); !ok {
		return false
	}
	return true
}

func CheckEmail(email string) bool {
	if ok, _ := regexp.MatchString(`^[\w]+@[\w]+\.[\w]+$`, email); !ok {
		return false
	}
	return true
}

func CheckVerificationCode(code string) bool {
	if ok, _ := regexp.MatchString(`^[a-zA-Z0-9]{6}$`, code); !ok {
		return false
	}
	return true
}

func CheckScreenName(name string) bool {
	if ok, _ := regexp.MatchString(`^.{1,10}$`, name); !ok {
		return false
	}
	return true
}
