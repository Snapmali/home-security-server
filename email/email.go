package email

import (
	"fmt"
	"gopkg.in/gomail.v2"
	"hsserver/config"
	"hsserver/model"
	"time"
)

func SendMail(mailTo *[]string, subject string, body string) error {
	mailCfg := config.Config.Email
	dialer := gomail.NewDialer(mailCfg.Host, mailCfg.Port, mailCfg.User, mailCfg.Password)
	mail := gomail.NewMessage()
	mail.SetAddressHeader("From", mailCfg.User, mailCfg.Name)
	mail.SetHeader("To", *mailTo...)
	mail.SetHeader("Subject", subject)
	mail.SetBody("text/html", body)

	err := dialer.DialAndSend(mail)
	return err
}

func SendVerificationCode(user model.User, subject string, code []byte) error {
	emailAddr := []string{user.Email}
	body := fmt.Sprintf(
		""+
			"<p>亲爱的用户：</p><br>"+
			"<p>您好！您的账号 %s 正在进行邮箱验证。本次的验证码为：</p>"+
			"<p style=\"font-size: 25px;\"><b>%s</b></p>"+
			"<p>验证码在15分钟内有效，请在这期间内完成验证。</p>"+
			"<p>请不要将验证码分享给其他人。若不是本人操作，请无视本邮件。</p><br><br>"+
			"<p>%s</p>", user.Username, code, time.Now().Format("2006-01-02 15:04:05 MST"))
	err := SendMail(&emailAddr, subject, body)
	if err != nil {
		return err
	}
	return nil
}
