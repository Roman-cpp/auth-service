package mailer

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"math"
	texttemplate "text/template"
	"time"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// Шаблоны разбираются один раз на старте: ошибка в вёрстке письма роняет
// процесс сразу, а не на первой попытке пользователя зарегистрироваться.
var (
	htmlTemplates = template.Must(template.ParseFS(templateFS, "templates/*.html.tmpl"))
	textTemplates = texttemplate.Must(texttemplate.ParseFS(templateFS, "templates/*.txt.tmpl"))
)

// CodeTemplate — тексты вокруг одноразового кода. Одна вёрстка на все три
// сценария: отличается только формулировка, а не структура письма.
type CodeTemplate struct {
	Subject string
	Heading string
	Lead    string
	Hint    string
}

var (
	TemplateEmailVerify = CodeTemplate{
		Subject: "Код подтверждения регистрации",
		Heading: "Подтвердите адрес почты",
		Lead:    "Чтобы завершить регистрацию, введите этот код на странице подтверждения:",
		Hint:    "Если вы не регистрировались, просто проигнорируйте это письмо — аккаунт не будет создан.",
	}
	TemplateLoginCode = CodeTemplate{
		Subject: "Код для входа",
		Heading: "Подтвердите вход",
		Lead:    "Для входа в аккаунт введите этот код:",
		Hint:    "Если вход пытались выполнить не вы, смените пароль — кто-то знает его.",
	}
	TemplatePasswordReset = CodeTemplate{
		Subject: "Код для смены пароля",
		Heading: "Сброс пароля",
		Lead:    "Чтобы задать новый пароль, введите этот код на странице восстановления:",
		Hint:    "Если вы не просили сбросить пароль, проигнорируйте это письмо — старый пароль продолжит работать.",
	}
	TemplateEnableTwoFactor = CodeTemplate{
		Subject: "Код подтверждения двухфакторной аутентификации",
		Heading: "Включение двухфакторной аутентификации",
		Lead:    "Чтобы включить подтверждение входа по коду, введите этот код в настройках профиля:",
		Hint:    "Если вы не включали двухфакторную аутентификацию, проигнорируйте это письмо.",
	}
)

type Mailer struct {
	sender  Sender
	appName string
}

func New(sender Sender, appName string) *Mailer {
	return &Mailer{sender: sender, appName: appName}
}

type codeData struct {
	AppName string
	Heading string
	Lead    string
	Hint    string
	Code    string
	Minutes int
}

func (m *Mailer) SendCode(ctx context.Context, to string, tpl CodeTemplate, code string, ttl time.Duration) error {
	data := codeData{
		AppName: m.appName,
		Heading: tpl.Heading,
		Lead:    tpl.Lead,
		Hint:    tpl.Hint,
		Code:    code,
		Minutes: int(math.Round(ttl.Minutes())),
	}

	var html, text bytes.Buffer
	if err := htmlTemplates.ExecuteTemplate(&html, "code.html.tmpl", data); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	if err := textTemplates.ExecuteTemplate(&text, "code.txt.tmpl", data); err != nil {
		return fmt.Errorf("render text: %w", err)
	}

	return m.sender.Send(ctx, Message{
		To:      to,
		Subject: tpl.Subject,
		HTML:    html.String(),
		Text:    text.String(),
	})
}
