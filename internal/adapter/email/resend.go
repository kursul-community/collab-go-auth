package email

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log"
	"time"

	"github.com/resend/resend-go/v2"

	"go-auth/config"
)

// ResendMailer - реализация Mailer через Resend API
type ResendMailer struct {
	client    *resend.Client
	cfg       config.ResendConfig
	smtpCfg   config.SMTPConfig // для сабжектов и FromName-фолбэка
	templates *template.Template
}

// NewResend создает новый экземпляр ResendMailer.
// smtpCfg используется только для шаблонных сабжектов (verificationSubject и т.д.),
// чтобы не дублировать конфиг.
func NewResend(cfg config.ResendConfig, smtpCfg config.SMTPConfig) (*ResendMailer, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("resend: api key is empty (set RESEND_API_KEY)")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("resend: from address is empty")
	}

	tmpl, err := template.New("emails").Parse(emailTemplates)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email templates: %w", err)
	}

	return &ResendMailer{
		client:    resend.NewClient(cfg.APIKey),
		cfg:       cfg,
		smtpCfg:   smtpCfg,
		templates: tmpl,
	}, nil
}

// fromAddress форматирует адрес отправителя как "Name <email@domain>"
func (m *ResendMailer) fromAddress() string {
	if m.cfg.FromName != "" {
		return fmt.Sprintf("%s <%s>", m.cfg.FromName, m.cfg.From)
	}
	return m.cfg.From
}

// appName используется в шаблонах
func (m *ResendMailer) appName() string {
	if m.cfg.FromName != "" {
		return m.cfg.FromName
	}
	if m.smtpCfg.FromName != "" {
		return m.smtpCfg.FromName
	}
	return "Auth"
}

// renderTemplate рендерит HTML шаблон
func (m *ResendMailer) renderTemplate(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := m.templates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// SendVerificationCode отправляет код подтверждения email
func (m *ResendMailer) SendVerificationCode(to, code string) error {
	body, err := m.renderTemplate("verification", VerificationData{
		Code:    code,
		AppName: m.appName(),
	})
	if err != nil {
		return fmt.Errorf("render verification: %w", err)
	}

	subject := m.smtpCfg.Templates.VerificationSubject
	if subject == "" {
		subject = "Код подтверждения email"
	}

	return m.Send(to, subject, body)
}

// SendWelcome отправляет приветственное письмо
func (m *ResendMailer) SendWelcome(to, username string) error {
	body, err := m.renderTemplate("welcome", WelcomeData{
		Username: username,
		AppName:  m.appName(),
	})
	if err != nil {
		return fmt.Errorf("render welcome: %w", err)
	}

	subject := m.smtpCfg.Templates.WelcomeSubject
	if subject == "" {
		subject = "Добро пожаловать!"
	}

	return m.Send(to, subject, body)
}

// SendPasswordReset отправляет письмо для сброса пароля
func (m *ResendMailer) SendPasswordReset(to, userID, requestID, frontendURL string) error {
	resetLink := fmt.Sprintf("%s/auth/login/password-recovery?userId=%s&requestId=%s",
		frontendURL, userID, requestID)

	body, err := m.renderTemplate("password_reset", PasswordResetData{
		ResetLink: resetLink,
		UserID:    userID,
		RequestID: requestID,
		AppName:   m.appName(),
	})
	if err != nil {
		return fmt.Errorf("render password reset: %w", err)
	}

	subject := m.smtpCfg.Templates.ResetPasswordSubject
	if subject == "" {
		subject = "Сброс пароля"
	}

	return m.Send(to, subject, body)
}

// Send отправляет письмо через Resend API
func (m *ResendMailer) Send(to, subject, body string) error {
	params := &resend.SendEmailRequest{
		From:    m.fromAddress(),
		To:      []string{to},
		Subject: subject,
		Html:    body,
	}

	// SendWithContext предпочтительнее, но интерфейс Mailer без ctx —
	// добавим короткий контекст с таймаутом, чтобы не висеть вечно.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sent, err := m.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		return fmt.Errorf("resend send: %w", err)
	}

	log.Printf("Resend: email sent to %s, id=%s, subject=%q", to, sent.Id, subject)
	return nil
}
