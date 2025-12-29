package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"strings"
	"time"

	"go-auth/config"
)

// Mailer - интерфейс для отправки email
type Mailer interface {
	SendVerificationCode(to, code string) error
	SendWelcome(to, username string) error
	SendPasswordReset(to, resetLink string) error
	Send(to, subject, body string) error
}

// SMTPMailer - реализация Mailer через SMTP
type SMTPMailer struct {
	cfg       config.SMTPConfig
	templates *template.Template
}

// New создает новый экземпляр SMTPMailer
func New(cfg config.SMTPConfig) (*SMTPMailer, error) {
	// Парсим встроенные шаблоны
	tmpl, err := template.New("emails").Parse(emailTemplates)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email templates: %w", err)
	}

	return &SMTPMailer{
		cfg:       cfg,
		templates: tmpl,
	}, nil
}

// SendVerificationCode отправляет код верификации на email
func (m *SMTPMailer) SendVerificationCode(to, code string) error {
	data := VerificationData{
		Code:    code,
		AppName: m.cfg.FromName,
	}

	body, err := m.renderTemplate("verification", data)
	if err != nil {
		return fmt.Errorf("failed to render verification template: %w", err)
	}

	subject := m.cfg.Templates.VerificationSubject
	if subject == "" {
		subject = "Код подтверждения email"
	}

	return m.Send(to, subject, body)
}

// SendWelcome отправляет приветственное письмо
func (m *SMTPMailer) SendWelcome(to, username string) error {
	data := WelcomeData{
		Username: username,
		AppName:  m.cfg.FromName,
	}

	body, err := m.renderTemplate("welcome", data)
	if err != nil {
		return fmt.Errorf("failed to render welcome template: %w", err)
	}

	subject := m.cfg.Templates.WelcomeSubject
	if subject == "" {
		subject = "Добро пожаловать!"
	}

	return m.Send(to, subject, body)
}

// SendPasswordReset отправляет письмо для сброса пароля
func (m *SMTPMailer) SendPasswordReset(to, resetLink string) error {
	data := PasswordResetData{
		ResetLink: resetLink,
		AppName:   m.cfg.FromName,
	}

	body, err := m.renderTemplate("password_reset", data)
	if err != nil {
		return fmt.Errorf("failed to render password reset template: %w", err)
	}

	subject := m.cfg.Templates.ResetPasswordSubject
	if subject == "" {
		subject = "Сброс пароля"
	}

	return m.Send(to, subject, body)
}

// Send отправляет email с указанным содержимым
func (m *SMTPMailer) Send(to, subject, body string) error {
	// Формируем заголовки письма
	from := m.cfg.From
	if m.cfg.FromName != "" {
		from = fmt.Sprintf("%s <%s>", m.cfg.FromName, m.cfg.From)
	}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	// Собираем сообщение
	var msg strings.Builder
	for k, v := range headers {
		msg.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Используем SSL (порт 465) или TLS (порт 587)
	if m.cfg.UseSSL {
		return m.sendWithSSL(to, msg.String())
	}

	// Для порта 587 используем STARTTLS
	return m.sendWithTLS(to, msg.String())
}

// sendWithTLS отправляет email через TLS (STARTTLS на порту 587)
func (m *SMTPMailer) sendWithTLS(to, message string) error {
	addr := m.cfg.Addr()
	host := m.cfg.Host

	// Подключаемся к серверу с таймаутом
	timeout := m.cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Создаем dialer с таймаутом и принудительным IPv4
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	// Принудительно используем IPv4 (tcp4), так как IPv6 может быть недоступен в Docker
	netConn, err := dialer.Dial("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server %s: %w", addr, err)
	}

	// Устанавливаем таймаут на чтение/запись
	netConn.SetDeadline(time.Now().Add(timeout))

	// Создаем SMTP клиент
	conn, err := smtp.NewClient(netConn, host)
	if err != nil {
		netConn.Close()
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer conn.Close()

	// Отправляем EHLO/HELO
	if err = conn.Hello("localhost"); err != nil {
		return fmt.Errorf("failed to send HELO: %w", err)
	}

	// Запускаем TLS
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false,
	}
	if err = conn.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("failed to start TLS: %w", err)
	}

	// Аутентификация
	if m.cfg.Username != "" && m.cfg.Password != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, host)
		if err = conn.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate (user: %s): %w", m.cfg.Username, err)
		}
	}

	// Отправляем письмо
	if err = conn.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("failed to set sender (%s): %w", m.cfg.From, err)
	}
	if err = conn.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient (%s): %w", to, err)
	}

	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return conn.Quit()
}

// sendWithSSL отправляет email через SSL (порт 465)
func (m *SMTPMailer) sendWithSSL(to, message string) error {
	addr := m.cfg.Addr()
	host := m.cfg.Host

	timeout := m.cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Создаем TLS соединение напрямую (для порта 465)
	tlsConfig := &tls.Config{
		ServerName: host,
	}

	// Подключаемся с таймаутом через TLS
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	netConn, err := tls.DialWithDialer(dialer, "tcp4", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to dial SMTP server (SSL) %s: %w", addr, err)
	}
	defer netConn.Close()

	// Создаем SMTP клиент
	conn, err := smtp.NewClient(netConn, host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer conn.Close()

	// Отправляем EHLO
	if err = conn.Hello("localhost"); err != nil {
		return fmt.Errorf("failed to send HELO: %w", err)
	}

	// Аутентификация
	if m.cfg.Username != "" && m.cfg.Password != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, host)
		if err = conn.Auth(auth); err != nil {
			return fmt.Errorf("failed to authenticate (user: %s): %w", m.cfg.Username, err)
		}
	}

	// Отправляем письмо
	if err = conn.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}
	if err = conn.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	w, err := conn.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	return conn.Quit()
}

// sendPlain отправляет email без TLS
func (m *SMTPMailer) sendPlain(to, message string) error {
	addr := m.cfg.Addr()
	host := m.cfg.Host

	var auth smtp.Auth
	if m.cfg.Username != "" && m.cfg.Password != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, host)
	}

	err := smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// renderTemplate рендерит шаблон с данными
func (m *SMTPMailer) renderTemplate(name string, data interface{}) (string, error) {
	var buf bytes.Buffer
	if err := m.templates.ExecuteTemplate(&buf, name, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
