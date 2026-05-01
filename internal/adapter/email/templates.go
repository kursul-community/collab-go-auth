package email

import (
	"embed"
	"fmt"
	"html/template"
)

// Структуры данных для шаблонов

// VerificationData - данные для письма верификации
type VerificationData struct {
	Code    string
	AppName string
}

// WelcomeData - данные для приветственного письма
type WelcomeData struct {
	Username string
	AppName  string
}

// PasswordResetData - данные для письма сброса пароля
type PasswordResetData struct {
	ResetLink string
	UserID    string
	RequestID string
	AppName   string
}

// compiledTemplatesFS — HTML, скомпилированный из MJML.
// Источники в templates/*.mjml, пересобираются командой `make emails-build`.
//
//go:embed templates/verification.html templates/password_reset.html
var compiledTemplatesFS embed.FS

// loadTemplates парсит все email-шаблоны в один *template.Template:
//   - welcome — встроен как const ниже (старый русский шаблон)
//   - verification, password_reset — из MJML-скомпилированных HTML-файлов
func loadTemplates() (*template.Template, error) {
	root := template.New("emails")

	if _, err := root.New("welcome").Parse(welcomeTemplate); err != nil {
		return nil, fmt.Errorf("parse welcome: %w", err)
	}

	files := map[string]string{
		"verification":   "templates/verification.html",
		"password_reset": "templates/password_reset.html",
	}
	for name, path := range files {
		body, err := compiledTemplatesFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		if _, err := root.New(name).Parse(string(body)); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
	}

	return root, nil
}

// welcomeTemplate — приветственное письмо. Не переведено и не редизайнено.
// При желании конвертируй в MJML аналогично verification/password_reset.
const welcomeTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Добро пожаловать!</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: #ffffff;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 28px;
            font-weight: bold;
            color: #4F46E5;
        }
        .emoji {
            font-size: 64px;
            text-align: center;
            margin: 20px 0;
        }
        h1 {
            color: #1a1a1a;
            font-size: 28px;
            margin-bottom: 20px;
            text-align: center;
        }
        .message {
            color: #666;
            font-size: 16px;
            text-align: center;
            margin-bottom: 20px;
        }
        .highlight {
            color: #4F46E5;
            font-weight: 600;
        }
        .features {
            background-color: #F3F4F6;
            border-radius: 12px;
            padding: 25px;
            margin: 30px 0;
        }
        .features h3 {
            margin-top: 0;
            color: #1a1a1a;
        }
        .features ul {
            margin: 0;
            padding-left: 20px;
        }
        .features li {
            margin: 10px 0;
            color: #666;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{{.AppName}}</div>
        </div>

        <div class="emoji">🎉</div>

        <h1>Добро пожаловать, <span class="highlight">{{.Username}}</span>!</h1>

        <p class="message">
            Спасибо за регистрацию! Мы рады видеть вас среди наших пользователей.
        </p>

        <div class="features">
            <h3>Что дальше?</h3>
            <ul>
                <li>Настройте свой профиль</li>
                <li>Изучите возможности платформы</li>
                <li>Начните использовать сервис</li>
            </ul>
        </div>

        <div class="footer">
            <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
            <p>© {{.AppName}}</p>
        </div>
    </div>
</body>
</html>`
