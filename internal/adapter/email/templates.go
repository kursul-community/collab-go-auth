package email

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
	AppName   string
}

// emailTemplates - встроенные HTML шаблоны писем
const emailTemplates = `
{{define "verification"}}
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Код подтверждения</title>
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
        h1 {
            color: #1a1a1a;
            font-size: 24px;
            margin-bottom: 20px;
            text-align: center;
        }
        .code-container {
            background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            margin: 30px 0;
        }
        .code {
            font-size: 42px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #ffffff;
            font-family: 'Courier New', monospace;
        }
        .message {
            color: #666;
            font-size: 16px;
            text-align: center;
            margin-bottom: 20px;
        }
        .warning {
            background-color: #FEF3C7;
            border-left: 4px solid #F59E0B;
            padding: 15px;
            margin-top: 30px;
            border-radius: 0 8px 8px 0;
        }
        .warning p {
            margin: 0;
            color: #92400E;
            font-size: 14px;
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
        
        <h1>Подтверждение email</h1>
        
        <p class="message">
            Используйте код ниже для подтверждения вашего email адреса.
            Код действителен в течение 15 минут.
        </p>
        
        <div class="code-container">
            <div class="code">{{.Code}}</div>
        </div>
        
        <div class="warning">
            <p>⚠️ Если вы не запрашивали этот код, просто проигнорируйте это письмо.</p>
        </div>
        
        <div class="footer">
            <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
            <p>© {{.AppName}}</p>
        </div>
    </div>
</body>
</html>
{{end}}

{{define "welcome"}}
<!DOCTYPE html>
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
</html>
{{end}}

{{define "password_reset"}}
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Сброс пароля</title>
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
        h1 {
            color: #1a1a1a;
            font-size: 24px;
            margin-bottom: 20px;
            text-align: center;
        }
        .message {
            color: #666;
            font-size: 16px;
            text-align: center;
            margin-bottom: 30px;
        }
        .button-container {
            text-align: center;
            margin: 30px 0;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%);
            color: #ffffff !important;
            text-decoration: none;
            padding: 16px 40px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
        }
        .link-text {
            background-color: #F3F4F6;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
            word-break: break-all;
            font-size: 14px;
            color: #666;
        }
        .warning {
            background-color: #FEF3C7;
            border-left: 4px solid #F59E0B;
            padding: 15px;
            margin-top: 30px;
            border-radius: 0 8px 8px 0;
        }
        .warning p {
            margin: 0;
            color: #92400E;
            font-size: 14px;
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
        
        <h1>🔐 Сброс пароля</h1>
        
        <p class="message">
            Мы получили запрос на сброс пароля для вашего аккаунта.
            Нажмите на кнопку ниже, чтобы создать новый пароль.
        </p>
        
        <div class="button-container">
            <a href="{{.ResetLink}}" class="button">Сбросить пароль</a>
        </div>
        
        <p style="text-align: center; color: #999; font-size: 14px;">
            Или скопируйте ссылку:
        </p>
        <div class="link-text">
            {{.ResetLink}}
        </div>
        
        <div class="warning">
            <p>⚠️ Ссылка действительна в течение 1 часа. Если вы не запрашивали сброс пароля, проигнорируйте это письмо.</p>
        </div>
        
        <div class="footer">
            <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
            <p>© {{.AppName}}</p>
        </div>
    </div>
</body>
</html>
{{end}}
`

