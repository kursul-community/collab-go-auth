# PowerShell скрипт для скачивания proto файлов

# Создаем директории
New-Item -ItemType Directory -Force -Path "third_party\google\api" | Out-Null

# Скачиваем proto файлы
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto" -OutFile "third_party\google\api\annotations.proto"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto" -OutFile "third_party\google\api\http.proto"

Write-Host "Proto files downloaded successfully!"

