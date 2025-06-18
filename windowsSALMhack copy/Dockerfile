# Используем базовый образ Windows
FROM mcr.microsoft.com/windows/nanoserver:ltsc2022

# Устанавливаем PowerShell
SHELL ["powershell", "-Command"]

# Копируем скрипт для атаки
COPY attack.ps1 C:attack.ps1

# Запускаем скрипт при старте контейнера
CMD ["powershell", "-File", "C:\attack.ps1"]
