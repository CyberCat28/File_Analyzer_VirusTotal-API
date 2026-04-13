# **File_Analyzer_VirusTotal-API**
Выполнили Тихонова и Балашова
# **Инструкция**
1. Скопировать репозиторий
2. Открыть папку с файлами в VSC
3. Установить зависимость: `pip install requests python-dotenv`
4. Создать файл `.env` и добавить строчку `API_KEY = (ваш API-ключ)`
5. запустить файл `main.py
# **Отчёт**
Проверка чистого файла (результат: harmless): \
<img width="779" height="209" alt="image" src="https://github.com/user-attachments/assets/b827fa70-8782-4f94-8088-438f8f7f7d6f" />\
Проверка известного вредоносного файла (например, EICAR test file): \
<img width="795" height="547" alt="image" src="https://github.com/user-attachments/assets/523d0056-625a-4438-9461-2dd9fba997d7" />\
Проверка URL:\
<img width="770" height="304" alt="image" src="https://github.com/user-attachments/assets/7e9660a5-46ca-4eaf-81f1-1b72c911a56a" />\
Обработка ошибки при превышении лимита запросов: не получилось вызвать ошибку
