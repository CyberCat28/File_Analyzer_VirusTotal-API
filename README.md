# **File_Analyzer_VirusTotal-API**
Выполнили Тихонова и Балашова
___________________________________
# **Инструкция**
1. Скопировать репозиторий
2. Открыть папку с файлами в VSC
3. Установить зависимость: `pip install requests python-dotenv`
4. Создать файл `.env` и добавить строчку `API_KEY = (ваш API-ключ)`
5. запустить файл `main.py`
___________________________________
# **Отчёт**
Проверка чистого файла (результат: harmless): \
<img width="881" height="291" alt="Снимок экрана 2026-04-11 210812" src="https://github.com/user-attachments/assets/bdd9a3ce-0a04-440a-be64-7690f03b302b" />\
Проверка известного вредоносного файла (например, EICAR test file): \
<img width="780" height="824" alt="Снимок экрана 2026-04-11 211052" src="https://github.com/user-attachments/assets/e9fd4063-d6a1-457a-a053-8fae5b735b70" />\
Проверка URL:\
 <img width="745" height="289" alt="Снимок экрана 2026-04-11 211741" src="https://github.com/user-attachments/assets/a50d9615-7b0b-4527-8f5c-500ed748d0f7" />\
Обработка ошибки при превышении лимита запросов: не получилось вызвать ошибку\
