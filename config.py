import os
from dotenv import load_dotenv

# загрузка переменных окружения из env файла
load_dotenv()

# константы
VT_API_URL_BASE = "https://www.virustotal.com/api/v3"
MAX_FILE_SIZE_FREE_TIER = 32 * 1024 * 1024  # макс. размер файла 32 МБ
RATE_LIMIT_DELAY = 15  # секунды между запросами для соблюдения лимита 4 запроса в минуту

def get_api_key():
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise ValueError("API ключ не найден. Установите API_KEY в файле .env")
    return api_key