import sys
import time
import logging
import requests
from config import get_api_key, RATE_LIMIT_DELAY
from file_scanner import FileScanner
from url_scanner import UrlScanner

# конфигурация логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("virustotal.log", encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class Scanner(FileScanner, UrlScanner):    # для взаимодействия с VirusTotal и реализации проверки
    def __init__(self):
        self.api_key = get_api_key() # получение API ключа из env файла
        
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _wait_for_rate_limit(self):     # реализация задержки для соблюдения ограниченийта рифа
        logger.debug(f"Ожидание {RATE_LIMIT_DELAY} секунд для соблюдения rate limit...")
        time.sleep(RATE_LIMIT_DELAY)

    def _handle_api_error(self, response):  # обработка ошибок
        if response.status_code == 200 or response.status_code == 201:
            return
      
        error_msg = f"API Error {response.status_code}: {response.text}"
        if response.status_code == 404:
            logger.warning(f"Ресурс не найден: {error_msg}")
            raise FileNotFoundError("Отчет не найден в VirusTotal")
        elif response.status_code == 429:
            logger.error("Превышен лимит запросов")
            raise ConnectionError("Превышен лимит запросов к API")
        elif response.status_code == 400:
            logger.error(f"Неверный запрос: {error_msg}")
            raise ValueError("Ошибка в параметрах запроса")
        else:
            logger.error(error_msg)
            raise ConnectionError(f"Ошибка сети или сервера: {response.status_code}")

    def check_file(self, file_path: str) -> dict:
        return self.check_file_logic(file_path)

    def check_url(self, url: str) -> dict:
        return self.check_url_logic(url)

    def check_by_hash(self, file_hash: str) -> dict:    # проверка файла по хешу
        logger.info(f"Проверка по хешу: {file_hash}")
        report = self._get_report_by_hash(file_hash)
        
        if report:
            return self._parse_analysis_report(report)
        else:
            return {
                "status": "not_found",
                "message": "Файл с таким хешем не найден"
            }

    def _parse_analysis_report(self, report_data: dict) -> dict:    # отчёт о файле
        data_obj = report_data.get('data', {})
        attrs = data_obj.get('attributes', {})
        
        stats = attrs.get('last_analysis_stats', {})
        results = attrs.get('last_analysis_results', {})
        
        malicious_detectors = []
        for engine, result in results.items():
            if result.get('category') == 'malicious':
                malicious_detectors.append({
                    "engine": engine,
                    "result": result.get('result', 'N/A'),
                    "update": result.get('engine_update', 'N/A')
                })

        return {
            "type": "file",
            "stats": stats,
            "malicious_details": malicious_detectors,
            "permalink": attrs.get('permalink', '')
        }