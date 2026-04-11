import os
import sys
import time
import base64
import hashlib
import logging
import requests

from dotenv import load_dotenv

load_dotenv()   # загрузка переменных окружения из env файла

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

# константы
VT_API_URL_BASE = "https://www.virustotal.com/api/v3"
MAX_FILE_SIZE_FREE_TIER = 32 * 1024 * 1024  # макс. размер файла 32 МБ
RATE_LIMIT_DELAY = 15  # секунды между запросами для соблюдения лимита 4 запроса в минуту

class Scanner:    # для взаимодействия с VirusTotal и реализации проверки
    def __init__(self):
        
        self.api_key = os.getenv("API_KEY") # получение API ключа из env файла
        if not self.api_key:
            logger.error("API ключ не найден. Установите API_KEY в файле .env")
            raise ValueError("API ключ не настроен")
        
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _wait_for_rate_limit(self):     # реализация задержки для соблюдения ограничений тарифа
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
            logger.error("Превышен лимит запросов (Quota Exceeded)")
            raise ConnectionError("Превышен лимит запросов к API")
        elif response.status_code == 400:
            logger.error(f"Неверный запрос: {error_msg}")
            raise ValueError("Ошибка в параметрах запроса")
        else:
            logger.error(error_msg)
            raise ConnectionError(f"Ошибка сети или сервера: {response.status_code}")

    def calculate_sha256(self, file_path: str) -> str:  # вычисление SHA-256
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError as e:
            logger.error(f"Ошибка чтения файла {file_path}: {e}")
            raise

    def check_file(self, file_path: str) -> dict:   # проверка файла: вычисляение хеша, поиск отчета, если нет - загружает его
        logger.info(f"Проверка файла: {file_path}")
        
        try:    # проверка размера файла
            file_size = os.path.getsize(file_path)
        except OSError as e:
            logger.error(f"Не удалось получить размер файла: {e}")
            return {"error": "Файл не доступен"}

        if file_size > MAX_FILE_SIZE_FREE_TIER:
            msg = f"Файл слишком большой ({file_size / (1024*1024):.2f} МБ). Лимит бесплатного тарифа: 32 МБ"
            logger.warning(msg)
            return {"error": msg, "note": "Используйте загрузку по URL для больших файлов"}

        file_hash = self.calculate_sha256(file_path)
        logger.info(f"SHA-256 хеш: {file_hash}")

        # проверка есть ли отчёт по хешу
        report = self._get_report_by_hash(file_hash)
        
        if report:
            logger.info("Отчет найден")
            return self._parse_analysis_report(report)
        
        # загрузка файла, если отчета нет
        logger.info("Отчет не найден. Загрузка файла на анализ...")
        try:
            upload_response = self._upload_file(file_path)
            # после загрузки ждём, пока VT проанализирует файл и возвращаем id анализа, так как мгновенного результата нет
            analysis_id = upload_response.get('data', {}).get('id')
            return {
                "status": "uploaded",
                "message": "Файл загружен на анализ",
                "analysis_id": analysis_id,
                "hash": file_hash
            }
        except Exception as e:
            logger.error(f"Ошибка при загрузке файла: {e}")
            return {"error": str(e)}

    def _get_report_by_hash(self, file_hash: str) -> dict:  # получение отчета по хешу файла
        url = f"{VT_API_URL_BASE}/files/{file_hash}"
        try:
            self._wait_for_rate_limit()
            response = self.session.get(url)
            
            if response.status_code == 404:
                return None
            
            self._handle_api_error(response)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Сетевая ошибка при поиске хеша: {e}")
            raise

    def _upload_file(self, file_path: str) -> dict:     # загрузка файла в VT
        url = f"{VT_API_URL_BASE}/files"
        try:
            self._wait_for_rate_limit()
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = self.session.post(url, files=files)
            
            self._handle_api_error(response)
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Сетевая ошибка при загрузке файла: {e}")
            raise

    def check_url(self, url: str) -> dict:  # проверка URL-адреса
        logger.info(f"Начало проверки URL-ссылки: {url}")
        
        # VT требует base64 encoded URL для поиска
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # попытка получения существующнго отчета
        report_url = f"{VT_API_URL_BASE}/urls/{url_id}"
        
        try:
            self._wait_for_rate_limit()
            response = self.session.get(report_url)
            
            if response.status_code == 200:
                logger.info("Отчет по URL-ссылке найден")
                data = response.json()
                return self._parse_url_report(data)
            
            elif response.status_code == 404:
                logger.info("Отчет по URL-ссылке не найден")
                return self._scan_url(url)
            else:
                self._handle_api_error(response)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка при проверке URL-ссылки: {e}")
            raise

    def _scan_url(self, url: str) -> dict:  # отправка URL на сканирование
        scan_url = f"{VT_API_URL_BASE}/urls"
        payload = {"url": url}
        
        try:
            self._wait_for_rate_limit()
            response = self.session.post(scan_url, data=payload)
            self._handle_api_error(response)
            data = response.json()
            
            analysis_id = data['data']['id']
            return {
                "status": "scanning",
                "message": "URL отправлен на анализ. Используйте check_analysis_status для получения результатов.",
                "analysis_id": analysis_id
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка при отправке URL на сканирование: {e}")
            raise

    def check_by_hash(self, file_hash: str) -> dict:    # проверка файла по хешу
        logger.info(f"Проверка по хешу: {file_hash}")
        report = self._get_report_by_hash(file_hash)
        
        if report:
            return self._parse_analysis_report(report)
        else:
            return {"status": "not_found", "message": "Файл с таким хешем не найден"}

    def _parse_analysis_report(self, report_data: dict) -> dict:    # отчёт о файле
        attrs = report_data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        results = attrs.get('last_analysis_results', {})
        
        malicious_detectors = []
        for engine, result in results.items():
            if result['category'] == 'malicious':
                malicious_detectors.append({
                    "engine": engine,
                    "result": result['result'],
                    "update": result['engine_update']
                })

        return {
            "type": "file",
            "stats": stats,     # malicious, suspicious, harmless, undetected, timeout
            "malicious_details": malicious_detectors,
            "permalink": attrs.get('permalink', '')
        }

    def _parse_url_report(self, report_data: dict) -> dict:     # отчёт об URL-ссылке
        attrs = report_data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        categories = attrs.get('categories', {})
        
        # Категория обычно зависит от вендора, берем первую попавшуюся или общую
        category_str = ", ".join(categories.values()) if categories else "Не определена"

        return {
            "type": "url",
            "stats": stats,
            "category": category_str,
            "permalink": attrs.get('permalink', '')
        }