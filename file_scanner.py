import os
import hashlib
import logging
import requests
from config import VT_API_URL_BASE, MAX_FILE_SIZE_FREE_TIER

logger = logging.getLogger(__name__)

class FileScanner:
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

    def check_file_logic(self, file_path: str) -> dict:   # проверка файла: вычисляение хеша, поиск отчета, если нет - загружает его
        logger.info(f"Проверка файла: {file_path}")
        
        try:
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
            # после загрузки ждём, пока VT проанализирует файл и возвращаем id анализа, так как мгновенного результат а нет
            analysis_id = upload_response.get('data', {}).get('id')
            return {
                "status": "uploaded",
                "message": "Файл загружен на анализ. Результат будет доступен позже.",
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