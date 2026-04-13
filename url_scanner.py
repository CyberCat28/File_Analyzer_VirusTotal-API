import base64
import logging
import requests
from config import VT_API_URL_BASE

logger = logging.getLogger(__name__)

class UrlScanner:
    def check_url_logic(self, url: str) -> dict:  # проверка URL-адреса
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
                "message": "URL отправлен на анализ",
                "analysis_id": analysis_id
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка при отправке URL на сканирование: {e}")
            raise

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