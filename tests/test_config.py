import os
import pytest
from unittest.mock import patch
from config import get_api_key, VT_API_URL_BASE, MAX_FILE_SIZE_FREE_TIER

def test_get_api_key_success():    # тестируем успешное получение ключа из переменных окружения
    with patch.dict(os.environ, {"API_KEY": "test_fake_key_123"}):
        key = get_api_key()
        assert key == "test_fake_key_123"

def test_get_api_key_missing():    # тестируем выброс исключения, если ключ не установлен
    with patch.dict(os.environ, {}, clear=True):
        # Удаляем ключ, если он был унаследован
        if "API_KEY" in os.environ:
            del os.environ["API_KEY"]
        
        with pytest.raises(ValueError, match="API ключ не найден"):
            get_api_key()

def test_config_constants():    # проверяем, что константы загружены корректно
    assert VT_API_URL_BASE == "https://www.virustotal.com/api/v3"
    assert MAX_FILE_SIZE_FREE_TIER == 32 * 1024 * 1024