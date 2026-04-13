import pytest
import os
import tempfile
from unittest.mock import patch
from file_scanner import FileScanner
from config import MAX_FILE_SIZE_FREE_TIER

class TestFileScanner:
    @pytest.fixture
    def scanner(self):
        return FileScanner()

    def test_calculate_sha256_correct_hash(self, scanner):    # провер какорректного вычисления SHA-256 для небольшого файла
        # создание временного файл с известным содержимым
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp_file:
            tmp_file.write("очень умный текст")
            tmp_path = tmp_file.name
            
        try:
            # Ожидаемый хеш для "очень умный текст" без новой строки
            expected_hash = "05f3d32b37a9405dd4252fab29c3df62bac7f48acb148ffb441a062470cda8ae"
            calculated_hash = scanner.calculate_sha256(tmp_path)
            assert calculated_hash == expected_hash
        finally:
            os.unlink(tmp_path)

    def test_check_file_logic_size_limit_exceeded(self, scanner):    # тестирование логики проверки размера файла
        # создание фиктивного путм к файлу
        dummy_path = "dummy_large_file.bin"

        large_size = MAX_FILE_SIZE_FREE_TIER + 1
        with patch('os.path.getsize', return_value=large_size):
            result = scanner.check_file_logic(dummy_path)
                
            assert "error" in result
            assert "Файл слишком большой" in result["error"]
            assert "note" in result