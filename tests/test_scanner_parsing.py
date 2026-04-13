import pytest
from scanner import Scanner

class TestScannerParsing:
    @pytest.fixture
    def scanner(self):
        with pytest.raises(ValueError):
            pass

    def test_parse_analysis_report_malicious(self):     # тестируется парсинг отчета о файле с обнаруженными угрозами
        scanner = object.__new__(Scanner)
        
        mock_report_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 2,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 5,
                        "timeout": 0
                    },
                    "last_analysis_results": {
                        "Kaspersky": {
                            "category": "malicious",
                            "result": "Trojan.Win32.Generic",
                            "engine_update": "20260413"
                        },
                        "ESET-NOD32": {
                            "category": "malicious",
                            "result": "a variant of Win32/Agent",
                            "engine_update": "20260413"
                        },
                        "Google": {
                            "category": "harmless",
                            "result": "clean",
                            "engine_update": "20260413"
                        }
                    },
                    "permalink": "https://www.virustotal.com/gui/file/123..."
                }
            }
        }

        result = scanner._parse_analysis_report(mock_report_data)

        # проверка структуры результата
        assert result["type"] == "file"
        assert result["stats"]["malicious"] == 2
        assert result["stats"]["harmless"] == 70
        assert len(result["malicious_details"]) == 2
        
        # проверка деталей первой угрозы
        first_threat = result["malicious_details"][0]
        assert first_threat["engine"] == "Kaspersky"
        assert first_threat["result"] == "Trojan.Win32.Generic"
        
        # проверка наличия ссылки
        assert "virustotal.com" in result["permalink"]

    def test_parse_analysis_report_clean(self):    # тестирование парсинга чистого файла
        scanner = object.__new__(Scanner)
        
        mock_report_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 75,
                        "undetected": 0,
                        "timeout": 0
                    },
                    "last_analysis_results": {},
                    "permalink": "https://www.virustotal.com/gui/file/clean..."
                }
            }
        }

        result = scanner._parse_analysis_report(mock_report_data)
        
        assert result["stats"]["malicious"] == 0
        assert len(result["malicious_details"]) == 0
        assert result["type"] == "file"