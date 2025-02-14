# coding: utf-8
"""
sqli_helpers.py
---------------
Базовые классы и функции для модулей SQL Injection (Error-based, Boolean-based, Time-based).
"""

import os
import re

class SQLiScanner:
    """
    Базовый класс для всех типов SQL Injection сканеров.
    Предоставляет:
      - Загрузку пэйлоадов из файла
      - Шаблонные методы scan_urls(...) и scan_forms(...)
      - Вспомогательные функции для анализа ответов
    """

    def __init__(self, requester, logger, payloads_file=None):
        """
        :param requester: Объект Requester для HTTP-запросов (имеет .get(url), .post(url, data))
        :param logger: Объект логирования
        :param payloads_file: Путь к файлу с SQLi-пэйлоадами (если None — используем дефолт).
        """
        self.requester = requester
        self.logger = logger
        self.payloads_file = payloads_file or self._default_payloads_path()
        self.payloads = self._load_payloads()

    def _default_payloads_path(self):
        """
        Возвращает путь к sql_payloads.txt по умолчанию, предполагая, что структура проекта:
        /web_vulnerability_scanner
          /data
            /payloads
              sql_payloads.txt
          /src
            /modules
              /sql_injection
                sqli_helpers.py
        """
        # На 3-4 уровня выше, в зависимости от реальной структуры
        # Подстройте под свой проект.
        base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../")
        )
        return os.path.join(base_dir, "data", "payloads", "sql_payloads.txt")

    def _load_payloads(self):
        """Считывает SQLi-пэйлоады из файла (по строкам)."""
        payloads = []
        try:
            with open(self.payloads_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
            self.logger.info(f"Loaded {len(payloads)} SQLi payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.warn(f"SQLi payloads file not found: {self.payloads_file}")
        return payloads

    def scan_urls(self, urls):
        """
        Шаблонный метод: должен быть переопределён в наследниках (ErrorBasedSQLi, BooleanBasedSQLi, ...)
        Возвращает list[dict] с информацией об уязвимостях.
        """
        raise NotImplementedError("Please implement scan_urls() in derived class.")

    def scan_forms(self, forms):
        """
        Шаблонный метод: должен быть переопределён в наследниках.
        Возвращает list[dict] с информацией об уязвимостях.
        """
        raise NotImplementedError("Please implement scan_forms() in derived class.")

    def _check_sql_error_signatures(self, response_text):
        """
        Ищем типичные сигнатуры SQL-ошибок в тексте ответа.
        Можно расширять под разные СУБД (MySQL, SQLite, PostgreSQL, MSSQL, Oracle и т.д.).
        """
        if not response_text:
            return False
        error_patterns = [
            r"you have an error in your sql syntax",
            r"sql syntax.*?error",
            r"warning:\s*mysql",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"microsoft oledb provider for odbc drivers error",
            r"syntax error.*sqlite",
            r"database error",
            r"db error",
            r"sqlstate",
            r"sqlite3::exception",
            r"Fatal error",
            r"PG::SyntaxError"
        ]
        combined_pattern = re.compile("|".join(error_patterns), re.IGNORECASE)
        if combined_pattern.search(response_text):
            return True
        return False
