# xss_helpers.py
# --------------
# Базовые классы и функции для XSS-сканирования.

import os
import re

class XSSScanner:
    """
    Базовый класс для XSS-сканеров (Reflected, Stored, DOM-based).
    Аналогично SQLiScanner, он загружает пэйлоады из файла
    и предоставляет методы scan_urls() и scan_forms().
    """

    def __init__(self, requester, logger, payloads_file=None):
        self.requester = requester
        self.logger = logger
        self.payloads_file = payloads_file or self._default_payloads_path()
        self.payloads = self._load_payloads()

    def _default_payloads_path(self):
        """
        Возвращает путь к файлу xss_payloads.txt по умолчанию,
        например /data/payloads/xss_payloads.txt
        """
        base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../")
        )
        return os.path.join(base_dir, "data", "payloads", "xss_payloads.txt")

    def _load_payloads(self):
        """
        Считываем XSS-пэйлоады из файла (каждая строка — один пэйлоад).
        """
        p = []
        try:
            with open(self.payloads_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        p.append(line)
            self.logger.info(f"Loaded {len(p)} XSS payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.warn(f"XSS payloads file not found: {self.payloads_file}")
        return p

    def scan_urls(self, urls):
        """
        Должен быть переопределён в наследниках (Reflected, Stored, DOM).
        Возвращает list[dict] (список уязвимостей).
        """
        raise NotImplementedError("Implement scan_urls() in derived class")

    def scan_forms(self, forms):
        """
        Аналогично, переопределяется в наследниках.
        """
        raise NotImplementedError("Implement scan_forms() in derived class")

    def _search_payload_in_response(self, response_text, payload):
        """
        Простейший способ проверять, появился ли пэйлоад (или кусок его) в ответе.
        Это может быть не 100% надёжно,
        но для демонстрации годится.
        """
        if not response_text:
            return False
        # Упрощённо ищем саму строку payload.
        # Для реального применения можно искать "<script>alert(1)</script>" с экранированием и т.д.
        return payload in response_text

