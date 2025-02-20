# csrf_helpers.py
# ---------------
# Базовый класс CSRFScanner и вспомогательная логика.

import os

class CSRFScanner:
    """
    Базовый класс для CSRF-сканирования.
    - Может загружать какую-то базу 'csrf_payloads.txt' (если нужны),
      например фейковые токены.
    - Имеет методы scan_urls() и scan_forms().
    """
    def __init__(self, requester, logger, payloads_file=None):
        self.requester = requester
        self.logger = logger
        self.payloads_file = payloads_file or self._default_payloads_path()
        self.payloads = self._load_payloads()

    def _default_payloads_path(self):
        # Путь по умолчанию, например /data/payloads/csrf_payloads.txt
        base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../")
        )
        return os.path.join(base_dir, "data", "payloads", "csrf_payloads.txt")

    def _load_payloads(self):
        payloads = []
        try:
            with open(self.payloads_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
            self.logger.info(f"Loaded {len(payloads)} CSRF payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.warn(f"CSRF payloads file not found: {self.payloads_file}")
        return payloads

    def scan_urls(self, urls):
        """
        Для CSRF сканирование URL может быть не так актуально,
        но иногда GET-запросы тоже требуют защиту.
        В реальности чаще сканируем формы (POST).
        """
        raise NotImplementedError("Implement scan_urls in derived class")

    def scan_forms(self, forms):
        raise NotImplementedError("Implement scan_forms in derived class")
