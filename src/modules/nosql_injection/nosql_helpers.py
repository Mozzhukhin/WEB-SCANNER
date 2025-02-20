# nosql_helpers.py
# ----------------
# Базовый класс NoSQLiScanner, аналогичный SQLiScanner.

import os

class NoSQLiScanner:
    """
    Базовый класс для NoSQL Injection (MongoDB, CouchDB и т.д.).
    Загрузка пэйлоадов, методы scan_urls/forms, проверка на ошибки или специфичное поведение.
    """

    def __init__(self, requester, logger, payloads_file=None):
        self.requester = requester
        self.logger = logger
        self.payloads_file = payloads_file or self._default_payloads_path()
        self.payloads = self._load_payloads()

    def _default_payloads_path(self):
        base_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../")
        )
        return os.path.join(base_dir, "data", "payloads", "nosql_payloads.txt")

    def _load_payloads(self):
        p = []
        try:
            with open(self.payloads_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        p.append(line)
            self.logger.info(f"Loaded {len(p)} NoSQL payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.warn(f"NoSQL payloads file not found: {self.payloads_file}")
        return p

    def scan_urls(self, urls):
        raise NotImplementedError("Implement scan_urls() in derived class")

    def scan_forms(self, forms):
        raise NotImplementedError("Implement scan_forms() in derived class")

    def _contains_nosql_error(self, response_text):
        """
        Ищем типичные строки ошибок/признаков NoSQL/Mongo.
        """
        if not response_text:
            return False
        triggers = [
            "MongoError", "mongodb", "NoSQL error",
            "cannot parse query", "bad query",
            "E11000 duplicate key", "Command failed"
        ]
        r_lower = response_text.lower()
        for t in triggers:
            if t.lower() in r_lower:
                return True
        return False
