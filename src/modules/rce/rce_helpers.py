# rce_helpers.py
# --------------
# Базовый класс RCEScanner и вспомогательная логика.

import os

class RCEScanner:
    """
    Базовый класс для RCE/Command Injection.
    Загрузка пэйлоадов, методы scan_urls/scan_forms.
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
        return os.path.join(base_dir, "data", "payloads", "rce_payloads.txt")

    def _load_payloads(self):
        p = []
        try:
            with open(self.payloads_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        p.append(line)
            self.logger.info(f"Loaded {len(p)} RCE payloads from {self.payloads_file}")
        except FileNotFoundError:
            self.logger.warn(f"RCE payloads file not found: {self.payloads_file}")
        return p

    def scan_urls(self, urls):
        raise NotImplementedError("Implement scan_urls in derived class")

    def scan_forms(self, forms):
        raise NotImplementedError("Implement scan_forms in derived class")

    def _check_rce_response(self, response_text):
        """
        Упрощённая проверка ответа на признаки выполнения команды:
        - Если скрипт выводит результат 'uid=0(root)', 'Windows IP Configuration'
        - или специфический "Command not found", "sh: 1: ... not found"
        """
        if not response_text:
            return False
        triggers = [
            "uid=0(",            # Linux root
            "root:x:0:0",        # etc/passwd
            "Windows IP Configuration",
            "sh: 1:",
            "cannot execute",
            "command not found",
            "Authorization: Basic"
        ]
        lower = response_text.lower()
        for t in triggers:
            if t.lower() in lower:
                return True
        return False
