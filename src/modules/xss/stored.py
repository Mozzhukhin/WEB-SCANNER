# stored.py
# ---------
# Модуль для Stored XSS (упрощённо).

import urllib.parse
from .xss_helpers import XSSScanner

class StoredXSSScanner(XSSScanner):
    def __init__(self, requester, logger, payloads_file=None, verify_url=None):
        """
        :param verify_url: URL, где контент отображается (например, /forum/view)
        """
        super().__init__(requester, logger, payloads_file)
        self.verify_url = verify_url

    def scan_urls(self, urls):
        """
        Для Stored XSS, возможно, мы будем искать "страницы с контентом".
        Но часто real logic => we do nothing or check "verify_url".
        """
        results = []
        if self.verify_url and self.verify_url in urls:
            # Проверяем, появляется ли XSS-пэйлоад
            # (В реальности нужно сопоставить payload <-> контент)
            pass
        return results

    def scan_forms(self, forms):
        """
        1) Находим форму, которая сохраняет контент
        2) Подставляем payload
        3) Сразу после отправки - GET verify_url, ищем payload
        """
        results = []
        for form in forms:
            # Допустим, action = /forum/post
            # method = post => insert into DB
            method = form["method"].lower()
            if method != "post":
                continue

            # Упрощённо: if "store" or "comment" or "create" in form["action"] ...
            # but let's test all forms
            for payload in self.payloads:
                post_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("text", "search", "password", "textarea"):
                        post_data[inp["name"]] = payload
                    else:
                        post_data[inp["name"]] = inp["value"]

                # Отправляем POST
                self.requester.post(form["action"], post_data)

                # Далее, если self.verify_url задан, делаем GET
                if self.verify_url:
                    resp_text = self.requester.get(self.verify_url)
                    if self._search_payload_in_response(resp_text, payload):
                        results.append({
                            "module": "stored_xss",
                            "verify_url": self.verify_url,
                            "payload": payload
                        })
        return results
