# coding: utf-8
"""
nosql_injection.py
------------------
Пример модуля для обнаружения NoSQL-инъекций (например, в MongoDB).
Аналогично SQLi-сканеру, но с другими пэйлоадами и проверкой ответов.
"""

import urllib.parse
import time

class NoSQLiScanner:
    """
    Базовый класс для NoSQL Injection сканирования.
    Упрощённый пример, где мы ищем ошибки или особенности ответа
    при вставке специфических NoSQL операторов ($gt, $ne, и т.п.).
    """

    def __init__(self, requester, logger, payloads=None):
        self.requester = requester
        self.logger = logger
        # Можно загрузить пэйлоады из файла,
        # или передать списком. Для примера:
        self.payloads = payloads or [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}'
        ]

    def scan_urls(self, urls):
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                original_value = values[0] if values else ""
                for payload in self.payloads:
                    new_params = query_params.copy()
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    response_text = self.requester.get(new_url)
                    # Для упрощения считаем, что если сервер вернул "MongoError" или "NoSQL error",
                    # это признак NoSQL Injection.
                    if response_text and ("MongoError" in response_text or "NoSQL" in response_text):
                        results.append({
                            "module": "nosql_injection",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload
                        })
        return results

    def scan_forms(self, forms):
        results = []
        for form in forms:
            method = form["method"].lower()
            if method not in ("post", "get"):
                continue

            for payload in self.payloads:
                post_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("text", "search", "password"):
                        post_data[inp["name"]] = payload
                    else:
                        post_data[inp["name"]] = inp["value"]

                if method == "post":
                    response_text = self.requester.post(form["action"], post_data)
                else:
                    query = urllib.parse.urlencode(post_data)
                    new_url = form["action"] + "?" + query
                    response_text = self.requester.get(new_url)

                if response_text and ("MongoError" in response_text or "NoSQL" in response_text):
                    results.append({
                        "module": "nosql_injection",
                        "form_action": form["action"],
                        "payload": payload
                    })
        return results
