# coding: utf-8
"""
error_based.py
--------------
Модуль для проверки Error-based SQL Injection:
- Подставляет пэйлоады
- Ищет в ответе типичные SQL-ошибки.
"""

import urllib.parse
from .sqli_helpers import SQLiScanner

class ErrorBasedSQLiScanner(SQLiScanner):
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
                    new_params = dict(query_params)
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    self.logger.debug(f"[ErrorBasedSQLi] Testing {param_name} with payload '{payload}' at {new_url}")
                    response_text = self.requester.get(new_url)
                    if self._check_sql_error_signatures(response_text):
                        results.append({
                            "module": "error_based_sqli",
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
                # Подготовка полей
                input_data = {}
                for inp in form["inputs"]:
                    # Подставляем payload только если тип поля - text/password/search/etc.
                    if inp["type"] in ("text", "search", "password"):
                        input_data[inp["name"]] = payload
                    else:
                        input_data[inp["name"]] = inp["value"]

                if method == "post":
                    self.logger.debug(f"[ErrorBasedSQLi] Testing form POST {form['action']} with payload '{payload}'")
                    resp_text = self.requester.post(form["action"], input_data)
                else:
                    # GET-форма
                    query_str = urllib.parse.urlencode(input_data)
                    new_url = form["action"] + "?" + query_str
                    self.logger.debug(f"[ErrorBasedSQLi] Testing form GET {new_url} with payload '{payload}'")
                    resp_text = self.requester.get(new_url)

                if self._check_sql_error_signatures(resp_text):
                    results.append({
                        "module": "error_based_sqli",
                        "form_action": form["action"],
                        "payload": payload
                    })

        return results
