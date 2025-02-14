# coding: utf-8
"""
blind_sql_injection.py
----------------------
Данный модуль реализует логику Blind SQL Injection (в частности Time-based),
когда мы не видим явных ошибок SQL, но можем судить об уязвимости
по задержке в ответе или по разнице в выводе при определённых условиях.

В данном примере показываем Time-based подход, заставляя сервер "задерживать" ответ.
На практике нужно подобрать подходящие функции sleep(), benchmark(), и т.д.
"""

import urllib.parse
import time
from src.modules.sql_injection.sqli_helpers import SQLiScanner

class BlindSQLiScanner(SQLiScanner):
    def __init__(self, requester, logger, payloads_file=None):
        super().__init__(requester, logger, payloads_file)
        # Можно иметь отдельный список payloads для Blind SQLi,
        # но в примере используем общий sql_payloads.txt

        # Опционально: паттерн, показывающий задержку (seconds)
        self.time_threshold = 3.0  # Если ответ задержался дольше этого, считаем, что была sleep()

    def scan_urls(self, urls):
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                for payload in self.payloads:
                    new_params = query_params.copy()
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    start_time = time.time()
                    response_text = self.requester.get(new_url)
                    elapsed = time.time() - start_time

                    # Логика: если ответ задержался > self.time_threshold, считаем это признаком Blind SQLi
                    if elapsed > self.time_threshold:
                        results.append({
                            "module": "blind_sql_injection",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload,
                            "delay_observed": round(elapsed, 2)
                        })
        return results

    def scan_forms(self, forms):
        results = []
        for form in forms:
            method = form["method"].lower()
            if method not in ("post", "get"):
                continue

            for payload in self.payloads:
                input_data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("text", "search", "password"):
                        input_data[inp["name"]] = payload
                    else:
                        input_data[inp["name"]] = inp["value"]

                start_time = time.time()

                if method == "post":
                    resp_text = self.requester.post(form["action"], input_data)
                else:
                    query = urllib.parse.urlencode(input_data)
                    new_url = form["action"] + "?" + query
                    resp_text = self.requester.get(new_url)

                elapsed = time.time() - start_time

                if elapsed > self.time_threshold:
                    results.append({
                        "module": "blind_sql_injection",
                        "form_action": form["action"],
                        "payload": payload,
                        "delay_observed": round(elapsed, 2)
                    })

        return results
