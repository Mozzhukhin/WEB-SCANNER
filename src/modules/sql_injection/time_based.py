# coding: utf-8
"""
time_based.py
-------------
Time-based Blind SQL Injection:
- Подставляем SLEEP(...) или WAITFOR DELAY, замеряем задержку
- Если ответ приходит спустя N секунд, считаем, что SQLi сработала
"""

import urllib.parse
import time
from .sqli_helpers import SQLiScanner

class TimeBasedSQLiScanner(SQLiScanner):
    def __init__(self, requester, logger, payloads_file=None, delay_threshold=3.0):
        """
        :param delay_threshold: Порог в секундах, превышение которого
                                считаем признаком успешной Time-based инъекции
        """
        super().__init__(requester, logger, payloads_file)
        self.delay_threshold = delay_threshold

    def scan_urls(self, urls):
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                for payload in self.payloads:
                    new_params = dict(query_params)
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    start = time.time()
                    resp_text = self.requester.get(new_url)
                    elapsed = time.time() - start

                    if elapsed >= self.delay_threshold:
                        results.append({
                            "module": "time_based_sqli",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload,
                            "observed_delay": round(elapsed, 2)
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

                start = time.time()
                if method == "post":
                    resp_text = self.requester.post(form["action"], post_data)
                else:
                    query = urllib.parse.urlencode(post_data)
                    new_url = form["action"] + "?" + query
                    resp_text = self.requester.get(new_url)
                elapsed = time.time() - start

                if elapsed >= self.delay_threshold:
                    results.append({
                        "module": "time_based_sqli",
                        "form_action": form["action"],
                        "payload": payload,
                        "observed_delay": round(elapsed, 2)
                    })
        return results
