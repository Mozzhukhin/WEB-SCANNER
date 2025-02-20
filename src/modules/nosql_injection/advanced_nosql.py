# advanced_nosql.py
# -----------------
# Пример более продвинутой логики NoSQLi.
# Например, подстановка {"$where": "sleep(2000)"} в Mongo,
# если сервер позволяет JS-вставки.

import urllib.parse
import time
from .nosql_helpers import NoSQLiScanner

class AdvancedNoSQLiScanner(NoSQLiScanner):
    def __init__(self, requester, logger, payloads_file=None, delay_threshold=2.0):
        super().__init__(requester, logger, payloads_file)
        self.delay_threshold = delay_threshold

    def scan_urls(self, urls):
        results = []
        # Пример "time-based" NoSQL injection
        # Если server поддерживает {"$where": function(){sleep(2000)}}
        # - довольно редкий кейс, но пример.
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

                    if elapsed > self.delay_threshold:
                        results.append({
                            "module": "nosql_injection",
                            "type": "advanced_nosql",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload,
                            "observed_delay": round(elapsed, 2),
                            "issue": "Possible time-based NoSQL injection"
                        })
        return results

    def scan_forms(self, forms):
        # Аналогичная логика
        results = []
        # ...
        return results
