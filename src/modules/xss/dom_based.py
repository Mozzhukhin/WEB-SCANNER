# dom_based.py
# ------------
# Упрощённый сканер DOM-based XSS:
# Ищем "document.write(location.hash)" в HTML,
# пробуем вставить "#<script>alert(1)</script>"

import re
import urllib.parse
from .xss_helpers import XSSScanner

class DomBasedXSSScanner(XSSScanner):
    def scan_urls(self, urls):
        results = []
        # 1. Ищем потенциальные DOM-синки
        # 2. Для каждого URL, подставляем #payload
        sink_pattern = re.compile(
            r"(document\.write|innerHTML|eval|location\.(hash|search))",
            re.IGNORECASE
        )

        for url in urls:
            # Получаем HTML
            resp_text = self.requester.get(url)
            if not resp_text:
                continue
            # Проверяем, есть ли синки
            if sink_pattern.search(resp_text):
                # Пробуем fragment-based payload
                for payload in self.payloads:
                    # fragment = #<script>alert(1)</script>
                    new_url = url + "#" + urllib.parse.quote(payload)
                    resp_text2 = self.requester.get(new_url)
                    if self._search_payload_in_response(resp_text2, payload):
                        results.append({
                            "module": "dom_based_xss",
                            "url": new_url,
                            "payload": payload
                        })
        return results

    def scan_forms(self, forms):
        # DOM-based обычно связан с fragment,
        # формы не так часто
        return []
