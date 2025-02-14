# reflected.py
# ------------
# Модуль для Reflected XSS, где пэйлоад сразу появляется в ответе.

import urllib.parse
from .xss_helpers import XSSScanner

class ReflectedXSSScanner(XSSScanner):
    def scan_urls(self, urls):
        """
        Ищем GET-параметры, подставляем XSS-пэйлоады, смотрим, появляется ли
        payload (или его часть) в ответе.
        """
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)

            if not query_params:
                continue

            for param_name, values in query_params.items():
                for payload in self.payloads:
                    # Подставляем payload в param_name
                    new_params = dict(query_params)
                    new_params[param_name] = [payload]
                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    resp_text = self.requester.get(new_url)
                    if self._search_payload_in_response(resp_text, payload):
                        results.append({
                            "module": "reflected_xss",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload
                        })
        return results

    def scan_forms(self, forms):
        """
        Если форма метод GET: подставляем в query
        Если POST: отправляем post_data
        Проверяем ответ на появление payload
        """
        results = []
        for form in forms:
            method = form["method"].lower()
            if method not in ("get", "post"):
                continue

            for payload in self.payloads:
                # Подготавливаем данные
                data = {}
                for inp in form["inputs"]:
                    t = inp["type"].lower()
                    if t in ("text", "search", "password"):
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = inp["value"]

                if method == "post":
                    resp_text = self.requester.post(form["action"], data)
                else:
                    query = urllib.parse.urlencode(data)
                    new_url = form["action"] + "?" + query
                    resp_text = self.requester.get(new_url)

                if self._search_payload_in_response(resp_text, payload):
                    results.append({
                        "module": "reflected_xss",
                        "form_action": form["action"],
                        "payload": payload
                    })
        return results
