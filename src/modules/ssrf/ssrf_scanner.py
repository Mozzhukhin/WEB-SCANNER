# ssrf_scanner.py
# ---------------
# Модуль, который ищет параметры (url, link, target, etc.) и подставляет
# http://127.0.0.1, http://169.254.169.254, file:///... Проверяем ответ.

import urllib.parse

from .ssrf_helpers import generate_ssrf_payloads, looks_like_url_param, is_ssrf_suspicious_response

class SSRFScanner:
    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.payloads = generate_ssrf_payloads()

    def scan_urls(self, urls):
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                # Если param_name "url", "link", etc.
                if looks_like_url_param(param_name):
                    for payload in self.payloads:
                        new_params = dict(query_params)
                        new_params[param_name] = [payload]
                        new_query = urllib.parse.urlencode(new_params, doseq=True)
                        new_url = urllib.parse.urlunparse(
                            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                        )

                        resp_text = self.requester.get(new_url)
                        if resp_text and is_ssrf_suspicious_response(resp_text):
                            results.append({
                                "module": "ssrf",
                                "url": new_url,
                                "param": param_name,
                                "payload": payload,
                                "issue": "Possible SSRF"
                            })
        return results

    def scan_forms(self, forms):
        """
        Аналогично: если форма содержит поля name=url/link/target, подставляем SSRF payloads.
        """
        results = []
        import urllib
        for form in forms:
            method = form["method"].lower()
            action = form["action"]
            data = {}
            for inp in form["inputs"]:
                data[inp["name"]] = inp["value"] or ""

            # Ищем, есть ли param_name, looks_like_url_param
            for param_name, orig_value in data.items():
                if looks_like_url_param(param_name):
                    for payload in self.payloads:
                        new_data = dict(data)
                        new_data[param_name] = payload

                        if method == "post":
                            resp_text = self.requester.post(action, new_data)
                        else:
                            from urllib.parse import urlencode
                            new_query = urlencode(new_data)
                            new_url = action + "?" + new_query
                            resp_text = self.requester.get(new_url)

                        if resp_text and is_ssrf_suspicious_response(resp_text):
                            results.append({
                                "module": "ssrf",
                                "form_action": action,
                                "param": param_name,
                                "payload": payload,
                                "issue": "Possible SSRF"
                            })
        return results
