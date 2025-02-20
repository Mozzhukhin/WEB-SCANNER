# code_injection.py
# -----------------
# Инъекция в интерпретатор (PHP, Node.js, Python, etc.).
# Аналог команд, но другие payloads (e.g. "<?php system($_GET['cmd']); ?>").

import urllib.parse
from .rce_helpers import RCEScanner

class CodeInjectionScanner(RCEScanner):
    """
    Проверяем возможность вставить "PHP" или "Node.js" код,
    смотрим, появились ли признаки исполнения.
    """

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

                    resp_text = self.requester.get(new_url)
                    if self._check_rce_response(resp_text):
                        results.append({
                            "module": "rce_code_injection",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload
                        })
        return results

    def scan_forms(self, forms):
        results = []
        import urllib

        for form in forms:
            method = form["method"].lower()
            if method not in ("get", "post"):
                continue

            for payload in self.payloads:
                data = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("text", "search", "password", "textarea"):
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = inp["value"]

                if method == "post":
                    resp_text = self.requester.post(form["action"], data)
                else:
                    query_str = urllib.parse.urlencode(data)
                    new_url = form["action"] + "?" + query_str
                    resp_text = self.requester.get(new_url)

                if self._check_rce_response(resp_text):
                    results.append({
                        "module": "rce_code_injection",
                        "form_action": form["action"],
                        "payload": payload
                    })
        return results
