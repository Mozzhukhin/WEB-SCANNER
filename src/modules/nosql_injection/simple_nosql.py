# simple_nosql.py
# ---------------
# Подставляем типичные NoSQL-операторы ($gt, $ne, $regex)
# в GET/POST-параметры, смотрим, выдаёт ли сервер ошибку
# или возвращает неожиданное поведение.

import urllib.parse
from .nosql_helpers import NoSQLiScanner

class SimpleNoSQLiScanner(NoSQLiScanner):
    def scan_urls(self, urls):
        """
        Аналог SQLi-сканера, разбираем query-параметры, подставляем payloads.
        Если видим ошибки NoSQL — докладываем уязвимость.
        """
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
                    # Проверяем ошибки/результат
                    if self._contains_nosql_error(resp_text):
                        results.append({
                            "module": "nosql_injection",
                            "type": "simple_nosql",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload,
                            "issue": "NoSQL error found"
                        })
                    else:
                        # Можно дополнительно смотреть, вернулось ли "много" данных
                        # (e.g. как '1=1' в SQL). Но упрощённо только ищем ошибки.
                        pass
        return results

    def scan_forms(self, forms):
        """
        Для форм — аналогично: если method=GET, form -> query.
        Если POST, отправляем data.
        """
        results = []
        for form in forms:
            method = form["method"].lower()
            if method not in ("get", "post"):
                continue

            for payload in self.payloads:
                data = {}
                for inp in form["inputs"]:
                    # Вставляем payload
                    if inp["type"] in ("text", "search", "password"):
                        data[inp["name"]] = payload
                    else:
                        data[inp["name"]] = inp["value"]

                if method == "post":
                    resp_text = self.requester.post(form["action"], data)
                else:
                    query = urllib.parse.urlencode(data)
                    new_url = form["action"] + "?" + query
                    resp_text = self.requester.get(new_url)

                if self._contains_nosql_error(resp_text):
                    results.append({
                        "module": "nosql_injection",
                        "type": "simple_nosql",
                        "form_action": form["action"],
                        "payload": payload,
                        "issue": "NoSQL error found"
                    })

        return results
