# coding: utf-8
"""
boolean_based.py
----------------
Модуль для Boolean-based SQL Injection (Blind) через анализ разницы в ответах:
- Подставляем две разные пэйлоады: условно "True" и "False"
- Сравниваем длину (или иной критерий) полученного ответа
"""

import urllib.parse
from .sqli_helpers import SQLiScanner

class BooleanBasedSQLiScanner(SQLiScanner):
    def __init__(self, requester, logger, payloads_file=None):
        super().__init__(requester, logger, payloads_file)
        # Можно завести специальные парные пэйлоады (true/false),
        # но здесь воспользуемся идеей: для каждого из self.payloads
        # создадим "true"-вариант и "false"-вариант, изменяя '1'='1' -> '1'='2'.

        # Например, хотим сделать пары: ("' OR '1'='1", "' OR '1'='2'").
        # Для упрощения оставим в scan_urls/scan_forms: 2 запроса.

    def scan_urls(self, urls):
        results = []
        # Порог разницы в длине (или контенте), при котором считаем, что поведение отличилось
        length_threshold = 50

        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                for payload in self.payloads:
                    # Генерируем "true" и "false" варианты.
                    # Простейший способ: заменить ' OR '1'='1' на ' OR '1'='2'
                    payload_true = payload.replace("'1'='1", "'1'='1").replace('"1"="1', '"1"="1')  # на самом деле не трогаем
                    payload_false = payload.replace("'1'='1", "'1'='2").replace('"1"="1', '"1"="2')

                    # Запрос 1 (true)
                    new_params_true = dict(query_params)
                    new_params_true[param_name] = [payload_true]
                    query_true = urllib.parse.urlencode(new_params_true, doseq=True)
                    new_url_true = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_true, parsed.fragment)
                    )
                    resp_true = self.requester.get(new_url_true) or ""
                    len_true = len(resp_true)

                    # Запрос 2 (false)
                    new_params_false = dict(query_params)
                    new_params_false[param_name] = [payload_false]
                    query_false = urllib.parse.urlencode(new_params_false, doseq=True)
                    new_url_false = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_false, parsed.fragment)
                    )
                    resp_false = self.requester.get(new_url_false) or ""
                    len_false = len(resp_false)

                    # Сравниваем длины
                    diff = abs(len_true - len_false)

                    if diff >= length_threshold:
                        # Значит поведение "true" и "false" отличается существенно
                        results.append({
                            "module": "boolean_based_sqli",
                            "url_true": new_url_true,
                            "url_false": new_url_false,
                            "param": param_name,
                            "payload_true": payload_true,
                            "payload_false": payload_false,
                            "len_true": len_true,
                            "len_false": len_false
                        })
        return results

    def scan_forms(self, forms):
        results = []
        length_threshold = 50

        for form in forms:
            method = form["method"].lower()
            if method not in ("post", "get"):
                continue

            for payload in self.payloads:
                payload_true = payload.replace("'1'='1", "'1'='1").replace('"1"="1', '"1"="1')
                payload_false = payload.replace("'1'='1", "'1'='2").replace('"1"="1', '"1"="2')

                # Сформируем data_true / data_false
                data_true = {}
                data_false = {}
                for inp in form["inputs"]:
                    if inp["type"] in ("text", "search", "password"):
                        data_true[inp["name"]] = payload_true
                        data_false[inp["name"]] = payload_false
                    else:
                        data_true[inp["name"]] = inp["value"]
                        data_false[inp["name"]] = inp["value"]

                if method == "post":
                    resp_true = self.requester.post(form["action"], data_true) or ""
                    len_true = len(resp_true)
                    resp_false = self.requester.post(form["action"], data_false) or ""
                    len_false = len(resp_false)
                else:
                    # GET-форма
                    query_true = urllib.parse.urlencode(data_true)
                    new_url_true = form["action"] + "?" + query_true
                    resp_true = self.requester.get(new_url_true) or ""
                    len_true = len(resp_true)

                    query_false = urllib.parse.urlencode(data_false)
                    new_url_false = form["action"] + "?" + query_false
                    resp_false = self.requester.get(new_url_false) or ""
                    len_false = len(resp_false)

                diff = abs(len_true - len_false)
                if diff >= length_threshold:
                    results.append({
                        "module": "boolean_based_sqli",
                        "form_action": form["action"],
                        "payload_true": payload_true,
                        "payload_false": payload_false,
                        "len_true": len_true,
                        "len_false": len_false
                    })

        return results
