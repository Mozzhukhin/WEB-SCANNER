# coding: utf-8
"""
open_redirect_scanner.py
------------------------
Модуль для поиска Open Redirect:
1) Ищет в URL/формах "подозрительные" параметры: next, url, redirect, ...
2) Подставляет payload (например, http://evil.com)
3) Делает запрос через Requester
4) Смотрит, если final_url (self.requester.last_url) указывает на внешний сайт,
   считаем это уязвимостью.
"""

import urllib.parse

from .open_redirect_helpers import generate_open_redirect_payloads, is_external_url

class OpenRedirectScanner:
    COMMON_PARAM_NAMES = ["next", "url", "redirect", "return", "goto", "dest", "continue", "to"]

    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.payloads = generate_open_redirect_payloads()

    def scan_urls(self, urls):
        """
        Обходит все URL (в виде set или list), ищет подозрительные параметры
        и подставляет open-redirect-пэйлоады (например, http://evil.com).
        Если Requester сохраняет финальный URL (last_url), проверяем, внешний ли он.
        """
        results = []

        # Преобразуем urls к списку (иначе urls[0] упадёт при set)
        url_list = list(urls)
        if not url_list:
            return results

        # Берём домен из первого URL
        domain = urllib.parse.urlparse(url_list[0]).netloc

        for url in url_list:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                # Если param_name не в списке "подозрительных" — пропускаем
                if param_name.lower() not in self.COMMON_PARAM_NAMES:
                    continue

                for payload in self.payloads:
                    # Подставляем payload
                    new_params = dict(query_params)
                    new_params[param_name] = [payload]

                    new_query = urllib.parse.urlencode(new_params, doseq=True)
                    new_url = urllib.parse.urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )

                    # Делаем GET-запрос
                    resp_text = self.requester.get(new_url)

                    # Забираем конечный URL (например, после 3xx)
                    final_url = self.requester.last_url

                    # Если есть final_url и оно внешнее — уязвимость
                    if final_url and is_external_url(final_url, domain):
                        results.append({
                            "module": "open_redirect",
                            "url": new_url,
                            "param": param_name,
                            "payload": payload,
                            "redirect_to": final_url
                        })

        return results

    def scan_forms(self, forms):
        """
        Аналогично scan_urls, но для HTML-форм.
        Ищем поля с name=next/url/redirect..., подставляем payload,
        делаем запрос, берём self.requester.last_url, проверяем внешний ли домен.
        """
        results = []

        # (Если нужен домен исходного сайта, можно передавать отдельно; здесь упрощённо)
        domain = None  # Или динамически брать из form["action"]

        for form in forms:
            method = form["method"].lower()
            if method not in ("get", "post"):
                continue

            action = form["action"]

            # Условно берём домен из action (упрощённо)
            if not domain:
                domain = urllib.parse.urlparse(action).netloc

            # Смотрим, есть ли param_name из COMMON_PARAM_NAMES
            form_param_names = [inp["name"].lower() for inp in form["inputs"]]

            # Пересекается ли с COMMON_PARAM_NAMES
            suspicious_names = set(self.COMMON_PARAM_NAMES) & set(form_param_names)

            if not suspicious_names:
                continue

            for param_name in suspicious_names:
                for payload in self.payloads:
                    # Готовим словарь data
                    data = {}
                    for inp in form["inputs"]:
                        if inp["name"].lower() == param_name:
                            data[inp["name"]] = payload
                        else:
                            data[inp["name"]] = inp["value"]

                    if method == "post":
                        resp_text = self.requester.post(action, data)
                    else:
                        from urllib.parse import urlencode
                        query_str = urlencode(data)
                        new_url = action + "?" + query_str
                        resp_text = self.requester.get(new_url)

                    final_url = self.requester.last_url
                    if final_url and domain and is_external_url(final_url, domain):
                        results.append({
                            "module": "open_redirect",
                            "form_action": action,
                            "param": param_name,
                            "payload": payload,
                            "redirect_to": final_url
                        })

        return results
