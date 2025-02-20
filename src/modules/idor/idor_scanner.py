# idor_scanner.py
# ---------------
# Основной класс, который:
# 1) Анализирует URL, ищет параметры, выясняет, "sequential" или "uuid".
# 2) Вызывает соответствующий тест (SequentialIDTest или UUIDTest).
# 3) Аналогично для форм.

import urllib.parse

from .idor_helpers import looks_like_id
from .sequential_id_test import SequentialIDTest
from .uuid_test import UUIDTest

class IDORScanner:
    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        # Подключаем подмодули
        self.seq_test = SequentialIDTest(requester, logger)
        self.uuid_test = UUIDTest(requester, logger)

    def scan_urls(self, urls):
        results = []
        for url in urls:
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            if not query_params:
                continue

            for param_name, values in query_params.items():
                # Берём первое значение
                if not values:
                    continue
                original_value = values[0]
                kind = looks_like_id(param_name, original_value)
                if kind == "sequential":
                    sub_results = self.seq_test.test_url(url, param_name, original_value)
                    results.extend(sub_results)
                elif kind == "uuid":
                    sub_results = self.uuid_test.test_url(url, param_name, original_value)
                    results.extend(sub_results)
                else:
                    # unknown => пропускаем
                    pass
        return results

    def scan_forms(self, forms):
        """
        Аналогично: для формы method=GET -> query, POST -> form-data.
        Смотрим, если name=value похоже на ID => подмодули.
        """
        results = []

        import urllib
        for form in forms:
            method = form["method"].lower()
            action = form["action"]
            # Собираем словарь param_name => original_value
            param_dict = {}
            for inp in form["inputs"]:
                param_dict[inp["name"]] = inp["value"] or ""

            for param_name, original_value in param_dict.items():
                kind = looks_like_id(param_name, original_value)
                if kind not in ("sequential", "uuid"):
                    continue

                if method == "get":
                    # Для теста sequential/uuid => подмодули
                    if kind == "sequential":
                        sub_results = self.seq_test.test_url(
                            self._build_url(action, param_dict),
                            param_name,
                            original_value
                        )
                        results.extend(sub_results)
                    elif kind == "uuid":
                        sub_results = self.uuid_test.test_url(
                            self._build_url(action, param_dict),
                            param_name,
                            original_value
                        )
                        results.extend(sub_results)
                elif method == "post":
                    # Для POST, нужно отправлять form-data
                    # Сейчас упрощённо:
                    if kind == "sequential":
                        # Подделываем param_name => new_value, остальное = old
                        # ...
                        pass
                    elif kind == "uuid":
                        # ...
                        pass

        return results

    def _build_url(self, action, param_dict):
        from urllib.parse import urlencode, urlparse, urlunparse
        query_str = urlencode(param_dict)
        parsed = urlparse(action)
        # Сливаем query
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_str, parsed.fragment)
        )
