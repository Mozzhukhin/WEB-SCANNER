# sequential_id_test.py
# ---------------------
# Пробуем, если param=123, подменять 122,124,1,9999, etc.

import urllib.parse

from .idor_helpers import is_access_denied, is_suspiciously_valid

class SequentialIDTest:
    """
    Тест для числовых ID: берем '123', пробуем +-1,0,9999,...
    """

    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger

    def test_url(self, url, param_name, original_value):
        """
        Возвращает список найденных уязвимостей (dict).
        """
        results = []
        # Генерируем список "test_values": [int(original_value)-1, +1, 1, 9999, ...]
        try:
            val_int = int(original_value)
        except ValueError:
            return results

        candidates = [val_int - 1, val_int + 1, 0, 9999]
        # Удалим тех, что <0
        candidates = [c for c in candidates if c >= 0]

        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)

        for cval in candidates:
            # Подставляем
            new_params = dict(query_params)
            new_params[param_name] = [str(cval)]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            new_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )

            resp_text = self.requester.get(new_url)
            # Пытаемся понять, даёт ли приложение «чужие» данные
            # Если is_suspiciously_valid(resp_text) => возможно уязвимость
            # И при этом не 'access denied'
            if resp_text and not is_access_denied(resp_text) and is_suspiciously_valid(resp_text):
                results.append({
                    "module": "idor",
                    "type": "idor_sequential",
                    "url": new_url,
                    "param": param_name,
                    "original": original_value,
                    "payload": str(cval),
                    "issue": "Possible IDOR using sequential ID"
                })
        return results
