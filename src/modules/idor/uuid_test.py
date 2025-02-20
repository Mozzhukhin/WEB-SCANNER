# uuid_test.py
# -----------
# Если param = uuid, генерируем другие uuid, смотрим, выдаёт ли чужие данные.

import uuid
import urllib.parse

from .idor_helpers import is_access_denied, is_suspiciously_valid

class UUIDTest:
    """
    Тест для UUID-based IDs: берем исходный UUID, генерируем несколько других,
    проверяем, не выдаёт ли сервер чужие объекты.
    """

    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger

    def test_url(self, url, param_name, original_value):
        results = []
        # Генерируем 2-3 других UUID
        random_uuids = [str(uuid.uuid4()) for _ in range(3)]

        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)

        for test_uuid in random_uuids:
            new_params = dict(query_params)
            new_params[param_name] = [test_uuid]
            new_query = urllib.parse.urlencode(new_params, doseq=True)
            new_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )

            resp_text = self.requester.get(new_url)

            if resp_text and not is_access_denied(resp_text) and is_suspiciously_valid(resp_text):
                results.append({
                    "module": "idor",
                    "type": "idor_uuid",
                    "url": new_url,
                    "param": param_name,
                    "original": original_value,
                    "payload": test_uuid,
                    "issue": "Possible IDOR using random UUID"
                })
        return results
