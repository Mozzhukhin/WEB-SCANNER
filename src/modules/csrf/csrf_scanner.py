# csrf_scanner.py
# ---------------
# Основная реализация, наследующая CSRFScanner

from .csrf_helpers import CSRFScanner
from .form_detection import is_sensitive_form
from .token_analysis import find_csrf_token

class BasicCSRFScanner(CSRFScanner):
    """
    Проверяем, что в "чувствительных" формах (POST) есть CSRF-токен,
    а если он есть, пробуем отправить запрос без токена/с подделанным.
    Если сервер принимает - уязвимость.
    """

    def scan_urls(self, urls):
        """
        CSRF обычно не критичен для GET,
        но если надо, можно проверить GET-ссылки,
        требующие CSRF (бывает в некоторых API).
        """
        results = []
        # Оставим пустым или реализуем при желании
        return results

    def scan_forms(self, forms):
        """
        Для каждой POST-формы, если is_sensitive_form ->
        проверяем наличие CSRF-токена. Если нет - уязвимость.
        Если есть, пробуем отправить запрос без него или с фейковым -
        смотрим, пройдет ли.
        """
        results = []
        for form in forms:
            method = form["method"].lower()
            if method != "post":
                continue

            if not is_sensitive_form(form):
                continue

            # Ищем токен
            token_value = find_csrf_token(form)
            if not token_value:
                # Токен не найден => уязвимость
                results.append({
                    "module": "csrf",
                    "form_action": form["action"],
                    "issue": "No CSRF token found in a sensitive form."
                })
            else:
                # Есть токен -> пробуем послать без него
                data_without_token = {}
                for inp in form["inputs"]:
                    if inp["name"].lower() not in ["csrf_token", "csrfmiddlewaretoken", "token", "__requestverificationtoken"]:
                        data_without_token[inp["name"]] = inp["value"]
                # POST без токена
                resp_text = self.requester.post(form["action"], data_without_token)
                # Если в resp_text нет сообщения об ошибке => возможно уязвимость
                # (Упрощённо, в реальности нужно определять логику)
                if self._is_request_success(resp_text):
                    results.append({
                        "module": "csrf",
                        "form_action": form["action"],
                        "issue": "CSRF token present but server accepted request without it."
                    })

        return results

    def _is_request_success(self, response_text):
        """
        Упрощённый метод: если нет 'error' или 'forbidden' => считаем, что прошло.
        В реальном анализе проверяем HTTP-код, редиректы, сообщение success.
        """
        if not response_text:
            return False
        keywords = ["error", "forbidden", "invalid csrf", "access denied"]
        for k in keywords:
            if k in response_text.lower():
                return False
        return True
