# auth_scanner.py
# ---------------
# Собирает логику weak_passwords, default_credentials
# Ищет форму логина (method=POST, поля user/password).

import urllib.parse
from .weak_passwords import WeakPasswordsTest
from .default_credentials import DefaultCredentialsTest

class AuthScanner:
    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.weak_test = WeakPasswordsTest(requester, logger)
        self.default_test = DefaultCredentialsTest(requester, logger)

    def scan_urls(self, urls):
        """
        В URL нечасто бывает логин "login?user=xxx&pass=xxx", но можно проверить.
        Здесь упрощённо пропустим. Чаще логин через формы.
        """
        return []

    def scan_forms(self, forms):
        """
        Ищем формы, в которых есть поля типа 'username'/'password',
        метод=POST, action=...
        Затем запускаем weak_passwords и default_credentials.
        """
        results = []

        # Имена полей:
        possible_user_fields = ["username", "user", "login", "email"]
        possible_pass_fields = ["password", "pass", "passwd", "pwd"]

        for form in forms:
            method = form["method"].lower()
            action = form["action"]
            if method != "post":
                continue

            # Собираем словарь
            # input_name -> input_value
            inputs = {}
            user_field = None
            pass_field = None
            for inp in form["inputs"]:
                name = inp["name"]
                itype = inp["type"]
                value = inp["value"]
                inputs[name] = value

                # Определяем, это ли username/password
                lname = name.lower()
                if lname in possible_user_fields:
                    user_field = name
                if lname in possible_pass_fields:
                    pass_field = name

            # Если не нашли user_field / pass_field, не считаем login-формой
            if not user_field or not pass_field:
                continue

            # У нас могут быть hidden поля, csrf, etc. => other_fields
            other_fields = dict(inputs)
            # Удалим user_field/pass_field
            other_fields.pop(user_field, None)
            other_fields.pop(pass_field, None)

            # 1) Пытаемся default credentials
            default_results = self.default_test.test_login_form(action, user_field, pass_field, other_fields)
            for r in default_results:
                r["module"] = "authentication"
                r["form_action"] = action
                results.append(r)

            # 2) Если хотим known_username, допустим user_field -> "admin"
            #   но мы не знаем, может value="" => we skip or test "admin"?
            # Упростим: if inputs[user_field], use that as known username
            known_username = inputs[user_field]  # может быть пусто
            if known_username:
                # test weak passwords
                weak_results = self.weak_test.test_login_form(action, user_field, pass_field, other_fields, known_username)
                for r in weak_results:
                    r["module"] = "authentication"
                    r["form_action"] = action
                    results.append(r)

        return results
