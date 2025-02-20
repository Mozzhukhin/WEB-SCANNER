# weak_passwords.py
# -----------------
# Модуль для перебора «слабых» паролей против формы логина.

import urllib.parse
from .auth_helpers import load_weak_passwords, is_login_success

class WeakPasswordsTest:
    """
    Проверяем «слабые» пароли для указанного пользователя
    (или набора пользователей).
    """

    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.weak_passes = load_weak_passwords()

    def test_login_form(self, action_url, user_field, pass_field, other_fields, known_username):
        """
        Пробуем для known_username + пароли из weak_passes.
        :param action_url: URL формы (POST)
        :param user_field: имя поля для логина (e.g. 'username')
        :param pass_field: имя поля для пароля (e.g. 'password')
        :param other_fields: dict других полей (hidden, csrf, etc.)
        :param known_username: текущий username, если известен
        Возвращаем True/False (найден ли успешный логин) или +info.
        """
        results = []
        for p in self.weak_passes:
            post_data = dict(other_fields)
            post_data[user_field] = known_username
            post_data[pass_field] = p

            resp_text = self.requester.post(action_url, post_data)
            if resp_text and is_login_success(resp_text):
                results.append({
                    "type": "weak_password",
                    "username": known_username,
                    "password": p
                })
        return results
