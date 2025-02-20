# default_credentials.py
# ----------------------
# Перебор «дефолтных» логин/пароль (admin/admin, root/root, etc.)

from .auth_helpers import common_default_credentials, is_login_success

class DefaultCredentialsTest:
    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.default_creds = common_default_credentials()

    def test_login_form(self, action_url, user_field, pass_field, other_fields):
        """
        Перебираем список (username, password) из default_creds,
        проверяем, даёт ли логин.
        """
        results = []
        for (u, p) in self.default_creds:
            post_data = dict(other_fields)
            post_data[user_field] = u
            post_data[pass_field] = p

            resp_text = self.requester.post(action_url, post_data)
            if resp_text and is_login_success(resp_text):
                results.append({
                    "type": "default_credentials",
                    "username": u,
                    "password": p
                })
        return results
