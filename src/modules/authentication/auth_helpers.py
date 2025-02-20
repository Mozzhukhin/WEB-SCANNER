# auth_helpers.py
# ---------------
# Вспомогательные функции для модуля аутентификации.

def load_weak_passwords():
    """
    Возвращаем список слабых паролей (можно загрузить из файла data/wordlists/passwords.txt).
    Для примера: top-10
    """
    return [
        "admin", "password", "123456", "qwerty", "111111",
        "12345678", "abc123", "user", "1234", "pass"
    ]

def common_default_credentials():
    """
    Известные дефолтные учётки: (username, password).
    Можно расширять: root/root, admin/admin, etc.
    """
    return [
        ("admin", "admin"),
        ("root", "root"),
        ("test", "test"),
        ("user", "user"),
        ("admin", "1234"),
        # ...
    ]

def is_login_success(response_text):
    """
    Упрощённая проверка, показывает, что логин успешен.
    Например, если на странице нет 'Invalid password',
    но есть 'Welcome' или 'Logout' и т.д.
    """
    if not response_text:
        return False
    text_lower = response_text.lower()
    # Эвристика:
    if "invalid" in text_lower or "wrong password" in text_lower or "authentication failed" in text_lower:
        return False
    # Если видим 'welcome' или 'logout', считаем, что логин ок
    if "welcome" in text_lower or "logout" in text_lower or "profile" in text_lower:
        return True
    return False
