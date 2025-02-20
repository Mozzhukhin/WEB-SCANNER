# idor_helpers.py
# ---------------
# Общие утилиты для IDOR

def looks_like_id(param_name, value):
    """
    Определяем, похоже ли значение на числовой ID (например, '123')
    или на uuid-like (xxxxxxxx-xxxx-...).
    Возвращаем 'sequential' | 'uuid' | 'unknown'.
    """
    import re

    # Проверяем UUID
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    if uuid_pattern.match(value):
        return "uuid"

    # Проверяем чисто ли это число
    if value.isdigit():
        return "sequential"

    return "unknown"

def is_access_denied(response_text):
    """
    Упрощённо ищем фразы, которые могут указывать на отказ:
    'Access Denied', 'Forbidden', 'You are not authorized', etc.
    """
    if not response_text:
        return True  # Пусто => возможно отказ
    keywords = [
        "access denied",
        "forbidden",
        "not authorized",
        "401 unauthorized"
    ]
    text_lower = response_text.lower()
    for kw in keywords:
        if kw in text_lower:
            return True
    return False

def is_suspiciously_valid(response_text):
    """
    Пытаемся понять, что ответ 'содержит реальные данные',
    e.g. 'username:', 'account balance:', 'email:'
    На практике это зависит от вашего приложения.
    """
    if not response_text:
        return False
    # Для примера
    suspicious_markers = [
        "user:", "email:", "profile:", "balance:", "<h1>Profile</h1>", "account #"
    ]
    text_lower = response_text.lower()
    for sm in suspicious_markers:
        if sm in text_lower:
            return True
    return False
