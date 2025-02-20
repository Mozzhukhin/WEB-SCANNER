# open_redirect_helpers.py
# ------------------------
# Общие функции для Open Redirect, например генерация payloads.

def generate_open_redirect_payloads():
    """
    Возвращает список строк, которые часто используют для open redirect:
    - //evil.com
    - http://evil.com
    - //google.com/%2F%2Fevil.com
    - ...
    """
    payloads = [
        "http://evil.com",
        "https://evil.com",
        "//evil.com",  # schemaless
        "//google.com/%2f%2fevil.com",
        "///example.org",
        "////attacker.com",
        "\\\\evil.com",  # иногда работают слэши
        "javascript://%0aalert(1)",  # иногда редирект если js: URL не фильтруется
        # ...
    ]
    return payloads

def is_external_url(url, domain):
    """
    Упрощённая проверка, является ли url внешним
    (не совпадает с основным доменом).
    Можно расширять логику, игнорировать subdomains etc.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.netloc:
        return False  # возможно относительный путь
    return (parsed.netloc != domain)
