# form_detection.py
# -----------------
# Логика для распознавания "чувствительных" форм,
# где обычно ожидается CSRF-токен.

def is_sensitive_form(form_data):
    """
    Принимает описание формы (method, action, inputs)
    и решает, чувствительная ли это операция (например, POST-форма на /delete, /update, /admin).
    Возвращает True/False.
    """
    method = form_data["method"].lower()
    action = form_data["action"].lower()

    if method == "post":
        # Предположим, если в action есть "delete", "update", "admin", "change_password"...
        sensitive_keywords = ["delete", "update", "admin", "change_password", "profile"]
        for kw in sensitive_keywords:
            if kw in action:
                return True

    return False
