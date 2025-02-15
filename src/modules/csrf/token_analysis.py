# token_analysis.py
# -----------------
# Анализ наличия/отсутствия CSRF-токена.

def find_csrf_token(form_data):
    """
    Ищет hidden-поле с именем вроде 'csrf_token', 'csrfmiddlewaretoken', 'token'.
    Возвращает значение или None, если не найдено.
    """
    possible_names = ["csrf_token", "csrfmiddlewaretoken", "token", "__RequestVerificationToken"]
    for inp in form_data["inputs"]:
        if inp["type"] == "hidden":
            if inp["name"].lower() in possible_names:
                return inp["value"]
    return None
