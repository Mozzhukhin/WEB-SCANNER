# upload_scanner.py
# -----------------
# Класс, который ищет формы, содержащие <input type="file">,
# затем пытается загрузить "вредоносные" файлы.
# Анализирует ответ (возможно, "File uploaded" и т.п.).

import urllib.parse
from .upload_helpers import generate_malicious_files, is_upload_suspicious_response

class FileUploadScanner:
    def __init__(self, requester, logger):
        self.requester = requester
        self.logger = logger
        self.malicious_files = generate_malicious_files()

    def scan_urls(self, urls):
        """
        Обычно file-upload формы обнаруживаются в HTML (т.е. 'scan_forms').
        Но если где-то GET /upload?filename=... (очень странный случай) —
        тут можно проверять.
        Чаще нужнее scan_forms().
        """
        return []

    def scan_forms(self, forms):
        """
        Для каждой формы, если enctype="multipart/form-data"
        и <input type="file">, загружаем набор "вредоносных" файлов.
        """
        results = []
        import urllib
        for form in forms:
            method = form["method"].lower()
            action = form["action"]
            # Обычно для file-upload есть enctype=multipart/form-data
            if form.get("enctype", "").lower() != "multipart/form-data":
                continue

            # Ищем file-поле
            has_file_input = any(inp["type"] == "file" for inp in form["inputs"])
            if not has_file_input:
                continue

            # Если метод не post, часто upload требует POST. Но проверим?
            if method != "post":
                continue

            # Попробуем загрузить каждый "вредоносный" файл
            for (filename, content) in self.malicious_files:
                # Собираем поля
                # (Учтём, что form["inputs"] может содержать text-поля, hidden поля, etc.)
                # "file" поле мы заменим на (filename, content).
                form_data = {}
                file_field_name = None
                for inp in form["inputs"]:
                    if inp["type"] == "file":
                        file_field_name = inp["name"]
                    else:
                        # Обычное поле
                        form_data[inp["name"]] = inp["value"] or ""

                if not file_field_name:
                    continue

                # отправить multipart/form-data
                resp_text = self._send_multipart(action, form_data, file_field_name, filename, content)

                if resp_text and is_upload_suspicious_response(resp_text):
                    results.append({
                        "module": "insecure_file_upload",
                        "form_action": action,
                        "filename": filename,
                        "issue": "Uploaded malicious file"
                    })
        return results

    def _send_multipart(self, url, fields, file_field_name, filename, file_content):
        """
        Отправляет multipart/form-data POST, включая 1 файл (filename, file_content),
        плюс остальные поля fields.
        """
        import requests
        # В отличие от urllib, requests проще собрать multipart.
        # Предположим, self.requester не завязан на requests, тогда
        # это mini-логика (или вы можете улучшить self.requester).
        # Упрощённо:
        try:
            # fields -> {key: (None, value)}
            # file -> {file_field_name: (filename, file_content, 'application/octet-stream')}
            files = {file_field_name: (filename, file_content, 'application/octet-stream')}
            data = {k: v for k, v in fields.items()}
            r = requests.post(url, files=files, data=data, timeout=10)
            return r.text
        except Exception as e:
            return None
