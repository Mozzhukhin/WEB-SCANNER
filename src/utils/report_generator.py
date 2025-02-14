# coding: utf-8
"""
Файл: report_generator.py
--------------------------
Назначение:
Этот модуль отвечает за генерацию отчётов о найденных уязвимостях в разных форматах:
- TXT (текстовый)
- HTML
- CSV

Принцип работы:
- Принимает список результатов (список словарей, каждый словарь описывает уязвимость).
  Формат результата может быть примерно таким:
  [
    {"module": "sql_injection", "url": "http://example.com/search", "payload": "' OR '1'='1"},
    {"module": "xss", "url": "http://example.com/search", "payload": "<script>alert(1)</script>"}
  ]

- В зависимости от выбранного формата:
  * TXT: Выводит текстовое перечисление
  * HTML: Генерирует простой HTML с таблицей
  * CSV: Генерирует данные через запятую

- Сохраняет результат в указанный файл (если файл не указан, может вернуть строку).

Комментарии на русском, вывод формируется на английском, чтобы отчет был понятен широкому кругу специалистов.
"""


class ReportGenerator:
    def __init__(self, report_format="txt"):
        """
        Инициализация генератора отчётов.
        report_format: txt, html или csv.
        """
        self.report_format = report_format.lower()

    def generate(self, results, output_file=None):
        """
        Генерирует отчёт в заданном формате.

        Параметры:
        results (list): Список уязвимостей.
        output_file (str): Путь к файлу, в который сохранить отчёт.
                           Если None, вернёт строку с результатом.

        Возвращает:
        str, если output_file=None, иначе None.
        """
        if self.report_format == "txt":
            content = self._generate_txt(results)
        elif self.report_format == "html":
            content = self._generate_html(results)
        elif self.report_format == "csv":
            content = self._generate_csv(results)
        else:
            # Если формат неизвестен, используем текстовый формат по умолчанию
            content = self._generate_txt(results)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            return None
        else:
            return content

    def _generate_txt(self, results):
        """
        Генерация простого текстового отчёта.
        """
        if not results:
            return "No vulnerabilities found.\n"
        lines = ["Vulnerability Report (TXT format):\n"]
        for r in results:
            line = f"- Module: {r['module']} | URL: {r['url']} | Payload: {r['payload']}"
            lines.append(line)
        return "\n".join(lines) + "\n"

    def _generate_html(self, results):
        """
        Генерация HTML отчёта.
        """
        if not results:
            return "<html><head><title>Report</title></head><body><h1>No Vulnerabilities Found</h1></body></html>"

        html_head = (
            "<html><head><meta charset='UTF-8'>"
            "<title>Vulnerability Report</title>"
            "<style>table{border-collapse:collapse;width:100%;}"
            "th,td{border:1px solid #ccc;padding:8px;text-align:left;}"
            "th{background:#eee;}</style>"
            "</head><body>"
        )
        html_title = "<h1>Vulnerability Report (HTML format)</h1>"
        html_table_start = "<table><tr><th>Module</th><th>URL</th><th>Payload</th></tr>"
        html_rows = []
        for r in results:
            row = f"<tr><td>{r['module']}</td><td>{r['url']}</td><td>{r['payload']}</td></tr>"
            html_rows.append(row)
        html_table_end = "</table>"
        html_end = "</body></html>"

        return html_head + html_title + html_table_start + "".join(html_rows) + html_table_end + html_end

    def _generate_csv(self, results):
        """
        Генерация CSV отчёта.
        Столбцы: module,url,payload
        """
        import csv
        from io import StringIO

        output = StringIO()
        writer = csv.writer(output, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)

        writer.writerow(["module", "url", "payload"])  # Заголовки
        for r in results:
            writer.writerow([r['module'], r['url'], r['payload']])

        return output.getvalue()
