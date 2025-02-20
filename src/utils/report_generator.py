# coding: utf-8
"""
report_generator.py
-------------------
Генератор отчётов (ReportGenerator), который умеет создавать отчёт
в нескольких форматах: TXT, CSV, HTML.
Вызывается из main.py:
    report_gen = ReportGenerator(report_format=args.report)
    report_gen.generate(results, output_file=args.output)
"""

import csv
import html

class ReportGenerator:
    def __init__(self, report_format="txt"):
        """
        :param report_format: "txt" (по умолчанию), "csv", "html"
        """
        self.report_format = report_format.lower()

    def generate(self, results, output_file):
        """
        Генерирует отчёт в зависимости от self.report_format,
        записывает в output_file (строка пути).
        """
        if not results:
            # Если нечего писать, можно написать "No vulnerabilities"
            # или просто создать пустой файл
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("No vulnerabilities found.\n")
            return

        if self.report_format == "txt":
            self._generate_txt(results, output_file)
        elif self.report_format == "csv":
            self._generate_csv(results, output_file)
        elif self.report_format == "html":
            self._generate_html(results, output_file)
        else:
            # Если формат не распознан, fallback: txt
            self._generate_txt(results, output_file)

    def _generate_txt(self, results, output_file):
        """
        Записываем простой текстовый отчёт.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("Vulnerabilities Report (TXT)\n")
            f.write("--------------------------------\n\n")
            for i, r in enumerate(results, start=1):
                module = r.get("module", "unknown").upper()
                url = r.get("url") or r.get("form_action")
                payload = r.get("payload") or r.get("test_value") or ""
                issue = r.get("issue", "")
                f.write(f"{i}) [{module}] {issue}\n")
                f.write(f"   URL: {url}\n")
                if payload:
                    f.write(f"   Payload: {payload}\n")
                f.write("\n")

    def _generate_csv(self, results, output_file):
        """
        CSV-формат: поля [Module,Issue,URL,Payload,...].
        Можно расширять.
        """
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Заголовки
            writer.writerow(["Module", "Issue", "URL", "Payload"])
            for r in results:
                module = r.get("module", "unknown")
                issue = r.get("issue", "")
                url = r.get("url") or r.get("form_action") or ""
                payload = r.get("payload") or r.get("test_value") or ""
                writer.writerow([module, issue, url, payload])

    def _generate_html(self, results, output_file):
        """
        Генерируем простой HTML-отчёт.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("<!DOCTYPE html>\n<html>\n<head>\n")
            f.write("<meta charset='utf-8'/>\n")
            f.write("<title>Vulnerabilities Report (HTML)</title>\n")
            f.write("</head>\n<body>\n")
            f.write("<h1>Vulnerabilities Report</h1>\n")
            f.write("<table border='1' cellpadding='5' cellspacing='0'>\n")
            f.write("<tr><th>#</th><th>Module</th><th>Issue</th><th>URL</th><th>Payload</th></tr>\n")

            for i, r in enumerate(results, start=1):
                module = r.get("module", "unknown")
                issue = r.get("issue", "")
                url = r.get("url") or r.get("form_action") or ""
                payload = r.get("payload") or r.get("test_value") or ""

                # Экранируем HTML
                module_esc = html.escape(module)
                issue_esc = html.escape(issue)
                url_esc = html.escape(url)
                payload_esc = html.escape(payload)

                f.write("<tr>")
                f.write(f"<td>{i}</td>")
                f.write(f"<td>{module_esc}</td>")
                f.write(f"<td>{issue_esc}</td>")
                f.write(f"<td>{url_esc}</td>")
                f.write(f"<td>{payload_esc}</td>")
                f.write("</tr>\n")

            f.write("</table>\n</body>\n</html>\n")

