import unittest
from unittest.mock import patch, MagicMock
import io
import sys
import os

# Предполагается, что main.py находится в верхнем уровне проекта.
# Если структура другая, путь к main может отличаться.
import main


class TestMainModule(unittest.TestCase):
    def setUp(self):
        # Данная функция вызывается перед каждым тестом
        # Можно использовать для настройки окружения теста
        self.original_stdout = sys.stdout

    def tearDown(self):
        # Функция вызывается после каждого теста
        sys.stdout = self.original_stdout
        # Чистим созданные файлы, если такие есть
        if os.path.exists("test_report.txt"):
            os.remove("test_report.txt")

    @patch('sys.argv', ['main.py', '--list-modules'])
    def test_list_modules(self):
        # Тестируем опцию --list-modules: программа должна вывести список модулей и завершиться
        captured_output = io.StringIO()
        sys.stdout = captured_output

        with self.assertRaises(SystemExit) as cm:
            main.main()

        output = captured_output.getvalue()
        self.assertIn("Available modules:", output)
        # Проверяем, что программа завершилась с кодом 0
        self.assertEqual(cm.exception.code, 0)

    @patch('sys.argv', ['main.py'])
    def test_no_url_provided(self):
        # Если не указан URL, должно быть сообщение об ошибке и программа должна завершиться с ошибкой
        with self.assertRaises(SystemExit) as cm:
            main.main()
        # Проверяем код завершения (argparse при ошибке парсинга вызывает SystemExit)
        self.assertNotEqual(cm.exception.code, 0)

    @patch('sys.argv', ['main.py', 'http://example.com', '--modules', 'sql_injection,xss'])
    def test_basic_scan_no_output_no_quiet(self):
        # Тестируем сканирование с указанием модулей без quiet и без output
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()  # Не ожидается SystemExit

        output = captured_output.getvalue()
        # Должен быть выведен полный отчет (txt по умолчанию)
        self.assertIn("Vulnerability Scan Report", output)
        self.assertIn("SQL_INJECTION", output)
        self.assertIn("XSS", output)

    @patch('sys.argv', ['main.py', 'http://example.com', '--output', 'test_report.txt', '--quiet', '--modules', 'all'])
    def test_with_output_and_quiet(self):
        # Тестируем с указанием output и quiet
        # При quiet в консоль минимальная инфо, а в файл полный отчет
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()

        # Проверяем вывод в консоль (минимальный)
        output = captured_output.getvalue()
        # Должна быть только краткая инфо о количестве уязвимостей
        # Так как по умолчанию "all" включает sql_injection и xss, ожидаем >0 уязвимостей
        self.assertRegex(output, r"Found \d+ vulnerabilities|No vulnerabilities found")

        # Проверяем, что файл создан
        self.assertTrue(os.path.exists('test_report.txt'))
        with open('test_report.txt', 'r', encoding='utf-8') as f:
            content = f.read()
            # В файле должен быть полный отчет
            self.assertIn("Vulnerability Scan Report", content)
            self.assertIn("SQL_INJECTION", content)
            self.assertIn("XSS", content)

    @patch('sys.argv', ['main.py', 'http://testsite.com', '--modules', 'all', '--verbose'])
    def test_all_modules_verbose_no_output(self):
        # Проверяем режим verbose для всех модулей без output
        # Ожидаем подробный вывод в консоль
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()

        output = captured_output.getvalue()
        # В verbose режиме должны быть дополнительная информация (логгирование DEBUG)
        # Хотя в данном упрощенном примере main просто выдает больше информации о ходе
        # работы, мы можем проверить наличие слова "Starting scan on"
        self.assertIn("Starting scan on http://testsite.com...", output)
        # Проверяем наличие уязвимостей
        self.assertIn("Vulnerability Scan Report", output)

    @patch('sys.argv', ['main.py', 'http://example.com', '--report', 'html'])
    def test_html_report_to_console(self):
        # Если report=html, но не указан output, отчет должен быть выведен в html-формате в консоль.
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()

        output = captured_output.getvalue()
        # Проверяем, что вывелся HTML
        self.assertIn("<html>", output)
        self.assertIn("<body>", output)
        self.assertIn("Vulnerability Scan Report", output)

    @patch('sys.argv', ['main.py', 'http://example.com', '--modules', 'xss', '--quiet'])
    def test_quiet_mode_no_output(self):
        # quiet без output: должна быть только краткая информация
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()

        output = captured_output.getvalue().strip()
        # Ожидается минимальный вывод: либо "Found X vulnerabilities." или "No vulnerabilities found."
        # Поскольку xss модуль добавляет уязвимость, ждем что найдёт хотя бы 1.
        self.assertRegex(output, r"Found \d+ vulnerabilities\.$")

    @patch('sys.argv', ['main.py', 'http://example.com', '--modules', 'none_such'])
    def test_no_vulnerabilities(self):
        # Если указать модуль, которого нет (в реальном случае логика бы не нашла уязвимостей)
        # Этот тест демонстрирует ситуацию, когда уязвимостей нет.
        captured_output = io.StringIO()
        sys.stdout = captured_output

        main.main()

        output = captured_output.getvalue()
        self.assertIn("No vulnerabilities found.", output)


if __name__ == '__main__':
    unittest.main()
