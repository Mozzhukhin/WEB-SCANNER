# coding: utf-8
"""
Модуль cli_parser.py
--------------------
Задача этого модуля — обработать аргументы командной строки, используя модуль argparse.
Все аргументы задают поведение сканера:
- Целевой URL
- Глубина сканирования
- Выбор модулей уязвимостей
- Формат отчёта и файл вывода
- Аутентификация, задержки, настройки уровня подробности вывода и т.д.

Все комментарии — на русском, логика кода и имена переменных — на английском языке.
Вывод самой программы (например, help) — на английском.
Это поможет достичь читаемости кода для русскоязычных разработчиков, при этом
соответствуя общепринятым стандартам неймминга для кода.
"""

import argparse

def parse_arguments():
    # Создаем парсер командной строки
    # Используем английский для описания команд в help-тексте,
    # чтобы при запуске "python3 main.py --help" пользователь
    # получал англоязычную справку.
    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner: Scan a website for various vulnerabilities."
    )

    # Позиционный аргумент: URL цели
    # Если пользователь не указал --url, можно дать возможность
    # просто указать первый позиционный аргумент без ключа.
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL to scan (e.g. http://example.com)."
    )

    # Аргумент глубины сканирования
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Depth of crawling (default: 1)."
    )

    # Модули уязвимостей: список или 'all'
    parser.add_argument(
        "--modules",
        default="all",
        help="Comma-separated list of modules or 'all' to enable all modules (default: all)."
    )

    # Показать список доступных модулей
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available vulnerability modules and exit."
    )

    # Формат отчета
    parser.add_argument(
        "--report",
        choices=["txt", "html", "csv"],
        default="txt",
        help="Report format: txt, html, or csv (default: txt)."
    )

    # Выходной файл для отчета
    # Если не указать, вывод пойдет в консоль
    parser.add_argument(
        "--output",
        help="Output file for the report. If not specified, results are printed to console."
    )

    # Аутентификация
    # username:password
    parser.add_argument(
        "--auth",
        help="Credentials for authentication in the format username:password."
    )

    # Задержка между запросами
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between requests in seconds (default: 0.0)."
    )

    # Режим quiet — минимальный вывод
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Minimal console output, only essential information."
    )

    # Режим verbose — детальный вывод
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose console output with detailed information."
    )

    # Таймаут запросов
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)."
    )

    # Пользовательский User-Agent
    parser.add_argument(
        "--user-agent",
        help="Custom User-Agent string for HTTP requests."
    )

    # Исключения путей (exclude)
    parser.add_argument(
        "--exclude",
        help="Exclude URLs matching this pattern from scanning."
    )

    # Ограничение сканирования определенными паттернами (scope)
    parser.add_argument(
        "--scope",
        help="Limit scanning to URLs matching this pattern."
    )

    # Отключение цвета в консоли
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output in the console."
    )

    # Парсим аргументы
    args = parser.parse_args()

    # Логика проверки аргументов после парсинга:
    # 1) Если не указана URL ни позиционно, ни через --url, нужно указать пользователю ошибку.
    #    Но Argparse может вывести help автоматически, если не указан URL.
    #    Здесь можно добавить проверку.
    if args.url is None and not args.list_modules:
        # Если не указан URL и пользователь не запросил список модулей, считаем это ошибкой
        parser.error("Please specify a target URL or use --list-modules.")

    # 2) Если пользователь указал и --quiet, и --verbose одновременно,
    #    можно либо отдать приоритет одному, либо вывести предупреждение.
    #    Для простоты допустим, что --quiet имеет приоритет над --verbose.
    if args.quiet and args.verbose:
        # Выводим предупреждение в консоль (на англ.), но не завершаем работу
        # Можно оставить как есть или просто игнорировать --verbose
        print("Warning: --quiet and --verbose are both set. --quiet takes precedence.")

    return args

# Таким образом, этот файл:
# - Предоставляет функцию parse_arguments(), которая возвращает парсированные аргументы.
# - Все аргументы задокументированы англоязычными help-текстами, но комментарии на русском.
# - В дальнейшем main.py будет импортировать parse_arguments() и использовать возвращенные настройки.
# - Это упрощает дальнейшее развитие: добавление нового аргумента сводится к добавлению parser.add_argument().
