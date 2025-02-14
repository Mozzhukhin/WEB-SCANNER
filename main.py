# coding: utf-8
"""
Файл: main.py
------------
Это точка входа в приложение. Здесь мы:

1) Парсим аргументы командной строки (cli_parser).
2) Настраиваем логирование (logger).
3) Если указано --list-modules, выводим список модулей и завершаем.
3) Если указано --list-modules, выводим список модулей и завершаем.
4) Инициализируем основные компоненты (requester, authenticator, crawler).
5) Запускаем краулер для сбора ссылок, выводим эти ссылки в консоль.
6) Определяем модули уязвимостей, запускаем их на найденных ссылках.
7) Собираем результаты, при необходимости формируем отчёт (--output), иначе выводим их в консоль.
8) Учитываем режимы --quiet, --verbose, --no-color.

Комментарии на русском, названия переменных и вывод — на английском.
"""

import sys

# Предполагаем, что наши готовые модули находятся в следующих местах:
from src.core.cli_parser import parse_arguments
from src.utils.logger import Logger
from src.core.requester import Requester
from src.core.crawler import Crawler

# Предполагаем, что есть класс ReportGenerator (если нужно)
# from src.utils.report_generator import ReportGenerator

# Предполагаем, что есть Authenticator (если нужна аутентификация)
# from src.core.authenticator import Authenticator

# Предполагаем, что есть реестр модулей (module_registry.py)
# from src.modules.module_registry import ModuleRegistry


def main():
    # 1) Парсим аргументы командной строки
    args = parse_arguments()

    # 2) Настраиваем логгер
    logger = Logger(
        quiet=args.quiet,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # 3) Проверяем флаг --list-modules (если используете ModuleRegistry)
    # В данном примере покажем список модулей заглушкой
    if args.list_modules:
        available_modules = ["sql_injection", "xss", "csrf", "rce"]
        logger.info("Available modules:")
        for m in available_modules:
            logger.info(f"- {m}")
        sys.exit(0)

    # 4) Инициализация основных компонентов
    # Инициализируем Requester
    requester = Requester(
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent
    )

    # Если у нас реализован класс Authenticator, можем подключить тут
    authenticator = None
    if args.auth:
        # authenticator = Authenticator(requester, args.auth)
        # authenticator.login()
        pass  # Заглушка

    # Инициализируем настоящий Crawler с учётом depth, scope, exclude и т.д.
    crawler = Crawler(
        start_url=args.url,
        depth=args.depth,
        scope_pattern=args.scope,
        exclude_pattern=args.exclude,
        delay=args.delay,     # Если crawler использует собственный delay / или Requester
        timeout=args.timeout, # Аналогично, если нужно
        user_agent=args.user_agent
    )

    logger.info("Starting scan...")

    # 5) Запускаем краулер и выводим найденные ссылки
    found_urls = crawler.run()
    logger.info(f"Crawler found {len(found_urls)} URLs:")
    for link in found_urls:
        logger.info(f" - {link}")

    # 6) Определяем модули уязвимостей (по args.modules) и запускаем проверки
    chosen_modules = resolve_modules(args.modules)
    # Здесь — заглушка проверки
    results = perform_dummy_scan(found_urls, chosen_modules)

    # 7) Считаем и выводим итоги
    vulnerabilities_count = len(results)
    if vulnerabilities_count > 0:
        logger.info(f"Found {vulnerabilities_count} vulnerabilities.")
    else:
        logger.info("No vulnerabilities found.")

    # Если пользователь указал --output, формируем отчёт (пример заглушки)
    if args.output:
        # report_gen = ReportGenerator(format=args.report)
        # report_gen.generate(results, output_file=args.output)
        logger.info(f"Report saved to {args.output}")
    else:
        # Иначе выводим результаты в консоль, если не quiet
        if not args.quiet:
            print_results_to_console(results, args.report, logger)


def resolve_modules(modules_str):
    """
    Заглушка для получения списка модулей уязвимостей.
    Если 'all', возвращаем условно полный список.
    Иначе делим по запятой.
    """
    if modules_str == "all":
        return ["sql_injection", "xss", "csrf", "rce"]
    else:
        return modules_str.split(",")


def perform_dummy_scan(urls, modules):
    """
    Заглушка "сканирования": просто говорит,
    что на каждом url при sql_injection найдена уязвимость.
    """
    results = []
    # for url in urls:
    #     for mod in modules:
    #         if mod == "sql_injection":
    #             results.append({
    #                 "module": "sql_injection",
    #                 "url": url,
    #                 "payload": "' OR '1'='1"
    #             })
    return results


def print_results_to_console(results, report_format, logger):
    """
    Печать подробных результатов в консоль.
    Если результатов нет — выводим об этом сообщение.
    """
    if not results:
        logger.info("No vulnerabilities.")
        return
    logger.info("Detailed results:")
    for vuln in results:
        logger.info(f"[{vuln['module'].upper()}] Found vulnerability at {vuln['url']} with payload {vuln['payload']}")


if __name__ == "__main__":
    main()
