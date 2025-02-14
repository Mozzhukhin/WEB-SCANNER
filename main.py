# coding: utf-8
"""
main.py
-------
Точка входа в приложение. Здесь мы:
1) Парсим аргументы командной строки (cli_parser).
2) Настраиваем логгер (logger).
3) Если указано --list-modules, выводим список модулей и завершаем.
4) Инициализируем компоненты (requester, authenticator, crawler).
5) Краулер обходит сайт, собирает ссылки и формы.
6) Проверяем уязвимости (SQL Injection, XSS, etc.) если выбраны в --modules.
7) Выводим результаты, при необходимости формируем отчёт.
"""

import sys
from src.core.cli_parser import parse_arguments
from src.utils.logger import Logger
from src.utils.report_generator import ReportGenerator  # Если есть
from src.core.requester import Requester
from src.core.crawler import Crawler

# Импортируем SQLi сканеры
from src.modules.sql_injection.error_based import ErrorBasedSQLiScanner
from src.modules.sql_injection.boolean_based import BooleanBasedSQLiScanner
from src.modules.sql_injection.time_based import TimeBasedSQLiScanner

# Импортируем XSS сканеры
from src.modules.xss.reflected import ReflectedXSSScanner
from src.modules.xss.stored import StoredXSSScanner
from src.modules.xss.dom_based import DomBasedXSSScanner

def main():
    # 1) Парсим аргументы командной строки
    args = parse_arguments()

    # 2) Настраиваем логгер
    logger = Logger(
        quiet=args.quiet,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # 3) --list-modules: выводим список доступных уязвимостей и выходим
    if args.list_modules:
        available_modules = [
            "sql_injection",
            "xss",
            # "nosql_injection",
            # "csrf",
            # ... другие
        ]
        logger.info("Available modules:")
        for m in available_modules:
            logger.info(f"- {m}")
        sys.exit(0)

    # 4) Инициализируем Requester
    requester = Requester(
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent
    )

    # (Опционально аутентификация, если есть класс Authenticator):
    # authenticator = None
    # if args.auth:
    #     authenticator = Authenticator(requester, args.auth)
    #     authenticator.login()

    # Инициализируем краулер
    crawler = Crawler(
        start_url=args.url,
        depth=args.depth,
        scope_pattern=args.scope,
        exclude_pattern=args.exclude,
        delay=args.delay,
        timeout=args.timeout,
        user_agent=args.user_agent
    )

    logger.info("Starting scan...")

    # 5) Запуск краулера (собирает URL и формы)
    found_urls = crawler.run()
    logger.info(f"Crawler found {len(found_urls)} URLs:")
    for link in found_urls:
        logger.info(f" - {link}")

    # Если формы извлекаются:
    if hasattr(crawler, "found_forms"):
        logger.info(f"Found {len(crawler.found_forms)} forms total.")
        for f in crawler.found_forms:
            logger.info(f"FORM: method={f['method']}, action={f['action']}, inputs={f['inputs']}")

    # 6) Проверка на уязвимости
    results = []

    # Разбираем modules
    if args.modules == "all":
        chosen_modules = ["sql_injection", "xss"]
    else:
        chosen_modules = args.modules.split(",")

    # Запуск SQL Injection
    if "sql_injection" in chosen_modules:
        sqli_results = run_sql_injection_scanners(
            requester, logger, found_urls, getattr(crawler, "found_forms", [])
        )
        results.extend(sqli_results)

    # Запуск XSS
    if "xss" in chosen_modules:
        xss_results = run_xss_scanners(
            requester, logger, found_urls, getattr(crawler, "found_forms", [])
        )
        results.extend(xss_results)

    # 7) Считаем и выводим итоги
    if results:
        logger.info(f"Found {len(results)} vulnerabilities.")
        if not args.output and not args.quiet:
            print_results_to_console(results, logger)
    else:
        logger.info("No vulnerabilities found.")
        if not args.quiet:
            logger.info("No vulnerabilities.")

    # Если указан --output, формируем отчёт
    if args.output:
        # При условии, что есть ReportGenerator
        report_gen = ReportGenerator(report_format=args.report)
        report_gen.generate(results, output_file=args.output)
        logger.info(f"Report saved to {args.output}")


def run_sql_injection_scanners(requester, logger, urls, forms):
    """
    Запускает все необходимые сканеры SQLi (Error-based, Boolean-based, Time-based).
    Возвращает список обнаруженных уязвимостей.
    """
    scanners = [
        ErrorBasedSQLiScanner(requester, logger),
        BooleanBasedSQLiScanner(requester, logger),
        TimeBasedSQLiScanner(requester, logger, delay_threshold=5.0)
    ]

    sqli_results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        sqli_results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        sqli_results.extend(r_forms)
    return sqli_results

def run_xss_scanners(requester, logger, urls, forms):
    """
    Запускает сканеры XSS (Reflected, Stored, DOM-based).
    """
    scanners = [
        ReflectedXSSScanner(requester, logger),
        StoredXSSScanner(requester, logger, verify_url=None),  # при желании передать verify_url
        DomBasedXSSScanner(requester, logger)
    ]

    xss_results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        xss_results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        xss_results.extend(r_forms)
    return xss_results


def print_results_to_console(results, logger):
    """
    Выводим детальные результаты в консоль (если не quiet).
    """
    logger.info("Detailed results:")
    for r in results:
        module = r.get("module")
        payload = r.get("payload")

        if module == "boolean_based_sqli":
            payload_true = r.get("payload_true")
            payload_false = r.get("payload_false")
            url_true = r.get("url_true")
            url_false = r.get("url_false")
            logger.info(f"[{module.upper()}] Detected difference for param with "
                        f"TRUE={payload_true} vs FALSE={payload_false}. "
                        f"URLs: {url_true}, {url_false}")
            continue

        if module == "time_based_sqli":
            observed_delay = r.get("observed_delay", 0)
            logger.info(f"[{module.upper()}] Found vulnerability with payload '{payload}'. "
                        f"Delay observed: {observed_delay} s. URL/form: {r.get('url') or r.get('form_action')}")
            continue

        # Пример вывода для XSS
        if module in ["reflected_xss", "stored_xss", "dom_based_xss"]:
            # Для stored может быть verify_url
            verify = r.get("verify_url")
            if verify:
                logger.info(f"[{module.upper()}] Found stored XSS, payload '{payload}', check {verify}")
            else:
                logger.info(f"[{module.upper()}] Found vulnerability with payload '{payload}' "
                            f"at {r.get('url') or r.get('form_action')}")
            continue

        # Ошибки SQLi (error_based) или прочие
        url = r.get("url") or r.get("form_action")
        logger.info(f"[{module.upper()}] Found vulnerability at {url} with payload {payload}")


if __name__ == "__main__":
    main()
