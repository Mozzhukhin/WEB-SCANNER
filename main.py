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
6) Проверяем уязвимости (SQL Injection, XSS, CSRF, etc.) если выбраны в --modules.
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
from src.modules.nosql_injection.simple_nosql import SimpleNoSQLiScanner
from src.modules.nosql_injection.advanced_nosql import AdvancedNoSQLiScanner
from src.modules.xss.reflected import ReflectedXSSScanner
from src.modules.xss.stored import StoredXSSScanner
from src.modules.xss.dom_based import DomBasedXSSScanner
from src.modules.csrf.csrf_scanner import BasicCSRFScanner
from src.modules.directory_traversal import DirectoryTraversalScanner
from src.modules.rce.command_injection import CommandInjectionScanner
from src.modules.rce.code_injection import CodeInjectionScanner
from src.modules.open_redirect import OpenRedirectScanner
from src.modules.idor import IDORScanner
from src.modules.ssrf import SSRFScanner
from src.modules.file_upload import FileUploadScanner
from src.modules.authentication import AuthScanner


def main():
    # 1) Парсим аргументы командной строки
    args = parse_arguments()

    # 2) Настраиваем логгер
    logger = Logger(
        quiet=args.quiet,
        verbose=args.verbose,
        no_color=args.no_color
    )

    # 3) Создаём словарь доступных модулей,
    #    чтобы при --list-modules и "all" использовать автоматически.
    module_handlers = {
        "sql_injection": run_sql_injection_scanners,
        "xss": run_xss_scanners,
        "csrf": run_csrf_scanner,
        "nosql_injection": run_nosql_injection_scanners,
        "directory_traversal": run_directory_traversal_scanner,
        "rce": run_rce_scanners,
        "open_redirect": run_open_redirect_scanner,
        "idor": run_idor_scanner,
        "ssrf": run_ssrf_scanner,
        "insecure_file_upload": run_insecure_file_upload_scanner,
        "authentication": run_authentication_scanner,
        # ...
    }

    # Если пользователь просит --list-modules, показываем и выходим
    if args.list_modules:
        logger.info("Available modules:")
        for m in module_handlers.keys():
            logger.info(f"- {m}")
        sys.exit(0)

    # 4) Инициализируем Requester
    requester = Requester(
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent
    )

    # (Опционально аутентификация)
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

    found_forms = getattr(crawler, "found_forms", [])
    if found_forms:
        logger.info(f"Found {len(found_forms)} forms total.")
        for f in found_forms:
            logger.info(f"FORM: method={f['method']}, action={f['action']}, inputs={f['inputs']}")

    # 6) Проверка на уязвимости
    results = []

    # Если modules=all, то берём все, иначе разбиваем
    if args.modules == "all":
        chosen_modules = list(module_handlers.keys())
    else:
        chosen_modules = args.modules.split(",")

    for mod in chosen_modules:
        mod = mod.strip()
        handler = module_handlers.get(mod)
        if handler:
            mod_results = handler(requester, logger, found_urls, found_forms)
            results.extend(mod_results)
        else:
            logger.warn(f"Module '{mod}' not recognized or not implemented.")

    # 7) Итог
    if results:
        logger.info(f"Found {len(results)} vulnerabilities.")
        if not args.output and not args.quiet:
            print_results_to_console(results, logger)
    else:
        logger.info("No vulnerabilities found.")
        if not args.quiet:
            logger.info("No vulnerabilities.")

    # --output => Report
    if args.output:
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
        StoredXSSScanner(requester, logger),
        DomBasedXSSScanner(requester, logger)
    ]

    xss_results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        xss_results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        xss_results.extend(r_forms)
    return xss_results


def run_csrf_scanner(requester, logger, urls, forms):
    """
    Запускает CSRF-сканер (например, BasicCSRFScanner).
    """
    from src.modules.csrf.csrf_scanner import BasicCSRFScanner

    scanners = [
        BasicCSRFScanner(requester, logger)
        # Если захотите сделать несколько видов CSRF-сканеров, добавьте их сюда
    ]

    csrf_results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        csrf_results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        csrf_results.extend(r_forms)
    return csrf_results


def print_results_to_console(results, logger):
    """
    Выводим детальные результаты в консоль (если не quiet).
    """
    logger.info("Detailed results:")
    for r in results:
        module = r.get("module")
        payload = r.get("payload")

        # Boolean-based SQLi
        if module == "boolean_based_sqli":
            payload_true = r.get("payload_true")
            payload_false = r.get("payload_false")
            url_true = r.get("url_true")
            url_false = r.get("url_false")
            logger.info(f"[{module.upper()}] Detected difference for param with "
                        f"TRUE={payload_true} vs FALSE={payload_false}. "
                        f"URLs: {url_true}, {url_false}")
            continue

        # Time-based SQLi
        if module == "time_based_sqli":
            observed_delay = r.get("observed_delay", 0)
            logger.info(f"[{module.upper()}] Found vulnerability with payload '{payload}'. "
                        f"Delay observed: {observed_delay} s. URL/form: {r.get('url') or r.get('form_action')}")
            continue

        # XSS
        if module in ["reflected_xss", "stored_xss", "dom_based_xss"]:
            verify = r.get("verify_url")
            if verify:
                logger.info(f"[{module.upper()}] Found stored XSS, payload '{payload}', check {verify}")
            else:
                logger.info(f"[{module.upper()}] Found vulnerability with payload '{payload}' "
                            f"at {r.get('url') or r.get('form_action')}")
            continue

        # CSRF
        if module == "csrf":
            issue = r.get("issue", "CSRF check failed")
            # example: "No CSRF token found" or "Server accepted request without token"
            logger.info(f"[CSRF] {issue} at form: {r.get('form_action')}")
            continue

        # Ошибки SQLi (error_based) или прочие
        url = r.get("url") or r.get("form_action")
        logger.info(f"[{module.upper()}] Found vulnerability at {url} with payload {payload}")


def run_nosql_injection_scanners(requester, logger, urls, forms):
    """
    Запускает SimpleNoSQLiScanner и AdvancedNoSQLiScanner.
    """
    scanners = [
        SimpleNoSQLiScanner(requester, logger),
        AdvancedNoSQLiScanner(requester, logger, delay_threshold=2.0)
    ]

    results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        results.extend(r_forms)
    return results


def run_directory_traversal_scanner(requester, logger, urls, forms):
    scanner = DirectoryTraversalScanner(requester, logger)
    results = []
    results.extend(scanner.scan_urls(urls))
    results.extend(scanner.scan_forms(forms))
    return results


def run_rce_scanners(requester, logger, urls, forms):
    scanners = [
        CommandInjectionScanner(requester, logger),
        CodeInjectionScanner(requester, logger)
    ]
    results = []
    for scanner in scanners:
        r_urls = scanner.scan_urls(urls)
        results.extend(r_urls)
        r_forms = scanner.scan_forms(forms)
        results.extend(r_forms)
    return results


def run_open_redirect_scanner(requester, logger, urls, forms):
    scanner = OpenRedirectScanner(requester, logger)
    results = []
    results.extend(scanner.scan_urls(urls))
    results.extend(scanner.scan_forms(forms))
    return results

def run_idor_scanner(requester, logger, urls, forms):
    scanner = IDORScanner(requester, logger)
    results = []
    results.extend(scanner.scan_urls(urls))
    results.extend(scanner.scan_forms(forms))
    return results

def run_ssrf_scanner(requester, logger, urls, forms):
    scanner = SSRFScanner(requester, logger)
    results = []
    results.extend(scanner.scan_urls(urls))
    results.extend(scanner.scan_forms(forms))
    return results


def run_insecure_file_upload_scanner(requester, logger, urls, forms):
    scanner = FileUploadScanner(requester, logger)
    results = []
    results.extend(scanner.scan_urls(urls))
    results.extend(scanner.scan_forms(forms))
    return results


def run_authentication_scanner(requester, logger, urls, forms):
    scanner = AuthScanner(requester, logger)
    results = []
    # Сканируем URL
    r_urls = scanner.scan_urls(urls)
    results.extend(r_urls)
    # Сканируем Forms
    r_forms = scanner.scan_forms(forms)
    results.extend(r_forms)
    return results


if __name__ == "__main__":
    main()
