# coding: utf-8
"""
Файл: logger.py
---------------
Назначение:
Этот модуль предоставляет класс Logger для управления выводом
информации в консоль с учётом флагов --quiet, --verbose и --no-color.

Основные задачи:
- Абстрагировать вывод от остального кода.
- Учесть режимы:
  * quiet: минимальный вывод, только важная информация (например, итоги)
  * verbose: подробный отладочный вывод
  * normal (по умолчанию): средний уровень детализации.
- Опционально отключать цвет для сред, не поддерживающих ANSI-коды
  (при указании --no-color).
- Предоставить методы:
  - info(msg): Выводит информационное сообщение (обычный уровень)
  - warn(msg): Предупреждающее сообщение
  - error(msg): Сообщение об ошибке
  - debug(msg): Отладочное сообщение (показывается только в verbose режиме)
- По возможности использовать цвета для различения уровней,
  если не установлен --no-color.

Пример использования:
logger = Logger(quiet=False, verbose=False, no_color=False)
logger.info("Scan started...")
logger.debug("This is a debug message") # не покажется если verbose=False
logger.error("Something went wrong")

Комментарии на русском, имена функций и переменных на английском, вывод — на английском.
"""

import sys


class Logger:
    def __init__(self, quiet=False, verbose=False, no_color=False):
        """
        Инициализирует логгер.

        Параметры:
        quiet (bool): Если True, выводим только самые необходимые сообщения (info с итогами, error)
        verbose (bool): Если True, выводим подробный отладочный вывод (debug).
                        Если quiet=True, verbose игнорируется, так как quiet имеет приоритет.
        no_color (bool): Если True, отключаем цветовое форматирование.
        """
        self.quiet = quiet
        self.verbose = verbose
        self.no_color = no_color

        # Если quiet=True, игнорируем verbose
        if self.quiet:
            self.verbose = False

        # Определим ANSI-коды для цветов, если no_color=False
        if self.no_color:
            self.color_info = ""
            self.color_warn = ""
            self.color_error = ""
            self.color_debug = ""
            self.color_reset = ""
        else:
            self.color_info = "\033[94m"  # Светло-синий для info
            self.color_warn = "\033[93m"  # Желтый для warn
            self.color_error = "\033[91m"  # Красный для error
            self.color_debug = "\033[90m"  # Серый для debug
            self.color_reset = "\033[0m"

    def info(self, msg):
        """
        Информационное сообщение. В normal и verbose режимах выводится всегда.
        В quiet режиме: выводим только если сообщение критически важно.

        Здесь предполагаем, что info — это обычный уровень.
        В quiet режиме мы можем продолжать выводить info, если это касается итогов,
        но давайте определим, что info — это "обычный" уровень.
        Чтобы иметь минимальный вывод, ограничим info при quiet:
        - Если quiet=True, то выводим info только если это итоговое или очень важное сообщение.
          Для упрощения считаем, что info — это всегда можно вывести, так как у нас нет уточнений.
          Но обычно quiet режим предполагает вывод очень ограниченный.
          Пусть в quiet режиме мы не будем выводить info, кроме случаев когда нужно итог.
          Тогда этот контроль делаем в месте вызова, а тут просто не выводим если quiet=True.
        """
        if not self.quiet:
            self._print_message(self.color_info, "INFO", msg)

    def warn(self, msg):
        """
        Предупреждающее сообщение. Обычно важно.
        В quiet режиме можно вывести, так как это предупреждение?
        Предположим, что warn важен, выведем даже в quiet-режиме.
        """
        if not self.quiet:
            self._print_message(self.color_warn, "WARN", msg)
        else:
            # В quiet режиме все же стоит что-то выводить, так как WARN — важное сообщение
            self._print_message("", "WARN", msg)

    def error(self, msg):
        """
        Сообщение об ошибке. Выводится всегда, даже в quiet режиме,
        так как это критически важная информация.
        """
        self._print_message(self.color_error, "ERROR", msg)

    def debug(self, msg):
        """
        Отладочное сообщение.
        Выводим только при verbose=True и quiet=False.
        """
        if self.verbose and not self.quiet:
            self._print_message(self.color_debug, "DEBUG", msg)

    def _print_message(self, color, level, msg):
        """
        Вспомогательный метод для вывода сообщения.
        Применяет цвет, уровень, сброс цвета.
        """
        # Форматируем строку: [LEVEL] msg
        # Если нужен цвет — используем, иначе color пустой.
        # Учитываем, что level будет в скобках, например [INFO].
        formatted = f"{color}[{level}]{self.color_reset} {msg}" if color else f"[{level}] {msg}"
        # Выводим в stdout. Можно было бы в будущем логировать в файл.
        print(formatted, file=sys.stdout)
