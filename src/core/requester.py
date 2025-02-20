# coding: utf-8
"""
Файл: requester.py
------------------
Назначение:
Этот модуль отвечает за отправку HTTP/HTTPS запросов с учётом:
- Таймаута (--timeout)
- Задержки между запросами (--delay)
- Пользовательского User-Agent (--user-agent)
- Обработку редиректов, куки и прочих нюансов.

Новая доработка:
- Сохраняем self.last_url (конечный URL после возможных редиректов).
  Это позволит сканеру проверить, что мы в итоге ушли на внешний ресурс.

Принцип работы (не ломаем существующую логику!):
- При инициализации: timeout, delay, user_agent, self.last_url=None
- get/post: возвращаем текст ответа или None, как раньше
- Если запрос прошёл, сохраняем self.last_url = response.geturl()
- Если произошла ошибка/исключение, self.last_url = None
"""

import time
import urllib.request
import urllib.error


class Requester:
    def __init__(self, timeout=10.0, delay=0.0, user_agent=None):
        """
        Инициализация Requester.

        Параметры:
        timeout (float): Максимальное время ожидания ответа (в секундах).
        delay (float): Задержка перед выполнением каждого запроса (в секундах).
        user_agent (str): Строка, используемая в заголовке User-Agent.
                         Если None, используем дефолтный "WebVulnScanner/1.0".
        """
        if not user_agent:
            user_agent = "WebVulnScanner/1.0"
        self.user_agent = user_agent

        self.timeout = timeout
        self.delay = delay
        # Запомним user_agent (ещё раз, чтобы быть уверенными)
        self.user_agent = user_agent if user_agent else "WebVulnScanner/1.0"

        # Новое поле: хранить конечный URL после 3xx-редиректов (если они были)
        self.last_url = None

    def get(self, url):
        """
        Выполняет GET-запрос к указанному URL.

        Возвращает:
        str: Тело ответа (HTML, JSON и т.д.), если запрос успешен.
        None, если произошла ошибка.
        После успешного запроса self.last_url = финальный URL (после редиректов).
        Если ошибка, self.last_url = None.
        """
        # Перед запросом учитываем задержку
        if self.delay > 0:
            time.sleep(self.delay)

        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                # Читаем ответ и декодируем
                data = response.read().decode("utf-8", errors="replace")
                # Сохраним финальный адрес
                self.last_url = response.geturl()  # URL после возможного редиректа
                return data
        except urllib.error.HTTPError:
            self.last_url = None
            return None
        except urllib.error.URLError:
            self.last_url = None
            return None

    def post(self, url, data):
        """
        Выполняет POST-запрос к указанному URL.

        Параметры:
        data (dict): Данные для отправки, преобразуем в form-data.

        Возвращает:
        str: Тело ответа, если запрос успешен.
        None, если произошла ошибка.
        Аналогично, после успешного запроса self.last_url = финальный URL.
        """
        # Перед запросом учитываем задержку
        if self.delay > 0:
            time.sleep(self.delay)

        encoded_data = None
        if data:
            from urllib.parse import urlencode
            encoded_data = urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=encoded_data, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                data = response.read().decode("utf-8", errors="replace")
                # Сохраним финальный адрес
                self.last_url = response.geturl()
                return data
        except urllib.error.HTTPError:
            self.last_url = None
            return None
        except urllib.error.URLError:
            self.last_url = None
            return None
