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

Задачи:
- Предоставить класс Requester, который умеет выполнять GET/POST-запросы.
- Учитывать задержку между запросами (rate limiting).
- Поддержать опциональный пользовательский User-Agent.
- Позже можно расширить поддержкой SSL, куки, сессий.

Принцип работы:
- При инициализации передаем параметры (timeout, delay, user_agent).
- При каждом запросе, если delay > 0, делаем небольшую паузу.
- Используем стандартные библиотеки Python для запросов (например, urllib).
- Возвращаем текст ответа или код статуса.
- Если нужно, в будущем реализуем логирование запросов, обработку ошибок.

Комментарии на русском, код и имена переменных на английском.
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
        user_agent (str): Строка, используемая в заголовке User-Agent. Если None, используем дефолтный.
        """
        if not user_agent:
            user_agent = "WebVulnScanner/1.0"
        self.user_agent = user_agent

        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent if user_agent else "WebVulnScanner/1.0"
        # Можно добавить поддержку cookies и session при необходимости
        # Пока оставляем простую реализацию.

    def get(self, url):
        """
        Выполняет GET-запрос к указанному URL.

        Возвращает:
        str: Тело ответа (HTML, JSON и т.д.), если запрос успешен.
        None, если произошла ошибка.
        """
        # Перед запросом учитываем задержку
        if self.delay > 0:
            time.sleep(self.delay)

        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                # Читаем ответ и декодируем
                data = response.read().decode("utf-8", errors="replace")
                return data
        except urllib.error.HTTPError as e:
            # Если сервер вернул ошибку (например, 404)
            # Можно залогировать или вернуть None
            return None
        except urllib.error.URLError as e:
            # Проблемы с сетью, DNS и т.п.
            return None

    def post(self, url, data):
        """
        Выполняет POST-запрос к указанному URL.

        Параметры:
        data (dict): Данные для отправки, преобразуем в form-data.

        Возвращает:
        str: Тело ответа, если запрос успешен.
        None, если произошла ошибка.
        """
        # Перед запросом учитываем задержку
        if self.delay > 0:
            time.sleep(self.delay)

        encoded_data = None
        if data:
            # Кодируем словарь в форму: key=value&key2=value2
            # Используем urllib.parse.urlencode
            from urllib.parse import urlencode
            encoded_data = urlencode(data).encode("utf-8")

        req = urllib.request.Request(url, data=encoded_data, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                data = response.read().decode("utf-8", errors="replace")
                return data
        except urllib.error.HTTPError:
            return None
        except urllib.error.URLError:
            return None
