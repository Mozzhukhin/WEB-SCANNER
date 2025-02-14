#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import urllib.error
import urllib.parse
import logging
import time
import re
from html.parser import HTMLParser
from typing import Set, Optional
from collections import deque

# ------------------------------------------
# Данный модуль реализует функционал краулинга целевого веб-сайта.
# Теперь он сохраняет ссылки только с тем же доменом, что и стартовый URL.
# ------------------------------------------

class LinkExtractor(HTMLParser):
    """
    Вспомогательный класс для извлечения ссылок из HTML-контента.
    Использует встроенный HTMLParser.
    """

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        # Ищем атрибут href в ссылках <a href="...">
        if tag.lower() == "a":
            for (attr, value) in attrs:
                if attr.lower() == "href" and value:
                    self.links.append(value)


class Crawler:
    """
    Класс Crawler отвечает за обход целевого сайта.
    Настраиваемый функционал:
    - depth: глубина обхода.
    - scope_pattern: паттерн (регекс) для ограничения обхода.
    - exclude_pattern: паттерн (регекс) для исключения определенных URL.
    - delay: задержка между запросами.
    - timeout: таймаут запросов.
    - user_agent: кастомный User-Agent.
    """
    def __init__(self,
                 start_url: str,
                 depth: int = 1,
                 scope_pattern: Optional[str] = None,
                 exclude_pattern: Optional[str] = None,
                 delay: float = 0.0,
                 timeout: float = 10.0,
                 user_agent: str = "WebVulnScanner/1.0"):
        # Присвоим user_agent, если он не задан
        if not user_agent:
            user_agent = "WebVulnScanner/1.0"

        self.user_agent = user_agent
        """
        :param start_url: Начальный URL для краулинга.
        :param depth: Максимальная глубина обхода.
        :param scope_pattern: Регулярное выражение для ограничения сканируемых URL.
        :param exclude_pattern: Регулярное выражение для исключения некоторых URL.
        :param delay: Задержка между запросами, в секундах.
        :param timeout: Таймаут запроса в секундах.
        :param user_agent: User-Agent для HTTP-запросов.
        """
        self.start_url = start_url
        self.depth = depth
        self.scope_pattern = re.compile(scope_pattern) if scope_pattern else None
        self.exclude_pattern = re.compile(exclude_pattern) if exclude_pattern else None
        self.delay = delay
        self.timeout = timeout
        self.user_agent = user_agent

        # Определяем домен стартового URL
        self.start_domain = urllib.parse.urlparse(self.start_url).netloc

        # Очередь для обхода: кортеж (url, current_depth)
        self.queue = deque([(start_url, 0)])
        # Множество посещенных URL, чтобы не заходить в цикл
        self.visited = set()

    def run(self) -> Set[str]:
        """
        Запускает процесс краулинга и возвращает множество всех найденных URL.
        """
        logging.debug(f"Starting crawl from {self.start_url}")
        while self.queue:
            url, current_depth = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            # Проверим, принадлежит ли URL нужному домену и подходит ли он под фильтры
            if not self._check_url_scope(url):
                logging.debug(f"Skipping {url}, does not match domain/scope/exclude patterns.")
                continue

            logging.debug(f"Crawling {url} at depth {current_depth}")
            # Задержка между запросами
            if self.delay > 0:
                time.sleep(self.delay)

            # Получаем HTML-страницу
            html_content = self._fetch(url)
            if html_content is None:
                # Не смогли получить контент
                continue

            # Если глубина не достигнута, извлекаем ссылки
            if current_depth < self.depth:
                found_links = self._extract_links(html_content, url)
                for link in found_links:
                    if link not in self.visited:
                        self.queue.append((link, current_depth + 1))

        logging.debug(f"Crawl finished. Found {len(self.visited)} URLs.")
        return self.visited

    def _fetch(self, url: str) -> Optional[str]:
        """
        Выполняет HTTP-запрос к URL и возвращает содержимое HTML.
        В случае ошибки или недоступности URL возвращает None.
        """
        # Настраиваем запрос с учетом User-Agent и таймаута
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if "text/html" in response.getheader("Content-Type", ""):
                    html = response.read().decode("utf-8", errors="replace")
                    return html
                else:
                    logging.debug(f"Skipping {url}, not HTML content.")
                    return None
        except (urllib.error.URLError, ValueError) as e:
            logging.debug(f"Failed to fetch {url}: {e}")
            return None

    def _extract_links(self, html_content: str, base_url: str) -> Set[str]:
        """
        Извлекает ссылки из HTML-контента, приводит их к абсолютному URL,
        фильтрует по домену и другим паттернам.
        """
        extractor = LinkExtractor()
        extractor.feed(html_content)

        found_links = set()
        for link in extractor.links:
            # Преобразуем относительный URL в абсолютный
            full_link = urllib.parse.urljoin(base_url, link)
            # Нормализуем URL (удаляем фрагменты и пр.)
            full_link = self._normalize_url(full_link)
            if full_link and self._check_url_scope(full_link):
                found_links.add(full_link)

        return found_links

    def _check_url_scope(self, url: str) -> bool:
        """
        Проверяет, принадлежит ли URL тому же домену, что и стартовый URL,
        и соответствует ли он заданным паттернам scope/exclude.
        Возвращает True, если URL должен быть просканирован.
        """
        parsed = urllib.parse.urlparse(url)
        # Сохраняем только ссылки с тем же доменом
        if parsed.netloc != self.start_domain:
            return False

        if self.scope_pattern:
            if not self.scope_pattern.search(url):
                return False

        if self.exclude_pattern:
            if self.exclude_pattern.search(url):
                return False

        return True

    def _normalize_url(self, url: str) -> Optional[str]:
        """
        Нормализует URL, удаляет фрагменты (#...) и другие незначащие элементы.
        Если URL невалиден, возвращает None.
        """
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            # Некорректный или неполный URL
            return None
        # Удаляем фрагмент
        url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
        return url
