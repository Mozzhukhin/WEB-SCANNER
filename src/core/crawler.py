#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib.request
import urllib.error
import urllib.parse
import logging
import time
import re
from html.parser import HTMLParser
from typing import Set, Optional, List, Dict
from collections import deque


class LinkAndFormExtractor(HTMLParser):
    """
    Парсер HTML, извлекающий:
    1) Все ссылки (<a href="...">).
    2) Формы (<form>) и их поля (<input>, <select>, <textarea> при желании).
    """

    def __init__(self):
        super().__init__()
        self.links = []       # Ссылки, найденные в <a href="...">
        self.forms = []       # Список форм, каждая — словарь с ключами: method, action, inputs
        self._current_form = None  # Временное хранилище для данных о форме, пока не встретим следующий <form>

    def handle_starttag(self, tag, attrs):
        # Приводим имя тега к нижнему регистру
        tag = tag.lower()

        if tag == "a":
            # Ищем href
            for (attr, value) in attrs:
                if attr.lower() == "href" and value:
                    self.links.append(value)

        elif tag == "form":
            # Начало формы: создаём новую структуру
            form_method = "get"
            form_action = ""
            for (attr, value) in attrs:
                if attr.lower() == "method" and value:
                    form_method = value.lower()
                if attr.lower() == "action" and value:
                    form_action = value
            self._current_form = {
                "method": form_method,
                "action": form_action,
                "inputs": []
            }
            self.forms.append(self._current_form)

        elif tag == "input" and self._current_form is not None:
            # Поле формы: name, type, value
            input_name = ""
            input_type = "text"
            input_value = ""
            for (attr, value) in attrs:
                attr = attr.lower()
                if attr == "name":
                    input_name = value
                elif attr == "type":
                    input_type = value.lower()
                elif attr == "value":
                    input_value = value
            # Добавляем в текущую форму
            self._current_form["inputs"].append({
                "name": input_name,
                "type": input_type,
                "value": input_value
            })

        # При желании можно обрабатывать <textarea>, <select> и т.д.

    def handle_endtag(self, tag):
        # Если встретили закрытие тега form — сбрасываем _current_form
        tag = tag.lower()
        if tag == "form" and self._current_form is not None:
            self._current_form = None


class Crawler:
    """
    Класс Crawler отвечает за обход целевого сайта (BFS) и извлечение ссылок / форм.
    Параметры:
    - depth: глубина обхода
    - scope_pattern: регекс для включения
    - exclude_pattern: регекс для исключения
    - delay: задержка между запросами
    - timeout: таймаут
    - user_agent: заголовок User-Agent
    - start_domain: выделяется из start_url, чтобы не уходить на другие домены
    """

    def __init__(self,
                 start_url: str,
                 depth: int = 1,
                 scope_pattern: Optional[str] = None,
                 exclude_pattern: Optional[str] = None,
                 delay: float = 0.0,
                 timeout: float = 10.0,
                 user_agent: str = "WebVulnScanner/1.0"):

        if not user_agent:
            user_agent = "WebVulnScanner/1.0"
        self.start_url = start_url
        self.depth = depth
        self.scope_pattern = re.compile(scope_pattern) if scope_pattern else None
        self.exclude_pattern = re.compile(exclude_pattern) if exclude_pattern else None
        self.delay = delay
        self.timeout = timeout
        self.user_agent = user_agent

        self.start_domain = urllib.parse.urlparse(self.start_url).netloc

        self.queue = deque([(start_url, 0)])
        self.visited = set()

        # Здесь будем хранить все формы, найденные во время обхода
        self.found_forms = []

    def run(self) -> Set[str]:
        """
        Запускает процесс краулинга и возвращает множество всех найденных URL.
        Все найденные формы сохраняются в self.found_forms.
        """
        logging.debug(f"Starting crawl from {self.start_url}")

        while self.queue:
            url, current_depth = self.queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            # Проверяем домен и фильтры
            if not self._check_url_scope(url):
                logging.debug(f"Skipping {url}, not in domain/scope/exclude.")
                continue

            logging.debug(f"Crawling {url} at depth {current_depth}")

            if self.delay > 0:
                time.sleep(self.delay)

            html_content = self._fetch(url)
            if html_content is None:
                continue

            # Извлекаем ссылки и формы
            found_links, found_forms = self._extract_links_and_forms(html_content, url)
            # Сохраняем формы (дополняем общий список)
            self.found_forms.extend(found_forms)

            # Если глубина ещё не достигнута, добавляем ссылки в очередь
            if current_depth < self.depth:
                for link in found_links:
                    if link not in self.visited:
                        self.queue.append((link, current_depth + 1))

        logging.debug(f"Crawl finished. Found {len(self.visited)} URLs total.")
        logging.debug(f"Found {len(self.found_forms)} forms total.")

        return self.visited

    def _fetch(self, url: str) -> Optional[str]:
        """
        Выполняет GET-запрос и возвращает текст страницы или None при ошибке.
        """
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if "text/html" in response.getheader("Content-Type", ""):
                    return response.read().decode("utf-8", errors="replace")
                else:
                    logging.debug(f"Skipping {url}, not HTML content.")
                    return None
        except (urllib.error.URLError, ValueError) as e:
            logging.debug(f"Failed to fetch {url}: {e}")
            return None

    def _extract_links_and_forms(self, html_content: str, base_url: str):
        """
        Извлекает ссылки и формы из HTML-кода.
        Ссылки приводим к абсолютным URL, фильтруем по домену и паттернам.
        Формы сохраняем как есть, но action тоже приводим к абсолютному URL.

        Возвращает:
          (set_of_links, list_of_forms)
        """
        parser = LinkAndFormExtractor()
        parser.feed(html_content)

        # Преобразуем ссылки
        found_links = set()
        for link in parser.links:
            full_link = urllib.parse.urljoin(base_url, link)
            full_link = self._normalize_url(full_link)
            if full_link and self._check_url_scope(full_link):
                found_links.add(full_link)

        # Преобразуем формы
        found_forms = []
        for form in parser.forms:
            action_abs = urllib.parse.urljoin(base_url, form["action"])
            action_abs = self._normalize_url(action_abs)
            if action_abs and self._check_url_scope(action_abs):
                # Создаём копию формы с абсолютным action
                new_form = {
                    "method": form["method"],
                    "action": action_abs,
                    "inputs": form["inputs"]
                }
                found_forms.append(new_form)

        return found_links, found_forms

    def _check_url_scope(self, url: str) -> bool:
        """
        Проверяем, принадлежит ли URL тому же домену, что и стартовый,
        и соответствует ли scope/exclude паттернам.
        """
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc != self.start_domain:
            return False

        if self.scope_pattern and not self.scope_pattern.search(url):
            return False

        if self.exclude_pattern and self.exclude_pattern.search(url):
            return False

        return True

    def _normalize_url(self, url: str) -> Optional[str]:
        """
        Удаляем фрагмент (#...) и возвращаем итоговый URL,
        или None, если URL некорректен.
        """
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return None
        # Собираем обратно без фрагмента
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, "")
        )
