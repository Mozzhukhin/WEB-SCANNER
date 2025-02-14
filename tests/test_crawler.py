import unittest
from src.core.crawler import Crawler
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import os

class TestCrawler(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Запускаем локальный HTTP-сервер на свободном порте
        cls.server_port = 8888
        cls.httpd = HTTPServer(('localhost', cls.server_port), SimpleHTTPRequestHandler)

        # Запускаем в отдельном потоке
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()

        # Допустим, HTML-файлы лежат в папке "test_pages", а мы меняем рабочую директорию, чтобы SimpleHTTPRequestHandler раздавал их
        os.chdir("examples/test_pages")

    def test_basic_crawl(self):
        # Допустим, у нас есть index.html, page1.html, page2.html
        start_url = f"http://localhost:{self.server_port}/index.html"
        crawler = Crawler(start_url, depth=1)
        found_urls = crawler.run()

        # Сравниваем набор найденных ссылок (указать ожидаемые ссылки в зависимости от структуры test_pages)
        expected_urls = {
            start_url,  # сам index.html
            f"http://localhost:{self.server_port}/page1.html",
            f"http://localhost:{self.server_port}/page2.html"
        }
        self.assertEqual(found_urls, expected_urls)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

if __name__ == '__main__':
    unittest.main()
