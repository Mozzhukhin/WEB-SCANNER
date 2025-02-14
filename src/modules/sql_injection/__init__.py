# coding: utf-8
"""
__init__.py
-----------
Упрощает импорт модулей SQL-инъекций.
"""

from .error_based import ErrorBasedSQLiScanner
from .boolean_based import BooleanBasedSQLiScanner
from .time_based import TimeBasedSQLiScanner
# from .union_based import UnionBasedSQLiScanner (если будете добавлять)
# from .blind_sql_injection import BlindSQLiScanner ...
