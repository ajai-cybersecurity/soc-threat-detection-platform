"""
Base parser – all log parsers extend this class.
"""
import re
from datetime import datetime
from abc import ABC, abstractmethod


class BaseParser(ABC):
    def __init__(self):
        self.name = 'base'

    @abstractmethod
    def parse_line(self, line: str) -> dict:
        pass

    def parse_file(self, filepath: str) -> list:
        results = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed = self.parse_line(line)
                        if parsed:
                            results.append(parsed)
        except Exception as e:
            print(f"[Parser Error] {self.name}: {e}")
        return results

    @staticmethod
    def safe_datetime(ts_str: str, fmt: str = None):
        formats = [
            '%b %d %H:%M:%S', '%b  %d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S', '%d/%b/%Y:%H:%M:%S %z',
            '%Y-%m-%dT%H:%M:%S', '%m/%d/%Y %I:%M:%S %p',
        ]
        if fmt:
            try:
                return datetime.strptime(ts_str.strip(), fmt)
            except Exception:
                pass
        for f in formats:
            try:
                dt = datetime.strptime(ts_str.strip(), f)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except Exception:
                continue
        return datetime.utcnow()

    @staticmethod
    def extract_ip(text: str) -> str:
        m = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
        return m.group(1) if m else None
