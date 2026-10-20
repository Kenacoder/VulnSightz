from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def sample_crawl_map() -> dict:
    return {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [
            {
                "url": "http://127.0.0.1:5001/reflect?q=test",
                "method": "GET",
                "params": [
                    {
                        "name": "q",
                        "value": "test",
                        "source": "query",
                        "input_type": "text",
                    }
                ],
            }
        ],
        "forms": [],
        "endpoints": [],
    }
