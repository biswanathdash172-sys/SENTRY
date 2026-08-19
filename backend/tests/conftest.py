"""
conftest.py
-----------
Pytest configuration: adds the backend/ directory to sys.path so that test
files can import modules like 'models', 'services', 'db', etc. without
needing relative imports.

This allows tests to use:
    from models import Alert
    from services import correlation_engine

Instead of:
    from ..models import Alert
    from ..services import correlation_engine
"""

import sys
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent
sys.path.insert(0, str(backend_dir))
