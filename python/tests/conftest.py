"""pytest configuration and fixtures for secretsh tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def temp_env_file() -> Generator[Path, None, None]:
    """Create a temporary .env file with test secrets."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("TEST_SECRET=hunter2\n")
        f.write("API_KEY=sk-test-12345\n")
        f.write("DATABASE_URL=postgresql://user:pass@localhost/db\n")
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    os.unlink(temp_path)


@pytest.fixture
def empty_env_file() -> Generator[Path, None, None]:
    """Create an empty .env file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    os.unlink(temp_path)


@pytest.fixture
def missing_key_env_file() -> Generator[Path, None, None]:
    """Create a .env file without the expected key."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("OTHER_KEY=somevalue\n")
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    os.unlink(temp_path)
