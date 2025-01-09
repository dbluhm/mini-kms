import pytest
import requests
import time
from typing import Generator


@pytest.fixture(scope="session")
def api_base_url() -> str:
    """Base URL for the API server."""
    return "http://localhost:8080"


@pytest.fixture(scope="function")
def api_client(api_base_url: str) -> Generator[requests.Session, None, None]:
    """Create a requests session for API calls."""
    session = requests.Session()
    session.headers.update({
        "Content-Type": "application/json",
        "Accept": "application/json"
    })
    
    # Wait for server to be ready
    max_retries = 30
    retry_delay = 1
    for _ in range(max_retries):
        try:
            response = session.get(f"{api_base_url}/docs")
            if response.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(retry_delay)
    else:
        pytest.fail("Server did not become ready in time")
    
    yield session
    session.close()