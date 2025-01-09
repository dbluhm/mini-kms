import pytest
import json
import base64
from typing import Dict

# Test data
TEST_PROFILE_NAME = "test_profile"
TEST_MESSAGE = "Hello, World!"
TEST_KEY_ALG = "ed25519"  # Using ed25519 as it's good for signing

def test_create_profile(api_client, api_base_url):
    """Test creating a new profile."""
    response = api_client.post(
        f"{api_base_url}/profile",
        json={"name": TEST_PROFILE_NAME}
    )
    assert response.status_code == 200
    assert response.json()["name"] == TEST_PROFILE_NAME

def test_generate_key(api_client, api_base_url):
    """Test generating a new key."""
    response = api_client.post(
        f"{api_base_url}/key/generate",
        headers={"X-Profile": TEST_PROFILE_NAME},
        json={"alg": TEST_KEY_ALG}
    )
    assert response.status_code == 200
    result = response.json()
    assert "kid" in result
    assert "jwk" in result
    assert "b58" in result

def test_sign_value(api_client, api_base_url):
    """Test signing a value with a generated key."""
    # First, generate a key
    key_response = api_client.post(
        f"{api_base_url}/key/generate",
        headers={"X-Profile": TEST_PROFILE_NAME},
        json={"alg": TEST_KEY_ALG}
    )
    assert key_response.status_code == 200
    kid = key_response.json()["kid"]
    
    # Now sign a message
    message_bytes = TEST_MESSAGE.encode('utf-8')
    message_b64 = base64.urlsafe_b64encode(message_bytes).decode('utf-8')
    
    sign_response = api_client.post(
        f"{api_base_url}/sign",
        headers={"X-Profile": TEST_PROFILE_NAME},
        json={
            "kid": kid,
            "data": message_b64
        }
    )
    assert sign_response.status_code == 200
    assert "sig" in sign_response.json()

def test_error_handling(api_client, api_base_url):
    """Test basic error handling."""
    # Test invalid profile name
    response = api_client.post(
        f"{api_base_url}/profile",
        json={"name": ""}
    )
    assert response.status_code == 422

    # Test invalid algorithm
    response = api_client.post(
        f"{api_base_url}/key/generate",
        headers={"X-Profile": TEST_PROFILE_NAME},
        json={"alg": "invalid_alg"}
    )
    assert response.status_code == 422

    # Test signing with non-existent key
    message_bytes = TEST_MESSAGE.encode('utf-8')
    message_b64 = base64.urlsafe_b64encode(message_bytes).decode('utf-8')
    response = api_client.post(
        f"{api_base_url}/sign",
        headers={"X-Profile": TEST_PROFILE_NAME},
        json={
            "kid": "non_existent_key",
            "data": message_b64
        }
    )
    assert response.status_code == 422