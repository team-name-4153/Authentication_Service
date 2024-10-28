import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app import app as main_app  # Import the main app for login and JWT generation
from pseudo_app import app as pseudo_app  # Import pseudo_app to test the protected route

@pytest.fixture
def main_client():
    main_app.testing = True
    return main_app.test_client()

@pytest.fixture
def pseudo_client():
    pseudo_app.testing = True
    return pseudo_app.test_client()

def test_protected_route_with_valid_token(main_client, pseudo_client):
    main_client.post('/register', json={'email': 'test_middleware@example.com', 'password': 'password123'})
    login_response = main_client.post('/login', json={'identifier': 'test_middleware@example.com', 'password': 'password123'}) 
    # login response contains cookie inside

    token_cookie = login_response.headers.get('Set-Cookie')
    token = token_cookie.split('token=')[1].split(';')[0]

    pseudo_client.set_cookie('token', token)
    response = pseudo_client.get('/hello')
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    response_json = response.get_json()
    assert response_json['message'] == "Hello World!"
