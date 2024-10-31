import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

# Environment variables for the test scenario
os.environ['SECRET_KEY'] = 'auth_secret_key'
os.environ['JWT_EXPIRATION'] = '10'  # Token expiration in 10 seconds
os.environ['JWT_REFRESH'] = '5'  # Token refresh in 5 seconds

from app import app
import json

@pytest.fixture
def client():
    app.testing = True
    return app.test_client()

def test_register_endpoint(client):
    response = client.post('/register', json={'email': 'test@example.com', 'password': 'password123'})
    assert response.status_code == 201, f"Expected 201, got {response.status_code}"
    
    response_json = json.loads(response.get_data())
    assert response_json['status'] == 'success'
    assert 'user_id' in response_json  # Verify user_id is returned
    assert response_json['message'] == 'Registration successful'

def test_login_endpoint(client):
    # client.post('/register', json={'email': 'test@example.com', 'password': 'password123'})
    response = client.post('/login', json={'identifier': 'test@example.com', 'password': 'password123'})
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    token_cookie = response.headers.get('Set-Cookie')
    assert token_cookie is not None, "Token cookie not found in response headers"
    assert 'token=' in token_cookie 

    response_json = json.loads(response.get_data())
    assert response_json['status'] == 'success'
    assert response_json['message'] == 'Token generate success'

def test_verify_token_endpoint(client):
    # client.post('/register', json={'email': 'test@example.com', 'password': 'password123'})
    login_response = client.post('/login', json={'identifier': 'test@example.com', 'password': 'password123'})
    token_cookie = login_response.headers.get('Set-Cookie')
    token = token_cookie.split('token=')[1].split(';')[0]
    response = client.post('/verify-token', json={'token': token})
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    response_json = json.loads(response.get_data())
    assert response_json['status'] == 'success'
    assert response_json['message'] == 'Token valid'

