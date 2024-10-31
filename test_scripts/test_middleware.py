import json
import sys
import os
import time
import pytest

os.environ['SECRET_KEY'] = 'auth_secret_key'
os.environ['JWT_EXPIRATION'] = '10'
os.environ['JWT_REFRESH'] = '5'

# Adjust the import paths for app and pseudo_app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    
    # Extract the token from the Set-Cookie header in login response
    token_cookie = login_response.headers.get('Set-Cookie')
    token = token_cookie.split('token=')[1].split(';')[0]

    # Set the token as a cookie in the pseudo_client
    pseudo_client.set_cookie('token', token)

    # Access the protected route in pseudo_app
    response = pseudo_client.get('/hello')
    
    # Check for successful access
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    response_json = json.loads(response.get_data())
    assert response_json['message'] == "Hello World!"

def test_protected_route_with_expired_token(main_client, pseudo_client):
    # Register and log in to get a token with a short expiration
    main_client.post('/register', json={'email': 'test_expired@example.com', 'password': 'password123'})
    login_response = main_client.post('/login', json={'identifier': 'test_expired@example.com', 'password': 'password123'})
    
    # Extract the token from the Set-Cookie header
    token_cookie = login_response.headers.get('Set-Cookie')
    token = token_cookie.split('token=')[1].split(';')[0]

    # Wait until the token expires (more than 10 seconds in this case)
    time.sleep(11)

    # Set the expired token in the pseudo_client
    pseudo_client.set_cookie('token', token)
    response = pseudo_client.get('/hello')
    
    # The response should indicate unauthorized access due to expiration
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"
    response_json = json.loads(response.get_data())
    assert response_json['status'] == 'error'
    assert response_json['message'] == 'Token has expired'

def test_protected_route_with_refreshable_token(main_client, pseudo_client):
    # Register and log in to get a token that can be refreshed
    main_client.post('/register', json={'email': 'test_refreshable@example.com', 'password': 'password123'})
    login_response = main_client.post('/login', json={'identifier': 'test_refreshable@example.com', 'password': 'password123'})
    
    # Extract the token from the Set-Cookie header
    token_cookie = login_response.headers.get('Set-Cookie')
    token = token_cookie.split('token=')[1].split(';')[0]

    # Wait just beyond the refresh time but before expiration
    time.sleep(6)

    # Set the refreshable token in the pseudo_client and access protected route
    pseudo_client.set_cookie('token', token)
    response = pseudo_client.get('/hello')
    
    # Check for successful access and token refresh
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    # Check that the token was refreshed by comparing it to the old token
    refreshed_token_cookie = response.headers.get('Set-Cookie')
    refreshed_token = refreshed_token_cookie.split('token=')[1].split(';')[0]
    assert refreshed_token != token, "Token was not refreshed as expected"

    # Validate response content
    response_json = json.loads(response.get_data())
    assert response_json['message'] == "Hello World!"

def test_protected_route_with_invalid_token(pseudo_client):
    # Set an invalid token directly in the pseudo_client
    pseudo_client.set_cookie('token', 'invalid_token')

    # Attempt to access the protected route with the invalid token
    response = pseudo_client.get('/hello')
    
    # Expect unauthorized status due to invalid token
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"
    response_json = json.loads(response.get_data())
    print(response_json)
    assert response_json['status'] == 'error'
    assert response_json['message'] == 'Invalid token'