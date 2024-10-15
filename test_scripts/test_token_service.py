# test_scripts/test_token_service.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import jwt
import time
from services.token_service import TokenService

# Setup a fixture to create a token service instance
@pytest.fixture
def token_service():
    secret_key = 'auth_secret_key'
    return TokenService(secret_key)

# Test that token generation
def test_generate_token(token_service):
    user_id = "test_user_id"
    token = token_service.generate_token(user_id)
    
    # Verify that the token can be decoded and contains the expected user_id
    decoded = jwt.decode(token, token_service.secret_key, algorithms=['HS256'])
    assert decoded['user_id'] == user_id
    assert 'exp' in decoded  # Check that expiration is included

# Test successful verification
def test_verify_token(token_service):
    user_id = "test_user_id"
    token = token_service.generate_token(user_id)
    
    result = token_service.verify_token(token)
    
    assert result['status'] == 'success'
    assert result['user_id'] == user_id

def test_invalid_token(token_service):
    # Test verification of an invalid token
    invalid_token = "invalid.token.string"
    
    result = token_service.verify_token(invalid_token)
    
    assert result['status'] == 'error'
    assert result['message'] == 'Invalid token'

# Test verification of an expired token
def test_expired_token(token_service):
    user_id = "test_user_id"
    
    # Generate a token with a very short expiration time (1 second)
    token = token_service.generate_token(user_id, exp_time=1)
    
    time.sleep(2)
    result = token_service.verify_token(token)
    assert result['status'] == 'error'
    assert result['message'] == 'Token has expired'

