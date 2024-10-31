# test_scripts/test_token_service.py

from flask import Flask, json, request, jsonify
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import jwt
import time
from datetime import datetime, timedelta, timezone
from services.token_service import TokenService
from models.Validation_Result_Model import VALIDATE_SUCCESS, VALIDATE_ERROR

# Setup a fixture to create a token service instance
@pytest.fixture
def token_service(jwt_refresh=None):
    secret_key = 'auth_secret_key'
    return TokenService(secret_key)

# Test that token generation includes expected fields
def test_generate_token(token_service):
    user_id = "test_user_id"
    token = token_service.generate_token(user_id)
    
    # Decode the token and verify it contains the expected fields
    decoded = jwt.decode(token, token_service.secret_key, algorithms=['HS256'])
    assert decoded['user_id'] == user_id
    assert 'exp' in decoded  # Ensure expiration time is included
    assert 'iat' in decoded  # Ensure issued-at time is included

# Test successful verification of a valid token
def test_verify_token(token_service):
    user_id = "test_user_id"
    token = token_service.generate_token(user_id)
    
    result = token_service.verify_token(token)
    assert result.status == VALIDATE_SUCCESS
    assert result.user_id == user_id
    assert result.message == 'Token valid'

# Test verification of an invalid token
def test_invalid_token(token_service):
    invalid_token = "invalid.token.string"
    
    result = token_service.verify_token(invalid_token)
    
    assert result.status == VALIDATE_ERROR
    assert result.message == 'Invalid token'

# Test verification of an expired token
def test_expired_token(token_service):
    user_id = "test_user_id"
    
    # Generate a token with a very short expiration time (1 second)
    token = token_service.generate_token(user_id, jwt_expiration=1)
    
    # Wait until the token expires
    time.sleep(2)
    result = token_service.verify_token(token)
    assert result.status == VALIDATE_ERROR
    assert result.message == 'Token has expired'

# Test the refresh token functionality with time past the refresh interval
def test_refresh_token(token_service):
    user_id = "test_user_id"
    
    # Generate a token with a long expiration (5 seconds) and a shorter refresh interval (2 seconds)
    token_service.jwt_refresh = 2
    token = token_service.generate_token(user_id, jwt_expiration=5)
    
    # Wait until we exceed the refresh interval
    time.sleep(3)
    
    # Attempt to refresh the token
    refreshed_token = token_service.refresh_token(token)
    
    # The refresh should create a new token since the refresh interval has been exceeded
    assert refreshed_token != token  # Ensure a new token is generated
    
    # Verify the new token
    refreshed_result = token_service.verify_token(refreshed_token)
    assert refreshed_result.status == VALIDATE_SUCCESS
    assert refreshed_result.user_id == user_id

# Test that the token is returned as-is if it does not need to be refreshed
def test_no_refresh_needed(token_service):
    user_id = "test_user_id"
    
    # Generate a token with a refresh interval that has not been exceeded
    token = token_service.generate_token(user_id, jwt_expiration=10)
    
    # Wait only a short period (less than the refresh interval)
    time.sleep(1)
    
    # Attempt to refresh the token
    refreshed_token = token_service.refresh_token(token)
    
    # Since the refresh interval hasn’t been exceeded, it should return the original token
    assert refreshed_token == token
