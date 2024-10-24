# test_scripts/test_auth_service.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from unittest.mock import MagicMock, patch
from services.auth_service import AuthService
from models.User_Info_Model import User
from models.Validation_Result_Model import ValidateResult
from models.Validation_Result_Model import VALIDATE_SUCCESS, VALIDATE_ERROR
import bcrypt
from dataclasses import asdict

@pytest.fixture
def auth_service():
    # Mock the database connection
    with patch('database.rds_database.rds_database') as MockDB:
        mock_db = MockDB(db_name="auth_db")
        return AuthService(db_name="auth_db", secret_key="auth_secret_key")

@pytest.fixture
def test_user():
    hashed_password = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return User(user_id="123e4567", email="testuser@example.com", password=hashed_password)

# Test for user registration
def test_register_user(auth_service, test_user):
    # Mock user does not exist
    auth_service.db.query_data = MagicMock(return_value=[])
    # Mock the bulk insert operation
    auth_service.db.bulk_insert_data = MagicMock(return_value="Success")

    result = auth_service.register(test_user.email, "password123")
    
    assert result.status == VALIDATE_SUCCESS
    assert not result.user_id == None
    auth_service.db.bulk_insert_data.assert_called_once()

# Test for registration of an existing user
def test_register_existing_user(auth_service, test_user):
    # Mock query to simulate the user already exists
    auth_service.db.query_data = MagicMock(return_value=[asdict(test_user)])  # Return user data to indicate existence

    # Try to register the existing user
    result = auth_service.register(test_user.email, "password123")
    assert result.status == VALIDATE_ERROR
    assert result.message == 'User already exists'

# Test for successful login
def test_login_success(auth_service, test_user):
    # Mock query to simulate user is found
    auth_service.db.query_data = MagicMock(return_value=[asdict(test_user)]) 

    # Test login with correct password
    result = auth_service.login(identifier=test_user.email, password="password123")
    
    assert result.status == VALIDATE_SUCCESS
    assert not result.user_id == None
    assert not result.token == None

# Test for invalid login due to wrong password
def test_login_wrong_password(auth_service, test_user):
    # Mock query to simulate user is found
    auth_service.db.query_data = MagicMock(return_value=[asdict(test_user)]) 

    # Test login with wrong password
    result = auth_service.login(identifier=test_user.email, password="wrongpassword")
    
    assert result.status == VALIDATE_ERROR
    assert result.message == 'Invalid password'

# Test for login when user doesn't exist
def test_login_nonexistent_user(auth_service):
    # Mock query to simulate user is not found
    auth_service.db.query_data = MagicMock(return_value=[])

    # Test login for nonexistent user
    result = auth_service.login(identifier="nonexistent@example.com", password="password123")
    
    assert result.status == VALIDATE_ERROR
    assert result.message == 'User not found'

# Test token verification
def test_verify_token(auth_service, test_user):
    # Mock token service to simulate a valid token
    auth_service.token_service.verify_token = MagicMock(
        return_value=ValidateResult(
            status=VALIDATE_SUCCESS,
            user_id=test_user.user_id
        ))

    # Generate a mock token and verify it
    token = auth_service.token_service.generate_token(test_user.user_id)
    result = auth_service.verify_token(token)
    
    assert result.status == VALIDATE_SUCCESS
    assert result.user_id == test_user.user_id
