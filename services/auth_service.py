import bcrypt
from models.user_model import User
from database.rds_database import rds_database
import uuid
from services.token_service import TokenService
from dataclasses import asdict

class AuthService:
    def __init__(self, db_name, secret_key):
        self.db = rds_database(db_name)
        self.token_service = TokenService(secret_key)

    def register(self, email, password):

        user = self.db.query_data('users', conditions={'email': email})
        if user:
            return {'status': 'error', 'message': 'User already exists'}
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Generate a unique user ID
        user_id = str(uuid.uuid4())

        # Create a User dataclass object
        new_user = User(user_id=user_id, email=email, password=hashed_password)

        # Insert the user into the database by converting to a dictionary
        self.db.bulk_insert_data('users', [asdict(new_user)])

        return {'status': 'success', 'user_id': user_id}

    def login(self, identifier, password):
        # Find user by either email or user_id
        user = self.db.query_data('users', conditions={'email': identifier}) or self.db.query_data('users', conditions={'user_id': identifier})
        
        if not user:
            return {'status': 'error', 'message': 'User not found'}

        # Extract the user record
        user = user[0]  

        # Check if the password is correct
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return {'status': 'error', 'message': 'Invalid password'}

        # Generate a JWT token
        token = self.token_service.generate_token(user['user_id'])

        return {'status': 'success', 'token': token}

    def verify_token(self, token):
        return self.token_service.verify_token(token)
