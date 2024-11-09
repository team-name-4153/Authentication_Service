import bcrypt
from models.Validation_Result_Model import VALIDATE_SUCCESS, VALIDATE_ERROR
from models.User_Info_Model import User
from models.Validation_Result_Model import ValidateResult
from database.rds_database import rds_database
import uuid
from services.token_service import TokenService
from dataclasses import asdict

class AuthService:
    def __init__(self, db_name, secret_key):
        self.db = rds_database(db_name)
        self.token_service = TokenService(secret_key)
        self.table_name = 'auth_db'

    def register(self, email, password):
        user = self.db.query_data(self.table_name, conditions={'email': email})
        if user:
            return ValidateResult(
                status=VALIDATE_ERROR,
                message='User already exists'
            )
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Generate a unique user ID
        user_id = str(uuid.uuid4())

        # Create a User dataclass object
        new_user = User(user_id=user_id, email=email, password=hashed_password)

        # Insert the user into the database by converting to a dictionary
        self.db.bulk_insert_data(self.table_name, [asdict(new_user)])

        return ValidateResult(
            status=VALIDATE_SUCCESS, 
            user_id=user_id,
            message="Registration successful")

    def login(self, identifier, password):
        # Find user by either email or user_id
        user = self.db.query_data(self.table_name, conditions={'email': identifier}) or self.db.query_data(self.table_name, conditions={'user_id': identifier})
        
        if not user:
            return ValidateResult(status=VALIDATE_ERROR, message='User not found')

        # Extract the user record
        if len(user)>1:
            return ValidateResult(status=VALIDATE_ERROR, message='User Info duplicate. Manual inspection needed')
        user = user[0]  

        # Check if the password is correct
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return ValidateResult(status=VALIDATE_ERROR, message='Invalid password')

        # Generate a JWT token
        token = self.token_service.generate_token(user['user_id'])

        return ValidateResult(
            status=VALIDATE_SUCCESS,
            user_id=user['user_id'],
            message='Token generate success',
            token=token
        )

    def verify_token(self, token):
        return self.token_service.verify_token(token)
