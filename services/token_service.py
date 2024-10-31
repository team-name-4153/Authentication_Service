import os
from sys import exception
import time
import jwt
import datetime
from models.Validation_Result_Model import ValidateResult
from models.Validation_Result_Model import VALIDATE_SUCCESS, VALIDATE_ERROR

class TokenService:
    def __init__(self, secret_key, jwt_expiration=None, jwt_refresh=None):
        self.secret_key = secret_key
        if jwt_expiration is None:
            self.jwt_expiration = int(os.getenv('JWT_EXPIRATION', '7200'))
        else:
            self.jwt_expiration = jwt_expiration
        if jwt_refresh is None:
            self.jwt_refresh = int(os.getenv('JWT_REFRESH', '3600'))
        else:
            self.jwt_refresh = jwt_refresh

    def generate_token(self, user_id, jwt_expiration=None, jwt_refresh=None):
        if jwt_expiration is None:
            jwt_expiration = self.jwt_expiration
        if jwt_refresh is None:
            jwt_refresh = self.jwt_refresh

        # Create a token with an expiration time
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=jwt_expiration),  # Use timezone-aware datetime
            'iat': datetime.datetime.now(datetime.timezone.utc)
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_token(self, token):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return ValidateResult(
                status=VALIDATE_SUCCESS,
                user_id=decoded['user_id'],
                message='Token valid'
            )
        except jwt.ExpiredSignatureError:
            return ValidateResult(
                status=VALIDATE_ERROR,
                message='Token has expired'
            )
        except jwt.InvalidTokenError:
            return ValidateResult(
                status=VALIDATE_ERROR,
                message='Invalid token'
            )
        
    def refresh_token(self, token):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            timediff = datetime.datetime.now(datetime.timezone.utc).timestamp() - decoded['iat']
            print("timediff", timediff)
            print("self.jwt_refresh", self.jwt_refresh)
            if timediff >= self.jwt_refresh:
                # current token has been issued for a while
                return self.generate_token(decoded['user_id'])
            else:
                return token
        except:
            print("refresh error: ", exception)
            return ""
