import jwt
import datetime
from models.Validation_Result_Model import ValidateResult
from models.Validation_Result_Model import VALIDATE_SUCCESS, VALIDATE_ERROR

class TokenService:
    def __init__(self, secret_key):
        self.secret_key = secret_key

    def generate_token(self, user_id, exp_time=3600):
        # Create a token with an expiration time
        payload = {
            'user_id': user_id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=exp_time)  # Use timezone-aware datetime
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
