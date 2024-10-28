import os
from flask import Request, Response
from models.Validation_Result_Model import VALIDATE_SUCCESS
from services.token_service import TokenService

class AccessMiddleware():
    # To pass in any condition
    # def __init__(self, app):
    #     super().__init__()
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
        self.token_service = TokenService(secret_key=self.secret_key)

    # To pass in any condition
    # def __call__(self, environ, start_response):
    #     return self.app(environ, start_response)
    def __call__(self, environ, start_response):
        request = Request(environ)
        token = request.cookies.to_dict().get('token')
        if token:
            result = self.token_service.verify_token(token)
            if result.status == VALIDATE_SUCCESS:
                return self.app(environ, start_response)
            else:
                res = Response(result.get_json_result(), mimetype= 'text/plain', status=401)
                return res(environ, start_response)
        else:
            res = Response("invalid token", mimetype= 'text/plain', status=401)
            return res(environ, start_response)