import os
from flask import Request, Response, json, jsonify
from flask_http_middleware import BaseHTTPMiddleware
import jwt
from models.Validation_Result_Model import VALIDATE_SUCCESS
from services import token_service
from services.token_service import TokenService

class AccessMiddleware():
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
        self.token_service = TokenService(secret_key=self.secret_key)

    def __call__(self, environ, start_response):
        request = Request(environ)
        token = request.cookies.to_dict().get('token')
        if token:
            result = self.token_service.verify_token(token)
            print(result)
            if result.status == VALIDATE_SUCCESS:
                print("success validate")
                return self.app(environ, start_response)
            else:
                res = Response(result.get_json_result(), mimetype= 'text/plain', status=401)
                return res(environ, start_response)
        else:
            res = Response("invalid token", mimetype= 'text/plain', status=401)
            return res(environ, start_response)