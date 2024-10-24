
from flask import Flask, request
from middleware import AccessMiddleware

from flask import Flask, jsonify
from flask_http_middleware import MiddlewareManager, BaseHTTPMiddleware

import os
from flask import json, jsonify
from flask_http_middleware import BaseHTTPMiddleware
from models.Validation_Result_Model import VALIDATE_SUCCESS
from services.token_service import TokenService

app = Flask('pseudo_app')

app.wsgi_app = AccessMiddleware(app.wsgi_app)

   
@app.route('/hello', methods=['GET'])
def hello():
    print("success")
    return jsonify(message="Hello World!")

if __name__ ==  '__main__':
    app.run('127.0.0.1', '5000', debug=True)