# auth_middleware.py

from flask import request, jsonify, redirect, make_response, session
from functools import wraps
import requests
import os
from jose import jwt, jwk
from jose.utils import base64url_decode
from urllib.parse import urlencode
import time

COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
COGNITO_REDIRECT_URI = os.getenv('COGNITO_REDIRECT_URI')

TOKEN_URL = f"{COGNITO_DOMAIN}/oauth2/token"
JWKS_URL = f"{COGNITO_DOMAIN}/.well-known/jwks.json"

def validate_jwt_token(token):
    try:
        jwks_response = requests.get(JWKS_URL).json()
        headers = jwt.get_unverified_header(token)
        kid = headers.get('kid')
        key = next(k for k in jwks_response['keys'] if k['kid'] == kid)
        public_key = jwk.construct(key)

        message, encoded_signature = token.rsplit('.', 1)
        decoded_signature = base64url_decode(encoded_signature.encode())
        if not public_key.verify(message.encode(), decoded_signature):
            return False

        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=['RS256'],
            audience=COGNITO_CLIENT_ID
        )

        if claims['exp'] < int(time.time()):
            return False

        return True
    except Exception as e:
        print(f"Token validation error: {e}")
        return False

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        refresh_token = request.cookies.get('refresh_token')

        if access_token and validate_jwt_token(access_token):
            return f(*args, **kwargs)

        if refresh_token:
            try:
                token_payload = {
                    "grant_type": "refresh_token",
                    "client_id": COGNITO_CLIENT_ID,
                    "client_secret": COGNITO_CLIENT_SECRET,
                    "refresh_token": refresh_token,
                }
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                response = requests.post(TOKEN_URL, data=token_payload, headers=headers)
                new_tokens = response.json()

                if "error" in new_tokens:
                    return jsonify({"error": "Failed to refresh token", "message": new_tokens["error_description"]}), 401

                res = make_response(f(*args, **kwargs))
                res.set_cookie("access_token", new_tokens.get("access_token"))
                res.set_cookie("id_token", new_tokens.get("id_token"))
                return res
            except Exception as e:
                print(f"Token refresh error: {e}")
                return jsonify({"error": "Failed to refresh token", "details": str(e)}), 401

        login_url = f"{COGNITO_DOMAIN}/oauth2/authorize"
        query_params = {
            "response_type": "code",
            "client_id": COGNITO_CLIENT_ID,
            "redirect_uri": COGNITO_REDIRECT_URI,
            "scope": "email openid phone profile",
            "state": request.path,
        }
        return redirect(f"{login_url}?{urlencode(query_params)}")

    return decorated_function
