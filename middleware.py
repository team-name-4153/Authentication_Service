from flask import Flask, request, jsonify, redirect, make_response, session
from functools import wraps
import requests
import os
from jose import jwt, jwk
from jose.utils import base64url_decode
from urllib.parse import urlencode
import time

# Middleware configuration
AUTH_SERVICE_BASE_URL = "http://localhost:5001"
COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
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
                    raise Exception(new_tokens["error_description"])

                res = make_response(f(*args, **kwargs))
                res.set_cookie("access_token", new_tokens.get("access_token"))
                return res
            except Exception as e:
                print(f"Token refresh error: {e}")

        # Redirect to the login page on the authentication service
        session['redirect_after_login'] = request.url
        return redirect(f"{AUTH_SERVICE_BASE_URL}/login")

    return decorated_function

