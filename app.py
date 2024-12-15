from flask import Flask, json, request, jsonify, redirect, make_response, g
import os
import json as js
from flask_cors import CORS
import requests
from dotenv import load_dotenv
import jwt
import logging
from urllib.parse import urlencode, quote, unquote

import urllib
from middleware import token_required, validate_jwt_token

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://localhost:3000"}})

app.logger.setLevel(logging.INFO)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Cognito configuration
COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
COGNITO_REDIRECT_URI = os.getenv('COGNITO_REDIRECT_URI')
COGNITO_LOGOUT_URI = os.getenv('COGNITO_LOGOUT_URI')
COGNITO_REGION = os.getenv('COGNITO_REGION')
USER_POOL_ID = os.getenv('USER_POOL_ID')
TOKEN_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{USER_POOL_ID}/oauth2/token"

global_credentials = {}

@app.route('/')
def home():
    # only for testing purpose
    return "Welcome to the Authentication Service!"

@app.route('/login')
def login():
    """
    Redirects user to Cognito Hosted UI for login.
    """
    app.logger.info("navigate to authentication_service /login")
    login_url = f"{COGNITO_DOMAIN}/oauth2/authorize"
    redirect_after_login = request.args.get("redirect_after_login", "/userHome")
    state = {
        "redirect_after_login": redirect_after_login
    }
    state_encoded = quote(json.dumps(state))

    query_params = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "scope": "email openid phone profile",
        "state": state_encoded,
    }
    return redirect(f"{login_url}?{urlencode(query_params)}")


@app.route('/auth/callback')
def auth_callback():
    """
    Handles Cognito's callback after login.
    Exchanges authorization code for tokens and sends data to the parent or sets cookies directly.
    """
    app.logger.info("navigate to authentication_service /auth/callback")

    code = request.args.get('code')
    state_encoded = request.args.get("state")
    if state_encoded:
        state = json.loads(unquote(state_encoded))
        redirect_after_login = state.get("redirect_after_login", "/")
    else:
        redirect_after_login = "/"

    if not code:
        return jsonify({"error": "Authorization code is required"}), 400

    token_payload = {
        "grant_type": "authorization_code",
        "client_id": COGNITO_CLIENT_ID,
        "client_secret": COGNITO_CLIENT_SECRET,
        "code": code,
        "redirect_uri": COGNITO_REDIRECT_URI,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        token_response = requests.post(f"{COGNITO_DOMAIN}/oauth2/token", data=token_payload, headers=headers)
        tokens = token_response.json()

        if "error" in tokens:
            return jsonify({"error": tokens["error"]}), 400

        id_token = tokens.get('id_token')
        claims = jwt.decode(id_token, algorithms=["RS256"], options={"verify_signature": False})

        user_info = {
            "user_id": claims.get("sub"),
            "email": claims.get("email"),
            "preferred_name": claims.get("preferred_username", ""),
            "photo_url": claims.get("picture", ""),
        }

        app.logger.info("[/auth/callback] all data prepared")

        # Store credentials in the session

        global global_credentials
        safe_user_info = json.dumps(user_info).replace('"', '\\"')
        global_credentials = {
            "user_info": user_info,
            "access_token": tokens.get('access_token'),
            "id_token": id_token,
            "refresh_token": tokens.get('refresh_token'),
        }

        res = make_response(redirect('/userHome'))
        res.set_cookie('access_token', tokens.get('access_token'))
        res.set_cookie('id_token', id_token)
        res.set_cookie('refresh_token', tokens.get('refresh_token'))
        res.set_cookie('user_info', safe_user_info)
        return res

    except Exception as e:
        app.logger.error(f"Error during auth callback: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/logout')
def logout():
    """
    Logs the user out from Cognito and clears cookies.
    """
    logout_url = f"{COGNITO_DOMAIN}/logout"
    query_params = {
        "client_id": COGNITO_CLIENT_ID,
        "logout_uri": COGNITO_LOGOUT_URI,
    }
    res = make_response(redirect(f"{logout_url}?{urlencode(query_params)}"))
    res.delete_cookie("access_token")
    res.delete_cookie("id_token")
    res.delete_cookie("refresh_token")
    res.delete_cookie("user_info")
    return res

@app.route('/auth/getcredential', methods=['GET'])
def get_credential():
    global global_credentials
    app.logger.info("get to /auth/getcredential")
    user_info = global_credentials.get("user_info")
    access_token = global_credentials.get("access_token")
    id_token = global_credentials.get("id_token")
    refresh_token = global_credentials.get("refresh_token")
    global_credentials = {}

    if not user_info or not access_token:
        return jsonify({"error": "Not authenticated"}), 401

    response_data = {
        "user_info": user_info,
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
    }
    
    app.logger.info("/auth/getcredential response 200")
    return jsonify(response_data), 200


@app.route('/auth/status', methods=["GET"])
def auth_status():
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if access_token:
        valid, _ = validate_jwt_token(access_token)
        if valid:
            return jsonify({"authenticated": True}), 200

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

            return jsonify({"authenticated": True}), 200
        except Exception as e:
            print(f"Token refresh error: {e}")

    return jsonify({"authenticated": False, "login_url": f"{COGNITO_DOMAIN}/oauth2/authorize?response_type=code&client_id={COGNITO_CLIENT_ID}&redirect_uri={COGNITO_REDIRECT_URI}&scope=email openid phone profile"}), 401

@app.route('/userHome', methods=["GET"])
@token_required
def user_home():
    """
    Protected route for authenticated users.
    """
    app.logger.info("get to /userHome")
    user_info_cookie = request.cookies.get('user_info')

    app.logger.info(f"Raw user_info_cookie: {user_info_cookie}")

    if not user_info_cookie:
        return jsonify({"error": "User info not available"}), 401

    try:
        decoded_cookie = urllib.parse.unquote(user_info_cookie)
        cleaned_cookie = decoded_cookie.strip('"').replace('\\054', ',').replace('\\012', '\n').replace('\\', '')

        start_index = cleaned_cookie.find('{')
        end_index = cleaned_cookie.rfind('}')
        if start_index != -1 and end_index != -1:
            cleaned_cookie = cleaned_cookie[start_index:end_index + 1]
        user_info = json.loads(cleaned_cookie)
        return jsonify({
            "message": "Welcome!",
            "email": user_info.get("email", ""),
            "photo_url": user_info.get("photo_url", ""),
            "user_id": user_info.get("user_id", ""),
            "preferred_name": user_info.get("preferred_name", ""),
        })
    except js.JSONDecodeError as e:
        app.logger.error(f"Error decoding user_info_cookie: {e}")
        return jsonify({"error": "Invalid user info format"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

