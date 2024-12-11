from flask import Flask, json, request, jsonify, redirect, make_response
import os
import requests
from dotenv import load_dotenv
import jwt
import logging
from urllib.parse import urlencode, quote, unquote
from dotenv import load_dotenv
from middleware import token_required, validate_jwt_token

# Load environment variables
load_dotenv()

app = Flask(__name__)
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

# Add CORS headers
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://localhost:3000"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.after_request
def apply_cors(response):
    return add_cors_headers(response)

@app.route('/<path:path>', methods=['OPTIONS'])
def options(path):
    response = make_response()
    return add_cors_headers(response)

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
    redirect_after_login = request.args.get("redirect_after_login", "/")
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
    Exchanges authorization code for tokens and packs user information.
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

        app.logger.info('go back to path: ' + redirect_after_login)
        res = make_response(redirect(redirect_after_login))
        res.set_cookie("access_token", tokens.get('access_token'))
        res.set_cookie("id_token", id_token)
        res.set_cookie("refresh_token", tokens.get('refresh_token'))
        res.set_cookie("user_info", jsonify(user_info).data.decode())  # Store user info in cookies
        return res

    except Exception as e:
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
    return res

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
    user_info_cookie = request.cookies.get('user_info')
    user_info = json.loads(user_info_cookie) if user_info_cookie else {}
    return jsonify({
        "message": "Welcome!",
        "email": user_info.get("email", ""),
        "photo_url": user_info.get("photo_url", ""),
        "user_id": user_info.get("user_id", ""),
        "preferred_name": user_info.get("preferred_name", ""),
    })

if __name__ == '__main__':
    app.run(host='localhost', port=5001, debug=True)
