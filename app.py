from flask import Flask, request, jsonify, redirect, make_response, session
from flask_cors import CORS
import os
import requests
from dotenv import load_dotenv
from urllib.parse import urlencode
import jwt

load_dotenv()

app = Flask(__name__)
CORS(app)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

COGNITO_DOMAIN = os.getenv('COGNITO_DOMAIN')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
COGNITO_CLIENT_SECRET = os.getenv('COGNITO_CLIENT_SECRET')
COGNITO_REDIRECT_URI = os.getenv('COGNITO_REDIRECT_URI')

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
    query_params = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "scope": "email openid phone profile",
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
            return jsonify({"error": tokens["error_description"]}), 400

        id_token = tokens.get('id_token')
        claims = jwt.decode(id_token, algorithms=["RS256"], options={"verify_signature": False})

        user_info = {
            "user_id": claims.get("sub"),
            "email": claims.get("email"),
            "preferred_name": claims.get("preferred_username", ""),
            "photo_url": claims.get("picture", ""),
        }

        res = make_response(redirect(session.pop('redirect_after_login', '/')))
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
        "logout_uri": COGNITO_REDIRECT_URI,
    }
    res = make_response(redirect(f"{logout_url}?{urlencode(query_params)}"))
    res.delete_cookie("access_token")
    res.delete_cookie("id_token")
    res.delete_cookie("refresh_token")
    return res


if __name__ == '__main__':
    # host and port for debug only
    app.run(host='localhost', port=5001, debug=True)
