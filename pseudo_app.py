# pseudo_app.py

import os
from flask import Flask, json, jsonify, request
from middleware import token_required

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")


@app.route("/protected", methods=["GET"])
@token_required
def protected_route():
    """
    Example protected route using the middleware.
    """
    user_info_cookie = request.cookies.get('user_info')
    user_info = json.loads(user_info_cookie) if user_info_cookie else {}

    return jsonify({
        "message": "You have accessed a protected route!",
        "email": user_info.get("email", ""),
        "photo_url": user_info.get("photo_url", ""),
        "preferred_name": user_info.get("preferred_name", ""),
        "user_id": user_info.get("user_id", ""),
    })

if __name__ == '__main__':
    app.run(host='localhost', port=5002, debug=True)
