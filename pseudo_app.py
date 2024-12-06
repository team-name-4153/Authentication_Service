# pseudo_app.py

import os
from flask import Flask, jsonify, request
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
    user_info = {}
    if user_info_cookie:
        user_info = jsonify(user_info_cookie).get_json()  # Decode user info from cookie

    return jsonify({
        "message": "You have accessed a protected route!",
        "user_info": user_info,
    })

if __name__ == '__main__':
    app.run(host='localhost', port=5002, debug=True)
