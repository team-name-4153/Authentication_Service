import os
from flask import Flask, jsonify
from middleware import token_required

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

@app.route('/protected', methods=['GET'])
@token_required
def protected_route():
    """
    Example protected route using the middleware.
    """
    return jsonify({"message": "You have accessed a protected route!"})

if __name__ == '__main__':
    app.run(host='localhost', port=5002, debug=True)
