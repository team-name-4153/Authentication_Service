from flask import Flask, request, jsonify
from flask_cors import CORS
from services.auth_service import AuthService
from services.token_service import TokenService
from database.rds_database import rds_database
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Secret key for JWT tokens
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')

# Initialize RDS database connection
db = rds_database(db_name='auth_db')

# initialize service
auth_service = AuthService(db_name='auth_db', secret_key=app.config['SECRET_KEY'])
token_service = TokenService(secret_key=app.config['SECRET_KEY'])


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Email and password required'}), 400

    # Register the user using AuthService
    result = auth_service.register(email, password)

    if result['status'] == 'success':
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    identifier = data.get('identifier')  # Can be either email or user_id
    password = data.get('password')

    if not identifier or not password:
        return jsonify({'status': 'error', 'message': 'Identifier and password required'}), 400

    # Login the user using AuthService
    result = auth_service.login(identifier, password)

    if result['status'] == 'success':
        return jsonify(result), 200
    else:
        return jsonify(result), 401


@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.json.get('token')

    if not token:
        return jsonify({'status': 'error', 'message': 'Token is required'}), 400

    # Verify the token
    result = token_service.verify_token(token)

    if result['status'] == 'success':
        return jsonify(result), 200
    else:
        return jsonify(result), 401

if __name__ == '__main__':
    app.run(debug=True)
