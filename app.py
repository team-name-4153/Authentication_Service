from flask import Flask, make_response, request, jsonify
from flask_cors import CORS
from services.auth_service import AuthService, VALIDATE_SUCCESS
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

    if result.status == VALIDATE_SUCCESS:
        return result.get_json_result(), 201
    else:
        return result.get_json_result(), 400

# after login success, will return token. store in cookie for next use
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    identifier = data.get('identifier')  # Can be either email or user_id
    password = data.get('password')

    if not identifier or not password:
        return jsonify({'status': 'error', 'message': 'Identifier and password required'}), 400

    # Login the user using AuthService
    result = auth_service.login(identifier, password)

    if result.status == VALIDATE_SUCCESS:
        output = result.get_json_result(), 200
    else:
        output = result.get_json_result(), 401
    
    res = make_response(output)
    res.set_cookie('token', result.token)
    return res


# whenever have new request. continue if got 'status': 'success'
@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.json.get('token')

    if not token:
        return jsonify({'status': 'error', 'message': 'Token is required'}), 400

    # Verify the token
    result = token_service.verify_token(token)

    if result.status == VALIDATE_SUCCESS:
        return result.get_json_result(), 200
    else:
        return result.get_json_result(), 401

if __name__ == '__main__':
    app.run(debug=True)
