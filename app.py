from flask import Flask, json, make_response, request, jsonify
from flask_cors import CORS
from services.auth_service import AuthService, VALIDATE_SUCCESS
from services.token_service import TokenService
from database.rds_database import rds_database
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['RDS_DB_NAME'] = os.getenv('RDS_DB_NAME', 'auth_db')

# Initialize RDS database connection
db = rds_database(db_name=app.config['RDS_DB_NAME'])

# initialize service
auth_service = AuthService(db_name=app.config['RDS_DB_NAME'], secret_key=app.config['SECRET_KEY'])
token_service = TokenService(secret_key=app.config['SECRET_KEY'])


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return make_response(json.dumps({'status': 'error', 'message': 'Email and password required'}), 400)
    result = auth_service.register(email, password)
    status_code = 201 if result.status == VALIDATE_SUCCESS else 400
    return make_response(result.get_json_result(), status_code)


# after login success, will return token. store in cookie for next use
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    identifier = data.get('identifier')
    password = data.get('password')

    if not identifier or not password:
        return make_response(json.dumps({'status': 'error', 'message': 'Identifier and password required'}), 400)

    result = auth_service.login(identifier, password)
    status_code = 200 if result.status == VALIDATE_SUCCESS else 401

    res = make_response(result.get_json_result(), status_code)
    if result.token:
        res.set_cookie('token', result.token)
    return res


# whenever have new request. continue if got 'status': 'success'
@app.route('/verify-token', methods=['POST'])
def verify_token():
    token = request.json.get('token')

    if not token:
        return make_response(json.dumps({'status': 'error', 'message': 'Token is required'}), 400)

    result = token_service.verify_token(token)
    status_code = 200 if result.status == VALIDATE_SUCCESS else 401
    return make_response(result.get_json_result(), status_code)

if __name__ == '__main__':
    app.run(debug=True)
