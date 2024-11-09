# Authentication_Service

Authentication Service is in charge of registration, login and authentication token cerification. In the lifecircle of our streaming app, Authentication service is mentioned (as an app) as a doorman of every user-only service, and take a role in middleware everytime a new resource is requested. `jwt` is used in the service to handle the permission issue, recording the user_id, exp and iat inside the payload. jwt token is stored inside cookie, under the keyword "token".

## Environment: 
```
# Database
RDS_HOST = 'team-name-database.cb4uyq8si6lp.us-east-2.rds.amazonaws.com'
RDS_PORT = 3306
RDS_USER = 'admin' 
RDS_PASSWORD = 'team-name-database'
RDS_DB_NAME = 'authenticatoin_service'

# JWT
SECRET_KEY=our_jwt_secret_key
JWT_REFRESH=3600 # auto refresh if time exceed
JWT_EXPIRATION=7200  # token expiration time in seconds

# Flask
FLASK_DEBUG=True
```


## To learn the code detailedly:

To know about the authentication service, i.e. the Authentication Flask App, read from `test_scripts/test_auth_integration.py`

To learn how middleware works, start from `test_scripts/test_middleware.py`