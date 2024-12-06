# Authentication_Service

Authentication Service is in charge of registration, login and authentication token cerification. In the lifecircle of our streaming app, Authentication service is mentioned (as an app) as a doorman of every user-only service, and take a role in middleware everytime a new resource is requested. `jwt` is used in the service to handle the permission issue, recording the user_id, exp and iat inside the payload. jwt token is stored inside cookie, under the keyword "token".

## Environment: 
```
# AWS Cognito Configuration
COGNITO_DOMAIN=https://us-east-2xa3953tkf.auth.us-east-2.amazoncognito.com
COGNITO_CLIENT_ID=6nlbf44e9tj8ogqumhm0dd8imd
COGNITO_CLIENT_SECRET=streaming_app
COGNITO_REDIRECT_URI=https://zt9vvpjd3k.execute-api.us-east-2.amazonaws.com/auth/callback
COGNITO_REGION=us-east-2

# Redirect Config
AUTH_SERVICE_BASE_URL=https://zt9vvpjd3k.execute-api.us-east-2.amazonaws.com/
SECRET_KEY=secure_random_key
```


## To learn the code detailedly:

To know about the authentication service, i.e. the Authentication Flask App, read from `test_scripts/test_auth_integration.py`

To learn how middleware works, start from `test_scripts/test_middleware.py`