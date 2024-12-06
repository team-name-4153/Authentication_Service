# Authentication_Service

Authentication Service is in charge of registration, login and authentication token cerification. In the lifecircle of our streaming app, Authentication service is mentioned (as an app) as a doorman of every user-only service, and take a role in middleware everytime a new resource is requested. 

Whenever the client try to request services that are supposed to be protected, it will automatically trigger our middleware `@token_required` to look into the browser cookie to see if there's any existing certificates. 

1. If the user have never login before, the middleware would navigate to `/auth/login`, which will redirect to **AWS Cognito**. Users could choose to either login or register with the help of AWS service. With the login certificate, our `/auth/callback` could exchange a set of longer life tokens, as well as collect detailed user informations and store all of them inside the cookie. Then the service would reirect to wherever the client originally want to visit. 
2. If the user have already login, it means that the browser has a set of valid tokens. The client could direct visit if all of their tokens are valid, or automatically refresh their tokens if only the refresh token is valid. Under both situation, the user will not notice the process, and could smoothly access the protected resources.

Currently we are using the setting: 
```
Authentication flow session duration: 3 minutes
Refresh token expiration: 5 day(s)
Access token expiration: 60 minutes
ID token expiration: 60 minutes
```

## Environment: 
```
# AWS Cognito Configuration
COGNITO_DOMAIN=https://us-east-2xa3953tkf.auth.us-east-2.amazoncognito.com
COGNITO_CLIENT_ID=6nlbf44e9tj8ogqumhm0dd8imd
COGNITO_CLIENT_SECRET=streaming_app
COGNITO_REDIRECT_URI=https://zt9vvpjd3k.execute-api.us-east-2.amazonaws.com/auth/callback
COGNITO_REGION=us-east-2

# Redirect Config
AUTH_SERVICE_BASE_URL=https://zt9vvpjd3k.execute-api.us-east-2.amazonaws.com/auth
SECRET_KEY=secure_random_key
```

## APIs:
```
GET /
ANY /auth/login
ANY /auth/callback
```
