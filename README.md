# Authentication_Service

Authentication Service is in charge of registration, login and authentication token cerification. In the lifecircle of our streaming app, Authentication service is mentioned (as an app) as a doorman of every user-only service, and take a role in middleware everytime a new resource is requested. `jwt` is used in the service to handle the permission issue, recording the user_id, exp and iat inside the payload. jwt token is stored inside cookie, under the keyword "token".

## Interface: 



## To learn the code detailedly:

To know about the authentication service, i.e. the Authentication Flask App, read from `test_scripts/test_auth_integration.py`

To learn how middleware works, start from `test_scripts/test_middleware.py`